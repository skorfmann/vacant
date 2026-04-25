package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

const usage = `vacant — domain availability checker

USAGE
  vacant [flags] <domain>...

DESCRIPTION
  Checks whether one or more domains are available for registration.
  Lookup order: optional DNS pre-filter (DoH) -> RDAP via the IANA
  bootstrap registry -> WHOIS fallback for ccTLDs without RDAP.

INPUT
  Domains can be given as positional args, via --file, or as bare names
  expanded with --tld. Names are lowercased and de-duplicated.

FLAGS
  -f, --file <path>      Read newline-separated domains. "-" reads stdin.
                         Lines starting with "#" are ignored.
  -t, --tld <list>       Comma-separated TLDs. Each bare name (no dot) is
                         expanded to name.tld for every tld in the list.
  -c, --concurrency <n>  Max parallel lookups (default 20). WHOIS is
                         additionally capped at 2 connections per registry
                         host to stay within typical rate limits.
      --dns              Enable DoH NS pre-filter via 1.1.1.1. Domains with
                         live NS records are reported as taken without an
                         RDAP/WHOIS round-trip. Faster for mostly-taken
                         batches; adds latency for mostly-available ones.
      --json             Emit one JSON object per line on stdout (NDJSON).
      --no-color         Disable ANSI colors in human output.

OUTPUT
  Human (default): one line per domain with a symbol, name, and status.
    ✓ available   ✗ taken   ! error   ? unknown

  JSON (--json): one object per line, schema:
    {
      "domain": "acme.dev",
      "status": "available" | "taken" | "error" | "unknown",
      "server": "<source that answered>",   // optional
      "error":  "<error message>"           // present iff status=error
    }

  The "server" field identifies which lookup path answered:
    "dns"          — DoH pre-filter short-circuited the result
    "https://..."  — RDAP base URL of the authoritative server
    "whois.nic.xx" — WHOIS host on port 43 that answered

EXIT CODES
  0  At least one domain was available.
  1  All checked domains were taken (none available, no errors).
  2  At least one domain returned an error.

EXAMPLES
  Single check:
    vacant acme.dev

  Expand a name across TLDs:
    vacant --tld com,io,dev,sh acme

  Bulk check from file with DNS pre-filter and JSON output:
    vacant --file names.txt --dns --json

  Stdin pipe:
    cat names.txt | vacant --file -

NOTES
  - Some ccTLDs (e.g. .es) block public WHOIS; those will report errors.
  - RDAP/WHOIS only report registration state, not premium pricing.
  - Pass IDN/Unicode names as Punycode (xn--...).
  - IANA RDAP bootstrap is cached on disk for 24h.
`

type config struct {
	file         string
	tlds         string
	concurrency  int
	jsonOut      bool
	noColor      bool
	dnsPrefilter bool
}

func main() {
	var cfg config
	fs := flag.NewFlagSet("vacant", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {} // handled below so --help goes to stdout, errors to stderr

	fs.StringVar(&cfg.file, "file", "", "")
	fs.StringVar(&cfg.file, "f", "", "")
	fs.StringVar(&cfg.tlds, "tld", "", "")
	fs.StringVar(&cfg.tlds, "t", "", "")
	fs.IntVar(&cfg.concurrency, "concurrency", 20, "")
	fs.IntVar(&cfg.concurrency, "c", 20, "")
	fs.BoolVar(&cfg.jsonOut, "json", false, "")
	fs.BoolVar(&cfg.noColor, "no-color", false, "")
	fs.BoolVar(&cfg.dnsPrefilter, "dns", false, "")

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Print(usage)
			os.Exit(0)
		}
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	domains, err := collectDomains(cfg, fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if len(domains) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	reg, err := loadRegistry()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	exitCode := run(ctx, cfg, reg, domains)
	os.Exit(exitCode)
}

func collectDomains(cfg config, args []string) ([]string, error) {
	var names []string
	names = append(names, args...)

	if cfg.file != "" {
		var r *os.File
		if cfg.file == "-" {
			r = os.Stdin
		} else {
			f, err := os.Open(cfg.file)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			r = f
		}
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			names = append(names, line)
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}

	if cfg.tlds == "" {
		return dedupe(names), nil
	}

	var tlds []string
	for _, t := range strings.Split(cfg.tlds, ",") {
		t = strings.TrimSpace(strings.TrimPrefix(t, "."))
		if t != "" {
			tlds = append(tlds, t)
		}
	}

	var expanded []string
	for _, n := range names {
		if strings.Contains(n, ".") {
			expanded = append(expanded, n)
			continue
		}
		for _, t := range tlds {
			expanded = append(expanded, n+"."+t)
		}
	}
	return dedupe(expanded), nil
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func run(ctx context.Context, cfg config, reg *registry, domains []string) int {
	client := newClient()
	jobs := make(chan string)
	results := make(chan result)

	var wg sync.WaitGroup
	workers := cfg.concurrency
	if workers < 1 {
		workers = 1
	}
	if workers > len(domains) {
		workers = len(domains)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				results <- checkDomain(ctx, client, reg, d, cfg.dnsPrefilter)
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, d := range domains {
			select {
			case <-ctx.Done():
				return
			case jobs <- d:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var anyAvailable, anyError bool
	enc := json.NewEncoder(os.Stdout)
	for r := range results {
		switch r.Status {
		case statusAvailable.String():
			anyAvailable = true
		case statusError.String():
			anyError = true
		}
		if cfg.jsonOut {
			_ = enc.Encode(r)
		} else {
			printHuman(r, cfg.noColor)
		}
	}

	switch {
	case anyError:
		return 2
	case anyAvailable:
		return 0
	default:
		return 1
	}
}

func printHuman(r result, noColor bool) {
	var sym, color string
	switch r.Status {
	case statusAvailable.String():
		sym, color = "✓", "\033[32m"
	case statusTaken.String():
		sym, color = "✗", "\033[31m"
	case statusError.String():
		sym, color = "!", "\033[33m"
	default:
		sym, color = "?", "\033[90m"
	}
	reset := "\033[0m"
	if noColor {
		color, reset = "", ""
	}
	line := fmt.Sprintf("%s%s %-30s %s%s", color, sym, r.Domain, r.Status, reset)
	if r.Error != "" {
		line += "  " + r.Error
	}
	fmt.Println(line)
}
