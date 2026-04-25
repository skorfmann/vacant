# vacant

A small Go CLI that checks whether domain names are available for registration.

It uses RDAP (the modern WHOIS replacement) as the primary lookup, with a port-43 WHOIS fallback for ccTLDs that don't yet support RDAP, and an optional DNS-over-HTTPS pre-filter for fast bulk scans.

## Install

```sh
go install ./...
```

Or build a local binary:

```sh
go build -o vacant .
```

Requires Go 1.25+. No external dependencies.

## Usage

```sh
vacant acme.dev                          # single domain
vacant acme.dev acme.io claude.ai        # several at once
vacant --tld com,io,dev,sh acme          # expand a bare name across TLDs
vacant --file names.txt                  # newline-separated list
cat names.txt | vacant --file -          # stdin
vacant --dns --json --file names.txt     # bulk + DNS pre-filter + machine output
```

Run `vacant --help` for the full reference (flags, status values, exit codes, JSON schema).

### Output

Human-readable by default:

```
✓ acme.dev                       available
✗ google.com                     taken
! acme.es                        error  connection refused
```

NDJSON with `--json`:

```json
{"domain":"acme.dev","status":"available","server":"https://pubapi.registry.google/rdap"}
{"domain":"google.com","status":"taken","server":"dns"}
```

## How it works

Three lookup tiers. The first one to give a definite answer wins.

1. **DNS pre-filter (optional, `--dns`).** Queries NS records via Cloudflare DoH. If records exist, the domain is taken — skip RDAP/WHOIS. NXDOMAIN and empty answers are inconclusive (a registered-but-undelegated domain has no NS), so they fall through.
2. **RDAP.** Looks up the authoritative RDAP server for the TLD via the IANA bootstrap file (`https://data.iana.org/rdap/dns.json`, cached on disk for 24h), then queries `GET {base}/domain/{name}`. `200` = taken, `404` = available.
3. **WHOIS fallback.** For TLDs without RDAP (`.es`, `.eu`, `.jp`, `.co`, and ~185 others), discovers the authoritative WHOIS server via `whois.iana.org` and queries it on port 43. The response is parsed heuristically for availability markers ("no match", "not found", "status: free", etc.).

WHOIS connections are capped at 2 concurrent per registry host to stay within typical rate limits — the `--concurrency` flag governs the overall worker pool, not per-host throttling.

## For agents

`vacant` is built to be driven by other programs. Use `--json` for parseable output and check the exit code for batch-level signals.

**JSON schema (one object per line):**

| Field    | Type   | Notes                                                                |
| -------- | ------ | -------------------------------------------------------------------- |
| `domain` | string | The queried domain, lowercased.                                      |
| `status` | string | `available` \| `taken` \| `error` \| `unknown`.                      |
| `server` | string | Source that answered: `dns`, an RDAP URL, or a WHOIS hostname.       |
| `error`  | string | Present only when `status=error`. Human-readable error message.      |

**Exit codes:**

| Code | Meaning                                                  |
| ---- | -------------------------------------------------------- |
| `0`  | At least one domain was available.                       |
| `1`  | All checked domains were taken (none available, no errors). |
| `2`  | At least one domain returned an error.                   |

The exit code reflects the batch as a whole. For per-domain decisions, parse `status` from the JSON output.

## Limitations

- Some ccTLD registries (notably `.es`) block public port-43 WHOIS and will return errors. Use a registrar API for those.
- RDAP and WHOIS only report registration state. They don't surface premium-domain pricing or registry-reserved-name status — an "available" domain may still be priced beyond a normal registration fee or held back by the registry.
- Pass IDN/Unicode names as Punycode (`xn--...`). No automatic conversion.
- The IANA bootstrap file is cached at `$XDG_CACHE_HOME/vacant/dns.json` (or `~/Library/Caches/vacant/dns.json` on macOS) for 24 hours.

## Layout

```
main.go        flag parsing, worker pool, output formatting
bootstrap.go   IANA RDAP bootstrap fetch, cache, TLD -> server lookup
check.go       per-domain orchestration (DNS -> RDAP -> WHOIS)
rdap.go        RDAP HTTPS query (in check.go)
whois.go       WHOIS port-43 query, IANA discovery, per-host limiter, parser
dns.go         DoH NS query against Cloudflare 1.1.1.1
```
