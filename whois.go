package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	ianaWhois              = "whois.iana.org:43"
	whoisTimeout           = 10 * time.Second
	whoisPerHostConcurrent = 2
)

var (
	whoisCacheMu sync.RWMutex
	whoisCache   = map[string]string{}

	hostLimiterMu sync.Mutex
	hostLimiters  = map[string]chan struct{}{}
)

func acquireHost(ctx context.Context, host string) error {
	hostLimiterMu.Lock()
	sem, ok := hostLimiters[host]
	if !ok {
		sem = make(chan struct{}, whoisPerHostConcurrent)
		hostLimiters[host] = sem
	}
	hostLimiterMu.Unlock()

	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseHost(host string) {
	hostLimiterMu.Lock()
	sem := hostLimiters[host]
	hostLimiterMu.Unlock()
	if sem != nil {
		<-sem
	}
}

// availabilityMarkers are case-insensitive substrings that indicate a domain
// is unregistered. Compiled from observed responses across many ccTLD
// registries — false positives here cause us to report "available" for a
// taken domain, so prefer specificity.
var availabilityMarkers = []string{
	"no match for",
	"not found",
	"no entries found",
	"no data found",
	"no object found",
	"is available for",
	"available for registration",
	"domain not found",
	"status: free",
	"status: available",
	"status:	available",
	"% no match",
	"object does not exist",
	"domain status: no object found",
	"no information available",
}

func checkWhois(ctx context.Context, domain string) (status, string, error) {
	tld, err := tldOf(domain)
	if err != nil {
		return statusError, "", err
	}
	server, err := discoverWhoisServer(ctx, tld)
	if err != nil {
		return statusError, "", err
	}
	resp, err := whoisQuery(ctx, server, domain)
	if err != nil {
		return statusError, server, err
	}
	return parseAvailability(resp), server, nil
}

func discoverWhoisServer(ctx context.Context, tld string) (string, error) {
	whoisCacheMu.RLock()
	if s, ok := whoisCache[tld]; ok {
		whoisCacheMu.RUnlock()
		if s == "" {
			return "", fmt.Errorf("no WHOIS server for .%s", tld)
		}
		return s, nil
	}
	whoisCacheMu.RUnlock()

	resp, err := whoisQuery(ctx, ianaWhois, tld)
	if err != nil {
		return "", fmt.Errorf("iana lookup: %w", err)
	}
	server := parseWhoisServer(resp)

	whoisCacheMu.Lock()
	whoisCache[tld] = server
	whoisCacheMu.Unlock()

	if server == "" {
		return "", fmt.Errorf("no WHOIS server for .%s", tld)
	}
	return server, nil
}

func parseWhoisServer(resp string) string {
	sc := bufio.NewScanner(strings.NewReader(resp))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "%") || line == "" {
			continue
		}
		lower := strings.ToLower(line)
		for _, key := range []string{"refer:", "whois:"} {
			if strings.HasPrefix(lower, key) {
				v := strings.TrimSpace(line[len(key):])
				if v != "" {
					return v
				}
			}
		}
	}
	return ""
}

func whoisQuery(ctx context.Context, server, query string) (string, error) {
	if !strings.Contains(server, ":") {
		server = server + ":43"
	}
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		host = server
	}
	if err := acquireHost(ctx, host); err != nil {
		return "", err
	}
	defer releaseHost(host)

	d := net.Dialer{Timeout: whoisTimeout}
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	deadline := time.Now().Add(whoisTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", err
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func parseAvailability(resp string) status {
	lower := strings.ToLower(resp)
	for _, m := range availabilityMarkers {
		if strings.Contains(lower, m) {
			return statusAvailable
		}
	}
	// A non-empty response with no availability marker almost always means
	// there's a registration record present.
	if strings.TrimSpace(resp) == "" {
		return statusUnknown
	}
	return statusTaken
}
