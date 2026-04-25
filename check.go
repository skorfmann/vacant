package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type status int

const (
	statusUnknown status = iota
	statusAvailable
	statusTaken
	statusForSale
	statusError
)

func (s status) String() string {
	switch s {
	case statusAvailable:
		return "available"
	case statusTaken:
		return "taken"
	case statusForSale:
		return "for-sale"
	case statusError:
		return "error"
	default:
		return "unknown"
	}
}

type result struct {
	Domain      string `json:"domain"`
	Status      string `json:"status"`
	Server      string `json:"server,omitempty"`
	Marketplace string `json:"marketplace,omitempty"`
	Error       string `json:"error,omitempty"`
}

type checkOpts struct {
	dnsPrefilter bool
	aftermarket  bool
}

func checkDomain(ctx context.Context, client *http.Client, reg *registry, domain string, opts checkOpts) result {
	domain = strings.ToLower(strings.TrimSpace(domain))
	res := result{Domain: domain}

	var nsRecords []string
	nsFetched := false

	if opts.dnsPrefilter {
		ns, err := dnsLookupNS(ctx, client, domain)
		if err == nil {
			nsRecords = ns
			nsFetched = true
			if len(ns) > 0 {
				res.Status = statusTaken.String()
				res.Server = "dns"
				applyAftermarket(&res, opts, ns)
				return res
			}
		}
	}

	resolveStatus(ctx, client, reg, domain, &res)

	if opts.aftermarket && res.Status == statusTaken.String() {
		if !nsFetched {
			nsRecords, _ = dnsLookupNS(ctx, client, domain)
		}
		applyAftermarket(&res, opts, nsRecords)
	}
	return res
}

func resolveStatus(ctx context.Context, client *http.Client, reg *registry, domain string, res *result) {
	servers, err := reg.lookup(domain)
	if err != nil {
		if errors.Is(err, errNoRDAPServer) {
			st, server, werr := checkWhois(ctx, domain)
			res.Status = st.String()
			res.Server = server
			if werr != nil {
				res.Error = werr.Error()
			}
			return
		}
		res.Status = statusError.String()
		res.Error = err.Error()
		return
	}

	var lastErr error
	for _, base := range servers {
		base = strings.TrimSuffix(base, "/")
		url := fmt.Sprintf("%s/domain/%s", base, domain)
		st, err := queryRDAP(ctx, client, url)
		if err != nil {
			lastErr = err
			continue
		}
		res.Status = st.String()
		res.Server = base
		return
	}
	res.Status = statusError.String()
	if lastErr != nil {
		res.Error = lastErr.Error()
	}
}

func applyAftermarket(res *result, opts checkOpts, ns []string) {
	if !opts.aftermarket {
		return
	}
	if mp := detectMarketplace(ns); mp != "" {
		res.Status = statusForSale.String()
		res.Marketplace = mp
	}
}

func queryRDAP(ctx context.Context, client *http.Client, url string) (status, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return statusUnknown, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "vacant/0.1 (+https://github.com/vacant)")

	resp, err := client.Do(req)
	if err != nil {
		return statusUnknown, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return statusTaken, nil
	case http.StatusNotFound:
		return statusAvailable, nil
	case http.StatusTooManyRequests:
		return statusUnknown, fmt.Errorf("rate limited (429)")
	default:
		return statusUnknown, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
}

func newClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}
