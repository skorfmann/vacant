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
	statusError
)

func (s status) String() string {
	switch s {
	case statusAvailable:
		return "available"
	case statusTaken:
		return "taken"
	case statusError:
		return "error"
	default:
		return "unknown"
	}
}

type result struct {
	Domain string `json:"domain"`
	Status string `json:"status"`
	Server string `json:"server,omitempty"`
	Error  string `json:"error,omitempty"`
}

func checkDomain(ctx context.Context, client *http.Client, reg *registry, domain string, dnsPrefilter bool) result {
	domain = strings.ToLower(strings.TrimSpace(domain))
	res := result{Domain: domain}

	if dnsPrefilter {
		if has, err := dnsHasNS(ctx, client, domain); err == nil && has {
			res.Status = statusTaken.String()
			res.Server = "dns"
			return res
		}
	}

	servers, err := reg.lookup(domain)
	if err != nil {
		if errors.Is(err, errNoRDAPServer) {
			st, server, werr := checkWhois(ctx, domain)
			res.Status = st.String()
			res.Server = server
			if werr != nil {
				res.Error = werr.Error()
			}
			return res
		}
		res.Status = statusError.String()
		res.Error = err.Error()
		return res
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
		return res
	}
	res.Status = statusError.String()
	if lastErr != nil {
		res.Error = lastErr.Error()
	}
	return res
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
