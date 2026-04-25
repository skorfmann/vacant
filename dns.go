package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const dohURL = "https://cloudflare-dns.com/dns-query"

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// dnsLookupNS returns NS record values for a domain via DoH. NXDOMAIN and
// empty answers return (nil, nil) — registered-but-undelegated domains have
// no NS, so absence is inconclusive for availability.
func dnsLookupNS(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	q := url.Values{}
	q.Set("name", domain)
	q.Set("type", "NS")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dohURL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}

	var dr dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil, err
	}
	if dr.Status != 0 {
		return nil, nil
	}
	var out []string
	for _, a := range dr.Answer {
		if a.Type == 2 && a.Data != "" {
			out = append(out, a.Data)
		}
	}
	return out, nil
}
