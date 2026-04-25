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

// dnsHasNS returns true only when DoH definitively reports NS records for
// the domain. NXDOMAIN, empty answers, and errors all return false because
// they're inconclusive — a registered-but-undelegated domain has no NS yet.
func dnsHasNS(ctx context.Context, client *http.Client, domain string) (bool, error) {
	q := url.Values{}
	q.Set("name", domain)
	q.Set("type", "NS")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dohURL+"?"+q.Encode(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("doh status %d", resp.StatusCode)
	}

	var dr dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return false, err
	}
	if dr.Status != 0 {
		return false, nil
	}
	for _, a := range dr.Answer {
		if a.Type == 2 && a.Data != "" {
			return true, nil
		}
	}
	return false, nil
}
