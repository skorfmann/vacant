package main

import "strings"

// parkingHosts maps the suffix of a nameserver hostname to the marketplace
// or parking service it belongs to. Matched case-insensitively against NS
// records to detect domains that are registered but listed for resale.
//
// Entries here are limited to high-confidence aftermarket signals.
// Shared-DNS providers (Cloudflare, NameSilo, registrar default NS, etc.)
// are deliberately excluded — they're not reliable for-sale indicators.
var parkingHosts = map[string]string{
	"sedoparking.com":        "Sedo",
	"parking.sedo.com":       "Sedo",
	"dan.com":                "Dan",
	"undeveloped.com":        "Dan",
	"afternic.com":           "Afternic",
	"parkingcrew.net":        "ParkingCrew",
	"bodis.com":              "Bodis",
	"uniregistrymarket.link": "Uniregistry",
	"cashparking.com":        "GoDaddy CashParking",
	"above.com":              "Above",
	"voodoo.com":             "Voodoo",
	"internettraffic.com":    "InternetTraffic",
	"domainsponsor.com":      "DomainSponsor",
	"hugedomains.com":        "HugeDomains",
	"buydomains.com":         "BuyDomains",
	"smartname.com":          "SmartName",
	"parkingpanel.com":       "ParkingPanel",
	"trafficnames.com":       "TrafficNames",
	"name-services.com":      "Atom",
	"atom.com":               "Atom",
}

func detectMarketplace(nsRecords []string) string {
	for _, ns := range nsRecords {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ns), "."))
		for suffix, market := range parkingHosts {
			if host == suffix || strings.HasSuffix(host, "."+suffix) {
				return market
			}
		}
	}
	return ""
}
