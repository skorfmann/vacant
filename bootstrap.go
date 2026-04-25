package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	bootstrapURL = "https://data.iana.org/rdap/dns.json"
	cacheTTL     = 24 * time.Hour
)

type bootstrapFile struct {
	Services [][]json.RawMessage `json:"services"`
	Version  string              `json:"version"`
}

type registry struct {
	servers map[string][]string
}

func loadRegistry() (*registry, error) {
	data, err := readCache()
	if err != nil {
		data, err = fetchBootstrap()
		if err != nil {
			return nil, fmt.Errorf("fetch bootstrap: %w", err)
		}
		_ = writeCache(data)
	}
	return parseBootstrap(data)
}

func parseBootstrap(data []byte) (*registry, error) {
	var bf bootstrapFile
	if err := json.Unmarshal(data, &bf); err != nil {
		return nil, fmt.Errorf("parse bootstrap: %w", err)
	}
	r := &registry{servers: make(map[string][]string)}
	for _, svc := range bf.Services {
		if len(svc) < 2 {
			continue
		}
		var tlds, urls []string
		if err := json.Unmarshal(svc[0], &tlds); err != nil {
			continue
		}
		if err := json.Unmarshal(svc[1], &urls); err != nil {
			continue
		}
		for _, tld := range tlds {
			r.servers[strings.ToLower(tld)] = urls
		}
	}
	return r, nil
}

var errNoRDAPServer = errors.New("no RDAP server for TLD")

func (r *registry) lookup(domain string) ([]string, error) {
	tld, err := tldOf(domain)
	if err != nil {
		return nil, err
	}
	urls, ok := r.servers[tld]
	if !ok {
		return nil, fmt.Errorf("%w: .%s", errNoRDAPServer, tld)
	}
	return urls, nil
}

func tldOf(domain string) (string, error) {
	parts := strings.Split(strings.ToLower(strings.TrimSuffix(domain, ".")), ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid domain: %s", domain)
	}
	return parts[len(parts)-1], nil
}

func cachePath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "vacant", "dns.json"), nil
}

func readCache() ([]byte, error) {
	p, err := cachePath()
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if time.Since(info.ModTime()) > cacheTTL {
		return nil, errors.New("cache expired")
	}
	return os.ReadFile(p)
}

func writeCache(data []byte) error {
	p, err := cachePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}

func fetchBootstrap() ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(bootstrapURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bootstrap status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
