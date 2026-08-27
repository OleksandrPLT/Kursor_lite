// Package netcheck answers "is this domain actually pointed at this
// server" — real DNS lookups (Go's own resolver, whatever /etc/resolv.conf
// says) and a real outbound call to learn this box's own public IP
// (a box behind NAT/a cloud provider's network can't reliably learn its
// own internet-facing address purely from its local interfaces — asking
// an external echo service is the only way that actually works, the
// same reasoning internal/version has for calling the GitHub API rather
// than trusting anything local).
package netcheck

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// lookupTimeout bounds every DNS/HTTP call here — this package is
// called from request handlers rendering a settings page, so a slow or
// blackholed DNS server must never hang the whole page indefinitely.
const lookupTimeout = 5 * time.Second

// ResolveA returns domain's IPv4 addresses (A records) — empty, no
// error if the name simply doesn't resolve (NXDOMAIN and "no
// addresses" are the normal, expected case while a domain hasn't been
// pointed here yet, not failures worth surfacing as errors).
func ResolveA(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	var r net.Resolver
	addrs, err := r.LookupHost(ctx, domain)
	if err != nil {
		if isNotFoundDNSErr(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, a := range addrs {
		if strings.Contains(a, ":") {
			continue // IPv6 — this func is deliberately A-only, callers that want AAAA too can extend later
		}
		out = append(out, a)
	}
	return out, nil
}

// ResolveNS returns domain's authoritative nameservers, host names
// with the trailing root dot trimmed (net.LookupNS keeps it, e.g.
// "ns1.example.com.") since every caller here wants to compare/display
// it as a normal hostname.
func ResolveNS(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	var r net.Resolver
	nss, err := r.LookupNS(ctx, domain)
	if err != nil {
		if isNotFoundDNSErr(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(nss))
	for _, ns := range nss {
		out = append(out, strings.TrimSuffix(ns.Host, "."))
	}
	return out, nil
}

func isNotFoundDNSErr(err error) bool {
	dnsErr, ok := err.(*net.DNSError)
	return ok && dnsErr.IsNotFound
}

// publicIPServices are tried in order — plain-text "what's my IP"
// endpoints, first one to answer wins. More than one, because any
// single one of these can be down or rate-limiting without that
// meaning anything about this box's own connectivity.
var publicIPServices = []string{
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
	"https://icanhazip.com",
}

// PublicIP asks an external echo service what address this box is
// reaching the internet from — the only reliable way to learn a
// server's own internet-facing IP, since a box behind NAT/a cloud
// provider's virtual network has no local interface that says so.
func PublicIP() (string, error) {
	client := &http.Client{Timeout: lookupTimeout}
	var lastErr error
	for _, url := range publicIPServices {
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip, nil
		}
		lastErr = &net.AddrError{Err: "not a valid IP", Addr: ip}
	}
	return "", lastErr
}

// PointsHere reports whether any of domain's A records match this
// box's own public IP — the actual "is my domain pointed at my
// server" answer the panel settings page shows.
func PointsHere(domain, publicIP string) (bool, []string, error) {
	ips, err := ResolveA(domain)
	if err != nil {
		return false, nil, err
	}
	for _, ip := range ips {
		if ip == publicIP {
			return true, ips, nil
		}
	}
	return false, ips, nil
}
