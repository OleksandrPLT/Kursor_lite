package powerdns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// httpClient has a short timeout — this call never leaves 127.0.0.1,
// so anything slow means the service is stuck, not that a real network
// round-trip needs more time.
var httpClient = &http.Client{Timeout: 5 * time.Second}

func apiRequest(apiKey, method, path string, body any) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, apiBase+path, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("PowerDNS API unreachable (is it running?): %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return respBody, resp.StatusCode, nil
}

func apiError(status int, body []byte) error {
	var parsed struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &parsed) == nil && parsed.Error != "" {
		return fmt.Errorf("PowerDNS API (%d): %s", status, parsed.Error)
	}
	return fmt.Errorf("PowerDNS API (%d): %s", status, string(body))
}

// Zone is one authoritative zone PowerDNS is serving.
type Zone struct {
	Name string `json:"name"` // canonical, trailing dot
	Kind string `json:"kind"`
}

// Record is one RRset within a zone (PowerDNS groups same name+type
// values into one set — e.g. multiple A records for round-robin — but
// Kursor's UI only ever manages one value at a time, matching how
// internal/dns's simpler model presents records).
type Record struct {
	Name  string // canonical, trailing dot
	Type  string
	TTL   int
	Value string
}

// CreateZone provisions a new zone with an SOA and NS records pointing
// at the given nameservers — the exact records a registrar's "custom
// nameserver" delegation expects to find once it starts asking this
// server about the domain.
func CreateZone(apiKey, domain string, nameservers []string) error {
	ns := make([]string, 0, len(nameservers))
	for _, n := range nameservers {
		ns = append(ns, canonical(n))
	}
	body := map[string]any{
		"name":        canonical(domain),
		"kind":        "Native",
		"nameservers": ns,
	}
	respBody, status, err := apiRequest(apiKey, "POST", "/zones", body)
	if err != nil {
		return err
	}
	if status != http.StatusCreated {
		return apiError(status, respBody)
	}
	return nil
}

func DeleteZone(apiKey, domain string) error {
	respBody, status, err := apiRequest(apiKey, "DELETE", "/zones/"+canonical(domain), nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return apiError(status, respBody)
	}
	return nil
}

// ListZones returns every zone PowerDNS currently serves.
func ListZones(apiKey string) ([]Zone, error) {
	respBody, status, err := apiRequest(apiKey, "GET", "/zones", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, apiError(status, respBody)
	}
	var zones []Zone
	if err := json.Unmarshal(respBody, &zones); err != nil {
		return nil, err
	}
	return zones, nil
}

// zoneDetail mirrors just the fields Kursor reads out of PowerDNS's
// zone-detail response — its rrsets carry every record in the zone.
type zoneDetail struct {
	RRSets []struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		TTL     int    `json:"ttl"`
		Records []struct {
			Content string `json:"content"`
		} `json:"records"`
	} `json:"rrsets"`
}

// ListRecords returns every record in a zone, one Record per value
// (an RRset with 2 A values becomes 2 Records) — flattened for a simple
// table, the same shape internal/dns.Record already uses elsewhere in
// the UI.
func ListRecords(apiKey, domain string) ([]Record, error) {
	respBody, status, err := apiRequest(apiKey, "GET", "/zones/"+canonical(domain), nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, apiError(status, respBody)
	}
	var detail zoneDetail
	if err := json.Unmarshal(respBody, &detail); err != nil {
		return nil, err
	}
	var out []Record
	for _, rr := range detail.RRSets {
		for _, rec := range rr.Records {
			out = append(out, Record{Name: rr.Name, Type: rr.Type, TTL: rr.TTL, Value: rec.Content})
		}
	}
	return out, nil
}

// UpsertRecord replaces the RRset for (name, type) with a single value
// — Kursor's UI manages one value per name+type at a time; PowerDNS's
// PATCH "REPLACE" changetype does exactly that atomically.
func UpsertRecord(apiKey, domain, name, recordType string, ttl int, value string) error {
	body := map[string]any{
		"rrsets": []map[string]any{{
			"name":       canonical(name),
			"type":       recordType,
			"ttl":        ttl,
			"changetype": "REPLACE",
			"records":    []map[string]any{{"content": value, "disabled": false}},
		}},
	}
	respBody, status, err := apiRequest(apiKey, "PATCH", "/zones/"+canonical(domain), body)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return apiError(status, respBody)
	}
	return nil
}

// DeleteRecord removes an entire RRset (name+type) from a zone.
func DeleteRecord(apiKey, domain, name, recordType string) error {
	body := map[string]any{
		"rrsets": []map[string]any{{
			"name":       canonical(name),
			"type":       recordType,
			"changetype": "DELETE",
		}},
	}
	respBody, status, err := apiRequest(apiKey, "PATCH", "/zones/"+canonical(domain), body)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return apiError(status, respBody)
	}
	return nil
}
