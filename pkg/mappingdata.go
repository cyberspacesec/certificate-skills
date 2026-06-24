package pkg

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// DedupMethod controls which certificate identity is used for de-duplication.
type DedupMethod int

const (
	DedupBySPKI DedupMethod = iota
	DedupByCertFingerprint
	DedupBySerialIssuer
)

// DedupKey is one normalized identity key for a certificate.
type DedupKey struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// DedupResult summarizes a de-duplication run.
type DedupResult struct {
	Total      int        `json:"total"`
	Unique     int        `json:"unique"`
	Duplicates int        `json:"duplicates"`
	DupKeys    []DedupKey `json:"duplicate_keys,omitempty"`
}

// CertDedup is a concurrency-safe in-memory certificate de-duplication engine.
type CertDedup struct {
	mu      sync.Mutex
	seen    map[DedupKey]bool
	methods []DedupMethod
	stats   DedupResult
}

// NewCertDedup creates a de-duplication engine. If no method is provided,
// certificate SHA-256 and SPKI SHA-256 are both used.
func NewCertDedup(methods ...DedupMethod) *CertDedup {
	if len(methods) == 0 {
		methods = []DedupMethod{DedupByCertFingerprint, DedupBySPKI}
	}
	return &CertDedup{
		seen:    make(map[DedupKey]bool),
		methods: methods,
	}
}

// IsDuplicate reports whether any configured identity key is already known.
func (d *CertDedup) IsDuplicate(cert *x509.Certificate) (bool, DedupKey, error) {
	keys, err := dedupKeys(cert, d.methods)
	if err != nil {
		return false, DedupKey{}, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	for _, key := range keys {
		if d.seen[key] {
			return true, key, nil
		}
	}
	return false, DedupKey{}, nil
}

// Add adds a certificate and returns false if it was already present.
func (d *CertDedup) Add(cert *x509.Certificate) (bool, DedupKey, error) {
	keys, err := dedupKeys(cert, d.methods)
	if err != nil {
		return false, DedupKey{}, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.stats.Total++
	for _, key := range keys {
		if d.seen[key] {
			d.stats.Duplicates++
			d.stats.DupKeys = append(d.stats.DupKeys, key)
			return false, key, nil
		}
	}
	for _, key := range keys {
		d.seen[key] = true
	}
	d.stats.Unique++
	return true, DedupKey{}, nil
}

// AddBatch adds all certificates to the engine.
func (d *CertDedup) AddBatch(certs []*x509.Certificate) (unique int, duplicates int, err error) {
	for _, cert := range certs {
		added, _, addErr := d.Add(cert)
		if addErr != nil {
			return unique, duplicates, addErr
		}
		if added {
			unique++
		} else {
			duplicates++
		}
	}
	return unique, duplicates, nil
}

// Stats returns a point-in-time copy of de-duplication counters.
func (d *CertDedup) Stats() DedupResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	stats := d.stats
	stats.DupKeys = append([]DedupKey(nil), d.stats.DupKeys...)
	return stats
}

// Reset clears all known keys and counters.
func (d *CertDedup) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = make(map[DedupKey]bool)
	d.stats = DedupResult{}
}

// Size returns the number of known identity keys.
func (d *CertDedup) Size() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}

// DedupCertificates performs one-shot de-duplication.
func DedupCertificates(certs []*x509.Certificate, method DedupMethod) ([]*x509.Certificate, DedupResult, error) {
	engine := NewCertDedup(method)
	unique := make([]*x509.Certificate, 0, len(certs))
	for _, cert := range certs {
		added, _, err := engine.Add(cert)
		if err != nil {
			return nil, engine.Stats(), err
		}
		if added {
			unique = append(unique, cert)
		}
	}
	return unique, engine.Stats(), nil
}

func dedupKeys(cert *x509.Certificate, methods []DedupMethod) ([]DedupKey, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}
	keys := make([]DedupKey, 0, len(methods))
	for _, method := range methods {
		key, err := computeDedupKey(cert, method)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func computeDedupKey(cert *x509.Certificate, method DedupMethod) (DedupKey, error) {
	switch method {
	case DedupBySPKI:
		h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		return DedupKey{Type: "spki_sha256", Value: hex.EncodeToString(h[:])}, nil
	case DedupByCertFingerprint:
		h := sha256.Sum256(cert.Raw)
		return DedupKey{Type: "cert_sha256", Value: hex.EncodeToString(h[:])}, nil
	case DedupBySerialIssuer:
		h := sha256.Sum256([]byte(cert.SerialNumber.String() + "\x00" + cert.Issuer.String()))
		return DedupKey{Type: "serial_issuer", Value: hex.EncodeToString(h[:])}, nil
	default:
		return DedupKey{}, fmt.Errorf("unknown dedup method: %d", method)
	}
}

// NormalizedSubject is a canonicalized certificate subject useful for grouping.
type NormalizedSubject struct {
	CommonName         string   `json:"common_name,omitempty"`
	Organization       string   `json:"organization,omitempty"`
	OrganizationalUnit string   `json:"organizational_unit,omitempty"`
	Country            string   `json:"country,omitempty"`
	Province           string   `json:"province,omitempty"`
	Locality           string   `json:"locality,omitempty"`
	DNSNames           []string `json:"dns_names,omitempty"`
	IPAddresses        []string `json:"ip_addresses,omitempty"`
	OrgKey             string   `json:"org_key,omitempty"`
}

// NormalizeCertificateSubject canonicalizes the subject and SANs of a certificate.
func NormalizeCertificateSubject(cert *x509.Certificate) NormalizedSubject {
	if cert == nil {
		return NormalizedSubject{}
	}
	ns := NormalizedSubject{
		CommonName:         normalizeName(cert.Subject.CommonName),
		Organization:       normalizeName(firstString(cert.Subject.Organization)),
		OrganizationalUnit: normalizeName(firstString(cert.Subject.OrganizationalUnit)),
		Country:            strings.ToUpper(normalizeName(firstString(cert.Subject.Country))),
		Province:           normalizeName(firstString(cert.Subject.Province)),
		Locality:           normalizeName(firstString(cert.Subject.Locality)),
		DNSNames:           normalizeDomains(cert.DNSNames),
		IPAddresses:        normalizeIPs(cert.IPAddresses),
	}
	ns.OrgKey = organizationKey(ns.Organization)
	if ns.OrgKey == "" {
		ns.OrgKey = organizationKey(ns.CommonName)
	}
	return ns
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func normalizeName(s string) string {
	fields := strings.Fields(strings.TrimSpace(s))
	return strings.Join(fields, " ")
}

func organizationKey(s string) string {
	s = strings.ToLower(normalizeName(s))
	s = strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsSpace(r) {
			return r
		}
		return ' '
	}, s)
	stop := map[string]bool{
		"inc": true, "llc": true, "ltd": true, "limited": true, "corp": true,
		"corporation": true, "co": true, "company": true, "gmbh": true, "sa": true,
	}
	var kept []string
	for _, part := range strings.Fields(s) {
		if !stop[part] {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, " ")
}

func normalizeDomains(values []string) []string {
	set := make(map[string]bool)
	for _, value := range values {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
		if name != "" {
			set[name] = true
		}
	}
	return sortedKeys(set)
}

func normalizeIPs(values []net.IP) []string {
	set := make(map[string]bool)
	for _, ip := range values {
		if ip != nil {
			set[ip.String()] = true
		}
	}
	return sortedKeys(set)
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// CertificateAsset carries a certificate plus external mapping metadata.
type CertificateAsset struct {
	Target       ScanTarget          `json:"target"`
	Cert         *x509.Certificate   `json:"-"`
	Chain        []*x509.Certificate `json:"-"`
	ASN          int                 `json:"asn,omitempty"`
	ASName       string              `json:"as_name,omitempty"`
	Organization string              `json:"organization,omitempty"`
	Source       string              `json:"source,omitempty"`
	ObservedAt   time.Time           `json:"observed_at"`
}

// AggregateEntry is a ranked aggregate bucket.
type AggregateEntry struct {
	Key        string   `json:"key"`
	Count      int      `json:"count"`
	Percentage float64  `json:"percentage"`
	Examples   []string `json:"examples,omitempty"`
}

// AggregateResult contains common certificate mapping aggregations.
type AggregateResult struct {
	Total     int              `json:"total"`
	ByOrg     []AggregateEntry `json:"by_org,omitempty"`
	ByCountry []AggregateEntry `json:"by_country,omitempty"`
	ByIssuer  []AggregateEntry `json:"by_issuer,omitempty"`
	ByASN     []AggregateEntry `json:"by_asn,omitempty"`
	BySPKI    []AggregateEntry `json:"by_spki,omitempty"`
	ByCert    []AggregateEntry `json:"by_cert,omitempty"`
}

// AggregateCertificates aggregates parsed certificates without external asset metadata.
func AggregateCertificates(certs []*x509.Certificate) AggregateResult {
	assets := make([]CertificateAsset, 0, len(certs))
	for _, cert := range certs {
		assets = append(assets, CertificateAsset{Cert: cert})
	}
	return AggregateCertificateAssets(assets)
}

// AggregateCertificateAssets aggregates certificates and optional ASN/asset metadata.
func AggregateCertificateAssets(assets []CertificateAsset) AggregateResult {
	b := newAggregateBuilder(len(assets))
	for _, asset := range assets {
		if asset.Cert == nil {
			continue
		}
		cert := asset.Cert
		ns := NormalizeCertificateSubject(cert)
		org := ns.OrgKey
		if asset.Organization != "" {
			org = organizationKey(asset.Organization)
		}
		b.add("org", org, cert.Subject.CommonName)
		b.add("country", ns.Country, cert.Subject.CommonName)
		b.add("issuer", normalizeName(cert.Issuer.CommonName), cert.Subject.CommonName)
		if asset.ASN > 0 {
			asKey := fmt.Sprintf("AS%d", asset.ASN)
			if asset.ASName != "" {
				asKey += " " + normalizeName(asset.ASName)
			}
			b.add("asn", asKey, cert.Subject.CommonName)
		}
		b.add("spki", computeHashHex(cert.RawSubjectPublicKeyInfo), cert.Subject.CommonName)
		b.add("cert", computeHashHex(cert.Raw), cert.Subject.CommonName)
	}
	return AggregateResult{
		Total:     b.total,
		ByOrg:     b.entries("org"),
		ByCountry: b.entries("country"),
		ByIssuer:  b.entries("issuer"),
		ByASN:     b.entries("asn"),
		BySPKI:    b.entries("spki"),
		ByCert:    b.entries("cert"),
	}
}

type aggregateBuilder struct {
	total   int
	counts  map[string]map[string]int
	samples map[string]map[string]map[string]bool
}

func newAggregateBuilder(total int) *aggregateBuilder {
	return &aggregateBuilder{
		total:   total,
		counts:  make(map[string]map[string]int),
		samples: make(map[string]map[string]map[string]bool),
	}
}

func (b *aggregateBuilder) add(kind, key, sample string) {
	if key == "" {
		key = "unknown"
	}
	if b.counts[kind] == nil {
		b.counts[kind] = make(map[string]int)
		b.samples[kind] = make(map[string]map[string]bool)
	}
	b.counts[kind][key]++
	if sample != "" {
		if b.samples[kind][key] == nil {
			b.samples[kind][key] = make(map[string]bool)
		}
		if len(b.samples[kind][key]) < 5 {
			b.samples[kind][key][sample] = true
		}
	}
}

func (b *aggregateBuilder) entries(kind string) []AggregateEntry {
	var entries []AggregateEntry
	for key, count := range b.counts[kind] {
		entry := AggregateEntry{Key: key, Count: count, Examples: sortedKeys(b.samples[kind][key])}
		if b.total > 0 {
			entry.Percentage = float64(count) * 100 / float64(b.total)
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count == entries[j].Count {
			return entries[i].Key < entries[j].Key
		}
		return entries[i].Count > entries[j].Count
	})
	return entries
}

func computeHashHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// CertCluster groups related certificates by shared identity or similarity.
type CertCluster struct {
	ID          string   `json:"id"`
	Reason      string   `json:"reason"`
	CertIndexes []int    `json:"cert_indexes"`
	Subjects    []string `json:"subjects,omitempty"`
}

// CertClusterResult contains certificate clusters and singleton indexes.
type CertClusterResult struct {
	Clusters   []CertCluster `json:"clusters"`
	Singletons []int         `json:"singletons,omitempty"`
}

// ClusterCertificates groups certificates by SPKI, organization, issuer, and SAN overlap.
func ClusterCertificates(certs []*x509.Certificate, sanOverlapThreshold float64) CertClusterResult {
	if sanOverlapThreshold <= 0 {
		sanOverlapThreshold = 0.5
	}
	parent := make([]int, len(certs))
	reason := make(map[int]string)
	for i := range parent {
		parent[i] = i
	}
	find := func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(a, b int, why string) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[rb] = ra
			reason[ra] = why
		}
	}

	for i := 0; i < len(certs); i++ {
		for j := i + 1; j < len(certs); j++ {
			if certs[i] == nil || certs[j] == nil {
				continue
			}
			switch {
			case computeHashHex(certs[i].RawSubjectPublicKeyInfo) == computeHashHex(certs[j].RawSubjectPublicKeyInfo):
				union(i, j, "shared_spki")
			case NormalizeCertificateSubject(certs[i]).OrgKey != "" &&
				NormalizeCertificateSubject(certs[i]).OrgKey == NormalizeCertificateSubject(certs[j]).OrgKey &&
				certs[i].Issuer.CommonName == certs[j].Issuer.CommonName:
				union(i, j, "same_org_and_issuer")
			case sanJaccard(certs[i].DNSNames, certs[j].DNSNames) >= sanOverlapThreshold:
				union(i, j, "san_overlap")
			}
		}
	}

	groups := make(map[int][]int)
	for i := range certs {
		groups[find(i)] = append(groups[find(i)], i)
	}

	result := CertClusterResult{
		Clusters:   make([]CertCluster, 0),
		Singletons: make([]int, 0),
	}
	for root, idxs := range groups {
		if len(idxs) == 1 {
			result.Singletons = append(result.Singletons, idxs[0])
			continue
		}
		var subjects []string
		for _, idx := range idxs {
			if certs[idx] != nil {
				subjects = append(subjects, certs[idx].Subject.String())
			}
		}
		sort.Strings(subjects)
		result.Clusters = append(result.Clusters, CertCluster{
			ID:          fmt.Sprintf("cluster-%d", root),
			Reason:      reason[root],
			CertIndexes: idxs,
			Subjects:    subjects,
		})
	}
	sort.Slice(result.Clusters, func(i, j int) bool {
		return result.Clusters[i].ID < result.Clusters[j].ID
	})
	sort.Ints(result.Singletons)
	return result
}

func sanJaccard(a, b []string) float64 {
	as, bs := make(map[string]bool), make(map[string]bool)
	for _, name := range normalizeDomains(a) {
		as[name] = true
	}
	for _, name := range normalizeDomains(b) {
		bs[name] = true
	}
	if len(as) == 0 && len(bs) == 0 {
		return 0
	}
	intersection := 0
	for name := range as {
		if bs[name] {
			intersection++
		}
	}
	union := len(as) + len(bs) - intersection
	return float64(intersection) / float64(union)
}

// OfflineParseResult is one parsed certificate file or stream record.
type OfflineParseResult struct {
	Source       string              `json:"source"`
	Certificates []*x509.Certificate `json:"-"`
	Count        int                 `json:"count"`
	Error        error               `json:"-"`
	ErrorMessage string              `json:"error,omitempty"`
}

// BatchParseConfig controls offline parsing concurrency.
type BatchParseConfig struct {
	Concurrency int `json:"concurrency"`
}

// ParseCertificatesFromBytes parses one DER certificate or one or more PEM certificates.
func ParseCertificatesFromBytes(data []byte) ([]*x509.Certificate, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty certificate data")
	}

	var certs []*x509.Certificate
	rest := trimmed
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
		rest = remaining
	}
	if len(certs) > 0 {
		return certs, nil
	}

	cert, err := x509.ParseCertificate(trimmed)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}

// BatchParseCertificateFiles parses many certificate files concurrently.
func BatchParseCertificateFiles(ctx context.Context, paths []string, config BatchParseConfig) ([]OfflineParseResult, error) {
	if config.Concurrency <= 0 {
		config.Concurrency = 16
	}
	results := make([]OfflineParseResult, len(paths))
	jobs := make(chan int)
	var wg sync.WaitGroup
	workers := config.Concurrency
	if workers > len(paths) && len(paths) > 0 {
		workers = len(paths)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				path := paths[idx]
				data, err := os.ReadFile(path)
				if err != nil {
					results[idx] = offlineParseError(path, err)
					continue
				}
				certs, err := ParseCertificatesFromBytes(data)
				if err != nil {
					results[idx] = offlineParseError(path, err)
					continue
				}
				results[idx] = OfflineParseResult{Source: path, Certificates: certs, Count: len(certs)}
			}
		}()
	}
	for i := range paths {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results, ctx.Err()
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()
	return results, ctx.Err()
}

// ParseCertificatePEMStream parses concatenated PEM certificates from a stream.
func ParseCertificatePEMStream(r io.Reader, source string) ([]OfflineParseResult, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var results []OfflineParseResult
	var block bytes.Buffer
	inBlock := false
	index := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "-----BEGIN CERTIFICATE-----") {
			inBlock = true
			block.Reset()
		}
		if inBlock {
			block.WriteString(line)
			block.WriteByte('\n')
		}
		if strings.Contains(line, "-----END CERTIFICATE-----") && inBlock {
			inBlock = false
			certs, err := ParseCertificatesFromBytes(block.Bytes())
			recordSource := fmt.Sprintf("%s#%d", source, index)
			if err != nil {
				results = append(results, offlineParseError(recordSource, err))
			} else {
				results = append(results, OfflineParseResult{Source: recordSource, Certificates: certs, Count: len(certs)})
			}
			index++
		}
	}
	if err := scanner.Err(); err != nil {
		return results, err
	}
	return results, nil
}

func offlineParseError(source string, err error) OfflineParseResult {
	return OfflineParseResult{Source: source, Error: err, ErrorMessage: err.Error()}
}
