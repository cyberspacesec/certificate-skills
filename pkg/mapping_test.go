package pkg

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestBatchScannerLocalTLSServer(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Listener = ln
	server.StartTLS()
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split hostport: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	scanner := NewBatchScanner(BatchScanConfig{
		Concurrency:   2,
		Timeout:       2 * time.Second,
		SkipTLSVerify: true,
	})
	results, err := scanner.Scan(context.Background(), []ScanTarget{{Host: host, Port: port}})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}
	if results[0].Error != nil {
		t.Fatalf("unexpected scan error: %v", results[0].Error)
	}
	if len(results[0].CertChain) == 0 || len(results[0].CertChainDER) == 0 {
		t.Fatal("expected collected certificate chain")
	}
	if results[0].TLSVersion == 0 || results[0].CipherSuite == 0 {
		t.Fatal("expected TLS connection metadata")
	}
}

func TestScanTargetExpansion(t *testing.T) {
	targets := ScanFromHosts([]string{"example.com", "example.net"}, []int{443, 8443})
	if len(targets) != 4 {
		t.Fatalf("expected 4 host targets, got %d", len(targets))
	}
	if targets[0].Address() != "example.com:443" {
		t.Fatalf("unexpected address: %s", targets[0].Address())
	}

	cidrTargets, err := ScanFromIPRange("192.0.2.0/31", []int{443})
	if err != nil {
		t.Fatalf("expand cidr: %v", err)
	}
	if len(cidrTargets) != 2 {
		t.Fatalf("expected 2 cidr targets, got %d", len(cidrTargets))
	}
}

func TestMappingDedupNormalizeAggregateClusterAndParse(t *testing.T) {
	key := mappingRSAKey(t)
	cert1 := mappingIssueCert(t, mappingCertSpec{
		CommonName: " WWW.Example.COM ",
		Org:        []string{"Example, Inc."},
		DNSNames:   []string{"www.example.com", "api.example.com"},
		Serial:     101,
		Key:        key,
	})
	cert2 := mappingIssueCert(t, mappingCertSpec{
		CommonName: "api.example.com",
		Org:        []string{"Example Inc"},
		DNSNames:   []string{"api.example.com", "admin.example.com"},
		Serial:     102,
		Key:        key,
	})
	cert3 := mappingIssueCert(t, mappingCertSpec{
		CommonName: "other.test",
		Org:        []string{"Other LLC"},
		DNSNames:   []string{"other.test"},
		Serial:     103,
	})

	unique, stats, err := DedupCertificates([]*x509.Certificate{cert1, cert2, cert3}, DedupBySPKI)
	if err != nil {
		t.Fatalf("dedup failed: %v", err)
	}
	if len(unique) != 2 || stats.Duplicates != 1 {
		t.Fatalf("expected 2 unique and 1 duplicate, got unique=%d duplicates=%d", len(unique), stats.Duplicates)
	}

	subject := NormalizeCertificateSubject(cert1)
	if subject.OrgKey != "example" {
		t.Fatalf("expected normalized org key example, got %q", subject.OrgKey)
	}
	if subject.DNSNames[0] != "api.example.com" {
		t.Fatalf("expected sorted normalized DNS names, got %#v", subject.DNSNames)
	}

	agg := AggregateCertificateAssets([]CertificateAsset{
		{Target: ScanTarget{Host: "192.0.2.10", Port: 443}, Cert: cert1, ASN: 64500, ASName: "Example Net"},
		{Target: ScanTarget{Host: "192.0.2.11", Port: 443}, Cert: cert2, ASN: 64500, ASName: "Example Net"},
		{Target: ScanTarget{Host: "192.0.2.12", Port: 443}, Cert: cert3, ASN: 64501, ASName: "Other Net"},
	})
	if agg.Total != 3 || len(agg.ByASN) != 2 || agg.ByASN[0].Count != 2 {
		t.Fatalf("unexpected aggregate result: %#v", agg.ByASN)
	}

	clusters := ClusterCertificates([]*x509.Certificate{cert1, cert2, cert3}, 0.3)
	if len(clusters.Clusters) != 1 || clusters.Clusters[0].Reason == "" {
		t.Fatalf("expected one related certificate cluster, got %#v", clusters)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw})
	parsed, err := ParseCertificatesFromBytes(pemData)
	if err != nil {
		t.Fatalf("parse PEM cert: %v", err)
	}
	if len(parsed) != 1 || parsed[0].SerialNumber.Cmp(cert1.SerialNumber) != 0 {
		t.Fatal("unexpected parsed PEM certificate")
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(certPath, pemData, 0644); err != nil {
		t.Fatalf("write cert fixture: %v", err)
	}
	results, err := BatchParseCertificateFiles(context.Background(), []string{certPath}, BatchParseConfig{Concurrency: 1})
	if err != nil {
		t.Fatalf("batch parse files: %v", err)
	}
	if len(results) != 1 || results[0].Count != 1 || results[0].Error != nil {
		t.Fatalf("unexpected batch parse result: %#v", results)
	}
}

func TestAnalyzeCertificateExtensions(t *testing.T) {
	cert := mappingIssueCert(t, mappingCertSpec{
		CommonName: "extensions.example.com",
		Org:        []string{"Example"},
		DNSNames:   []string{"extensions.example.com"},
		IPAddresses: []net.IP{
			net.ParseIP("192.0.2.20"),
		},
		Serial:             201,
		OCSPServer:         []string{"http://ocsp.example.com"},
		IssuingCertURL:     []string{"http://ca.example.com/intermediate.cer"},
		CRLDistribution:    []string{"http://crl.example.com/root.crl"},
		PolicyIdentifiers:  []asn1.ObjectIdentifier{{2, 23, 140, 1, 2, 1}},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 2, 3, 4, 5}},
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyID:       []byte{1, 2, 3, 4},
		AuthorityKeyID:     []byte{5, 6, 7, 8},
		ExtraCriticalOID:   asn1.ObjectIdentifier{1, 2, 3, 4, 999},
		ExtraCriticalValue: []byte{0x05, 0x00},
	})
	cert.PolicyIdentifiers = []asn1.ObjectIdentifier{{2, 23, 140, 1, 2, 1}}

	info := AnalyzeCertificateExtensions(cert)
	if info.SubjectKeyID != "01020304" || info.AuthorityKeyID != "05060708" {
		t.Fatalf("unexpected key identifiers: %#v", info)
	}
	if len(info.DNSNames) != 1 || info.DNSNames[0] != "extensions.example.com" {
		t.Fatalf("unexpected SAN DNS names: %#v", info.DNSNames)
	}
	if len(info.OCSPServers) != 1 || len(info.IssuingCertURLs) != 1 || len(info.CRLDistribution) != 1 {
		t.Fatalf("missing AIA/CRL fields: %#v", info)
	}
	if len(info.Policies) != 1 || info.Policies[0].Type != "DV" {
		t.Fatalf("expected known DV policy, got %#v", info.Policies)
	}
	if len(info.UnknownCritical) != 1 {
		t.Fatalf("expected one unknown critical extension, got %#v", info.UnknownCritical)
	}
}

func TestTrustChainTopologyAndTimeline(t *testing.T) {
	rootKey := mappingRSAKey(t)
	root := mappingIssueCert(t, mappingCertSpec{
		CommonName: "Root CA",
		Org:        []string{"Example Trust"},
		Serial:     301,
		Key:        rootKey,
		IsCA:       true,
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	})
	leafKey := mappingRSAKey(t)
	leaf := mappingIssueCert(t, mappingCertSpec{
		CommonName: "leaf.example.com",
		Org:        []string{"Example"},
		DNSNames:   []string{"leaf.example.com"},
		Serial:     302,
		Key:        leafKey,
		Issuer:     root,
		IssuerKey:  rootKey,
	})

	topology := BuildTrustChainTopology([][]*x509.Certificate{{leaf, root}})
	if len(topology.Nodes) != 2 || len(topology.Edges) != 2 {
		t.Fatalf("unexpected topology size: nodes=%d edges=%d", len(topology.Nodes), len(topology.Edges))
	}
	if len(topology.Roots) != 1 || len(topology.Leaves) != 1 {
		t.Fatalf("expected one root and one leaf, got roots=%v leaves=%v", topology.Roots, topology.Leaves)
	}

	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	renewed := mappingIssueCert(t, mappingCertSpec{
		CommonName: "leaf.example.com",
		Org:        []string{"Example"},
		DNSNames:   []string{"leaf.example.com"},
		Serial:     303,
		Key:        leafKey,
	})
	replaced := mappingIssueCert(t, mappingCertSpec{
		CommonName: "leaf.example.com",
		Org:        []string{"Example"},
		DNSNames:   []string{"leaf.example.com"},
		Serial:     304,
	})

	snaps := []CertSnapshot{
		SnapshotFromCertificate("leaf.example.com:443", leaf, now.Add(-48*time.Hour), nil),
		SnapshotFromCertificate("leaf.example.com:443", renewed, now.Add(-24*time.Hour), nil),
		SnapshotFromCertificate("leaf.example.com:443", replaced, now, nil),
	}
	timeline := BuildCertificateTimeline(snaps, now)
	types := map[string]bool{}
	for _, event := range timeline.EventsByTarget["leaf.example.com:443"] {
		types[event.Type] = true
	}
	if !types["first_seen"] || !types["renewed"] || !types["replaced"] {
		t.Fatalf("missing expected timeline events: %#v", timeline.EventsByTarget["leaf.example.com:443"])
	}
}

type mappingCertSpec struct {
	CommonName         string
	Org                []string
	DNSNames           []string
	IPAddresses        []net.IP
	Serial             int64
	Key                any
	Issuer             *x509.Certificate
	IssuerKey          any
	IsCA               bool
	KeyUsage           x509.KeyUsage
	ExtKeyUsage        []x509.ExtKeyUsage
	OCSPServer         []string
	IssuingCertURL     []string
	CRLDistribution    []string
	PolicyIdentifiers  []asn1.ObjectIdentifier
	UnknownExtKeyUsage []asn1.ObjectIdentifier
	SubjectKeyID       []byte
	AuthorityKeyID     []byte
	ExtraCriticalOID   asn1.ObjectIdentifier
	ExtraCriticalValue []byte
}

func mappingIssueCert(t *testing.T, spec mappingCertSpec) *x509.Certificate {
	t.Helper()

	key := spec.Key
	if key == nil {
		key = mappingRSAKey(t)
	}
	publicKey := key
	if privateKey, ok := key.(*rsa.PrivateKey); ok {
		publicKey = &privateKey.PublicKey
	}
	if publicKey == nil {
		t.Fatal("certificate key is nil")
	}

	issuer := spec.Issuer
	issuerKey := spec.IssuerKey
	if issuer == nil {
		issuer = &x509.Certificate{}
		issuerKey = key
	}
	if issuerKey == nil {
		issuerKey = key
	}

	serial := spec.Serial
	if serial == 0 {
		serial = 1
	}
	keyUsage := spec.KeyUsage
	if keyUsage == 0 {
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	extKeyUsage := spec.ExtKeyUsage
	if len(extKeyUsage) == 0 && !spec.IsCA {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: spec.CommonName, Organization: spec.Org},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  spec.IsCA,
		DNSNames:              spec.DNSNames,
		IPAddresses:           spec.IPAddresses,
		OCSPServer:            spec.OCSPServer,
		IssuingCertificateURL: spec.IssuingCertURL,
		CRLDistributionPoints: spec.CRLDistribution,
		PolicyIdentifiers:     spec.PolicyIdentifiers,
		UnknownExtKeyUsage:    spec.UnknownExtKeyUsage,
		SubjectKeyId:          spec.SubjectKeyID,
		AuthorityKeyId:        spec.AuthorityKeyID,
	}
	if len(spec.ExtraCriticalOID) > 0 {
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:       spec.ExtraCriticalOID,
			Critical: true,
			Value:    spec.ExtraCriticalValue,
		})
	}

	if spec.Issuer == nil {
		issuer = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, publicKey, issuerKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func mappingRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}
