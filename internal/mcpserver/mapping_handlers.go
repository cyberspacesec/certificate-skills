package mcpserver

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cyberspacesec/certificate-skills/pkg"
	"github.com/mark3labs/mcp-go/mcp"
)

type mcpMappingCertSummary struct {
	Source       string                        `json:"source,omitempty"`
	Index        int                           `json:"index"`
	Subject      string                        `json:"subject"`
	CommonName   string                        `json:"common_name,omitempty"`
	Issuer       string                        `json:"issuer"`
	NotBefore    time.Time                     `json:"not_before"`
	NotAfter     time.Time                     `json:"not_after"`
	SerialNumber string                        `json:"serial_number"`
	DNSNames     []string                      `json:"dns_names,omitempty"`
	Normalized   pkg.NormalizedSubject         `json:"normalized"`
	Extensions   *pkg.CertificateExtensionInfo `json:"extensions,omitempty"`
}

type mcpMappingAnalysis struct {
	TotalCertificates int                     `json:"total_certificates"`
	Dedup             pkg.DedupResult         `json:"dedup"`
	Aggregate         pkg.AggregateResult     `json:"aggregate"`
	Clusters          pkg.CertClusterResult   `json:"clusters"`
	Topology          pkg.TrustChainTopology  `json:"topology"`
	Timeline          pkg.CertificateTimeline `json:"timeline"`
	Certificates      []mcpMappingCertSummary `json:"certificates"`
}

type mcpMapScanResult struct {
	Target       pkg.ScanTarget                `json:"target"`
	TLSVersion   uint16                        `json:"tls_version,omitempty"`
	CipherSuite  uint16                        `json:"cipher_suite,omitempty"`
	ServerName   string                        `json:"server_name,omitempty"`
	ObservedAt   time.Time                     `json:"observed_at"`
	Duration     time.Duration                 `json:"duration"`
	Error        string                        `json:"error,omitempty"`
	CertChainDER [][]byte                      `json:"cert_chain_der,omitempty"`
	Leaf         *mcpMappingCertSummary        `json:"leaf,omitempty"`
	Extensions   *pkg.CertificateExtensionInfo `json:"extensions,omitempty"`
}

type mcpMapScanOutput struct {
	Targets  int                `json:"targets"`
	Success  int                `json:"success"`
	Failed   int                `json:"failed"`
	Results  []mcpMapScanResult `json:"results"`
	Analysis mcpMappingAnalysis `json:"analysis"`
}

type mcpMapParseOutput struct {
	Files    []pkg.OfflineParseResult `json:"files"`
	Analysis mcpMappingAnalysis       `json:"analysis"`
}

func HandleCertMapScan(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ports, err := mcpParseMappingPorts(req.GetString("ports", "443"))
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	targets, err := mcpBuildMappingTargets(
		req.GetStringSlice("hosts", []string{}),
		req.GetStringSlice("cidrs", []string{}),
		ports,
	)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if len(targets) == 0 {
		return mcp.NewToolResultError("at least one host or CIDR is required"), nil
	}

	scanner := pkg.NewBatchScanner(pkg.BatchScanConfig{
		Concurrency:   req.GetInt("concurrency", 100),
		Timeout:       time.Duration(req.GetInt("timeout_seconds", 5)) * time.Second,
		RateLimit:     req.GetInt("rate_limit", 0),
		RetryCount:    req.GetInt("retry_count", 2),
		SkipTLSVerify: true,
		ServerName:    req.GetString("server_name", ""),
	})
	results, err := scanner.Scan(ctx, targets)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to scan targets: %v", err)), nil
	}

	return marshalResult(mcpBuildMapScanOutput(results, true))
}

func HandleCertMapParseFiles(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	paths := req.GetStringSlice("file_paths", []string{})
	if len(paths) == 0 {
		return mcp.NewToolResultError("file_paths array is required"), nil
	}
	results, err := pkg.BatchParseCertificateFiles(ctx, paths, pkg.BatchParseConfig{Concurrency: req.GetInt("concurrency", 16)})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to parse files: %v", err)), nil
	}
	assets := mcpAssetsFromOfflineResults(results)
	return marshalResult(mcpMapParseOutput{
		Files:    results,
		Analysis: mcpBuildMappingAnalysis(assets, req.GetBool("include_extensions", true)),
	})
}

func HandleCertMapTimeline(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	paths := req.GetStringSlice("snapshot_files", []string{})
	if len(paths) == 0 {
		return mcp.NewToolResultError("snapshot_files array is required"), nil
	}
	snapshots, err := mcpReadMappingSnapshotFiles(paths)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return marshalResult(pkg.BuildCertificateTimeline(snapshots, time.Now()))
}

func mcpParseMappingPorts(value string) ([]int, error) {
	if strings.TrimSpace(value) == "" {
		return []int{443}, nil
	}
	parts := strings.Split(value, ",")
	ports := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		ports = append(ports, port)
	}
	if len(ports) == 0 {
		ports = append(ports, 443)
	}
	return ports, nil
}

func mcpBuildMappingTargets(hosts []string, cidrs []string, ports []int) ([]pkg.ScanTarget, error) {
	var cleanHosts []string
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host != "" {
			cleanHosts = append(cleanHosts, host)
		}
	}
	targets := pkg.ScanFromHosts(cleanHosts, ports)
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		cidrTargets, err := pkg.ScanFromIPRange(cidr, ports)
		if err != nil {
			return nil, err
		}
		targets = append(targets, cidrTargets...)
	}
	return targets, nil
}

func mcpBuildMapScanOutput(results []pkg.BatchScanResult, includeExtensions bool) mcpMapScanOutput {
	out := mcpMapScanOutput{Targets: len(results), Results: make([]mcpMapScanResult, 0, len(results))}
	assets := make([]pkg.CertificateAsset, 0, len(results))
	for _, result := range results {
		item := mcpMapScanResult{
			Target:       result.Target,
			TLSVersion:   result.TLSVersion,
			CipherSuite:  result.CipherSuite,
			ServerName:   result.ServerName,
			ObservedAt:   result.ObservedAt,
			Duration:     result.Duration,
			Error:        result.ErrorMessage,
			CertChainDER: result.CertChainDER,
		}
		if result.ErrorMessage != "" {
			out.Failed++
		} else {
			out.Success++
		}
		if len(result.CertChain) > 0 {
			item.Leaf = mcpCertificateSummary("", 0, result.CertChain[0], includeExtensions)
			if includeExtensions {
				ext := pkg.AnalyzeCertificateExtensions(result.CertChain[0])
				item.Extensions = &ext
			}
			assets = append(assets, pkg.CertificateAsset{
				Target:     result.Target,
				Cert:       result.CertChain[0],
				Chain:      result.CertChain,
				Source:     "scan",
				ObservedAt: result.ObservedAt,
			})
		}
		out.Results = append(out.Results, item)
	}
	out.Analysis = mcpBuildMappingAnalysis(assets, includeExtensions)
	return out
}

func mcpAssetsFromOfflineResults(results []pkg.OfflineParseResult) []pkg.CertificateAsset {
	var assets []pkg.CertificateAsset
	for _, result := range results {
		for index, cert := range result.Certificates {
			assets = append(assets, pkg.CertificateAsset{
				Target:     pkg.ScanTarget{Host: fmt.Sprintf("%s#%d", result.Source, index), Port: 443},
				Cert:       cert,
				Chain:      []*x509.Certificate{cert},
				Source:     result.Source,
				ObservedAt: time.Now(),
			})
		}
	}
	return assets
}

func mcpBuildMappingAnalysis(assets []pkg.CertificateAsset, includeExtensions bool) mcpMappingAnalysis {
	certs := make([]*x509.Certificate, 0, len(assets))
	summaries := make([]mcpMappingCertSummary, 0, len(assets))
	for index, asset := range assets {
		if asset.Cert == nil {
			continue
		}
		certs = append(certs, asset.Cert)
		summaries = append(summaries, *mcpCertificateSummary(asset.Source, index, asset.Cert, includeExtensions))
	}
	_, dedup, err := pkg.DedupCertificates(certs, pkg.DedupByCertFingerprint)
	if err != nil {
		dedup = pkg.DedupResult{Total: len(certs)}
	}
	snapshots := pkg.SnapshotsFromCertificateAssets(assets)
	return mcpMappingAnalysis{
		TotalCertificates: len(certs),
		Dedup:             dedup,
		Aggregate:         pkg.AggregateCertificateAssets(assets),
		Clusters:          pkg.ClusterCertificates(certs, 0.5),
		Topology:          pkg.BuildTrustChainTopologyFromAssets(assets),
		Timeline:          pkg.BuildCertificateTimeline(snapshots, time.Now()),
		Certificates:      summaries,
	}
}

func mcpCertificateSummary(source string, index int, cert *x509.Certificate, includeExtensions bool) *mcpMappingCertSummary {
	if cert == nil {
		return nil
	}
	summary := &mcpMappingCertSummary{
		Source:       source,
		Index:        index,
		Subject:      cert.Subject.String(),
		CommonName:   cert.Subject.CommonName,
		Issuer:       cert.Issuer.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SerialNumber: cert.SerialNumber.String(),
		DNSNames:     append([]string(nil), cert.DNSNames...),
		Normalized:   pkg.NormalizeCertificateSubject(cert),
	}
	if includeExtensions {
		ext := pkg.AnalyzeCertificateExtensions(cert)
		summary.Extensions = &ext
	}
	return summary
}

func mcpReadMappingSnapshotFiles(paths []string) ([]pkg.CertSnapshot, error) {
	var snapshots []pkg.CertSnapshot
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var many []pkg.CertSnapshot
		if err := json.Unmarshal(data, &many); err == nil {
			snapshots = append(snapshots, many...)
			continue
		}
		var one pkg.CertSnapshot
		if err := json.Unmarshal(data, &one); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		snapshots = append(snapshots, one)
	}
	return snapshots, nil
}
