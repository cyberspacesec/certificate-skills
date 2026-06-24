package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cyberspacesec/certificate-skills/internal/display"
	"github.com/cyberspacesec/certificate-skills/pkg"
	"github.com/spf13/cobra"
)

type mappingCertSummary struct {
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

type mappingAnalysisSummary struct {
	TotalCertificates int                     `json:"total_certificates"`
	Dedup             pkg.DedupResult         `json:"dedup"`
	Aggregate         pkg.AggregateResult     `json:"aggregate"`
	Clusters          pkg.CertClusterResult   `json:"clusters"`
	Topology          pkg.TrustChainTopology  `json:"topology"`
	Timeline          pkg.CertificateTimeline `json:"timeline"`
	Certificates      []mappingCertSummary    `json:"certificates"`
}

type mapScanOutput struct {
	Targets  int                    `json:"targets"`
	Success  int                    `json:"success"`
	Failed   int                    `json:"failed"`
	Results  []mapScanResultOutput  `json:"results"`
	Analysis mappingAnalysisSummary `json:"analysis"`
}

type mapScanResultOutput struct {
	Target       pkg.ScanTarget                `json:"target"`
	TLSVersion   uint16                        `json:"tls_version,omitempty"`
	CipherSuite  uint16                        `json:"cipher_suite,omitempty"`
	ServerName   string                        `json:"server_name,omitempty"`
	ObservedAt   time.Time                     `json:"observed_at"`
	Duration     time.Duration                 `json:"duration"`
	Error        string                        `json:"error,omitempty"`
	CertChainDER [][]byte                      `json:"cert_chain_der,omitempty"`
	Leaf         *mappingCertSummary           `json:"leaf,omitempty"`
	Extensions   *pkg.CertificateExtensionInfo `json:"extensions,omitempty"`
}

type mapParseOutput struct {
	Files    []pkg.OfflineParseResult `json:"files"`
	Analysis mappingAnalysisSummary   `json:"analysis"`
}

var mapScanCmd = &cobra.Command{
	Use:   "map-scan",
	Short: "Batch collect certificates from hosts or CIDR ranges",
	Long: `Batch collect TLS certificates from many hosts or CIDR ranges and produce
cyberspace mapping summaries including de-duplication, normalized subjects,
aggregations, clusters, extension inventory, chain topology, and timeline data.

Examples:
  cert-skills map-scan --hosts example.com,github.com --ports 443 --output json
  cert-skills map-scan --cidrs 192.0.2.0/30 --ports 443,8443 --concurrency 20`,
	Run: func(cmd *cobra.Command, args []string) {
		outputFormat, _ := cmd.Flags().GetString("output")
		hostsArg, _ := cmd.Flags().GetString("hosts")
		cidrsArg, _ := cmd.Flags().GetString("cidrs")
		portsArg, _ := cmd.Flags().GetString("ports")
		concurrency, _ := cmd.Flags().GetInt("concurrency")
		timeoutSeconds, _ := cmd.Flags().GetInt("timeout")
		rateLimit, _ := cmd.Flags().GetInt("rate-limit")
		retryCount, _ := cmd.Flags().GetInt("retries")
		serverName, _ := cmd.Flags().GetString("server-name")

		ports, err := parseMappingPorts(portsArg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		targets, err := buildMappingTargets(hostsArg, cidrsArg, ports)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if len(targets) == 0 {
			fmt.Fprintln(os.Stderr, "Error: at least one host or CIDR is required")
			os.Exit(1)
		}

		scanner := pkg.NewBatchScanner(pkg.BatchScanConfig{
			Concurrency:   concurrency,
			Timeout:       time.Duration(timeoutSeconds) * time.Second,
			RateLimit:     rateLimit,
			RetryCount:    retryCount,
			SkipTLSVerify: true,
			ServerName:    serverName,
		})

		results, err := scanner.Scan(context.Background(), targets)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning targets: %v\n", err)
			os.Exit(1)
		}

		out := buildMapScanOutput(results, true)
		if outputFormat == "json" {
			printMappingJSON(out)
			return
		}
		displayMapScanText(out)
	},
}

var mapParseCmd = &cobra.Command{
	Use:   "map-parse [cert files...]",
	Short: "Parse certificate files and build mapping summaries",
	Long: `Parse PEM or DER certificate files offline and produce cyberspace mapping
summaries including de-duplication, normalized subjects, aggregations, clusters,
extension inventory, trust topology, and timeline data.

Examples:
  cert-skills map-parse leaf.pem chain.pem --output json
  cert-skills map-parse *.crt --concurrency 8`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		outputFormat, _ := cmd.Flags().GetString("output")
		concurrency, _ := cmd.Flags().GetInt("concurrency")
		includeExtensions, _ := cmd.Flags().GetBool("extensions")

		results, err := pkg.BatchParseCertificateFiles(context.Background(), args, pkg.BatchParseConfig{Concurrency: concurrency})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing files: %v\n", err)
			os.Exit(1)
		}

		assets := assetsFromOfflineResults(results)
		out := mapParseOutput{
			Files:    results,
			Analysis: buildMappingAnalysis(assets, includeExtensions),
		}

		if outputFormat == "json" {
			printMappingJSON(out)
			return
		}
		displayMapParseText(out)
	},
}

var mapTimelineCmd = &cobra.Command{
	Use:   "map-timeline [snapshot-json files...]",
	Short: "Build a certificate lifecycle timeline from snapshot JSON files",
	Long: `Build a certificate lifecycle timeline from one or more JSON files containing
CertSnapshot records. Each file may contain a single snapshot or an array of snapshots.

Examples:
  cert-skills map-timeline snapshots/*.json --output json`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		outputFormat, _ := cmd.Flags().GetString("output")
		snapshots, err := readMappingSnapshotFiles(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		timeline := pkg.BuildCertificateTimeline(snapshots, time.Now())
		if outputFormat == "json" {
			printMappingJSON(timeline)
			return
		}
		displayMapTimelineText(timeline)
	},
}

func init() {
	rootCmd.AddCommand(mapScanCmd)
	rootCmd.AddCommand(mapParseCmd)
	rootCmd.AddCommand(mapTimelineCmd)

	mapScanCmd.Flags().String("hosts", "", "Comma-separated hostnames or IP addresses")
	mapScanCmd.Flags().String("cidrs", "", "Comma-separated CIDR ranges")
	mapScanCmd.Flags().String("ports", "443", "Comma-separated TCP ports")
	mapScanCmd.Flags().Int("concurrency", 100, "Maximum concurrent TLS connections")
	mapScanCmd.Flags().Int("timeout", 5, "Per-target timeout in seconds")
	mapScanCmd.Flags().Int("rate-limit", 0, "Maximum connection attempts per second, 0 for unlimited")
	mapScanCmd.Flags().Int("retries", 2, "Retry count per target")
	mapScanCmd.Flags().String("server-name", "", "Override TLS SNI server name")

	mapParseCmd.Flags().Int("concurrency", 16, "Maximum concurrent file parses")
	mapParseCmd.Flags().Bool("extensions", true, "Include parsed TLS/X.509 extension inventory")
}

func parseMappingPorts(value string) ([]int, error) {
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

func buildMappingTargets(hostsArg, cidrsArg string, ports []int) ([]pkg.ScanTarget, error) {
	var targets []pkg.ScanTarget
	if hosts := splitMappingCSV(hostsArg); len(hosts) > 0 {
		targets = append(targets, pkg.ScanFromHosts(hosts, ports)...)
	}
	for _, cidr := range splitMappingCSV(cidrsArg) {
		cidrTargets, err := pkg.ScanFromIPRange(cidr, ports)
		if err != nil {
			return nil, err
		}
		targets = append(targets, cidrTargets...)
	}
	return targets, nil
}

func splitMappingCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func buildMapScanOutput(results []pkg.BatchScanResult, includeExtensions bool) mapScanOutput {
	out := mapScanOutput{Targets: len(results), Results: make([]mapScanResultOutput, 0, len(results))}
	assets := make([]pkg.CertificateAsset, 0, len(results))
	for _, result := range results {
		item := mapScanResultOutput{
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
			item.Leaf = certificateSummary("", 0, result.CertChain[0], includeExtensions)
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
	out.Analysis = buildMappingAnalysis(assets, includeExtensions)
	return out
}

func assetsFromOfflineResults(results []pkg.OfflineParseResult) []pkg.CertificateAsset {
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

func buildMappingAnalysis(assets []pkg.CertificateAsset, includeExtensions bool) mappingAnalysisSummary {
	certs := make([]*x509.Certificate, 0, len(assets))
	summaries := make([]mappingCertSummary, 0, len(assets))
	for index, asset := range assets {
		if asset.Cert == nil {
			continue
		}
		certs = append(certs, asset.Cert)
		summaries = append(summaries, *certificateSummary(asset.Source, index, asset.Cert, includeExtensions))
	}

	_, dedup, err := pkg.DedupCertificates(certs, pkg.DedupByCertFingerprint)
	if err != nil {
		dedup = pkg.DedupResult{Total: len(certs)}
	}
	snapshots := pkg.SnapshotsFromCertificateAssets(assets)
	return mappingAnalysisSummary{
		TotalCertificates: len(certs),
		Dedup:             dedup,
		Aggregate:         pkg.AggregateCertificateAssets(assets),
		Clusters:          pkg.ClusterCertificates(certs, 0.5),
		Topology:          pkg.BuildTrustChainTopologyFromAssets(assets),
		Timeline:          pkg.BuildCertificateTimeline(snapshots, time.Now()),
		Certificates:      summaries,
	}
}

func certificateSummary(source string, index int, cert *x509.Certificate, includeExtensions bool) *mappingCertSummary {
	if cert == nil {
		return nil
	}
	summary := &mappingCertSummary{
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

func readMappingSnapshotFiles(paths []string) ([]pkg.CertSnapshot, error) {
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

func printMappingJSON(v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

func displayMapScanText(out mapScanOutput) {
	fmt.Println(display.SectionHeader("Certificate Mapping Scan"))
	fmt.Println(display.Separator())
	fmt.Println(display.BulletKeyValue("Targets", strconv.Itoa(out.Targets)))
	fmt.Printf("Success: %d | Failed: %d | Unique certs: %d\n", out.Success, out.Failed, out.Analysis.Dedup.Unique)
	for _, result := range out.Results {
		target := result.Target.Address()
		if result.Error != "" {
			fmt.Printf("  - %s: error: %s\n", target, result.Error)
			continue
		}
		cn := ""
		issuer := ""
		if result.Leaf != nil {
			cn = result.Leaf.CommonName
			issuer = result.Leaf.Issuer
		}
		fmt.Printf("  - %s: CN=%s Issuer=%s TLS=0x%04x\n", target, cn, issuer, result.TLSVersion)
	}
}

func displayMapParseText(out mapParseOutput) {
	fmt.Println(display.SectionHeader("Certificate Mapping Parse"))
	fmt.Println(display.Separator())
	fmt.Println(display.BulletKeyValue("Files", strconv.Itoa(len(out.Files))))
	fmt.Println(display.BulletKeyValue("Certificates", strconv.Itoa(out.Analysis.TotalCertificates)))
	fmt.Printf("Unique: %d | Duplicates: %d | Clusters: %d\n",
		out.Analysis.Dedup.Unique, out.Analysis.Dedup.Duplicates, len(out.Analysis.Clusters.Clusters))
	for _, cert := range out.Analysis.Certificates {
		fmt.Printf("  - %s: CN=%s Issuer=%s\n", cert.Source, cert.CommonName, cert.Issuer)
	}
}

func displayMapTimelineText(timeline pkg.CertificateTimeline) {
	fmt.Println(display.SectionHeader("Certificate Mapping Timeline"))
	fmt.Println(display.Separator())
	fmt.Println(display.BulletKeyValue("Events", strconv.Itoa(len(timeline.Events))))
	for _, event := range timeline.Events {
		fmt.Printf("  - %s %s %s\n", event.At.Format(time.RFC3339), event.Target, event.Type)
	}
}
