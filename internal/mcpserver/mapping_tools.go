package mcpserver

import "github.com/mark3labs/mcp-go/mcp"

var CertMapScanTool = mcp.NewTool("cert_map_scan",
	mcp.WithDescription(
		"Batch collect TLS certificates from hosts or CIDR ranges for cyberspace mapping. "+
			"Returns per-target scan results plus de-duplication, aggregation, clustering, extension inventory, trust topology, and timeline summaries."),
	mcp.WithArray("hosts",
		mcp.Description("Hostnames or IP addresses to scan (e.g., ['example.com', '192.0.2.10'])."),
	),
	mcp.WithArray("cidrs",
		mcp.Description("CIDR ranges to expand and scan (e.g., ['192.0.2.0/30'])."),
	),
	mcp.WithString("ports",
		mcp.Description("Comma-separated TCP ports. Default: 443."),
	),
	mcp.WithNumber("concurrency",
		mcp.Description("Maximum concurrent TLS connections. Default: 100."),
	),
	mcp.WithNumber("timeout_seconds",
		mcp.Description("Per-target timeout in seconds. Default: 5."),
	),
	mcp.WithNumber("rate_limit",
		mcp.Description("Maximum connection attempts per second. Default: unlimited."),
	),
	mcp.WithNumber("retry_count",
		mcp.Description("Retry count per target. Default: 2."),
	),
	mcp.WithString("server_name",
		mcp.Description("Optional TLS SNI override."),
	),
)

var CertMapParseFilesTool = mcp.NewTool("cert_map_parse_files",
	mcp.WithDescription(
		"Parse PEM or DER certificate files offline and build cyberspace mapping summaries: "+
			"de-duplication, normalized subjects, aggregations, clusters, extension inventory, trust topology, and timeline data."),
	mcp.WithArray("file_paths",
		mcp.Required(),
		mcp.Description("Certificate file paths to parse."),
	),
	mcp.WithNumber("concurrency",
		mcp.Description("Maximum concurrent file parses. Default: 16."),
	),
	mcp.WithBoolean("include_extensions",
		mcp.Description("Include parsed TLS/X.509 extension inventory. Default: true."),
	),
)

var CertMapTimelineTool = mcp.NewTool("cert_map_timeline",
	mcp.WithDescription(
		"Build a certificate lifecycle timeline from JSON files containing CertSnapshot records. "+
			"Each file may contain one snapshot object or an array of snapshot objects."),
	mcp.WithArray("snapshot_files",
		mcp.Required(),
		mcp.Description("JSON files containing CertSnapshot records."),
	),
)
