# JARM Probe Methodology

## How JARM Works

JARM sends 10 specially crafted TLS Client Hello messages to the target server, varying:

1. **TLS version** in Client Hello (TLS 1.2 vs TLS 1.3)
2. **Cipher suites** offered (different combinations)
3. **ALPN values** (none, http/1.1, h2+http/1.1)
4. **Supported groups** (different elliptic curve selections)

The server's response to each probe (Server Hello parameters: TLS version, cipher suite, ALPN) is recorded and hashed to produce the final fingerprint.

## The 10 Probes

| Probe | TLS Version | Ciphers | ALPN |
|-------|-------------|---------|------|
| 0 | TLS 1.2 | Standard ECDHE | None |
| 1 | TLS 1.2 | Standard ECDHE | http/1.1 |
| 2 | TLS 1.2 | ECDHE + RSA | h2, http/1.1 |
| 3 | TLS 1.3 | Standard + TLS 1.3 | None |
| 4 | TLS 1.3 | Standard + TLS 1.3 | http/1.1 |
| 5 | TLS 1.3 | ECDHE + RSA + TLS 1.3 | h2, http/1.1 |
| 6 | TLS 1.3 | Standard + TLS 1.3 | h2, http/1.1 |
| 7 | TLS 1.2 | Short ECDHE | None |
| 8 | TLS 1.2 | Short ECDHE | http/1.1 |
| 9 | TLS 1.2 | Short ECDHE | h2, http/1.1 |

## Known JARM Fingerprints

Common server fingerprints for reference:

| JARM Hash | Server |
|-----------|--------|
| `29d29d15d29d29d21c42d42d42d41d...` | Cloudflare |
| `07d14d16d21d21d07c42d41d00041d...` | nginx (typical) |
| `2ad2ad0002ad2ad22c2ad2ad2ad2ad...` | Apache (typical) |
| `07b07b09b07b09b07b42d42d42d41d...` | Cobalt Strike (default) |
| `000000000000000000000000000000...` | No TLS / connection refused |

Note: JARM hashes change with server configuration. These are representative examples.

## JSON Output Structure

```json
{
  "target": "example.com",
  "jarm_hash": "29d29d15d29d29d21c42d42d42d41d...",
  "raw_hash": "...",
  "tls_version": "TLS 1.3",
  "cipher_suite": "TLS_AES_128_GCM_SHA256"
}
```

## Use in Cyberspace Mapping

JARM is particularly valuable for:

1. **Infrastructure clustering** — Group servers with identical JARM hashes
2. **C2 detection** — Match against known malicious JARM hashes
3. **CDN identification** — Distinguish origin servers from CDN-fronted servers
4. **Configuration auditing** — Verify TLS configuration consistency across fleet
5. **Service versioning** — Different JARM hashes may indicate different server versions
