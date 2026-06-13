# JA3/JA3S Format Specification

## JA3 Raw String Format

```
TLSVersion,CipherSuites,Extensions,EllipticCurves,PointFormats
```

### Example

```
771,4866-4867-4865-49199-49195-49200-49196-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0
```

### Component Breakdown

| Component | Description | Example |
|-----------|-------------|---------|
| TLSVersion | Decimal TLS version number | 771 (TLS 1.2), 772 (TLS 1.3) |
| CipherSuites | Dash-separated decimal cipher suite IDs | 4866-4867-4865-... |
| Extensions | Dash-separated decimal extension IDs | 0-23-65281-10-11-... |
| EllipticCurves | Dash-separated decimal curve IDs | 29-23-24-25-256-257 |
| PointFormats | Dash-separated decimal point format IDs | 0 |

The JA3 hash is the MD5 of this raw string.

## JA3S Raw String Format

```
TLSVersion,CipherSuite,Extensions
```

### Example

```
772,4865,43-16-5-51-13-65281
```

Much simpler than JA3 — only the server's chosen values.

## Common TLS Version Numbers

| Version | Decimal | Hex |
|---------|---------|-----|
| SSL 3.0 | 768 | 0x0300 |
| TLS 1.0 | 769 | 0x0301 |
| TLS 1.1 | 770 | 0x0302 |
| TLS 1.2 | 771 | 0x0303 |
| TLS 1.3 | 772 | 0x0304 |

## Common Extension IDs

| ID | Name |
|----|------|
| 0 | server_name |
| 5 | status_request (OCSP stapling) |
| 10 | supported_groups |
| 11 | ec_point_formats |
| 13 | signature_algorithms |
| 16 | application_layer_protocol_negotiation (ALPN) |
| 23 | session_ticket |
| 35 | session_ticket (extended) |
| 43 | supported_versions |
| 45 | psk_key_exchange_modes |
| 51 | key_share |
| 65281 | renegotiation_info |

## Known JA3 Hashes

Common client JA3 hashes for reference:

| JA3 Hash | Client |
|----------|--------|
| `cd08e31494f9531f560d64c695473da9` | Chrome (typical) |
| `72b9c6e4c4b85e93b4e5b18d8bb7e594` | Firefox (typical) |
| `e7d705a3286e19ea42f587b344ee6865` | Go http.Client |
| `771,4865-4866-4867,...` | Python requests |
| Various | Metasploit, Cobalt Strike, etc. |

Note: JA3 hashes change with client versions and configurations.

## JSON Output Structure

```json
{
  "target": "example.com",
  "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
  "ja3_raw": "771,4866-4867-...,0-23-65281-10-11-...,29-23-24-25,0",
  "ja3s_hash": "4e724a2f0998558b7ff3ea3e9b5bf3a2",
  "ja3s_raw": "772,4865,43-16-5-51-13-65281",
  "tls_version": "TLS 1.3",
  "cipher_suite": "TLS_AES_128_GCM_SHA256",
  "alpn": "h2"
}
```
