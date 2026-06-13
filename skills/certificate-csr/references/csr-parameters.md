# CSR Generation Parameters Reference

## Complete Parameter Table

| Parameter | CLI Flag | MCP Key | Type | Default | Required |
|-----------|----------|---------|------|---------|----------|
| Common Name | `--common-name, -n` | `common_name` | string | — | Yes |
| Organization | `--organization` | `organization` | string | "" | No |
| Country | `--country` | `country` | string | "" | No |
| Province | `--province` | `province` | string | "" | No |
| Locality | `--locality` | `locality` | string | "" | No |
| DNS Names | `--dns-names` | `dns_names` | string/array | "" | No |
| Key Size | `--key-size` | `key_size` | int | 2048 | No |
| Key Type | `--key-type` | `key_type` | string | "rsa" | No |

## CA-Specific Recommendations

### Let's Encrypt

- Key type: RSA 2048 or ECDSA P-256
- Must include `--dns-names` for all subdomains
- Country/organization are optional but recommended for EV certificates

### DigiCert / Symantec

- Key type: RSA 2048 (most compatible) or RSA 4096 (high security)
- Organization and country are usually **required** for OV/EV certificates
- Include all SANs in `--dns-names`

### Cloudflare

- Key type: ECDSA P-256 or P-384 preferred (Cloudflare optimizes for ECDSA)
- DNS names should cover all proxied domains

### Internal CA (Microsoft ADCS, OpenSSL CA)

- Key type: RSA 2048 or RSA 4096
- Include full subject DN (organization, country, province, locality)

## CSR PEM Format

```
-----BEGIN CERTIFICATE REQUEST-----
<Base64-encoded DER>
-----END CERTIFICATE REQUEST-----
```

## Key Type and Size Combinations

| Key Type | Key Size | Curve | Security | CA Compatibility |
|----------|----------|-------|----------|------------------|
| rsa | 2048 | — | Standard | Universal |
| rsa | 4096 | — | High | Universal |
| ecdsa | 256 | P-256 | High | Most modern CAs |
| ecdsa | 384 | P-384 | Very High | Most modern CAs |
| ecdsa | 521 | P-521 | Maximum | Limited CA support |
| ed25519 | 256 | Ed25519 | Very High | Very limited CA support |
