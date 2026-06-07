# Certificate Generation Options Reference

## All Parameters

| Parameter | Short | Type | Default | Description |
|-----------|-------|------|---------|-------------|
| `--common-name` | `-n` | string | (required) | Common Name (CN) field |
| `--organization` | | string | "" | Organization (O) field |
| `--country` | | string | "" | Country code (C), 2 letters |
| `--province` | | string | "" | State/Province (ST) |
| `--locality` | | string | "" | City/Locality (L) |
| `--dns-names` | | string | "" | Comma-separated SAN DNS names |
| `--validity-days` | | int | 365 | Certificate validity in days |
| `--key-size` | | int | 2048 | RSA key size: 2048 or 4096 |
| `--is-ca` | | bool | false | Generate as Certificate Authority |
| `--output-cert` | | string | `<cn>.pem` | Certificate output path |
| `--output-key` | | string | `<cn>-key.pem` | Private key output path |

## Output File Formats

### Certificate File (PEM)

```
-----BEGIN CERTIFICATE-----
<Base64-encoded DER>
-----END CERTIFICATE-----
```

### Private Key File (PKCS#8 PEM)

```
-----BEGIN PRIVATE KEY-----
<Base64-encoded DER>
-----END PRIVATE KEY-----
```

## Certificate Extensions

Generated certificates include:

- **Basic Constraints**: `CA:TRUE` (if `--is-ca`) or `CA:FALSE`
- **Key Usage**: `Digital Signature, Key Encipherment` (leaf); adds `Certificate Sign` (CA)
- **Extended Key Usage**: `Server Authentication`
- **Subject Alternative Names**: All DNS names specified; adds CN if no DNS names given

## Key Size Details

| Size | Security Level | Performance | Recommended |
|------|---------------|-------------|-------------|
| 2048 | Standard | Fast | General purpose, most web servers |
| 4096 | High | Slower handshake | CA certificates, high-security needs |

## Validity Period Recommendations

| Use Case | Recommended |
|----------|-------------|
| Local development | 365 days |
| Internal services | 365-730 days |
| CA root certificate | 3650 days (10 years) |
| Short-lived testing | 30-90 days |
