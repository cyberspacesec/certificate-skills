# Certificate Download Output Reference

## JSON Output Structure

```json
{
  "target": "google.com",
  "chain_length": 3,
  "saved_files": [
    "./google.com-chain.pem",
    "./google.com-leaf.pem"
  ]
}
```

## PEM File Format

### Chain File (`<domain>-chain.pem`)

Contains multiple PEM blocks in order:

```
-----BEGIN CERTIFICATE-----
<leaf certificate base64>
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
<intermediate certificate base64>
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
<root certificate base64 (if provided by server)>
-----END CERTIFICATE-----
```

### Leaf File (`<domain>-leaf.pem`)

Contains a single PEM block:

```
-----BEGIN CERTIFICATE-----
<leaf/server certificate base64>
-----END CERTIFICATE-----
```

## Usage After Download

Downloaded PEM files can be used with:

- **Web servers**: Configure nginx/apache with the chain and leaf files
- **Trust stores**: Add the chain file to system or application trust stores
- **Inspection**: Use `cert-hacker parse <file>` to view certificate details
- **Fingerprinting**: Use `cert-hacker fingerprint <file>` to generate fingerprints
- **Comparison**: Use `cert-hacker compare --target1 <file> --target2 <domain>` to verify
