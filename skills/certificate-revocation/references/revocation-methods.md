# Certificate Revocation Methods Reference

## OCSP vs CRL Comparison

| Aspect | OCSP | CRL |
|--------|------|-----|
| Response time | Real-time | Periodic (hours to days) |
| Bandwidth | Small request/response | Large list download |
| Privacy | Reveals which cert you're checking | Private (download entire list) |
| Freshness | Current status | May be stale |
| Availability | Depends on CA responder | Depends on CA CRL server |
| Caching | Short-lived responses | Can be cached locally |

## OCSP Stapling

OCSP stapling (formally: TLS Certificate Status Request extension) allows the server to include a pre-fetched OCSP response in the TLS handshake.

**Benefits:**
- Client doesn't need to contact CA's OCSP responder
- Reduces CA server load
- Protects client privacy
- Faster handshake completion

**Detection:** `cert-hacker info <domain>` shows `HasOCSPStaple` field.

## OCSP Must-Staple

The OCSP Must-Staple extension (TLS feature extension, OID 1.3.6.1.5.5.7.1.24) requires the server to staple an OCSP response.

**Why it matters:**
- Prevents OCSP soft-fail attacks (where a revoked cert appears valid because OCSP is unavailable)
- Forces servers to maintain valid OCSP responses
- Critical for high-security environments

## Revocation Checking Workflow

1. **Check OCSP first** — real-time status, fastest
2. **If OCSP unavailable, check CRL** — fallback method
3. **If both unavailable** — status is Unknown (not safe to assume Good)
4. **If either says Revoked** — certificate is revoked

## JSON Output Structure

```json
{
  "target": "example.com",
  "ocsp_status": {
    "checked": true,
    "status": "Good",
    "ocsp_url": "http://r11.o.lencr.org",
    "this_update": "2025-10-01T00:00:00Z",
    "next_update": "2025-10-08T00:00:00Z"
  },
  "crl_status": {
    "checked": true,
    "status": "Good",
    "crl_url": "http://r11.c.lencr.org/r11.crl",
    "this_update": "2025-10-01T00:00:00Z",
    "next_update": "2025-10-08T00:00:00Z"
  },
  "overall_status": "Good"
}
```

## Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| OCSP check fails | CA responder unavailable, firewall blocking | Try CRL as fallback |
| CRL download fails | CRL server unavailable, large CRL size | Try OCSP instead |
| Both fail | Network issue or cert lacks both AIA and CRL DP | Verify cert has proper extensions |
| Status "Unknown" | OCSP/CRL unavailable or cert too new | Wait and retry, or contact CA |
| OCSP response expired | Server's stapled response is stale | Server needs to refresh OCSP response |
