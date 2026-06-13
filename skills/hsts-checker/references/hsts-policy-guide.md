# HSTS Policy Implementation Guide

## HSTS Response Header Format

```
Strict-Transport-Security: max-age=<seconds>[; includeSubDomains][; preload]
```

## Implementation Examples

### Nginx

```nginx
server {
    listen 443 ssl;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}
```

### Apache

```apache
<VirtualHost *:443>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</VirtualHost>
```

### HAProxy

```
frontend https
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

### Node.js (Express)

```javascript
const helmet = require('helmet');
app.use(helmet.hsts({
  maxAge: 31536000,
  includeSubDomains: true,
  preload: true
}));
```

## Incremental Rollout Strategy

HSTS misconfiguration can lock out users. Follow this rollout strategy:

### Phase 1: Testing (1 week)

```
Strict-Transport-Security: max-age=60
```

- 1-minute max-age for quick testing
- Verify HTTPS works for all resources
- Check that no mixed content warnings appear

### Phase 2: Short-term (1 month)

```
Strict-Transport-Security: max-age=86400
```

- 1-day max-age
- Monitor for issues on all subdomains

### Phase 3: Production (permanent)

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

- 1-year max-age with subdomain protection
- Monitor for 1-2 months before adding preload

### Phase 4: Preload

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

- Submit to https://hstspreload.org
- **⚠️ Irreversible**: Removal from preload list takes months

## Common Pitfalls

| Pitfall | Impact | Prevention |
|---------|--------|------------|
| Setting too high max-age initially | Can't revert if HTTPS breaks | Start small, increase gradually |
| `includeSubDomains` with HTTP subdomains | Subdomains become inaccessible | Audit ALL subdomains first |
| Preload without thorough testing | Removal takes weeks/months | Test for months before preloading |
| Missing HTTPS redirect | First visit still uses HTTP | Add 301 redirect from HTTP to HTTPS |
| HSTS on development domains | Dev environments break | Exclude dev domains from `includeSubDomains` |

## MCP Output Structure

```json
{
  "target": "google.com",
  "hsts": {
    "enabled": true,
    "max_age": 31536000,
    "include_sub_domains": true,
    "preload": true
  }
}
```

## HSTS Preload List

The browser preload list is a hardcoded list of domains that must only be accessed via HTTPS, even on the very first visit (before seeing an HSTS header).

- **Chromium list**: https://chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json
- **Submission**: https://hstspreload.org
- **Requirements**: Valid cert, redirect HTTP→HTTPS, HSTS with max-age ≥ 31536000, includeSubDomains, preload directive
