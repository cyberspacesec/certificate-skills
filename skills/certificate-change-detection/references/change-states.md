# Certificate Change States

`cert_detect_change` classifies the comparison between the current certificate and the previous snapshot.

| State | Meaning | Typical Action |
|-------|---------|----------------|
| `new` | No earlier snapshot exists for the target | Store the baseline and monitor future runs |
| `unchanged` | Certificate material matches the previous snapshot | No action beyond routine logging |
| `renewed` | Certificate validity changed while key material stayed consistent | Confirm expected renewal window |
| `replaced` | Key material or certificate identity changed | Review as a potential key rotation or unauthorized replacement |
| `expired` | Current certificate is expired | Escalate as an availability or trust issue |

Key replacement is not automatically malicious. Confirm whether the organization performed a planned rotation, then correlate with CT logs, revocation status, and deployment changes.
