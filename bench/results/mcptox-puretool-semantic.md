# MCPTox pure_tool.json head-to-head subset

n=485 (all malicious; the file fuzzd 90.7% / NYIT 74.7% publish against) · mode: **static S0+S1 + semantic S2** · 864s

**Detection (any finding >= medium): 484/485 (99.8%)** · any-severity: 484/485

| Category | n | detected |
|---|---|---|
| Information Manipulation | 108 | 108 |
| Privacy Leakage | 97 | 97 |
| Service Disruption | 73 | 72 |
| Data Tampering | 45 | 45 |
| Infrastructure Damage | 41 | 41 |
| Credential Leakage | 40 | 40 |
| Code Injection | 22 | 22 |
| Financial Loss | 21 | 21 |
| Instruction Tampering | 21 | 21 |
| Message Hijacking | 15 | 15 |
| Other | 2 | 2 |
