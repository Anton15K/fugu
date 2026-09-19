## Fugu eval report

- Samples: **10** (6 malicious, 4 benign); 6 received predictions
- Micro: P=0.632 R=1.000 F1=**0.774**
- Macro: P=0.633 R=1.000 F1=**0.759**
- Benign-FP: **0.000** (0/4 benign samples flagged)

### Per-OWASP-id metrics

| OWASP id | precision | recall | F1 | tp | fp | fn | support |
|---|---|---|---|---|---|---|---|
| LLM01 | 0.800 | 1.000 | 0.889 | 4 | 1 | 0 | 4 |
| LLM02 | 0.500 | 1.000 | 0.667 | 2 | 2 | 0 | 2 |
| MCP01 | 0.500 | 1.000 | 0.667 | 2 | 2 | 0 | 2 |
| MCP03 | 1.000 | 1.000 | 1.000 | 2 | 0 | 0 | 2 |
| MCP05 | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | 1 |
| MCP06 | 0.500 | 1.000 | 0.667 | 1 | 1 | 0 | 1 |

### Confusion pairs (predicted → expected)

_none_

