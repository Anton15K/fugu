# Fugu eval harness

Labeled corpus → predictions → OWASP-mapped per-category precision /
recall / F1, micro/macro averages, confusion pairs, benign-FP rate. This
is the "measured recall" tier from IDEA.md: **published coverage numbers,
not vibes** — the differentiation proof that no other scanner ships.

```
eval/
  loader.py     corpus loading + manifest validation (Sample objects)
  metrics.py    pure scoring functions + typed MetricsReport + renderers
  run_eval.py   CLI (--selfcheck | --corpus X --results Y)
  fixtures/     4-sample fallback corpus, same manifest schema
```

## Quick start

```bash
# executable sanity proof (no corpus, no results file needed)
uv run --no-sync python -m eval.run_eval --selfcheck

# score a predictions file against the real corpus
uv run --no-sync python -m eval.run_eval --corpus corpus/ --results results.json
```

If `--corpus` is missing or doesn't exist, the built-in fixtures are
used (same schema, 4 samples), so the harness is always runnable even
while the corpus workstream is still landing.

## Corpus schema

A corpus is a directory of sample sub-directories, each with
`manifest.json`:

```json
{
  "name": "hidden-unicode-instructions",   // required, unique
  "kind": "malicious",                     // "malicious" | "benign"
  "expected_owasp_ids": ["LLM01", "MCP06"],
  "description": "...",                    // optional
  "source": "crafted"                      // optional
}
```

Valid ids come from `fugu.types.OWASP_IDS` (MCP01–MCP10 incl. MCP04B,
LLM01/02/03/06). Schema violations raise `ManifestError`; unknown ids
and soft oddities only append warnings (returned by `load_corpus`,
printed by the CLI) so taxonomy extensions don't break the harness.

## results.json schema

```json
{
  "provenance": "fugu pipeline @ commit abc123 (optional, any string)",
  "predictions": {
    "hidden-unicode-instructions": ["LLM01", "MCP06"],
    "clean-pdf-skill": [],
    "env-harvest-install": ["MCP01"]
  }
}
```

- Keys are sample `name`s from the manifests; values are lists of OWASP
  ids (empty list = "no findings" — a legal, scored prediction).
- A bare `{"name": [...]}` mapping without the wrapper is also accepted
  for hand-written smoke files.
- Predictions on `kind=benign` samples are the benign-FP signal —
  include benign samples, don't filter them out.
- Extra keys not in the corpus are reported (`unmatched_prediction_keys`)
  but don't crash; missing keys score as "no findings".

## Producing results.json from the real pipeline

Once the stage workstreams land, prefer the pipeline path over
hand-writing results. `run_eval.py` tries these import targets in order
(first callable wins, everything behind try/except ImportError):

1. `fugu.pipeline.run_audit(target: Path) -> list[Finding]`
2. `fugu.stages.run_audit(target: Path) -> list[Finding]`
3. `fugu.cli.audit_path(target: Path) -> list[Finding]`

If `--results` is omitted and none are importable you get a clear error
pointing at this README — hand-write a results.json for smoke tests
until then.

Canonical loop (to be wired into a `scripts/` driver once the pipeline
lands):

```python
from pathlib import Path
from fugu.pipeline import run_audit          # when it exists
from eval.loader import load_corpus

samples, _ = load_corpus("corpus/")
predictions = {
    s.name: sorted({oid for f in run_audit(s.path) for oid in f.owasp_ids})
    for s in samples
}
```

The pipeline-facing contract that makes this lossless: stages emit
`Finding`s (see `src/fugu/types.py`) whose `owasp_ids` ⊆ `OWASP_IDS`.
Any adapter that turns findings into the results.json mapping just
unions `owasp_ids` across findings per sample. **Contract request to the
lead:** expose one stable `run_audit(target) -> list[Finding]` entry
(or tell us the real name) and we'll pin `collect_pipeline_predictions`
to it — see "Contract requests" in the workstream summary.

## Methodology notes

**Multi-label, set-based scoring.** A sample can carry several OWASP ids
(overlapping labels are the norm — exfiltration is both MCP01 token
mismanagement and LLM02 disclosure). Per id X: tp = expected∧predicted,
fp = predicted∧¬expected, fn = expected∧¬predicted; precision/recall/F1
with 0.0-on-zero-division.

**Micro vs macro.** Micro pools tp/fp/fn across ids — overall scanner
quality, dominated by frequent categories. Macro averages per-id scores
unweighted over every id seen in gold labels or predictions — rare
category sensitivity. Report both; a scanner with great micro and poor
macro catches the common attacks and misses the niche ones.

**Confusion pairs.** Multi-label generalization of the confusion matrix:
for a malicious sample, every wrong predicted id X × every missed
expected id Y increments `X → Y`. Read as "cried X where Y was the
truth" — e.g. MCP03 → MCP06 means we flagged tool poisoning where the
label says intent subversion. These feed Stage-2 checklist tuning.
Benign samples contribute no confusion pairs (no true Y); their signal
lives in benign-FP.

**Why benign-FP matters.** Precision on malicious samples does not
capture the cost of crying wolf on clean extensions: a scanner that
flags 78% of the ecosystem gets ignored (see IDEA.md's Invariant/Snyk
prior-art discussion). `benign_fp.rate` = fraction of `kind=benign`
samples with ≥1 predicted id, with the offending samples and ids listed.
Target: near zero — this number belongs in the README and the report,
next to recall.

**Confidence tiers.** Metrics here measure the *whole stack* end-to-end
(deterministic S0 through advisory LLM judgments) — per IDEA.md's tiered
guarantees: deterministic layers are proofs, this harness produces the
**measured** tier, canary exfil is empirical evidence, LLM-judged
findings stay advisory. When per-finding tier data lands in results.json
we can split metrics by tier (deterministic-only recall should approach
1.0 on concealment samples).

## Selfcheck as sanity proof

`--selfcheck` scores synthetic predictions against the fixtures and
asserts the metrics contract — perfect predictions give micro/macro
F1 = 1.0 with zero benign-FP, garbage (unknown id on every malicious
sample) gives F1 = 0.0, and one flagged benign sample moves the rate to
0.5. It exits non-zero on any violation, so it's CI-able as-is.
