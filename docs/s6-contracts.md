# S6 Composition — wave contracts (lead-authored, FROZEN for bots)

Shared interfaces for the S6 build wave. Implement against these exactly;
`src/fugu/types.py` and `src/fugu/pipeline/base.py` stay UNTOUCHED (change
requests go in your summary). No new dependencies anywhere (stdlib + existing).

## 1. Capability taxonomy (plain strings — no enum added to types.py)

- Legs: `INGRESS`, `PRIVATE-DATA`, `EGRESS`, `EXEC`
- Modifiers: `INJECTION-CARRIER`, `AGENT-INFLUENCE`, `DEFENSE-GAP`
- Strength: `strong` | `medium` | `weak` (from the contributing finding's
  confidence tier: deterministic/empirical → strong, measured → medium,
  advisory → weak)

Dataclasses live in `src/fugu/pipeline/stages/composition.py` (NOT types.py):

- `Capability(kind: str, strength: str, source_finding_title: str, evidence: EvidenceSnippet)`
- `ExtensionNode(label: str, slug: str, capabilities: list[Capability], tool_names: list[str], findings: list[Finding])`
- `MemberResult(label: str, slug: str, findings: list[Finding], tool_names: list[str], target_dir: Path | None)`

## 2. CompositionStage + pure detectors (workstream W1)

- Class `CompositionStage` implements the Stage protocol (`name = "composition"`).
- The runner injects members via attribute: `stage._member_results: list[MemberResult]`
  set before `run`. Missing/empty → `StageResult(ok=True, metrics={"skipped": "single-source job"})`.
- `run()` maps each MemberResult to an ExtensionNode via pure
  `map_capabilities(findings, tool_names) -> list[Capability]`, then calls pure
  `detect_trifecta(nodes) -> list[Finding]` and `detect_shadowing(nodes) -> list[Finding]`.
  Pure functions must be importable and unit-testable with zero stage machinery.
- Signal → capability mapping (from docs/s6-plan.md §1a): static findings whose
  rule ids/titles indicate env harvest / sensitive-path access → PRIVATE-DATA;
  curl-to-raw-IP / curl-pipe-shell / install-script fetches → EGRESS (+EXEC);
  npm hooks / setup.py execution → EXEC; skill-injection phrases / tool-description
  injection / concealment payload families → INJECTION-CARRIER; semantic findings
  with owasp_ids LLM01/MCP03/MCP06 → INJECTION-CARRIER weak; detonation canary
  exfil → EGRESS+PRIVATE-DATA strong; unexpected egress → EGRESS medium; harness
  disclose/directive signals → AGENT-INFLUENCE; tool names/docs matching
  fetch|get|read|web|url|rss verbs → INGRESS medium. Read the real rule ids from
  `src/fugu/pipeline/stages/static_scan.py` and `harness.py` — do not guess.
- Trifecta detection: minimal combos of 2–3 DISTINCT extensions covering
  INGRESS + PRIVATE-DATA + EGRESS; prune supersets; rank by leg-strength sum
  (+3 if the ingress node is INJECTION-CARRIER or AGENT-INFLUENCE); emit ≤5.
- Honesty rules: bare weak-leg co-existence with no carrier → severity low,
  confidence advisory (hygiene note). All-advisory legs → severity at most
  medium and the finding must read as WARN-level, never FAIL-level.
- Severity policy: trifecta with ≥1 strong leg → high (confidence from the
  strongest contributing tier, at most `measured`); otherwise medium. Shadowing
  → medium, high if the shadowING extension has INJECTION-CARRIER.
- OWASP ids: trifecta → MCP03 + MCP06 + LLM02 (+MCP07/MCP10 where the evidence
  says so); shadowing → MCP03 (NOT MCP09).
- Findings are ordinary `Finding(stage="composition")`; one EvidenceSnippet per
  leg, source string format `member:<slug>:<finding-title>`; shadowing evidence
  source `tools:<name>`.
- Tool-name normalization: lowercase, strip `mcp__server__` style prefixes,
  collapse non-alphanumerics.

## 3. Multi-source server plumbing (workstream W3)

- `POST /audits` body gains OPTIONAL `sources: list[{ref: str, label: str | null}]`
  (2..8 entries, validated like `source` today: local dir must exist; git URLs
  accepted for runtime). When `sources` is present, `source` must be absent/null.
- Parent job: `job.source = "composition:" + ", ".join(label or ref for each)`.
  Response shape unchanged (job_id, status, events URL).
- New module `src/fugu/server/composition_jobs.py` exposing
  `async def run_composition_job(job, sources, stages_for_children, store, max_files, max_bytes) -> None`:
  1. Per source (sequentially): child `AuditJob(id=new_job_id(), source=ref, depth="standard")`,
     `store.create`, then call the EXISTING `run_job(child, stages, store, keep_target=True)`.
     After each child, emit parent log event:
     `{"stage": "composition", "message": "member <label>: job <child_id> <status>, <N> findings", "child_job_id": <child_id>}`.
  2. Build MemberResults from each child snapshot (`snap.findings`,
     `snap.target_dir`); harvest tool_names by scanning text files under the
     child target with the same tool-name regex used by static_scan.
  3. Clean up cloned child target dirs (git sources) after harvest; local dirs are
     the user's own — never delete.
  4. Inject `_member_results` into a `CompositionStage` instance imported from
     `fugu.pipeline.stages.composition`, run it as the parent's ONLY stage using
     the same emit/persist pattern as run_job (stage_started / finding /
     stage_done with dedupe skipped — composition findings are never echoes).
  5. Parent verdict via `aggregate_verdict(parent_findings, parent_stages)`,
     status done, close stream. Parent failure mode: if EVERY child failed
     extraction → parent status failed with error event.
- Single-source path (no `sources`) stays byte-identical: same handler code path
  as today, all existing tests untouched.
- W3's own tests use a STUB composition stage injected via the same attribute
  contract (no dependency on W1 landing); integration with the real stage is the
  lead's job.

## 4. Corpus set schema (workstream W2)

`corpus/composition/<set-name>/set.json` + one subdir per member:

```json
{
  "name": "trifecta-canonical",
  "kind": "attack",
  "description": "one line",
  "members": [{"dir": "web-digest", "label": "web-digest"}],
  "expected": {"trifecta": true, "shadowing": false}
}
```

- 2..8 members; each member dir is a plausible mini-extension (SKILL.md and/or
  MCP server shape, style of `corpus/01-*` … `corpus/08-*`).
- Attack trifecta sets: the UNION completes ingress + private-data + egress, but
  EVERY member is individually clean: running concealment+static only
  (`run_audit(..., include_detonation=False, include_semantic=False,
  include_harness=False, include_reputation=False)`) yields NO high/critical
  finding for any member alone. Loader + corpus tests enforce this precondition.
- Attack shadowing sets: colliding normalized tool names across members,
  individually clean otherwise.
- Controls (kind "control"): benign unions — ingress+egress with NO private-data;
  private+egress with no ingress; single self-sufficient extension + clean
  neighbors (must NOT be reported as cross-extension).
- Required sets: canonical trifecta, shuffled-order variant, dilution variant
  (+2 irrelevant members), shadowing set, and ≥3 controls covering the cases above.

## 5. Eval set metrics (workstream W5)

- `eval/loader.py`: add `load_set_specs(root: Path) -> list[SetSpec]` where SetSpec
  mirrors set.json (name, kind, members, expected). Existing loaders unchanged.
- `eval/metrics.py`: add pure `set_metrics(results, specs) -> dict` producing
  per-set rows (name, kind, expected, predicted, correct) plus
  `set_detection_rate` over attacks and `set_fp_rate` over controls. Reported
  SEPARATELY from per-extension metrics; composition tier labeled "advisory".
- `eval/run_eval.py`: new `--sets PATH` mode scoring a predictions JSON of shape
  `{"sets": [{"set": name, "trifecta": bool, "shadowing": bool}]}`. Existing
  modes untouched. Build your own tiny fixture sets under
  `tests/fixtures/composition-sets/` — do NOT depend on corpus/composition existing.
- Tests: `tests/test_eval_sets.py` (hermetic).

## 6. Web wire format (workstream W4)

- Composition findings arrive as ordinary SSE `finding` events and
  `GET /api/audits/<id>` entries: `stage: "composition"`, member attribution in
  `evidence[].source` (`member:<slug>:…`, `tools:<name>`), stage list contains a
  single `{stage: "composition"}` entry for multi-source jobs. No API changes.
- `web/src/lib/types.ts` + `STAGE_ORDER`: add "composition" (render only when present).
- Member strip in the pipeline monitor: parse parent `log` events carrying
  `child_job_id` into a compact member list (label + status + findings count).
- Scorecard "Combination" section, rendered only when composition findings exist:
  chain view INGRESS → PRIVATE-DATA → EGRESS, nodes labeled with member labels,
  red chain when a trifecta finding fired; shadowing shown as colliding tool names.
- Match the existing Tailwind/shadcn style; `npm run build` + `npx tsc --noEmit` clean.
- Build against `web/src/lib/mockStream.ts` extended with a mock composition job.

## 7. Ownership map (territories — zero overlap)

| WS | Territory (create/modify ONLY here) |
|----|-------------------------------------|
| W1 | `src/fugu/pipeline/stages/composition.py`, `tests/test_composition_core.py` |
| W2 | `corpus/composition/**`, `tests/test_composition_corpus.py` |
| W3 | `src/fugu/server/composition_jobs.py`, `tests/test_composition_server.py`, surgical edits in `src/fugu/server/app.py` (ONLY: request model gains `sources`, `create_audit` branches to `run_composition_job`; no other handler), export in `src/fugu/server/__init__.py` |
| W4 | `web/src/**` |
| W5 | `eval/loader.py`, `eval/metrics.py`, `eval/run_eval.py`, `tests/test_eval_sets.py`, `tests/fixtures/composition-sets/**` |
