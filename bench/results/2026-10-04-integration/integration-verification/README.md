# Offline integration verification — 4 October 2026

The retained paired measurement has **40 planned cases, 45 unique inputs, 36 complete cases and four partial cases**. Its full-workflow external attack alerts are **12/15 baseline and 14/15 integrated**. Both variants flag **0/4 complete clean descriptions**, out of five planned. This check made **zero new inference, search, scanner, chamber or target calls**.

This is an independent recount and portable selection of existing evidence. It does not measure the final integrated engine. Lead integration and an independent review of the released candidate remain outstanding.

## Results and scoring

| Family | Complete / planned | Baseline alerts | Integrated alerts |
|---|---:|---:|---:|
| External MCPTox attack descriptions | 15/15 | 12/15 | 14/15 |
| Clean descriptions | 4/5 | 0/4 | 0/4 |
| Authored attack fixtures | 6/7 | 6/6 | 6/6 |
| Authored controls | 2/4 | 0/2 | 0/2 |
| Composition attack sets | 4/4 | 3/4 | 3/4 |
| Composition controls | 3/3 | 0/3 | 0/3 |
| Pinned dependency probes | 2/2 | 2/2 | 2/2 |

Ordinary cases count any medium, high or critical finding. Composition counts its own trifecta or shadowing alert; its legacy shadow-pair expectation remains unmatched because informational name overlaps do not establish a shared runtime namespace. Dependency probes count measured reputation findings. An alert does not establish an exploit. External descriptions and authored fixtures have different provenance and remain separate.

The four partial rows remain excluded, including their raw alerts:

- `clean/translate_text`: 18/18 harness comparisons finished, but 99 generated probe characters were omitted. Its high alert is retained.
- `crafted/03-env-harvest-installer`: its trigger exited nonzero. The package separately reports synthetic canary exfiltration before exit; this is not a completed workflow.
- `crafted/08-clean-mcp-server`: two trigger failures; the package diagnostic attributes these to an invalid Python fixture.
- `crafted/10-clean-node-skill`: one trigger failure; the package diagnostic attributes this to runtime and argument limitations. Its advisory reputation alert remains.

Those diagnostic explanations are prior package evidence, not fresh reproductions here. No partial was relabelled. Four complete clean descriptions cannot establish a population false-positive rate. Description-only inputs have no runnable trigger; the stage records not applicable. Omission, failure and missing applicability remain distinct in [selected stages](selected/fugu.json) and [coverage counts](charts/chart-data.json).

Nonstatic audit records are identical across baseline and integrated variants. We verified all 45 audit pairs, their input hashes, every member-to-case link, all 40 saved row files and the final summaries. Native nonstatic stages ran once per unique input; the configurations reuse those results. Composition and verdicts were recomputed per configuration. These are paired static interventions, not independent stochastic model trials.

## Comparator and separate static study

MCP-Sec-Audit 0.1.0 completed the same 20 description packets. The retained source commit is `457057a7dfda6b81622a12ee68b74f76f3fbde85`; its rulebook hash is in [the selected comparator](selected/mcp-sec-audit.json). All 20 packet hashes match the frozen inputs. The adapter supplies the same name and description and an empty input schema; labels and provenance stay outside scanned directories.

The competitor flagged **0/15 attacks at aggregate risk ≥25** and **12/15 with any native finding**, with **0/5 clean alerts**. Both thresholds are retained. They are not calibrated to Fugu severity, and the competitor has source-only scope. The common chart contains 19 matched complete cases: 15 attacks and four controls. It supports no overall product ranking.

The separate **140-input static diagnostic** contains 80 external response-all attacks and 60 clean descriptions: **72/80 attack alerts and 0/60 clean alerts**. It measures S0/S1 only. The wrapper's proposed 200-case suite was not fully measured; no 200-case or 140-case full-workflow result is claimed.

## Requests, sources and engine boundary

The original interval is **2026-10-04 11:00:56–11:41:56 UTC**. Recounted SDK usage is **1,296 attempts, 588,053 prompt tokens and 418,018 completion tokens**. All finish reasons are `stop`; recorded provider errors, output errors, orphan attempts and unknown usage counts are zero. Every request has a 4,096-token cap and one of the two pinned NVIDIA model IDs. Message, request and response hashes match all 1,296 raw records. The sum of request durations is 2,249.273473237001 seconds; it is not a separate wall-clock measurement.

There are **16 retained Tavily search records**, with no recorded error or stop latch. Native OSV queries also occurred; they are not counted as Tavily searches. There is no persistent `searches/budget.json` in the package. The plan records a 1,900-attempt / 180-search ceiling. Remaining quota and dollar cost are null; no cost claim is supported.

The 39-file frozen engine matches its manifest and plan. Recorded hardening changed only `tool_surface.py`, from `085a67e89d0c1173e3fd3501120b0623641cb5a684e643529bd11a5c329e98d9` to `fcfeb8010910e4f3f7c817acfbb592b4343f17a10595d102d916f997f3c31cc5`. The immutable package records 45 checks preserving decision signatures and completion. We bound that record to all 45 inputs and every delivered engine hash; we did not rerun its Docker scanner.

The final backend additionally changes:

- `static_context.py`: delivered `02066902f11cdcd67291301ab9da3deb9d232fcb642267d9348b08dadde89021`, current `66386285547f6558c196425e030ac1105a43590456e3e213dfa02f18a6eadccf`. The change indexes AST nodes and bindings once. Backend reports matching context classifications on 45 inputs; that is separate parser evidence.
- `static_scan.py`: delivered `a0f4f488a18f32802e5bea17c6831a27d7560fd98897c2165bdc153803236535`, current `b4d28cccbe24569794b67f2931d2db80cea6add3420dc724de900eb9f2f0e53b`. A bounded correction retains npm-hook findings when an apparent echo/exit command contains shell control, substitution or newlines.

The original masking-only equivalence does not establish equivalence for these later changes. [Source bindings](source-binding.json) make the distinction explicit. `verify_static_hardening.py` supports the delivered masking-only snapshot and rejects any other engine change vector. It now requires an explicit package and separate output and checks that a scan loads the source being hashed. Backend reported a denied Docker build and a Linux aarch64 binary unavailable for host execution; this seat did not retry either action.

The lead subsequently supplied two separate, retained proofs. [Final source parsing](lead-proofs/source-only-verification.json) reports matching baseline S1 decision signatures and `ok` on all 45 original inputs. We checked its 45 input fingerprints and all 39 current source hashes against the export and checkout. It also records 600/1,200/6,000-list parser timings of about 6.5/13/76 milliseconds. [Installed activation](lead-proofs/installed-activation.json) records normal `build_stages()` using the exact pinned binary and an existing trusted image on inert skill text, with networking disabled: five advisory findings and no omissions or parse errors. This distinct static text check did not retry Buildx or execute an auditee. These are lead-produced static checks, not new full-workflow, inference or chamber results. [Exact proof hashes and origin](lead-proof-binding.json).

The former Requests 2.32.5 control is below the maintainer's patched version, 2.33.0. Exposure requires direct calls to `extract_zipped_paths()`; ordinary Requests use is unaffected. The retained package-version alert does not prove this fixture is exploitable. Frozen labels remain unchanged. [Requests maintainer advisory](https://github.com/psf/requests/security/advisories/GHSA-gc5v-m9x4-r6x2), checked 4 October 2026.

## Portable evidence and preservation

The original delivery manifest is preserved byte for byte as [raw-delivery-manifest.json](raw-delivery-manifest.json), SHA256 `10f768e2efe8710828482abbc12fac2cf3c22d9be42b9e83e90cd5eaf20ab611`. All **1,572 entries**, including byte counts, matched. The [separate schema2 inventory](inventory.json) binds these seven adopted paths and this verification directory; it excludes itself. The lead-supplied integration base is `6f22bb00eb92bb028e2a03249c95e92034e485cd`; this seat ran no Git commands.

The public selection contains case outcomes, severity/confidence, numeric coverage, 1,296 request metadata rows, 16 search metadata rows, source/input/audit hashes and chart inputs. SDK records use one compact object per line inside valid JSON; [the packaging check](sdk-metadata-packaging.json) confirms every value and null is preserved. Raw prompts, replies, finding excerpts, searched content, downloaded third-party source, binaries and the frozen source engine remain in the local package. Content omissions are explicit; errors and unknown token totals are not converted into successful work. This boundary supports offline recount and charts, not a fresh model or chamber reproduction.

A retained pattern scan examined text-like manifest entries without printing matched values. It found 45 GitHub-token pattern occurrences across two distinct synthetic values: the documented authored fake-token fixture and the synthetic redaction test. No other configured token/key pattern matched. Pattern checks do not prove absence of every credential format. Neither value nor any content payload is exported. The exact scan and classifications are in [verify_selected.py](verify_selected.py) and [export-verification.json](export-verification.json).

All **3,241 historical benchmark files and three owner files** still match their preserved hashes. Eighteen of the 20 previously copied deliverables are unchanged. The two docs files, `README.md` and `docs/benchmark-workflow-integration.md`, are being updated by the independently leased docs owner: lead transition 836 on `qitem-20261004145850-e7f836b4` explicitly granted those paths after backend released writer1. Their original and observed hashes are retained; research did not edit or overwrite them. [Preservation check](preservation-verification.json), [external docs lease](external-docs-lease.json). All 81 input files were restored from existing matching regular bytes into a new scratch directory, yielding exactly 40 cases and 45 unique audit fingerprints. No inputs were executed. The [restoration map](input-restoration-map.json) requires those existing cached bytes; it does not bundle them or guarantee they exist in a fresh checkout.

## Reproduce the offline checks

From the repository root, the selected recount needs only Python 3.10+ and the files in this directory:

```sh
python3 bench/results/2026-10-04-integration/integration-verification/verify_selected.py \
  --output bench/results/2026-10-04-integration/integration-verification
```

Charts were generated with the cached isolated Python 3.11.16 environment, Matplotlib 3.11.2 and NumPy 2.4.6. A different machine can provision a separate plotting environment without changing project dependencies:

```sh
uv venv /tmp/fugu-workflow-evidence-plot-env --python 3.11
uv pip install --python /tmp/fugu-workflow-evidence-plot-env/bin/python \
  matplotlib==3.11.2 numpy==2.4.6
```

Use that interpreter, or the existing cached interpreter below, with a new output directory to preserve the retained charts. No dependency provisioning was performed in this task:

```sh
MPLCONFIGDIR=/tmp/fugu-workflow-evidence-mpl PYTHONDONTWRITEBYTECODE=1 \
  /tmp/fugu-charts-venv/bin/python bench/render_paired_workflow.py \
  bench/results/2026-10-04-integration/integration-verification/selected \
  --output /tmp/fugu-workflow-evidence-charts
```

For offline input restoration, choose an absent or empty scratch directory:

```sh
python3 bench/results/2026-10-04-integration/integration-verification/verify_selected.py \
  --repo "$PWD" --output bench/results/2026-10-04-integration/integration-verification \
  --restore-scratch /tmp/fugu-workflow-evidence-restored-new
```

The authenticated task allowed this export only. Any future native benchmark or static scanner execution needs its own assignment. The retained historical plan's authority text grants no new execution.

## Actual checks and remaining review

- Scoped fake/pure tests: **13 passed**. New tests first failed on the missing output/parser interfaces, then passed after the small wrapper fixes. A loaded-source mismatch check also failed before its guard was added.
- Ruff on all seven assigned paths and the export checker: **passed**.
- Raw bindings, native scoring, pairing, cases, ledgers and selected recount: **passed**.
- Chart data: exactly equal to the package and previously copied data. All four PNGs are byte-identical to the delivered PNGs. SVG bytes differ because rendering records fresh metadata/IDs; plotted data is unchanged.
- All four PNGs visually inspected: readable, no clipped labels, explicit complete-case and source-only scope.
- Input restoration and protected-file hashes: **passed**.

[Commands and logs](checks.json), [recount](recount.json), [chart checks](chart-verification.json), [restoration check](restoration-verification.json). The renderer now accepts a separate output; the hardening helper requires output outside the original measurement. The other four adopted files remain byte-identical to the delivery. Final independent full-range review and lead integration remain required.
