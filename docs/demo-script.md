# Fugu demo: an evidence-backed install decision

Target: **2 minutes 45 seconds**, leaving margin under three minutes. Audience:
a developer evaluating a community extension before giving an AI coding assistant
access to its workspace/tools. This is a proposed recording script, not evidence
that recording or publication has happened.

## Rehearse before recording

1. Use the reviewed build and a dedicated persistent database. Open live mode
   at `/?mock=0`; confirm **LIVE ANALYSIS** and the API-provided bundled examples.
   Select **Hidden instructions**, then **Start audit**. Do not assume
   a sample exists on every server; use one accepted small source if absent.
2. Complete the suspicious run and **Benign comparison**. Check actual verdict reasons,
   coverage and exhibits; counts/timing can differ from the two earlier UI runs.
   Verify failure, skip and no-trigger language on the final backend build.
   Those two stored UI audits predate the larger current production profile; do
   not present them as evidence of the new limits or benchmark behavior.
3. Expand a decisive finding and the pipeline/history disclosure. Reopen the
   real `/audit/<id>` URL and confirm it restores that run without creating one.
4. Record desktop and narrow-screen readability. Keep credentials and unrelated
   workspace data out of frame. For the exact current audit, read
   `GET /api/audits/<id>` and show its actual `stages[].metrics.effective_limits`,
   coverage omissions, `llm_calls`, and `request_attempts` if showing limits or
   sponsor use. `llm_calls` is a logical-call summary, not an SDK dispatch count.
   Use attempt records for requested/served model IDs and token usage; unknown
   usage is null, not zero. Show this response in a terminal or API viewer,
   not an invented UI model panel. Do not assume complete Super telemetry.
5. Use visibly labeled time cuts or an earlier completed real audit for long
   waits. `/?mock=1` and **Play simulated audit** are scripted illustrations,
   explicitly labeled **SIMULATED**, not recorded measurements. They make no
   source/model analysis call and do not validate the submitted extension.

The 2 October full-capability benchmark includes verified Docker canary
evidence. A recording that shows a canary must rehearse the chamber on its
actual source/build and show that run’s fake-canary evidence and coverage;
the new current-profile measurement excludes detonation. Remote Nebius
Sandboxes transport remains unverified. No hit is not proof of safety.

The current production profile allows up to 4,096 output tokens per request,
24 semantic units of at most 6,000 characters each, a 32,000-character harness
source/RED packet, and the first three valid generated probes up to 200
characters each. Requests time out at 90 seconds and the SDK performs zero
automatic retries; explicit stage-level response recovery is separately
recorded. These are product bounds, not a UI depth setting or proof that every
source file was analyzed. Rehearse against the exact current build and use that
audit’s omission and completion metrics. See [production limits](production-limits.md)
and the [current-limit protocol](benchmark-current-limits.md).

## Storyboard and narration

| Time | Actual screen/action | Narration |
|---|---|---|
| 0:00–0:15 | Entry in live mode | “I want to add a community skill to my coding agent. That agent can read my workspace and run tools. Before I grant access, I audit the extension with Fugu.” |
| 0:15–0:35 | Select bundled suspicious example; Start audit | “Fugu decodes concealed text and checks concrete patterns locally. NVIDIA Nemotron on Nebius Token Factory reads supplied text for suspicious instructions when hosted analysis is enabled. Runtime checks depend on the available chamber.” |
| 0:35–1:15 | Completed report; expand decisive finding | “Here is the reason to stop before installing.” Point to the actual source excerpt and evidence tier. “This source match is deterministic; the model’s interpretation is advisory. The A/B harness compares the agent’s stated plans with and without the extension.” Do not describe plan text as executed actions or a universal exfiltration proof. |
| 1:15–1:40 | Analysis coverage beside verdict; pipeline disclosure | “These are the checks that completed and the source or probes each could inspect. Fugu reports omissions when a bound or request prevents complete coverage. A missing check is not a clean result. I would investigate this exact behavior before installing this version.” |
| 1:40–2:05 | New audit; rehearsed clean result | “For this clean example, completed checks found no qualifying issue. A PASS is a scoped result, not a certificate of safety. A skill without runnable triggers was not executed.” |
| 2:05–2:30 | Existing audit API model records; brief sponsor explanation | “The configured Token Factory endpoint supplies NVIDIA Nemotron inference. Ultra handles semantic analysis and the default harness calls; Super supplies the everyday-agent arm. Extension text goes to hosted inference when these checks are enabled.” |
| 2:30–2:45 | Reopen suspicious audit URL or Continue an audit | “I can return to the same evidence and coverage without starting another audit. Fugu gives me an inspectable reason for an install decision.” |

Optional verified canary substitution for 0:35–1:15: show an actual trigger,
captured destination and fake-canary match. Say “The chamber observed this fake
secret in this captured request.” State the driver and observation boundary.
A simulated canary panel must retain its simulated label and cannot substitute
for that live proof.

## Sponsor and claims checklist

The [client](../src/fugu/client.py) connects to configured Nebius Token Factory;
[semantic](../src/fugu/pipeline/stages/semantic.py) selects Ultra, and
[harness](../src/fugu/pipeline/stages/harness.py) uses that default caller for probe
generation, baseline and strong mounted responses plus an explicit Super arm.
The verifier uses deterministic response-signal checks; there is no separate
LLM adjudication call. Nano is a router option,
not an established active analysis stage. Optional cloud sandbox code is not
proof of live Nebius Sandbox deployment. Tavily/OSV reputation lookups cross
the local boundary when active.

Keep benchmarks brief. The [2 October full-capability report](benchmark-full.md)
records 40 frozen cases completed after bounded recovery, with Fugu detecting
12/15 shared attack descriptions versus fuzzd’s 10/15 at medium severity or
above. Those results belong to that dated frozen run; the reported zero
confirmed false positives use its adjudication contract. Authored
source/composition/dependency cohorts remain separate. Show the historical
comparison chart with its task distinctions and unavailable Snyk result.

The [3 October current-limit report](benchmark-current-limits.md) is a stopped
subset, not a completed 40-case evaluation. It records 12 completed cases, one
partial and 27 unattempted after an HTTP 500 from the Super harness at SDK
attempt 359. All 12 completed cases and the one partial case were MCPTox
descriptions. The primary MCPTox result is 11/15 planned attacks (73.3%); the
secondary completed-case result is 11/12 (91.7%). One complete miss, one partial
case and two unattempted attacks remain visible. All 12 benign controls were
unattempted, so benign flag and false-positive rates are unmeasured. The chart’s
zero confirmed false-positive records reflect no observed benign cases, not a
clean-control result. The run observed S0/S1/S2/S4 on 13 of 45 distinct audits;
32 remain unknown, and no composition case started. Detonation, live reputation,
target execution and fresh competitor execution are outside this run. The selected,
previously inspected cases do not establish blind or population performance.
One failed request has unknown token usage; cost and remaining quota are
unknown, and quota exhaustion was not established. Do not claim latency or
cost savings, universal superiority, adoption or complete safety.

Before publication, confirm the exact reviewed commit, public repo/demo access,
video duration and permissions for recorded material. Deployment and public video
publication remain unassigned outcomes. See [readiness](hackathon-assessment.md).
