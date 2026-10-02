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
3. Expand a decisive finding and the pipeline/history disclosure. Reopen the
   real `/audit/<id>` URL and confirm it restores that run without creating one.
4. Record desktop and narrow-screen readability. Keep credentials and unrelated
   workspace data out of frame. Read `GET /api/audits/<id>` for actual `stages[].metrics.llm_calls`
   if showing sponsor use; these model records were present in the inspected
   existing suspicious run. Show this response in a terminal or API viewer,
   not an invented UI model panel. Do not assume complete Super telemetry.
5. Use visibly labeled time cuts or an earlier completed real audit for long
   waits. `/?mock=1` and **Play simulated audit** are scripted illustrations,
   explicitly labeled **SIMULATED**, not recorded measurements. They make no
   source/model analysis call and do not validate the submitted extension.

Docker was unavailable for current live verification. Do not press **Detonate**
or promise a canary result in the main recording. Only include a canary segment
if the lead assigns and verifies a live chamber run on the target; show its actual
fake-canary evidence and coverage. No hit is not proof of safety.

## Storyboard and narration

| Time | Actual screen/action | Narration |
|---|---|---|
| 0:00–0:15 | Entry in live mode | “I want to add a community skill to my coding agent. That agent can read my workspace and run tools. Before I grant access, I audit the extension with Fugu.” |
| 0:15–0:35 | Select bundled suspicious example; Start audit | “Fugu decodes concealed text and checks concrete patterns locally. NVIDIA Nemotron on Nebius Token Factory reads supplied text for suspicious instructions. Runtime checks depend on the available chamber.” |
| 0:35–1:15 | Completed report; expand decisive finding | “Here is the reason to stop before installing.” Point to the actual source excerpt and evidence tier. “This source match is deterministic; the model’s interpretation is advisory. The A/B harness compares the agent’s stated plans with and without the extension.” Do not describe plan text as executed actions or a universal exfiltration proof. |
| 1:15–1:40 | Analysis coverage beside verdict; pipeline disclosure | “These are the checks that completed, and these did not. A missing check is not a clean result. I would investigate this exact behavior before installing this version.” |
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

Keep benchmarks off the core story. If shown, use the [fresh report](benchmark.md):
26 detections among 30 planned attacks, with two completed misses and two parse
failures among the remaining cases; constructed clean 0/20 and public skills 0/19 completed with one
incomplete of 20 stay separate. No superiority, zero-FPR, adoption, cost-saving
or full local-only claim. Historical label-contaminated headlines are excluded.

Before publication, confirm the exact reviewed commit, public repo/demo access,
video duration and permissions for recorded material. Deployment and public video
publication remain unassigned outcomes. See [readiness](hackathon-assessment.md).
