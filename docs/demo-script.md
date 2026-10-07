# Fugu demo: an evidence-backed install decision

Target: **2 minutes 45 seconds**, leaving margin under three minutes. Audience:
a developer evaluating a community extension before giving an AI coding assistant
access to its workspace/tools. This is a proposed recording script, not evidence
that recording or publication has happened.

Updated **7 October 2026** against accepted production engine
`ed2c134011689a1c4f3241bee6df7f026f5de214`. The [offline casebook](judge-casebook.md)
now reproduces three authored source/decision boundaries. The latest retained
benchmark is the **5 October** frozen workflow, not a new measurement on this
engine. Recording, live success rehearsal and publication remain unverified.

## Choose and label the evidence mode

| Mode | What it establishes | Label and current status |
|---|---|---|
| [Offline casebook](judge-casebook.md) | Real production local analysis of authored inert text via in-process API/SSE; decoded exhibit, limited PASS and missing-source error | **OFFLINE SOURCE AUDIT — local checks only.** Three cases verified 7 October; no hosted inference, chamber or target execution. |
| UI `/?mock=1` / Play simulated audit | Scripted interface walkthrough; no source audited | **SIMULATED — scripted findings/verdict.** Never substitute for real source or sponsor evidence. Controlled transport fixtures are UI validation only. |
| Current-build live provider/chamber rehearsal | Only the actual audited source, supplied model/attempt records and any genuinely observed chamber evidence | **HUMAN-AUTHORIZED LIVE REHEARSAL — unverified until run.** Credentials, environment choice, paid calls, recording and publication are human-owned. |

Do not combine the modes into a purported live run. Pick one for the recording,
keep its label visible and disclose omissions. The offline casebook can be
reproduced now without credits or a shared server:

```sh
PYTHONPATH="$PWD/src:$PWD" PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY="" \
  uv run --no-sync python -m pytest tests/test_judge_casebook.py -q -s
```

### Offline 2:45 storyboard (proposed recording)

| Time | Terminal output/action | Narration |
|---|---|---|
| 0:00–0:20 | Name the before-install decision and show **OFFLINE SOURCE AUDIT** label | “These are authored examples. We audit source text locally; models and runtime are unavailable.” |
| 0:20–0:45 | Run the command above; show actual CASEBOOK output | “The real API and local scanners run in temporary state. No source is executed or sent to a provider.” |
| 0:45–1:20 | Hidden case: file:SKILL.md:L5, decoded payload, critical deterministic finding and FAIL reason | “The visible note conceals an instruction. This is the exact decoded source evidence. I stop and investigate; no agent behavior was observed.” |
| 1:20–1:55 | Ordinary case: scoped PASS, semantic/harness skipped, optional surface scanner disabled, reputation/detonation excluded | “No finding from the performed local checks is not a safety certificate. I inspect missing coverage and permissions before installing.” |
| 1:55–2:20 | Absent case: HTTP 422 versus accepted-then-removed terminal error and zero verdicts | “Missing input cannot produce a clean verdict. I restore the source or correct its path and retry.” |
| 2:20–2:45 | Explain the next action and the human audience protocol | “Fugu makes the evidence and limits inspectable. These cases do not prove audience benefit or NVIDIA runtime; those need separate observation.” |

Use actual observed outputs and label any time cut. The test run duration is not
end-user decision time or a savings estimate. The third case deliberately removes
an owned source after acceptance; it is a controlled extraction failure, not a
shared-server request or a provider error. Public demo/video access, audience
outcomes and submitted-build live success still require human follow-through.

## Human-authorized live rehearsal before recording (unverified)

1. Use the reviewed build and a dedicated persistent database. Open live mode
   at `/?mock=0`; confirm **LIVE ANALYSIS** and the API-provided bundled examples.
   Select **Hidden instructions**, then **Start audit**. Do not assume
   a sample exists on every server; use one accepted small source if absent.
2. Complete the suspicious run and one clean-description comparison. Check actual
   verdict reasons, coverage and exhibits; counts/timing can differ from the two
   earlier UI runs. If showing the measured `clean/read_file` case, disclose that
   its raw model flag is pending independent adjudication and came from a
   synthetic harness canary in model replies; no file tool or target filesystem
   ran. Do not present that flag as a real extension exploit or a confirmed
   false positive. Verify failure, skip and no-trigger language on the final
   backend build. The two stored UI audits predate the current profile; do not
   present them as evidence of its limits or benchmark behavior.
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
6. On the human-approved demo environment, submit an intentionally missing local
   source before recording. Confirm analysis interrupted, the actual error in
   Stream log, stopped empty views and a working **new audit** action. Return
   to the approved real sample. The 6 October browser fixture proved this UI
   behavior with controlled responses; it did not exercise extraction or a
   provider. Do not use that fixture as the functioning judge demonstration.

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
audit’s omission and completion metrics. See [production limits](production-limits.md),
the [first-interval stop report](benchmark-current-limits.md), and the
[sealed two-interval continuation report](benchmark-current-limits-continuation.md).

## Live 2:45 storyboard and narration (proposed, after verified rehearsal)

| Time | Actual screen/action | Narration |
|---|---|---|
| 0:00–0:15 | Entry in live mode | “I want to add a community skill to my coding agent. That agent can read my workspace and run tools. Before I grant access, I audit the extension with Fugu.” |
| 0:15–0:35 | Select bundled suspicious example; Start audit | “Fugu decodes concealed text and checks concrete patterns locally. NVIDIA Nemotron on Nebius Token Factory reads supplied text for suspicious instructions when hosted analysis is enabled. Runtime checks depend on the available chamber.” |
| 0:35–1:15 | Completed report; expand decisive finding | “Here is the reason to stop before installing.” Point to the actual source excerpt and evidence tier. “This source match is deterministic; the model’s interpretation is advisory. The A/B harness compares the agent’s stated plans with and without the extension.” Do not describe plan text as executed actions or a universal exfiltration proof. |
| 1:15–1:40 | Analysis coverage beside verdict; pipeline disclosure | “These are the checks that completed and the source or probes each could inspect. Fugu reports omissions when a bound or request prevents complete coverage. A missing check is not a clean result. I would investigate this exact behavior before installing this version.” |
| 1:40–2:05 | Clean `read_file` description; show actual coverage and model evidence | “This description asks for ordinary file reading. The mounted model response included our synthetic canary after a probe asked for file contents. No file tool or target filesystem ran. The raw flag is under independent adjudication, so I treat it as a reason to inspect, not proof of malicious behavior.” |
| 2:05–2:30 | Existing audit API model records; brief sponsor explanation | “The configured Token Factory endpoint supplies NVIDIA Nemotron inference. Ultra handles semantic analysis and the default harness calls; Super supplies the everyday-agent arm. Extension text goes to hosted inference when these checks are enabled.” |
| 2:30–2:45 | Reopen suspicious audit URL or Continue an audit | “I can return to the same evidence and coverage without starting another audit. Fugu gives me an inspectable reason for an install decision.” |

Optional verified canary substitution for 0:35–1:15: show an actual trigger,
captured destination and fake-canary match. Say “The chamber observed this fake
secret in this captured request.” State the driver and observation boundary.
A simulated canary panel must retain its simulated label and cannot substitute
for that live proof.

## Sponsor and claims checklist

For the offline casebook, semantic/harness explicitly skip because the key is
empty; no model is served and no NVIDIA/Nebius runtime claim is supported.
The roles below describe production code and a proposed real rehearsal, not
inference observed in these new cases.

The [client](../src/fugu/client.py) connects to configured Nebius Token Factory;
[semantic](../src/fugu/pipeline/stages/semantic.py) selects Ultra, and
[harness](../src/fugu/pipeline/stages/harness.py) uses that default caller for probe
generation, baseline and strong mounted responses plus an explicit Super arm.
The verifier uses deterministic response-signal checks; there is no separate
LLM adjudication call. Nano is a router option,
not an established active analysis stage. Optional cloud sandbox code is not
proof of live Nebius Sandbox deployment. Tavily/OSV reputation lookups cross
the local boundary when active.

Keep benchmarks brief. The [5 October full-workflow report](benchmark-full-workflow-20261005.md)
and its charts are the latest retained measurement: **110/140 Fugu cases
complete and 30 partial**, with **314/320 native comparator rows complete**.
The engine was frozen at `dbc4f641bfad39f7004e64f08bf8351697f5ae7c`;
this candidate was not measured. Show planned coverage beside any matched
comparison, including 28 unavailable applicable detonation cases and two
harness shortfalls. No source case and no composition attack set completed.
Target execution remained unavailable.

If a comparison belongs in the recording, show the complete matched metadata
intersection and original thresholds: Fugu 80/80 versus Sentinel 11/80 and
MCP-Sec 12/80 primary attack flags; Cisco MCP and Fugu both 74/74. MCP-Sec
any-alert is separately 66/80. Cisco Skill's three complete attack pairs give
Fugu 2/3 and Cisco 3/3; that small intersection supports no broad skill ranking.
These previously visible convenience fixtures and uncalibrated thresholds
support no population accuracy or universal scanner superiority claim.

Keep **raw control flags 1/19 metadata and 2/6 skills** visible. Adjudication is
null, so no confirmed false-positive rate is established. Composition controls
can contain risky members and are not clean packages. The recorded 4,581 SDK
dispatches and 46 searches are historical accounting, not a cost, latency or
quota forecast. No provider error was recorded in that measurement; it does
not guarantee today's demo reliability.

The [2 October full-capability report](benchmark-full.md) remains dated Docker
fake-canary evidence. The [3 October continuation](benchmark-current-limits-continuation.md)
remains a separate bounded-inference history. Do not mix their denominators,
runtime observations or adjudication into the 5 October charts.

Suggested one-sentence result explanation: “These are completed checks on
fixed inputs; the missing runtime and partial cases stay visible, and a model
flag is a reason to inspect the evidence.” The short recording can omit
comparators entirely and focus on an actual source exhibit and install decision.

Before publication, confirm the reviewed commit, real successful rehearsal,
public repository/demo access, video permissions and actual duration. Human
recording, publication and submission remain outstanding. See the dated
[assessment and access checklist](hackathon-assessment.md).
