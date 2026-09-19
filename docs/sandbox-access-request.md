# Sandboxes beta access request

> Fill the [BRACKETS] before sending. Keep it this short — beta requests get triaged in seconds.

## Form version (paste into the access-request form)

**Standard (~165 words — use if the field allows it):**

> I'm building an entry for the Nebius × NVIDIA Global AI Hackathon (Devpost, deadline Oct 30) in the Coding & Agentic Engineering track: an agentic security auditor for third-party agent extensions (skills, MCP servers, plugins) that maps findings to OWASP categories. The core differentiator is a dynamic detonation chamber: we execute an untrusted extension in an isolated sandbox seeded with canary credentials (fake API keys via env vars), capture its network egress and filesystem changes, and produce evidence-backed verdicts — did it try to exfiltrate secrets, does its behavior match its declared description. Static-only scanners can't do this. I specifically need Sandboxes' VM-level isolation (deliberately running potentially malicious code), OCI image import, env-var injection, Git-like branching (fork the pre-install state, detonate install/import/invocation triggers in parallel), and resource metrics for anomaly detection. Usage is modest: solo developer, short-lived commands, a few hundred sandbox-minutes over 6 weeks, plus a public demo that must stay reproducible through judging (Dec 15). Glad to provide structured beta feedback on the SDK/API.

**Compact (~65 words — if the field has a tight limit):**

> Hackathon entry (Nebius × NVIDIA, Coding & Agentic track): a security auditor for agent skills/MCP servers that detonates untrusted extensions in isolated sandboxes with canary credentials and captures egress/filesystem evidence. Needs VM isolation, env-var injection, OCI image import, branching, resource metrics. Solo dev, modest usage (few hundred sandbox-minutes over 6 weeks, demo live through Dec 15 judging). Happy to give structured SDK feedback.

---

## Email version (if the form leads to email instead)

Send to: **contree@nebius.com** (beta contact per docs) — or ping the team in Nebius Discord
(https://discord.gg/ZdC3rXMJH) and offer to email the details.

---

**Subject:** Sandboxes beta access — Nebius×NVIDIA hackathon entry: detonation chamber for agent-extension security audits

Hi ConTree team,

I'm [NAME], participating in the Nebius x NVIDIA Global AI Hackathon (Devpost, submitting Oct 30), in the **Coding & Agentic Engineering** track. I'd like access to the Sandboxes beta.

**What I'm building — "Fugu":** an agentic security auditor for third-party agent extensions (skills / MCP servers / plugins). The pipeline maps every finding to OWASP categories and has three engines: static analysis, LLM-as-judge on Nemotron via Token Factory, and — the part that needs Sandboxes — a **dynamic detonation chamber**: we execute an untrusted extension in a VM-isolated sandbox seeded with canary credentials, capture its network egress and filesystem changes, and produce evidence-backed verdicts (did it try to exfiltrate the canary? does its behavior match its declared description?). Static-only scanners (e.g. Snyk Agent Scan) can't do this; execution-based verification is our core differentiator.

**Which Sandboxes features we rely on:**
- VM-level isolation — we deliberately run untrusted, potentially malicious code
- OCI image import (python/node base images) + file sync for the extension under test
- Environment variable injection — seeding canary credentials (fake AWS keys, tokens)
- Git-like branching — fork the pre-install state, detonate multiple triggers in parallel (install hook, import-time, first invocation), compare outcomes
- Async operations + polling — parallel detonations per audit
- Resource metrics — anomaly signatures (e.g. unexpected CPU = cryptominer)

**Scale & timeline:** solo developer, 6 weeks. Modest usage: a few base images, short-lived commands (seconds to a couple of minutes each), est. a few hundred sandbox-minutes total for development, demos, and the eval corpus. The public demo must stay reproducible through mid-December (hackathon judging ends Dec 15).

**Beta feedback:** the hackathon requires a written feedback section on Token Factory tooling — I'll gladly share structured feedback on the SDK/API (we're using `contree-sdk` from Python) well before then, including any rough edges in image import, env injection, and branching workflows.

Account details:
- Token Factory account: [EMAIL YOU LOG IN WITH]
- Nebius project ID (if needed): [FROM CONSOLE, IF YOU HAVE ONE]
- Best contact: [YOUR EMAIL]

Thanks!
[NAME]
[GitHub repo if you want to show it — optional but credible]

---

## Discord short version (2 sentences)

> Hi! I'm building a hackathon entry (Coding & Agentic track) — a security auditor that detonates untrusted MCP servers/agent skills in Sandboxes with canary credentials and captures egress as evidence. Could I get beta access? Happy to email full details + give structured SDK feedback — I'm at [email].
