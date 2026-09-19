# Wild findings — Fugu catches in the real world (citation sheet)

> For README, demo video, and Devpost. Use these framings verbatim; both are
> verifiable. Decision (2026-09-20): NO public engagement on upstream issues —
> cite only.

## 1. Anthropic docx skill — timeout reported as success

- **Found by:** S2 semantic judge (Nemotron Ultra), unsupervised benchmark run
  over 76 real-world skills, cold read of the code, no prior knowledge.
- **What:** `skills/docx/scripts/accept_changes.py:76` — `except
  subprocess.TimeoutExpired:` returns the *same* "Successfully accepted all
  tracked changes" message as genuine success. LibreOffice timeouts leave the
  document in an unknown state while the caller is told it worked; `__main__`
  also exits 0.
- **Security angle:** "accept all tracked changes" is a document-sanitization
  step before sharing; a silent no-op defeats it (edit history/comments may
  remain embedded).
- **Independent corroboration (use this in materials):** the same defect is
  defect #1 in anthropics/skills issue **#1770**
  (https://github.com/anthropics/skills/issues/1770, opened by Joi 2026-09-14,
  still OPEN) — filed by a human via manual inspection. Our automated auditor
  rediscovered it independently from cold code.
- **Approved framing:** "Our automated auditor independently rediscovered
  defect #1 of anthropics/skills#1770 — a timeout-reported-as-success in the
  production docx skill — during an unsupervised benchmark run. The issue
  remains open at time of writing."

## 2. skills.sh registry random-draw — live `curl | bash` install

- **Found by:** S1 static scanner during the seeded random-draw audit
  (seed 20260920, 25 skills from a 2,862-skill catalog union).
- **What:** skill `reason-machines/trending-skills/openviking-context-database`
  instructs `curl -fsSL https://raw.githubusercontent.com/volcengine/OpenViking/main/crates/ov_cli/install.sh | bash`
  in its SKILL.md — remote code piped to a shell at install time, no pinning,
  no checksum.
- **Approved framing:** "On a seeded random draw of 25 registry skills, Fugu
  flagged exactly one skill medium+ — adjudicated a true positive: an
  unpinned curl-to-shell install. The other 24 passed clean."
  (Path-mention FP found in the same run was fixed; see bf313f6.)

## Numbers sheet (current, all reproducible)

| Metric | Result | Artifact |
|---|---|---|
| MCPTox detection (strict contract, n=160, 11/11 categories) | 160/160 (100%) | bench/results/mcptox-semantic-confirm.md |
| MCPTox static-only (full corpus n=1,312) | 9% (by design — cascade) | bench/results/mcptox-static-full.json |
| Curated real skills (n=76, 4 sources) | 0 static FP / 3 semantic flags (1 true = finding #1 above) | bench/results/semantic-real.md |
| Random-draw registry (n=25, seeded) | 1 flag = true positive (finding #2 above) | bench/results/random-draw.md |
| Field contrast (MCPZoo '26) | 96.89% of servers flagged, <50% of alerts true | arXiv 2607.11086 |
