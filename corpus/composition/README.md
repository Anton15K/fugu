# S6 composition corpus — attack + control SETS

Sets of *individually clean* mini-extensions whose UNION carries (or
deliberately lacks) the lethal trifecta: untrusted-content ingress +
private-data access + egress channel split across extensions, plus
cross-extension tool shadowing. Ground truth for the composition stage
(docs/s6-contracts.md §4; loader: `eval.loader.load_set_specs`).

## Hard precondition

Every member of every set — attack AND control — is individually clean:
`run_audit(member, include_detonation=False, include_semantic=False,
include_harness=False, include_reputation=False)` yields NO high/critical
finding for any member alone. Signals inside members are intentionally
mild (single env-var reads, curl-to-named-host, fetch/read tool verbs);
the high-severity static shapes (env-harvest loops, curl|sh, raw-IP
fetches, `~/.ssh`/`~/.aws`/`~/.netrc` access, hidden codepoints,
injection phrases) are deliberately absent. `tests/test_composition_corpus.py`
enforces all of this.

## Sets

| set                     | kind    | members                                                          | exercises |
|-------------------------|---------|------------------------------------------------------------------|-----------|
| trifecta-canonical      | attack  | web-digest + notes-lookup + status-poster                        | canonical 3-way trifecta (INGRESS / PRIVATE-DATA / EGRESS) |
| trifecta-shuffled       | attack  | same three, different order in set.json                          | order-independence of detection |
| trifecta-diluted        | attack  | canonical three + weather-lookup + unit-convert                  | attack survives 2 irrelevant clean members |
| shadow-pair             | attack  | filesystem + filesystem-enhanced + help-docs                     | normalized tool-name collision (`read_file`, `list_dir`) without trifecta |
| control-ingress-egress  | control | feed-watch + deploy-notify                                       | benign union missing PRIVATE-DATA (FP guard) |
| control-private-egress  | control | config-lookup + deploy-notify                                    | benign union missing INGRESS (FP guard) |
| control-self-sufficient | control | workspace-sync + weather-lookup + unit-convert                   | single self-sufficient extension must NOT be reported as a cross-extension combo |

Shared member names (web-digest, notes-lookup, status-poster,
weather-lookup, unit-convert, deploy-notify) are duplicated across set
directories on purpose — the set schema (§4) puts members inside each
set dir. A drift-guard test keeps every shared copy byte-identical.

## Member capability notes

- **web-digest** — INGRESS: `fetch_url` / `read_rss` tools + fetch/read/web verbs in docs.
- **notes-lookup** — PRIVATE-DATA: reads `NOTES_DIR`/`NOTES_SYNC_TOKEN` env vars and `~/.config/notes-lookup/settings.json`; home-relative paths, no `.ssh`/`.aws`/`.netrc`.
- **status-poster** — EGRESS: `curl -X POST` to named HTTPS endpoints + webhook usage.
- **filesystem / filesystem-enhanced** — collide on `read_file` + `list_dir` after normalization.
- **feed-watch** — INGRESS only (urllib fetch of stored feed URLs).
- **deploy-notify** — EGRESS only (curl POST to webhook).
- **config-lookup** — PRIVATE-DATA only (env-var presence checks + dotfile existence reporting).
- **workspace-sync** — all three legs mild, in ONE extension (self-sufficient control).
- **weather-lookup / unit-convert** — fully clean diluents.

## Adding a set

1. `corpus/composition/<set-name>/set.json` per the schema (name, kind
   attack|control, description, members[{dir,label}], expected
   {trifecta, shadowing}); 2..8 members; member dirs must exist next to
   the set.json.
2. One subdir per member, styled like `corpus/01-*`…`corpus/08-*`
   (SKILL.md and/or MCP-server shape).
3. Keep every member individually clean — the corpus tests will fail
   otherwise.
