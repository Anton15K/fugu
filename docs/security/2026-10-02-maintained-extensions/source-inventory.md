# Pinned source inventory

Retrieved 2026-10-02T11:57:34.895763+00:00. Six public projects; four MCP project families and two skill repositories. Selection favored recent upstream activity and explicit capability contracts. Maintenance means an unarchived project with a default-branch commit or release within 45 days of retrieval; it is not a security assurance.

| Project | Pinned revision | Primary maintenance evidence | Inspected feature scope |
|---|---|---|---|
| [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | `f46d9578190b476b3501923ea8977d899e8db2cb` | [Commit](https://github.com/modelcontextprotocol/servers/commit/f46d9578190b476b3501923ea8977d899e8db2cb) dated 2026-09-22; [2026.8.31](https://github.com/modelcontextprotocol/servers/releases/tag/2026.8.31) published 2026-08-31; archived=false | Filesystem path/roots validation and listing; Fetch URL/robots contract |
| [microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp) | `f183dad4a52965583e3cc1d59b88cdc279e2e57d` | [Commit](https://github.com/microsoft/playwright-mcp/commit/f183dad4a52965583e3cc1d59b88cdc279e2e57d) dated 2026-09-28; [v0.0.83](https://github.com/microsoft/playwright-mcp/releases/tag/v0.0.83) published 2026-09-28; archived=false | Wrapper entrypoints, pinned dependency metadata, browser origin/file-access contract |
| [microsoft/markitdown](https://github.com/microsoft/markitdown) | `2b61a335a4bec721144498fe425a61f23e9e3d6e` | [Commit](https://github.com/microsoft/markitdown/commit/2b61a335a4bec721144498fe425a61f23e9e3d6e) dated 2026-10-02; [v0.1.8](https://github.com/microsoft/markitdown/releases/tag/v0.1.8) published 2026-09-21; archived=false | MCP conversion entrypoint, URI dispatch, HTTP binding and documented local trust contract |
| [github/github-mcp-server](https://github.com/github/github-mcp-server) | `36e5c48f2e376f8f4ffa30fd718c38deedb7ae27` | [Commit](https://github.com/github/github-mcp-server/commit/36e5c48f2e376f8f4ffa30fd718c38deedb7ae27) dated 2026-10-02; [v1.13.0](https://github.com/github/github-mcp-server/releases/tag/v1.13.0) published 2026-10-01; archived=false | Read-only inventory filter, tool annotations, lockdown author check, permission docs |
| [anthropics/skills](https://github.com/anthropics/skills) | `8a1541c4a3ffa5a20a5a91de0dcf3f0bab1d1ef4` | [Commit](https://github.com/anthropics/skills/commit/8a1541c4a3ffa5a20a5a91de0dcf3f0bab1d1ef4) dated 2026-09-29; archived=false | mcp-builder evaluation parser/connections, docx validation source, demonstration and license context |
| [obra/superpowers](https://github.com/obra/superpowers) | `8ca22dba9a94f28898bbce59f2537ff4d87c747d` | [Commit](https://github.com/obra/superpowers/commit/8ca22dba9a94f28898bbce59f2537ff4d87c747d) dated 2026-09-25; [v6.4.2](https://github.com/obra/superpowers/releases/tag/v6.4.2) published 2026-09-25; archived=false | Brainstorm companion auth/file guards/startup, helper and session hook source |

## Version and exclusion notes

- **modelcontextprotocol/servers:** Filesystem package source declares 0.6.3; repository release 2026.8.31. Excluded: Git, memory, all other servers; runtime/SDK behavior.
- **microsoft/playwright-mcp:** @playwright/mcp 0.0.83. Excluded: Delegated playwright-core implementation/browser runtime, sessions and client approval integration.
- **microsoft/markitdown:** MarkItDown release v0.1.8; MCP source declares 0.0.1a7. Excluded: Format converters/plugins, network/server execution, cloud metadata access.
- **github/github-mcp-server:** Latest release v1.13.0; audited default-branch snapshot is the exact commit below. Excluded: Tool implementation correctness across all toolsets, authenticated API calls and HTTP transports.
- **anthropics/skills:** No release returned; exact default-branch snapshot. Excluded: Other skills, document parser/runtime execution, model agent loop, commercial Claude implementations.
- **obra/superpowers:** Release v6.4.2. Excluded: Runtime HTTP/WebSocket behavior, browser interaction, other skills and external telemetry.

Anthropic describes these skill sources as demonstrations; commercial implementations may differ. The repository contains both Apache-licensed and source-available document skills. Full acquired third-party sources are local-only caches, and no fetched instructions were used as host instructions. [Pinned README](https://github.com/anthropics/skills/blob/8a1541c4a3ffa5a20a5a91de0dcf3f0bab1d1ef4/README.md).

Playwright wrapper dependency: `playwright-core` / `playwright` version `1.64.0-alpha-1790635538000`; npm metadata pins git head `e8149b8257d32dcf8f72573ecc43e72439da7080`. Package metadata/archive hashes are retained; bundled core behavior was not tested or included in the 44-file Fugu scope.

The acquisition cache omitted five MarkItDown files larger than 2 MB. All five are named in acquisition.json; none is in the selected 44-file scan. The other five repository acquisitions had no nonregular/large omissions. The selected scan copied only source-hash-verified regular files and had no collection omissions.

The exact file list and hashes are in [scope.json](../../../bench/results/2026-10-02-wild-audit/scope.json), [acquisition.json](../../../bench/results/2026-10-02-wild-audit/acquisition.json), and [source-inventory.json](../../../bench/results/2026-10-02-wild-audit/source-inventory.json). Source hashes identify bytes; they do not establish authorship or safety.
