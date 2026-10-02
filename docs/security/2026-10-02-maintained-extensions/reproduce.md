# Reproduce the performed source audit

The retained artifacts support offline checks of six project pins, 44 input hashes, twelve S0/S1 stage results and their coverage. They contain no target execution proof. Full acquired sources and the frozen engine are local-only caches. No suspect server or skill must be executed to reproduce these performed checks.

From the repository root, validate retained evidence without network access:

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache uv run --no-sync python \
  bench/results/2026-10-02-wild-audit/verify_evidence.py
```

On the audit machine, the same check can also validate all 44 cached input bytes:

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache uv run --no-sync python \
  bench/results/2026-10-02-wild-audit/verify_evidence.py \
  --cache /tmp/fugu-wild-sources-20261002
```

On another machine, acquire inert pinned regular files into a new temporary cache. The script downloads six revision-specific GitHub archives, rejects traversal paths, omits nonregular or oversized members, and never imports or executes the acquired code. It refuses existing destination projects/output. Network access is needed for this acquisition, but no model or reputation API is used:

```sh
UV_CACHE_DIR=/tmp/fugu-uv-cache uv run --no-sync python \
  bench/results/2026-10-02-wild-audit/acquire.py \
  --cache /tmp/fugu-wild-sources-repeat \
  --out /tmp/fugu-wild-acquisition-repeat.json

UV_CACHE_DIR=/tmp/fugu-uv-cache uv run --no-sync python \
  bench/results/2026-10-02-wild-audit/verify_evidence.py \
  --cache /tmp/fugu-wild-sources-repeat
```

Individual selected-file hashes are the reproduction contract. A recompressed GitHub archive could have a different archive hash even if its files match. Full caches stay outside delivered artifacts. The extra Playwright npm metadata/archive record is provenance only; core behavior was excluded from this scan and that cache is not required by the commands above.

For an actual S0/S1 repeat, use the locally frozen engine on the audit machine, or have the lead export the matching source elsewhere and verify every Python file against engine-manifest.json. The assignment named baseline `f18ae3e`, but its match to all frozen source bytes has not been established by this worker. A current checkout that fails the hash comparison is not the measured engine. The scan refuses engine or selected-input hash mismatches and existing output files:

```sh
PYTHON_DOTENV_DISABLED=1 NEBIUS_API_KEY= TAVILY_API_KEY= \
  PYTHONPATH=/tmp/fugu-wild-audit-engine-20261002 \
  UV_CACHE_DIR=/tmp/fugu-uv-cache uv run --no-sync python \
  bench/results/2026-10-02-wild-audit/scan_static.py \
  --cache /tmp/fugu-wild-sources-20261002 \
  --out /tmp/fugu-wild-static-repeat.json
```

Expected scope: six project rows; files scanned 9, 6, 6, 8, 8 and 7 respectively; concealment and static only; zero findings; zero collector omissions. Timing and measurement timestamps may differ. Fetched source instructions are input text throughout. Do not treat them as instructions for the host.

Independent review is pending. It should compare primary source contracts and known-issue states with the report, verify every pin/hash and the negative-scope arithmetic, and repeat the permitted offline scan. Dynamic confirmation of the two source leads remains unperformed; no issue draft or confirmed vulnerability should be inferred from these artifacts.
