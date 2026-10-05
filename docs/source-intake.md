# Source intake and descendant links

Fugu accepts a local directory or a shallow Git clone as an audit source. Intake
resolves the explicit root once, inspects the whole authorized tree without
reading file contents, then copies the selected view into an owned snapshot of
regular files. Pipeline stages, automatic skill fan-out, and chamber packaging
receive this snapshot. Direct calls to a stage on an unmaterialized tree keep
the stricter preflight and reject every descendant symlink.

A descendant link is materialized only when it points directly to a regular
file inside the resolved source root. The source root is the boundary: a link
inside a selected skill unit may refer to a file elsewhere in the same cloned
repository, because links are checked against the full repository before
selection or fan-out. An absolute target is accepted only if its normalized
path stays inside that anchor. Each accepted link becomes an ordinary file in
the snapshot; the original link and owner checkout are unchanged.

Intake rejects links that escape the root, point to missing files, form a
cycle or chain, or point to a directory. Unsupported special files and paths
that change into unsafe entries during copying also fail extraction. Unsafe
entries are reported as extraction errors, so the audit does not continue with
silently omitted source or a clean verdict based on partial input.

For accepted links, the extraction event retains the link's repository-relative
path, original link target, resolved repository-relative path, SHA-256 of the
materialized bytes, and byte count. This provenance describes the copied input;
it does not claim that the source stayed unchanged during the entire audit.

The 20,000-entry and 512 MiB limits apply to the completed snapshot, including
duplicate bytes when multiple links point to the same file. Failed copies are
removed. Job runners remove successful snapshots after their last stage or
fan-out harvest; callers of `extract_source` directly own cleanup of the
returned directory. Git clone transfer itself remains bounded by the existing
clone timeout, not by the materialized-tree byte limit.

Preflight and copying narrow the race window but do not provide a filesystem
snapshot against a concurrently modified local directory. For reproducible
results, audit an immutable checkout. Extension content remains untrusted and
is never run on the host as part of intake.
