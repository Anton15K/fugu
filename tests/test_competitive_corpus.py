"""Offline invariants for the new full-workflow selection."""
import hashlib
import json
from pathlib import Path
import pytest

from bench import competitive_corpus as corpus


def required(name):
    function = getattr(corpus, name, None)
    assert callable(function), f"corpus behavior missing: {name}"
    return function


def test_packet_preserves_genuine_schema_and_excludes_labels():
    original = {"name": "lookup", "description": "Return a public record.",
                "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
                "_meta": {"is_attack": False}, "label": "benign", "expected": {"flag": False}}
    packet = required("tool_packet")(original)
    assert packet == {"tools": [{k: original[k] for k in ("name", "description", "inputSchema")}]}
    assert original["_meta"] == {"is_attack": False}


def test_packet_does_not_invent_an_absent_schema():
    packet = required("tool_packet")({"name": "lookup", "description": "Record."})
    assert packet == {"tools": [{"name": "lookup", "description": "Record."}]}


def test_selection_is_order_independent_stratified_and_excludes_old_content():
    rows = [{"id": str(i), "stratum": "A" if i < 5 else "B", "content_hash": str(i)}
            for i in range(10)]
    choose = required("select_stratified")
    a = choose(rows, 4, seed="fixed", exclude_ids={"0"}, exclude_content={"9"})
    b = choose(list(reversed(rows)), 4, seed="fixed", exclude_ids={"0"}, exclude_content={"9"})
    assert a == b
    assert len(a) == 4 and {x["stratum"] for x in a} == {"A", "B"}
    assert not ({"0", "9"} & {x["id"] for x in a})


def test_selection_rejects_insufficient_pool_and_duplicate_identity():
    choose = required("select_stratified")
    with pytest.raises(ValueError, match="insufficient"):
        choose([], 1, seed="fixed")
    with pytest.raises(ValueError, match="duplicate"):
        choose([{"id": "x", "stratum": "A"}, {"id": "x", "stratum": "B"}], 1, seed="fixed")


def test_hashing_matches_runner_and_rejects_symlink_descendants(tmp_path):
    hashes = required("input_hashes")
    (tmp_path / "target.txt").write_bytes(b"inert")
    (tmp_path / "set.json").write_text('{"expected": true}')
    expected = {"target.txt": hashlib.sha256(b"inert").hexdigest()}
    assert hashes(tmp_path) == expected
    assert required("fingerprint")(expected) == hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest()
    (tmp_path / "escape").symlink_to(tmp_path / "target.txt")
    with pytest.raises(ValueError, match="symlink"):
        hashes(tmp_path)


def test_python_preflight_parses_without_executing_and_catches_json_booleans(tmp_path):
    validate = required("validate_sources")
    (tmp_path / "safe.py").write_text("raise RuntimeError('must never execute')\n")
    assert validate(tmp_path)[0]["status"] == "valid"
    (tmp_path / "bad.py").write_text("value = false\n")
    rows = validate(tmp_path)
    assert next(x for x in rows if x["path"] == "bad.py")["status"] == "invalid"


def test_copy_is_hash_bound_drops_metadata_and_refuses_overwrite(tmp_path):
    copy = required("copy_input")
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("Ordinary instructions.")
    (source / "_expected.json").write_text('{"label":"benign"}')
    destination = tmp_path / "target"
    expected = {"SKILL.md": hashlib.sha256((source / "SKILL.md").read_bytes()).hexdigest()}
    copy(source, destination, expected)
    assert {p.name for p in destination.iterdir()} == {"SKILL.md"}
    (source / "SKILL.md").write_text("Changed.")
    with pytest.raises(ValueError, match="hash"):
        copy(source, destination, expected)


def test_append_preserves_prefix_and_excludes_existing_and_prior_content(tmp_path):
    append = required("append_metadata")
    first = {"name": "existing", "description": "Original."}
    packet = tmp_path / "original"
    packet.mkdir()
    (packet / "tools.json").write_text(json.dumps({"tools": [first]}))
    row = {"id": "old", "cohort": "mcp_metadata", "kind": "malicious", "target": str(packet),
           "input_sha256": corpus.input_hashes(packet), "provenance": {"source": "inert"},
           "overlap": {"known": True}, "expected": {"flag": True}}
    original = {"schema": 1, "status": "NOT RELEASED", "seed": "original-seed",
                "selection_protocol": "original protocol", "cases": [row]}
    before = json.dumps(original, sort_keys=True)
    candidates = [{"id": identity, "stratum": "A" if i % 2 else "B", "cohort": "mcp_metadata",
                   "kind": "malicious", "tool": {"name": identity, "description": "Ordinary text."},
                   "provenance": {}, "overlap": {}} for i, identity in enumerate(["old", "prior", "a", "b", "c", "copy"])]
    candidates[-1]["tool"] = first
    for candidate in candidates:
        candidate["content_hash"] = corpus.content_hash(candidate["tool"])
    result = append(original, candidates, count=2, seed="fixed-extra", target_root=tmp_path / "extra",
                    exclude_ids={"prior"}, exclude_content=set())
    assert result["cases"][:1] == original["cases"]
    assert json.dumps(original, sort_keys=True) == before
    assert {r["id"] for r in result["cases"][1:]} <= {"a", "b", "c"}
    assert corpus.input_hashes(packet) == row["input_sha256"]
    for extra in result["cases"][1:]:
        tool = json.loads((Path(extra["target"]) / "tools.json").read_text())["tools"][0]
        assert set(tool) == {"name", "description"}
    repeat = append(original, list(reversed(candidates)), count=2, seed="fixed-extra",
                    target_root=tmp_path / "extra", exclude_ids={"prior"}, exclude_content=set())
    assert repeat == result


def test_append_rejects_shortfall_and_original_input_drift(tmp_path):
    append = required("append_metadata")
    original = {"schema": 1, "cases": []}
    with pytest.raises(ValueError, match="insufficient"):
        append(original, [], count=20, seed="extra", target_root=tmp_path / "extra")
    folder = tmp_path / "original"
    folder.mkdir()
    (folder / "tools.json").write_text('{"tools": []}')
    original["cases"] = [{"id": "old", "target": str(folder), "cohort": "mcp_metadata",
                          "input_sha256": {"tools.json": "wrong"}}]
    with pytest.raises(ValueError, match="original input"):
        append(original, [], count=0, seed="extra", target_root=tmp_path / "extra")
