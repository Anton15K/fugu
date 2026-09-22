"""Tests for S6 composition-set eval: loader validation, set_metrics,
and the run_eval --sets CLI mode. Hermetic — the fixture sets under
tests/fixtures/composition-sets/ are tiny (one file per member dir) and
are NOT audited here (corpus precondition tests live with W2)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import itertools

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from eval.loader import SetSpecError, load_set_specs
from eval.metrics import (
    SET_ADVISORY_CAVEAT,
    set_metrics,
    sets_to_console,
    sets_to_markdown,
)
from eval.run_eval import main as run_main

FIXTURES = _PROJECT_ROOT / "tests" / "fixtures" / "composition-sets"


# --- helpers -------------------------------------------------------------------


def make_set(
    tmp_path: Path,
    name: str = "s",
    kind: str = "attack",
    members: list[tuple[str, str]] | None = None,
    trifecta: bool = True,
    shadowing: bool = False,
    set_json: object = None,
) -> Path:
    """Write one valid set (or a custom set.json) under tmp_path/<name>."""
    set_dir = tmp_path / name
    set_dir.mkdir(parents=True)
    if members is None:
        members = [("a", "a"), ("b", "b")]
    for member_dir, _label in members:
        (set_dir / member_dir).mkdir()
        (set_dir / member_dir / "SKILL.md").write_text(f"# {member_dir}\n")
    if set_json is None:
        set_json = {
            "name": name,
            "kind": kind,
            "description": f"test set {name}",
            "members": [{"dir": d, "label": l} for d, l in members],
            "expected": {"trifecta": trifecta, "shadowing": shadowing},
        }
    (set_dir / "set.json").write_text(json.dumps(set_json))
    return set_dir


def load_specs_from(obj: object, tmp_path: Path, name: str = "s") -> list:
    """Validate one custom set.json in isolation; return specs or raise."""
    make_set(tmp_path, name=name, set_json=obj)
    return load_set_specs(tmp_path)


_case_counter = itertools.count()


def expected_isolated_error(tmp_path: Path, obj: object, match: str) -> None:
    """Fresh root per case so earlier bad sets don't leak in."""
    solo = tmp_path / f"case-{next(_case_counter)}"
    with pytest.raises(SetSpecError, match=match):
        load_specs_from(obj, solo)


def fixture_specs() -> list:
    return load_set_specs(FIXTURES)


def fixture_results() -> list[dict[str, object]]:
    """Perfect predictions against the shipped fixture sets."""
    return [
        {"set": "trifecta-canonical", "trifecta": True, "shadowing": False},
        {"set": "benign-pair", "trifecta": False, "shadowing": False},
        {"set": "shadow-tools", "trifecta": False, "shadowing": True},
    ]


# --- loader: happy path ----------------------------------------------------------


def test_load_fixture_sets() -> None:
    specs = fixture_specs()
    assert [s.name for s in specs] == ["benign-pair", "shadow-tools", "trifecta-canonical"]
    by_name = {s.name: s for s in specs}
    canon = by_name["trifecta-canonical"]
    assert canon.kind == "attack"
    assert canon.expected_trifecta is True
    assert canon.expected_shadowing is False
    assert canon.expected == {"trifecta": True, "shadowing": False}
    assert [m.dir for m in canon.members] == ["web-digest", "notes-lookup", "status-poster"]
    assert [m.label for m in canon.members] == ["web-digest", "notes-lookup", "status-poster"]
    assert canon.path == (FIXTURES / "trifecta-canonical").resolve()

    assert by_name["benign-pair"].kind == "control"
    assert by_name["benign-pair"].expected_trifecta is False
    assert by_name["shadow-tools"].kind == "attack"
    assert by_name["shadow-tools"].expected_shadowing is True


def test_loader_roundtrip_in_tmp(tmp_path: Path) -> None:
    make_set(tmp_path, name="two-member", kind="control", trifecta=False)
    (tmp_path / "not-a-set.txt").write_text("files at the root are ignored")
    (tmp_path / "no-set-json").mkdir()  # no set.json -> skipped silently
    (tmp_path / ".hidden").mkdir()
    (tmp_path / "__pycache__").mkdir()
    specs = load_set_specs(tmp_path)
    assert len(specs) == 1
    spec = specs[0]
    assert spec.name == "two-member"
    assert spec.kind == "control"
    assert spec.expected == {"trifecta": False, "shadowing": False}
    assert len(spec.members) == 2
    assert all((spec.path / m.dir).is_dir() for m in spec.members)


def test_loader_eight_members_ok(tmp_path: Path) -> None:
    members = [(f"m{i}", f"member-{i}") for i in range(8)]
    make_set(tmp_path, name="eight", members=members)
    specs = load_set_specs(tmp_path)
    assert len(specs[0].members) == 8
    assert [m.label for m in specs[0].members] == [l for _, l in members]


def test_loader_missing_root_raises(tmp_path: Path) -> None:
    with pytest.raises(SetSpecError, match="not found"):
        load_set_specs(tmp_path / "nope")


def test_loader_empty_root_returns_empty(tmp_path: Path) -> None:
    assert load_set_specs(tmp_path) == []


def test_loader_duplicate_set_names_raise(tmp_path: Path) -> None:
    # two set dirs whose set.json carries the same "name" value
    make_set(tmp_path, name="dir-one", set_json={
        "name": "dup", "kind": "attack",
        "members": [{"dir": "a", "label": "a"}, {"dir": "b", "label": "b"}],
        "expected": {"trifecta": True, "shadowing": False},
    })
    make_set(tmp_path, name="dir-two", set_json={
        "name": "dup", "kind": "control",
        "members": [{"dir": "a", "label": "a"}, {"dir": "b", "label": "b"}],
        "expected": {"trifecta": False, "shadowing": False},
    })
    with pytest.raises(SetSpecError, match="duplicate set name"):
        load_set_specs(tmp_path)


# --- loader: malformed set.json ----------------------------------------------------


def test_malformed_not_an_object(tmp_path: Path) -> None:
    expected_isolated_error(tmp_path, ["not", "an", "object"], "JSON object")


def test_malformed_bad_name(tmp_path: Path) -> None:
    base = {"kind": "attack", "members": [{"dir": "a", "label": "a"}, {"dir": "b", "label": "b"}],
            "expected": {"trifecta": True, "shadowing": False}}
    expected_isolated_error(tmp_path, {**base, "name": ""}, "name")
    expected_isolated_error(tmp_path, {k: v for k, v in base.items()}, "name")


def test_malformed_bad_kind(tmp_path: Path) -> None:
    obj = {"name": "s", "kind": "benign",
           "members": [{"dir": "a", "label": "a"}, {"dir": "b", "label": "b"}],
           "expected": {"trifecta": True, "shadowing": False}}
    expected_isolated_error(tmp_path, obj, "'kind' must be one of")


def test_malformed_too_few_members(tmp_path: Path) -> None:
    obj = {"name": "s", "kind": "attack",
           "members": [{"dir": "a", "label": "a"}],
           "expected": {"trifecta": True, "shadowing": False}}
    expected_isolated_error(tmp_path, obj, "2..8")


def test_malformed_too_many_members(tmp_path: Path) -> None:
    obj = {"name": "s", "kind": "attack",
           "members": [{"dir": f"m{i}", "label": f"m{i}"} for i in range(9)],
           "expected": {"trifecta": True, "shadowing": False}}
    expected_isolated_error(tmp_path, obj, "2..8")


def test_malformed_member_dir_missing(tmp_path: Path) -> None:
    obj = {"name": "s", "kind": "attack",
           "members": [{"dir": "a", "label": "a"}, {"dir": "ghost", "label": "ghost"}],
           "expected": {"trifecta": True, "shadowing": False}}
    expected_isolated_error(tmp_path, obj, "does not exist")


def test_malformed_member_not_object(tmp_path: Path) -> None:
    obj = {"name": "s", "kind": "attack",
           "members": [{"dir": "a", "label": "a"}, "b"],
           "expected": {"trifecta": True, "shadowing": False}}
    expected_isolated_error(tmp_path, obj, "members\\[1\\]")


def test_malformed_expected_missing_key(tmp_path: Path) -> None:
    obj = {"name": "s", "kind": "attack",
           "members": [{"dir": "a", "label": "a"}, {"dir": "b", "label": "b"}],
           "expected": {"trifecta": True}}
    expected_isolated_error(tmp_path, obj, "missing key")


def test_malformed_expected_not_bool(tmp_path: Path) -> None:
    obj = {"name": "s", "kind": "attack",
           "members": [{"dir": "a", "label": "a"}, {"dir": "b", "label": "b"}],
           "expected": {"trifecta": "yes", "shadowing": False}}
    expected_isolated_error(tmp_path, obj, "boolean")


def test_malformed_expected_missing_entirely(tmp_path: Path) -> None:
    obj = {"name": "s", "kind": "control",
           "members": [{"dir": "a", "label": "a"}, {"dir": "b", "label": "b"}]}
    expected_isolated_error(tmp_path, obj, "expected")


def test_malformed_bad_json(tmp_path: Path) -> None:
    set_dir = tmp_path / "broken"
    set_dir.mkdir()
    (set_dir / "set.json").write_text("{not json")
    with pytest.raises(SetSpecError, match="cannot parse"):
        load_set_specs(tmp_path)


def test_malformed_error_names_the_file(tmp_path: Path) -> None:
    obj = {"name": "s", "kind": "wat",
           "members": [{"dir": "a", "label": "a"}, {"dir": "b", "label": "b"}],
           "expected": {"trifecta": True, "shadowing": False}}
    make_set(tmp_path, name="badset", set_json=obj)
    with pytest.raises(SetSpecError, match="badset/set.json"):
        load_set_specs(tmp_path)


# --- set_metrics --------------------------------------------------------------------


def test_set_metrics_perfect_predictions() -> None:
    report = set_metrics(fixture_results(), fixture_specs())
    assert report["tier"] == "advisory"
    assert report["n_sets"] == 3
    assert report["n_sets_with_predictions"] == 3
    assert report["unmatched_prediction_keys"] == []
    assert all(row["correct"] for row in report["rows"])
    agg = report["aggregate"]
    assert agg["n_attacks"] == 2 and agg["n_attacks_detected"] == 2
    assert agg["set_detection_rate"] == 1.0
    assert agg["n_controls"] == 1 and agg["n_controls_flagged"] == 0
    assert agg["set_fp_rate"] == 0.0


def test_set_metrics_rows_shape() -> None:
    report = set_metrics(fixture_results(), fixture_specs())
    rows = {row["name"]: row for row in report["rows"]}
    canon = rows["trifecta-canonical"]
    assert canon["kind"] == "attack"
    assert canon["expected_trifecta"] is True
    assert canon["predicted_trifecta"] is True
    assert canon["predicted_shadowing"] is False
    assert canon["correct"] is True
    # shadowing attack correctly NOT crying trifecta -> still "correct"
    shadow = rows["shadow-tools"]
    assert shadow["correct"] is True and shadow["predicted_trifecta"] is False
    assert shadow["predicted_shadowing"] is True


def test_set_metrics_control_fp_on_either_signal() -> None:
    # control fires trifecta -> FP
    preds = [{"set": "benign-pair", "trifecta": True, "shadowing": False}]
    report = set_metrics(preds, fixture_specs())
    agg = report["aggregate"]
    assert agg["n_controls_flagged"] == 1 and agg["set_fp_rate"] == 1.0
    row = next(r for r in report["rows"] if r["name"] == "benign-pair")
    assert row["correct"] is False  # expected False, predicted True

    # control fires ONLY shadowing -> still an FP per §5
    preds = [{"set": "benign-pair", "trifecta": False, "shadowing": True}]
    report = set_metrics(preds, fixture_specs())
    agg = report["aggregate"]
    assert agg["n_controls_flagged"] == 1 and agg["set_fp_rate"] == 1.0
    row = next(r for r in report["rows"] if r["name"] == "benign-pair")
    assert row["correct"] is True  # trifecta prediction itself was right


def test_set_metrics_missed_attack() -> None:
    # nothing predicted at all: the trifecta attack is missed; the control
    # stays silent (clean). The shadowing attack (expected trifecta=False)
    # still counts as "correct trifecta prediction" per contracts §5.
    report = set_metrics([], fixture_specs())
    agg = report["aggregate"]
    assert agg["n_attacks_detected"] == 1  # shadow-tools only
    assert agg["set_detection_rate"] == 0.5
    assert agg["set_fp_rate"] == 0.0
    rows = {row["name"]: row for row in report["rows"]}
    assert rows["trifecta-canonical"]["correct"] is False  # missed
    assert rows["shadow-tools"]["correct"] is True  # expected no-trifecta, predicted none
    assert report["n_sets_with_predictions"] == 0


def test_set_metrics_unmatched_keys() -> None:
    preds = fixture_results() + [{"set": "ghost-set", "trifecta": True, "shadowing": False}]
    report = set_metrics(preds, fixture_specs())
    assert report["unmatched_prediction_keys"] == ["ghost-set"]
    assert report["n_sets"] == 3  # ghost did not create a row
    assert report["aggregate"]["set_detection_rate"] == 1.0  # nor moved aggregates


def test_set_metrics_empty_specs_and_results() -> None:
    report = set_metrics([], [])
    assert report["n_sets"] == 0
    assert report["rows"] == []
    assert report["aggregate"] == {
        "n_attacks": 0,
        "n_attacks_detected": 0,
        "set_detection_rate": 0.0,
        "n_controls": 0,
        "n_controls_flagged": 0,
        "set_fp_rate": 0.0,
    }
    # renderers must not explode on the degenerate report
    assert "composition-set report" in sets_to_markdown(report).lower()
    assert "COMPOSITION-SET REPORT" in sets_to_console(report)


def test_set_metrics_rejects_bad_rows() -> None:
    with pytest.raises(ValueError, match="trifecta.*shadowing|'set'"):
        set_metrics([{"set": "x", "trifecta": "yes", "shadowing": False}], fixture_specs())
    with pytest.raises(ValueError, match="'set'"):
        set_metrics([{"trifecta": True, "shadowing": False}], fixture_specs())


def test_set_metrics_json_serializable() -> None:
    report = set_metrics(fixture_results(), fixture_specs())
    dumped = json.dumps(report)  # must not raise
    reloaded = json.loads(dumped)
    assert reloaded["aggregate"]["set_detection_rate"] == report["aggregate"]["set_detection_rate"]


# --- renderers ----------------------------------------------------------------------


def test_sets_renderers_carry_table_and_caveat() -> None:
    report = set_metrics(fixture_results(), fixture_specs())
    md = sets_to_markdown(report)
    assert md.startswith("## Fugu composition-set report (tier: advisory)")
    assert "| set | kind | expected trifecta | predicted trifecta | predicted shadowing | correct |" in md
    assert "| trifecta-canonical | attack | True | True | False | ✅ |" in md
    assert "set_detection_rate" in md and "1.000" in md
    assert "set_fp_rate" in md and "0.000" in md
    assert SET_ADVISORY_CAVEAT in md

    text = sets_to_console(report)
    assert "FUGU COMPOSITION-SET REPORT (tier: advisory)" in text
    assert "set_detection_rate: 1.000 (2/2)" in text
    assert "set_fp_rate: 0.000 (0/1)" in text
    assert "trifecta-canonical" in text
    assert "advisory tier" in text


# --- CLI: --sets mode --------------------------------------------------------------


def test_cli_sets_mode_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    results = tmp_path / "sets-results.json"
    results.write_text(json.dumps({"sets": fixture_results()}))
    md_out = tmp_path / "sets-report.md"
    rc = run_main(["--sets", str(FIXTURES), "--results", str(results), "--markdown", str(md_out)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "## Fugu composition-set report (tier: advisory)" in out
    assert "| set | kind | expected trifecta | predicted trifecta | predicted shadowing | correct |" in out
    assert "| trifecta-canonical | attack | True | True | False | ✅ |" in out
    assert "set_detection_rate" in out and "(2/2)" in out
    assert "set_fp_rate" in out and "(0/1)" in out
    assert "advisory" in out
    assert md_out.is_file()
    assert sets_to_markdown(set_metrics(fixture_results(), fixture_specs())) in md_out.read_text()


def test_cli_sets_mode_via_subprocess(tmp_path: Path) -> None:
    import subprocess

    results = tmp_path / "sets-results.json"
    results.write_text(json.dumps({
        "sets": [
            {"set": "trifecta-canonical", "trifecta": True, "shadowing": False},
            {"set": "benign-pair", "trifecta": False, "shadowing": False},
            {"set": "shadow-tools", "trifecta": False, "shadowing": True},
        ]
    }))
    proc = subprocess.run(
        [sys.executable, "-m", "eval.run_eval", "--sets", str(FIXTURES),
         "--results", str(results)],
        capture_output=True, text=True, cwd=_PROJECT_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    assert "Fugu composition-set report" in proc.stdout
    assert "set_detection_rate" in proc.stdout
    assert "set_fp_rate" in proc.stdout
    assert "advisory" in proc.stdout


def test_cli_sets_requires_results(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = run_main(["--sets", str(FIXTURES)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--sets requires --results" in err


def test_cli_sets_rejects_corpus_combination(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        run_main(["--sets", str(FIXTURES), "--corpus", str(tmp_path / "corpus")])
    assert excinfo.value.code == 2
    assert "cannot be combined" in capsys.readouterr().err
    for extra in (["--fixtures"], ["--selfcheck"]):
        capsys.readouterr()  # drain
        with pytest.raises(SystemExit):
            run_main(["--sets", str(FIXTURES), *extra])
        assert "cannot be combined" in capsys.readouterr().err


def test_cli_sets_malformed_spec_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    make_set(tmp_path, name="bad", set_json={
        "name": "bad", "kind": "attack",
        "members": [{"dir": "a", "label": "a"}],  # 1 member: violates 2..8
        "expected": {"trifecta": True, "shadowing": False},
    })
    results = tmp_path / "r.json"
    results.write_text(json.dumps({"sets": []}))
    rc = run_main(["--sets", str(tmp_path), "--results", str(results)])
    assert rc == 2
    assert "2..8" in capsys.readouterr().err


def test_cli_sets_bad_results_shape_exits(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    results = tmp_path / "r.json"
    results.write_text(json.dumps({"predictions": {}}))  # wrong shape for sets mode
    with pytest.raises(SystemExit, match=r"\{\"sets\""):
        run_main(["--sets", str(FIXTURES), "--results", str(results)])


def test_cli_sets_unmatched_keys_warn(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    results = tmp_path / "r.json"
    results.write_text(json.dumps({
        "sets": fixture_results() + [{"set": "ghost-set", "trifecta": True, "shadowing": False}]
    }))
    rc = run_main(["--sets", str(FIXTURES), "--results", str(results)])
    assert rc == 0
    captured = capsys.readouterr()
    assert "ghost-set" in captured.err
    assert "no set spec" in captured.err
