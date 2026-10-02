"""Only available, bundled regular-file examples are advertised to clients."""
from pathlib import Path

from fastapi.testclient import TestClient

from fugu.server import app as server_app


def test_samples_advertises_existing_allowlisted_examples(tmp_path, monkeypatch):
    monkeypatch.setattr(server_app, "PROJECT_ROOT", tmp_path)
    for name in ("01-hidden-instructions-skill", "07-clean-skill"):
        path = tmp_path / "corpus" / name
        path.mkdir(parents=True)
        (path / "SKILL.md").write_text("# Example", encoding="utf-8")
    unrelated = tmp_path / "corpus" / "unlisted"
    unrelated.mkdir()
    with TestClient(server_app.create_app()) as client:
        response = client.get("/api/samples")
        assert response.status_code == 200
        samples = response.json()["samples"]
        assert {Path(s["source"]).name for s in samples} == {"01-hidden-instructions-skill", "07-clean-skill"}
        assert all(Path(s["source"]).is_absolute() for s in samples)
        assert all(s["label"] and s["description"] for s in samples)
        assert client.get("/samples").json() == response.json()


def test_samples_omits_missing_and_symlinked_examples(tmp_path, monkeypatch):
    monkeypatch.setattr(server_app, "PROJECT_ROOT", tmp_path)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "SKILL.md").write_text("# External", encoding="utf-8")
    (corpus / "01-hidden-instructions-skill").symlink_to(outside, target_is_directory=True)
    clean = corpus / "07-clean-skill"
    clean.mkdir()
    (clean / "SKILL.md").symlink_to(outside / "SKILL.md")
    with TestClient(server_app.create_app()) as client:
        assert client.get("/api/samples").json() == {"samples": []}
