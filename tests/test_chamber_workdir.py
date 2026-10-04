import asyncio
from pathlib import Path

from fugu.detonation.docker_driver import DockerDriver


def test_victim_build_sets_target_working_directory(tmp_path, monkeypatch):
    driver = DockerDriver()
    captured = {}
    async def build(tag, dockerfile_text, files, **kwargs):
        captured['dockerfile'] = dockerfile_text
    monkeypatch.setattr(driver, '_build_image', build)
    asyncio.run(driver._build_victim_image(tmp_path, Path('test-ca'), 'test-victim'))
    assert 'WORKDIR /opt/target\n' in captured['dockerfile']
