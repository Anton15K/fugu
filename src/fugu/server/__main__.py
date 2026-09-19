"""Run the Fugu API server: uv run python -m fugu.server [--port 8000]."""
from __future__ import annotations

import argparse

import uvicorn

from fugu.pipeline import build_stages
from fugu.server.app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="Fugu audit API server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--static-dir", default=None, help="web/dist to serve (default: auto)")
    args = parser.parse_args()
    app = create_app(stages=build_stages(), static_dir=args.static_dir)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
