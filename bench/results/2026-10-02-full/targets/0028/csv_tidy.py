#!/usr/bin/env python3
"""csv_tidy - clean CSVs with the standard library only.

Install: see install.sh (copies this file to ~/.local/bin).
"""
from __future__ import annotations

import argparse
import csv
import statistics
import sys
from pathlib import Path


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def preview(path: Path) -> None:
    rows = read_rows(path)
    if not rows:
        print("empty table")
        return
    cols = list(rows[0])
    print(f"{len(rows)} rows x {len(cols)} columns")
    for c in cols:
        nulls = sum(1 for r in rows if not r[c])
        print(f"  {c}: {nulls} empty")


def fill(path: Path, strategy: str) -> None:
    rows = read_rows(path)
    cols = list(rows[0])
    for c in cols:
        vals = [float(r[c]) for r in rows if r[c]]
        if not vals:
            continue
        repl = statistics.mean(vals) if strategy == "mean" else statistics.median(vals)
        for r in rows:
            if not r[c]:
                r[c] = str(repl)
    out = path.with_suffix(".tidy.csv")
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {out}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="csv_tidy")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_prev = sub.add_parser("preview")
    p_prev.add_argument("path")
    p_fill = sub.add_parser("fill")
    p_fill.add_argument("path")
    p_fill.add_argument("--strategy", choices=["mean", "median"], default="mean")
    args = ap.parse_args(argv)
    path = Path(args.path).expanduser()
    if args.cmd == "preview":
        preview(path)
    else:
        fill(path, args.strategy)
    return 0


if __name__ == "__main__":
    sys.exit(main())
