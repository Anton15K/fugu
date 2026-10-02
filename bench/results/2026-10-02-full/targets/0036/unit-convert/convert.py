"""unit-convert: offline unit conversion, standard library only."""
from __future__ import annotations

import sys

LENGTH_TO_M = {"m": 1.0, "km": 1000.0, "mi": 1609.344, "ft": 0.3048}
MASS_TO_G = {"g": 1.0, "kg": 1000.0, "lb": 453.59237, "oz": 28.349523125}


def to_celsius(value: float, unit: str) -> float:
    if unit == "c":
        return value
    if unit == "f":
        return (value - 32.0) * 5.0 / 9.0
    return value - 273.15  # k


def from_celsius(c: float, unit: str) -> float:
    if unit == "c":
        return c
    if unit == "f":
        return c * 9.0 / 5.0 + 32.0
    return c + 273.15  # k


def convert(value: float, src: str, dst: str) -> float:
    src, dst = src.lower(), dst.lower()
    if src in LENGTH_TO_M and dst in LENGTH_TO_M:
        return value * LENGTH_TO_M[src] / LENGTH_TO_M[dst]
    if src in MASS_TO_G and dst in MASS_TO_G:
        return value * MASS_TO_G[src] / MASS_TO_G[dst]
    if src in ("c", "f", "k") and dst in ("c", "f", "k"):
        return from_celsius(to_celsius(value, src), dst)
    raise ValueError(f"unknown or mismatched units: {src} -> {dst}")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 3:
        print("usage: convert.py <value> <src> <dst>", file=sys.stderr)
        return 64
    try:
        result = convert(float(args[0]), args[1], args[2])
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 65
    print(f"{result:.4g}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
