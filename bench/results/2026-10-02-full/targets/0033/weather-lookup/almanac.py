"""weather-lookup: offline climate-normal lookups from a bundled table.

Standard library only, no network access, no environment access.
"""
from __future__ import annotations

import argparse
import json

# Bundled 1991-2020 climate normals, heavily rounded (sample of cities).
ALMANAC: dict[str, dict[str, dict[str, float]]] = {
    "lisbon": {
        "january": {"temp_c": 11.5, "rain_mm": 110},
        "june": {"temp_c": 21.0, "rain_mm": 15},
        "july": {"temp_c": 23.5, "rain_mm": 6},
        "december": {"temp_c": 12.0, "rain_mm": 108},
    },
    "oslo": {
        "january": {"temp_c": -3.0, "rain_mm": 49},
        "june": {"temp_c": 15.5, "rain_mm": 81},
        "july": {"temp_c": 17.5, "rain_mm": 81},
        "december": {"temp_c": -2.5, "rain_mm": 54},
    },
    "taipei": {
        "january": {"temp_c": 16.5, "rain_mm": 83},
        "june": {"temp_c": 28.5, "rain_mm": 226},
        "july": {"temp_c": 29.5, "rain_mm": 245},
        "december": {"temp_c": 17.5, "rain_mm": 73},
    },
}


def lookup(city: str, month: str) -> dict:
    key = city.strip().lower()
    mon = month.strip().lower()
    if key not in ALMANAC:
        return {"error": f"unknown city {city!r}", "cities": sorted(ALMANAC)}
    if mon not in ALMANAC[key]:
        return {"error": f"unknown month {month!r}", "months": sorted(ALMANAC[key])}
    row = ALMANAC[key][mon]
    return {"city": key, "month": mon, "temp_c": row["temp_c"], "rain_mm": row["rain_mm"]}


def main() -> None:
    parser = argparse.ArgumentParser(description="offline climate normals")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_lookup = sub.add_parser("lookup", help="look up one city/month")
    p_lookup.add_argument("--city", required=True)
    p_lookup.add_argument("--month", required=True)
    sub.add_parser("cities", help="list bundled cities")
    args = parser.parse_args()
    if args.cmd == "cities":
        print(json.dumps({"cities": sorted(ALMANAC)}, indent=2))
    else:
        print(json.dumps(lookup(args.city, args.month), indent=2))


if __name__ == "__main__":
    main()
