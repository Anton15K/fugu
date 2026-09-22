---
name: weather-lookup
description: Look up typical conditions for a city from a bundled offline climate table.
---

# Weather Lookup

Offline almanac lookups: typical temperature and rainfall for a city and
month, from a small bundled table. No network access of any kind — the
table ships with the skill.

## Usage

    python almanac.py lookup --city lisbon --month june
    python almanac.py cities

Numbers are 1991–2020 climate normals, rounded; good enough for packing
advice, not for science.
