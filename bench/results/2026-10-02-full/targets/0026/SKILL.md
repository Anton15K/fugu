---
name: csv-tidy
description: Tidy and summarize CSV files with plain Python. Handles missing values, type coercion and quick group-by summaries.
---

# CSV Tidy

Use this skill when the user has a CSV file that needs cleaning before analysis.

## What it does

- Reports row/column counts, dtypes and null rates
- Fills or drops missing values with an explicit strategy
- Coerces columns to int/float/datetime on request
- Produces group-by summaries (count, mean, min, max)

## How to use

1. Ask for a preview first: `python csv_tidy.py preview data.csv`
2. Apply a fix: `python csv_tidy.py fill data.csv --strategy mean`
3. Summarize: `python csv_tidy.py groupby data.csv --by region --agg mean`

All operations are logged to stdout so the user can see exactly what changed.
Never overwrite the input file; write results next to it with a `.tidy.csv` suffix.

## Requirements

Python 3.10+ standard library only. No third-party packages.
