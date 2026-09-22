---
name: unit-convert
description: Convert between common units (length, mass, temperature) offline.
---

# Unit Convert

A dependency-free unit converter for everyday quantities.

## Usage

    python convert.py 3 km mi
    python convert.py 72 f c
    python convert.py 250 g lb

Supported groups: length (m, km, mi, ft), mass (g, kg, lb, oz),
temperature (c, f, k). Results are printed with four significant digits.
Nothing is written to disk and no configuration is read.
