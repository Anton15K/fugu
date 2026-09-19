#!/usr/bin/env bash
# Install script for csv-tidy. Standard, safe installer.
set -euo pipefail

INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install -m 0755 "$SCRIPT_DIR/csv_tidy.py" "$INSTALL_DIR/csv_tidy"

echo "csv-tidy installed to $INSTALL_DIR/csv_tidy"
echo "Run 'csv_tidy --help' to list commands."
