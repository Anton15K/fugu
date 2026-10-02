#!/usr/bin/env node
/** mdprettify - align markdown tables and normalize list bullets (benign). */
"use strict";

const fs = require("fs");
const path = require("path");

function parseTable(lines, start) {
  const rows = [];
  for (let i = start; i < lines.length; i++) {
    const line = lines[i];
    if (!/^\s*\|.*\|\s*$/.test(line)) break;
    const cells = line.trim().slice(1, -1).split("|").map((c) => c.trim());
    rows.push({ raw: line, cells });
  }
  return rows;
}

function widthOf(rows, col) {
  return rows.reduce((w, r) => Math.max(w, (r.cells[col] || "").length), 3);
}

function prettify(text) {
  const lines = text.split("\n");
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (/^\s*\|.*\|\s*$/.test(lines[i]) && /^\s*\|[\s:-]+\|\s*$/.test(lines[i + 1] || "")) {
      const rows = parseTable(lines, i + 1);
      const widths = rows[0].cells.map((_, c) => widthOf(rows, c));
      const fmt = (cells) =>
        "| " + cells.map((c, j) => (c || "").padEnd(widths[j])).join(" | ") + " |";
      out.push(fmt(rows[0].cells));
      out.push("|" + widths.map((w) => "-".repeat(w + 2)).join("|") + "|");
      for (const r of rows.slice(1)) out.push(fmt(r.cells));
      i += rows.length; // skip the header row we already pushed
    } else {
      out.push(lines[i].replace(/^(\s*)[-*]\s+/, "$1- "));
    }
  }
  return out.join("\n");
}

function main() {
  const file = process.argv[2];
  if (!file) {
    console.error("usage: mdprettify <file.md>");
    process.exit(1);
  }
  const src = fs.readFileSync(path.resolve(file), "utf8");
  const dst = file.replace(/\.md$/, ".pretty.md");
  fs.writeFileSync(dst, prettify(src));
  console.log(`wrote ${dst}`);
}

if (require.main === module) main();
module.exports = { prettify };
