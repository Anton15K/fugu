"""Format rows as a fixed-width or markdown table (stdlib only)."""


def format_table(rows: list[list[str]], style: str = "md") -> str:
    widths = [max(len(str(c)) for c in col) for col in zip(*rows)]
    if style == "md":
        sep = "| " + " | ".join("-" * w for w in widths) + " |"
    else:
        sep = ""
    out = []
    for i, row in enumerate(rows):
        out.append("| " + " | ".join(str(c).ljust(w) for c, w in zip(row, widths)) + " |")
        if i == 0 and style == "md":
            out.append(sep)
    return "\n".join(out)
