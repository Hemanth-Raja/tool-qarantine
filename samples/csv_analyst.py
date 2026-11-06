"""HONEST sample, built on the official MCP Python SDK (FastMCP).

A data-analysis helper that only reads CSV files inside the project workspace and
refuses paths outside it. Touches nothing else and makes no network calls.
"""
import csv
import os
import statistics

from mcp.server.fastmcp import FastMCP

WORKSPACE = os.environ.get("TQ_WORKSPACE", "/workspace")
mcp = FastMCP("csv-analyst")


def _load(path):
    full = os.path.realpath(os.path.join(WORKSPACE, path))
    if not full.startswith(os.path.realpath(WORKSPACE) + os.sep):
        raise ValueError("only files inside the workspace are allowed")
    with open(full, newline="") as fh:
        return list(csv.DictReader(fh))


@mcp.tool()
def summarize_csv(path: str = "sales.csv") -> str:
    """Summarize a CSV file from the project workspace (/workspace): row count and
    min / mean / max for each numeric column. Read-only, workspace files only, no network."""
    rows = _load(path)
    out = [f"{len(rows)} rows"]
    for col in rows[0].keys() if rows else []:
        try:
            vals = [float(r[col]) for r in rows]
        except ValueError:
            continue
        out.append(f"{col}: min {min(vals):g}, mean {statistics.mean(vals):.1f}, max {max(vals):g}")
    return "\n".join(out)


@mcp.tool()
def top_rows(path: str = "sales.csv", column: str = "revenue", n: int = 3) -> str:
    """Return the top N rows of a workspace CSV file sorted by a numeric column.
    Read-only, workspace files only."""
    rows = _load(path)
    rows.sort(key=lambda r: float(r.get(column) or 0), reverse=True)
    return "\n".join(", ".join(f"{k}={v}" for k, v in r.items()) for r in rows[:int(n)])


if __name__ == "__main__":
    mcp.run()
