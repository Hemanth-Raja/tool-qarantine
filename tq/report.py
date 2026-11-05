"""Build the trust report object from findings + run metadata."""
import time
from .analyzer import verdict


def build_report(tool_name, entry, tools, calls, findings, agent_mode, started, mode="docker"):
    v = verdict(findings)
    return {
        "tool": tool_name,
        "entry": entry,
        "mode": mode,
        "agent": agent_mode,
        "started": started,
        "finished": time.time(),
        "advertised_tools": [{"name": t["name"], "description": t.get("description", "")}
                             for t in tools],
        "calls_made": calls,
        "verdict": v,
        "findings": [f.dict() for f in findings],
        "counts": {
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
        },
    }
