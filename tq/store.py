"""Tiny JSON file store for runs and approval decisions. No database needed for a demo."""
import json
import os
import threading
import time
import uuid

_DIR = os.environ.get("TQ_DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "data"))
DATA_DIR = _DIR
_lock = threading.Lock()


def _path(rid):
    return os.path.join(_DIR, f"{rid}.json")


def save_run(report):
    os.makedirs(_DIR, exist_ok=True)
    rid = report.get("id") or uuid.uuid4().hex[:12]
    report["id"] = rid
    report.setdefault("decision", {"state": "pending", "note": "", "at": None})
    with _lock:
        with open(_path(rid), "w") as f:
            json.dump(report, f, indent=2)
    return rid


def get_run(rid):
    try:
        with open(_path(rid)) as f:
            return json.load(f)
    except OSError:
        return None


def set_decision(rid, state, note=""):
    r = get_run(rid)
    if not r:
        return None
    r["decision"] = {"state": state, "note": note, "at": time.time()}
    with _lock:
        with open(_path(rid), "w") as f:
            json.dump(r, f, indent=2)
    r["registry"] = _register(r, state, note)
    return r


def list_runs():
    if not os.path.isdir(_DIR):
        return []
    out = []
    for fn in os.listdir(_DIR):
        if fn.endswith(".json"):
            try:
                out.append(json.load(open(os.path.join(_DIR, fn))))
            except Exception:
                pass
    out.sort(key=lambda r: r.get("started", 0), reverse=True)
    return out


# ------------------------------------------------------------------ tool registry
# Approving a run pins that exact code (sha256 of the tool's files) to the allowlist;
# rejecting blocks it. Agents / MCP gateways ask /api/registry/check before launching a
# tool, so a changed tool (new hash) is unknown again and has to be re-quarantined.
_REG = os.path.join(_DIR, "registry", "registry.json")


def _load_registry():
    try:
        with open(_REG) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def registry():
    return _load_registry()


def registry_entry(tool_hash):
    return _load_registry().get(tool_hash)


def _register(run, state, note):
    h = run.get("tool_hash")
    if not h:
        return None
    with _lock:
        reg = _load_registry()
        reg[h] = {"hash": h, "state": "approved" if state == "approve" else "blocked",
                  "tool": run.get("tool"), "entry": run.get("entry"), "source": run.get("source"),
                  "run_id": run.get("id"), "verdict": (run.get("verdict") or {}).get("label"),
                  "score": (run.get("verdict") or {}).get("score"), "note": note, "at": time.time()}
        os.makedirs(os.path.dirname(_REG), exist_ok=True)
        tmp = _REG + ".tmp"
        with open(tmp, "w") as f:
            json.dump(reg, f, indent=2)
        os.replace(tmp, _REG)
        return reg[h]
