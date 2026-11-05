"""Tiny JSON file store for runs and approval decisions. No database needed for a demo."""
import json
import os
import threading
import time
import uuid

_DIR = os.environ.get("TQ_DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "data"))
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
