"""Workspace policies: rules an admin sets once, applied to every quarantine verdict.

Each rule matches something the sandbox observed and has an action:
  block   the version is blocked automatically when the run finishes, and nobody can approve
          it while the rule is on (turn the rule off or to "review" to allow an exception)
  review  a reviewer may approve it, but only with a written reason
  off     ignored
Two settings are not per-finding rules:
  auto_approve      versions rated TRUSTED with a perfect score are approved automatically
  approval_ttl_days approvals expire after N days and the tool has to be re-quarantined
"""
import json
import os
import threading
import time

from . import store

ACTIONS = ("block", "review", "off")

RULES = [
    {"id": "exfiltration", "name": "Data sent off the machine",
     "desc": "The tool tried to send data to an external host (HTTP, TLS, or data hidden in DNS lookups).",
     "default": "block"},
    {"id": "credentials", "name": "Credential files read",
     "desc": "The tool opened SSH keys, cloud credentials, tokens or other secrets it had no reason to touch.",
     "default": "block"},
    {"id": "poisoning", "name": "Hidden instructions for the AI",
     "desc": "The tool's description tries to steer the agent's model (tool poisoning).",
     "default": "block"},
    {"id": "persistence", "name": "Writes outside the workspace",
     "desc": "The tool tried to modify shell profiles, autostart entries or other files outside the project.",
     "default": "block"},
    {"id": "rug_pull", "name": "Behaviour changes between calls",
     "desc": "The tool behaved cleanly at first and changed what it did on later calls (rug pull).",
     "default": "block"},
    {"id": "overreach", "name": "Reads outside its declared scope",
     "desc": "The tool read files beyond what its own description says it needs.",
     "default": "review"},
    {"id": "egress", "name": "Any network attempt",
     "desc": "The tool tried to open a network connection that its description doesn't mention.",
     "default": "review"},
    {"id": "processes", "name": "Spawns other programs",
     "desc": "The tool started processes other than its own interpreter.",
     "default": "review"},
    {"id": "low_score", "name": "Trust score below threshold",
     "desc": "The quarantine trust score is below the minimum set here.",
     "default": "review", "threshold": 60},
]

DEFAULTS = {"rules": {r["id"]: {"action": r["default"], **({"threshold": r["threshold"]}
                                                            if "threshold" in r else {})}
                      for r in RULES},
            "auto_approve": False, "approval_ttl_days": 0,
            "updated_at": None, "updated_by": None}

_lock = threading.Lock()


def _path():
    return os.path.join(store._DIR, "policies.json")


def get():
    try:
        with open(_path()) as f:
            saved = json.load(f)
    except (OSError, ValueError):
        saved = {}
    out = json.loads(json.dumps(DEFAULTS))
    for rid, cfg in (saved.get("rules") or {}).items():
        if rid in out["rules"] and isinstance(cfg, dict):
            out["rules"][rid].update({k: v for k, v in cfg.items() if k in ("action", "threshold")})
    for k in ("auto_approve", "approval_ttl_days", "updated_at", "updated_by"):
        if k in saved:
            out[k] = saved[k]
    return out


def save(new, who=""):
    cur = get()
    for rid, cfg in (new.get("rules") or {}).items():
        if rid not in cur["rules"] or not isinstance(cfg, dict):
            continue
        if cfg.get("action") in ACTIONS:
            cur["rules"][rid]["action"] = cfg["action"]
        if "threshold" in cfg and "threshold" in cur["rules"][rid]:
            cur["rules"][rid]["threshold"] = max(0, min(100, int(cfg["threshold"])))
    if "auto_approve" in new:
        cur["auto_approve"] = bool(new["auto_approve"])
    if "approval_ttl_days" in new:
        cur["approval_ttl_days"] = max(0, min(365, int(new["approval_ttl_days"] or 0)))
    cur["updated_at"] = time.time()
    cur["updated_by"] = (who or "").strip()[:60] or "admin"
    os.makedirs(os.path.dirname(_path()), exist_ok=True)
    with _lock:
        tmp = _path() + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cur, f, indent=2)
        os.replace(tmp, _path())
    return cur


def _matches(run):
    """Which rule ids this run trips, each with the finding titles that tripped it."""
    hits = {}

    def add(rid, why):
        hits.setdefault(rid, [])
        if why not in hits[rid]:
            hits[rid].append(why)

    for f in run.get("findings") or []:
        cat, title, sev = f.get("category"), f.get("title", ""), f.get("severity")
        low = title.lower()
        if cat == "secret-access":
            add("credentials", title)
        elif cat == "network":
            add("exfiltration" if sev == "critical" or "exfiltration" in low else "egress", title)
        elif cat == "tool-poisoning":
            add("poisoning", title)
        elif cat == "write":
            add("persistence", title)
        elif cat == "scope-overreach":
            add("overreach", title)
        elif cat == "exec":
            add("processes", title)
        elif cat in ("rug-pull", "behaviour-change") or "rug pull" in low or "changed behaviour" in low:
            add("rug_pull", title)
    return hits


def evaluate(run, pol=None):
    """Apply the workspace policy to a finished run.
    Returns {outcome: blocked|review|approved|clear, hits: [...], evaluated_at}."""
    pol = pol or get()
    v = run.get("verdict") or {}
    found = _matches(run)
    score = v.get("score")
    low = pol["rules"]["low_score"]
    if score is not None and score < low.get("threshold", 60):
        found.setdefault("low_score", []).append(f"Trust score {score} < {low.get('threshold', 60)}")
    hits = []
    for r in RULES:
        if r["id"] in found:
            act = pol["rules"][r["id"]]["action"]
            if act != "off":
                hits.append({"rule": r["id"], "name": r["name"], "action": act,
                             "because": found[r["id"]][:4]})
    if any(h["action"] == "block" for h in hits):
        outcome = "blocked"
    elif hits:
        outcome = "review"
    elif pol.get("auto_approve") and v.get("label") == "trusted" and score == 100:
        outcome = "approved"
    else:
        outcome = "clear"
    return {"outcome": outcome, "hits": hits, "evaluated_at": time.time()}


def blocking_hits(run):
    """Rules that currently forbid approving this run (re-evaluated against today's policy)."""
    if run.get("status") not in (None, "done"):
        return []
    return [h for h in evaluate(run)["hits"] if h["action"] == "block"]


def approval_expired(entry, pol=None):
    pol = pol or get()
    ttl = pol.get("approval_ttl_days") or 0
    if not ttl or not entry or entry.get("state") != "approved":
        return False
    return time.time() - (entry.get("at") or 0) > ttl * 86400
