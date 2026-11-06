"""Tool Quarantine web service (FastAPI).

Endpoints:
  GET  /                      dashboard (samples, upload, list of runs)
  GET  /run/{id}              trust report page: live activity feed, claims vs reality,
                              findings, Approve / Reject
  POST /api/runs              start a run {sample entry | tool_id}       -> {id} immediately
  GET  /api/runs              list runs (JSON)
  GET  /api/runs/{id}         one run (JSON; status running | done | error)
  GET  /api/runs/{id}/live    ?after=N  timeline events since N while the run is going
  POST /api/runs/{id}/decide  {state: approve|reject, note}  pins / blocks that code's hash
  GET  /api/registry          approved and blocked tool versions
  GET  /api/registry/check    ?hash=  can this exact code run? (for agents / MCP gateways)
  POST /api/tools/upload      raw zip body, ?name=&entry=          -> uploaded tool
  POST /api/tools/github      {url, name?, entry?}                 -> uploaded tool
  GET  /api/tools             uploaded tools
  GET  /healthz
The HTML is served from static/ ; the pages are plain JS calling the JSON API.
"""
import os
import threading
import time
import traceback
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import live, policy, runner, store, uploads
from .fingerprint import tool_hash

STATIC = os.path.join(os.path.dirname(__file__), "static")
SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")
MAX_PARALLEL = int(os.environ.get("TQ_MAX_PARALLEL", "2"))
UPLOADS_ON = os.environ.get("TQ_ALLOW_UPLOADS", "1") != "0"

app = FastAPI(title="Tool Quarantine")
_slots = threading.BoundedSemaphore(MAX_PARALLEL)


class RunReq(BaseModel):
    tool_dir: str = SAMPLES
    entry: str = ""
    name: str = ""
    mode: str = "auto"
    tool_id: str = ""


class DecideReq(BaseModel):
    state: str
    note: str = ""
    reviewer: str = ""


class GithubReq(BaseModel):
    url: str
    name: str = ""
    entry: str = ""


@app.get("/healthz")
def healthz():
    return {"ok": True}


def _resolve(req):
    """Map a request to (tool_dir, entry, name, source). Only samples/ and uploaded tools
    are allowed, never arbitrary host paths (unless TQ_ALLOW_ANY_DIR is set)."""
    if req.tool_id:
        try:
            d = uploads.tool_dir(req.tool_id)
        except uploads.UploadError as e:
            raise HTTPException(404, str(e))
        meta = uploads.get_meta(req.tool_id) or {}
        return d, req.entry or meta.get("entry"), req.name or meta.get("name"), meta.get("source")
    tool_dir = os.path.abspath(req.tool_dir)
    if not os.environ.get("TQ_ALLOW_ANY_DIR") and not tool_dir.startswith(os.path.abspath(SAMPLES)):
        raise HTTPException(400, "tool_dir must be under samples/ (set TQ_ALLOW_ANY_DIR to override)")
    if not req.entry:
        raise HTTPException(400, "entry is required")
    return tool_dir, req.entry, req.name, "built-in sample"


def _work(rid, lv, tool_dir, entry, name, mode, source):
    with _slots:
        try:
            rep = runner.run(tool_dir, entry, tool_name=name or None, mode=mode, live=lv)
            rep.update(id=rid, status="done", source=source,
                       tool_hash=tool_hash(tool_dir, entry, source))
            rep["policy"] = pol = policy.evaluate(rep)
            blockers = ", ".join(h["name"] for h in pol["hits"] if h["action"] == "block")
            if pol["outcome"] == "blocked":
                lv.emit("policy", "crit", "Blocked by workspace policy", blockers)
            elif pol["outcome"] == "review":
                lv.emit("policy", "warn", "Policy: needs a reviewer's written reason to approve",
                        ", ".join(h["name"] for h in pol["hits"]))
            elif pol["outcome"] == "approved":
                lv.emit("policy", "ok", "Approved automatically by workspace policy", "")
            rep["timeline"] = list(lv.events)
            store.save_run(rep)
            _apply_policy(rid, rep)
        except Exception as e:
            traceback.print_exc()
            lv.emit("error", "crit", "Run failed", str(e)[:400])
            store.save_run({"id": rid, "tool": name or "tool", "entry": entry, "status": "error",
                            "error": str(e)[:400], "started": lv.t0, "source": source,
                            "timeline": list(lv.events)})
        finally:
            lv.status = "finished"
            live.forget(rid)


def _apply_policy(rid, rep):
    """Act on the policy outcome: auto-block, or auto-approve a perfectly clean tool."""
    pol = rep.get("policy") or {}
    reg = store.registry_entry(rep.get("tool_hash"))
    try:
        if pol.get("outcome") == "blocked" and (not reg or reg.get("state") != "blocked"):
            names = ", ".join(h["name"] for h in pol["hits"] if h["action"] == "block")
            store.set_decision(rid, "reject", f"Automatically blocked by policy: {names}.",
                               "Policy engine")
        elif pol.get("outcome") == "approved" and not reg:
            store.set_decision(rid, "approve", "Automatically approved: rated TRUSTED 100/100 "
                               "and the workspace allows auto-approval.", "Policy engine")
    except store.DecisionError:
        pass


@app.post("/api/runs")
def start_run(req: RunReq):
    tool_dir, entry, name, source = _resolve(req)
    rid = uuid.uuid4().hex[:12]
    lv = live.LiveRun()
    live.register(rid, lv)
    store.save_run({"id": rid, "tool": name or os.path.basename(tool_dir), "entry": entry,
                    "status": "running", "started": lv.t0, "source": source})
    threading.Thread(target=_work, args=(rid, lv, tool_dir, entry, name, req.mode, source),
                     daemon=True).start()
    return {"id": rid, "status": "running"}


@app.get("/api/runs")
def api_list():
    return [{"id": r["id"], "tool": r.get("tool"), "verdict": r.get("verdict"),
             "status": r.get("status", "done"), "source": r.get("source"),
             "decision": r.get("decision"), "started": r.get("started"),
             "counts": r.get("counts")} for r in store.list_runs()]


@app.get("/api/runs/{rid}")
def api_get(rid: str):
    r = store.get_run(rid)
    if not r:
        raise HTTPException(404, "no such run")
    if r.get("status") == "running" and not live.get(rid):
        r["status"] = "error"   # orphaned by a restart
        r["error"] = "the server restarted while this run was in progress"
    r["registry"] = store.registry_entry(r.get("tool_hash")) if r.get("tool_hash") else None
    if r.get("status") == "done" and r.get("verdict"):
        r["policy_now"] = policy.evaluate(r)      # against today's rules, not run-time ones
    if r["registry"]:
        r["registry"]["expired"] = policy.approval_expired(r["registry"])
    return r


@app.get("/api/runs/{rid}/live")
def api_live(rid: str, after: int = 0):
    lv = live.get(rid)
    if not lv:
        r = store.get_run(rid)
        if not r:
            raise HTTPException(404, "no such run")
        tl = r.get("timeline") or []
        return {"events": tl[after:], "running": False, "runtime_files": r.get("runtime_files", 0),
                "status": r.get("status", "done")}
    events, noise = lv.since(after)
    return {"events": events, "running": lv.status == "running", "runtime_files": noise,
            "status": "running" if lv.status == "running" else "done"}


@app.post("/api/runs/{rid}/decide")
def api_decide(rid: str, req: DecideReq):
    if req.state not in ("approve", "reject"):
        raise HTTPException(400, "state must be approve or reject")
    try:
        r = store.set_decision(rid, req.state, req.note, req.reviewer)
    except store.DecisionError as e:
        raise HTTPException(409, str(e))
    if not r:
        raise HTTPException(404, "no such run")
    return {**r["decision"], "registry": r.get("registry")}


@app.get("/api/registry")
def api_registry():
    """Every tool version a human has approved or blocked, newest first."""
    return sorted(store.registry().values(), key=lambda e: e.get("at", 0), reverse=True)


@app.get("/api/registry/check")
def api_registry_check(hash: str):
    """What an agent or MCP gateway asks before launching a tool: is this exact code allowed?"""
    e = store.registry_entry(hash)
    if not e:
        return {"allowed": False, "state": "unknown", "hash": hash,
                "reason": "This code has never been quarantined and approved. Run it through "
                          "Tool Quarantine first."}
    run = store.get_run(e["run_id"]) if e["state"] == "approved" else None
    hard = policy.blocking_hits(run) if run else []
    if hard:
        return {"allowed": False, "state": "blocked_by_policy", "hash": hash, "tool": e["tool"],
                "run_id": e["run_id"], "verdict": e.get("verdict"),
                "reason": "Approved earlier, but the workspace policy now blocks it ("
                          + ", ".join(h["name"] for h in hard) + ")."}
    if policy.approval_expired(e):
        return {"allowed": False, "state": "expired", "hash": hash, "tool": e["tool"],
                "run_id": e["run_id"], "verdict": e.get("verdict"),
                "reason": "The approval has expired under the workspace policy. Quarantine "
                          "the tool again to renew it."}
    return {"allowed": e["state"] == "approved", "state": e["state"], "hash": hash,
            "tool": e["tool"], "run_id": e["run_id"], "verdict": e.get("verdict"),
            "reason": ("Approved after a quarantine run." if e["state"] == "approved"
                       else "Blocked by a reviewer after a quarantine run.")}


# ------------------------------------------------------------------ bring your own tool
def _check_uploads():
    if not UPLOADS_ON:
        raise HTTPException(403, "uploads are disabled on this server")


@app.post("/api/tools/upload")
async def api_upload(request: Request, name: str = "", entry: str = ""):
    _check_uploads()
    data = await request.body()
    if not data:
        raise HTTPException(400, "send the zip file as the request body")
    try:
        return uploads.from_zip(data, name, entry)
    except uploads.UploadError as e:
        raise HTTPException(400, str(e))


@app.post("/api/tools/github")
def api_github(req: GithubReq):
    _check_uploads()
    try:
        return uploads.from_github(req.url, req.name, req.entry)
    except uploads.UploadError as e:
        raise HTTPException(400, str(e))


@app.get("/api/tools")
def api_tools():
    return uploads.list_tools()


@app.get("/api/config")
def api_config():
    from . import agent
    return {"uploads": UPLOADS_ON, "agent": agent.model_label()}


# ------------------------------------------------------------------ policies
class PolicyReq(BaseModel):
    rules: dict = {}
    auto_approve: bool | None = None
    approval_ttl_days: int | None = None
    updated_by: str = ""


def _policy_body(req):
    body = {"rules": req.rules}
    if req.auto_approve is not None:
        body["auto_approve"] = req.auto_approve
    if req.approval_ttl_days is not None:
        body["approval_ttl_days"] = req.approval_ttl_days
    return body


@app.get("/api/policies")
def api_policies():
    return {**policy.get(), "catalog": policy.RULES}


@app.put("/api/policies")
def api_policies_save(req: PolicyReq):
    return {**policy.save(_policy_body(req), req.updated_by), "catalog": policy.RULES}


@app.post("/api/policies/simulate")
def api_policies_simulate(req: PolicyReq):
    """What a draft policy would do to the latest run of every tool (nothing is saved)."""
    draft = policy.get()
    for rid, cfg in (req.rules or {}).items():
        if rid in draft["rules"] and isinstance(cfg, dict):
            if cfg.get("action") in policy.ACTIONS:
                draft["rules"][rid]["action"] = cfg["action"]
            if "threshold" in cfg and "threshold" in draft["rules"][rid]:
                draft["rules"][rid]["threshold"] = int(cfg["threshold"])
    if req.auto_approve is not None:
        draft["auto_approve"] = req.auto_approve
    latest = {}
    for r in store.list_runs():
        if r.get("status") == "done" and r.get("verdict"):
            latest.setdefault(r.get("tool_hash") or r["id"], r)
    out = []
    for r in latest.values():
        ev = policy.evaluate(r, draft)
        out.append({"id": r["id"], "tool": r.get("tool"), "verdict": r["verdict"],
                    "outcome": ev["outcome"], "hits": ev["hits"]})
    return out


# ------------------------------------------------------------------ overview
@app.get("/api/stats")
def api_stats(days: int = 14):
    days = max(1, min(90, days))
    runs = store.list_runs()
    done = [r for r in runs if r.get("status") == "done" and r.get("verdict")]
    reg = store.registry()
    now = time.time()
    day0 = int(now // 86400) - days + 1
    trend = [{"day": (day0 + i) * 86400, "trusted": 0, "review": 0, "suspicious": 0,
              "dangerous": 0} for i in range(days)]
    cats, exfil, secrets, durations = {}, 0, 0, []
    for r in done:
        i = int((r.get("started") or 0) // 86400) - day0
        if 0 <= i < days:
            trend[i][r["verdict"]["label"]] = trend[i].get(r["verdict"]["label"], 0) + 1
        for f in r.get("findings") or []:
            cats[f.get("category")] = cats.get(f.get("category"), 0) + 1
            if f.get("category") == "network":
                exfil += 1
            if f.get("category") == "secret-access":
                secrets += 1
        if r.get("finished") and r.get("started"):
            durations.append(r["finished"] - r["started"])
    by_label = {k: sum(1 for r in done if r["verdict"]["label"] == k)
                for k in ("trusted", "review", "suspicious", "dangerous")}
    tools = {}
    for r in done:                                  # newest run per tool name
        tools.setdefault(r.get("tool"), r)
    pending = []
    for r in tools.values():
        e = reg.get(r.get("tool_hash")) if r.get("tool_hash") else None
        if not e:
            pending.append({"id": r["id"], "tool": r.get("tool"), "verdict": r["verdict"],
                            "started": r.get("started")})
    activity = []
    for e in reg.values():
        for h in e.get("history") or []:
            activity.append({**h, "tool": e.get("tool"), "hash": e.get("hash")})
    activity.sort(key=lambda h: h.get("at") or 0, reverse=True)
    states = [e.get("state") for e in reg.values()]
    return {
        "scans": len(done), "tools": len(tools), "running": sum(r.get("status") == "running" for r in runs),
        "failed": sum(r.get("status") == "error" for r in runs),
        "by_label": by_label, "threats_contained": sum(1 for r in done if r.get("findings")),
        "exfil_attempts": exfil, "credentials_touched": secrets,
        "approved": states.count("approved"), "blocked": states.count("blocked"),
        "pending_review": pending[:8], "pending_count": len(pending),
        "avg_scan_seconds": round(sum(durations) / len(durations), 1) if durations else None,
        "trend": trend, "categories": cats, "activity": activity[:12],
        "policy": {"updated_at": policy.get().get("updated_at")},
    }


# ------------------------------------------------------------------ pages
def _page(name):
    return FileResponse(os.path.join(STATIC, name))


@app.get("/")
def landing():
    return _page("landing.html")


@app.get("/app")
def app_overview():
    return _page("overview.html")


@app.get("/app/scans")
def app_scans():
    return _page("index.html")


@app.get("/app/registry")
def app_registry():
    return _page("registry.html")


@app.get("/app/policies")
def app_policies():
    return _page("policies.html")


@app.get("/app/integrations")
def app_integrations():
    return _page("integrations.html")


@app.get("/run/{rid}")
def run_page(rid):
    return _page("report.html")


@app.get("/api/runs/{rid}/export")
def api_export(rid: str):
    """The full trust report as a downloadable JSON file (for audits and tickets)."""
    from fastapi.responses import JSONResponse
    r = api_get(rid)
    return JSONResponse(r, headers={"Content-Disposition":
                                    f'attachment; filename="trust-report-{r.get("tool","tool")}-{rid}.json"'})


if os.path.isdir(STATIC):
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
