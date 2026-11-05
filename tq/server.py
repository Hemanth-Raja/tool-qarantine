"""Tool Quarantine web service (FastAPI).

Endpoints:
  GET  /                      dashboard (samples, upload, list of runs)
  GET  /run/{id}              trust report page: live activity feed, claims vs reality,
                              findings, Approve / Reject
  POST /api/runs              start a run {sample entry | tool_id}       -> {id} immediately
  GET  /api/runs              list runs (JSON)
  GET  /api/runs/{id}         one run (JSON; status running | done | error)
  GET  /api/runs/{id}/live    ?after=N  timeline events since N while the run is going
  POST /api/runs/{id}/decide  {state: approve|reject, note}      approval workflow
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

from . import live, runner, store, uploads

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
            rep.update(id=rid, status="done", source=source)
            store.save_run(rep)
        except Exception as e:
            traceback.print_exc()
            lv.emit("error", "crit", "Run failed", str(e)[:400])
            store.save_run({"id": rid, "tool": name or "tool", "entry": entry, "status": "error",
                            "error": str(e)[:400], "started": lv.t0, "source": source,
                            "timeline": list(lv.events)})
        finally:
            lv.status = "finished"
            live.forget(rid)


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
    r = store.set_decision(rid, req.state, req.note)
    if not r:
        raise HTTPException(404, "no such run")
    return r["decision"]


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


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/run/{rid}")
def run_page(rid):
    return FileResponse(os.path.join(STATIC, "report.html"))


if os.path.isdir(STATIC):
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
