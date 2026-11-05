"""Tool Quarantine web service (FastAPI).

Endpoints:
  GET  /                      dashboard (list of runs)
  GET  /run/{id}              trust report page with Approve / Reject buttons
  POST /api/runs              start a run for a tool dir + entry  -> {id}
  GET  /api/runs              list runs (JSON)
  GET  /api/runs/{id}         one run (JSON)
  POST /api/runs/{id}/decide  {state: approve|reject, note}      approval workflow
  GET  /healthz
The HTML is served from static/ ; the pages are plain JS calling the JSON API.
"""
import os
import threading

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import runner, store

STATIC = os.path.join(os.path.dirname(__file__), "static")
SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")

app = FastAPI(title="Tool Quarantine")


class RunReq(BaseModel):
    tool_dir: str = SAMPLES
    entry: str
    name: str = ""
    mode: str = "auto"


class DecideReq(BaseModel):
    state: str
    note: str = ""


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/api/runs")
def start_run(req: RunReq):
    # Only sample tools and explicitly provided dirs are allowed; no arbitrary host paths
    # unless TQ_ALLOW_ANY_DIR is set (demo safety).
    tool_dir = os.path.abspath(req.tool_dir)
    if not os.environ.get("TQ_ALLOW_ANY_DIR") and not tool_dir.startswith(os.path.abspath(SAMPLES)):
        raise HTTPException(400, "tool_dir must be under samples/ (set TQ_ALLOW_ANY_DIR to override)")
    rep = runner.run(tool_dir, req.entry, tool_name=req.name or None, mode=req.mode)
    rid = store.save_run(rep)
    return {"id": rid, "verdict": rep["verdict"]}


@app.get("/api/runs")
def api_list():
    return [{"id": r["id"], "tool": r["tool"], "verdict": r["verdict"],
             "decision": r.get("decision"), "started": r.get("started"),
             "counts": r.get("counts")} for r in store.list_runs()]


@app.get("/api/runs/{rid}")
def api_get(rid: str):
    r = store.get_run(rid)
    if not r:
        raise HTTPException(404, "no such run")
    return r


@app.post("/api/runs/{rid}/decide")
def api_decide(rid: str, req: DecideReq):
    if req.state not in ("approve", "reject"):
        raise HTTPException(400, "state must be approve or reject")
    r = store.set_decision(rid, req.state, req.note)
    if not r:
        raise HTTPException(404, "no such run")
    return r["decision"]


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/run/{rid}")
def run_page(rid):
    return FileResponse(os.path.join(STATIC, "report.html"))


if os.path.isdir(STATIC):
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
