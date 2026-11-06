"""End-to-end run: spin up a disposable sandbox, let the agent exercise the tool,
collect evidence, analyze, and return a trust report. The sandbox is always destroyed.

Two modes:
  * "docker"  - the real quarantine (default).
  * "trace"   - no Docker: run the tool locally under the host's strace against a temp
                home full of decoys. Used for tests/CI and machines without Docker.
"""
import json
import os
import shutil
import subprocess
import tempfile
import time

from . import agent, report
from .analyzer import Finding, analyze, poison_hits, scope_comparison, verdict
from .live import LiveRun, Tailer
from .mcp_client import StdioMCPClient

DECOY_SRC = os.path.join(os.path.dirname(__file__), "..", "sandbox", "decoys")
WORKSPACE_SRC = os.path.join(os.path.dirname(__file__), "..", "sandbox", "workspace")


def _declared_text(tools):
    return "\n".join(t.get("description", "") for t in tools)


def _result_text(res):
    try:
        parts = [c.get("text", "") for c in (res or {}).get("content", []) if isinstance(c, dict)]
        return " ".join(parts).strip()[:300]
    except Exception:
        return ""


def _exercise(client, live):
    """MCP handshake, let the agent plan, make each call. Returns (tools, calls, agent_mode)."""
    live.phase("MCP handshake", "initialize → tools/list over stdio")
    client.initialize()
    tools = client.list_tools()
    live.emit("tools", "info", f"Tool advertises {len(tools)} function{'s' if len(tools) != 1 else ''}",
              "; ".join(f"{t['name']}: {t.get('description', '')}" for t in tools)[:600])
    live.declared = _declared_text(tools)
    hits = poison_hits(live.declared)
    if hits:
        live.emit("poison", "crit", "Hidden instructions for the AI in the tool description",
                  " · ".join(hits)[:500])
    live.phase("Agent planning", f"{agent.model_label()} decides how a real user would call it")
    plan, agent_mode = agent.plan_calls(tools)
    live.emit("plan", "info", f"Agent ({agent_mode}) planned {len(plan)} call{'s' if len(plan) != 1 else ''}",
              ", ".join(c["name"] for c in plan))
    calls_made = []
    for call in plan:
        args = call.get("arguments", {})
        live.emit("call", "info", f"Calling {call['name']}", json.dumps(args)[:300])
        try:
            res = client.call_tool(call["name"], args)
            ok = not (res or {}).get("isError")
            text = _result_text(res)
        except Exception as e:
            ok, text = False, str(e)[:300]
        live.flush()
        live.emit("result", "ok" if ok else "warn",
                  f"{call['name']} {'returned' if ok else 'failed'}", text)
        calls_made.append({"name": call["name"], "arguments": args, "ok": ok, "output": text})
    return tools, calls_made, agent_mode


def _rug_pull(events):
    """A tool that is clean on its first call and misbehaves on a later one ("rug pull")."""
    per_call, cur = [], None
    for ev in events:
        if ev["kind"] == "call":
            cur = {"name": ev["title"].replace("Calling ", ""), "bad": []}
            per_call.append(cur)
        elif cur is not None and ev["level"] == "crit" and ev["kind"] != "verdict":
            cur["bad"].append(ev["title"])
    if len(per_call) >= 2 and not per_call[0]["bad"] and any(c["bad"] for c in per_call[1:]):
        first_bad = next(i for i, c in enumerate(per_call) if c["bad"])
        return {"severity": "high", "category": "rug-pull",
                "title": "Behaved well on the first call, then turned malicious",
                "detail": "Its first call was clean, so a quick manual test would have passed it. "
                          "The bad behaviour only started on a later call. Running it under "
                          "realistic, repeated use is what exposed it.",
                "evidence": [f"call 1 ({per_call[0]['name']}): clean",
                             f"call {first_bad + 1} ({per_call[first_bad]['name']}): "
                             + "; ".join(dict.fromkeys(per_call[first_bad]["bad"]))[:300]]}
    return None


def _finish(live, findings, tool_name, entry, tools, calls, agent_mode, started, mode, trace,
            sink, declared):
    rep = report.build_report(tool_name, entry, tools, calls, findings, agent_mode, started,
                              mode=mode)
    rep["scope"] = scope_comparison(trace, sink, declared)
    rug = _rug_pull(live.events)
    if rug:
        rep["findings"].append(rug)
        rep["counts"]["high"] += 1
        rep["verdict"] = verdict([Finding(**f) for f in rep["findings"]])
    v = rep["verdict"]
    live.emit("verdict", {"trusted": "ok", "review": "warn", "suspicious": "warn",
                          "dangerous": "crit"}.get(v["label"], "info"),
              f"Verdict: {v['label'].upper()} ({v['score']}/100)", v["summary"])
    rep["timeline"] = list(live.events)
    rep["runtime_files"] = live.runtime_files
    return rep


def run_docker(tool_dir, entry, tool_name=None, live=None):
    from .sandbox import SandboxRun
    live = live or LiveRun()
    started = time.time()
    box = SandboxRun(tool_dir, entry)
    tailer = None
    calls_made, tools, agent_mode = [], [], "mock"
    try:
        live.phase("Creating isolated network", f"{box.net} (--internal: no route to the internet)")
        box.setup()
        live.phase("Sinkhole up", f"{box.sink_name} at {box.sink_ip} answers all DNS, records HTTP/TLS")
        live.phase("Launching sandbox", "read-only FS · all caps dropped · 256 MB · 0.5 CPU · "
                   "decoy credentials planted · strace on every syscall")
        tailer = Tailer(live, os.path.join(box.audit_dir, "trace.log"), box.sink_name)
        tailer.start()
        with StdioMCPClient(box.docker_cmd()) as client:
            tools, calls_made, agent_mode = _exercise(client, live)
        tailer.stop()
        tailer = None
        trace, sink = box.collect()
    finally:
        if tailer:
            tailer.stop()
        box.teardown()
        live.phase("Sandbox destroyed", "container, sinkhole and network removed")
    declared = _declared_text(tools)
    findings = analyze(trace, sink, declared)
    return _finish(live, findings, tool_name or os.path.basename(tool_dir.rstrip("/")), entry,
                   tools, calls_made, agent_mode, started, "docker", trace, sink, declared)


def run_trace(tool_dir, entry, tool_name=None, live=None):
    """Docker-free fallback: strace on the host with a decoy HOME. No network sinkhole,
    so network findings come only from connect() syscalls, not captured payloads."""
    live = live or LiveRun()
    started = time.time()
    home = tempfile.mkdtemp(prefix="tq-home-")
    ws = tempfile.mkdtemp(prefix="tq-ws-")
    audit = tempfile.mkdtemp(prefix="tq-audit-")
    trace_path = os.path.join(audit, "trace.log")
    tool_dir = os.path.abspath(tool_dir)

    def norm(text):
        return text.replace(home, "/home/dev").replace(ws, "/workspace").replace(tool_dir, "/tool")

    try:
        live.phase("Preparing trace sandbox", "no Docker here: host strace with a decoy home directory")
        if os.path.isdir(DECOY_SRC):
            shutil.copytree(DECOY_SRC, home, dirs_exist_ok=True)
        if os.path.isdir(WORKSPACE_SRC):
            shutil.copytree(WORKSPACE_SRC, ws, dirs_exist_ok=True)
        env = dict(os.environ, HOME=home, TQ_WORKSPACE=ws)
        strace = shutil.which("strace")
        prog = [a.replace("/tool/", tool_dir + "/", 1) if a.startswith("/tool/") else a
                for a in entry.split()]
        if strace:
            argv = [strace, "-f", "-qq", "-tt", "-s", "200", "-yy",
                    "-e", "trace=openat,open,connect,execve,rename,unlink,mkdir",
                    "-o", trace_path] + prog
        else:
            argv = prog  # degrade gracefully; analyzer just sees no trace
        wrapped = StdioMCPClient(argv, env=dict(env, PYTHONPATH=tool_dir))
        calls_made, tools, agent_mode = [], [], "mock"
        tailer = Tailer(live, trace_path, None, normalise=norm)
        tailer.start()
        # run the tool from the workspace dir so relative /workspace-like reads resolve
        orig = os.getcwd()
        os.chdir(ws)
        try:
            with wrapped as client:
                tools, calls_made, agent_mode = _exercise(client, live)
        finally:
            os.chdir(orig)
            tailer.stop()
        trace = open(trace_path, errors="replace").read() if os.path.exists(trace_path) else ""
        # in trace mode the decoys live under `home`, not /home/dev; normalise for the analyzer
        trace = norm(trace)
        live.phase("Sandbox destroyed", "temporary home, workspace and audit dirs removed")
        declared = _declared_text(tools)
        findings = analyze(trace, "", declared)
        return _finish(live, findings, tool_name or os.path.basename(tool_dir.rstrip("/")),
                       entry, tools, calls_made, agent_mode, started, "trace", trace, "",
                       declared)
    finally:
        for d in (home, ws, audit):
            shutil.rmtree(d, ignore_errors=True)


def run(tool_dir, entry, tool_name=None, mode="auto", live=None):
    if mode == "docker":
        return run_docker(tool_dir, entry, tool_name, live)
    if mode == "trace":
        return run_trace(tool_dir, entry, tool_name, live)
    # auto: prefer docker if the daemon is reachable
    try:
        if subprocess.run(["docker", "info"], capture_output=True).returncode == 0:
            return run_docker(tool_dir, entry, tool_name, live)
    except FileNotFoundError:
        pass
    return run_trace(tool_dir, entry, tool_name, live)
