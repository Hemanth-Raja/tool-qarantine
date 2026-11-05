"""End-to-end run: spin up a disposable sandbox, let the agent exercise the tool,
collect evidence, analyze, and return a trust report. The sandbox is always destroyed.

Two modes:
  * "docker"  - the real quarantine (default).
  * "trace"   - no Docker: run the tool locally under the host's strace against a temp
                home full of decoys. Used for tests/CI and machines without Docker.
"""
import os
import shutil
import subprocess
import tempfile
import time

from . import agent, report
from .analyzer import analyze
from .mcp_client import StdioMCPClient

DECOY_SRC = os.path.join(os.path.dirname(__file__), "..", "sandbox", "decoys")
WORKSPACE_SRC = os.path.join(os.path.dirname(__file__), "..", "sandbox", "workspace")


def _declared_text(tools):
    return "\n".join(t.get("description", "") for t in tools)


def run_docker(tool_dir, entry, tool_name=None):
    from .sandbox import SandboxRun
    started = time.time()
    box = SandboxRun(tool_dir, entry).setup()
    calls_made, tools = [], []
    try:
        with StdioMCPClient(box.docker_cmd()) as client:
            client.initialize()
            tools = client.list_tools()
            plan, agent_mode = agent.plan_calls(tools)
            for call in plan:
                try:
                    res = client.call_tool(call["name"], call.get("arguments", {}))
                    ok = not (res or {}).get("isError")
                except Exception as e:
                    res, ok = {"error": str(e)}, False
                calls_made.append({"name": call["name"], "arguments": call.get("arguments", {}),
                                   "ok": ok})
        trace, sink = box.collect()
    finally:
        box.teardown()
    findings = analyze(trace, sink, _declared_text(tools))
    return report.build_report(tool_name or os.path.basename(tool_dir.rstrip("/")),
                               entry, tools, calls_made, findings, agent_mode, started,
                               mode="docker")


def run_trace(tool_dir, entry, tool_name=None):
    """Docker-free fallback: strace on the host with a decoy HOME. No network sinkhole,
    so network findings come only from connect() syscalls, not captured payloads."""
    started = time.time()
    home = tempfile.mkdtemp(prefix="tq-home-")
    ws = tempfile.mkdtemp(prefix="tq-ws-")
    audit = tempfile.mkdtemp(prefix="tq-audit-")
    trace_path = os.path.join(audit, "trace.log")
    try:
        if os.path.isdir(DECOY_SRC):
            shutil.copytree(DECOY_SRC, home, dirs_exist_ok=True)
        if os.path.isdir(WORKSPACE_SRC):
            shutil.copytree(WORKSPACE_SRC, ws, dirs_exist_ok=True)
        env = dict(os.environ, HOME=home, TQ_WORKSPACE=ws)
        strace = shutil.which("strace")
        prog = entry.split()
        if strace:
            argv = [strace, "-f", "-qq", "-tt", "-s", "200", "-yy",
                    "-e", "trace=openat,open,connect,execve,rename,unlink,mkdir",
                    "-o", trace_path] + prog
        else:
            argv = prog  # degrade gracefully; analyzer just sees no trace
        wrapped = StdioMCPClient(argv, env=dict(env, PYTHONPATH=tool_dir))
        calls_made, tools = [], []
        # run the tool from the workspace dir so relative /workspace-like reads resolve
        orig = os.getcwd()
        os.chdir(ws)
        try:
            with wrapped as client:
                client.initialize()
                tools = client.list_tools()
                plan, agent_mode = agent.plan_calls(tools)
                for call in plan:
                    try:
                        res = client.call_tool(call["name"], call.get("arguments", {}))
                        ok = not (res or {}).get("isError")
                    except Exception as e:
                        res, ok = {"error": str(e)}, False
                    calls_made.append({"name": call["name"],
                                       "arguments": call.get("arguments", {}), "ok": ok})
        finally:
            os.chdir(orig)
        trace = open(trace_path, errors="replace").read() if os.path.exists(trace_path) else ""
        # in trace mode the decoys live under `home`, not /home/dev; normalise for the analyzer
        trace = trace.replace(home, "/home/dev").replace(ws, "/workspace")
        findings = analyze(trace, "", _declared_text(tools))
        return report.build_report(tool_name or os.path.basename(tool_dir.rstrip("/")),
                                   entry, tools, calls_made, findings, agent_mode, started,
                                   mode="trace")
    finally:
        for d in (home, ws, audit):
            shutil.rmtree(d, ignore_errors=True)


def run(tool_dir, entry, tool_name=None, mode="auto"):
    if mode == "docker":
        return run_docker(tool_dir, entry, tool_name)
    if mode == "trace":
        return run_trace(tool_dir, entry, tool_name)
    # auto: prefer docker if the daemon is reachable
    try:
        if subprocess.run(["docker", "info"], capture_output=True).returncode == 0:
            return run_docker(tool_dir, entry, tool_name)
    except FileNotFoundError:
        pass
    return run_trace(tool_dir, entry, tool_name)
