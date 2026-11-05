"""Minimal MCP stdio client.

Talks JSON-RPC 2.0 over a subprocess's stdin/stdout. The subprocess is normally
`docker run -i ... <tool>` so the tool runs inside the quarantine sandbox while this
client drives it from the host. Trace output goes to a file inside the container, so
stdout stays a clean MCP channel.
"""
import json
import subprocess
import threading
import time


class MCPError(Exception):
    pass


class StdioMCPClient:
    def __init__(self, argv, env=None):
        self.argv = argv
        self.env = env
        self.proc = None
        self._id = 0
        self._stderr = []

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.close()

    def start(self):
        self.proc = subprocess.Popen(
            self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=self.env, bufsize=1, text=True)
        t = threading.Thread(target=self._drain_stderr, daemon=True)
        t.start()

    def _drain_stderr(self):
        for line in self.proc.stderr:
            self._stderr.append(line.rstrip("\n"))

    def _rpc(self, method, params=None, timeout=30, notify=False):
        if notify:
            msg = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                msg["params"] = params
            self.proc.stdin.write(json.dumps(msg) + "\n")
            self.proc.stdin.flush()
            return None
        self._id += 1
        mid = self._id
        msg = {"jsonrpc": "2.0", "id": mid, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                raise MCPError(f"server exited; stderr: {' | '.join(self._stderr[-5:])}")
            line = line.strip()
            if not line:
                continue
            try:
                resp = json.loads(line)
            except json.JSONDecodeError:
                continue  # stray non-JSON output
            if resp.get("id") != mid:
                continue  # skip notifications / mismatched ids
            if "error" in resp:
                raise MCPError(str(resp["error"]))
            return resp.get("result")
        raise MCPError(f"timeout waiting for {method}")

    def initialize(self):
        res = self._rpc("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "tool-quarantine", "version": "0.1.0"}})
        self._rpc("notifications/initialized", notify=True)
        return res

    def list_tools(self):
        return (self._rpc("tools/list") or {}).get("tools", [])

    def call_tool(self, name, arguments, timeout=30):
        return self._rpc("tools/call", {"name": name, "arguments": arguments}, timeout=timeout)

    def close(self):
        if not self.proc:
            return
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
