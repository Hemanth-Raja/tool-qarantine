"""A tiny, dependency-free MCP stdio server used by the sample tools.

Speaks newline-delimited JSON-RPC 2.0 (the MCP stdio transport) and supports
initialize, tools/list and tools/call. Servers built on the official SDK behave the
same on the wire, so Tool Quarantine treats them identically.
"""
import json
import sys
import traceback

PROTOCOL_VERSION = "2025-06-18"


class Server:
    def __init__(self, name, version="0.1.0"):
        self.name, self.version = name, version
        self.tools = {}

    def tool(self, name, description, schema):
        def deco(fn):
            self.tools[name] = {"fn": fn, "description": description, "schema": schema}
            return fn
        return deco

    def _reply(self, mid, result=None, error=None):
        msg = {"jsonrpc": "2.0", "id": mid}
        if error is not None:
            msg["error"] = error
        else:
            msg["result"] = result
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()

    def run(self):
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue
            method, mid = req.get("method"), req.get("id")
            if mid is None:  # notification
                continue
            if method == "initialize":
                self._reply(mid, {"protocolVersion": PROTOCOL_VERSION,
                                  "capabilities": {"tools": {}},
                                  "serverInfo": {"name": self.name, "version": self.version}})
            elif method == "tools/list":
                self._reply(mid, {"tools": [
                    {"name": n, "description": t["description"], "inputSchema": t["schema"]}
                    for n, t in self.tools.items()]})
            elif method == "tools/call":
                p = req.get("params", {})
                t = self.tools.get(p.get("name"))
                if not t:
                    self._reply(mid, error={"code": -32602, "message": "unknown tool"})
                    continue
                try:
                    out = t["fn"](**(p.get("arguments") or {}))
                    self._reply(mid, {"content": [{"type": "text", "text": str(out)}], "isError": False})
                except Exception as e:
                    self._reply(mid, {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True})
                    traceback.print_exc(file=sys.stderr)
            elif method == "ping":
                self._reply(mid, {})
            else:
                self._reply(mid, error={"code": -32601, "message": f"method not found: {method}"})
