"""Disposable sandbox orchestration.

A run creates:
  * an isolated bridge network with no internet route,
  * a sinkhole container on it (DNS/HTTP/TLS capture),
  * a sandbox container that runs the untrusted tool under strace, with:
      - the sinkhole as its only DNS server and only reachable host,
      - a read-only root filesystem,
      - decoy canary credentials in the home dir (baked into the image),
      - all Linux capabilities dropped, no-new-privileges,
      - CPU / memory / pid / wall-clock caps,
      - /audit as a tmpfs the host reads before teardown.
Everything is torn down and removed at the end of the run, pass or fail.
"""
import json
import os
import shlex
import subprocess
import tempfile
import time
import uuid

SANDBOX_IMAGE = os.environ.get("TQ_SANDBOX_IMAGE", "tq-sandbox:latest")
SINKHOLE_IMAGE = os.environ.get("TQ_SINKHOLE_IMAGE", "tq-sinkhole:latest")


def _run(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


class SandboxRun:
    def __init__(self, tool_dir, entry, mem="256m", cpus="0.5", pids=64, wall=30):
        self.tool_dir = os.path.abspath(tool_dir)
        self.entry = entry            # e.g. "python /tool/unit_converter.py"
        self.mem, self.cpus = mem, cpus
        self.pids, self.wall = pids, wall
        self.rid = uuid.uuid4().hex[:10]
        self.net = f"tq-net-{self.rid}"
        self.sink_name = f"tq-sink-{self.rid}"
        self.audit_dir = tempfile.mkdtemp(prefix="tq-audit-")
        os.chmod(self.audit_dir, 0o777)  # uid 1000 in the sandbox writes trace.log here
        self.sink_ip = None

    # -- lifecycle -----------------------------------------------------------
    def setup(self):
        # internal network: --internal removes the default route to the internet.
        _run(["docker", "network", "create", "--internal", "--driver", "bridge", self.net])
        _run(["docker", "run", "-d", "--name", self.sink_name, "--network", self.net,
              "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
              SINKHOLE_IMAGE])
        # discover the sinkhole's IP on the network
        for _ in range(30):
            insp = _run(["docker", "inspect", "-f",
                         "{{(index .NetworkSettings.Networks \"" + self.net + "\").IPAddress}}",
                         self.sink_name])
            ip = insp.stdout.strip()
            if ip:
                self.sink_ip = ip
                break
            time.sleep(0.2)
        return self

    def docker_cmd(self):
        """The argv that launches the untrusted tool in the sandbox, MCP on stdio."""
        args = [
            "docker", "run", "-i", "--rm",
            "--network", self.net,
            "--name", f"tq-box-{self.rid}",
            "--read-only",
            "-v", f"{self.audit_dir}:/audit",  # host-side; survives container exit for collection
            "--tmpfs", "/tmp:rw,size=32m,uid=1000",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--memory", self.mem, "--memory-swap", self.mem,
            "--cpus", self.cpus, "--pids-limit", str(self.pids),
            "-v", f"{self.tool_dir}:/tool:ro",
            "-w", "/workspace",
        ]
        if self.sink_ip:
            args += ["--dns", self.sink_ip,
                     "--add-host", f"analytics.tq-demo.example:{self.sink_ip}"]
        args += [SANDBOX_IMAGE] + shlex.split(self.entry)
        return args

    def collect(self):
        """Read the strace log (bind-mounted to the host) and the sinkhole log."""
        trace = ""
        p = os.path.join(self.audit_dir, "trace.log")
        if os.path.exists(p):
            trace = open(p, errors="replace").read()
        sink = _run(["docker", "logs", self.sink_name]).stdout
        return trace, sink

    def teardown(self):
        _run(["docker", "rm", "-f", f"tq-box-{self.rid}"])
        _run(["docker", "rm", "-f", self.sink_name])
        _run(["docker", "network", "rm", self.net])
        try:
            for f in os.listdir(self.audit_dir):
                os.remove(os.path.join(self.audit_dir, f))
            os.rmdir(self.audit_dir)
        except OSError:
            pass
