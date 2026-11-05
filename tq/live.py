"""Live activity feed for a run in progress.

A run gets a LiveRun: an append-only list of timeline events that the web UI polls
(GET /api/runs/{id}/live?after=N). Events come from two places:
  * the runner itself (phases: network created, sinkhole up, MCP handshake, agent plan,
    each tool call and its result, teardown), and
  * a Tailer thread that follows the sandbox's strace log and the sinkhole's log while
    the tool runs, classifying each new line (secret read, home-dir read, DNS, the
    exfiltration POST, process spawn, write attempt).
When the run finishes, the timeline is saved into the report so it can be replayed.
"""
import json
import os
import subprocess
import threading
import time

from .analyzer import classify_sink_event, classify_strace_line

_RUNS = {}
_RUNS_LOCK = threading.Lock()


class LiveRun:
    def __init__(self, rid=None):
        self.rid = rid
        self.t0 = time.time()
        self.events = []
        self.runtime_files = 0
        self.status = "running"
        self.flusher = None   # set by a Tailer: drain pending evidence on demand
        self._lock = threading.Lock()

    def emit(self, kind, level, title, detail="", **extra):
        with self._lock:
            ev = {"seq": len(self.events), "t": round(time.time() - self.t0, 3),
                  "kind": kind, "level": level, "title": title, "detail": detail or ""}
            ev.update(extra)
            self.events.append(ev)
        return ev

    def phase(self, title, detail="", level="info"):
        return self.emit("phase", level, title, detail)

    def since(self, after):
        with self._lock:
            return self.events[after:], self.runtime_files

    def flush(self):
        if self.flusher:
            self.flusher()

    def add_noise(self, n=1):
        with self._lock:
            self.runtime_files += n


def register(rid, live):
    live.rid = rid
    with _RUNS_LOCK:
        _RUNS[rid] = live


def get(rid):
    with _RUNS_LOCK:
        return _RUNS.get(rid)


def forget(rid, delay=120):
    """Drop a finished run from memory after a grace period (its timeline is persisted)."""
    def _drop():
        time.sleep(delay)
        with _RUNS_LOCK:
            _RUNS.pop(rid, None)
    threading.Thread(target=_drop, daemon=True).start()


class NullLive(LiveRun):
    """Used when nobody is watching (CLI, tests): same API, still records the timeline."""


class Tailer(threading.Thread):
    """Follow a strace log file (and optionally a sinkhole container's log) and push
    classified events into a LiveRun until stopped. stop() drains everything first."""

    def __init__(self, live, trace_path, sink_container=None, normalise=None, interval=0.12):
        super().__init__(daemon=True)
        self.live, self.trace_path = live, trace_path
        self.sink_container, self.normalise = sink_container, normalise
        self.interval = interval
        self._pos, self._buf, self._sink_seen = 0, "", 0
        self._seen = set()
        self._stop_evt = threading.Event()
        self._io = threading.Lock()
        live.flusher = self.flush

    def run(self):
        last_sink = 0.0
        while not self._stop_evt.is_set():
            with self._io:
                self._read_trace()
                if self.sink_container and time.time() - last_sink > 0.3:
                    self._read_sink()
                    last_sink = time.time()
            self._stop_evt.wait(self.interval)

    def flush(self):
        """Read everything written so far (called after each tool call, so the evidence
        lands in the feed between the call and its result)."""
        time.sleep(0.05)  # let strace / the sinkhole finish writing
        with self._io:
            self._read_trace()
            if self.sink_container:
                self._read_sink()

    def stop(self):
        self._stop_evt.set()
        self.join(timeout=3)
        self.live.flusher = None
        with self._io:
            self._read_trace(final=True)
            if self.sink_container:
                self._read_sink()

    # ------------------------------------------------------------------
    def _read_trace(self, final=False):
        try:
            with open(self.trace_path, errors="replace") as f:
                f.seek(self._pos)
                chunk = f.read()
                self._pos = f.tell()
        except OSError:
            return
        self._buf += chunk
        lines = self._buf.split("\n")
        self._buf = "" if final else lines.pop()
        noise = 0
        for line in lines:
            if not line.strip():
                continue
            if self.normalise:
                line = self.normalise(line)
            ev, is_noise = classify_strace_line(line)
            if is_noise:
                noise += 1
            if ev:
                key = (ev["kind"], ev["title"], ev["detail"])
                if key in self._seen:
                    continue  # the same file read twice is one event
                self._seen.add(key)
                self.live.emit(ev["kind"], ev["level"], ev["title"], ev["detail"], source="strace")
        if noise:
            self.live.add_noise(noise)

    def _read_sink(self):
        try:
            out = subprocess.run(["docker", "logs", self.sink_container],
                                 capture_output=True, text=True, timeout=5).stdout
        except Exception:
            return
        lines = [l for l in out.splitlines() if l.strip()]
        for line in lines[self._sink_seen:]:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ev = classify_sink_event(rec)
            if ev:
                self.live.emit(ev["kind"], ev["level"], ev["title"], ev["detail"], source="sinkhole")
        self._sink_seen = len(lines)
