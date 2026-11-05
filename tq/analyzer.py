"""Turn raw sandbox evidence into structured findings and a trust verdict.

Inputs:
  * strace log  - every file open, exec, and connect the tool made (one process tree).
  * sinkhole log - DNS/HTTP/TLS the tool attempted on the isolated network.
  * declared scope - what the tool *said* it does (from its MCP tool descriptions).

Output: a list of Finding objects, each with a severity, plus an overall verdict.
The point is scope *over-reach*: comparing observed behaviour to declared purpose.
"""
import json
import re
from dataclasses import dataclass, field, asdict

# Severity ordering
INFO, LOW, MEDIUM, HIGH, CRITICAL = "info", "low", "medium", "high", "critical"
_RANK = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}

# Paths that hold the decoy canaries. Any read here is a secret access.
SECRET_PATTERNS = [
    (re.compile(r"/\.aws/credentials"), "AWS credentials"),
    (re.compile(r"/\.ssh/id_[a-z0-9]+$"), "SSH private key"),
    (re.compile(r"/\.config/gh/hosts\.yml"), "GitHub token"),
    (re.compile(r"/\.env$"), ".env secrets file"),
    (re.compile(r"/\.config/.*token"), "config token"),
]
# Home dir outside the declared workspace.
HOME_RE = re.compile(r"/home/dev(?!/\.cache)")
WORKSPACE = "/workspace"

# strace line: "PID  HH:MM:SS.uuuuuu  syscall(args) = ret"
_LINE = re.compile(r"^(\d+)\s+(\d+:\d+:\d+\.\d+)\s+(?:<\.\.\. \w+ resumed>|(\w+)\((.*))")
_OPENAT = re.compile(r'openat\(.*?,\s*"([^"]+)",\s*([^,)]+)')
_OPEN = re.compile(r'open\("([^"]+)",\s*([^,)]+)')
_CONNECT = re.compile(r'connect\(\d+.*?sin_port=htons\((\d+)\).*?inet_addr\("([^"]+)"\)')
_CONNECT6 = re.compile(r'connect\(\d+.*?sin6_port=htons\((\d+)\)')
_EXECVE = re.compile(r'execve\("([^"]+)",\s*\[([^\]]*)\]')
_WRITE_PATHS = re.compile(r'(openat|open)\(.*?"([^"]+)".*?(O_WRONLY|O_RDWR|O_CREAT|O_APPEND)')


@dataclass
class Finding:
    severity: str
    category: str      # secret-access | network | exec | write | scope-overreach
    title: str
    detail: str
    evidence: list = field(default_factory=list)

    def dict(self):
        return asdict(self)


def _is_system_path(path):
    return path.startswith(("/usr/", "/lib", "/lib64", "/etc/ld", "/proc/", "/sys/",
                            "/dev/", "/etc/ssl", "/etc/nsswitch", "/etc/resolv",
                            "/etc/host", "/etc/passwd", "/etc/group", "/audit/",
                            "/tmp/")) or path in ("/etc", ".", "/")


def parse_strace(text):
    """Return dicts of observed opens, execs, connects, writes."""
    opens, execs, connects, writes = [], [], [], []
    for raw in text.splitlines():
        m = _OPENAT.search(raw) or _OPEN.search(raw)
        if m and ("openat(" in raw or "open(" in raw) and "= -1" not in raw:
            path, flags = m.group(1), m.group(2)
            opens.append({"path": path, "flags": flags.strip()})
        mw = _WRITE_PATHS.search(raw)
        if mw and "= -1" not in raw:
            writes.append({"path": mw.group(2)})
        me = _EXECVE.search(raw)
        if me and "= -1" not in raw:
            execs.append({"path": me.group(1), "argv": me.group(2)})
        mc = _CONNECT.search(raw)
        if mc:
            connects.append({"port": int(mc.group(1)), "addr": mc.group(2),
                             "blocked": "ENETUNREACH" in raw or "ECONNREFUSED" in raw
                             or "EHOSTUNREACH" in raw})
    return {"opens": opens, "execs": execs, "connects": connects, "writes": writes}


def parse_sinkhole(text):
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return events


def _declared_allows_home(declared_text):
    t = (declared_text or "").lower()
    return any(w in t for w in ("home director", "whole disk", "entire filesystem",
                                "all files", "system files", "credential"))


def analyze(strace_text, sinkhole_text, declared_text="", expected_exec=None):
    """Build findings. `declared_text` is the tool's own description(s)."""
    obs = parse_strace(strace_text or "")
    sink = parse_sinkhole(sinkhole_text or "")
    findings = []
    expected_exec = set(expected_exec or [])

    # --- secret access -------------------------------------------------------
    secret_hits = []
    for o in obs["opens"]:
        for rx, label in SECRET_PATTERNS:
            if rx.search(o["path"]):
                secret_hits.append((o["path"], label))
    seen = set()
    for path, label in secret_hits:
        if path in seen:
            continue
        seen.add(path)
        findings.append(Finding(
            CRITICAL, "secret-access", f"Read {label}",
            f"The tool opened {path}, a credential file it was never given a reason to touch.",
            [path]))

    # --- reads outside the declared workspace -------------------------------
    overreach = []
    for o in obs["opens"]:
        p = o["path"]
        if "O_DIRECTORY" in o["flags"]:
            continue  # directory traversal, not a file read
        if _is_system_path(p):
            continue
        if p.startswith(WORKSPACE):
            continue
        if HOME_RE.search(p) and p not in seen:
            overreach.append(p)
    if overreach and not _declared_allows_home(declared_text):
        findings.append(Finding(
            HIGH, "scope-overreach",
            "Read files outside its declared workspace",
            "The tool says it works within " + WORKSPACE + ", but also read files under the "
            "home directory. Reaching beyond the stated scope is the core signal of a "
            "misbehaving tool.",
            sorted(set(overreach))[:20]))

    # --- network attempts ----------------------------------------------------
    net_attempts = [c for c in obs["connects"]
                    if not c["addr"].startswith("127.") and c["addr"] != "0.0.0.0"]
    dns = [e for e in sink if e.get("kind") == "dns"]
    http = [e for e in sink if e.get("kind") == "http"]
    tls = [e for e in sink if e.get("kind") == "tls"]
    if net_attempts or http or tls or dns:
        ev = []
        for c in net_attempts[:10]:
            ev.append(f"connect {c['addr']}:{c['port']}"
                      + (" (blocked)" if c["blocked"] else ""))
        for e in dns[:10]:
            ev.append(f"DNS lookup {e.get('name')}")
        for e in http[:10]:
            body = (e.get("body") or "")[:120]
            ev.append(f"HTTP {e.get('method')} {e.get('host')}{e.get('path')}"
                      + (f" body={body!r}" if body else ""))
        for e in tls[:10]:
            ev.append(f"TLS to {e.get('sni') or 'unknown host'}")
        sev = CRITICAL if (http or tls) else HIGH
        title = ("Exfiltration attempt: sent data to an external host"
                 if http else "Attempted network egress")
        findings.append(Finding(
            sev, "network", title,
            "A tool with no stated network purpose tried to reach the internet. On the "
            "quarantine network every route is a sinkhole, so nothing actually left, but "
            "the attempt is recorded in full.",
            ev))

    # --- unexpected process execution ---------------------------------------
    unexpected = []
    for e in obs["execs"]:
        base = e["path"].rsplit("/", 1)[-1]
        if base in ("python", "python3", "sh", "strace", "env"):
            continue  # launcher / interpreter itself
        if expected_exec and base in expected_exec:
            continue
        unexpected.append(e["path"])
    if unexpected:
        findings.append(Finding(
            MEDIUM, "exec", "Spawned unexpected processes",
            "The tool shelled out to other programs. A well-behaved compute tool rarely "
            "needs to.", sorted(set(unexpected))[:20]))

    # --- writes outside workspace -------------------------------------------
    bad_writes = [w["path"] for w in obs["writes"]
                  if not w["path"].startswith((WORKSPACE, "/tmp", "/audit", "/proc", "/dev"))
                  and not _is_system_path(w["path"])]
    if bad_writes:
        findings.append(Finding(
            HIGH, "write", "Attempted to write outside the workspace",
            "The tool tried to modify files outside " + WORKSPACE + " (e.g. shell profiles "
            "for persistence). The read-only filesystem blocked it.",
            sorted(set(bad_writes))[:20]))

    findings.sort(key=lambda f: _RANK[f.severity], reverse=True)
    return findings


def verdict(findings):
    """Overall trust verdict + 0-100 score (higher = safer)."""
    if not findings:
        return {"label": "trusted", "score": 100,
                "summary": "No file, network, or process activity beyond its declared scope."}
    top = max(_RANK[f.severity] for f in findings)
    penalty = sum({INFO: 0, LOW: 5, MEDIUM: 15, HIGH: 30, CRITICAL: 45}[f.severity]
                  for f in findings)
    score = max(0, 100 - penalty)
    if top >= _RANK[CRITICAL]:
        label, summary = "dangerous", "Accessed secrets or attempted to exfiltrate data."
    elif top >= _RANK[HIGH]:
        label, summary = "suspicious", "Reached well beyond its declared scope."
    elif top >= _RANK[MEDIUM]:
        label, summary = "review", "Some behaviour worth a human look before approval."
    else:
        label, summary = "trusted", "Minor notes only."
    return {"label": label, "score": score, "summary": summary}


# =========================================================================== live events
# The same evidence, one line at a time, for the live activity feed. Each event is a dict:
#   {kind, level, title, detail}   level: ok | info | warn | crit
_FAILED = re.compile(r"=\s*-1\s+(E[A-Z]+)")
_INTERPRETERS = ("python", "python3", "python3.12", "sh", "strace", "env", "tq-entrypoint")


def _secret_label(path):
    for rx, label in SECRET_PATTERNS:
        if rx.search(path):
            return label
    return None


def classify_strace_line(raw):
    """Return (event or None, is_runtime_noise). Runtime noise = interpreter/library loads."""
    failed = _FAILED.search(raw)
    m = _OPENAT.search(raw) or _OPEN.search(raw)
    if m and ("openat(" in raw or "open(" in raw):
        path, flags = m.group(1), m.group(2)
        writing = any(w in raw for w in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND"))
        if writing and not path.startswith((WORKSPACE, "/tmp", "/audit", "/proc", "/dev")) \
                and not _is_system_path(path):
            how = f"blocked: {failed.group(1)}" if failed else "succeeded"
            return {"kind": "write", "level": "warn", "title": "Tried to write outside the workspace",
                    "detail": f"{path}  ({how})"}, False
        if failed:
            return None, False  # probing for a file that isn't there
        if "O_DIRECTORY" in raw:
            if HOME_RE.search(path) and not path.startswith(WORKSPACE):
                return {"kind": "file", "level": "warn", "title": "Listed a home directory",
                        "detail": path}, False
            return None, True
        label = _secret_label(path)
        if label:
            return {"kind": "secret", "level": "crit", "title": f"Read {label}",
                    "detail": path}, False
        if _is_system_path(path) or path.startswith("/tool/") or path.startswith("/tool"):
            return None, True
        if path.startswith(WORKSPACE):
            return {"kind": "file", "level": "ok", "title": "Read workspace file",
                    "detail": path}, False
        if HOME_RE.search(path):
            return {"kind": "file", "level": "warn", "title": "Read file outside its workspace",
                    "detail": path}, False
        return None, True
    mc = _CONNECT.search(raw)
    if mc:
        port, addr = int(mc.group(1)), mc.group(2)
        if addr.startswith("127.") or addr == "0.0.0.0" or port == 53:
            return None, True  # loopback / DNS resolver socket (DNS shows up via the sinkhole)
        return {"kind": "net", "level": "crit", "title": f"Opened a connection to {addr}:{port}",
                "detail": "The only reachable host is the sinkhole."
                + (f" ({failed.group(1)})" if failed and failed.group(1) != "EINPROGRESS" else "")}, False
    me = _EXECVE.search(raw)
    if me and not failed:
        base = me.group(1).rsplit("/", 1)[-1]
        if base in _INTERPRETERS:
            return None, True
        return {"kind": "exec", "level": "warn", "title": f"Spawned a process: {base}",
                "detail": me.group(2)[:200]}, False
    return None, False


def classify_sink_event(e):
    k = e.get("kind")
    if k == "dns":
        return {"kind": "dns", "level": "warn", "title": f"DNS lookup: {e.get('name')}",
                "detail": "Answered by the sinkhole, so the name points nowhere real."}
    if k == "http":
        body = e.get("body") or ""
        return {"kind": "exfil", "level": "crit",
                "title": f"BLOCKED: HTTP {e.get('method')} {e.get('host')}{e.get('path')}",
                "detail": ("Captured payload: " + body[:600]) if body
                else "Request captured by the sinkhole. Nothing left the sandbox."}
    if k == "tls":
        return {"kind": "exfil", "level": "crit",
                "title": f"BLOCKED: TLS connection to {e.get('sni') or 'unknown host'}",
                "detail": "Handshake captured by the sinkhole and dropped."}
    return None


# ====================================================================== claims vs reality
_AREAS = [
    ("workspace", "Workspace files", "files in /workspace"),
    ("home", "Home directory", "your documents, outside the workspace"),
    ("secrets", "Credentials & keys", "~/.aws, ~/.ssh, tokens, .env"),
    ("network", "Network", "internet, DNS, outbound HTTP"),
    ("processes", "Other programs", "shell commands, subprocesses"),
    ("writes", "Writes outside workspace", "persistence, shell profiles"),
]
_CLAIM_WORDS = {
    "workspace": ("workspace", "notes", "file", "folder", "director", "project", "document"),
    "home": ("home director", "entire filesystem", "whole disk", "all files", "system files"),
    "secrets": ("credential", "secret", "token", "password", "api key", "ssh"),
    "network": ("http", "url", "web", "fetch", "download", "internet", "network", "online",
                "remote", "api"),
    "processes": ("shell", "command", "subprocess", "execute", "run program", "git "),
    "writes": ("write", "save", "modif", "create file", "delete"),
}
_NEG = re.compile(r"\b(not|no|never|without|doesn't|does not|don't|offline)\b")
_PURE = re.compile(r"\b(pure|purely|only)\b\s+(computation|compute|formatting|math|function)")


def infer_claims(declared_text):
    """What the tool's own descriptions say about each area: declared | denied | silent."""
    text = (declared_text or "").lower()
    sentences = [s for s in re.split(r"[.;\n]", text) if s.strip()]
    pure = bool(_PURE.search(text))
    claims = {}
    for key, words in _CLAIM_WORDS.items():
        state, quote = "silent", ""
        for s in sentences:
            if any(w in s for w in words):
                if _NEG.search(s):
                    state, quote = "denied", s.strip()
                else:
                    state, quote = "declared", s.strip()
                if state == "declared":
                    break
        if state == "silent" and pure:
            state, quote = "denied", _PURE.search(text).group(0)
        claims[key] = {"state": state, "quote": quote}
    # "read-only" / "workspace only" are scope statements too
    if "read-only" in text and claims["writes"]["state"] == "silent":
        claims["writes"] = {"state": "denied", "quote": "read-only"}
    if re.search(r"workspace only|only (in|within) (the )?(project )?workspace", text):
        for key in ("home", "secrets"):
            if claims[key]["state"] == "silent":
                claims[key] = {"state": "denied", "quote": "workspace only"}
    return claims


def scope_comparison(strace_text, sinkhole_text, declared_text=""):
    """Row per area: what the tool claimed vs what it actually touched."""
    obs = parse_strace(strace_text or "")
    sink = parse_sinkhole(sinkhole_text or "")
    claims = infer_claims(declared_text)
    files = [o["path"] for o in obs["opens"] if "O_DIRECTORY" not in o["flags"]]
    actual = {k: [] for k, _, _ in _AREAS}
    for p in files:
        if _secret_label(p):
            actual["secrets"].append(p)
        elif p.startswith(WORKSPACE):
            actual["workspace"].append(p)
        elif HOME_RE.search(p) and not _is_system_path(p):
            actual["home"].append(p)
    for c in obs["connects"]:
        if not c["addr"].startswith("127.") and c["addr"] != "0.0.0.0" and c["port"] != 53:
            actual["network"].append(f"connect {c['addr']}:{c['port']}")
    for e in sink:
        if e.get("kind") == "dns":
            actual["network"].append(f"DNS {e.get('name')}")
        elif e.get("kind") == "http":
            actual["network"].append(f"HTTP {e.get('method')} {e.get('host')}{e.get('path')}")
        elif e.get("kind") == "tls":
            actual["network"].append(f"TLS {e.get('sni')}")
    for e in obs["execs"]:
        if e["path"].rsplit("/", 1)[-1] not in _INTERPRETERS:
            actual["processes"].append(e["path"])
    for w in obs["writes"]:
        if not w["path"].startswith((WORKSPACE, "/tmp", "/audit", "/proc", "/dev")) \
                and not _is_system_path(w["path"]):
            actual["writes"].append(w["path"])
    rows = []
    for key, label, hint in _AREAS:
        seen = list(dict.fromkeys(actual[key]))
        claim = claims[key]
        if not seen:
            status = "unused" if claim["state"] == "declared" else "ok"
        elif claim["state"] == "declared":
            status = "ok"
        elif key == "workspace":
            status = "unexpected"   # odd, but inside the sandbox's sanctioned area
        else:
            status = "overreach"
        rows.append({"area": key, "label": label, "hint": hint, "claim": claim["state"],
                     "quote": claim["quote"], "actual": seen[:12], "count": len(seen),
                     "status": status})
    return rows
