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
