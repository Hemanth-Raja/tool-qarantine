"""Bring-your-own-tool: accept a zip upload or a public GitHub repo link, unpack it safely
into the data dir, and work out how to launch it.

Uploaded code is never executed here. It is only ever run inside the quarantine sandbox,
mounted read-only at /tool. The sandbox has no network, so a tool must be self-contained:
Python stdlib, the official `mcp` SDK (pre-installed in the sandbox image), or vendored deps.
"""
import io
import json
import os
import re
import shutil
import time
import urllib.request
import uuid
import zipfile

from .store import DATA_DIR

TOOLS_DIR = os.path.join(DATA_DIR, "tools")
MAX_ZIP = 10 * 1024 * 1024        # compressed
MAX_UNPACKED = 40 * 1024 * 1024   # total uncompressed
MAX_FILES = 3000
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache", ".tox"}
GITHUB_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?"
    r"(?:/tree/([^/]+)(?:/(.*))?)?/?$")
_MCP_HINTS = ("FastMCP", "mcp.server", "@mcp.tool", "tools/list", "mini_mcp", "list_tools",
              "stdio_server")


class UploadError(ValueError):
    pass


def _meta_path(tid):
    return os.path.join(TOOLS_DIR, tid, ".tq-meta.json")


def tool_dir(tid):
    if not re.fullmatch(r"[a-f0-9]{12}", tid or ""):
        raise UploadError("bad tool id")
    d = os.path.join(TOOLS_DIR, tid, "src")
    if not os.path.isdir(d):
        raise UploadError("no such uploaded tool")
    return d


def get_meta(tid):
    try:
        with open(_meta_path(tid)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def list_tools():
    if not os.path.isdir(TOOLS_DIR):
        return []
    out = [m for m in (get_meta(t) for t in os.listdir(TOOLS_DIR)) if m]
    out.sort(key=lambda m: m.get("created", 0), reverse=True)
    return out


def _extract(data, dest, subdir=None):
    if len(data) > MAX_ZIP:
        raise UploadError(f"zip is larger than {MAX_ZIP // (1024 * 1024)} MB")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise UploadError("that is not a valid zip file")
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if len(infos) > MAX_FILES:
        raise UploadError(f"more than {MAX_FILES} files")
    if sum(i.file_size for i in infos) > MAX_UNPACKED:
        raise UploadError("unpacked size is too large")
    names = [i.filename for i in infos]
    # strip a single top-level folder (GitHub zipballs, "zip the folder" uploads)
    prefix = ""
    tops = {n.split("/", 1)[0] for n in names}
    if len(tops) == 1 and all("/" in n for n in names):
        prefix = tops.pop() + "/"
    if subdir:
        prefix += subdir.strip("/") + "/"
    os.makedirs(dest, exist_ok=True)
    root = os.path.realpath(dest)
    count = 0
    for info in infos:
        name = info.filename
        if not name.startswith(prefix):
            continue
        rel = name[len(prefix):]
        parts = [p for p in rel.split("/") if p]
        if not parts or any(p in SKIP_DIRS for p in parts) or any(p == ".." for p in parts):
            continue
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            continue  # symlink: never follow
        target = os.path.realpath(os.path.join(root, *parts))
        if not target.startswith(root + os.sep):
            continue  # zip-slip
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as out:
            shutil.copyfileobj(src, out)
        os.chmod(target, 0o644)
        count += 1
    if not count:
        raise UploadError("no files found" + (f" under {subdir}" if subdir else ""))
    for dirpath, dirs, _ in os.walk(root):
        for d in dirs:
            os.chmod(os.path.join(dirpath, d), 0o755)
    os.chmod(root, 0o755)
    return count


def detect_entry(src):
    """Find the most likely MCP server entry point. Returns e.g. 'python /tool/server.py'."""
    candidates = []
    for dirpath, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        depth = os.path.relpath(dirpath, src).count(os.sep) + (0 if dirpath == src else 1)
        if depth > 3:
            continue
        for fn in files:
            if not fn.endswith(".py"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, fn), src)
            try:
                text = open(os.path.join(dirpath, fn), errors="replace").read(200_000)
            except OSError:
                continue
            score = 0
            score += 5 * sum(h in text for h in _MCP_HINTS)
            score += 4 if "__main__" in text else 0
            score += {"server.py": 6, "main.py": 4, "mcp_server.py": 6, "__main__.py": 3,
                      "app.py": 2}.get(fn, 0)
            score -= depth * 2
            score -= 6 if fn.startswith("test") or "/tests/" in "/" + rel else 0
            score -= 8 if fn == "mini_mcp.py" else 0
            if score > 0:
                candidates.append((score, rel))
    if not candidates:
        return None
    candidates.sort(key=lambda c: (-c[0], c[1]))
    return "python /tool/" + candidates[0][1].replace(os.sep, "/")


def _describe(src):
    files = []
    for dirpath, dirs, fs in os.walk(src):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in fs:
            files.append(os.path.relpath(os.path.join(dirpath, f), src))
    return sorted(files)


def _finalise(tid, src, name, source, entry):
    # tools written against our tiny helper can run without it being included
    if not os.path.exists(os.path.join(src, "mini_mcp.py")):
        for dirpath, _, fs in os.walk(src):
            if any("from mini_mcp import" in open(os.path.join(dirpath, f), errors="replace").read()
                   for f in fs if f.endswith(".py")):
                here = os.path.join(os.path.dirname(__file__), "..", "samples", "mini_mcp.py")
                shutil.copy(here, os.path.join(dirpath, "mini_mcp.py"))
                os.chmod(os.path.join(dirpath, "mini_mcp.py"), 0o644)
                break
    entry = (entry or "").strip() or detect_entry(src)
    if not entry:
        raise UploadError("couldn't find a Python MCP server in it; give the entry command, "
                          "e.g. python /tool/server.py")
    files = _describe(src)
    meta = {"id": tid, "name": name, "source": source, "entry": entry,
            "files": files[:200], "file_count": len(files), "created": time.time()}
    with open(_meta_path(tid), "w") as f:
        json.dump(meta, f, indent=2)
    return meta


def _new_slot():
    tid = uuid.uuid4().hex[:12]
    src = os.path.join(TOOLS_DIR, tid, "src")
    os.makedirs(src)
    return tid, src


def from_zip(data, name="", entry=""):
    tid, src = _new_slot()
    try:
        _extract(data, src)
        return _finalise(tid, src, (name or "uploaded-tool")[:60], "zip upload", entry)
    except Exception:
        shutil.rmtree(os.path.join(TOOLS_DIR, tid), ignore_errors=True)
        raise


def from_github(url, name="", entry=""):
    m = GITHUB_RE.match((url or "").strip())
    if not m:
        raise UploadError("use a public GitHub link like https://github.com/owner/repo "
                          "(optionally /tree/branch/path)")
    owner, repo, ref, subdir = m.groups()
    api = f"https://api.github.com/repos/{owner}/{repo}/zipball" + (f"/{ref}" if ref else "")
    req = urllib.request.Request(api, headers={"User-Agent": "tool-quarantine",
                                               "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read(MAX_ZIP + 1)
    except urllib.error.HTTPError as e:
        raise UploadError(f"GitHub said {e.code}: is the repo public and the branch right?")
    except Exception as e:
        raise UploadError(f"couldn't download from GitHub: {e}")
    tid, src = _new_slot()
    try:
        _extract(data, src, subdir)
        label = f"{owner}/{repo}" + (f"/{subdir}" if subdir else "")
        return _finalise(tid, src, (name or (subdir or "").strip("/").rsplit("/", 1)[-1] or repo)[:60], f"github.com/{label}", entry)
    except Exception:
        shutil.rmtree(os.path.join(TOOLS_DIR, tid), ignore_errors=True)
        raise
