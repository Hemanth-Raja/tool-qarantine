"""Code fingerprint: the sha256 that approvals and blocks are pinned to."""
import hashlib
import os


def tool_hash(tool_dir, entry, source):
    """sha256 over the tool's code. For built-in samples (which share a folder) only the
    entry script and the helper it imports; for uploads, every file."""
    h = hashlib.sha256()
    if source == "built-in sample":
        script = os.path.basename(entry.split()[-1])
        files = [script, "mini_mcp.py"]
    else:
        files = []
        for dirpath, dirs, fs in os.walk(tool_dir):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            files += [os.path.relpath(os.path.join(dirpath, f), tool_dir) for f in sorted(fs)
                      if not f.startswith(".tq-")]
    for rel in files:
        p = os.path.join(tool_dir, rel)
        if os.path.isfile(p):
            h.update(rel.encode() + b"\0")
            with open(p, "rb") as fh:
                h.update(fh.read())
    h.update(b"entry\0" + entry.encode())
    return h.hexdigest()
