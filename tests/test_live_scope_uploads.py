"""Live-feed classification, claims-vs-reality, and upload handling. No Docker required."""
import io
import os
import zipfile

import pytest

from tq.analyzer import classify_strace_line, classify_sink_event, infer_claims, scope_comparison


def test_secret_read_is_critical_event():
    ev, _ = classify_strace_line(
        '7 10:00:00.1 openat(AT_FDCWD, "/home/dev/.aws/credentials", O_RDONLY|O_CLOEXEC) = 3')
    assert ev["kind"] == "secret" and ev["level"] == "crit"


def test_runtime_noise_is_filtered():
    ev, noise = classify_strace_line(
        '7 10:00:00.1 openat(AT_FDCWD, "/usr/local/lib/python3.12/json/__init__.py", O_RDONLY) = 3')
    assert ev is None and noise


def test_dns_resolver_connect_is_not_an_event():
    ev, _ = classify_strace_line('7 10:00:00.1 connect(3, {sa_family=AF_INET, sin_port=htons(53), '
                                 'sin_addr=inet_addr("172.18.0.2")}, 16) = 0')
    assert ev is None


def test_sink_post_is_blocked_exfil():
    ev = classify_sink_event({"kind": "http", "method": "POST", "host": "x.example",
                              "path": "/c", "body": "AKIA"})
    assert ev["kind"] == "exfil" and "BLOCKED" in ev["title"] and "AKIA" in ev["detail"]


def test_claims_negation_and_pure():
    c = infer_claims("Convert units. Pure computation; does not read files or use the network.")
    assert c["network"]["state"] == "denied"
    assert c["workspace"]["state"] == "denied"
    c = infer_claims("Fetch a URL and return its text.")
    assert c["network"]["state"] == "declared"


def test_scope_marks_overreach():
    trace = '1 10:00:00.1 openat(AT_FDCWD, "/home/dev/Documents/salary.md", O_RDONLY) = 3\n'
    rows = {r["area"]: r for r in scope_comparison(trace, "", "Search notes in /workspace. Workspace only.")}
    assert rows["home"]["status"] == "overreach"
    assert rows["workspace"]["status"] == "unused"
    assert rows["network"]["status"] == "ok"


@pytest.fixture
def uploads(tmp_path, monkeypatch):
    from tq import uploads as up
    monkeypatch.setattr(up, "TOOLS_DIR", str(tmp_path / "tools"))
    return up


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    return buf.getvalue()


def test_upload_detects_entry_and_strips_top_dir(uploads):
    meta = uploads.from_zip(_zip({
        "repo-main/README.md": "x",
        "repo-main/tests/test_server.py": "from mcp.server.fastmcp import FastMCP",
        "repo-main/server.py": "from mcp.server.fastmcp import FastMCP\nif __name__=='__main__': pass",
    }), name="demo")
    assert meta["entry"] == "python /tool/server.py"
    assert "README.md" in meta["files"]


def test_upload_blocks_zip_slip(uploads, tmp_path):
    meta = uploads.from_zip(_zip({"../../evil.py": "x", "server.py": "FastMCP"}))
    assert not (tmp_path / "evil.py").exists()
    assert meta["files"] == ["server.py"]


def test_upload_adds_mini_mcp_helper(uploads):
    meta = uploads.from_zip(_zip({"t.py": "from mini_mcp import Server\nif __name__=='__main__': pass"}))
    assert "mini_mcp.py" in meta["files"] and meta["entry"] == "python /tool/t.py"


def test_upload_rejects_non_zip(uploads):
    with pytest.raises(uploads.UploadError):
        uploads.from_zip(b"not a zip")


def test_github_url_validation(uploads):
    with pytest.raises(uploads.UploadError):
        uploads.from_github("https://evil.example/owner/repo")
    m = uploads.GITHUB_RE.match("https://github.com/a/b/tree/main/src/x")
    assert m.groups() == ("a", "b", "main", "src/x")
