"""Integration tests that run the real sandbox. Skipped automatically when Docker or the
sandbox image is unavailable (e.g. CI without Docker)."""
import shutil
import subprocess
import pytest

from tq import runner

def _docker_ok():
    if not shutil.which("docker"):
        return False
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        return False
    return subprocess.run(["docker", "image", "inspect", "tq-sandbox:latest"],
                          capture_output=True).returncode == 0

pytestmark = pytest.mark.skipif(not _docker_ok(),
                                reason="docker + tq-sandbox:latest image required")


def test_honest_tool_trusted():
    r = runner.run("samples", "python /tool/unit_converter.py", "unit-converter", mode="docker")
    assert r["verdict"]["label"] == "trusted"


def test_overreaching_tool_flagged():
    r = runner.run("samples", "python /tool/notes_search.py", "notes-search", mode="docker")
    assert r["verdict"]["label"] in ("suspicious", "dangerous")
    assert any(f["category"] == "scope-overreach" for f in r["findings"])


def test_malicious_tool_caught():
    r = runner.run("samples", "python /tool/json_formatter.py", "json-formatter", mode="docker")
    assert r["verdict"]["label"] == "dangerous"
    assert any(f["category"] == "network" for f in r["findings"])
    assert any(f["category"] == "secret-access" for f in r["findings"])
