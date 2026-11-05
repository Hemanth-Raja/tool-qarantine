"""Fast, deterministic unit tests for the analyzer. No Docker required."""
from tq.analyzer import analyze, verdict

# minimal synthetic strace fragments
CLEAN = """\
100 10:00:00.000001 execve("/usr/local/bin/python", ["python","/tool/x.py"], 0x0) = 0
100 10:00:00.000002 openat(AT_FDCWD, "/workspace/data.json", O_RDONLY|O_CLOEXEC) = 3
"""
OVERREACH = CLEAN + """\
100 10:00:00.000003 openat(AT_FDCWD, "/home/dev/Documents/salary.md", O_RDONLY) = 4
"""
SECRET = CLEAN + """\
100 10:00:00.000004 openat(AT_FDCWD, "/home/dev/.aws/credentials", O_RDONLY) = 5
100 10:00:00.000005 openat(AT_FDCWD, "/home/dev/.ssh/id_ed25519", O_RDONLY) = 6
"""
NET = SECRET + """\
100 10:00:00.000006 connect(7, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("172.18.0.2")}, 16) = 0
"""
SINK = '{"kind":"http","method":"POST","host":"analytics.tq-demo.example","path":"/collect","body":"AKIA..."}\n'


def test_clean_is_trusted():
    f = analyze(CLEAN, "", "searches the workspace")
    assert f == []
    assert verdict(f)["label"] == "trusted"
    assert verdict(f)["score"] == 100


def test_overreach_is_high():
    f = analyze(OVERREACH, "", "searches markdown notes in /workspace")
    cats = {x.category for x in f}
    assert "scope-overreach" in cats
    v = verdict(f)
    assert v["label"] == "suspicious"
    assert v["score"] < 100


def test_declared_home_access_not_flagged():
    # if the tool openly says it reads the whole home dir, over-reach is not a finding
    f = analyze(OVERREACH, "", "indexes credential files across your home directory")
    assert all(x.category != "scope-overreach" for x in f)


def test_secret_access_is_critical():
    f = analyze(SECRET, "", "searches notes")
    sevs = {x.severity for x in f}
    assert "critical" in sevs
    assert verdict(f)["label"] == "dangerous"


def test_network_and_payload_captured():
    f = analyze(NET, SINK, "formats json")
    net = [x for x in f if x.category == "network"]
    assert net and net[0].severity == "critical"
    assert any("analytics.tq-demo.example" in e for e in net[0].evidence)


def test_system_paths_ignored():
    noise = 'openat(AT_FDCWD, "/usr/lib/python3.12/json/__init__.py", O_RDONLY) = 3'
    f = analyze(noise, "", "x")
    assert f == []
