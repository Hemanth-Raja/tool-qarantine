"""Workspace policies: auto-block, review-with-reason, approval expiry, registry check."""
import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def data(tmp_path, monkeypatch):
    from tq import store
    monkeypatch.setattr(store, "_DIR", str(tmp_path))
    monkeypatch.setattr(store, "_REG", str(tmp_path / "registry" / "registry.json"))
    return store


EXFIL = [{"severity": "critical", "category": "secret-access", "title": "Read AWS credentials"},
         {"severity": "critical", "category": "network",
          "title": "Exfiltration attempt: sent data to an external host"}]
OVERREACH = [{"severity": "high", "category": "scope-overreach",
              "title": "Read files outside its declared workspace"}]


def _run(store, findings, label, score, h):
    return store.save_run({"tool": "t", "status": "done", "tool_hash": h, "findings": findings,
                           "verdict": {"label": label, "score": score},
                           "started": time.time()})


def test_default_policy_blocks_exfiltration_and_reviews_overreach(data):
    from tq import policy
    ev = policy.evaluate({"findings": EXFIL, "verdict": {"label": "dangerous", "score": 0}})
    assert ev["outcome"] == "blocked"
    assert {h["rule"] for h in ev["hits"]} >= {"exfiltration", "credentials", "low_score"}
    ev = policy.evaluate({"findings": OVERREACH, "verdict": {"label": "suspicious", "score": 70}})
    assert ev["outcome"] == "review" and [h["rule"] for h in ev["hits"]] == ["overreach"]
    assert policy.evaluate({"findings": [], "verdict": {"label": "trusted", "score": 100}})["outcome"] == "clear"


def test_blocking_rule_forbids_approval_until_relaxed(data):
    from tq import policy
    rid = _run(data, EXFIL, "dangerous", 0, "aa" * 32)
    with pytest.raises(data.DecisionError, match="policy"):
        data.set_decision(rid, "approve", "I really want it")
    policy.save({"rules": {"exfiltration": {"action": "review"}, "credentials": {"action": "off"}}})
    data.set_decision(rid, "approve", "vendor confirmed it's a test fixture")
    assert data.registry_entry("aa" * 32)["state"] == "approved"


def test_registry_check_honours_policy_and_expiry(data):
    from tq import policy, server
    c = TestClient(server.app)
    rid = _run(data, OVERREACH, "suspicious", 70, "bb" * 32)
    data.set_decision(rid, "approve", "reviewed the index code")
    assert c.get("/api/registry/check", params={"hash": "bb" * 32}).json()["allowed"] is True
    policy.save({"rules": {"overreach": {"action": "block"}}})          # tightened later
    j = c.get("/api/registry/check", params={"hash": "bb" * 32}).json()
    assert j["allowed"] is False and j["state"] == "blocked_by_policy"
    policy.save({"rules": {"overreach": {"action": "review"}}, "approval_ttl_days": 1})
    reg = data.registry()
    reg["bb" * 32]["at"] = time.time() - 2 * 86400
    import json
    with open(data._REG, "w") as f:
        json.dump(reg, f)
    assert c.get("/api/registry/check", params={"hash": "bb" * 32}).json()["state"] == "expired"


def test_simulate_and_stats_endpoints(data):
    from tq import server
    c = TestClient(server.app)
    _run(data, EXFIL, "dangerous", 0, "cc" * 32)
    _run(data, [], "trusted", 100, "dd" * 32)
    sim = c.post("/api/policies/simulate", json={"rules": {}, "auto_approve": True}).json()
    assert sorted(x["outcome"] for x in sim) == ["approved", "blocked"]
    assert c.get("/api/policies").json()["auto_approve"] is False       # simulate saves nothing
    s = c.get("/api/stats").json()
    assert s["scans"] == 2 and s["by_label"]["dangerous"] == 1 and s["exfil_attempts"] == 1
    assert sum(sum(d[k] for k in ("trusted", "dangerous")) for d in s["trend"]) == 2
    for path in ("/", "/app", "/app/scans", "/app/registry", "/app/policies", "/app/integrations"):
        assert c.get(path).status_code == 200
