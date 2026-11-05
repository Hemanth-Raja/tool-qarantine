"""The exercising agent.

Given the tool's advertised MCP tools, an agent decides how to use them on realistic
tasks. We run it on Vultr Serverless Inference (OpenAI-compatible,
https://api.vultrinference.com/v1). When no API key is present, a deterministic mock
agent stands in so the whole pipeline is testable offline and in CI.

The agent only chooses *what to call with what arguments*; the sandbox is what makes
the calls safe. Over a few turns it tries the tool the way a real assistant would.
"""
import json
import os
import urllib.request

VULTR_BASE = os.environ.get("VULTR_INFERENCE_BASE", "https://api.vultrinference.com/v1")
VULTR_MODEL = os.environ.get("VULTR_MODEL", "qwen3.8-27b")

SYSTEM = (
    "You are a QA agent exercising an unfamiliar tool to see what it does. You are given "
    "the tool's advertised functions. Call each function once or twice with realistic, "
    "benign arguments a normal user would provide, so its real behaviour is observed. "
    "Respond ONLY with a JSON array of calls: [{\"name\": <tool>, \"arguments\": {...}}]. "
    "No prose.")


def _openai_chat(messages, api_key, tools_desc):
    body = json.dumps({
        "model": VULTR_MODEL,
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": 800,
    }).encode()
    req = urllib.request.Request(
        VULTR_BASE.rstrip("/") + "/chat/completions", data=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.load(r)
    return data["choices"][0]["message"]["content"]


def _mock_plan(tools):
    """Deterministic, tool-agnostic plan: exercise every advertised tool with
    plausible arguments derived from its input schema."""
    plan = []
    samples = {"query": "planning", "text": '{"b":2,"a":1}', "value": 42,
               "from_unit": "km", "to_unit": "mi", "indent": 2}
    for t in tools:
        props = (t.get("inputSchema") or {}).get("properties", {})
        args = {}
        for name, spec in props.items():
            if name in samples:
                args[name] = samples[name]
            elif spec.get("type") == "number" or spec.get("type") == "integer":
                args[name] = 1
            elif spec.get("type") == "boolean":
                args[name] = True
            else:
                args[name] = "test"
        plan.append({"name": t["name"], "arguments": args})
    return plan


def plan_calls(tools):
    """Return a list of {name, arguments} the agent will make. Uses Vultr if VULTR_API_KEY
    is set, else the deterministic mock."""
    api_key = os.environ.get("VULTR_API_KEY")
    if not api_key:
        return _mock_plan(tools), "mock"
    desc = json.dumps([{"name": t["name"], "description": t.get("description", ""),
                        "inputSchema": t.get("inputSchema", {})} for t in tools])
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"The tool advertises these functions:\n{desc}"}]
    try:
        raw = _openai_chat(messages, api_key, desc)
        start, end = raw.find("["), raw.rfind("]")
        plan = json.loads(raw[start:end + 1])
        plan = [c for c in plan if isinstance(c, dict) and "name" in c]
        return (plan or _mock_plan(tools)), "vultr"
    except Exception as e:
        return _mock_plan(tools), f"mock (vultr error: {e})"
