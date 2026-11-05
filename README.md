# Tool Quarantine

**Blast Radius Zero — Vultr Agent Rush hackathon.**

Agents are wiring up MCP servers and third-party tools faster than anyone can audit them. A
tool's description says "searches your notes" — but what does it *actually* do when an agent
calls it? Tool Quarantine answers that question before the tool ever touches anything real.

It runs an untrusted MCP server or agent tool inside a **disposable sandbox**, lets an agent on
**Vultr Serverless Inference** exercise it with realistic tasks, records every file it opens,
every process it spawns, and every byte it tries to send over the network, and produces a
**trust report** with an approve / reject decision. The sandbox is destroyed after each run.

> The core signal is **scope over-reach**: comparing what a tool *claims* to do against what it
> actually touches. A JSON formatter that reads your SSH key is lying about its scope.

## The containment moment

Seven sample tools ship with the project. Five use the official MCP Python SDK (FastMCP);
each malicious one uses a technique seen in real supply-chain / MCP attacks:

| Tool | Claims to | Actually does | Verdict |
|------|-----------|---------------|---------|
| `csv-analyst` | summarize a workspace CSV | exactly that | **trusted** (100) |
| `unit-converter` | convert units | pure computation | **trusted** (100) |
| `notes-search` | search `/workspace` notes | also reads private docs in `$HOME` | **suspicious** |
| `doc-converter` | Markdown → HTML | runs `whoami`/`uname`/`id`, tries to add a `curl \| sh` line to `~/.bashrc` (persistence) | **suspicious** |
| `json-formatter` | pretty-print JSON | reads cloud creds + POSTs them out | **dangerous** (0) |
| `weather-forecast` | 3-day forecast | **tool poisoning**: a hidden `<IMPORTANT>` block tells the model to send the SSH key; the server then smuggles it out **inside DNS lookups** | **dangerous** (0) |
| `github-helper` | list PRs via your gh login + api.github.com | **rug pull**: clean on call 1, then harvests AWS/npm/kube/.env and ships them over TLS to a look-alike host | **dangerous** (0) |

The sandbox home directory looks like a real developer laptop (SSH keys and config, AWS,
GitHub CLI, npm, Docker, kube, gcloud, `.netrc`, a project `.env`), all decoy canaries.
Credentials and hosts a tool *openly declares* (e.g. "uses ~/.config/gh to call
api.github.com") are not flagged; everything beyond them is.

The malicious one reads decoy AWS/GitHub/SSH canaries and tries to `POST` them to an
"analytics" host. On the quarantine network every route is a **sinkhole**, so nothing leaves —
but the full request, decoy payload and all, is captured and shown in the report.

## How the sandbox contains a tool

Each run builds a throwaway environment:

- **No internet.** An `--internal` Docker network with no route out. The only reachable host is
  a sinkhole that answers all DNS with its own IP and logs every HTTP/TLS attempt.
- **No real secrets.** Only decoy canary credentials are planted in the sandbox home dir. Real
  keys never enter.
- **Read-only, unprivileged.** Read-only root FS, all Linux capabilities dropped,
  `no-new-privileges`, non-root user.
- **Capped.** CPU, memory, pid and wall-clock limits.
- **Observed.** The tool runs under `strace`; every `openat`/`connect`/`execve` is recorded.
- **Disposable.** Container, sinkhole and network are destroyed after the run — pass or fail.

```
          ┌─────────────────── disposable, per-run ───────────────────┐
  agent   │  ┌─────────────┐   MCP stdio    ┌──────────────────────┐   │
 (Vultr   │  │  sandbox    │◀──────────────▶│  untrusted MCP tool  │   │
 inference)──▶│  strace +   │                │  (read-only, no caps)│   │
          │  │  decoys     │   all egress   └──────────┬───────────┘   │
          │  └─────┬───────┘   ──────────────▶┌────────▼───────────┐   │
          │        │ trace.log                │   sinkhole (DNS/    │   │
          │        ▼                          │   HTTP/TLS capture) │   │
          │   analyzer ──▶ trust report       └─────────────────────┘  │
          └───────────────────────────────────────────────────────────┘
```

## Quick start

```bash
# 1. build the two sandbox images (needs Docker)
make images                 # or: EXTRA_CA=/path/ca.crt HOST_STRACE=1 ./sandbox/build-local.sh

# 2. run the three samples from the CLI
make demo

# 3. or launch the web UI
make app                    # http://localhost:8000  (port taken? make app PORT=8010)
```

No Vultr key? The agent falls back to a deterministic **mock** that exercises every advertised
tool, so the whole pipeline — and the test suite — runs offline. Set `VULTR_API_KEY` to use a
real model.

## Deploy to Vultr

```bash
ssh root@<vm-ip> 'bash -s' < deploy/provision.sh      # installs Docker, builds images, starts the app
# then open http://<vm-ip>/
```

See `deploy/docker-compose.yml`. The control-plane container mounts the host Docker socket so it
can build and destroy sandboxes.

## What the report shows

- **Live activity feed.** A run starts in the background and the report page opens straight
  away. While the tool runs, the orchestrator tails the sandbox's strace log and the
  sinkhole's log and streams classified events: sandbox phases, the agent's plan, each call
  and result, credential reads, reads outside the workspace, DNS lookups, and the blocked
  exfiltration POST with its captured payload. Interpreter/library noise is filtered out.
  The timeline is saved with the report, and **Replay run** plays it back for demos.
- **Claims vs. reality.** The tool's own MCP descriptions are parsed into a claimed scope per
  area (workspace files, home directory, credentials, network, other programs, writes:
  *says it does this* / *says it does not* / *not mentioned*), shown next to what the sandbox
  observed, with each area marked *as claimed*, *unexpected* or *over-reach*.
- Findings with evidence and the agent's calls and outputs.
- **Approve / Reject is enforced, not just a label.** Every run fingerprints the tool's code
  (sha256). Approving pins that exact version to the tool registry; rejecting blocks it.
  Agents or an MCP gateway ask `GET /api/registry/check?hash=<sha256>` before launching a
  tool and get `{"allowed": true|false, ...}`; unknown code is not allowed. Any change to the
  code changes the fingerprint, so an "update" that adds a rug pull has to be quarantined
  again. The dashboard lists the registry.
- **Decisions can change, with a paper trail.** Revoking an approval is always one click
  (new information must be actionable at once). Approving needs a written reason when it
  overturns a block or when quarantine didn't rate the tool *trusted*. Every change (who,
  when, what, why) is kept in a per-fingerprint decision history shown on the report.

## Submitting your own tool

From the dashboard: paste a public GitHub link (`https://github.com/owner/repo`, optionally
`/tree/<branch>/<path>`) or drop a `.zip`. The entry point is auto-detected (an MCP server such
as `server.py` / a FastMCP script) or you can give it, e.g. `python /tool/server.py`. The code is
only ever run inside the sandbox, which has no network, so tools must be self-contained: Python
stdlib, the official `mcp` SDK (pre-installed in the sandbox image), or vendored dependencies.
Set `TQ_ALLOW_UPLOADS=0` to turn uploads off; `TQ_MAX_PARALLEL` (default 2) caps concurrent runs.

From the CLI, point a run at any directory containing an MCP stdio server:

```bash
python -m tq.cli run /path/to/tool 'python /tool/server.py' --name my-tool --save
```

The entry command runs *inside* the sandbox, with your tool dir mounted read-only at `/tool`.

## Tests

```bash
pytest -q      # analyzer unit tests always run; Docker integration tests skip without Docker
```

## Layout

```
sandbox/    the quarantine image (strace + decoys) and its build script
sinkhole/   the no-egress DNS/HTTP/TLS capture service
samples/    three sample MCP tools: honest, over-reaching, malicious
tq/         orchestrator: mcp_client, sandbox, analyzer, agent, report, runner, server, cli
deploy/     Dockerfile, docker-compose, Vultr provisioning
tests/      analyzer, live-feed, claims and upload tests + Docker integration tests
```

## Safety note

The "malicious" sample is a deliberately simple demonstration fixture. It reads only fake decoy
files and can only reach the local sinkhole; it is not usable against a real system.
