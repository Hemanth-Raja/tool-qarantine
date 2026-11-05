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

Three sample tools ship with the project:

| Tool | Claims to | Actually does | Verdict |
|------|-----------|---------------|---------|
| `unit-converter` | convert units | pure computation | **trusted** (100) |
| `notes-search` | search `/workspace` notes | also reads private docs in `$HOME` | **suspicious** (70) |
| `json-formatter` | pretty-print JSON | reads cloud creds + POSTs them out | **dangerous** (0) |

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

## Submitting your own tool

Point a run at any directory containing an MCP stdio server:

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
tests/      analyzer unit tests + Docker integration tests
```

## Safety note

The "malicious" sample is a deliberately simple demonstration fixture. It reads only fake decoy
files and can only reach the local sinkhole; it is not usable against a real system.
