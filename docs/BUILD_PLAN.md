# Tool Quarantine — build plan & demo script

**Hackathon:** Vultr Agent Rush (lablab.ai) · **Track:** Blast Radius Zero
**Deadline:** Sun Nov 9, 2026, 12:00 AM CEST
**Status as of Nov 4 (overnight build):** working end-to-end prototype. Everything below under
"Done" is built and tested in this repo; the rest is the plan to a polished submission.

## What it is (one sentence)

A Vultr-hosted service that runs an untrusted MCP server / agent tool in a disposable sandbox,
has an agent on Vultr Serverless Inference exercise it, records what it actually touches, and
produces a trust report with an approve/reject decision.

## Why it wins the track

- **Containment is real, not a scan.** We execute the tool and watch syscalls + network, rather
  than statically scanning a package.
- **The differentiator is scope over-reach** — observed behaviour vs. declared purpose. That is
  the MCP-specific angle and the thing a static scanner can't see.
- **One clean demo moment:** a "JSON formatter" caught reading cloud creds and trying to POST
  them out, with the exact payload shown — stopped dead by the sinkhole.

## How it differs from "Detonation Chamber" (the other entry)

| | Detonation Chamber | **Tool Quarantine** |
|---|---|---|
| Target | npm/PyPI packages | **MCP servers & agent tools** |
| Method | install + gVisor + honeypot | **execute tool + strace + sinkhole** |
| Core signal | risk score of a package | **scope over-reach: claimed vs. actual** |
| Human loop | report | **approve / reject workflow per tool** |

## Architecture (built)

- `sandbox/` — Docker image: `strace` + decoy canaries, non-root, read-only, caps dropped.
- `sinkhole/` — no-egress service: answers all DNS with itself, logs HTTP body + TLS SNI.
- `tq/sandbox.py` — per-run `--internal` network + sinkhole + capped container; destroyed after.
- `tq/mcp_client.py` — MCP stdio client that drives the tool inside the box.
- `tq/agent.py` — Vultr Serverless Inference agent (OpenAI-compatible) + deterministic mock.
- `tq/analyzer.py` — turns strace + sinkhole logs into findings; scope-overreach is the core rule.
- `tq/report.py` / `store.py` — trust report + JSON persistence.
- `tq/server.py` + `static/` — FastAPI dashboard, report page, approve/reject API.
- `tq/cli.py` — `python -m tq.cli run ...`.
- `samples/` — honest / over-reaching / malicious MCP tools.
- `deploy/` — Dockerfile, docker-compose, Vultr provisioning script.
- `tests/` — analyzer unit tests (offline) + Docker integration tests.

## Done (Nov 4 overnight)

- [x] Sandbox image builds; verified no network, read-only FS, caps dropped, decoys planted.
- [x] Sinkhole captures DNS/HTTP(+body)/TLS-SNI.
- [x] Full run pipeline: agent exercises tool → evidence → findings → verdict.
- [x] Three samples produce trusted(100) / suspicious(70) / dangerous(0); exfil payload captured.
- [x] Web UI (dashboard + trust report + approve/reject) and CLI, both working.
- [x] 9 tests passing. Clean teardown verified (no leaked containers/networks).
- [x] Deployment files + README + this plan.

## Remaining to submit (day-by-day)

**Nov 5 (Hemanth + Claude)** — *needs Hemanth's accounts*
- [ ] Create GitHub repo; push this code (see handoff checklist).
- [ ] Spin up a Vultr VM; run `deploy/provision.sh`; get the **public demo URL** live.
- [ ] Add a real `VULTR_API_KEY`; confirm the live agent (not mock) drives a run end-to-end.

**Nov 6** — *harden + polish*
- [ ] Upload-your-own-tool flow in the UI (zip or git URL), not just the three samples.
- [ ] Live activity stream on the report page (tail strace/sinkhole as the run happens).
- [ ] Per-tool scope declaration (let the submitter state allowed paths/hosts; flag deviations).
- [ ] Tighten analyzer: a couple more syscall rules, dedupe evidence, friendlier copy.

**Nov 7** — *the demo*
- [ ] Record the demo video: run honest tool (green) → malicious tool (red, show the captured
      POST with decoy creds) → reject. This is the one required containment moment.
- [ ] PHI Quarantine angle (optional): a fake patient-records MCP server as a 4th sample, for a
      healthcare framing. Only if time allows.

**Nov 8** — *submit*
- [ ] Finalize README, architecture diagram, screenshots.
- [ ] Submit on lablab.ai: repo link, public URL, video. Buffer day before the Nov 9 deadline.

## Demo script (90 seconds)

1. "Agents install tools faster than anyone can review them. Here's one that says it formats
   JSON." — show `json-formatter` in the dropdown.
2. Click **Quarantine & run.** A disposable sandbox builds, an agent calls the tool, the box is
   destroyed. ~1–2s.
3. Report lands **DANGEROUS**. Scroll to the finding: *read AWS credentials*, *read GitHub
   token*, and **Exfiltration attempt** showing the literal `POST analytics.tq-demo.example`
   with the decoy key in the body.
4. "Nothing actually left — the sandbox network is a sinkhole. We saw exactly what it would have
   done." Click **Reject.**
5. Contrast: run `unit-converter` → **TRUSTED 100**, no findings. "Same pipeline. This one earns
   the trust."

## Open questions for Hemanth

- GitHub repo name/visibility?
- Which Vultr region + VM size? (A small shared-CPU instance is plenty for the demo.)
- Vultr Serverless Inference model: `qwen3.8-27b` (llama-3.3-70b is not on our key).
- Do we want the PHI/healthcare framing in, or keep it general-purpose for the video?
