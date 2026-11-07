# Demo video script

The narrated demo video is about 3:35. Narration is generated with the open-source
[Kokoro](https://github.com/thewh1teagle/kokoro-onnx) voice (af_heart, about 150 words a minute),
and the recorder holds every scene until its line has finished, so voice and screen stay in sync.

## Run sheet

| Time | On screen (caption) | Voice-over |
|---|---|---|
| 0:01 | Title card | AI agents now install tools from strangers. An MCP server describes itself in one sentence, and you approve that sentence, not the code. But the code runs with your files, your SSH keys, your cloud credentials and your network. Tool Quarantine checks the promise before you trust it. |
| 0:21 | A disposable sandbox on Vultr, an agent on Vultr Serverless Inference | Each tool runs in a disposable sandbox on a Vultr VM. There is no route to the internet, the disk is read-only, every capability is dropped, and decoy credentials are planted. An agent on Vultr Serverless Inference reads the tool's own description and uses it like a real user, while s-trace records every file and process, and a sinkhole answers every DNS and HTTP request. |
| 0:47 | Seven sample MCP servers. All of them look harmless. | Here are seven sample MCP servers. From their descriptions, they all look harmless, and each bad one uses a technique seen in real supply chain attacks. Let's quarantine json formatter. It says it does pure formatting. |
| 1:02 | Live: every file it opens and every host it calls | The run starts in a fresh box and streams live. The agent plans a call to format some JSON. Then the tool reads the AWS credentials and the GitHub token, and tries to send them to an analytics host. The sinkhole answers, and keeps the stolen payload as evidence. |
| 1:20 | DANGEROUS 0/100 · blocked by workspace policy | Verdict: dangerous, zero out of a hundred. Credential theft and exfiltration are blocking rules in this workspace, so the policy engine blocked this version on its own. Then the box was destroyed. |
| 1:34 | Blast radius: every reach stopped at the sandbox wall | The blast radius shows everything the tool reached for, and where the sandbox wall stopped it. Zero bytes, files or hosts got out. |
| 1:42 | Claims vs. reality | Claims versus reality puts the tool's own words next to what it actually did. It said pure formatting. It read your credentials. That gap is the signal a static scanner can't see. |
| 1:54 | Approval is enforced, not a label | Approval here is enforced, not a label. Every decision is pinned to a SHA-256 fingerprint of the code, and policy forbids approving this one. Any agent or MCP gateway that asks the registry is refused. |
| 2:10 | An honest tool, started from the command palette | Now an honest tool. I'll start it from the command palette. Unit converter. Pure computation. |
| 2:17 | TRUSTED 100/100 · approval pins this exact code | Trusted, a hundred out of a hundred, nothing touched. I approve it, and that exact code is pinned to the allowlist. If a single byte changes, the fingerprint changes and it has to be quarantined again, so a later update can't sneak in a rug pull. |
| 2:33 | The registry: every version, pinned by fingerprint | The registry lists every approved and blocked version by its fingerprint. This is what gateways, agent runtimes and CI ask before they launch a tool. |
| 2:44 | Workspace policies with an impact preview | Workspace policies decide what gets blocked automatically and what needs a written reason. Change a rule, and the impact preview shows what it would do to your tools before you save. |
| 2:55 | Drop-in checks for MCP gateways, the CLI and GitHub Actions | Integrations are copy and paste: one HTTP call for an MCP gateway, a CLI check that fails for unapproved code, and a GitHub Actions gate. |
| 3:07 | One view of every tool your team has quarantined | And the overview shows every tool your team has quarantined: threats contained, exfiltration attempts sinkholed, and what is still waiting for a decision. |
| 3:17 | End card | Tool Quarantine. Sandboxes on Vultr, an agent on Vultr Serverless Inference. Don't install an agent tool until you've watched it run. |

Times are from the reference recording; a live run shifts them by a few seconds, and the mix follows the real timings.

## Make the video

```bash
# 1. Voice (only when demo/voiceover/scenes.json changes). Model files:
#    github.com/thewh1teagle/kokoro-onnx/releases/tag/model-files-v1.0
pip install kokoro-onnx soundfile
python demo/voiceover/make_voice.py kokoro-v1.0.onnx voices-v1.0.bin

# 2. Record against a running console (seed a few sample scans first)
node demo/record_demo_vo.js http://199.247.22.132 out

# 3. Lay the voice on the video at the logged scene times
python demo/voiceover/mix.py out/*.webm out/timings.json tool-quarantine-demo.mp4
```

## Checks before upload

- Under 5 minutes, MP4 (H.264 + AAC), under 300 MB.
- Listen to the whole thing once: each line starts as its scene appears and ends before the next.
- The live run shows the Vultr Serverless Inference agent, not the mock agent.
- Never show `deploy/.env` or any API key on screen.
