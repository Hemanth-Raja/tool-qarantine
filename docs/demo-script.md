# Demo video script

The narrated demo video is about 3:40, by Team Spartans. It opens with a hook (the tool's promise, then what it really does), then the team card. Narration is generated with the open-source
[Kokoro](https://github.com/thewh1teagle/kokoro-onnx) voice (af_heart, about 150 words a minute),
and the recorder holds every scene until its line has finished, so voice and screen stay in sync. The MP4 carries an English subtitle track, and mix.py writes the same subtitles as an .srt for YouTube.

## Run sheet

| Time | On screen | Voice-over |
|---|---|---|
| 0:01 | Hook card: json-formatter and its one-line promise | This tool promises one thing. It formats JSON. |
| 0:06 | The real run replays: AWS keys and GitHub token read, exfiltration attempt | Now watch what it does the moment an agent calls it. It opens your AWS keys. Then your GitHub token. And it tries to ship them to a server it never mentioned. |
| 0:16 | Team Spartans presents Tool Quarantine (team, members, Vultr, track) | Most agents would have installed it without a second look. We're Team Spartans, and this is Tool Quarantine. |
| 0:23 | The problem | AI agents now install tools from strangers. You approve a one-line description, not the code. Yet that code runs with your files, your SSH keys, your cloud credentials and your network. We check the promise before you trust it. |
| 0:38 | How it works: a sealed box on Vultr | Each tool runs in a disposable sandbox on a Vultr VM. There is no route to the internet, the disk is read-only, every capability is dropped, and decoy credentials are planted. An agent on Vultr Serverless Inference reads the tool's own description and uses it like a real user, while strace records every file and process, and a sinkhole answers every DNS and HTTP request. |
| 1:04 | Seven sample MCP servers. All of them look harmless. | Here are seven sample MCP servers. From their descriptions, they all look harmless, and each bad one uses a technique seen in real supply chain attacks. Let's quarantine json formatter. It says it does pure formatting. |
| 1:18 | Live: every file it opens and every host it calls | The run starts in a fresh box and streams live. The agent plans a call to format some JSON. Then the tool reads the AWS credentials and the GitHub token, and tries to send them to an analytics host. The sinkhole answers, and keeps the stolen payload as evidence. |
| 1:35 | DANGEROUS 0/100 · blocked by workspace policy | Verdict: dangerous, zero out of a hundred. Credential theft and exfiltration are blocking rules in this workspace, so the policy engine blocked this version on its own. Then the box was destroyed. |
| 1:48 | Blast radius: every reach stopped at the sandbox wall | The blast radius shows everything the tool reached for, and where the sandbox wall stopped it. Zero bytes, files or hosts got out. |
| 1:56 | Claims vs. reality | Claims versus reality puts the tool's own words next to what it actually did. It said pure formatting. It read your credentials. That gap is the signal a static scanner can't see. |
| 2:08 | Approval is enforced, not a label | Approval here is enforced, not a label. Every decision is pinned to a SHA-256 fingerprint of the code, and policy forbids approving this one. Any agent or MCP gateway that asks the registry is refused. |
| 2:23 | An honest tool, started from the command palette | Now an honest tool. I'll start it from the command palette. Unit converter. Pure computation. |
| 2:30 | TRUSTED 100/100 · approval pins this exact code | Trusted, a hundred out of a hundred, nothing touched. I approve it, and that exact code is pinned to the allowlist. If a single byte changes, the fingerprint changes and it has to be quarantined again, so a later update can't sneak in a rug pull. |
| 2:45 | The registry: every version, pinned by fingerprint | The registry lists every approved and blocked version by its fingerprint. This is what gateways, agent runtimes and CI ask before they launch a tool. |
| 2:56 | Workspace policies with an impact preview | Workspace policies decide what gets blocked automatically and what needs a written reason. Change a rule, and the impact preview shows what it would do to your tools before you save. |
| 3:07 | Drop-in checks for MCP gateways, the CLI and GitHub Actions | Integrations are copy and paste: one HTTP call for an MCP gateway, a CLI check that fails for unapproved code, and a GitHub Actions gate. |
| 3:18 | One view of every tool your team has quarantined | And the overview shows every tool your team has quarantined: threats contained, exfiltration attempts sinkholed, and what is still waiting for a decision. |
| 3:27 | End card: tagline, live demo, code, Team Spartans | Tool Quarantine, by Team Spartans. Sandboxes on Vultr, an agent on Vultr Serverless Inference. Don't install an agent tool until you've watched it run. |

Times are from the reference recording; a live run shifts them by a few seconds, and the mix follows the real timings.

## Make the video

```bash
# 1. Voice (only when demo/voiceover/scenes.json changes). Model files:
#    github.com/thewh1teagle/kokoro-onnx/releases/tag/model-files-v1.0
pip install kokoro-onnx soundfile numpy
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
