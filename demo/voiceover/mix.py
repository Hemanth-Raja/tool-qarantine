"""Lay the narration clips on the recorded video at the logged scene times, add the subtitle
track, and export an MP4 (H.264 + AAC + mov_text subtitles) plus a matching .srt.

  python demo/voiceover/mix.py <video.webm> <timings.json> <out.mp4> [ffmpeg-binary]
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
video, timings_path, out = sys.argv[1:4]
ffmpeg = sys.argv[4] if len(sys.argv) > 4 else "ffmpeg"
LEAD_MS = 250   # the clip starts just after the scene appears

timings = json.load(open(timings_path))
cues = json.load(open(os.path.join(HERE, "cues.json")))
ids = [i for i in timings if os.path.exists(os.path.join(HERE, i + ".wav"))]


def stamp(sec):
    ms = int(round(sec * 1000))
    return f"{ms // 3600000:02d}:{ms // 60000 % 60:02d}:{ms // 1000 % 60:02d},{ms % 1000:03d}"


# Subtitles: each cue is relative to its scene's clip, which starts at timings[id] + LEAD_MS.
srt_path = os.path.splitext(out)[0] + ".srt"
rows = []
for i in ids:
    base = (timings[i] + LEAD_MS) / 1000
    for a, b, text in cues.get(i, []):
        rows.append((base + a, base + b + 0.15, text))
with open(srt_path, "w", encoding="utf-8") as f:
    for n, (a, b, text) in enumerate(rows, start=1):
        if n < len(rows):
            b = min(b, rows[n][0] - 0.02)   # never overlap the next cue
        f.write(f"{n}\n{stamp(a)} --> {stamp(b)}\n{text}\n\n")

# Video length, for the fade-out at the end.
probe = subprocess.run([ffmpeg, "-i", video], capture_output=True, text=True).stderr
dur = 0.0
for line in probe.splitlines():
    if "Duration:" in line and "N/A" not in line:
        h, m, s = line.split("Duration:")[1].split(",")[0].strip().split(":")
        dur = int(h) * 3600 + int(m) * 60 + float(s)
if not dur:   # webm from a browser recording may not carry a duration: decode to find it
    probe = subprocess.run([ffmpeg, "-i", video, "-f", "null", "-"], capture_output=True, text=True).stderr
    t = [x for x in probe.replace("\r", "\n").splitlines() if "time=" in x][-1]
    h, m, s = t.split("time=")[1].split()[0].split(":")
    dur = int(h) * 3600 + int(m) * 60 + float(s)

cmd = [ffmpeg, "-y", "-i", video]
for i in ids:
    cmd += ["-i", os.path.join(HERE, i + ".wav")]
cmd += ["-i", srt_path]
parts = []
for n, i in enumerate(ids, start=1):
    d = max(0, int(timings[i]) + LEAD_MS)
    parts.append(f"[{n}:a]aresample=48000,adelay={d}|{d}[a{n}]")
mix = "".join(f"[a{n}]" for n in range(1, len(ids) + 1))
parts.append(f"{mix}amix=inputs={len(ids)}:normalize=0:dropout_transition=0,"
             f"loudnorm=I=-16:TP=-1.5:LRA=11,apad,afade=t=out:st={max(0, dur - 1.2):.2f}:d=1.2[aout]")
parts.append(f"[0:v]fade=t=in:st=0:d=0.6,fade=t=out:st={max(0, dur - 1.2):.2f}:d=1.2[vout]")
sub = len(ids) + 1
cmd += ["-filter_complex", ";".join(parts), "-map", "[vout]", "-map", "[aout]", "-map", f"{sub}:s",
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "19", "-preset", "medium",
        "-c:a", "aac", "-b:a", "160k", "-c:s", "mov_text",
        "-metadata:s:s:0", "language=eng", "-metadata:s:s:0", "title=English",
        "-disposition:s:0", "default", "-t", f"{dur:.2f}", "-movflags", "+faststart", out]
subprocess.run(cmd, check=True)
print("wrote", out, "and", srt_path)
