"""Lay the narration clips on the recorded video at the logged scene times and export an MP4.

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
ids = [i for i in timings if os.path.exists(os.path.join(HERE, i + ".wav"))]
cmd = [ffmpeg, "-y", "-i", video]
for i in ids:
    cmd += ["-i", os.path.join(HERE, i + ".wav")]
parts = []
for n, i in enumerate(ids, start=1):
    d = max(0, int(timings[i]) + LEAD_MS)
    parts.append(f"[{n}:a]aresample=48000,adelay={d}|{d},volume=1.0[a{n}]")
mix = "".join(f"[a{n}]" for n in range(1, len(ids) + 1))
parts.append(f"{mix}amix=inputs={len(ids)}:normalize=0:dropout_transition=0,"
             "loudnorm=I=-16:TP=-1.5:LRA=11,apad[aout]")
cmd += ["-filter_complex", ";".join(parts), "-map", "0:v", "-map", "[aout]",
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "20", "-preset", "medium",
        "-c:a", "aac", "-b:a", "160k", "-shortest", "-movflags", "+faststart", out]
subprocess.run(cmd, check=True)
print("wrote", out)
