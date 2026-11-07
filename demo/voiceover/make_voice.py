"""Generate the narration clips for the demo video with the Kokoro neural voice (offline).

  pip install kokoro-onnx soundfile numpy
  # model files (once): github.com/thewh1teagle/kokoro-onnx/releases/tag/model-files-v1.0
  python demo/voiceover/make_voice.py path/to/kokoro-v1.0.onnx path/to/voices-v1.0.bin

Each scene's line is voiced one sentence at a time, so subtitle timings follow the voice; a long
sentence gets several subtitle lines, timed by length. Writes, next to scenes.json:
  <id>.wav        the scene's narration
  durations.json  seconds per scene
  cues.json       {id: [[start_s, end_s, text], ...]} relative to the start of the scene's clip
"""
import json
import os
import re
import sys

import numpy as np
import soundfile as sf
from kokoro_onnx import Kokoro

HERE = os.path.dirname(os.path.abspath(__file__))
VOICE = os.environ.get("TQ_VOICE", "af_heart")
SPEED = float(os.environ.get("TQ_VOICE_SPEED", "1.0"))
PAUSE = 0.18      # seconds of silence between cues
MAX = 84          # longest subtitle line, in characters


def split_long(sent):
    """Split a sentence into subtitle-sized lines, at a comma or before 'and', 'while', ..."""
    parts = [sent]
    while any(len(p) > MAX for p in parts):
        p = max(parts, key=len)
        i = parts.index(p)
        mid = len(p) // 2
        cands = [m.end() for m in re.finditer(r",\s|;\s|\s(?=and |but |while |then |so )", p)]
        if not cands:
            cands = [m.start() for m in re.finditer(r"\s", p)]
        cut = min(cands, key=lambda c: abs(c - mid))
        parts[i:i + 1] = [p[:cut].strip(), p[cut:].strip()]
    return [p for p in parts if p]


def spoken(cue):
    # what the voice says may differ from what is shown: "strace" reads better as "s-trace"
    return cue.replace("strace", "s-trace").replace("SHA-256", "SHA two fifty-six")


k = Kokoro(sys.argv[1], sys.argv[2])
scenes = json.load(open(os.path.join(HERE, "scenes.json")))
durations, cues = {}, {}
for s in scenes:
    pieces, t, sr, rows = [], 0.0, 24000, []
    for sent in re.split(r"(?<=[.!?:])\s+", s["text"].strip()):
        # voice whole sentences (natural intonation); long ones get several subtitle lines,
        # timed in proportion to their length
        audio, sr = k.create(spoken(sent), voice=VOICE, speed=SPEED, lang="en-us")
        dur, lines = len(audio) / sr, split_long(sent)
        total, t1 = sum(len(x) for x in lines), t
        for x in lines:
            d = dur * len(x) / total
            rows.append([round(t1, 3), round(t1 + d, 3), x])
            t1 += d
        pieces += [audio, np.zeros(int(PAUSE * sr), dtype=audio.dtype)]
        t += dur + PAUSE
    audio = np.concatenate(pieces[:-1])
    sf.write(os.path.join(HERE, s["id"] + ".wav"), audio, sr)
    durations[s["id"]] = round(len(audio) / sr, 3)
    cues[s["id"]] = rows
    print(f'{s["id"]:18s} {durations[s["id"]]:6.2f}s  {len(s["text"].split())} words  {len(rows)} cues')
json.dump(durations, open(os.path.join(HERE, "durations.json"), "w"), indent=1)
json.dump(cues, open(os.path.join(HERE, "cues.json"), "w"), indent=1)
print("total", round(sum(durations.values()), 1), "s")
