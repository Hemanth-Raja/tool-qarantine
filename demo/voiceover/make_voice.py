"""Generate the narration clips for the demo video with the Kokoro neural voice (offline).

  pip install kokoro-onnx soundfile
  # model files (once): github.com/thewh1teagle/kokoro-onnx/releases/tag/model-files-v1.0
  python demo/voiceover/make_voice.py path/to/kokoro-v1.0.onnx path/to/voices-v1.0.bin

Writes demo/voiceover/<id>.wav and durations.json next to scenes.json.
"""
import json
import os
import sys

import soundfile as sf
from kokoro_onnx import Kokoro

HERE = os.path.dirname(os.path.abspath(__file__))
VOICE = os.environ.get("TQ_VOICE", "af_heart")
SPEED = float(os.environ.get("TQ_VOICE_SPEED", "1.0"))

k = Kokoro(sys.argv[1], sys.argv[2])
scenes = json.load(open(os.path.join(HERE, "scenes.json")))
durations = {}
for s in scenes:
    audio, sr = k.create(s["text"], voice=VOICE, speed=SPEED, lang="en-us")
    sf.write(os.path.join(HERE, s["id"] + ".wav"), audio, sr)
    durations[s["id"]] = round(len(audio) / sr, 3)
    print(f'{s["id"]:18s} {durations[s["id"]]:6.2f}s  {len(s["text"].split())} words')
json.dump(durations, open(os.path.join(HERE, "durations.json"), "w"), indent=1)
print("total", round(sum(durations.values()), 1), "s")
