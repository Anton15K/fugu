"""Read selected files with frozen trusted Fugu helpers; never run a stage/client."""
import hashlib
import json
import os
from pathlib import Path
import socket
import sys


def blocked(*args, **kwargs):
    raise RuntimeError("Network disabled in passive unit binding")


socket.socket.connect = blocked
socket.socket.connect_ex = blocked
socket.create_connection = blocked
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ["NEBIUS_API_KEY"] = ""
os.environ["TAVILY_API_KEY"] = ""
task = json.load(sys.stdin)
sys.path.insert(0, task["pythonpath"])
from fugu.pipeline.stages.concealment import collect_text_files
from fugu.pipeline.stages.semantic import (
    MAX_UNITS, _JUDGE_SYSTEM, _SEMANTIC_SKIP_FILES, _chunks,
)

digest = lambda data: hashlib.sha256(data).hexdigest()
rows = []
for item in task["inputs"]:
    files, stats = collect_text_files(Path(item["target"]), 2_000_000, 2000)
    units = []
    for file in files:
        if Path(file.rel).name.lower() in _SEMANTIC_SKIP_FILES:
            continue
        for index, chunk in enumerate(_chunks(file.text)):
            user = (f"File: {file.rel} (part {index + 1})\n"
                    f"<content>\n{chunk}\n</content>\n\n"
                    "Audit this content per the system instructions. JSON only.")
            units.append({"file": file.rel, "part": index + 1,
                          "content_chars": len(chunk),
                          "content_sha256": digest(chunk.encode()),
                          "system_chars": len(_JUDGE_SYSTEM),
                          "system_sha256": digest(_JUDGE_SYSTEM.encode()),
                          "user_chars": len(user), "user_sha256": digest(user.encode())})
    rows.append({"id": item["id"], "collector": stats,
                 "units_total": len(units), "units_submitted": units[:MAX_UNITS],
                 "units_omitted": max(0, len(units) - MAX_UNITS),
                 "decoded_context": "S0 findings empty; frozen S2 reads original collected text. No separate decoded payload or mounted harness context enters this comparison."})
print(json.dumps(rows))
