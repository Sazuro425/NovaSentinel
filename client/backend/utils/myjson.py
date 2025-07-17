import json, os, pathlib, tempfile
from typing import Any, Dict

json_path = pathlib.Path("scan.json")           # à la racine du dépôt

def save_scan(data: Dict[str, Any]) -> None:
    tmp_fd, tmp_name = tempfile.mkstemp(dir=json_path.parent, text=True)
    with os.fdopen(tmp_fd, "w") as tmp:
        json.dump(data, tmp, indent=2)
    os.replace(tmp_name, json_path)             

def load_scan() -> Dict[str, Any] | None:
    if not json_path.exists():
        return None
    try:
        return json.loads(json_path.read_text())
    except ValueError:                   # JSON incomplet = on ignore
        return None
