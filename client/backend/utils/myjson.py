from pathlib import Path
from typing import Any, Dict, Optional
import json

def load_scan(path: str | Path) -> Optional[Dict[str, Any]]:
    """
    Charge et retourne le contenu JSON du fichier passé en argument.
    Renvoie None si le chemin est vide, inexistant ou si le JSON est invalide.
    """
    if not path:                       # path == "" ou None
        return None

    p = Path(path)                     # accepte str ou Path
    if not p.exists():
        return None

    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError):
        # Fichier en cours d'écriture ou contenu non valide
        return None
