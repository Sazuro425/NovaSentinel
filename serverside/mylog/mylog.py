import os
import logging

def get_custom_logger(name: str) -> logging.Logger:
    # 1️⃣ Niveau de log configurable via LEVEL_LOG, par défaut INFO
    lvl_str = os.getenv("LEVEL_LOG", "INFO").upper()
    if hasattr(logging, lvl_str):
        level = getattr(logging, lvl_str)
    else:
        try:
            level = int(lvl_str)
        except ValueError:
            level = logging.INFO

    # Création du logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    # Détermination de la racine du projet
    #    __file__ ≃ .../NovaSentinel/core/log/mylog.py
    project_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), os.pardir, os.pardir)
    )

    # 4réation du dossier 'log' à la racine si nécessaire
    log_dir = os.path.join(project_root, "log")
    os.makedirs(log_dir, exist_ok=True)

    # hemin complet du fichier de log
    log_path = os.path.join(log_dir, f"{name}.log")

    # Ajout du FileHandler si pas déjà présent
    if not any(
        isinstance(h, logging.FileHandler) and os.path.abspath(h.baseFilename) == log_path
        for h in logger.handlers
    ):
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(
            logging.Formatter(
                "%(asctime)s — %(name)s — %(levelname)s — %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
        )
        logger.addHandler(fh)

    return logger