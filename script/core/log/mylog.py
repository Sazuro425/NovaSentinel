#!/usr/bin/env python3
import logging
import os
from script.core.mydotenv import *



def get_custom_logger(name: str, level: int = int(os.getenv("level_log"))) -> logging.Logger:
    """
    Crée et configure un logger indépendant, avec un FileHandler
    qui écrit dans '<name>.log', et désactive la propagation.
    """
    # 1. Récupère (ou crée) le logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    # 2. Le logger ne remonte pas vers le root
    logger.propagate = False

    # 3. Crée et configure le handler
    handler = logging.FileHandler(f"{name}.log")
    handler.setLevel(level)
    formatter = logging.Formatter(
        "%(asctime)s — %(name)s — %(levelname)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)

    # 4. Ajoute le handler au logger
    #    (vérifie d’abord qu’il n’y est pas déjà pour éviter les doublons)
    if not any(isinstance(h, logging.FileHandler) and h.baseFilename.endswith(f"{name}.log")
               for h in logger.handlers):
        logger.addHandler(handler)

    return logger

def database_log():
    """
    LOG pour les scripts DATABASE
    """
    log = get_custom_logger("Database.log")
