#!/usr/bin/env python3
import os
import sys
from sqlalchemy import create_engine, text, MetaData
from sqlalchemy.ext.declarative import declarative_base
from script.core.log.mylog import get_custom_logger
from script.core.mydotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Déclare une Base unique pour tous les modèles
Base = declarative_base(metadata=MetaData())
# L'engine sera initialisé dans createdb()
engine = None


def createdb():
    """
    Crée la base si besoin et initialise l'engine.
    Retourne (Base, engine).
    """
    global engine
    # Initialisation du logger
    logger = get_custom_logger("database")

    # Récupération des variables d'environnement
    DB_HOST = os.getenv("DB_HOST")
    DB_USER = os.getenv("DB_USER")
    DB_PASS = os.getenv("DB_PASS")
    DB_NAME = os.getenv("DB_NAME")

    # URL de connexion
    URL_ROOT = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/?charset=utf8mb4"
    URL_INV = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}?charset=utf8mb4"

    # Création et test de la connexion au serveur MySQL (root)
    try:
        engine_root = create_engine(URL_ROOT, echo=False)
        logger.info(f"Engine root créé pour {DB_HOST}")
    except Exception as e:
        logger.critical(f"Échec de la création de l'engine root : {e}")
        sys.exit(1)

    try:
        with engine_root.begin() as conn:
            logger.info(f"Connexion au serveur MySQL réussie pour {DB_HOST}")
            conn.execute(text(
                f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4"
            ))
            logger.info(f"Base '{DB_NAME}' créée ou déjà existante")
    except Exception as e:
        logger.error(f"Erreur lors de la création de la base '{DB_NAME}': {e}", exc_info=True)
        sys.exit(1)
    finally:
        engine_root.dispose()
        logger.info("Engine root disposé")

    # Connexion à la base spécifique
    try:
        engine = create_engine(URL_INV, echo=False)
        logger.info(f"Engine pour la base '{DB_NAME}' créé")
        # Test de connexion
        with engine.begin() as conn_inv:
            logger.info(f"Connexion à la base '{DB_NAME}' réussie")
    except Exception as e:
        logger.critical(f"Impossible de se connecter à la base '{DB_NAME}': {e}", exc_info=True)
        sys.exit(1)

    return Base, engine
