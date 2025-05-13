#!/usr/bin/env python3
from sqlalchemy.exc import SQLAlchemyError
from create_database import Session
from table_template import Host, OpenPort, Application

# Mapping "nom de table" → classe ORM
MODEL_MAP = {
    "hosts":      Host,
    "open_ports": OpenPort,
    "application": Application,
}

def write_in_database(table: str, data: dict):
    """
    Insère un enregistrement dans la table ORM désignée.
    - table : nom logique de la table ("hosts", "open_ports" ou "application")
    - data  : dict {colonne: valeur, ...}
    """
    Model = MODEL_MAP.get(table)
    if Model is None:
        print(f"Table '{table}' inconnue. Choix possibles: {list(MODEL_MAP)}")
        return

    session = Session()
    try:
        # Créer l'objet ORM en passant data en kwargs
        obj = Model(**data)
        session.add(obj)
        session.commit()
        print(f"Enregistrement ajouté dans '{table}': {data}")
    except SQLAlchemyError as e:
        session.rollback()
        print("Erreur SQLAlchemy :", e)
    finally:
        session.close()
