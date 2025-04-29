import os
import pymysql.cursors
from create_database import db_connect

def write_in_database(database: str, table: str, data: dict):
    """
    Insère un enregistrement dans `database`.`table` à partir d'un dict `data`.
    - database : nom de la base (ex : "inventory")
    - table    : nom de la table (ex : "hosts")
    - data     : dict {colonne: valeur, ...}
    """
    # 1) Connexion
    conn = db_connect(database)
    if conn is None:
        print("Error: impossible de se connecter à la base")
        return

    try:
        with conn.cursor() as cursor:
            # 2) Construction dynamique des colonnes et placeholders
            cols = ", ".join(f"`{col}`" for col in data.keys())
            placeholders = ", ".join("%s" for _ in data)
            values = tuple(data.values())

            # 3) Requête INSERT
            sql = (
                f"INSERT INTO `{table}` ({cols}) "
                f"VALUES ({placeholders})"
            )
            cursor.execute(sql, values)

        # 4) Valider la transaction
        conn.commit()
        print(f"✅ Enregistrement inséré dans {table}")

    except pymysql.MySQLError as e:
        print("MySQL Error:", e)

    finally:
        conn.close()
