#!/usr/bin/env python3
from script.core.database.creation.create_database import createdb
from script.core.database.creation.table           import createtable

if __name__ == "__main__":
    Base, engine = createdb()
    createtable(Base, engine)
