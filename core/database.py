import sqlite3
import json
import os
from pathlib import Path

def init_db():
    """Инициализация базы данных угроз"""
    db_path = Path("data/threats.db")
    if db_path.exists():
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''CREATE TABLE threats
                     (id INTEGER PRIMARY KEY,
                      code TEXT UNIQUE,
                      description TEXT,
                      category TEXT,
                      level TEXT,
                      solution TEXT)''')
    
    with open("data/threats_db.json", "r", encoding="utf-8") as f:
        threats = json.load(f)
        for threat in threats:
            cursor.execute(
                "INSERT INTO threats VALUES (NULL,?,?,?,?,?)",
                (threat['code'], threat['description'], threat['category'],
                 threat['level'], threat['solution'])
            )
    
    conn.commit()
    conn.close()