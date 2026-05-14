import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.environ.get("DB_PATH", "vulnradar.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            email TEXT,
            ntfy_channel TEXT,
            alert_on_cve INTEGER DEFAULT 1,
            alert_on_score INTEGER DEFAULT 1,
            last_score INTEGER DEFAULT 0,
            last_cves TEXT DEFAULT '[]',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_checked TEXT
        )
    """)
    conn.commit()
    conn.close()

def add_subscription(domain, email=None, ntfy_channel=None, alert_on_cve=True, alert_on_score=True):
    conn = get_conn()
    existing = conn.execute(
        "SELECT * FROM subscriptions WHERE domain = ? AND (email = ? OR ntfy_channel = ?)",
        (domain, email, ntfy_channel)
    ).fetchone()
    if existing:
        conn.close()
        return {"status": "exists", "id": existing["id"]}
    cursor = conn.execute(
        "INSERT INTO subscriptions (domain, email, ntfy_channel, alert_on_cve, alert_on_score) VALUES (?, ?, ?, ?, ?)",
        (domain, email, ntfy_channel, int(alert_on_cve), int(alert_on_score))
    )
    conn.commit()
    sub_id = cursor.lastrowid
    conn.close()
    return {"status": "created", "id": sub_id}

def get_all_subscriptions():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM subscriptions").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def update_subscription_state(sub_id, score, cves):
    conn = get_conn()
    conn.execute(
        "UPDATE subscriptions SET last_score = ?, last_cves = ?, last_checked = ? WHERE id = ?",
        (score, json.dumps([c.get("id") for c in cves]), datetime.utcnow().isoformat(), sub_id)
    )
    conn.commit()
    conn.close()

def delete_subscription(domain, email):
    conn = get_conn()
    cursor = conn.execute(
        "DELETE FROM subscriptions WHERE domain = ? AND email = ?", (domain, email)
    )
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted
