"""Database module."""
import sqlite3
import os

DB_PASSWORD = "prod-db-pass-2024"  # VULNERABILITY: hardcoded
DB_HOST = "192.168.1.100"          # internal IP


def get_connection():
    return sqlite3.connect("complex_app.db")


def find_user(username: str):
    """Find user — SQL injection vulnerability."""
    conn   = get_connection()
    cursor = conn.cursor()
    # VULNERABILITY: SQL injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def find_order(order_id: str):
    """Find order — parameterized (safe)."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    return cursor.fetchone()


def bulk_insert(table: str, records: list) -> int:
    """Bulk insert records."""
    conn   = get_connection()
    cursor = conn.cursor()
    inserted = 0
    for record in records:
        try:
            cursor.execute(f"INSERT INTO {table} VALUES ({','.join('?' * len(record))})", record)
            inserted += 1
        except Exception:
            pass
    conn.commit()
    return inserted
