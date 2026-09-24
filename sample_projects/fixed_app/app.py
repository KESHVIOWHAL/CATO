# AI-Generated Demo Application - FIXED VERSION
# Security issues have been remediated

import os
import sqlite3
import subprocess

# FIX 1: Credentials loaded from environment variables, not hardcoded
API_KEY = os.environ.get("API_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
SECRET_TOKEN = os.environ.get("SECRET_TOKEN")

def get_user(username: str):
    # FIX 2: Parameterized query prevents SQL injection
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()

def run_command(user_input: str):
    # FIX 3: shell=False with argument list prevents command injection
    allowed_commands = ["ls", "pwd", "whoami"]
    if user_input not in allowed_commands:
        raise ValueError(f"Command not allowed: {user_input}")
    result = subprocess.run([user_input], shell=False, capture_output=True)
    return result.stdout

def calculate(a, b):
    return a + b

def process_data(items):
    return [item.strip() for item in items if item]
