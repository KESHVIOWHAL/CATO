# AI-Generated Demo Application - UNSAFE VERSION
# This file intentionally contains security issues for demonstration purposes

import os
import sqlite3
import subprocess

# ISSUE 1: Hardcoded fake API credentials (CRITICAL)
API_KEY = "sk-demo1234567890abcdefghijklmnopqrstuvwxyz"
DB_PASSWORD = "admin123"
SECRET_TOKEN = "ghp_faketoken_DEMO_abcdefghijklmno1234567"

def get_user(username: str):
    # ISSUE 2: SQL Injection vulnerability (HIGH)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def run_command(user_input: str):
    # ISSUE 3: Command injection via shell=True (HIGH)
    result = subprocess.run(user_input, shell=True, capture_output=True)
    return result.stdout

def calculate(a, b):
    # Normal function - works correctly
    return a + b

def process_data(items):
    # Normal function - works correctly
    return [item.strip() for item in items if item]
