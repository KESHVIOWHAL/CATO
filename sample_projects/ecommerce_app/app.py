# E-Commerce Application — intentionally vulnerable for CATO demo
import subprocess
import sqlite3

# VULNERABILITY: Hardcoded payment API credentials
PAYMENT_API_KEY = "sk-payment-live-9F82X71abcdefghijk"
STRIPE_SECRET   = "sk_live_demo_51NqXXXXXXXXXXXXXX"
DB_PASSWORD     = "ecommerce_prod_2024"

def get_product(product_id: str):
    """Fetch product by ID — SQL injection vulnerability."""
    conn   = sqlite3.connect("ecommerce.db")
    cursor = conn.cursor()
    # VULNERABILITY: SQL injection via string concatenation
    query  = "SELECT * FROM products WHERE id = '" + product_id + "'"
    cursor.execute(query)
    return cursor.fetchone()

def get_order(order_id: str):
    """Fetch order — another SQL injection."""
    conn   = sqlite3.connect("ecommerce.db")
    cursor = conn.cursor()
    query  = "SELECT * FROM orders WHERE order_id = '" + order_id + "'"
    cursor.execute(query)
    return cursor.fetchall()

def process_payment(card_data: dict):
    """Process payment — sends to payment gateway."""
    import urllib.request, json
    headers = {"Authorization": f"Bearer {PAYMENT_API_KEY}"}
    return {"status": "charged", "amount": card_data.get("amount")}

def run_report(report_type: str):
    """Generate report — command injection vulnerability."""
    # VULNERABILITY: shell=True with user input
    result = subprocess.run(
        f"python reports/{report_type}_report.py",
        shell=True, capture_output=True
    )
    return result.stdout.decode()

def calculate_discount(price: float, pct: float) -> float:
    return price * (1 - pct / 100)

def format_currency(amount: float) -> str:
    return f"₹{amount:.2f}"
