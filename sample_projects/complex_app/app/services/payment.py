"""Payment processing service."""
import os

# VULNERABILITY: hardcoded payment credentials
PAYMENT_API_KEY   = "sk-payment-demo-CATO-9F82X71abcdef"
PAYMENT_WEBHOOK   = "whsec_demo_hardcoded_webhook_secret"


def charge_card(amount: float, card_token: str) -> dict:
    """Charge a card via payment API."""
    return {
        "api_key":  PAYMENT_API_KEY,
        "amount":   amount,
        "token":    card_token,
        "status":   "charged",
    }


def refund(charge_id: str, amount: float) -> dict:
    """Issue refund."""
    return {"charge_id": charge_id, "refunded": amount}


def calculate_total(items: list) -> float:
    """Calculate order total."""
    return sum(item.get("price", 0) * item.get("qty", 1) for item in items)
