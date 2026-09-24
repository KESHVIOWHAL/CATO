"""User model."""
from dataclasses import dataclass
from typing import Optional


@dataclass
class User:
    id: int
    username: str
    email: str
    role: str = "viewer"
    active: bool = True

    def is_admin(self) -> bool:
        return self.role == "admin"

    def to_dict(self) -> dict:
        return {
            "id":       self.id,
            "username": self.username,
            "email":    self.email,
            "role":     self.role,
        }


@dataclass
class Order:
    id: str
    user_id: int
    total: float
    status: str = "pending"

    def is_paid(self) -> bool:
        return self.status == "paid"
