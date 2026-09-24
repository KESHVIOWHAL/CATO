"""
Simple in-memory blockchain registry — DEMO MODE.

Each block contains:
  - index
  - timestamp
  - certificate_hash
  - certificate_id
  - previous_hash
  - block_hash  (SHA-256 of the above)

A real implementation would use web3.py + a local Hardhat/Ganache node.
For the prototype this gives us a verifiable chain without external deps.
"""

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Optional, Dict, List


class Block:
    def __init__(self, index: int, timestamp: str, cert_hash: str,
                 cert_id: str, previous_hash: str):
        self.index = index
        self.timestamp = timestamp
        self.certificate_hash = cert_hash
        self.certificate_id = cert_id
        self.previous_hash = previous_hash
        self.block_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        data = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "certificate_hash": self.certificate_hash,
            "certificate_id": self.certificate_id,
            "previous_hash": self.previous_hash,
        }, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "certificate_hash": self.certificate_hash,
            "certificate_id": self.certificate_id,
            "previous_hash": self.previous_hash,
            "block_hash": self.block_hash,
        }


class BlockchainRegistry:
    def __init__(self):
        self.chain: List[Block] = []
        self._create_genesis()
        # cert_hash → block_hash mapping for quick lookup
        self._index: Dict[str, Block] = {}

    def _create_genesis(self):
        genesis = Block(
            index=0,
            timestamp=datetime.now(timezone.utc).isoformat(),
            cert_hash="0" * 64,
            cert_id="GENESIS",
            previous_hash="0" * 64,
        )
        self.chain.append(genesis)

    def register(self, cert_hash: str, cert_id: str) -> dict:
        previous = self.chain[-1]
        block = Block(
            index=len(self.chain),
            timestamp=datetime.now(timezone.utc).isoformat(),
            cert_hash=cert_hash,
            cert_id=cert_id,
            previous_hash=previous.block_hash,
        )
        self.chain.append(block)
        self._index[cert_hash] = block
        return {
            "tx_hash": block.block_hash,
            "block_index": block.index,
            "status": "RECORDED",
        }

    def verify(self, cert_hash: str) -> dict:
        block = self._index.get(cert_hash)
        if block:
            return {
                "verified": True,
                "block_index": block.index,
                "timestamp": block.timestamp,
                "certificate_id": block.certificate_id,
                "tx_hash": block.block_hash,
            }
        return {"verified": False}

    def get_chain(self) -> List[dict]:
        return [b.to_dict() for b in self.chain]

    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            cur = self.chain[i]
            prev = self.chain[i - 1]
            if cur.block_hash != cur._compute_hash():
                return False
            if cur.previous_hash != prev.block_hash:
                return False
        return True


# Singleton registry for the process lifetime
registry = BlockchainRegistry()
