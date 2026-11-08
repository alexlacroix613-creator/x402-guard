"""x402-guard: turn any Flask/FastAPI endpoint into a pay-per-call x402 endpoint.

Flow (x402 protocol, USDC on Base):
  1. Client calls your endpoint without payment.
  2. Guard replies HTTP 402 with a JSON payment requirement (price, payTo, asset).
  3. Client signs an EIP-3009 `TransferWithAuthorization` (USDC native meta-tx)
     and retries with the `X-Payment` header.
  4. Guard verifies the EIP-712 signature (free, local), checks amount/destination/
     validity window, then serves the resource and returns a receipt header.

Settlement: hand the verified authorization to your facilitator (or submit on-chain
via USDC.transferWithAuthorization). Verification here never touches the network.
"""
import base64
import json
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
BASE_CHAIN_ID = 8453

# EIP-712 domain for native USDC (Circle deployment)
DOMAIN = {
    "name": "USD Coin",
    "version": "2",
    "chainId": BASE_CHAIN_ID,
    "verifyingContract": USDC_BASE,
}

TRANSFER_WITH_AUTH_TYPE = (
    "TransferWithAuthorization("
    "address from,address to,uint256 value,"
    "uint256 validAfter,uint256 validBefore,bytes32 nonce)"
)

def _auth_digest(payment: dict) -> str:
    return Account.recover_message(
        encode_typed_data(domain_data=DOMAIN, message_types={
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"},
            ],
        }, message_data={
            "from": payment["from"],
            "to": payment["to"],
            "value": int(payment["value"]),
            "validAfter": int(payment["validAfter"]),
            "validBefore": int(payment["validBefore"]),
            "nonce": bytes.fromhex(payment["nonce"].removeprefix("0x")),
        }),
        signature=bytes.fromhex(payment["signature"].removeprefix("0x")),
    )

@dataclass
class PaymentRequirement:
    price_usd: float
    pay_to: str
    asset: str = USDC_BASE
    network: str = "base"
    scheme: str = "exact"
    extra: dict = field(default_factory=dict)

    def to_402(self) -> dict:
        return {
            "x402Version": 1,
            "scheme": self.scheme,
            "network": self.network,
            "asset": self.asset,
            "payTo": self.pay_to,
            "amount": str(int(self.price_usd * 1_000_000)),  # USDC: 6 decimals
            "extra": self.extra,
        }

class X402Guard:
    """Framework-agnostic guard. Use with the Flask/FastAPI helpers below."""

    def __init__(self, requirement: PaymentRequirement,
                 settle: Optional[Callable[[dict, str], None]] = None,
                 max_future_skew_s: int = 300):
        self.req = requirement
        self.settle = settle          # called with (payment, payer) after verify
        self.skew = max_future_skew_s

    def challenge(self) -> tuple[int, dict, dict]:
        return 402, {"error": "Payment required", "accepts": [self.req.to_402()]}, {}

    def verify(self, x_payment_header: str) -> tuple[Optional[str], Optional[dict]]:
        """Returns (error, payment). error is None on success."""
        try:
            payment = json.loads(base64.b64decode(x_payment_header).decode())
        except Exception:
            return "malformed X-Payment header", None
        try:
            now = int(time.time())
            va, vb = int(payment["validAfter"]), int(payment["validBefore"])
            if va > now + self.skew:
                return "authorization not yet valid (clock skew?)", None
            if vb < now:
                return "authorization expired", None
            if payment["to"].lower() != self.req.pay_to.lower():
                return f"wrong payTo: {payment['to']}", None
            if int(payment["value"]) < int(self.req.to_402()["amount"]):
                return "insufficient amount", None
            if payment.get("asset", self.req.asset).lower() != self.req.asset.lower():
                return "wrong asset", None
            payer = _auth_digest(payment)
            if payer.lower() != payment["from"].lower():
                return "signature does not match from", None
        except (KeyError, ValueError) as e:
            return f"incomplete payment object: {e}", None
        if self.settle:
            self.settle(payment, payer)
        return None, payment

# --- Framework helpers -------------------------------------------------------

def flask_guard(guard: X402Guard):
    """Decorator for Flask view functions: `@flask_guard(g) def view(): ...`"""
    from functools import wraps
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            from flask import jsonify, request
            hdr = request.headers.get("X-Payment")
            if not hdr:
                code, body, _ = guard.challenge()
                return jsonify(body), code
            err, payment = guard.verify(hdr)
            if err:
                return jsonify({"error": err}), 402
            resp, status = fn(*a, **kw)
            out = jsonify(resp) if not hasattr(resp, "headers") else resp
            out.headers["X-Payment-Response"] = base64.b64encode(json.dumps({
                "payer": payment["from"],
                "tx": "settlement-pending",   # replace with facilitator tx hash
            }).encode()).decode()
            return out, status
        return wrapper
    return deco
