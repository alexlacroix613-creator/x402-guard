"""Offline tests: full sign -> challenge -> verify round trip. No network, no funds."""
import base64
import json
import os
import sys
import time
import secrets

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eth_account import Account
from eth_account.messages import encode_typed_data

from x402_guard import DOMAIN, X402Guard, PaymentRequirement

PAY_TO = "0x4C1eAEe4D67e85e4188082fBEaEe507F2d2CCcB3"

def make_payment(priv_key: str, value: int, pay_to: str, valid_before=None):
    acct = Account.from_key(priv_key)
    payment = {
        "from": acct.address,
        "to": pay_to,
        "value": value,
        "validAfter": int(time.time()) - 60,
        "validBefore": valid_before or int(time.time()) + 600,
        "nonce": "0x" + secrets.token_hex(32),
    }
    msg = encode_typed_data(
        domain_data=DOMAIN,
        message_types={"TransferWithAuthorization": [
            {"name": "from", "type": "address"},
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "validAfter", "type": "uint256"},
            {"name": "validBefore", "type": "uint256"},
            {"name": "nonce", "type": "bytes32"},
        ]},
        message_data={**payment, "nonce": bytes.fromhex(payment["nonce"][2:])},
    )
    payment["signature"] = acct.sign_message(msg).signature.hex()
    return payment

def hdr(payment: dict) -> str:
    return base64.b64encode(json.dumps(payment).encode()).decode()

def run():
    buyer = Account.create()
    g = X402Guard(PaymentRequirement(price_usd=0.05, pay_to=PAY_TO))

    # 1. Challenge shape
    code, body, _ = g.challenge()
    assert code == 402 and body["accepts"][0]["amount"] == "50000", "challenge malformed"
    print("PASS: 402 challenge carries correct atomic amount")

    # 2. Good payment verifies
    err, p = g.verify(hdr(make_payment(buyer.key.hex(), 50_000, PAY_TO)))
    assert err is None and p["from"] == buyer.address, f"good payment rejected: {err}"
    print("PASS: valid authorization verifies, payer recovered")

    # 3. Wrong amount
    err, _ = g.verify(hdr(make_payment(buyer.key.hex(), 10_000, PAY_TO)))
    assert err == "insufficient amount", err
    print("PASS: underpayment rejected")

    # 4. Wrong payTo
    other = Account.create().address
    err, _ = g.verify(hdr(make_payment(buyer.key.hex(), 50_000, other)))
    assert err and err.startswith("wrong payTo"), err
    print("PASS: wrong payTo rejected")

    # 5. Expired
    err, _ = g.verify(hdr(make_payment(buyer.key.hex(), 50_000, PAY_TO,
                                        valid_before=int(time.time()) - 10)))
    assert err == "authorization expired", err
    print("PASS: expired authorization rejected")

    # 6. Bad signature (from mismatch)
    bad = make_payment(buyer.key.hex(), 50_000, PAY_TO)
    bad["from"] = Account.create().address
    err, _ = g.verify(hdr(bad))
    assert err == "signature does not match from", err
    print("PASS: tampered from-address rejected")

    # 7. Settlement hook fires
    seen = []
    g2 = X402Guard(PaymentRequirement(price_usd=0.05, pay_to=PAY_TO),
                   settle=lambda payment, payer: seen.append((payment["value"], payer)))
    err, _ = g2.verify(hdr(make_payment(buyer.key.hex(), 50_000, PAY_TO)))
    assert err is None and seen and seen[0][0] == 50_000, seen
    print("PASS: settle hook receives (payment, recovered payer)")

    print("\nALL 7 CHECKS PASSED — no network, no funds, fully offline.")

def run_settlement_tests():
    """Settlement path, offline: fake chain, real key handling + tx building."""
    import json as _json
    import tempfile
    from settle import settle_authorization, _split_sig

    captured = {}

    class FakeContractFn:
        def __init__(self, *a): self.args = a
        def build_transaction(self, tx):
            captured["transferWithAuthorization"] = self
            return {"data": "0x", **tx}
    class FakeFns:
        def __getattr__(self, name):
            def mk(*a): return FakeContractFn(*a)
            return mk
    class FakeContract:
        functions = FakeFns()
    class FakeEth:
        def get_transaction_count(self, addr): return 0
        def call(self, tx): return b""  # simulated success
        def send_raw_transaction(self, raw): return b"\x12\x34"
        def wait_for_transaction_receipt(self, h):
            return type("R", (), {"status": 1})()
        def contract(self, **kw): return FakeContract()
    class FakeW3:
        eth = FakeEth()
        @staticmethod
        def to_checksum_address(a): return a
        @staticmethod
        def to_wei(v, u): return int(v * 1e9)

    buyer = Account.create()
    seller = Account.create()
    payment = make_payment(buyer.key.hex(), 50_000, seller.address)

    # persist seller keystore for load_json_key
    tmp = tempfile.mkdtemp()
    kf = os.path.join(tmp, "k.json")
    with open(kf, "w") as f:
        f.write(_json.dumps(Account.encrypt(seller.key, "test-pass")))

    v, r, s = _split_sig(payment["signature"])
    assert 27 <= v <= 28 and len(r) == 32 and len(s) == 32
    print("PASS: signature split (v,r,s) valid")

    rep = settle_authorization(payment, kf, "test-pass", w3=FakeW3(), execute=False)
    assert rep["mode"] == "DRY-RUN" and rep["amount_usd"] == 0.05, rep
    assert rep["payer"] == buyer.address and rep["seller"] == seller.address
    fn = captured["transferWithAuthorization"]
    assert fn.args[0].lower() == buyer.address.lower()  # from == payer
    assert fn.args[1].lower() == seller.address.lower()  # to == seller
    print("PASS: dry-run builds transferWithAuthorization tx, simulates ok")

    rep2 = settle_authorization(payment, kf, "test-pass", w3=FakeW3(), execute=True)
    assert rep2["tx_hash"] and rep2["receipt_status"] == 1, rep2
    print("PASS: execute path broadcasts + reads receipt (fake chain)")

    print("SETTLEMENT: ALL 3 CHECKS PASSED — offline.")

if __name__ == "__main__":
    run()
    run_settlement_tests()
