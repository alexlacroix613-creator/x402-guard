"""Demo: a paid research-echo endpoint. Run: python demo_server.py
Then: curl -i localhost:8402/research?q=hello   (expect 402)
Paying clients retry with X-Payment. Verification is offline; settlement hook
is where you'd call your facilitator or submit on-chain."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, request
from x402_guard import X402Guard, PaymentRequirement, flask_guard

app = Flask(__name__)
guard = X402Guard(
    PaymentRequirement(price_usd=0.02, pay_to="0x4C1eAEe4D67e85e4188082fBEaEe507F2d2CCcB3"),
    settle=lambda payment, payer: print(f"[settle] {payment['value']} atomic from {payer}"),
)

@app.route("/research")
@flask_guard(guard)
def research():
    q = request.args.get("q", "")
    return jsonify({"echo": q, "note": "you paid 0.02 USDC (settlement hook fired)"}), 200

if __name__ == "__main__":
    app.run(port=8402)
