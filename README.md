# x402-guard

Drop-in Python guard that turns any Flask (or plain WSGI) endpoint into a **pay-per-call x402 endpoint**, settled in **USDC on Base**.

The x402 protocol: your server answers `402 Payment Required` with a machine-readable price; the client signs an EIP-3009 `TransferWithAuthorization`; retries with `X-Payment`; you verify locally (offline, free) and serve.

## Why this exists
Most x402 examples assume you run a full facilitator stack. This is the minimal guard: ~150 lines, no services, verification is pure cryptography. Settlement is a hook you point at your facilitator or an on-chain `transferWithAuthorization` call.

## Install & test

```bash
pip install eth-account eth-utils flask   # flask only for the demo
python tests/test_roundtrip.py            # 7 offline checks, no network/funds
python examples/demo_server.py            # 402 on localhost:8402/research
```

## Use

```python
from x402_guard import X402Guard, PaymentRequirement, flask_guard

guard = X402Guard(
    PaymentRequirement(price_usd=0.02, pay_to="0xYOUR_ADDRESS"),
    settle=lambda payment, payer: my_facilitator.submit(payment),
)

@app.route("/api")
@flask_guard(guard)
def api():
    return {"data": "expensive stuff"}
```

Free clients get `402 + {accepts: [...]}`; paying clients get the resource + an `X-Payment-Response` receipt.

## Security notes
- Verification checks signature, `from`, `to`, amount, asset, and validity window — **offline**.
- Settlement is your responsibility: verify-then-settle, or you risk serving without payment.
- The guard never holds keys; it only verifies authorizations clients sign.

## Status
v0.1 — works offline end-to-end; on-chain settlement adapters for Coinbase/x402.org facilitators are the roadmap.

## License
MIT.

## Tip jar
If this saved you time: USDC on Base → `0x4C1eAEe4D67e85e4188082fBEaEe507F2d2CCcB3`
