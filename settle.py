"""On-chain settlement for verified x402 authorizations.

After X402Guard.verify() confirms an EIP-3009 TransferWithAuthorization, the
recipient submits it to USDC on Base via `transferWithAuthorization`. The
authorization pulls funds from `payer`; the submitter pays gas and receives
the USDC — standard x402 seller settlement.

Default mode is DRY-RUN: builds + signs the transaction, decodes what would
happen, and reports — nothing is broadcast. Pass execute=True to submit.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eth_account import Account
from web3 import Web3

from x402_guard import BASE_CHAIN_ID, USDC_BASE, load_json_key

USDC_ABI = [
    {
        "name": "transferWithAuthorization",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "from", "type": "address"},
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "validAfter", "type": "uint256"},
            {"name": "validBefore", "type": "uint256"},
            {"name": "nonce", "type": "bytes32"},
            {"name": "v", "type": "uint8"},
            {"name": "r", "type": "bytes32"},
            {"name": "s", "type": "bytes32"},
        ],
        "outputs": [],
    }
]

def _split_sig(signature_hex: str):
    sig = bytes.fromhex(signature_hex.removeprefix("0x"))
    v, r, s = sig[64], sig[0:32], sig[32:64]
    if v < 27:
        v += 27
    return v, r, s

def settle_authorization(payment: dict, keyfile: str, passphrase: str,
                          rpc: str = "https://mainnet.base.org",
                          execute: bool = False, w3=None) -> dict:
    """Submit a verified authorization. Returns a report dict.

    execute=False (default): full build + sign + simulation report, no broadcast.
    execute=True: broadcast and return the tx hash.
    w3: optional pre-built Web3 instance (used by tests to stay offline).
    """
    if w3 is None:
        w3 = Web3(Web3.HTTPProvider(rpc))
    acct = Account.from_key(load_json_key(keyfile, passphrase))
    usdc = w3.eth.contract(address=Web3.to_checksum_address(USDC_BASE), abi=USDC_ABI)

    v, r, s = _split_sig(payment["signature"])
    args = (
        Web3.to_checksum_address(payment["from"]),
        Web3.to_checksum_address(payment["to"]),
        int(payment["value"]),
        int(payment["validAfter"]),
        int(payment["validBefore"]),
        bytes.fromhex(payment["nonce"].removeprefix("0x")),
        v, r, s,
    )

    contract_fn = usdc.functions.transferWithAuthorization(*args)
    tx = contract_fn.build_transaction({
        "chainId": BASE_CHAIN_ID,
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "maxFeePerGas": w3.to_wei(0.02, "gwei"),
        "maxPriorityFeePerGas": w3.to_wei(0.005, "gwei"),
        "gas": 120000,
    })
    signed = acct.sign_transaction(tx)

    report = {
        "seller": acct.address,
        "payer": payment["from"],
        "amount_atomic": int(payment["value"]),
        "amount_usd": int(payment["value"]) / 1e6,
        "nonce_hex": payment["nonce"],
        "gas_estimate_tx": tx,
        "mode": "EXECUTE" if execute else "DRY-RUN",
    }

    if not execute:
        # Local static call: would this authorization succeed on-chain?
        try:
            w3.eth.call(tx)  # simulates against latest state (works even unfunded)
            report["simulation"] = "ok (reverts excluded)"
        except Exception as e:
            report["simulation"] = f"would revert: {e}"
        return report

    report["tx_hash"] = w3.eth.send_raw_transaction(signed.raw_transaction).hex()
    report["receipt_status"] = w3.eth.wait_for_transaction_receipt(report["tx_hash"]).status
    return report
