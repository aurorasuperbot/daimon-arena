"""Pull-claim handler — process a player's ticket claim.

Invoked by .github/workflows/pull-claim.yml when an Issue is opened with
the ``pull-claim`` label. Reads the Issue body, verifies the player's
signature, enforces sequential claiming, deducts balance, updates collection,
and increments ``next_claim_index``.

Validation:
  1. Issue author must match ``github_username`` in body
  2. Player must be registered (``players/{username}.json`` exists)
  3. Player signature must verify against registered pubkey
  4. ``ticket_index`` must equal ``next_claim_index`` (sequential enforcement)
  5. Player must have sufficient balance (>= ticket cost)

On success:
  - Deducts cost from ``state/{username}/balance.json``
  - Appends serial to ``state/{username}/collection.json``
  - Increments ``next_claim_index`` in ``state/{username}/tickets/pending.json``

CLI usage (CI):
  python scripts/process_pull_claim.py \
      --issue-number 42 \
      --issue-author alice \
      --body-file /tmp/claim/body.txt \
      --arena-root .

Self-test:
  python scripts/process_pull_claim.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict

try:
    from daimon.identity import verify
except ImportError as e:
    print(f"FATAL: daimon engine not importable: {e}", file=sys.stderr)
    sys.exit(127)


PROTOCOL_VERSION_PULL_CLAIM = "daimon-pull-claim-v1"
_KV = re.compile(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.+?)\s*$", re.MULTILINE)


def parse_kv(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _KV.finditer(text):
        out[m.group(1).lower()] = m.group(2)
    return out


def pull_claim_signing_payload(github_username: str,
                               ticket_index: int,
                               ts_iso: str) -> bytes:
    return (
        PROTOCOL_VERSION_PULL_CLAIM.encode() + b"\n"
        + github_username.encode() + b"\n"
        + str(ticket_index).encode() + b"\n"
        + ts_iso.encode()
    )


def process_pull_claim(
    issue_number: int,
    issue_author: str,
    body: str,
    arena_root: Path,
) -> Dict[str, Any]:
    """Process a pull-claim Issue. Returns a result envelope."""
    kv = parse_kv(body)

    required = ["github_username", "pubkey_hex", "ticket_index",
                 "claimed_at", "signature", "protocol"]
    missing = [k for k in required if k not in kv]
    if missing:
        return {"ok": False, "error": "missing_fields",
                "message": f"missing required fields: {missing}"}

    username = kv["github_username"].strip()
    pubkey_hex = kv["pubkey_hex"].strip().lower()
    ticket_index = int(kv["ticket_index"].strip())
    claimed_at = kv["claimed_at"].strip()
    signature = kv["signature"].strip().lower()
    protocol = kv["protocol"].strip()

    if protocol != PROTOCOL_VERSION_PULL_CLAIM:
        return {"ok": False, "error": "protocol_mismatch",
                "message": f"expected {PROTOCOL_VERSION_PULL_CLAIM}, got {protocol}"}

    # Issue author must match
    if issue_author.lower() != username.lower():
        return {"ok": False, "error": "author_mismatch",
                "message": (
                    f"Issue author '{issue_author}' does not match "
                    f"github_username '{username}' in body"
                )}

    # Player must be registered
    player_file = arena_root / "players" / f"{username}.json"
    if not player_file.exists():
        return {"ok": False, "error": "not_registered",
                "message": f"no player profile for {username}"}

    player = json.loads(player_file.read_text())
    registered_pubkey = player.get("pubkey_hex", "").lower()

    if registered_pubkey != pubkey_hex:
        return {"ok": False, "error": "pubkey_mismatch",
                "message": "pubkey_hex does not match registered pubkey"}

    # Verify signature
    payload = pull_claim_signing_payload(username, ticket_index, claimed_at)
    try:
        sig_bytes = bytes.fromhex(signature)
    except ValueError:
        return {"ok": False, "error": "invalid_signature",
                "message": "signature is not valid hex"}
    if not verify(pubkey_hex, payload, sig_bytes):
        return {"ok": False, "error": "signature_failed",
                "message": "ed25519 signature does not verify"}

    # Sequential enforcement
    state_dir = arena_root / "state" / username
    tickets_file = state_dir / "tickets" / "pending.json"
    if not tickets_file.exists():
        return {"ok": False, "error": "no_tickets",
                "message": f"no ticket file for {username}"}

    pending = json.loads(tickets_file.read_text())
    next_idx = pending.get("next_claim_index", 0)

    if ticket_index != next_idx:
        return {"ok": False, "error": "index_mismatch",
                "message": (
                    f"ticket_index {ticket_index} != next_claim_index {next_idx}"
                )}

    # Find the ticket to get its cost and serial
    tickets = pending.get("tickets", [])
    ticket_entry = None
    for t in tickets:
        if t.get("index") == ticket_index:
            ticket_entry = t
            break

    if ticket_entry is None:
        return {"ok": False, "error": "ticket_not_found",
                "message": f"no ticket at index {ticket_index}"}

    # Decrypt the ticket to get the cost and serial
    # The arbiter has the private key so it can unseal
    # But actually, the arbiter GENERATED the ticket so it knows the plaintext.
    # We need to store the plaintext alongside the sealed version for the arbiter.
    # Alternative: store a separate arbiter-side manifest.
    #
    # For now: the arbiter stores a parallel plaintext file at
    # state/{username}/tickets/manifest.json that maps index → plaintext ticket.
    manifest_file = state_dir / "tickets" / "manifest.json"
    if not manifest_file.exists():
        return {"ok": False, "error": "no_manifest",
                "message": "ticket manifest not found (generator may not have run)"}

    manifest = json.loads(manifest_file.read_text())
    ticket_plain = manifest.get(str(ticket_index))
    if ticket_plain is None:
        return {"ok": False, "error": "ticket_not_in_manifest",
                "message": f"ticket {ticket_index} not in manifest"}

    cost = ticket_plain.get("cost", 100)
    serial = ticket_plain.get("serial", "")
    card_id = ticket_plain.get("card_id", "")

    # Check balance
    balance_file = state_dir / "balance.json"
    if not balance_file.exists():
        return {"ok": False, "error": "no_balance",
                "message": f"no balance file for {username}"}

    balance_data = json.loads(balance_file.read_text())
    balance = balance_data.get("balance", 0)

    if balance < cost:
        return {"ok": False, "error": "insufficient_balance",
                "message": f"balance {balance} < cost {cost}"}

    # All checks pass — commit the claim
    # 1. Deduct balance
    balance_data["balance"] = balance - cost
    balance_file.write_text(json.dumps(balance_data, indent=2))

    # 2. Append serial to collection
    collection_file = state_dir / "collection.json"
    collection = json.loads(collection_file.read_text()) if collection_file.exists() else {"serials": []}
    collection["serials"].append(serial)
    collection_file.write_text(json.dumps(collection, indent=2))

    # 3. Increment next_claim_index
    pending["next_claim_index"] = next_idx + 1
    tickets_file.write_text(json.dumps(pending, indent=2, sort_keys=True))

    return {
        "ok": True,
        "action": "claimed",
        "username": username,
        "ticket_index": ticket_index,
        "card_id": card_id,
        "serial": serial,
        "cost": cost,
        "balance_after": balance - cost,
        "issue_number": issue_number,
    }


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _self_test() -> None:
    import tempfile
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as _ser

    player_priv = Ed25519PrivateKey.generate()
    player_pub_hex = player_priv.public_key().public_bytes(
        _ser.Encoding.Raw, _ser.PublicFormat.Raw).hex()

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)

        # Setup player
        (root / "players").mkdir()
        (root / "players" / "alice.json").write_text(json.dumps({
            "github_username": "alice",
            "pubkey_hex": player_pub_hex,
        }))

        # Setup state
        state = root / "state" / "alice"
        (state / "tickets").mkdir(parents=True)
        (state / "tickets" / "pending.json").write_text(json.dumps({
            "tickets": [{"index": 0, "sealed_hex": "dummy"}],
            "next_claim_index": 0,
        }))
        (state / "tickets" / "manifest.json").write_text(json.dumps({
            "0": {"card_id": "flame_imp", "serial": "s-001",
                  "cost": 100, "rarity": "common"},
        }))
        (state / "balance.json").write_text(json.dumps({"balance": 300}))
        (state / "collection.json").write_text(json.dumps({"serials": []}))

        # Test 1: Valid claim
        ts = "2026-05-01T00:00:00Z"
        payload = pull_claim_signing_payload("alice", 0, ts)
        sig = player_priv.sign(payload).hex()
        body = f"""claim_type: pull
github_username: alice
pubkey_hex: {player_pub_hex}
ticket_index: 0
claimed_at: {ts}
signature: {sig}
protocol: {PROTOCOL_VERSION_PULL_CLAIM}"""

        r = process_pull_claim(42, "alice", body, root)
        assert r["ok"], f"expected ok, got {r}"
        assert r["card_id"] == "flame_imp"
        assert r["balance_after"] == 200

        # Verify state was updated
        bal = json.loads((state / "balance.json").read_text())
        assert bal["balance"] == 200
        col = json.loads((state / "collection.json").read_text())
        assert "s-001" in col["serials"]
        pend = json.loads((state / "tickets" / "pending.json").read_text())
        assert pend["next_claim_index"] == 1

        # Test 2: Duplicate claim (index already consumed)
        r2 = process_pull_claim(43, "alice", body, root)
        assert not r2["ok"]
        assert r2["error"] == "index_mismatch"

        # Test 3: Wrong author
        body_wrong = body.replace("github_username: alice",
                                  "github_username: alice")
        r3 = process_pull_claim(44, "bob", body_wrong, root)
        assert not r3["ok"]
        assert r3["error"] == "author_mismatch"

        print("self-test: 3/3 PASS")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Process pull claim")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--issue-number", type=int)
    parser.add_argument("--issue-author")
    parser.add_argument("--body-file")
    parser.add_argument("--arena-root", default=".")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return

    if not all([args.issue_number, args.issue_author, args.body_file]):
        print("ERROR: --issue-number, --issue-author, --body-file required",
              file=sys.stderr)
        sys.exit(1)

    body = Path(args.body_file).read_text(encoding="utf-8")
    result = process_pull_claim(
        issue_number=args.issue_number,
        issue_author=args.issue_author,
        body=body,
        arena_root=Path(args.arena_root),
    )
    print(json.dumps(result, indent=2))
    if not result.get("ok"):
        sys.exit(1)


if __name__ == "__main__":
    main()
