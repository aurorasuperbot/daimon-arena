"""Migration handler — one-time local state transfer to arena.

Invoked by .github/workflows/migration.yml when an Issue is opened with
the ``migration`` label. Validates the player's signature, checks card_ids
against the catalog, caps balance, and writes server state.

Validation:
  1. Issue author must match github_username in body
  2. Player must be registered (players/{username}.json exists)
  3. Player must NOT already be migrated
  4. Signature must verify against registered pubkey
  5. Balance is capped at 10000
  6. Card IDs must exist in the catalog

On success:
  - Sets balance in state/{username}/balance.json
  - Sets card_ids in state/{username}/collection.json
  - Marks player as migrated in players/{username}.json

CLI usage (CI):
  python scripts/process_migration.py \
      --issue-number 42 \
      --issue-author alice \
      --body-file /tmp/claim/body.txt \
      --arena-root .

Self-test:
  python scripts/process_migration.py --self-test
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

try:
    from daimon.identity import verify
    from daimon.catalog.loader import load_catalog
except ImportError as e:
    print(f"FATAL: daimon engine not importable: {e}", file=sys.stderr)
    sys.exit(127)


PROTOCOL_VERSION_MIGRATION = "daimon-migration-v1"
BALANCE_CAP = 10000
_KV = re.compile(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.+?)\s*$", re.MULTILINE)
_JSON_BLOCK = re.compile(r"```json\s*\n(.*?)\n\s*```", re.DOTALL)


def parse_kv(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _KV.finditer(text):
        out[m.group(1).lower()] = m.group(2)
    return out


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def migration_signing_payload(github_username: str,
                              balance: int,
                              collection_hash: str,
                              ts_iso: str) -> bytes:
    return (
        PROTOCOL_VERSION_MIGRATION.encode() + b"\n"
        + github_username.encode() + b"\n"
        + str(balance).encode() + b"\n"
        + collection_hash.encode() + b"\n"
        + ts_iso.encode()
    )


def process_migration(
    issue_number: int,
    issue_author: str,
    body: str,
    arena_root: Path,
) -> Dict[str, Any]:
    """Process a migration Issue. Returns a result envelope."""
    kv = parse_kv(body)

    required = ["github_username", "pubkey_hex", "balance",
                "collection_hash", "migrated_at", "signature", "protocol"]
    missing = [k for k in required if k not in kv]
    if missing:
        return {"ok": False, "error": "missing_fields",
                "message": f"missing required fields: {missing}"}

    username = kv["github_username"].strip()
    pubkey_hex = kv["pubkey_hex"].strip().lower()
    balance = int(kv["balance"].strip())
    collection_hash = kv["collection_hash"].strip().lower()
    migrated_at = kv["migrated_at"].strip()
    signature = kv["signature"].strip().lower()
    protocol = kv["protocol"].strip()

    if protocol != PROTOCOL_VERSION_MIGRATION:
        return {"ok": False, "error": "protocol_mismatch",
                "message": f"expected {PROTOCOL_VERSION_MIGRATION}, got {protocol}"}

    if issue_author.lower() != username.lower():
        return {"ok": False, "error": "author_mismatch",
                "message": f"Issue author '{issue_author}' != github_username '{username}'"}

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

    # Check if already migrated
    if player.get("migrated"):
        return {"ok": False, "error": "already_migrated",
                "message": f"{username} has already migrated"}

    # Verify signature
    payload = migration_signing_payload(username, balance, collection_hash, migrated_at)
    try:
        sig_bytes = bytes.fromhex(signature)
    except ValueError:
        return {"ok": False, "error": "invalid_signature",
                "message": "signature is not valid hex"}
    if not verify(pubkey_hex, payload, sig_bytes):
        return {"ok": False, "error": "signature_failed",
                "message": "ed25519 signature does not verify"}

    # Cap balance
    capped_balance = min(balance, BALANCE_CAP)

    # Extract collection from JSON block
    json_match = _JSON_BLOCK.search(body)
    if not json_match:
        return {"ok": False, "error": "no_collection",
                "message": "no JSON code block with collection data"}

    try:
        collection_data = json.loads(json_match.group(1))
    except json.JSONDecodeError as e:
        return {"ok": False, "error": "invalid_collection_json",
                "message": f"invalid JSON in collection block: {e}"}

    card_ids = collection_data.get("card_ids", [])

    # Verify collection hash
    computed_hash = hashlib.sha256(canonical_json(collection_data)).hexdigest()
    if computed_hash != collection_hash:
        return {"ok": False, "error": "collection_hash_mismatch",
                "message": "collection hash does not match body content"}

    # Validate card_ids against catalog
    try:
        catalog = load_catalog()
        valid_ids = {c.card_id for c in catalog.cards}
    except Exception:
        valid_ids = set()

    invalid_cards = [cid for cid in card_ids if cid not in valid_ids] if valid_ids else []
    if invalid_cards:
        return {"ok": False, "error": "invalid_card_ids",
                "message": f"unknown card_ids: {invalid_cards[:5]}"}

    # Write state
    state_dir = arena_root / "state" / username
    state_dir.mkdir(parents=True, exist_ok=True)

    # Update balance (add migrated balance to existing)
    balance_file = state_dir / "balance.json"
    if balance_file.exists():
        balance_data = json.loads(balance_file.read_text())
    else:
        balance_data = {"balance": 0}
    balance_data["balance"] = balance_data.get("balance", 0) + capped_balance
    balance_data["migrated_balance"] = capped_balance
    balance_data["migrated_at"] = migrated_at
    balance_file.write_text(json.dumps(balance_data, indent=2))

    # Update collection
    collection_file = state_dir / "collection.json"
    if collection_file.exists():
        col = json.loads(collection_file.read_text())
    else:
        col = {"serials": [], "card_ids": []}
    col.setdefault("card_ids", [])
    col["card_ids"].extend(card_ids)
    col["migrated_card_ids"] = card_ids
    collection_file.write_text(json.dumps(col, indent=2))

    # Mark player as migrated
    player["migrated"] = True
    player["migrated_at"] = migrated_at
    player["migration_issue"] = issue_number
    player_file.write_text(json.dumps(player, indent=2))

    return {
        "ok": True,
        "action": "migrated",
        "username": username,
        "balance_added": capped_balance,
        "cards_added": len(card_ids),
        "balance_after": balance_data["balance"],
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
        state.mkdir(parents=True)
        (state / "balance.json").write_text(json.dumps({"balance": 300}))
        (state / "collection.json").write_text(json.dumps({
            "serials": [], "card_ids": [],
        }))

        # Build collection payload
        collection_payload = {"card_ids": ["iron_boar", "dashmouse"], "serial_count": 2}
        collection_json = canonical_json(collection_payload)
        collection_hash = hashlib.sha256(collection_json).hexdigest()

        # Test 1: Valid migration
        ts = "2026-05-01T00:00:00Z"
        capped_balance = 5000
        payload = migration_signing_payload("alice", capped_balance, collection_hash, ts)
        sig = player_priv.sign(payload).hex()
        body = f"""claim_type: migration
github_username: alice
pubkey_hex: {player_pub_hex}
balance: {capped_balance}
original_balance: 7500
collection_hash: {collection_hash}
card_count: 2
migrated_at: {ts}
signature: {sig}
protocol: {PROTOCOL_VERSION_MIGRATION}

```json
{collection_json.decode()}
```
"""

        r = process_migration(42, "alice", body, root)
        assert r["ok"], f"expected ok, got {r}"
        assert r["balance_added"] == 5000
        assert r["cards_added"] == 2
        # 300 existing + 5000 migrated = 5300
        assert r["balance_after"] == 5300, f"expected 5300, got {r['balance_after']}"

        # Verify state
        bal = json.loads((state / "balance.json").read_text())
        assert bal["balance"] == 5300
        col = json.loads((state / "collection.json").read_text())
        assert "iron_boar" in col["card_ids"]
        assert "dashmouse" in col["card_ids"]
        player = json.loads((root / "players" / "alice.json").read_text())
        assert player["migrated"] is True

        # Test 2: Duplicate migration
        r2 = process_migration(43, "alice", body, root)
        assert not r2["ok"]
        assert r2["error"] == "already_migrated"

        # Test 3: Wrong author
        r3 = process_migration(44, "bob", body, root)
        assert not r3["ok"]
        assert r3["error"] == "author_mismatch"

        # Test 4: Balance cap
        player["migrated"] = False
        (root / "players" / "alice.json").write_text(json.dumps(player))
        over_cap = 15000
        payload4 = migration_signing_payload("alice", over_cap, collection_hash, ts)
        sig4 = player_priv.sign(payload4).hex()
        body4 = body.replace(f"balance: {capped_balance}", f"balance: {over_cap}")
        body4 = body4.replace(f"signature: {sig}", f"signature: {sig4}")
        r4 = process_migration(45, "alice", body4, root)
        assert r4["ok"]
        assert r4["balance_added"] == BALANCE_CAP  # capped

        print("self-test: 4/4 PASS")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Process migration")
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
    result = process_migration(
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
