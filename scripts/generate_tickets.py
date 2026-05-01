"""Batch ticket generator — pre-mint encrypted pull tickets for each player.

Invoked by .github/workflows/ticket-generator.yml on schedule (every 6h),
manual dispatch, or repository_dispatch (after pool depletion).

For each registered player in ``players/``:
  1. Read ``state/{username}/tickets/pending.json``
  2. Count unclaimed tickets (index >= ``next_claim_index``)
  3. If fewer than ``MIN_UNCLAIMED`` unclaimed, generate up to ``BATCH_SIZE``
  4. Each ticket: seed = HMAC-SHA256(arbiter_secret, pubkey || index || batch_nonce)
  5. Roll card from catalog with that seed
  6. Sign the ticket with the arbiter's ed25519 key
  7. Encrypt (seal) with the player's ed25519 public key
  8. Write updated ``pending.json``

The arbiter's ed25519 private key is passed via ``--arbiter-key-hex`` (from
GitHub Actions secret ``ARBITER_PRIVATE_KEY``). The public key is published
at ``arbiter_pubkey.json`` in the repo root.

CLI usage (CI):
  python scripts/generate_tickets.py \
      --arbiter-key-hex <64-char-hex> \
      --arena-root . \
      [--min-unclaimed 10] \
      [--batch-size 20]

Self-test:
  python scripts/generate_tickets.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from daimon.arena.crypto import seal_hex
    from daimon.arena.encoding import canonical_json, ticket_signing_payload
    from daimon.catalog import load_catalog, roll_pull
except ImportError as e:
    print(f"FATAL: required module not importable: {e}", file=sys.stderr)
    sys.exit(127)

MIN_UNCLAIMED = 10
BATCH_SIZE = 20
PULL_COST = 100
DEFAULT_PACK = "v1_alpha"
PROTOCOL_VERSION_TICKET = "daimon-ticket-v1"


def _derive_seed(arbiter_secret: bytes, pubkey_hex: str,
                 index: int, batch_nonce: bytes) -> bytes:
    """Deterministic 32-byte seed for a specific ticket slot."""
    msg = pubkey_hex.encode() + b"|" + str(index).encode() + b"|" + batch_nonce
    return hmac.new(arbiter_secret, msg, hashlib.sha256).digest()


def _load_pending(state_dir: Path) -> Dict[str, Any]:
    tickets_file = state_dir / "tickets" / "pending.json"
    if tickets_file.exists():
        return json.loads(tickets_file.read_text())
    return {"tickets": [], "next_claim_index": 0}


def _save_pending(state_dir: Path, data: Dict[str, Any]) -> None:
    tickets_dir = state_dir / "tickets"
    tickets_dir.mkdir(parents=True, exist_ok=True)
    (tickets_dir / "pending.json").write_text(
        json.dumps(data, indent=2, sort_keys=True))


def generate_for_player(
    username: str,
    player_pubkey_hex: str,
    arbiter_priv: Ed25519PrivateKey,
    arbiter_secret: bytes,
    arena_root: Path,
    min_unclaimed: int = MIN_UNCLAIMED,
    batch_size: int = BATCH_SIZE,
    catalog_name: str = DEFAULT_PACK,
) -> Dict[str, Any]:
    """Generate tickets for one player. Returns a summary envelope."""
    state_dir = arena_root / "state" / username
    pending = _load_pending(state_dir)

    tickets = pending.get("tickets", [])
    next_idx = pending.get("next_claim_index", 0)
    unclaimed = [t for t in tickets if t.get("index", -1) >= next_idx]

    if len(unclaimed) >= min_unclaimed:
        return {"action": "skipped", "username": username,
                "unclaimed": len(unclaimed)}

    # Load the player's ed25519 public key for encryption
    try:
        player_pub_bytes = bytes.fromhex(player_pubkey_hex)
        player_pub = Ed25519PublicKey.from_public_bytes(player_pub_bytes)
    except Exception as e:
        return {"action": "error", "username": username,
                "error": f"invalid player pubkey: {e}"}

    # Determine the next index to generate from
    max_existing = max((t.get("index", -1) for t in tickets), default=-1)
    start_idx = max(next_idx, max_existing + 1)

    catalog = load_catalog(catalog_name)
    batch_nonce = os.urandom(32)
    new_sealed = []
    new_plaintext = []

    for i in range(batch_size - len(unclaimed)):
        idx = start_idx + i
        seed = _derive_seed(arbiter_secret, player_pubkey_hex, idx, batch_nonce)
        pull = roll_pull(catalog, seed)

        ticket_content = {
            "index": idx,
            "card_id": pull.card.card_id,
            "rarity": pull.rarity,
            "pack": catalog_name,
            "serial": str(uuid.uuid4()),
            "seed_hex": seed.hex(),
            "edition": "1st" if catalog_name == "v1_alpha" else None,
            "cost": PULL_COST,
        }

        # Sign the ticket
        payload = ticket_signing_payload(ticket_content)
        sig_hex = arbiter_priv.sign(payload).hex()

        # Encrypt: bundle ticket + signature, then seal with player's pubkey
        inner = json.dumps({
            "ticket": ticket_content,
            "arbiter_sig": sig_hex,
        })
        sealed = seal_hex(inner.encode(), player_pub)

        new_sealed.append({"index": idx, "sealed_hex": sealed})
        new_plaintext.append(ticket_content)

    tickets.extend(new_sealed)
    pending["tickets"] = tickets
    _save_pending(state_dir, pending)

    # Write arbiter-side manifest (plaintext tickets keyed by index).
    # The claim handler reads this to deduct balance and update collection
    # without having to unseal the player-encrypted blobs.
    manifest_file = state_dir / "tickets" / "manifest.json"
    manifest = json.loads(manifest_file.read_text()) if manifest_file.exists() else {}
    for tc in new_plaintext:
        manifest[str(tc["index"])] = tc
    manifest_file.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    return {"action": "generated", "username": username,
            "new_count": len(new_sealed),
            "total_tickets": len(tickets),
            "unclaimed_after": len(unclaimed) + len(new_sealed)}


def generate_all(
    arbiter_key_hex: str,
    arena_root: Path,
    min_unclaimed: int = MIN_UNCLAIMED,
    batch_size: int = BATCH_SIZE,
) -> List[Dict[str, Any]]:
    """Generate tickets for all registered players."""
    arbiter_priv = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(arbiter_key_hex))

    # Derive a secret from the private key for HMAC seed generation
    arbiter_secret = hashlib.sha256(
        b"daimon-ticket-seed-secret|" + bytes.fromhex(arbiter_key_hex)
    ).digest()

    players_dir = arena_root / "players"
    if not players_dir.exists():
        return []

    results = []
    for pf in sorted(players_dir.glob("*.json")):
        try:
            player = json.loads(pf.read_text())
        except Exception:
            continue
        username = player.get("github_username", pf.stem)
        pubkey_hex = player.get("pubkey_hex", "")
        if not pubkey_hex:
            continue

        result = generate_for_player(
            username=username,
            player_pubkey_hex=pubkey_hex,
            arbiter_priv=arbiter_priv,
            arbiter_secret=arbiter_secret,
            arena_root=arena_root,
            min_unclaimed=min_unclaimed,
            batch_size=batch_size,
        )
        results.append(result)
    return results


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _self_test() -> None:
    import tempfile

    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    # Create a player keypair
    player_priv = Ed25519PrivateKey.generate()
    player_pub_hex = player_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        players_dir = root / "players"
        players_dir.mkdir()
        state_dir = root / "state" / "testuser"
        state_dir.mkdir(parents=True)
        (state_dir / "tickets").mkdir()
        (state_dir / "tickets" / "pending.json").write_text(
            json.dumps({"tickets": [], "next_claim_index": 0}))

        (players_dir / "testuser.json").write_text(json.dumps({
            "github_username": "testuser",
            "pubkey_hex": player_pub_hex,
        }))

        # Generate tickets
        results = generate_all(priv_hex, root, min_unclaimed=5, batch_size=10)
        assert len(results) == 1, f"expected 1 result, got {len(results)}"
        r = results[0]
        assert r["action"] == "generated", f"expected generated, got {r}"
        assert r["new_count"] == 10, f"expected 10 tickets, got {r['new_count']}"

        # Verify tickets can be decrypted
        from daimon.arena.crypto import unseal_hex as _unseal_hex
        pending = json.loads(
            (state_dir / "tickets" / "pending.json").read_text())
        assert len(pending["tickets"]) == 10

        t0 = pending["tickets"][0]
        plaintext = _unseal_hex(t0["sealed_hex"], player_priv)
        inner = json.loads(plaintext)
        assert "ticket" in inner
        assert "arbiter_sig" in inner
        assert inner["ticket"]["index"] == 0
        assert inner["ticket"]["card_id"]

        # Verify arbiter signature
        from daimon.arena.encoding import verify_ticket_signature
        arbiter_pub_hex = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        assert verify_ticket_signature(
            inner["ticket"], inner["arbiter_sig"], arbiter_pub_hex)

        # Re-run: should skip (enough unclaimed)
        results2 = generate_all(priv_hex, root, min_unclaimed=5, batch_size=10)
        assert results2[0]["action"] == "skipped"

        print("self-test: 3/3 PASS")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate pull tickets")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--arbiter-key-hex")
    parser.add_argument("--arena-root", default=".")
    parser.add_argument("--min-unclaimed", type=int, default=MIN_UNCLAIMED)
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return

    if not args.arbiter_key_hex:
        print("ERROR: --arbiter-key-hex is required", file=sys.stderr)
        sys.exit(1)

    results = generate_all(
        arbiter_key_hex=args.arbiter_key_hex,
        arena_root=Path(args.arena_root),
        min_unclaimed=args.min_unclaimed,
        batch_size=args.batch_size,
    )
    for r in results:
        print(json.dumps(r))


if __name__ == "__main__":
    main()
