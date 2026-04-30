"""Registration handler — bind a GitHub user to a daimon ed25519 pubkey.

Invoked by .github/workflows/register.yml when an Issue is opened with
the ``identity`` label. Reads the Issue body, verifies the ed25519
signature, checks for duplicate registrations, and writes:

  players/{github_username}.json   — identity binding
  state/{github_username}/         — initial economic state (Phase 2)

The handler is idempotent: if ``players/{username}.json`` already exists
with the same pubkey, it's a no-op. If it exists with a DIFFERENT pubkey,
the registration is rejected (one account per GitHub user).

CLI usage (CI):
  python scripts/register.py \
      --issue-number 42 \
      --issue-author alice \
      --body-file /tmp/register/body.txt \
      --arena-root .

Self-test:
  python scripts/register.py --self-test
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from daimon.identity import verify
except ImportError as e:
    print(f"FATAL: daimon engine not importable: {e}", file=sys.stderr)
    sys.exit(127)


PROTOCOL_VERSION_REGISTER = "daimon-register-v1"
GENESIS_BALANCE = 300

_KV = re.compile(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.+?)\s*$", re.MULTILINE)
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def parse_kv(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _KV.finditer(text):
        out[m.group(1).lower()] = m.group(2)
    return out


def register_signing_payload(pubkey_hex: str, handle: str, ts_iso: str) -> bytes:
    return (
        PROTOCOL_VERSION_REGISTER.encode() + b"\n"
        + pubkey_hex.encode() + b"\n"
        + handle.encode() + b"\n"
        + ts_iso.encode()
    )


def process_registration(
    issue_number: int,
    issue_author: str,
    body: str,
    arena_root: Path,
) -> Dict[str, Any]:
    """Process a registration Issue. Returns a result envelope."""
    kv = parse_kv(body)

    required = ["pubkey_hex", "handle", "github_username", "signed_at",
                 "signature", "protocol"]
    missing = [k for k in required if k not in kv]
    if missing:
        return {"ok": False, "error": "missing_fields",
                "message": f"missing required fields: {missing}"}

    pubkey_hex = kv["pubkey_hex"].strip().lower()
    handle = kv["handle"].strip()
    github_username = kv["github_username"].strip()
    github_id = kv.get("github_id", "").strip()
    signed_at = kv["signed_at"].strip()
    signature = kv["signature"].strip().lower()
    protocol = kv["protocol"].strip()

    if protocol != PROTOCOL_VERSION_REGISTER:
        return {"ok": False, "error": "protocol_mismatch",
                "message": f"expected {PROTOCOL_VERSION_REGISTER}, got {protocol}"}

    if not _HEX64.match(pubkey_hex):
        return {"ok": False, "error": "invalid_pubkey",
                "message": "pubkey_hex must be 64 hex chars"}

    # Issue author must match the github_username in the body.
    if issue_author.lower() != github_username.lower():
        return {"ok": False, "error": "author_mismatch",
                "message": (
                    f"Issue author '{issue_author}' does not match "
                    f"github_username '{github_username}' in body"
                )}

    # Verify ed25519 signature
    payload = register_signing_payload(pubkey_hex, handle, signed_at)
    try:
        sig_bytes = bytes.fromhex(signature)
    except ValueError:
        return {"ok": False, "error": "invalid_signature",
                "message": "signature is not valid hex"}
    if not verify(pubkey_hex, payload, sig_bytes):
        return {"ok": False, "error": "signature_failed",
                "message": "ed25519 signature does not verify against pubkey"}

    # Check for duplicate registrations
    players_dir = arena_root / "players"
    players_dir.mkdir(exist_ok=True)
    player_file = players_dir / f"{github_username}.json"

    if player_file.exists():
        existing = json.loads(player_file.read_text())
        if existing.get("pubkey_hex", "").lower() == pubkey_hex:
            return {"ok": True, "action": "already_registered",
                    "message": f"{github_username} already registered with this pubkey"}
        return {"ok": False, "error": "already_registered",
                "message": (
                    f"{github_username} is already registered with a different "
                    f"pubkey ({existing.get('pubkey_hex', '?')[:16]}…)"
                )}

    # Check if pubkey is already bound to a different user
    for pf in players_dir.glob("*.json"):
        if pf.name == f"{github_username}.json":
            continue
        try:
            data = json.loads(pf.read_text())
            if data.get("pubkey_hex", "").lower() == pubkey_hex:
                return {"ok": False, "error": "pubkey_taken",
                        "message": (
                            f"pubkey {pubkey_hex[:16]}… is already bound to "
                            f"{pf.stem}"
                        )}
        except Exception:
            continue

    now = dt.datetime.now(dt.timezone.utc).isoformat()

    # Write player profile
    profile = {
        "github_username": github_username,
        "github_id": int(github_id) if github_id.isdigit() else github_id,
        "pubkey_hex": pubkey_hex,
        "handle": handle,
        "registered_at": now,
        "issue_number": issue_number,
        "version": 1,
    }
    player_file.write_text(json.dumps(profile, indent=2, sort_keys=True))

    # Create initial economic state (Phase 2 bootstrap)
    state_dir = arena_root / "state" / github_username
    state_dir.mkdir(parents=True, exist_ok=True)

    balance_file = state_dir / "balance.json"
    if not balance_file.exists():
        balance_file.write_text(json.dumps({
            "balance": GENESIS_BALANCE,
            "last_daily_bonus": None,
        }, indent=2))

    collection_file = state_dir / "collection.json"
    if not collection_file.exists():
        collection_file.write_text(json.dumps({"serials": []}, indent=2))

    tickets_dir = state_dir / "tickets"
    tickets_dir.mkdir(exist_ok=True)
    pending_file = tickets_dir / "pending.json"
    if not pending_file.exists():
        pending_file.write_text(json.dumps({
            "tickets": [],
            "next_claim_index": 0,
        }, indent=2))

    return {
        "ok": True,
        "action": "registered",
        "github_username": github_username,
        "pubkey_hex": pubkey_hex,
        "genesis_balance": GENESIS_BALANCE,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_MAX_BODY_SIZE = 16 * 1024


def main() -> int:
    p = argparse.ArgumentParser(description="DAIMON registration handler")
    p.add_argument("--issue-number", type=int)
    p.add_argument("--issue-author", type=str)
    p.add_argument("--body-file", type=str)
    p.add_argument("--arena-root", default=".")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()

    if args.self_test:
        return _self_test()

    if not all([args.issue_number, args.issue_author, args.body_file]):
        print("error: --issue-number, --issue-author, and --body-file "
              "required (or --self-test)", file=sys.stderr)
        return 2

    body = Path(args.body_file).read_text(encoding="utf-8")
    if len(body) > _MAX_BODY_SIZE:
        print(f"error: body exceeds {_MAX_BODY_SIZE} bytes", file=sys.stderr)
        return 2

    result = process_registration(
        args.issue_number,
        args.issue_author,
        body,
        Path(args.arena_root),
    )
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _self_test() -> int:
    import tempfile
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    print("Running registration self-test...")

    priv = Ed25519PrivateKey.from_private_bytes(bytes([0x42]) * 32)
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pubkey_hex = pub.hex()

    handle = "testuser"
    ts = "2026-05-01T00:00:00+00:00"
    payload = register_signing_payload(pubkey_hex, handle, ts)
    sig = priv.sign(payload).hex()

    body = (
        f"pubkey_hex: {pubkey_hex}\n"
        f"handle: {handle}\n"
        f"github_username: testuser\n"
        f"github_id: 99999\n"
        f"signed_at: {ts}\n"
        f"signature: {sig}\n"
        f"protocol: {PROTOCOL_VERSION_REGISTER}\n"
    )

    with tempfile.TemporaryDirectory() as td:
        arena = Path(td)
        result = process_registration(42, "testuser", body, arena)
        if not result.get("ok"):
            print(f"FAIL: registration failed: {result}")
            return 1
        print(f"PASS: registered {result['github_username']} "
              f"with balance {result['genesis_balance']}")

        # Verify files were created
        pf = arena / "players" / "testuser.json"
        if not pf.exists():
            print("FAIL: players/testuser.json not created")
            return 1
        profile = json.loads(pf.read_text())
        if profile["pubkey_hex"] != pubkey_hex:
            print("FAIL: pubkey mismatch in profile")
            return 1
        print(f"PASS: players/testuser.json created with correct pubkey")

        bf = arena / "state" / "testuser" / "balance.json"
        if not bf.exists():
            print("FAIL: state/testuser/balance.json not created")
            return 1
        balance = json.loads(bf.read_text())
        if balance["balance"] != GENESIS_BALANCE:
            print(f"FAIL: balance {balance['balance']} != {GENESIS_BALANCE}")
            return 1
        print(f"PASS: genesis balance = {GENESIS_BALANCE}")

        # Idempotency: re-register same pubkey
        result2 = process_registration(43, "testuser", body, arena)
        if not result2.get("ok") or result2["action"] != "already_registered":
            print(f"FAIL: idempotent re-registration: {result2}")
            return 1
        print("PASS: idempotent re-registration detected")

        # Different pubkey for same user
        priv2 = Ed25519PrivateKey.from_private_bytes(bytes([0x99]) * 32)
        pub2 = priv2.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        pubkey2 = pub2.hex()
        ts2 = "2026-05-01T01:00:00+00:00"
        payload2 = register_signing_payload(pubkey2, handle, ts2)
        sig2 = priv2.sign(payload2).hex()
        body2 = (
            f"pubkey_hex: {pubkey2}\n"
            f"handle: {handle}\n"
            f"github_username: testuser\n"
            f"github_id: 99999\n"
            f"signed_at: {ts2}\n"
            f"signature: {sig2}\n"
            f"protocol: {PROTOCOL_VERSION_REGISTER}\n"
        )
        result3 = process_registration(44, "testuser", body2, arena)
        if result3.get("ok"):
            print(f"FAIL: should reject different pubkey for same user: {result3}")
            return 1
        print(f"PASS: rejected different pubkey for same user: {result3['error']}")

        # Author mismatch
        result4 = process_registration(45, "evil_impersonator", body, arena)
        if result4.get("ok"):
            print(f"FAIL: should reject author mismatch: {result4}")
            return 1
        print(f"PASS: rejected author mismatch: {result4['error']}")

    print("All registration self-tests passed (5/5)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
