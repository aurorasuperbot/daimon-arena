"""Tier-claim handler — process a player's tier-up reward claim.

Invoked by .github/workflows/tier-claim.yml when an Issue is opened with
the ``tier-claim`` label. Checks the leaderboard for the player's win count,
verifies the claimed tier is valid and not already claimed, and credits
the tier-up reward.

Tier thresholds and rewards:
  Novice    →  3 wins  → 100¤
  Veteran   → 10 wins  → 250¤
  Elite     → 25 wins  → 500¤
  Champion  → 50 wins  → 1000¤

Multi-tier jumps (e.g. Rookie → Veteran) claim ALL intermediate tiers.

CLI usage (CI):
  python scripts/process_tier_claim.py \
      --issue-number 42 \
      --issue-author alice \
      --body-file /tmp/claim/body.txt \
      --arena-root .

Self-test:
  python scripts/process_tier_claim.py --self-test
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    from daimon.identity import verify
except ImportError as e:
    print(f"FATAL: daimon engine not importable: {e}", file=sys.stderr)
    sys.exit(127)


PROTOCOL_VERSION_TIER_CLAIM = "daimon-tier-claim-v1"
_KV = re.compile(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.+?)\s*$", re.MULTILINE)

TIER_THRESHOLDS: Tuple[Tuple[str, int], ...] = (
    ("Champion", 50),
    ("Elite", 25),
    ("Veteran", 10),
    ("Novice", 3),
    ("Rookie", 0),
)

TIER_REWARDS: Dict[str, int] = {
    "Novice": 100,
    "Veteran": 250,
    "Elite": 500,
    "Champion": 1000,
}


def tier_of(wins: int) -> str:
    for name, threshold in TIER_THRESHOLDS:
        if wins >= threshold:
            return name
    return "Rookie"


def parse_kv(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _KV.finditer(text):
        out[m.group(1).lower()] = m.group(2)
    return out


def tier_claim_signing_payload(github_username: str,
                               tier: str,
                               ts_iso: str) -> bytes:
    return (
        PROTOCOL_VERSION_TIER_CLAIM.encode() + b"\n"
        + github_username.encode() + b"\n"
        + tier.encode() + b"\n"
        + ts_iso.encode()
    )


def _get_player_wins(arena_root: Path, pubkey_hex: str) -> int:
    """Read wins from leaderboard for a given pubkey."""
    lb_path = arena_root / "leaderboard.json"
    if not lb_path.exists():
        return 0
    lb = json.loads(lb_path.read_text())
    entries = lb.get("entries", {})
    entry = entries.get(pubkey_hex.lower(), entries.get(pubkey_hex, {}))
    return entry.get("wins", 0)


def _unclaimed_tiers(arena_root: Path, username: str,
                     current_tier: str) -> List[str]:
    """Return tiers the player has earned but not yet claimed."""
    state_dir = arena_root / "state" / username
    claims_file = state_dir / "tier_claims.json"
    claimed = set()
    if claims_file.exists():
        data = json.loads(claims_file.read_text())
        claimed = {c.get("tier") for c in data.get("claims", [])}

    unclaimed = []
    for name, _ in reversed(TIER_THRESHOLDS):
        if name == "Rookie":
            continue
        if name in claimed:
            continue
        if name == current_tier or _tier_rank(name) <= _tier_rank(current_tier):
            unclaimed.append(name)
    return unclaimed


def _tier_rank(tier: str) -> int:
    """Numeric rank for tier comparison (higher = better)."""
    ranks = {"Rookie": 0, "Novice": 1, "Veteran": 2, "Elite": 3, "Champion": 4}
    return ranks.get(tier, 0)


def process_tier_claim(
    issue_number: int,
    issue_author: str,
    body: str,
    arena_root: Path,
) -> Dict[str, Any]:
    """Process a tier-claim Issue. Returns a result envelope."""
    kv = parse_kv(body)

    required = ["github_username", "pubkey_hex", "tier",
                "claimed_at", "signature", "protocol"]
    missing = [k for k in required if k not in kv]
    if missing:
        return {"ok": False, "error": "missing_fields",
                "message": f"missing required fields: {missing}"}

    username = kv["github_username"].strip()
    pubkey_hex = kv["pubkey_hex"].strip().lower()
    claimed_tier = kv["tier"].strip()
    claimed_at = kv["claimed_at"].strip()
    signature = kv["signature"].strip().lower()
    protocol = kv["protocol"].strip()

    if protocol != PROTOCOL_VERSION_TIER_CLAIM:
        return {"ok": False, "error": "protocol_mismatch",
                "message": f"expected {PROTOCOL_VERSION_TIER_CLAIM}, got {protocol}"}

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

    # Verify signature
    payload = tier_claim_signing_payload(username, claimed_tier, claimed_at)
    try:
        sig_bytes = bytes.fromhex(signature)
    except ValueError:
        return {"ok": False, "error": "invalid_signature",
                "message": "signature is not valid hex"}
    if not verify(pubkey_hex, payload, sig_bytes):
        return {"ok": False, "error": "signature_failed",
                "message": "ed25519 signature does not verify"}

    # Verify tier validity
    if claimed_tier not in TIER_REWARDS:
        return {"ok": False, "error": "invalid_tier",
                "message": f"'{claimed_tier}' is not a valid tier for rewards"}

    # Check leaderboard wins
    wins = _get_player_wins(arena_root, pubkey_hex)
    actual_tier = tier_of(wins)

    if _tier_rank(claimed_tier) > _tier_rank(actual_tier):
        return {"ok": False, "error": "tier_not_reached",
                "message": (
                    f"player has {wins} wins (tier {actual_tier}), "
                    f"cannot claim {claimed_tier}"
                )}

    # Check if already claimed
    state_dir = arena_root / "state" / username
    claims_file = state_dir / "tier_claims.json"
    claims = json.loads(claims_file.read_text()) if claims_file.exists() else {"claims": []}
    claimed_tiers = {c.get("tier") for c in claims.get("claims", [])}

    if claimed_tier in claimed_tiers:
        return {"ok": False, "error": "already_claimed",
                "message": f"tier '{claimed_tier}' already claimed"}

    # Find ALL unclaimed tiers up to and including the claimed tier
    tiers_to_credit: List[str] = []
    for name, _ in reversed(TIER_THRESHOLDS):
        if name == "Rookie":
            continue
        if name in claimed_tiers:
            continue
        if _tier_rank(name) <= _tier_rank(claimed_tier):
            tiers_to_credit.append(name)

    total_reward = sum(TIER_REWARDS.get(t, 0) for t in tiers_to_credit)

    # Apply daily bonus
    balance_file = state_dir / "balance.json"
    if not balance_file.exists():
        return {"ok": False, "error": "no_balance",
                "message": f"no balance file for {username}"}

    balance_data = json.loads(balance_file.read_text())
    today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    if balance_data.get("last_daily_bonus") != today:
        balance_data["balance"] = balance_data.get("balance", 0) + 100
        balance_data["last_daily_bonus"] = today

    balance_data["balance"] = balance_data.get("balance", 0) + total_reward
    balance_file.write_text(json.dumps(balance_data, indent=2))

    # Record claims
    for t in tiers_to_credit:
        claims["claims"].append({
            "tier": t,
            "reward": TIER_REWARDS.get(t, 0),
            "wins_at_claim": wins,
            "claimed_at": claimed_at,
            "issue_number": issue_number,
        })
    claims_file.write_text(json.dumps(claims, indent=2))

    return {
        "ok": True,
        "action": "tier_claimed",
        "username": username,
        "tiers_claimed": tiers_to_credit,
        "total_reward": total_reward,
        "wins": wins,
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

        # Setup state + leaderboard
        state = root / "state" / "alice"
        state.mkdir(parents=True)
        (state / "balance.json").write_text(json.dumps({"balance": 300}))

        # Leaderboard with 12 wins (Veteran tier)
        (root / "leaderboard.json").write_text(json.dumps({
            "version": 1,
            "entries": {
                player_pub_hex: {"wins": 12, "losses": 3, "draws": 0}
            },
        }))

        # Test 1: Claim Veteran (should also claim Novice)
        ts = "2026-05-01T00:00:00Z"
        payload = tier_claim_signing_payload("alice", "Veteran", ts)
        sig = player_priv.sign(payload).hex()
        body = f"""claim_type: tier_up
github_username: alice
pubkey_hex: {player_pub_hex}
tier: Veteran
claimed_at: {ts}
signature: {sig}
protocol: {PROTOCOL_VERSION_TIER_CLAIM}"""

        r = process_tier_claim(42, "alice", body, root)
        assert r["ok"], f"expected ok, got {r}"
        assert set(r["tiers_claimed"]) == {"Novice", "Veteran"}
        assert r["total_reward"] == 350  # 100 + 250
        # 300 + 100 (daily) + 350 (tier rewards) = 750
        assert r["balance_after"] == 750, f"expected 750, got {r['balance_after']}"

        # Test 2: Duplicate claim
        r2 = process_tier_claim(43, "alice", body, root)
        assert not r2["ok"]
        assert r2["error"] == "already_claimed"

        # Test 3: Claim tier not yet reached
        payload3 = tier_claim_signing_payload("alice", "Champion", ts)
        sig3 = player_priv.sign(payload3).hex()
        body3 = body.replace("tier: Veteran", "tier: Champion").replace(
            f"signature: {sig}", f"signature: {sig3}")
        r3 = process_tier_claim(44, "alice", body3, root)
        assert not r3["ok"]
        assert r3["error"] == "tier_not_reached"

        # Test 4: Wrong author
        r4 = process_tier_claim(45, "bob", body, root)
        assert not r4["ok"]
        assert r4["error"] == "author_mismatch"

        print("self-test: 4/4 PASS")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Process tier claim")
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
    result = process_tier_claim(
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
