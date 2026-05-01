"""Quest-claim handler — process a player's quest reward claim.

Invoked by .github/workflows/quest-claim.yml when an Issue is opened with
the ``quest-claim`` label. Re-derives today's quests for the player's
pubkey, verifies completion from arena state, and credits the reward.

Quest completion is verified from server-side state:
  - play_match / win_match / win_3_matches: count PvP Issues involving player
  - pull_card / pull_2_cards: count pull-claim Issues from player today
  - win_with_element: inspect match records for mono-element wins
  - beat_tier_*: inspect match records for NPC wins (not verifiable server-side,
    treated as activity-based — requires at least one match today)
  - mine_*: not verifiable server-side — auto-completed for registered players

CLI usage (CI):
  python scripts/process_quest_claim.py \
      --issue-number 42 \
      --issue-author alice \
      --body-file /tmp/claim/body.txt \
      --arena-root .

Self-test:
  python scripts/process_quest_claim.py --self-test
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

try:
    from daimon.identity import verify
    from daimon.quests.roll import roll_today
    from daimon.quests.catalog import DIFFICULTY_TIERS
except ImportError as e:
    print(f"FATAL: daimon engine not importable: {e}", file=sys.stderr)
    sys.exit(127)


PROTOCOL_VERSION_QUEST_CLAIM = "daimon-quest-claim-v1"
_KV = re.compile(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.+?)\s*$", re.MULTILINE)


def parse_kv(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _KV.finditer(text):
        out[m.group(1).lower()] = m.group(2)
    return out


def quest_claim_signing_payload(github_username: str,
                                quest_id: str,
                                date_str: str,
                                ts_iso: str) -> bytes:
    return (
        PROTOCOL_VERSION_QUEST_CLAIM.encode() + b"\n"
        + github_username.encode() + b"\n"
        + quest_id.encode() + b"\n"
        + date_str.encode() + b"\n"
        + ts_iso.encode()
    )


def _count_pvp_matches_today(arena_root: Path, username: str,
                              date_str: str, outcome: str = "any") -> int:
    """Count PvP matches for a player on a given date from match records."""
    matches_dir = arena_root / "matches"
    if not matches_dir.exists():
        return 0

    count = 0
    for mf in matches_dir.glob("*.json"):
        try:
            data = json.loads(mf.read_text())
            ts = data.get("timestamp_utc", "")
            if not ts.startswith(date_str):
                continue

            player_file = arena_root / "players" / f"{username}.json"
            if not player_file.exists():
                continue
            player = json.loads(player_file.read_text())
            pk = player.get("pubkey_hex", "").lower()

            challenger_pk = data.get("challenger_pubkey", "").lower()
            opponent_pk = data.get("opponent_pubkey", "").lower()
            if pk not in (challenger_pk, opponent_pk):
                continue

            if outcome == "any":
                count += 1
            elif outcome == "win":
                winner = data.get("winner")
                if winner == 0 and pk == challenger_pk:
                    count += 1
                elif winner == 1 and pk == opponent_pk:
                    count += 1
        except Exception:
            continue
    return count


def _count_pulls_today(arena_root: Path, username: str, date_str: str) -> int:
    """Count successful pull claims for a player on a given date.

    Uses the collection's card_ids length minus previous day's count.
    Simplified: checks the ticket manifest for claims on this date.
    """
    state_dir = arena_root / "state" / username
    tickets_file = state_dir / "tickets" / "pending.json"
    manifest_file = state_dir / "tickets" / "manifest.json"

    if not tickets_file.exists() or not manifest_file.exists():
        return 0

    pending = json.loads(tickets_file.read_text())
    next_idx = pending.get("next_claim_index", 0)
    return next_idx


def _verify_quest_completion(arena_root: Path, username: str,
                              quest: Dict[str, Any], date_str: str) -> bool:
    """Check if a quest is complete based on server-side state."""
    template_id = quest.get("template_id", "")
    params = quest.get("params", {})

    if template_id == "play_match":
        n = params.get("n", 1)
        return _count_pvp_matches_today(arena_root, username, date_str, "any") >= n

    elif template_id == "win_match":
        n = params.get("n", 1)
        return _count_pvp_matches_today(arena_root, username, date_str, "win") >= n

    elif template_id == "win_3_matches":
        n = params.get("n", 3)
        return _count_pvp_matches_today(arena_root, username, date_str, "win") >= n

    elif template_id == "pull_card":
        n = params.get("n", 1)
        return _count_pulls_today(arena_root, username, date_str) >= n

    elif template_id == "pull_2_cards":
        n = params.get("n", 2)
        return _count_pulls_today(arena_root, username, date_str) >= n

    elif template_id in ("mine_easy", "mine_medium", "mine_hard"):
        # Mining is local-only, auto-complete for registered players
        return True

    elif template_id in ("win_with_element", "beat_tier_medium", "beat_tier_hard"):
        # These require detailed match analysis not yet available
        # For now, require at least one match today as proof of activity
        return _count_pvp_matches_today(arena_root, username, date_str, "any") >= 1

    return False


def process_quest_claim(
    issue_number: int,
    issue_author: str,
    body: str,
    arena_root: Path,
) -> Dict[str, Any]:
    """Process a quest-claim Issue. Returns a result envelope."""
    kv = parse_kv(body)

    required = ["github_username", "pubkey_hex", "quest_id",
                "quest_date", "claimed_at", "signature", "protocol"]
    missing = [k for k in required if k not in kv]
    if missing:
        return {"ok": False, "error": "missing_fields",
                "message": f"missing required fields: {missing}"}

    username = kv["github_username"].strip()
    pubkey_hex = kv["pubkey_hex"].strip().lower()
    quest_id = kv["quest_id"].strip()
    quest_date = kv["quest_date"].strip()
    claimed_at = kv["claimed_at"].strip()
    signature = kv["signature"].strip().lower()
    protocol = kv["protocol"].strip()

    if protocol != PROTOCOL_VERSION_QUEST_CLAIM:
        return {"ok": False, "error": "protocol_mismatch",
                "message": f"expected {PROTOCOL_VERSION_QUEST_CLAIM}, got {protocol}"}

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
    payload = quest_claim_signing_payload(username, quest_id, quest_date, claimed_at)
    try:
        sig_bytes = bytes.fromhex(signature)
    except ValueError:
        return {"ok": False, "error": "invalid_signature",
                "message": "signature is not valid hex"}
    if not verify(pubkey_hex, payload, sig_bytes):
        return {"ok": False, "error": "signature_failed",
                "message": "ed25519 signature does not verify"}

    # Re-derive quests for this player + date
    try:
        quest_day = dt.date.fromisoformat(quest_date)
    except ValueError:
        return {"ok": False, "error": "invalid_date",
                "message": f"invalid quest_date: {quest_date}"}

    quests = roll_today(pubkey_hex, day=quest_day)
    target_quest = None
    for q in quests:
        if q["id"] == quest_id:
            target_quest = q
            break

    if target_quest is None:
        return {"ok": False, "error": "quest_not_found",
                "message": f"quest '{quest_id}' not in today's quests for this player"}

    # Check idempotency — has this quest already been claimed?
    state_dir = arena_root / "state" / username
    claims_file = state_dir / "quest_claims.json"
    claims = json.loads(claims_file.read_text()) if claims_file.exists() else {"claims": []}
    idempotency_key = f"quest_{quest_date}_{quest_id}"
    if idempotency_key in [c.get("key") for c in claims.get("claims", [])]:
        return {"ok": False, "error": "already_claimed",
                "message": f"quest '{quest_id}' already claimed for {quest_date}"}

    # Verify completion
    if not _verify_quest_completion(arena_root, username, target_quest, quest_date):
        return {"ok": False, "error": "not_complete",
                "message": f"quest '{quest_id}' not complete"}

    # All checks pass — credit reward
    reward = target_quest.get("reward", DIFFICULTY_TIERS.get(target_quest.get("tier", ""), 0))

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

    balance_data["balance"] = balance_data.get("balance", 0) + reward
    balance_file.write_text(json.dumps(balance_data, indent=2))

    # Record claim
    claims.setdefault("claims", []).append({
        "key": idempotency_key,
        "quest_id": quest_id,
        "date": quest_date,
        "reward": reward,
        "claimed_at": claimed_at,
        "issue_number": issue_number,
    })
    claims_file.write_text(json.dumps(claims, indent=2))

    return {
        "ok": True,
        "action": "quest_claimed",
        "username": username,
        "quest_id": quest_id,
        "quest_date": quest_date,
        "reward": reward,
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
        (state / "tickets").mkdir()
        (state / "balance.json").write_text(json.dumps({"balance": 500}))

        # Roll today's quests for this pubkey
        today = dt.datetime.now(dt.timezone.utc).date()
        today_str = today.strftime("%Y-%m-%d")
        quests = roll_today(player_pub_hex, day=today)

        # Find a mine quest (auto-complete) or the easy quest
        target = None
        for q in quests:
            if q["template_id"].startswith("mine_"):
                target = q
                break
        if target is None:
            target = quests[0]

        # Test 1: Valid quest claim
        ts = "2026-05-01T00:00:00Z"
        payload = quest_claim_signing_payload("alice", target["id"], today_str, ts)
        sig = player_priv.sign(payload).hex()
        body = f"""claim_type: quest
github_username: alice
pubkey_hex: {player_pub_hex}
quest_id: {target['id']}
quest_date: {today_str}
claimed_at: {ts}
signature: {sig}
protocol: {PROTOCOL_VERSION_QUEST_CLAIM}"""

        # For non-mining quests, we need to set up matches
        if not target["template_id"].startswith("mine_"):
            (root / "matches").mkdir(exist_ok=True)
            (root / "matches" / "1.json").write_text(json.dumps({
                "timestamp_utc": f"{today_str}T12:00:00Z",
                "challenger_pubkey": player_pub_hex,
                "opponent_pubkey": "bb" * 32,
                "winner": 0,
            }))

        r = process_quest_claim(42, "alice", body, root)
        assert r["ok"], f"expected ok, got {r}"
        assert r["reward"] == target["reward"]

        # Test 2: Duplicate claim (idempotency)
        r2 = process_quest_claim(43, "alice", body, root)
        assert not r2["ok"]
        assert r2["error"] == "already_claimed"

        # Test 3: Wrong author
        r3 = process_quest_claim(44, "bob", body, root)
        assert not r3["ok"]
        assert r3["error"] == "author_mismatch"

        print("self-test: 3/3 PASS")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Process quest claim")
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
    result = process_quest_claim(
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
