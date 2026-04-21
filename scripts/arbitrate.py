"""Arbiter — canonical PvP match resolver.

Invoked by .github/workflows/arbiter.yml when a match-challenge Issue has both
players' commit + reveal phases complete. Produces a signed match record and
writes it to matches/<issue_number>.json.

Protocol (commit-reveal, signature-verified):

  1. CHALLENGE: player A opens an Issue with body containing:
       challenger_pubkey:  <hex>
       opponent_handle:    <gh-handle>
       pack_pin:           <oci-tag>
       loadout_commit:     <sha256 of canonical(loadout_a) || nonce_a>

  2. ACCEPT: player B comments "/accept" with body:
       opponent_pubkey:    <hex>
       loadout_commit:     <sha256 of canonical(loadout_b) || nonce_b>

  3. REVEAL: each player posts ONE comment starting with "/reveal" containing:
       loadout:    {...full card list...}
       nonce:      <32-byte hex>
       signature:  <ed25519 signature, hex>

     Signature is over canonical bytes:
       b"nullpoint-pvp-v1\n"
       + str(issue_number).encode()
       + b"\n"
       + canonical(loadout)
       + b"\n"
       + bytes.fromhex(nonce)

     Verified against the player's bound pubkey.

  4. ARBITER:
     - Verify each player's commit hash matches sha256(canonical(loadout) || nonce)
     - Verify each player's signature
     - Derive joint seed:
         sha256(b"nullpoint-pvp-seed-v1\n"
                + str(issue_number).encode() + b"\n"
                + commit_a + b"\n" + commit_b + b"\n"
                + nonce_a + b"\n" + nonce_b)
     - Resolve match deterministically
     - Write matches/<issue_number>.json + update leaderboard.json
     - Return outcome dict (workflow uses this to label the Issue + close it)

Cheat detection:
  - Tier 1 (canonical): the engine output here is definitive.
  - Tier 2 (reputation): if a player commits but never reveals within the
    deadline, the workflow appends a strike to disputes/no-show/<pubkey>.json.
  - Tier 3 (receipt-of-shame): if commit hash or signature verification fails,
    write to disputes/<issue>.json + add to Wall-of-Shame queue.

Local testing:
  python scripts/arbitrate.py --self-test

CI usage:
  python scripts/arbitrate.py \
      --issue-number 42 \
      --challenge-body  challenge.txt \
      --accept-body     accept.txt \
      --reveal-a-body   reveal_a.txt \
      --reveal-b-body   reveal_b.txt \
      --arena-root      .
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# nullpoint engine import — provided by the workflow via pip install or sys.path.
# In tests, we add the sibling nullpoint repo to sys.path before importing.
try:
    from nullpoint.cards import load_card_dict
    from nullpoint.engine import Loadout, resolve_match
    from nullpoint.identity import verify
except ImportError as e:
    print(f"FATAL: nullpoint engine not importable: {e}", file=sys.stderr)
    print("Install with: pip install nullpoint==<pinned-version>", file=sys.stderr)
    sys.exit(127)


PROTOCOL_VERSION = "nullpoint-pvp-v1"
SEED_LABEL = "nullpoint-pvp-seed-v1"


# ---------------------------------------------------------------------------
# Canonical JSON: stable bytes for hashing + signing
# ---------------------------------------------------------------------------

def canonical_json(obj: Any) -> bytes:
    """Stable JSON encoding: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def loadout_commit_hash(loadout_obj: Any, nonce_hex: str) -> str:
    nonce = bytes.fromhex(nonce_hex)
    payload = canonical_json(loadout_obj) + nonce
    return hashlib.sha256(payload).hexdigest()


def signing_payload(issue_number: int, loadout_obj: Any, nonce_hex: str) -> bytes:
    return (
        PROTOCOL_VERSION.encode() + b"\n"
        + str(issue_number).encode() + b"\n"
        + canonical_json(loadout_obj) + b"\n"
        + bytes.fromhex(nonce_hex)
    )


def derive_joint_seed(
    issue_number: int, commit_a: str, commit_b: str, nonce_a: str, nonce_b: str
) -> bytes:
    payload = (
        SEED_LABEL.encode() + b"\n"
        + str(issue_number).encode() + b"\n"
        + commit_a.encode() + b"\n"
        + commit_b.encode() + b"\n"
        + nonce_a.encode() + b"\n"
        + nonce_b.encode()
    )
    return hashlib.sha256(payload).digest()


# ---------------------------------------------------------------------------
# Body parsing — Issues / comments are markdown with key: value pairs
# ---------------------------------------------------------------------------

# Match `key: value` lines (case-insensitive keys).
_KV = re.compile(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.+?)\s*$", re.MULTILINE)
# Match a fenced JSON code block.
_JSON_BLOCK = re.compile(r"```(?:json)?\s*\n(.*?)\n```", re.DOTALL)


def parse_kv(text: str) -> Dict[str, str]:
    """Extract `key: value` pairs from a body. Last value wins on duplicate."""
    out: Dict[str, str] = {}
    for m in _KV.finditer(text):
        out[m.group(1).lower()] = m.group(2)
    return out


def extract_json_block(text: str) -> Optional[Any]:
    """Find first ```json ... ``` block and parse it."""
    m = _JSON_BLOCK.search(text)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Dataclasses for parsed phases
# ---------------------------------------------------------------------------

@dataclass
class Challenge:
    challenger_pubkey: str
    opponent_handle: str
    pack_pin: str
    loadout_commit: str


@dataclass
class Accept:
    opponent_pubkey: str
    loadout_commit: str


@dataclass
class Reveal:
    loadout: Any           # JSON object {"cards": [...]}
    nonce: str             # hex
    signature: str         # hex


@dataclass
class ArbitrationResult:
    ok: bool
    issue_number: int
    winner: Optional[int]            # 0, 1, or None for draw
    reason: str                      # "wipe" / "round_cap" / "draw" / "cheat" / "missing_data"
    side_a_final_hp: int = 0
    side_b_final_hp: int = 0
    round_count: int = 0
    seed_hex: str = ""
    challenger_pubkey: str = ""
    opponent_pubkey: str = ""
    challenger_loadout: Any = None
    opponent_loadout: Any = None
    errors: List[str] = field(default_factory=list)
    timestamp_utc: str = ""

    def to_record(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


# ---------------------------------------------------------------------------
# Phase parsers
# ---------------------------------------------------------------------------

def parse_challenge(body: str) -> Challenge:
    kv = parse_kv(body)
    required = ["challenger_pubkey", "opponent_handle", "pack_pin", "loadout_commit"]
    missing = [k for k in required if k not in kv]
    if missing:
        raise ValueError(f"challenge missing fields: {missing}")
    return Challenge(
        challenger_pubkey=kv["challenger_pubkey"].strip().lower(),
        opponent_handle=kv["opponent_handle"].strip(),
        pack_pin=kv["pack_pin"].strip(),
        loadout_commit=kv["loadout_commit"].strip().lower(),
    )


def parse_accept(body: str) -> Accept:
    kv = parse_kv(body)
    if "opponent_pubkey" not in kv or "loadout_commit" not in kv:
        raise ValueError("accept missing opponent_pubkey or loadout_commit")
    return Accept(
        opponent_pubkey=kv["opponent_pubkey"].strip().lower(),
        loadout_commit=kv["loadout_commit"].strip().lower(),
    )


def parse_reveal(body: str) -> Reveal:
    kv = parse_kv(body)
    loadout = extract_json_block(body)
    if loadout is None:
        raise ValueError("reveal missing fenced JSON loadout block")
    if "nonce" not in kv or "signature" not in kv:
        raise ValueError("reveal missing nonce or signature")
    return Reveal(
        loadout=loadout,
        nonce=kv["nonce"].strip().lower(),
        signature=kv["signature"].strip().lower(),
    )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_phase(
    issue_number: int,
    pubkey: str,
    expected_commit: str,
    reveal: Reveal,
    side_label: str,
) -> List[str]:
    """Returns list of error strings (empty list = OK)."""
    errors: List[str] = []
    actual_commit = loadout_commit_hash(reveal.loadout, reveal.nonce)
    if actual_commit != expected_commit:
        errors.append(
            f"{side_label}: commit hash mismatch "
            f"(expected {expected_commit[:16]}…, got {actual_commit[:16]}…)"
        )

    payload = signing_payload(issue_number, reveal.loadout, reveal.nonce)
    try:
        sig_bytes = bytes.fromhex(reveal.signature)
    except ValueError:
        errors.append(f"{side_label}: signature is not valid hex")
        return errors
    if not verify(pubkey, payload, sig_bytes):
        errors.append(f"{side_label}: signature does not verify against pubkey")
    return errors


def loadout_from_obj(obj: Any) -> Loadout:
    if not isinstance(obj, dict) or "cards" not in obj:
        raise ValueError("loadout must be {'cards': [...]}")
    cards = tuple(load_card_dict(c) for c in obj["cards"])
    return Loadout(cards=cards)


# ---------------------------------------------------------------------------
# Arbitration entry point
# ---------------------------------------------------------------------------

def arbitrate(
    issue_number: int,
    challenge_body: str,
    accept_body: str,
    reveal_a_body: str,
    reveal_b_body: str,
) -> ArbitrationResult:
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    result = ArbitrationResult(
        ok=False, issue_number=issue_number, winner=None, reason="pending",
        timestamp_utc=now,
    )

    # Parse all phases
    try:
        challenge = parse_challenge(challenge_body)
        accept = parse_accept(accept_body)
        reveal_a = parse_reveal(reveal_a_body)
        reveal_b = parse_reveal(reveal_b_body)
    except ValueError as e:
        result.reason = "missing_data"
        result.errors.append(str(e))
        return result

    result.challenger_pubkey = challenge.challenger_pubkey
    result.opponent_pubkey = accept.opponent_pubkey

    # Verify both phases
    errors_a = verify_phase(
        issue_number, challenge.challenger_pubkey, challenge.loadout_commit,
        reveal_a, "side_a",
    )
    errors_b = verify_phase(
        issue_number, accept.opponent_pubkey, accept.loadout_commit,
        reveal_b, "side_b",
    )
    result.errors.extend(errors_a + errors_b)
    if result.errors:
        result.reason = "cheat"
        return result

    # Build loadouts
    try:
        lo_a = loadout_from_obj(reveal_a.loadout)
        lo_b = loadout_from_obj(reveal_b.loadout)
    except (ValueError, TypeError) as e:
        result.reason = "invalid_loadout"
        result.errors.append(str(e))
        return result

    # Derive joint seed (deterministic, neither side can grind)
    seed = derive_joint_seed(
        issue_number,
        challenge.loadout_commit,
        accept.loadout_commit,
        reveal_a.nonce,
        reveal_b.nonce,
    )
    result.seed_hex = seed.hex()

    # Run canonical engine
    match = resolve_match(lo_a, lo_b, seed)
    result.winner = match.winner
    result.reason = match.reason
    result.side_a_final_hp = match.side_a_final_hp
    result.side_b_final_hp = match.side_b_final_hp
    result.round_count = len(match.rounds)
    result.challenger_loadout = reveal_a.loadout
    result.opponent_loadout = reveal_b.loadout
    result.ok = True
    return result


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def write_match_record(arena_root: Path, result: ArbitrationResult) -> Path:
    matches_dir = arena_root / "matches"
    matches_dir.mkdir(exist_ok=True)
    path = matches_dir / f"{result.issue_number}.json"
    path.write_text(json.dumps(result.to_record(), indent=2, sort_keys=True))
    return path


def update_leaderboard(arena_root: Path, result: ArbitrationResult) -> None:
    if not result.ok or result.winner is None:
        return  # draws don't update standings (V1 simple rule)
    lb_path = arena_root / "leaderboard.json"
    if lb_path.exists():
        data = json.loads(lb_path.read_text())
    else:
        data = {"version": 1, "entries": {}}

    entries = data.setdefault("entries", {})
    winner_pk = result.challenger_pubkey if result.winner == 0 else result.opponent_pubkey
    loser_pk = result.opponent_pubkey if result.winner == 0 else result.challenger_pubkey

    for pk, key in [(winner_pk, "wins"), (loser_pk, "losses")]:
        entry = entries.setdefault(pk, {"wins": 0, "losses": 0, "draws": 0})
        entry[key] += 1

    data["last_updated"] = dt.datetime.now(dt.timezone.utc).isoformat()
    lb_path.write_text(json.dumps(data, indent=2, sort_keys=True))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _read_text(path: Optional[str]) -> str:
    if not path:
        return ""
    return Path(path).read_text(encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description="NULLPOINT PvP arbiter")
    p.add_argument("--issue-number", type=int)
    p.add_argument("--challenge-body")
    p.add_argument("--accept-body")
    p.add_argument("--reveal-a-body")
    p.add_argument("--reveal-b-body")
    p.add_argument("--arena-root", default=".")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--no-write", action="store_true",
                   help="Don't write matches/<id>.json or update leaderboard")
    args = p.parse_args()

    if args.self_test:
        return _self_test()

    if not all([args.issue_number, args.challenge_body, args.accept_body,
                args.reveal_a_body, args.reveal_b_body]):
        print("error: all phase arguments required (or --self-test)", file=sys.stderr)
        return 2

    result = arbitrate(
        args.issue_number,
        _read_text(args.challenge_body),
        _read_text(args.accept_body),
        _read_text(args.reveal_a_body),
        _read_text(args.reveal_b_body),
    )

    print(json.dumps(result.to_record(), indent=2, sort_keys=True))

    if not args.no_write and result.ok:
        arena = Path(args.arena_root)
        record_path = write_match_record(arena, result)
        update_leaderboard(arena, result)
        print(f"\nWritten: {record_path}", file=sys.stderr)

    return 0 if result.ok else 1


# ---------------------------------------------------------------------------
# Self-test (for `python scripts/arbitrate.py --self-test` in CI sanity check)
# ---------------------------------------------------------------------------

def _self_test() -> int:
    """Synthetic full-protocol round trip with two ed25519 identities."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    print("Running arbiter self-test...")

    def _make_id(seed_byte: int):
        priv = Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return priv, pub.hex()

    priv_a, pubkey_a = _make_id(0x11)
    priv_b, pubkey_b = _make_id(0x22)

    def _filler(slot: str, suffix: str = "f"):
        return {
            "card_id": f"filler_{slot.lower()}_{suffix}",
            "slot": slot, "atk": 5, "def": 5, "hp": 20, "spd": 5, "triggers": [],
        }

    loadout_a = {"cards": [_filler(s, "A") for s in
                           ["HEAD", "TORSO", "ARM_L", "ARM_R", "LEGS", "CORE"]]}
    loadout_b = {"cards": [_filler(s, "B") for s in
                           ["HEAD", "TORSO", "ARM_L", "ARM_R", "LEGS", "CORE"]]}
    # Make B different so we get a deterministic winner
    loadout_b["cards"][2]["atk"] = 12  # ARM_L crank

    nonce_a = "11" * 32
    nonce_b = "22" * 32
    issue = 999

    commit_a = loadout_commit_hash(loadout_a, nonce_a)
    commit_b = loadout_commit_hash(loadout_b, nonce_b)

    sig_a = priv_a.sign(signing_payload(issue, loadout_a, nonce_a)).hex()
    sig_b = priv_b.sign(signing_payload(issue, loadout_b, nonce_b)).hex()

    challenge_body = f"""challenger_pubkey: {pubkey_a}
opponent_handle: bob
pack_pin: starter-v1.0.0
loadout_commit: {commit_a}
"""
    accept_body = f"""opponent_pubkey: {pubkey_b}
loadout_commit: {commit_b}
"""
    reveal_a_body = f"""nonce: {nonce_a}
signature: {sig_a}

```json
{json.dumps(loadout_a)}
```
"""
    reveal_b_body = f"""nonce: {nonce_b}
signature: {sig_b}

```json
{json.dumps(loadout_b)}
```
"""

    result = arbitrate(issue, challenge_body, accept_body, reveal_a_body, reveal_b_body)
    if not result.ok:
        print(f"FAIL: {result.errors}")
        return 1

    print(f"PASS: winner={result.winner} reason={result.reason} "
          f"hp={result.side_a_final_hp}/{result.side_b_final_hp} "
          f"rounds={result.round_count}")

    # Tamper test: flip a byte in the loadout, expect cheat detection
    tampered = json.loads(json.dumps(loadout_a))
    tampered["cards"][0]["atk"] = 99  # alter after committing
    tampered_reveal = f"""nonce: {nonce_a}
signature: {sig_a}

```json
{json.dumps(tampered)}
```
"""
    result2 = arbitrate(issue, challenge_body, accept_body, tampered_reveal, reveal_b_body)
    if result2.ok or result2.reason != "cheat":
        print(f"FAIL: tamper test should have caught cheating, got ok={result2.ok} "
              f"reason={result2.reason}")
        return 1
    print(f"PASS: tamper detected → {result2.errors[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
