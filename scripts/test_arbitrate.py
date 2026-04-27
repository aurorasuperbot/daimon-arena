"""Tests for the arbiter.

Run from the arena repo root with:
  PYTHONPATH=../daimon pytest scripts/test_arbitrate.py

Or directly without pytest:
  python scripts/test_arbitrate.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure the arbiter module is importable
sys.path.insert(0, str(Path(__file__).parent))

from arbitrate import (
    Reveal,
    arbitrate,
    canonical_json,
    derive_joint_seed,
    extract_json_block,
    loadout_commit_hash,
    parse_accept,
    parse_challenge,
    parse_kv,
    parse_reveal,
    signing_payload,
    update_leaderboard,
    write_match_record,
    verify_phase,
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_id(seed_byte: int):
    priv = Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub.hex()


# V2 monster schema: cards have `species` + `element` (no `slot`). Order in
# the loadout's `cards` list IS the battle position, so we just use position
# in the species name to keep it unique.
_ELEMENTS = ["FIRE", "WATER", "NATURE", "VOLT", "VOID", "NORMAL"]


def filler(position: int, suffix: str = "x"):
    return {
        "card_id": f"filler_{position}_{suffix}",
        "species": f"filler_species_{position}",
        "element": _ELEMENTS[position],
        "atk": 5, "def": 5, "hp": 20, "spd": 5, "triggers": [],
    }


def full_loadout(suffix: str = "x"):
    return {"cards": [filler(i, suffix) for i in range(6)]}


def make_protocol_set(issue: int = 100):
    """Helper: produce a complete valid (challenge, accept, reveal_a, reveal_b) set."""
    priv_a, pub_a = make_id(0xAA)
    priv_b, pub_b = make_id(0xBB)

    lo_a = full_loadout("A")
    lo_b = full_loadout("B")
    lo_b["cards"][2]["atk"] = 12  # asymmetric so we get a winner

    nonce_a, nonce_b = "aa" * 32, "bb" * 32
    commit_a = loadout_commit_hash(lo_a, nonce_a)
    commit_b = loadout_commit_hash(lo_b, nonce_b)
    sig_a = priv_a.sign(signing_payload(issue, lo_a, nonce_a)).hex()
    sig_b = priv_b.sign(signing_payload(issue, lo_b, nonce_b)).hex()

    challenge = (
        f"challenger_pubkey: {pub_a}\n"
        f"opponent_handle: bob\n"
        f"pack_pin: starter-v1.0.0\n"
        f"loadout_commit: {commit_a}\n"
    )
    accept = f"opponent_pubkey: {pub_b}\nloadout_commit: {commit_b}\n"
    # Reveals carry the revealing player's pubkey so the arbiter can match
    # them to the right side regardless of comment arrival order.
    reveal_a = (f"pubkey: {pub_a}\nnonce: {nonce_a}\nsignature: {sig_a}\n\n"
                f"```json\n{json.dumps(lo_a)}\n```\n")
    reveal_b = (f"pubkey: {pub_b}\nnonce: {nonce_b}\nsignature: {sig_b}\n\n"
                f"```json\n{json.dumps(lo_b)}\n```\n")

    return {
        "issue": issue,
        "pub_a": pub_a, "pub_b": pub_b,
        "lo_a": lo_a, "lo_b": lo_b,
        "nonce_a": nonce_a, "nonce_b": nonce_b,
        "commit_a": commit_a, "commit_b": commit_b,
        "sig_a": sig_a, "sig_b": sig_b,
        "challenge": challenge, "accept": accept,
        "reveal_a": reveal_a, "reveal_b": reveal_b,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestParsing(unittest.TestCase):

    def test_parse_kv(self):
        body = "key1: value1\nKEY2: value 2\n  trailing: stuff  \n"
        kv = parse_kv(body)
        self.assertEqual(kv["key1"], "value1")
        self.assertEqual(kv["key2"], "value 2")
        self.assertEqual(kv["trailing"], "stuff")

    def test_extract_json_block(self):
        body = "blah\n```json\n{\"a\": 1}\n```\nmore"
        self.assertEqual(extract_json_block(body), {"a": 1})

    def test_extract_json_block_no_lang(self):
        body = "```\n{\"a\": 1}\n```"
        self.assertEqual(extract_json_block(body), {"a": 1})

    def test_extract_json_block_missing(self):
        self.assertIsNone(extract_json_block("no code blocks here"))

    def test_parse_challenge_complete(self):
        body = ("challenger_pubkey: abc\nopponent_handle: bob\n"
                "pack_pin: starter\nloadout_commit: deadbeef\n")
        c = parse_challenge(body)
        self.assertEqual(c.challenger_pubkey, "abc")
        self.assertEqual(c.pack_pin, "starter")

    def test_parse_challenge_missing_field(self):
        body = "challenger_pubkey: abc\nopponent_handle: bob\n"
        with self.assertRaises(ValueError):
            parse_challenge(body)

    def test_parse_reveal_complete(self):
        body = ("pubkey: deadbeef\nnonce: aabb\nsignature: 1122\n\n"
                "```json\n{\"cards\": []}\n```\n")
        r = parse_reveal(body)
        self.assertEqual(r.pubkey, "deadbeef")
        self.assertEqual(r.nonce, "aabb")
        self.assertEqual(r.signature, "1122")
        self.assertEqual(r.loadout, {"cards": []})

    def test_parse_reveal_no_loadout(self):
        body = "pubkey: aa\nnonce: aabb\nsignature: 1122\n"
        with self.assertRaises(ValueError):
            parse_reveal(body)

    def test_parse_reveal_no_pubkey(self):
        """pubkey is mandatory — required to dispatch reveals to the right
        side under arbitrary comment arrival order."""
        body = ("nonce: aabb\nsignature: 1122\n\n"
                "```json\n{\"cards\": []}\n```\n")
        with self.assertRaises(ValueError):
            parse_reveal(body)


class TestCanonical(unittest.TestCase):

    def test_canonical_json_sorted(self):
        a = canonical_json({"b": 1, "a": 2})
        b = canonical_json({"a": 2, "b": 1})
        self.assertEqual(a, b)

    def test_loadout_commit_deterministic(self):
        lo = full_loadout()
        h1 = loadout_commit_hash(lo, "ab" * 32)
        h2 = loadout_commit_hash(lo, "ab" * 32)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_loadout_commit_changes_with_nonce(self):
        lo = full_loadout()
        self.assertNotEqual(
            loadout_commit_hash(lo, "ab" * 32),
            loadout_commit_hash(lo, "cd" * 32),
        )

    def test_joint_seed_changes_per_issue(self):
        s1 = derive_joint_seed(1, "a", "b", "c", "d")
        s2 = derive_joint_seed(2, "a", "b", "c", "d")
        self.assertNotEqual(s1, s2)
        self.assertEqual(len(s1), 32)


class TestSignatureVerify(unittest.TestCase):

    def test_valid_signature_passes(self):
        priv, pub = make_id(0x55)
        lo = full_loadout()
        nonce = "55" * 32
        commit = loadout_commit_hash(lo, nonce)
        sig = priv.sign(signing_payload(7, lo, nonce)).hex()
        reveal = Reveal(loadout=lo, nonce=nonce, signature=sig)
        errors = verify_phase(7, pub, commit, reveal, "test")
        self.assertEqual(errors, [])

    def test_wrong_pubkey_fails(self):
        priv, _ = make_id(0x55)
        _, wrong_pub = make_id(0x56)
        lo = full_loadout()
        nonce = "55" * 32
        commit = loadout_commit_hash(lo, nonce)
        sig = priv.sign(signing_payload(7, lo, nonce)).hex()
        reveal = Reveal(loadout=lo, nonce=nonce, signature=sig)
        errors = verify_phase(7, wrong_pub, commit, reveal, "test")
        self.assertTrue(any("signature" in e for e in errors))

    def test_replay_to_different_issue_fails(self):
        priv, pub = make_id(0x55)
        lo = full_loadout()
        nonce = "55" * 32
        commit = loadout_commit_hash(lo, nonce)
        sig = priv.sign(signing_payload(7, lo, nonce)).hex()
        # Replay sig from issue 7 against issue 8
        reveal = Reveal(loadout=lo, nonce=nonce, signature=sig)
        errors = verify_phase(8, pub, commit, reveal, "test")
        self.assertTrue(any("signature" in e for e in errors))


class TestArbitrate(unittest.TestCase):

    def test_happy_path_produces_winner(self):
        s = make_protocol_set(issue=42)
        result = arbitrate(s["issue"], s["challenge"], s["accept"],
                           s["reveal_a"], s["reveal_b"])
        self.assertTrue(result.ok)
        self.assertIn(result.winner, [0, 1, None])
        self.assertEqual(len(result.errors), 0)
        self.assertEqual(len(result.seed_hex), 64)

    def test_deterministic_across_runs(self):
        s = make_protocol_set(issue=42)
        r1 = arbitrate(s["issue"], s["challenge"], s["accept"],
                       s["reveal_a"], s["reveal_b"])
        r2 = arbitrate(s["issue"], s["challenge"], s["accept"],
                       s["reveal_a"], s["reveal_b"])
        self.assertEqual(r1.winner, r2.winner)
        self.assertEqual(r1.side_a_final_hp, r2.side_a_final_hp)
        self.assertEqual(r1.seed_hex, r2.seed_hex)

    def test_tampered_loadout_caught(self):
        s = make_protocol_set(issue=42)
        # Modify loadout in reveal but keep old signature — sig won't verify
        # AND commit hash won't match. Pubkey stays correct so the reveal
        # routes to side A; the verification step is what catches the tamper.
        bad_lo = json.loads(json.dumps(s["lo_a"]))
        bad_lo["cards"][0]["atk"] = 999
        bad_reveal = (f"pubkey: {s['pub_a']}\nnonce: {s['nonce_a']}\n"
                      f"signature: {s['sig_a']}\n\n"
                      f"```json\n{json.dumps(bad_lo)}\n```\n")
        result = arbitrate(s["issue"], s["challenge"], s["accept"],
                           bad_reveal, s["reveal_b"])
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "cheat")
        self.assertTrue(any("commit hash" in e for e in result.errors))

    def test_missing_phase_data_returns_missing(self):
        result = arbitrate(99, "garbage body", "", "", "")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "missing_data")

    def test_reveals_in_swapped_order_resolve_identically(self):
        """The arbiter dispatches reveals to sides by embedded pubkey, so
        responder revealing first must produce the same outcome.

        This is the property that makes the engine ↔ arbiter contract safe
        under GitHub's lack of comment-arrival ordering guarantees.
        """
        s = make_protocol_set(issue=42)
        canonical = arbitrate(s["issue"], s["challenge"], s["accept"],
                              s["reveal_a"], s["reveal_b"])
        swapped = arbitrate(s["issue"], s["challenge"], s["accept"],
                            s["reveal_b"], s["reveal_a"])
        self.assertTrue(canonical.ok)
        self.assertTrue(swapped.ok)
        self.assertEqual(canonical.winner, swapped.winner)
        self.assertEqual(canonical.seed_hex, swapped.seed_hex)
        self.assertEqual(canonical.side_a_final_hp, swapped.side_a_final_hp)
        self.assertEqual(canonical.side_b_final_hp, swapped.side_b_final_hp)

    def test_reveal_with_unknown_pubkey_is_cheat(self):
        """A reveal whose pubkey doesn't match either side is a cheat."""
        s = make_protocol_set(issue=42)
        # Build a reveal carrying a third pubkey unrelated to the match.
        priv_c, pub_c = make_id(0xCC)
        lo = full_loadout("C")
        nonce_c = "cc" * 32
        sig_c = priv_c.sign(signing_payload(s["issue"], lo, nonce_c)).hex()
        rogue = (f"pubkey: {pub_c}\nnonce: {nonce_c}\nsignature: {sig_c}\n\n"
                 f"```json\n{json.dumps(lo)}\n```\n")
        result = arbitrate(s["issue"], s["challenge"], s["accept"],
                           s["reveal_a"], rogue)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "cheat")
        self.assertTrue(any("does not match" in e for e in result.errors))

    def test_two_reveals_from_same_pubkey_is_cheat(self):
        """Replaying the same reveal twice (e.g. as a DoS) is detected."""
        s = make_protocol_set(issue=42)
        result = arbitrate(s["issue"], s["challenge"], s["accept"],
                           s["reveal_a"], s["reveal_a"])
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "cheat")
        self.assertTrue(
            any("two reveals" in e for e in result.errors))

    def test_only_one_reveal_returns_missing_data(self):
        """If only one side reveals, missing_data — not cheat."""
        s = make_protocol_set(issue=42)
        # Pass the same body twice: first revealer will be matched, second
        # will collide (cheat) — so test missing case using empty body.
        # An empty body will fail parse_reveal first, surfacing missing_data.
        result = arbitrate(s["issue"], s["challenge"], s["accept"],
                           s["reveal_a"], "")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "missing_data")

    def test_seed_differs_per_issue(self):
        s_a = make_protocol_set(issue=1)
        s_b = make_protocol_set(issue=2)
        # Same identities/loadouts/nonces, different issue → different seed → different game
        # (NB: identical because nonces are deterministic in helper, only issue differs)
        r1 = arbitrate(s_a["issue"], s_a["challenge"], s_a["accept"],
                       s_a["reveal_a"], s_a["reveal_b"])
        r2 = arbitrate(s_b["issue"], s_b["challenge"], s_b["accept"],
                       s_b["reveal_a"], s_b["reveal_b"])
        # Wait — issues are different so signatures will be different too
        # Just assert seeds differ
        self.assertNotEqual(r1.seed_hex, r2.seed_hex)


class TestPersistence(unittest.TestCase):

    def test_write_match_record(self):
        s = make_protocol_set(issue=77)
        result = arbitrate(s["issue"], s["challenge"], s["accept"],
                           s["reveal_a"], s["reveal_b"])
        with tempfile.TemporaryDirectory() as tmp:
            arena = Path(tmp)
            path = write_match_record(arena, result)
            self.assertTrue(path.exists())
            self.assertEqual(path.name, "77.json")
            data = json.loads(path.read_text())
            self.assertEqual(data["issue_number"], 77)
            self.assertEqual(data["ok"], True)

    def test_update_leaderboard_creates_file(self):
        s = make_protocol_set(issue=77)
        result = arbitrate(s["issue"], s["challenge"], s["accept"],
                           s["reveal_a"], s["reveal_b"])
        # Force a winner (might already be one, but let's not depend on it)
        if result.winner is None:
            self.skipTest("happened to be a draw, can't test leaderboard update")
        with tempfile.TemporaryDirectory() as tmp:
            arena = Path(tmp)
            update_leaderboard(arena, result)
            lb_path = arena / "leaderboard.json"
            self.assertTrue(lb_path.exists())
            data = json.loads(lb_path.read_text())
            self.assertIn("entries", data)
            self.assertEqual(len(data["entries"]), 2)
            wins = sum(e["wins"] for e in data["entries"].values())
            losses = sum(e["losses"] for e in data["entries"].values())
            self.assertEqual(wins, 1)
            self.assertEqual(losses, 1)
            # Settled-match guard recorded the issue number.
            self.assertEqual(data.get("settled_match_ids"), [77])

    def test_update_leaderboard_idempotent_on_replay(self):
        """Calling update_leaderboard N times for the same match must
        produce identical standings — the live arbiter workflow can fire
        multiple concurrent runs (one per issue_comment), and even with
        the concurrency group landed in arbiter.yml, idempotency at this
        layer is the canonical guarantee that double-counting is
        impossible."""
        s = make_protocol_set(issue=88)
        result = arbitrate(s["issue"], s["challenge"], s["accept"],
                           s["reveal_a"], s["reveal_b"])
        if result.winner is None:
            self.skipTest("draw — can't exercise standings idempotency")
        with tempfile.TemporaryDirectory() as tmp:
            arena = Path(tmp)
            update_leaderboard(arena, result)
            update_leaderboard(arena, result)
            update_leaderboard(arena, result)
            data = json.loads((arena / "leaderboard.json").read_text())
            wins = sum(e["wins"] for e in data["entries"].values())
            losses = sum(e["losses"] for e in data["entries"].values())
            self.assertEqual(wins, 1)
            self.assertEqual(losses, 1)
            self.assertEqual(data["settled_match_ids"], [88])

    def test_update_leaderboard_distinct_matches_accumulate(self):
        """Idempotency keys on issue_number — DIFFERENT matches must still
        accumulate. Catches the bug where someone overgeneralizes the
        guard to "skip if any match settled" or "skip if pubkeys present"."""
        s1 = make_protocol_set(issue=10)
        r1 = arbitrate(s1["issue"], s1["challenge"], s1["accept"],
                       s1["reveal_a"], s1["reveal_b"])
        s2 = make_protocol_set(issue=20)
        r2 = arbitrate(s2["issue"], s2["challenge"], s2["accept"],
                       s2["reveal_a"], s2["reveal_b"])
        if r1.winner is None or r2.winner is None:
            self.skipTest("draw — can't exercise distinct-match accumulation")
        with tempfile.TemporaryDirectory() as tmp:
            arena = Path(tmp)
            update_leaderboard(arena, r1)
            update_leaderboard(arena, r2)
            data = json.loads((arena / "leaderboard.json").read_text())
            # Each match is its own row of (1 win + 1 loss). The two matches
            # use different pubkey pairs (different identities seeded per
            # protocol set), so cumulative totals are 2 wins / 2 losses.
            wins = sum(e["wins"] for e in data["entries"].values())
            losses = sum(e["losses"] for e in data["entries"].values())
            self.assertEqual(wins, 2)
            self.assertEqual(losses, 2)
            self.assertEqual(sorted(data["settled_match_ids"]), [10, 20])

    def test_write_match_record_idempotent_same_content(self):
        s = make_protocol_set(issue=99)
        result = arbitrate(s["issue"], s["challenge"], s["accept"],
                           s["reveal_a"], s["reveal_b"])
        with tempfile.TemporaryDirectory() as tmp:
            arena = Path(tmp)
            p1 = write_match_record(arena, result)
            mtime1 = p1.stat().st_mtime_ns
            content1 = p1.read_text()
            # Second call must not raise; must NOT rewrite.
            p2 = write_match_record(arena, result)
            self.assertEqual(p1, p2)
            self.assertEqual(p2.read_text(), content1)

    def test_write_match_record_refuses_to_overwrite_diff(self):
        """Append-only history: a match-record file on disk is law. If
        someone tries to settle the same issue with different content
        (cheat / arbiter drift), this MUST blow up loudly."""
        s = make_protocol_set(issue=55)
        result = arbitrate(s["issue"], s["challenge"], s["accept"],
                           s["reveal_a"], s["reveal_b"])
        with tempfile.TemporaryDirectory() as tmp:
            arena = Path(tmp)
            write_match_record(arena, result)
            # Surgically change the file to simulate drift.
            path = arena / "matches" / "55.json"
            path.write_text(path.read_text().replace('"ok": true',
                                                     '"ok": false'))
            with self.assertRaises(RuntimeError):
                write_match_record(arena, result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
