"""Trade settler — atomic settlement of a two-party signed trade Issue.

Invoked by .github/workflows/trade-settle.yml when both sides have posted
`/accept` comments on a trade-offer Issue.

Protocol (V1)
-------------

1. trade-offer Issue body parsed for:
       offerer_pubkey:        <64-hex>
       counterparty_handle:   <github_handle>
       offering: (textarea)
         <card_id>:<serial-uuid>
         ...
       wanting: (textarea)
         <card_id>:<serial-uuid>
         ...   (no `:any` allowed at settlement — must be resolved already)

2. The two `/accept` comments are expected to contain (in any order):
       /accept
       acceptor_pubkey:     <hex64>
       trade_payload_hash:  <hex64>
       signature:           <hex>

   `trade_payload_hash` is a sha256 over the canonical bytes of:

       {
         "offerer_pubkey":   "...",
         "counterparty_pubkey": "...",
         "offering":  ["card_id:serial", ...],   # sorted lex
         "wanting":   ["card_id:serial", ...],   # sorted lex
         "issue_number": <int>
       }

   The settler recomputes this hash from the Issue body + comments and
   verifies both /accept comments report the SAME hash (byte-identical).

3. Verification:
   - Both signatures verify (ed25519) against their declared
     acceptor_pubkey, signing the trade_payload_hash bytes.
   - Each acceptor_pubkey appears in identities/<handle>.json for the
     handle they claim to be:
       * offerer:       handle = Issue author
       * counterparty:  handle = `counterparty_handle:` from body
   - Each handle currently owns the serials they're transferring per
     arena/collections/<handle>.json.

4. Atomic update on success:
   - Move offered serials  : offerer_collection  → counterparty_collection
   - Move wanted serials   : counterparty_coll   → offerer_collection
   - Write trades/<issue_number>.json with the full receipt + both sigs.
   - The workflow YAML stages all three files into a single commit.

5. Output (single JSON to stdout):
   {
     "ok": true,
     "issue_number":  N,
     "trade_id":      "<sha256>",
     "offerer":       "<handle>",
     "counterparty":  "<handle>",
     "offered":       ["card_id:serial", ...],
     "wanted":        ["card_id:serial", ...],
     "files_written": ["trades/N.json", "collections/A.json", "collections/B.json"]
   }

   {"ok": false, "error": "<reason>", "stage": "parse"|"verify"|"own"}

Side effects
------------
The script *does* write files (collections + trade record). The workflow
YAML is responsible for: git commit + push, posting the Issue comment,
closing the Issue. This is one tier looser than validate_issue.py /
audit_mining.py because the file mutations are intrinsically atomic and
need to happen as one unit; the YAML can't reasonably orchestrate them
across separate scripts.

Self-test
---------
`--self-test` builds two ephemeral identities, two synthetic collections,
and a synthetic trade-offer + two /accept payloads in a temp dir, runs
settle_trade, and asserts the collections moved correctly + the trade
record is signed correctly.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Engine import — same exit-2 convention as audit_mining.py / arbitrate.py.
try:
    from daimon.identity import verify
    from daimon.identity.keys import _seed_to_identity, Identity
except ImportError as e:
    print(json.dumps({"error": f"daimon engine import failed: {e}"}),
          file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Regex / parsing — mirrored from validate_issue.py for consistency
# ---------------------------------------------------------------------------

_KV = re.compile(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.+?)\s*$", re.MULTILINE)
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_CARD_LINE = re.compile(
    r"^([a-z][a-z0-9_]*)\s*:\s*"
    r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s*$"
)


def parse_kv(text: str) -> Dict[str, str]:
    return {m.group(1).lower(): m.group(2) for m in _KV.finditer(text)}


def parse_block(text: str, key: str) -> List[str]:
    pattern = re.compile(
        rf"^{re.escape(key)}\s*:\s*\n((?:(?!^[a-zA-Z_][a-zA-Z0-9_]*\s*:).+\n?)*)",
        re.MULTILINE | re.IGNORECASE,
    )
    m = pattern.search(text)
    if not m:
        return []
    return [line.strip() for line in m.group(1).splitlines() if line.strip()]


def parse_card_lines(lines: List[str]) -> Tuple[List[str], Optional[str]]:
    """Return (sorted-lex `card_id:serial` strings, error)."""
    out: List[str] = []
    for ln in lines:
        m = _CARD_LINE.match(ln)
        if not m:
            return [], f"malformed card line: {ln!r} (must be `card_id:uuid`)"
        out.append(f"{m.group(1)}:{m.group(2).lower()}")
    return sorted(out), None


# ---------------------------------------------------------------------------
# Canonical trade payload + hash
# ---------------------------------------------------------------------------

def trade_payload(*,
                  offerer_pubkey: str,
                  counterparty_pubkey: str,
                  offering: List[str],
                  wanting: List[str],
                  issue_number: int) -> Dict[str, Any]:
    return {
        "offerer_pubkey":      offerer_pubkey.lower(),
        "counterparty_pubkey": counterparty_pubkey.lower(),
        "offering":            sorted(offering),
        "wanting":             sorted(wanting),
        "issue_number":        int(issue_number),
    }


def trade_payload_hash(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------------------
# Identity / collection lookup
# ---------------------------------------------------------------------------

def _load_identity_pubkeys(arena_root: Path,
                           handle: str) -> List[str]:
    p = arena_root / "identities" / f"{handle}.json"
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out = []
    for entry in data.get("pubkeys") or []:
        pk = (entry or {}).get("pubkey_hex", "").lower()
        if pk and len(pk) == 64 and pk != "0" * 64:
            out.append(pk)
    return out


def _load_collection(arena_root: Path,
                     handle: str) -> Dict[str, Any]:
    p = arena_root / "collections" / f"{handle}.json"
    if not p.exists():
        return {"pubkey_hex": None, "serials": []}
    return json.loads(p.read_text(encoding="utf-8"))


def _save_collection(arena_root: Path,
                     handle: str,
                     data: Dict[str, Any]) -> Path:
    p = arena_root / "collections" / f"{handle}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return p


def _serials_owned(coll: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Return {serial_lowercase: serial_record}."""
    return {
        (s.get("serial") or "").lower(): s
        for s in coll.get("serials", [])
        if isinstance(s, dict) and s.get("serial")
    }


# ---------------------------------------------------------------------------
# Settle pipeline
# ---------------------------------------------------------------------------

def parse_accept_comment(body: str) -> Optional[Dict[str, str]]:
    """Return None if not a /accept comment; else {acceptor_pubkey, hash, signature}."""
    if "/accept" not in body.lower():
        return None
    kv = parse_kv(body)
    pk  = kv.get("acceptor_pubkey", "").lower()
    th  = kv.get("trade_payload_hash", "").lower()
    sig = kv.get("signature", "").lower()
    if not (_HEX64.match(pk) and _HEX64.match(th) and sig):
        return None
    return {"acceptor_pubkey": pk, "trade_payload_hash": th, "signature": sig}


def settle(*,
           arena_root: Path,
           issue_number: int,
           offerer_handle: str,
           challenge_body: str,
           accept_bodies: List[str]) -> Dict[str, Any]:
    """Pure settlement — all reads + writes happen here.

    Returns a JSON-able envelope (success or error). Never raises on user
    error — only on infra bugs (which the workflow surfaces as exit 2).
    """
    # --- Parse Issue body -----------------------------------------------
    body_kv = parse_kv(challenge_body)
    offerer_pubkey      = body_kv.get("offerer_pubkey", "").lower()
    counterparty_handle = body_kv.get("counterparty_handle", "").strip()

    if not _HEX64.match(offerer_pubkey):
        return {"ok": False, "stage": "parse",
                "error": "offerer_pubkey missing or not 64-hex"}
    if not counterparty_handle:
        return {"ok": False, "stage": "parse",
                "error": "counterparty_handle missing"}

    offering, err = parse_card_lines(parse_block(challenge_body, "offering"))
    if err:
        return {"ok": False, "stage": "parse", "error": f"offering: {err}"}
    wanting, err = parse_card_lines(parse_block(challenge_body, "wanting"))
    if err:
        return {"ok": False, "stage": "parse", "error": f"wanting: {err}"}

    if not offering or not wanting:
        return {"ok": False, "stage": "parse",
                "error": "offering/wanting must each have ≥1 line"}

    # --- Parse /accept comments -----------------------------------------
    accepts: List[Dict[str, str]] = []
    for b in accept_bodies:
        a = parse_accept_comment(b)
        if a:
            accepts.append(a)

    if len(accepts) < 2:
        return {"ok": False, "stage": "parse",
                "error": f"need 2 /accept comments, found {len(accepts)}"}

    # First two unique acceptors win — protects against double-accept spam.
    seen: Dict[str, Dict[str, str]] = {}
    for a in accepts:
        seen.setdefault(a["acceptor_pubkey"], a)
        if len(seen) == 2:
            break
    if len(seen) < 2:
        return {"ok": False, "stage": "parse",
                "error": "two /accept comments must be from different pubkeys"}
    accept_list = list(seen.values())

    # --- Identify counterparty pubkey from acceptor list ----------------
    a_pks = {a["acceptor_pubkey"] for a in accept_list}
    if offerer_pubkey not in a_pks:
        return {"ok": False, "stage": "verify",
                "error": "offerer did not sign /accept"}
    counterparty_candidates = a_pks - {offerer_pubkey}
    counterparty_pubkey = next(iter(counterparty_candidates))

    # --- Verify identity manifest binding -------------------------------
    offerer_pks      = _load_identity_pubkeys(arena_root, offerer_handle)
    counterparty_pks = _load_identity_pubkeys(arena_root, counterparty_handle)
    if offerer_pubkey not in offerer_pks:
        return {"ok": False, "stage": "verify",
                "error": f"offerer_pubkey not bound to handle {offerer_handle}"}
    if counterparty_pubkey not in counterparty_pks:
        return {"ok": False, "stage": "verify",
                "error": f"counterparty_pubkey not bound to handle {counterparty_handle}"}

    # --- Recompute canonical hash + verify both signatures --------------
    payload = trade_payload(
        offerer_pubkey=offerer_pubkey,
        counterparty_pubkey=counterparty_pubkey,
        offering=offering,
        wanting=wanting,
        issue_number=issue_number,
    )
    expected_hash = trade_payload_hash(payload)

    for a in accept_list:
        if a["trade_payload_hash"] != expected_hash:
            return {"ok": False, "stage": "verify",
                    "error": f"hash mismatch for {a['acceptor_pubkey'][:12]}...: "
                             f"got {a['trade_payload_hash']}, "
                             f"expected {expected_hash}"}
        try:
            sig_bytes = bytes.fromhex(a["signature"])
        except ValueError:
            return {"ok": False, "stage": "verify",
                    "error": f"signature not hex for {a['acceptor_pubkey'][:12]}..."}
        if not verify(a["acceptor_pubkey"],
                      bytes.fromhex(expected_hash),
                      sig_bytes):
            return {"ok": False, "stage": "verify",
                    "error": f"signature failed for {a['acceptor_pubkey'][:12]}..."}

    # --- Ownership check -------------------------------------------------
    off_coll = _load_collection(arena_root, offerer_handle)
    cp_coll  = _load_collection(arena_root, counterparty_handle)
    off_owned = _serials_owned(off_coll)
    cp_owned  = _serials_owned(cp_coll)

    for line in offering:
        serial = line.split(":", 1)[1]
        if serial not in off_owned:
            return {"ok": False, "stage": "own",
                    "error": f"offerer {offerer_handle} does not own serial {serial}"}
    for line in wanting:
        serial = line.split(":", 1)[1]
        if serial not in cp_owned:
            return {"ok": False, "stage": "own",
                    "error": f"counterparty {counterparty_handle} does not own serial {serial}"}

    # --- Atomic transfer (in-memory, then write all three files) --------
    for line in offering:
        serial = line.split(":", 1)[1]
        record = off_owned.pop(serial)
        cp_owned[serial] = record
    for line in wanting:
        serial = line.split(":", 1)[1]
        record = cp_owned.pop(serial)
        off_owned[serial] = record

    off_coll["serials"] = list(off_owned.values())
    cp_coll["serials"]  = list(cp_owned.values())
    off_coll["pubkey_hex"] = offerer_pubkey
    cp_coll["pubkey_hex"]  = counterparty_pubkey

    files_written: List[str] = []

    p1 = _save_collection(arena_root, offerer_handle, off_coll)
    files_written.append(str(p1.relative_to(arena_root)))
    p2 = _save_collection(arena_root, counterparty_handle, cp_coll)
    files_written.append(str(p2.relative_to(arena_root)))

    # Trade receipt
    trade_record = {
        "issue_number":         issue_number,
        "settled_at":           _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "offerer_handle":       offerer_handle,
        "counterparty_handle":  counterparty_handle,
        "offerer_pubkey":       offerer_pubkey,
        "counterparty_pubkey":  counterparty_pubkey,
        "offering":             offering,
        "wanting":              wanting,
        "trade_payload_hash":   expected_hash,
        "signatures":           [
            {"pubkey": a["acceptor_pubkey"], "signature": a["signature"]}
            for a in accept_list
        ],
    }
    trades_dir = arena_root / "trades"
    trades_dir.mkdir(parents=True, exist_ok=True)
    trade_path = trades_dir / f"{issue_number}.json"
    trade_path.write_text(
        json.dumps(trade_record, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    files_written.append(str(trade_path.relative_to(arena_root)))

    return {
        "ok":            True,
        "issue_number":  issue_number,
        "trade_id":      expected_hash,
        "offerer":       offerer_handle,
        "counterparty":  counterparty_handle,
        "offered":       offering,
        "wanted":        wanting,
        "files_written": files_written,
    }


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _ephemeral_identity() -> Identity:
    import secrets as _secrets
    return _seed_to_identity(_secrets.token_bytes(32))


def _seed_collection(arena_root: Path,
                     handle: str,
                     pubkey_hex: str,
                     serials: List[Tuple[str, str]]) -> None:
    coll = {
        "pubkey_hex": pubkey_hex,
        "serials": [
            {
                "serial":     s_uuid,
                "card_id":    cid,
                "pack":       "v1_alpha",
                "rarity":     "rare",
                "minted_at":  "2026-04-25T00:00:00Z",
                "minted_via": "pull",
            }
            for cid, s_uuid in serials
        ],
    }
    p = arena_root / "collections" / f"{handle}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(coll, indent=2) + "\n", encoding="utf-8")


def _seed_identity(arena_root: Path,
                   handle: str,
                   pubkey_hex: str) -> None:
    p = arena_root / "identities" / f"{handle}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({
        "schema_version": 1,
        "github_handle":  handle,
        "pubkeys": [{
            "pubkey_hex":   pubkey_hex,
            "machine_label": "selftest",
            "added_at":     "2026-04-25T00:00:00Z",
        }],
    }) + "\n", encoding="utf-8")


def _run_self_test() -> int:
    failures: List[str] = []

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        # Two ephemeral parties
        alice_id = _ephemeral_identity()
        bob_id   = _ephemeral_identity()

        alice_serial = "11111111-1111-4111-8111-111111111111"
        bob_serial   = "22222222-2222-4222-8222-222222222222"
        offering = [f"voltcat_apex:{alice_serial}"]
        wanting  = [f"tide_empress:{bob_serial}"]

        _seed_identity(root, "alice", alice_id.pubkey_hex)
        _seed_identity(root, "bob",   bob_id.pubkey_hex)
        _seed_collection(root, "alice", alice_id.pubkey_hex,
                         [("voltcat_apex", alice_serial)])
        _seed_collection(root, "bob", bob_id.pubkey_hex,
                         [("tide_empress", bob_serial)])

        challenge_body = (
            f"offerer_pubkey: {alice_id.pubkey_hex}\n"
            f"counterparty_handle: bob\n"
            f"offering:\n  voltcat_apex:{alice_serial}\n"
            f"wanting:\n  tide_empress:{bob_serial}\n"
        )

        # Compute canonical payload hash; both sign it
        payload = trade_payload(
            offerer_pubkey=alice_id.pubkey_hex,
            counterparty_pubkey=bob_id.pubkey_hex,
            offering=offering,
            wanting=wanting,
            issue_number=42,
        )
        h = trade_payload_hash(payload)
        h_bytes = bytes.fromhex(h)

        alice_sig = alice_id.sign_bytes(h_bytes).hex()
        bob_sig   = bob_id.sign_bytes(h_bytes).hex()

        accept_alice = (
            "/accept\n"
            f"acceptor_pubkey: {alice_id.pubkey_hex}\n"
            f"trade_payload_hash: {h}\n"
            f"signature: {alice_sig}\n"
        )
        accept_bob = (
            "/accept\n"
            f"acceptor_pubkey: {bob_id.pubkey_hex}\n"
            f"trade_payload_hash: {h}\n"
            f"signature: {bob_sig}\n"
        )

        # Happy path
        result = settle(
            arena_root=root,
            issue_number=42,
            offerer_handle="alice",
            challenge_body=challenge_body,
            accept_bodies=[accept_alice, accept_bob],
        )
        if not result.get("ok"):
            failures.append(f"happy-path settle failed: {result}")

        # Verify collections moved
        alice_after = _load_collection(root, "alice")
        bob_after   = _load_collection(root, "bob")
        alice_serials = [s["serial"] for s in alice_after["serials"]]
        bob_serials   = [s["serial"] for s in bob_after["serials"]]
        if bob_serial not in alice_serials:
            failures.append("alice didn't receive bob's serial")
        if alice_serial not in bob_serials:
            failures.append("bob didn't receive alice's serial")
        if alice_serial in alice_serials:
            failures.append("alice still has her offered serial")
        if bob_serial in bob_serials:
            failures.append("bob still has his wanted serial")

        # Trade receipt exists
        if not (root / "trades" / "42.json").exists():
            failures.append("trade receipt not written")

        # Reverse-direction tamper test: bob signs a DIFFERENT hash
        with tempfile.TemporaryDirectory() as tmp2:
            root2 = Path(tmp2)
            _seed_identity(root2, "alice", alice_id.pubkey_hex)
            _seed_identity(root2, "bob",   bob_id.pubkey_hex)
            _seed_collection(root2, "alice", alice_id.pubkey_hex,
                             [("voltcat_apex", alice_serial)])
            _seed_collection(root2, "bob", bob_id.pubkey_hex,
                             [("tide_empress", bob_serial)])
            bad_h = "f" * 64
            bad_sig = bob_id.sign_bytes(bytes.fromhex(bad_h)).hex()
            accept_bob_bad = (
                "/accept\n"
                f"acceptor_pubkey: {bob_id.pubkey_hex}\n"
                f"trade_payload_hash: {bad_h}\n"
                f"signature: {bad_sig}\n"
            )
            tamper_result = settle(
                arena_root=root2,
                issue_number=43,
                offerer_handle="alice",
                challenge_body=challenge_body,
                accept_bodies=[accept_alice, accept_bob_bad],
            )
            if tamper_result.get("ok"):
                failures.append(f"tampered hash should have failed: {tamper_result}")
            if tamper_result.get("stage") != "verify":
                failures.append(
                    f"tampered hash should fail at 'verify' stage, "
                    f"got {tamper_result.get('stage')}"
                )

        # Ownership-failure test: alice doesn't actually own the serial.
        # NOTE: signatures must be re-computed for issue_number=44 because
        # the canonical payload includes issue_number — reusing the issue-42
        # signatures here would surface as a verify-stage failure, not an
        # ownership-stage failure (which is what we're testing).
        with tempfile.TemporaryDirectory() as tmp3:
            root3 = Path(tmp3)
            _seed_identity(root3, "alice", alice_id.pubkey_hex)
            _seed_identity(root3, "bob",   bob_id.pubkey_hex)
            _seed_collection(root3, "alice", alice_id.pubkey_hex, [])  # empty
            _seed_collection(root3, "bob", bob_id.pubkey_hex,
                             [("tide_empress", bob_serial)])
            payload44 = trade_payload(
                offerer_pubkey=alice_id.pubkey_hex,
                counterparty_pubkey=bob_id.pubkey_hex,
                offering=offering,
                wanting=wanting,
                issue_number=44,
            )
            h44 = trade_payload_hash(payload44)
            h44_bytes = bytes.fromhex(h44)
            accept_alice_44 = (
                "/accept\n"
                f"acceptor_pubkey: {alice_id.pubkey_hex}\n"
                f"trade_payload_hash: {h44}\n"
                f"signature: {alice_id.sign_bytes(h44_bytes).hex()}\n"
            )
            accept_bob_44 = (
                "/accept\n"
                f"acceptor_pubkey: {bob_id.pubkey_hex}\n"
                f"trade_payload_hash: {h44}\n"
                f"signature: {bob_id.sign_bytes(h44_bytes).hex()}\n"
            )
            own_result = settle(
                arena_root=root3,
                issue_number=44,
                offerer_handle="alice",
                challenge_body=challenge_body,
                accept_bodies=[accept_alice_44, accept_bob_44],
            )
            if own_result.get("ok"):
                failures.append(f"missing-ownership should have failed: {own_result}")
            if own_result.get("stage") != "own":
                failures.append(
                    f"missing-ownership should fail at 'own' stage, "
                    f"got {own_result.get('stage')}"
                )

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 3

    print("settle_trade self-test: OK (happy + tamper + ownership verified)")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Settle a DAIMON arena trade-offer Issue.")
    p.add_argument("--arena-root", type=Path, default=Path("."),
                   help="Path to the arena repo root (default: cwd).")
    p.add_argument("--issue-number", type=int, default=None,
                   help="Trade-offer Issue number.")
    p.add_argument("--offerer-handle", default=None,
                   help="GitHub handle of the Issue author / offerer.")
    p.add_argument("--challenge-body", type=Path, default=None,
                   help="Path to the trade-offer Issue body.")
    p.add_argument("--accept-body", type=Path, action="append", default=[],
                   help="Path to a /accept comment body. Pass twice (one per side).")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)

    if args.self_test:
        return _run_self_test()

    missing = [
        n for n, v in [
            ("--issue-number",    args.issue_number),
            ("--offerer-handle",  args.offerer_handle),
            ("--challenge-body",  args.challenge_body),
        ] if v in (None, "")
    ]
    if missing or len(args.accept_body) < 2:
        print("error: --issue-number, --offerer-handle, --challenge-body, and "
              "two --accept-body args are required (or --self-test)",
              file=sys.stderr)
        return 2

    challenge = args.challenge_body.read_text(encoding="utf-8")
    accepts   = [p.read_text(encoding="utf-8") for p in args.accept_body]

    result = settle(
        arena_root=args.arena_root,
        issue_number=args.issue_number,
        offerer_handle=args.offerer_handle,
        challenge_body=challenge,
        accept_bodies=accepts,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
