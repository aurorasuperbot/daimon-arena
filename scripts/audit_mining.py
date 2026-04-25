"""Mining audit — verify every published ledger in arena/mining/ daily.

Invoked by .github/workflows/mining-audit.yml on a 04:17 UTC cron.

What it does
------------
Each agent that opts into the public ledger publishes their full
hash-chained mining ledger to:

    arena/mining/<github_handle>/ledger.jsonl

The audit walks every such file, looks up the canonical pubkey for that
handle in `arena/identities/<github_handle>.json`, and runs the canonical
`daimon.mining.ledger.verify_ledger()` against the file with that pubkey
pinned. That single call:

  - Re-derives the prev_hash chain from genesis.
  - Verifies every entry's ed25519 signature.
  - Confirms every entry was signed by the expected pubkey (not just
    *any* pubkey from the identity manifest's history).

Output (single JSON to stdout)
------------------------------
    {
      "audited":   N,                   # ledger files inspected
      "ok":        [handle, ...],
      "failed":    [{handle, errors:[...], first_bad_index, entries}],
      "skipped":   [{handle, reason}],  # missing identity, no canonical pubkey, etc.
      "audited_at": "<rfc3339>"
    }

Exit codes
----------
    0   audit completed (clean OR found anomalies — both are "ran successfully")
    2   infra failure (couldn't import daimon engine, couldn't read root)
    3   --self-test failed

Side effects
------------
None. The Python script is read-only. Workflow YAML is responsible for:
  - filing dispute Issues for failures
  - updating Wall-of-Shame.md
  - committing audit log entries

This boundary is the same as validate_issue.py / arbitrate.py — the
script returns a JSON envelope; the workflow does GitHub mutations.

Self-test
---------
`--self-test` synthesizes a tiny ledger with a fresh identity, writes it
to a temp dir, and runs the full audit pipeline against it. Proves the
script is wired correctly to the engine even when no real data exists.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

# Import the engine. If it's missing, the workflow caller treats it as
# infra failure (exit 2) — same convention as arbitrate.py.
try:
    from daimon.mining.ledger import (
        verify_ledger,
        initialize_ledger,
        append_mine_entry,
    )
    from daimon.identity.keys import _seed_to_identity, Identity
except ImportError as e:
    print(json.dumps({"error": f"daimon engine import failed: {e}"}),
          file=sys.stderr)
    sys.exit(2)


def _ephemeral_identity() -> Identity:
    """Build a one-shot in-memory Identity for self-test use.

    `generate_identity()` writes private-key bytes to ``~/.config/daimon/``
    which we must NOT do during a CI audit run. This bypass produces a
    pristine ed25519 keypair with no on-disk side effects, suitable for
    signing temp-dir ledger entries and then being discarded.
    """
    import secrets as _secrets
    return _seed_to_identity(_secrets.token_bytes(32))


# ---------------------------------------------------------------------------
# Identity lookup
# ---------------------------------------------------------------------------

def _load_identity_manifest(identities_dir: Path,
                            handle: str) -> Optional[Dict[str, Any]]:
    """Read arena/identities/<handle>.json. Returns None if missing/invalid."""
    p = identities_dir / f"{handle}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _canonical_pubkey(manifest: Dict[str, Any]) -> Optional[str]:
    """Pick the canonical signing pubkey from an identity manifest.

    For V1 we accept any pubkey listed in the manifest's `pubkeys` array
    that has a non-empty `pubkey_hex`. The first such entry wins — matches
    `daimon.identity.keys.load_identity()` which always uses the primary
    machine identity.

    Future (V1.2): rotate based on `added_at` + revocation list.
    """
    pubs = manifest.get("pubkeys") or []
    for entry in pubs:
        pk = (entry or {}).get("pubkey_hex", "").lower()
        if pk and len(pk) == 64 and all(c in "0123456789abcdef" for c in pk):
            # Skip the EXAMPLE template's all-zeros pubkey.
            if pk == "0" * 64:
                continue
            return pk
    return None


# ---------------------------------------------------------------------------
# Audit core
# ---------------------------------------------------------------------------

def audit_root(arena_root: Path) -> Dict[str, Any]:
    """Run verify_ledger() across every published handle ledger.

    Layout assumed:
        arena_root/mining/<handle>/ledger.jsonl
        arena_root/identities/<handle>.json

    Handles without an identity manifest are SKIPPED (not failed) — the
    arena rejects unbound publications at submission time, so a missing
    manifest at audit time means the publication is stale or in-flight.
    """
    mining_dir     = arena_root / "mining"
    identities_dir = arena_root / "identities"
    ok:      List[str]                    = []
    failed:  List[Dict[str, Any]]         = []
    skipped: List[Dict[str, Any]]         = []

    if not mining_dir.exists():
        return {
            "audited":    0,
            "ok":         [],
            "failed":     [],
            "skipped":    [],
            "audited_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "note":       "mining/ directory not present",
        }

    # Walk one level: mining/<handle>/ledger.jsonl
    handles = sorted(
        p.name for p in mining_dir.iterdir()
        if p.is_dir() and not p.name.startswith(".")
    )
    audited = 0
    for handle in handles:
        ledger_path = mining_dir / handle / "ledger.jsonl"
        if not ledger_path.exists():
            skipped.append({"handle": handle, "reason": "no ledger.jsonl"})
            continue

        manifest = _load_identity_manifest(identities_dir, handle)
        if manifest is None:
            skipped.append({"handle": handle, "reason": "no identity manifest"})
            continue

        canonical_pk = _canonical_pubkey(manifest)
        if canonical_pk is None:
            skipped.append(
                {"handle": handle, "reason": "no usable pubkey in manifest"}
            )
            continue

        audited += 1
        result = verify_ledger(ledger_path, expected_pubkey_hex=canonical_pk)
        if result.get("ok"):
            ok.append(handle)
        else:
            failed.append({
                "handle":          handle,
                "errors":          result.get("errors", []),
                "first_bad_index": result.get("first_bad_index", -1),
                "entries":         result.get("entries", 0),
            })

    return {
        "audited":    audited,
        "ok":         ok,
        "failed":     failed,
        "skipped":    skipped,
        "audited_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _run_self_test() -> int:
    """Synthesize a 3-entry signed ledger + identity manifest in a temp arena
    and prove the auditor reports it as `ok`. Then tamper with the ledger
    and prove the auditor reports it as `failed`.
    """
    failures: List[str] = []

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        mining_dir = root / "mining" / "audit_selftest_handle"
        ident_dir  = root / "identities"
        mining_dir.mkdir(parents=True)
        ident_dir.mkdir(parents=True)

        # 1. Build a real signed ledger with a fresh in-memory identity.
        identity = _ephemeral_identity()
        ledger_path = mining_dir / "ledger.jsonl"

        initialize_ledger(identity=identity, path=ledger_path)
        append_mine_entry(
            identity=identity,
            tool_name="self_test",
            factors={"base": 1},
            amount=5,
            novelty_key="selftest_1",
            path=ledger_path,
        )
        append_mine_entry(
            identity=identity,
            tool_name="self_test",
            factors={"base": 1},
            amount=7,
            novelty_key="selftest_2",
            path=ledger_path,
        )

        # 2. Write a matching identity manifest.
        manifest_path = ident_dir / "audit_selftest_handle.json"
        manifest_path.write_text(json.dumps({
            "schema_version": 1,
            "github_handle":  "audit_selftest_handle",
            "pubkeys": [{
                "pubkey_hex":   identity.pubkey_hex,
                "machine_label": "selftest",
                "added_at":     "2026-04-25T00:00:00Z",
            }],
        }))

        # 3. Run the auditor — expect clean.
        clean = audit_root(root)
        if "audit_selftest_handle" not in clean["ok"]:
            failures.append(
                f"clean audit didn't list handle as ok: {clean}"
            )
        if clean["failed"]:
            failures.append(f"clean audit reported failures: {clean['failed']}")

        # 4. Tamper: flip a byte in entry 1's amount field.
        lines = ledger_path.read_text(encoding="utf-8").splitlines()
        if len(lines) >= 2:
            tampered = lines[1].replace('"amount":5', '"amount":500')
            if tampered != lines[1]:
                lines[1] = tampered
                ledger_path.write_text("\n".join(lines) + "\n",
                                       encoding="utf-8")

        # 5. Run again — expect failed.
        dirty = audit_root(root)
        bad = [f for f in dirty["failed"]
               if f["handle"] == "audit_selftest_handle"]
        if not bad:
            failures.append(
                f"tampered audit didn't list handle as failed: {dirty}"
            )

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 3

    print("audit_mining self-test: OK (clean + tamper-detect verified)")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Audit DAIMON mining ledgers in an arena root.")
    p.add_argument("--arena-root", type=Path, default=Path("."),
                   help="Path to the arena repo root (default: cwd).")
    p.add_argument("--self-test", action="store_true",
                   help="Run synthetic self-test cases and exit.")
    args = p.parse_args(argv)

    if args.self_test:
        return _run_self_test()

    if not args.arena_root.exists():
        print(json.dumps({"error": f"arena root not found: {args.arena_root}"}),
              file=sys.stderr)
        return 2

    result = audit_root(args.arena_root)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
