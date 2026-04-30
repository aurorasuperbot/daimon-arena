"""Issue validator — first-line schema check on every Issue created/edited.

Invoked by .github/workflows/validator.yml on issue.opened / .edited / .reopened.
Fails fast on shape errors so the arbiter, trade-settler, and mining-audit
workflows downstream can assume well-formed Issue bodies.

Templates this script knows about (label-driven, see config below):

  match-challenge:  challenger_pubkey, opponent_handle, loadout_commit, pack_pin?, rule_set?
  trade-offer:      offerer_pubkey, counterparty_handle, offering, wanting, expires_at?
  dispute-appeal:   pubkey, subject, claim, evidence
  card-proposal:    name, stats, triggers, justification (slot is template-ambiguous post-monster-pivot)
  identity:         pubkey_hex, handle, github_username, signed_at, signature, protocol

Validation tiers (most → least strict):
  1. Pubkey hex fields: 64-char ed25519 hex (no 0x prefix, lowercase normalized)
  2. Commit hash fields: 64-char sha256 hex
  3. Owner-formatted card lists (`<card_id>:<serial-uuid>`): per-line parse
  4. Free-form fields (claim, evidence, justification): non-empty + length cap

Output (single JSON to stdout):
  {"label": "valid"|"invalid", "errors": [...], "warnings": [...], "template": "<name>"}

Exit codes:
  0   valid (label = valid)
  0   invalid but not a fatal parsing failure (label = invalid)
  2   could not classify (no recognized template label)
  127 daimon engine import failure (treated as workflow infra bug, not Issue bug)

The workflow then applies the `valid`/`invalid` label and sticky-comments the
first error if invalid. We deliberately keep this script side-effect-free —
all GitHub mutations live in the workflow YAML so the script stays
unit-testable from the CLI.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Body parsing — matches arbitrate.py's regex shape so error messages are
# consistent across workflows.
# ---------------------------------------------------------------------------

_KV = re.compile(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.+?)\s*$", re.MULTILINE)
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_ISO8601 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})$"
)
# `<card_id>:<serial-or-any>` — card_id is `[a-z][a-z0-9_]*`, serial is UUID
# or the literal string `any` (for "any serial of this card_id" wants).
_CARD_LINE = re.compile(
    r"^([a-z][a-z0-9_]*)\s*:\s*"
    r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|any)\s*$"
)


def parse_kv(text: str) -> Dict[str, str]:
    """Extract `key: value` pairs from a body. Last value wins on duplicate."""
    out: Dict[str, str] = {}
    for m in _KV.finditer(text):
        # Skip multi-line textarea values that look like code-fenced lists.
        # Those are parsed separately by the caller via parse_block.
        out[m.group(1).lower()] = m.group(2)
    return out


def parse_block(text: str, key: str) -> List[str]:
    """Extract a multi-line block following `<key>:` (or a textarea field).

    Looks for the pattern:
        <key>:
          line 1
          line 2
        ...

    Returns the list of non-empty lines (whitespace stripped). Stops at the
    next `key:` line or end of text.
    """
    pattern = re.compile(
        rf"^{re.escape(key)}\s*:\s*\n((?:(?!^[a-zA-Z_][a-zA-Z0-9_]*\s*:).+\n?)*)",
        re.MULTILINE | re.IGNORECASE,
    )
    m = pattern.search(text)
    if not m:
        return []
    return [line.strip() for line in m.group(1).splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Per-template validators
# ---------------------------------------------------------------------------

def _check_hex64(value: str, field: str) -> Optional[str]:
    if not _HEX64.match(value or ""):
        return f"{field}: expected 64-char hex (ed25519 pubkey), got {value!r}"
    return None


def _check_handle(value: str, field: str) -> Optional[str]:
    # GitHub handle: alphanumeric + hyphens, 1-39 chars, can't start/end hyphen.
    if not re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$", value or ""):
        return f"{field}: not a valid GitHub handle: {value!r}"
    return None


def _check_iso8601(value: str, field: str) -> Optional[str]:
    if not _ISO8601.match(value or ""):
        return f"{field}: not ISO 8601 datetime: {value!r}"
    return None


def _validate_match_challenge(body: str) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    kv = parse_kv(body)

    for required in ("challenger_pubkey", "opponent_handle", "loadout_commit"):
        if required not in kv:
            errors.append(f"missing required field: {required}")

    if "challenger_pubkey" in kv:
        e = _check_hex64(kv["challenger_pubkey"], "challenger_pubkey")
        if e:
            errors.append(e)

    if "opponent_handle" in kv:
        e = _check_handle(kv["opponent_handle"], "opponent_handle")
        if e:
            errors.append(e)

    if "loadout_commit" in kv:
        e = _check_hex64(kv["loadout_commit"], "loadout_commit")
        if e:
            errors.append(e)

    if "pack_pin" not in kv:
        warnings.append("pack_pin not specified — defaulting to standard-v1.0.0")
    if "rule_set" not in kv:
        warnings.append("rule_set not specified — defaulting to standard-v1")

    return errors, warnings


def _validate_trade_offer(body: str) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    kv = parse_kv(body)

    for required in ("offerer_pubkey", "counterparty_handle"):
        if required not in kv:
            errors.append(f"missing required field: {required}")

    if "offerer_pubkey" in kv:
        e = _check_hex64(kv["offerer_pubkey"], "offerer_pubkey")
        if e:
            errors.append(e)

    if "counterparty_handle" in kv:
        e = _check_handle(kv["counterparty_handle"], "counterparty_handle")
        if e:
            errors.append(e)

    offering = parse_block(body, "offering")
    wanting = parse_block(body, "wanting")
    if not offering:
        errors.append("offering: must list at least one card "
                      "(format `<card_id>:<serial-uuid>`)")
    if not wanting:
        errors.append("wanting: must list at least one card")

    for line in offering:
        if not _CARD_LINE.match(line):
            errors.append(f"offering: malformed line {line!r} "
                          f"(expected `<card_id>:<uuid>` — `any` not allowed offerer-side)")
        elif line.endswith(":any"):
            errors.append(f"offering: must specify exact serials, not `any`: {line!r}")

    for line in wanting:
        if not _CARD_LINE.match(line):
            errors.append(f"wanting: malformed line {line!r} "
                          f"(expected `<card_id>:<uuid>` or `<card_id>:any`)")

    if "expires_at" in kv:
        e = _check_iso8601(kv["expires_at"], "expires_at")
        if e:
            errors.append(e)
    else:
        warnings.append("expires_at not set — offer never auto-closes")

    return errors, warnings


def _validate_dispute_appeal(body: str) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    kv = parse_kv(body)

    for required in ("pubkey", "subject"):
        if required not in kv:
            errors.append(f"missing required field: {required}")

    if "pubkey" in kv:
        e = _check_hex64(kv["pubkey"], "pubkey")
        if e:
            errors.append(e)

    # claim + evidence are textareas, parsed as blocks (anything after the key).
    claim = parse_block(body, "claim") or [kv.get("claim", "")] if kv.get("claim") else []
    evidence = (parse_block(body, "evidence")
                or [kv.get("evidence", "")] if kv.get("evidence") else [])

    if not any(claim):
        errors.append("claim: must be non-empty")
    if not any(evidence):
        errors.append("evidence: must include at least one link or signed payload")

    return errors, warnings


def _validate_identity(body: str) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    kv = parse_kv(body)

    for required in ("pubkey_hex", "handle", "github_username", "signed_at",
                      "signature", "protocol"):
        if required not in kv:
            errors.append(f"missing required field: {required}")

    if "pubkey_hex" in kv:
        e = _check_hex64(kv["pubkey_hex"], "pubkey_hex")
        if e:
            errors.append(e)

    if "signature" in kv:
        sig = kv["signature"].strip()
        if not re.match(r"^[0-9a-fA-F]{128}$", sig):
            errors.append(f"signature: expected 128-char hex (ed25519 sig), got {len(sig)} chars")

    if "signed_at" in kv:
        e = _check_iso8601(kv["signed_at"], "signed_at")
        if e:
            errors.append(e)

    if "protocol" in kv and kv["protocol"].strip() != "daimon-register-v1":
        errors.append(f"protocol: expected daimon-register-v1, got {kv['protocol']!r}")

    return errors, warnings


def _validate_card_proposal(body: str) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    kv = parse_kv(body)

    if "name" not in kv:
        errors.append("missing required field: name")
    if "stats" not in kv:
        errors.append("missing required field: stats")
    else:
        # Format `atk/def/hp/spd` — four ints separated by slashes.
        if not re.match(r"^\s*\d+\s*/\s*\d+\s*/\s*\d+\s*/\s*\d+\s*$",
                        kv["stats"]):
            errors.append(
                f"stats: expected `atk/def/hp/spd` (four ints), got {kv['stats']!r}"
            )

    triggers = parse_block(body, "triggers")
    if not triggers:
        warnings.append("triggers: empty — vanilla card with no abilities")

    justification = parse_block(body, "justification") or (
        [kv["justification"]] if kv.get("justification") else []
    )
    if not any(justification):
        errors.append("justification: must explain design intent (non-empty)")

    return errors, warnings


# ---------------------------------------------------------------------------
# Dispatch — label drives which validator runs
# ---------------------------------------------------------------------------

VALIDATORS = {
    "match-challenge": _validate_match_challenge,
    "trade-offer": _validate_trade_offer,
    "dispute-appeal": _validate_dispute_appeal,
    "card-proposal": _validate_card_proposal,
    "identity": _validate_identity,
}


def validate(body: str, labels: List[str]) -> Dict[str, Any]:
    """Run the matching validator for the Issue's labels.

    Returns the JSON envelope the workflow consumes. Never raises — surface
    errors as `errors=[...]` so the CI step always exits 0 except on truly
    unclassifiable Issues (no recognized label).
    """
    matched_template: Optional[str] = None
    for label in labels:
        if label in VALIDATORS:
            matched_template = label
            break

    if matched_template is None:
        return {
            "label": "skip",
            "errors": [],
            "warnings": [],
            "template": None,
            "skipped_reason": (
                "no recognized template label "
                f"(expected one of: {', '.join(VALIDATORS)})"
            ),
        }

    errors, warnings = VALIDATORS[matched_template](body)

    return {
        "label": "valid" if not errors else "invalid",
        "errors": errors,
        "warnings": warnings,
        "template": matched_template,
    }


# ---------------------------------------------------------------------------
# Self-test — synthetic round-trip proving each template flow.
# ---------------------------------------------------------------------------

def _run_self_test() -> int:
    failures: List[str] = []

    # match-challenge happy path
    happy_match = (
        "challenger_pubkey: " + "a" * 64 + "\n"
        "opponent_handle: alice-bot\n"
        "loadout_commit: " + "b" * 64 + "\n"
        "pack_pin: starter-v1.0.0\n"
        "rule_set: standard-v1\n"
    )
    r = validate(happy_match, ["match-challenge"])
    if r["label"] != "valid":
        failures.append(f"match-challenge happy path failed: {r}")

    # match-challenge missing pubkey
    bad_match = "opponent_handle: alice\nloadout_commit: " + "b" * 64 + "\n"
    r = validate(bad_match, ["match-challenge"])
    if r["label"] != "invalid" or "challenger_pubkey" not in str(r["errors"]):
        failures.append(f"match-challenge bad path failed: {r}")

    # match-challenge bad hex
    short_hex_match = (
        "challenger_pubkey: deadbeef\n"
        "opponent_handle: alice\n"
        "loadout_commit: " + "b" * 64 + "\n"
    )
    r = validate(short_hex_match, ["match-challenge"])
    if r["label"] != "invalid":
        failures.append(f"match-challenge short hex failed: {r}")

    # trade-offer happy path
    happy_trade = (
        "offerer_pubkey: " + "c" * 64 + "\n"
        "counterparty_handle: bob-bot\n"
        "expires_at: 2026-05-01T12:00:00Z\n"
        "offering:\n"
        "  voltcat_apex:550e8400-e29b-41d4-a716-446655440000\n"
        "wanting:\n"
        "  tide_empress:any\n"
    )
    r = validate(happy_trade, ["trade-offer"])
    if r["label"] != "valid":
        failures.append(f"trade-offer happy path failed: {r}")

    # trade-offer with `any` on offering side (not allowed)
    bad_trade = (
        "offerer_pubkey: " + "c" * 64 + "\n"
        "counterparty_handle: bob-bot\n"
        "offering:\n"
        "  voltcat_apex:any\n"
        "wanting:\n"
        "  tide_empress:any\n"
    )
    r = validate(bad_trade, ["trade-offer"])
    if r["label"] != "invalid":
        failures.append(f"trade-offer with `any` on offering side passed: {r}")

    # dispute-appeal happy path
    happy_dispute = (
        "pubkey: " + "d" * 64 + "\n"
        "subject: match-42\n"
        "claim:\n"
        "  The arbiter resolved my reveal as malformed but the signature "
        "verifies locally.\n"
        "evidence:\n"
        "  https://github.com/foo/daimon-arena/issues/42#issuecomment-99\n"
    )
    r = validate(happy_dispute, ["dispute-appeal"])
    if r["label"] != "valid":
        failures.append(f"dispute-appeal happy path failed: {r}")

    # card-proposal happy path
    happy_card = (
        "name: Voltkraken Apex\n"
        "stats: 11/3/16/12\n"
        "triggers:\n"
        "  ON_ATTACK | BUFF_ATK | SELF | 2\n"
        "justification:\n"
        "  Fills the volt-tempo curve at 11 ATK with a self-snowball trigger.\n"
    )
    r = validate(happy_card, ["card-proposal"])
    if r["label"] != "valid":
        failures.append(f"card-proposal happy path failed: {r}")

    # card-proposal bad stats
    bad_card_stats = (
        "name: Foo\n"
        "stats: not-a-stat-line\n"
        "triggers:\n"
        "  ON_ATTACK | BUFF_ATK | SELF | 2\n"
        "justification:\n"
        "  Reasonable.\n"
    )
    r = validate(bad_card_stats, ["card-proposal"])
    if r["label"] != "invalid":
        failures.append(f"card-proposal bad stats accepted: {r}")

    # identity happy path
    happy_identity = (
        "pubkey_hex: " + "a" * 64 + "\n"
        "handle: alice\n"
        "github_username: alice\n"
        "github_id: 12345\n"
        "signed_at: 2026-05-01T00:00:00+00:00\n"
        "signature: " + "b" * 128 + "\n"
        "protocol: daimon-register-v1\n"
    )
    r = validate(happy_identity, ["identity"])
    if r["label"] != "valid":
        failures.append(f"identity happy path failed: {r}")

    # identity missing pubkey
    bad_identity = (
        "handle: alice\n"
        "github_username: alice\n"
        "signed_at: 2026-05-01T00:00:00+00:00\n"
        "signature: " + "b" * 128 + "\n"
        "protocol: daimon-register-v1\n"
    )
    r = validate(bad_identity, ["identity"])
    if r["label"] != "invalid" or "pubkey_hex" not in str(r["errors"]):
        failures.append(f"identity missing pubkey failed: {r}")

    # No recognized label → skip
    r = validate(happy_match, ["bug-report", "needs-triage"])
    if r["label"] != "skip":
        failures.append(f"unrecognized label not skipped: {r}")

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1

    print("validate_issue self-test: OK (10/10 cases passed)")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Validate a DAIMON arena Issue body.")
    p.add_argument("--body-file", type=Path, default=None,
                   help="Path to a file containing the Issue body. - = stdin.")
    p.add_argument("--labels", default="",
                   help="Comma-separated label list from the GH event payload.")
    p.add_argument("--self-test", action="store_true",
                   help="Run synthetic self-test cases and exit.")
    args = p.parse_args(argv)

    if args.self_test:
        return _run_self_test()

    if args.body_file is None:
        print("error: --body-file required (or --self-test)", file=sys.stderr)
        return 2

    if str(args.body_file) == "-":
        body = sys.stdin.read()
    else:
        body = args.body_file.read_text(encoding="utf-8")

    labels = [s.strip() for s in args.labels.split(",") if s.strip()]
    result = validate(body, labels)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
