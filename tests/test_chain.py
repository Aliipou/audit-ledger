"""Hash-chain tests + conformance to the contracts-spec audit_entry schema."""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest
from jsonschema import Draft202012Validator

from audit_ledger.chain import GENESIS_PREV_HASH, HashChainedAudit, _canonical_hash

_CONTRACTS = pathlib.Path(__file__).resolve().parents[1] / "contracts"


class _A:
    actor, tool, action_purpose, data_labels, session_id = "agent:bot", "send", "support", ("cs",), "s1"


class _D:
    def __init__(self, verdict: str, reason: str) -> None:
        self.verdict = type("V", (), {"value": verdict})()
        self.reason = reason


def _tmp() -> pathlib.Path:
    return pathlib.Path(tempfile.mkdtemp()) / "audit.jsonl"


def _entry_schema() -> Draft202012Validator:
    return Draft202012Validator(json.loads((_CONTRACTS / "audit_entry.schema.json").read_text(encoding="utf-8")))


def test_record_and_verify() -> None:
    log = HashChainedAudit(_tmp())
    for i in range(4):
        log.record(_A(), _D("allow", f"e{i}"), layer="kernel")
    assert log.verify() is True


def test_recorded_entries_conform_to_contract() -> None:
    path = _tmp()
    log = HashChainedAudit(path)
    log.record(_A(), _D("allow", "ok"), layer="kernel")
    log.record(_A(), _D("deny", "nope"), layer="capability")
    val = _entry_schema()
    for line in path.read_text(encoding="utf-8").splitlines():
        val.validate(json.loads(line))


def test_tamper_is_detected() -> None:
    path = _tmp()
    log = HashChainedAudit(path)
    log.record(_A(), _D("allow", "clean"), layer="kernel")
    log.record(_A(), _D("allow", "WIRE $10M"), layer="kernel")
    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["reason"] = "harmless"
    lines[1] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # Reopening a tampered chain REFUSES to resume — the refusal is the detection.
    with pytest.raises(ValueError, match="tampered/corrupt"):
        HashChainedAudit(path)


def test_anchor_detects_in_process_forgery() -> None:
    path = _tmp()
    retained: list[tuple[int, str]] = []
    log = HashChainedAudit(path, anchor=lambda seq, h: retained.append((seq, h)))
    log.record(_A(), _D("allow", "innocuous"), layer="kernel")
    log.record(_A(), _D("allow", "WIRED $10M TO ATTACKER"), layer="kernel")
    anchor_seq, anchor_hash = retained[-1]

    entries = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    kept = [e for e in entries if "ATTACKER" not in e["reason"]]
    prev = GENESIS_PREV_HASH
    forged = []
    for seq, e in enumerate(kept):
        e = dict(e, seq=seq, prev_hash=prev)
        e.pop("entry_hash", None)
        e["entry_hash"] = _canonical_hash(e)
        prev = e["entry_hash"]
        forged.append(e)
    path.write_text("".join(json.dumps(e) + "\n" for e in forged), encoding="utf-8")

    reader = HashChainedAudit(path)
    assert reader.verify() is True  # forgery is internally consistent
    ok, reason = reader.verify_against_anchor(anchor_hash, anchor_seq)
    assert ok is False and "diverges" in reason  # ...but the retained head betrays it
