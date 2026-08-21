# audit-ledger — write-only, tamper-evident traceability

**Live (graph):** [https://ali-audit-ledger.vercel.app](https://ali-audit-ledger.vercel.app)

The accountability layer of the Decision OS. It receives records; it holds **no
authority** (it never emits a Decision). Every kernel decision and executed
effect is appended here, hash-chained, and its head is anchored out-of-process so
tampering is provable.

- **Append-only + hash-chained.** Each entry carries `prev_hash`/`entry_hash`
  (sha256 over canonical JSON); any edit/insert/delete/reorder breaks the chain
  and `verify()` catches it. Entries conform to `contracts-spec` `audit_entry`.
- **Out-of-process notary.** `verify()` alone can't catch an in-process forger
  who rewrites the whole file and recomputes every hash — so the head is
  published to a separate-process append-only notary; `verify_against_anchor`
  then makes the forgery provable. (The honest limits — same-trust-domain, SPOF,
  omission — are the same ones documented in the notary.)
- **Zero runtime dependencies.** Pure stdlib. Migrated from the proven
  authgate-gate implementation (already red-teamed to 0 escapes).

## Shape

```
audit_ledger/
  chain.py    # HashChainedAudit: record / verify / head / anchor / verify_against_anchor
  notary.py   # NotaryServer / NotaryLedger / NotaryClient / make_anchor
contracts/    # vendored, pinned audit_entry schema
tests/        # chain + notary + contract conformance + rule A (imports only stdlib)
```

## Use

```python
from audit_ledger import HashChainedAudit, NotaryClient, make_anchor

log = HashChainedAudit("audit.jsonl", anchor=make_anchor(NotaryClient(host, port, key), "chain-1"))
log.record(action, decision, layer="kernel")   # action/decision are duck-typed
```

Run the notary in a separate trust domain: `python -m audit_ledger.notary`.
