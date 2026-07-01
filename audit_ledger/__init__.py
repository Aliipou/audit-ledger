"""audit-ledger — the write-only, tamper-evident traceability layer.

Append-only, hash-chained decision/effect records (conforming to the
contracts-spec `audit_entry` schema), with an out-of-process notary that anchors
the chain head so an in-process forger who rewrites the local log is caught.

Migrated from the proven authgate-gate implementation; stdlib-only.
"""

from .chain import GENESIS_PREV_HASH, HashChainedAudit
from .notary import NotaryClient, NotaryLedger, NotaryServer, make_anchor

__all__ = [
    "HashChainedAudit",
    "GENESIS_PREV_HASH",
    "NotaryServer",
    "NotaryLedger",
    "NotaryClient",
    "make_anchor",
]
