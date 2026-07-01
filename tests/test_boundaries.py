"""Rule A: audit-ledger is a leaf. It imports no kernel/research/agent/control
layer — only stdlib. (It receives records; it holds no authority.)"""

from __future__ import annotations

import ast
from pathlib import Path

_PKG = Path(__file__).resolve().parent.parent / "audit_ledger"
_FORBIDDEN = {
    "kernel",
    "decision_kernel_core",
    "research",
    "fdk_research",
    "agent_runtime",
    "control_plane",
}


def _modules(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            yield node.module


def test_ledger_imports_only_stdlib() -> None:
    bad = []
    for py in _PKG.rglob("*.py"):
        for mod in _modules(ast.parse(py.read_text(encoding="utf-8"))):
            if mod in _FORBIDDEN or mod.split(".")[0] in _FORBIDDEN:
                bad.append(f"{py.name}: {mod}")
    assert not bad, bad
