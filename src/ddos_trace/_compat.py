"""Compatibility helpers for older Python runtimes."""

try:
    from dataclasses import dataclass, field
except ImportError:  # pragma: no cover - Python 3.6 fallback
    from dataclasses import dataclass, field  # type: ignore

__all__ = ["dataclass", "field"]
