"""
ULPF Normalization Package.
"""

from ulpf.normalization.normalizer import UniversalNormalizer
from ulpf.normalization.taxonomy import (
    normalize_action,
    normalize_severity,
    normalize_protocol,
    ACTION_TAXONOMY_MAP,
    SEVERITY_TAXONOMY_MAP,
)

__all__ = [
    "UniversalNormalizer",
    "normalize_action",
    "normalize_severity",
    "normalize_protocol",
    "ACTION_TAXONOMY_MAP",
    "SEVERITY_TAXONOMY_MAP",
]
