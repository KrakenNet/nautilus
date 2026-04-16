"""Nautilus intent analysis subpackage — design §3.3."""

from nautilus.analysis.base import IntentAnalyzer
from nautilus.analysis.fallback import FallbackIntentAnalyzer, FallbackMode
from nautilus.analysis.pattern_matching import PatternMatchingIntentAnalyzer

__all__ = [
    "FallbackIntentAnalyzer",
    "FallbackMode",
    "IntentAnalyzer",
    "PatternMatchingIntentAnalyzer",
]
