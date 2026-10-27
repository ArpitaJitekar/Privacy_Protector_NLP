"""
Context-window matching rules and keyword analyzers.
Analyzes surrounding text to interpret ambiguous tokens, boost detection confidence,
and adjust heuristic risk scores dynamically.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
import re


@dataclass
class ContextMatchResult:
    matched_keywords: List[str]
    context_snippet: str
    risk_adjustment: int        # -1, 0, +1, +2
    context_notes: str
    semantic_intent: Optional[str] = None


# High-sensitivity indicator keywords mapped to semantic categories
SENSITIVE_CONTEXT_KEYWORDS: Dict[str, Set[str]] = {
    "Financial": {
        "salary", "compensation", "wage", "bank account", "routing", "iban", "swift",
        "balance", "credit card", "cvv", "cvc", "pin", "cardholder", "billing",
        "tax return", "w-2", "1099", "net worth", "wire transfer", "payroll"
    },
    "Government Identification": {
        "ssn", "social security", "national id", "aadhaar", "uidai", "pan number",
        "pan card", "passport", "driving license", "driver's license", "voter id",
        "taxpayer id", "citizenship", "green card", "visa number"
    },
    "Medical & Health": {
        "diagnosis", "patient", "prescription", "doctor", "hospital", "clinic",
        "treatment", "health record", "medical condition", "hipaa", "disability",
        "blood group", "insurance claim", "policyholder"
    },
    "Authentication & Security": {
        "password", "secret", "token", "private key", "credential", "auth",
        "passcode", "access key", "api key", "encryption key", "bearer"
    },
    "Demographic & Personal": {
        "dob", "date of birth", "born on", "birthplace", "mother's maiden name",
        "marital status", "gender", "race", "ethnicity", "religion"
    }
}

# Benign or technical keywords that lower suspicion or identify mock/sample data
BENIGN_INDICATOR_KEYWORDS: Set[str] = {
    "sample", "example", "dummy", "placeholder", "test", "demo", "foo", "bar",
    "version", "build", "rfc", "spec", "standard", "template", "schema", "lorem ipsum"
}


class ContextAnalyzer:
    """Performs sliding context-window matching on text around a detected entity."""

    def __init__(self, window_chars: int = 60):
        self.window_chars = window_chars

    def extract_window(self, full_text: str, start: int, end: int) -> Tuple[str, str]:
        """Extracts text within window_chars before and after match, returning (context_str, formatted_snippet)."""
        left_bound = max(0, start - self.window_chars)
        right_bound = min(len(full_text), end + self.window_chars)

        prefix = "..." if left_bound > 0 else ""
        suffix = "..." if right_bound < len(full_text) else ""

        before_str = full_text[left_bound:start]
        matched_str = full_text[start:end]
        after_str = full_text[end:right_bound]

        # Formatted visual snippet highlighting the target
        snippet = f"{prefix}{before_str}[{matched_str}]{after_str}{suffix}"
        surrounding_context = f"{before_str} {after_str}".lower()

        return surrounding_context, snippet

    def analyze_context(self, full_text: str, start: int, end: int, category: str) -> ContextMatchResult:
        """Evaluates surrounding tokens to adjust risk level and provide semantic context."""
        surrounding_context, snippet = self.extract_window(full_text, start, end)

        matched_kw: List[str] = []
        found_categories: List[str] = []
        risk_adjustment = 0
        notes = []

        # 1. Search for sensitive context keywords
        for cat_name, kw_set in SENSITIVE_CONTEXT_KEYWORDS.items():
            for kw in kw_set:
                # Whole-word or boundary match in surrounding context
                pattern = r"\b" + re.escape(kw) + r"\b"
                if re.search(pattern, surrounding_context, re.IGNORECASE):
                    matched_kw.append(kw)
                    if cat_name not in found_categories:
                        found_categories.append(cat_name)

        # 2. Check for benign/sample markers
        is_sample = False
        for benign_kw in BENIGN_INDICATOR_KEYWORDS:
            if re.search(r"\b" + re.escape(benign_kw) + r"\b", surrounding_context, re.IGNORECASE):
                is_sample = True
                notes.append(f"Preceded/followed by non-production keyword '{benign_kw}'")
                risk_adjustment -= 1
                break

        # 3. Assess sensitive keyword impact
        if matched_kw:
            unique_kw = list(dict.fromkeys(matched_kw))
            notes.append(
                f"Surrounding context contains sensitive indicators: {', '.join(unique_kw[:4])} ({', '.join(found_categories)})"
            )
            # High-risk keywords elevate the threat level
            if any(c in found_categories for c in ["Financial", "Authentication & Security", "Medical & Health", "Government Identification"]):
                risk_adjustment += 1
        else:
            notes.append("No explicit sensitive context keywords found in immediate ±60 char window.")

        semantic_label = found_categories[0] if found_categories else None

        return ContextMatchResult(
            matched_keywords=list(dict.fromkeys(matched_kw)),
            context_snippet=snippet,
            risk_adjustment=risk_adjustment,
            context_notes="; ".join(notes),
            semantic_intent=semantic_label
        )
