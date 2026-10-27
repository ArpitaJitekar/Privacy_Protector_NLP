"""
Heuristic risk scoring engine for documents.
Calculates transparent 0-100 risk score based on finding severity, volume,
category diversity, and context exposure hazards.
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple
import math


RISK_TIERS = {
    "Low": {"color": "#10B981", "badge": "🟢 Low Risk", "min": 0, "max": 25},
    "Medium": {"color": "#F59E0B", "badge": "🟡 Medium Risk", "min": 26, "max": 55},
    "High": {"color": "#EF4444", "badge": "🟠 High Risk", "min": 56, "max": 79},
    "Critical": {"color": "#7F1D1D", "badge": "🔴 Critical Risk", "min": 80, "max": 100},
}

SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]

SEVERITY_WEIGHTS = {
    "Low": 15,
    "Medium": 35,
    "High": 70,
    "Critical": 95,
}


@dataclass
class Finding:
    category: str
    raw_value: str
    masked_value: str
    risk_level: str           # "Low", "Medium", "High", "Critical"
    numerical_risk: int       # 0 - 100
    location: str             # e.g., "Page 1, Line 3"
    reason: str               # Reason for detection
    context_snippet: str      # Visual surrounding context
    context_notes: str        # Explanation of context matching
    recommendation: str       # Specific action for this finding


@dataclass
class DocumentRiskSummary:
    total_findings: int
    total_categories: int
    risk_score: int           # 0 to 100
    risk_tier: str            # "Low", "Medium", "High", "Critical"
    category_counts: Dict[str, int]
    severity_counts: Dict[str, int]
    recommendations: List[str]
    exposure_summary: str


class RiskScorer:
    """Computes transparent heuristic risk scores and recommendations."""

    @staticmethod
    def adjust_finding_severity(base_risk: str, risk_adj: int) -> str:
        """Adjusts finding severity by -1, 0, +1 based on context analysis."""
        idx = SEVERITY_LEVELS.index(base_risk) if base_risk in SEVERITY_LEVELS else 1
        new_idx = max(0, min(len(SEVERITY_LEVELS) - 1, idx + risk_adj))
        return SEVERITY_LEVELS[new_idx]

    @classmethod
    def calculate_document_risk(cls, findings: List[Finding]) -> DocumentRiskSummary:
        """Computes comprehensive score, category breakdown, and prescriptive remediation."""
        if not findings:
            return DocumentRiskSummary(
                total_findings=0,
                total_categories=0,
                risk_score=0,
                risk_tier="Low",
                category_counts={},
                severity_counts={"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
                recommendations=["No sensitive personal data patterns were detected in this document."],
                exposure_summary="Clean document. No structured PII or sensitive identifiers identified."
            )

        category_counts: Dict[str, int] = {}
        severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}

        for f in findings:
            category_counts[f.category] = category_counts.get(f.category, 0) + 1
            severity_counts[f.risk_level] = severity_counts.get(f.risk_level, 0) + 1

        # Heuristic scoring components:
        # 1. Base anchor from peak severity found
        max_severity = "Low"
        for s in reversed(SEVERITY_LEVELS):
            if severity_counts.get(s, 0) > 0:
                max_severity = s
                break
        peak_weight = SEVERITY_WEIGHTS[max_severity]

        # 2. Cumulative weighted findings score with logarithmic damping
        weighted_sum = sum(SEVERITY_WEIGHTS.get(f.risk_level, 20) for f in findings)
        volume_factor = min(35.0, 10.0 * math.log2(1 + len(findings)))

        # 3. Category diversity penalty: Cross-referencing risk rises with diverse data types
        cat_count = len(category_counts)
        diversity_bonus = min(20.0, (cat_count - 1) * 5.0) if cat_count > 1 else 0.0

        # Blended raw score
        # 50% peak finding weight + 30% volume curve + 20% diversity
        raw_score = (0.50 * peak_weight) + (0.35 * volume_factor) + (0.15 * diversity_bonus * 2.5)

        # High-impact escalations
        if severity_counts["Critical"] > 0:
            raw_score = max(raw_score, 80.0)
        elif severity_counts["High"] >= 2:
            raw_score = max(raw_score, 65.0)

        final_score = int(min(100, max(0, round(raw_score))))

        # Determine Tier
        if final_score <= 25:
            tier = "Low"
        elif final_score <= 55:
            tier = "Medium"
        elif final_score <= 79:
            tier = "High"
        else:
            tier = "Critical"

        # Generate action-oriented recommendations
        recommendations = cls._generate_recommendations(category_counts, severity_counts, final_score)
        summary_text = cls._generate_exposure_summary(findings, final_score, tier)

        return DocumentRiskSummary(
            total_findings=len(findings),
            total_categories=len(category_counts),
            risk_score=final_score,
            risk_tier=tier,
            category_counts=category_counts,
            severity_counts=severity_counts,
            recommendations=recommendations,
            exposure_summary=summary_text
        )

    @staticmethod
    def _generate_recommendations(
        cat_counts: Dict[str, int],
        sev_counts: Dict[str, int],
        score: int
    ) -> List[str]:
        recs = []

        if any("Card" in c or "Financial" in c for c in cat_counts):
            recs.append("CRITICAL: Payment card data detected. Mask immediately to 4 trailing digits per PCI-DSS standards; ensure no CVV or PAN is stored in plaintext.")

        if any("Secret" in c or "Key" in c for c in cat_counts):
            recs.append("CRITICAL: Authentication credentials/tokens found. Revoke immediately, invalidate sessions, and implement automated secrets scanning in git pre-commit hooks.")

        if any("Aadhaar" in c or "SSN" in c or "PAN" in c or "Passport" in c for c in cat_counts):
            recs.append("HIGH: Government identity documents detected. Apply data masking (e.g. Masked Aadhaar / SSN-4) and restrict access to authorized compliance personnel only.")

        if any("Email" in c for c in cat_counts):
            recs.append("MEDIUM: Personal email addresses detected. Obfuscate usernames or use departmental contact aliases (e.g. privacy@company.com) before public dissemination.")

        if any("Phone" in c for c in cat_counts):
            recs.append("MEDIUM: Direct phone numbers identified. Mask middle digits (e.g. 98******10) to guard against SIM swaps and automated marketing scrapers.")

        if any("IP" in c for c in cat_counts):
            recs.append("LOW: Internal or public IP addresses identified. Sanitize network topologies in external documentation to prevent network enumeration.")

        if score >= 60:
            recs.append("POLICY: Place this document under strict Role-Based Access Control (RBAC) and do not transmit over unencrypted communication channels.")

        recs.append("AUDIT: Maintain an audit trail of redactions prior to archiving or sharing this document with third parties.")
        return recs

    @staticmethod
    def _generate_exposure_summary(findings: List[Finding], score: int, tier: str) -> str:
        if not findings:
            return "No sensitive exposure detected."
        cats = sorted(list(set(f.category for f in findings)))
        return (
            f"Document evaluated with a {tier} Privacy Risk Score of {score}/100. "
            f"Identified {len(findings)} exposed data points across {len(cats)} categories "
            f"({', '.join(cats[:3])}{'...' if len(cats) > 3 else ''})."
        )
