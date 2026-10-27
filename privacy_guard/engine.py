"""
Core Privacy Risk Analyzer Engine.
Coordinates text segmentation, regex pattern matching, context-window analysis,
entity validation, and overall risk calculation.
"""

from dataclasses import dataclass
from typing import List, Set, Tuple
import re

from .extractor import DocumentExtractor, TextSegment
from .patterns import REGEX_PATTERNS, PatternDefinition
from .context_rules import ContextAnalyzer
from .risk_scorer import Finding, RiskScorer, DocumentRiskSummary, SEVERITY_WEIGHTS
from .maskers import mask_value


@dataclass
class AnalysisResult:
    filename: str
    total_segments: int
    findings: List[Finding]
    summary: DocumentRiskSummary


class PrivacyAnalyzerEngine:
    """End-to-end rule-based NLP privacy analyzer."""

    def __init__(self, context_window: int = 60):
        self.context_analyzer = ContextAnalyzer(window_chars=context_window)
        self.patterns = REGEX_PATTERNS

    def analyze_document(self, file_bytes: bytes, filename: str) -> AnalysisResult:
        """Extracts text, detects PII entities, evaluates context, and computes risk."""
        segments = DocumentExtractor.extract(file_bytes, filename)
        findings: List[Finding] = []
        seen_spans: Set[Tuple[str, int, int]] = set()

        for seg in segments:
            text = seg.text
            if not text:
                continue

            for pattern_def in self.patterns:
                for match in pattern_def.pattern.finditer(text):
                    start, end = match.start(), match.end()
                    span_key = (seg.location, start, end)

                    # Deduplicate overlapping spans
                    if any(
                        s_loc == seg.location and not (end <= s_start or start >= s_end)
                        for (s_loc, s_start, s_end) in seen_spans
                    ):
                        continue

                    raw_val = match.group(0).strip()

                    # Run custom validation if defined
                    if pattern_def.validator is not None:
                        if not pattern_def.validator(raw_val):
                            continue

                    seen_spans.add(span_key)

                    # Context-window matching
                    ctx_res = self.context_analyzer.analyze_context(
                        full_text=text,
                        start=start,
                        end=end,
                        category=pattern_def.category
                    )

                    # Adjust severity based on context
                    final_severity = RiskScorer.adjust_finding_severity(
                        base_risk=pattern_def.base_risk,
                        risk_adj=ctx_res.risk_adjustment
                    )

                    # Generate masked presentation
                    masked_val = mask_value(pattern_def.category, raw_val)

                    num_risk = SEVERITY_WEIGHTS.get(final_severity, 35)

                    findings.append(
                        Finding(
                            category=pattern_def.category,
                            raw_value=raw_val,
                            masked_value=masked_val,
                            risk_level=final_severity,
                            numerical_risk=num_risk,
                            location=seg.location,
                            reason=pattern_def.reason,
                            context_snippet=ctx_res.context_snippet,
                            context_notes=ctx_res.context_notes,
                            recommendation=pattern_def.recommendation
                        )
                    )

        # Sort findings: Critical -> High -> Medium -> Low
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        findings.sort(key=lambda x: (severity_order.get(x.risk_level, 4), x.location))

        summary = RiskScorer.calculate_document_risk(findings)

        return AnalysisResult(
            filename=filename,
            total_segments=len(segments),
            findings=findings,
            summary=summary
        )
