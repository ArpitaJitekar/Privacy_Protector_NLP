"""
Automated validation suite for PrivacyGuard.
Tests text extraction, regex detection, Luhn validation, context matching, scoring, and report generation.
"""

from pathlib import Path
from privacy_guard.engine import PrivacyAnalyzerEngine
from privacy_guard.report_generator import ReportGenerator

def run_tests():
    print("=" * 60)
    print("Running PrivacyGuard Verification Suite")
    print("=" * 60)

    engine = PrivacyAnalyzerEngine(context_window=60)
    sample_file = Path(__file__).parent / "samples" / "sample_resume.txt"

    assert sample_file.exists(), f"Sample file not found at {sample_file}"
    content_bytes = sample_file.read_bytes()

    result = engine.analyze_document(content_bytes, sample_file.name)
    summary = result.summary

    print(f"Document: {result.filename}")
    print(f"Total Segments: {result.total_segments}")
    print(f"Total Findings: {summary.total_findings}")
    print(f"Total Categories: {summary.total_categories}")
    print(f"Risk Score: {summary.risk_score}/100 ({summary.risk_tier} Risk)")
    print("\nDetected Categories:")
    for cat, count in summary.category_counts.items():
        print(f"  - {cat}: {count}")

    print("\nDetailed Findings:")
    for idx, f in enumerate(result.findings, 1):
        print(f"  [{idx}] {f.category} | {f.masked_value} | Risk: {f.risk_level} | Loc: {f.location}")
        print(f"      Context snippet: {f.context_snippet}")
        print(f"      Notes: {f.context_notes}")

    # Assertions
    assert summary.total_findings >= 6, f"Expected >= 6 findings, got {summary.total_findings}"
    assert summary.total_categories >= 4, f"Expected >= 4 categories, got {summary.total_categories}"
    assert summary.risk_score >= 60, f"Expected high risk score (>=60), got {summary.risk_score}"

    print("\nTesting DOCX Extraction & Analysis:")
    docx_file = Path(__file__).parent / "samples" / "sample_contract.docx"
    docx_bytes = docx_file.read_bytes()
    docx_result = engine.analyze_document(docx_bytes, docx_file.name)
    print(f"DOCX findings: {docx_result.summary.total_findings}, categories: {docx_result.summary.total_categories}, score: {docx_result.summary.risk_score}")
    assert docx_result.summary.total_findings >= 4

    print("\nTesting PDF Extraction & Analysis:")
    pdf_file = Path(__file__).parent / "samples" / "sample_policy.pdf"
    pdf_bytes = pdf_file.read_bytes()
    pdf_result = engine.analyze_document(pdf_bytes, pdf_file.name)
    print(f"PDF findings: {pdf_result.summary.total_findings}, categories: {pdf_result.summary.total_categories}, score: {pdf_result.summary.risk_score}")
    assert pdf_result.summary.total_findings >= 3

    # Test Reports
    csv_rep = ReportGenerator.generate_csv(result)
    assert "Category,Masked Value" in csv_rep, "CSV report header missing"

    json_rep = ReportGenerator.generate_json(result)
    assert '"risk_score":' in json_rep, "JSON report missing risk_score"

    md_rep = ReportGenerator.generate_markdown(result)
    assert "# PrivacyGuard" in md_rep, "Markdown report header missing"

    html_rep = ReportGenerator.generate_html(result)
    assert "PrivacyGuard Security Report" in html_rep, "HTML report missing header"

    print("\nTesting Clean Document:")
    clean_file = Path(__file__).parent / "samples" / "public_announcement.txt"
    clean_bytes = clean_file.read_bytes()
    clean_result = engine.analyze_document(clean_bytes, clean_file.name)
    print(f"Clean doc findings: {clean_result.summary.total_findings}, score: {clean_result.summary.risk_score}")
    assert clean_result.summary.total_findings == 0
    assert clean_result.summary.risk_score == 0

    print("\n[SUCCESS] All PrivacyGuard tests passed successfully!")

if __name__ == "__main__":
    run_tests()
