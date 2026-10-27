# PrivacyGuard — Personal Data Privacy Risk Analyzer for Documents

**PrivacyGuard** is a production-ready, rule-based NLP application developed in Python and Streamlit to detect, classify, and mitigate sensitive Personally Identifiable Information (PII) in uploaded documents.

---

## 🌟 Key Features

1. **Multi-Format Document Ingestion:**
   - **PDF:** Page-by-page extraction and coordinate/line referencing via PyMuPDF (`fitz`).
   - **DOCX:** Paragraph and tabular structure extraction via `python-docx`.
   - **TXT / Markdown / CSV:** Line-by-line parsing.

2. **Rule-Based Regex Detection:**
   - Email addresses (international & standard).
   - Phone numbers (+country code, US format, Indian format).
   - Government IDs:
     - US Social Security Numbers (SSN) with sanity checks.
     - Indian PAN cards (`[A-Z]{5}[0-9]{4}[A-Z]`).
     - Indian Aadhaar numbers (with 12-digit format checks).
     - International Passport numbers.
   - Financial credentials (Credit/Debit card numbers with **Luhn Checksum Algorithm** verification).
   - Network identifiers (IPv4 validation excluding private test masks).
   - Cryptographic API keys, JWT tokens, and secret strings.

3. **Context-Window Matching Engine:**
   - Extracts a configurable sliding context window (e.g. $\pm 60$ characters) around each match.
   - Searches for sensitive indicator keywords (e.g. *salary*, *diagnosis*, *password*, *aadhaar*, *SSN*, *routing*).
   - Dynamic Risk Adjustment: Escalates risk if found near sensitive terms or de-escalates if surrounded by benign/placeholder keywords (e.g., *sample*, *rfc*).

4. **Multi-Factor Heuristic Risk Scoring (0–100):**
   - **Peak Severity Anchor:** Accounts for the highest-risk finding.
   - **Volume Factor:** Diminishing returns logarithmic curve on finding density.
   - **Category Diversity Factor:** Penalizes cross-referencing hazards when multiple PII types are co-located.
   - **Risk Tiers:** Low (0–25), Medium (26–55), High (56–79), Critical (80–100).

5. **Privacy-Preserving UI & Masking:**
   - Masks sensitive values automatically (e.g. `r***@gmail.com`, `98******10`, `Value masked for privacy`).
   - Card view (mockup style) and interactive detailed audit table.
   - Optional toggle for authorized audit unmasking.

6. **Comprehensive Multi-Format Report Export:**
   - **Executive Markdown (`.md`):** High-level summary with tables and actionable remediation.
   - **Detailed CSV (`.csv`):** Tabular format for compliance officers and Excel auditing.
   - **Formatted HTML (`.html`):** Styled report ready for browser viewing or PDF printing.
   - **Machine-Readable JSON (`.json`):** For CI/CD security pipelines.

---

## 🚀 Quick Start Guide

### 1. Installation

Ensure Python 3.10+ is installed, then install the dependencies:

```bash
pip install -r requirements.txt
```

### 2. Launch the Application

Navigate to the project directory and run Streamlit:

```bash
streamlit run app.py
```

Streamlit will launch a local web server (usually at `http://localhost:8501`).

### 3. Using Built-in Samples

You don't need to create a test document from scratch! From the left sidebar dropdown, select:
- **Sample Resume with PII:** Demonstrates 8+ findings across emails, phone numbers, Aadhaar, PAN, SSN, salary context, and API keys.
- **Clean Public Announcement:** Demonstrates a clean document resulting in 0 findings and a Low Risk (0/100) score.

---

## 📂 Project Structure

```text
privacy_guard/
├── app.py                      # Main Streamlit web frontend
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
├── privacy_guard/              # Core NLP & Analysis Package
│   ├── __init__.py
│   ├── extractor.py            # PDF (PyMuPDF), DOCX (python-docx), and TXT text extractors
│   ├── patterns.py             # Regex patterns and algorithmic validators (Luhn, SSN, etc.)
│   ├── context_rules.py        # Sliding context-window matching & indicator keywords
│   ├── engine.py               # Main pipeline combining regex + context rules
│   ├── risk_scorer.py          # 0-100 heuristic scoring and tier classification
│   ├── maskers.py              # PII masking algorithms (r***@gmail.com, etc.)
│   └── report_generator.py     # CSV, JSON, Markdown, and HTML report exporters
└── samples/
    ├── sample_resume.txt       # Realistic high-risk demo document
    └── public_announcement.txt # Zero-risk demo document
```

---

## 🛡️ Architecture & Tech Stack

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Frontend** | Streamlit | Responsive dashboard, metrics cards, report download buttons |
| **Backend** | Python 3.12 | Processing pipeline and orchestration |
| **Pattern Detection** | Regex (`re`) | Fast structured token identification |
| **Validation** | Python (Luhn, etc.) | Eliminates false positive card/ID numbers |
| **Context Analysis**| Window Matching | Interprets $\pm 60$ char context surrounding matches |
| **PDF Extraction** | PyMuPDF (`fitz`) | Multi-page PDF text and line numbering |
| **DOCX Extraction**| `python-docx` | Structured paragraph and table parsing |
| **Reporting** | Markdown / CSV / HTML / JSON | Audit-ready compliance reporting |
