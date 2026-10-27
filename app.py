"""
PrivacyGuard — Personal Data Privacy Risk Analyzer for Documents
Streamlit Frontend Application
"""

import os
from pathlib import Path
import streamlit as st
import pandas as pd

from privacy_guard.engine import PrivacyAnalyzerEngine
from privacy_guard.report_generator import ReportGenerator

# Streamlit Page Config
st.set_page_config(
    page_title="PrivacyGuard — Personal Data Privacy Risk Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .main-title {
        font-size: 2.3rem;
        font-weight: 800;
        color: #1E293B;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        font-size: 1.1rem;
        color: #64748B;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        padding: 18px 20px;
        text-align: center;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .metric-value {
        font-size: 2.2rem;
        font-weight: 700;
        color: #0F172A;
    }
    .metric-label {
        font-size: 0.9rem;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-top: 4px;
    }
    .finding-card {
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 12px;
        border-left: 5px solid #CBD5E1;
        background: #FFFFFF;
        box-shadow: 0 1px 2px rgba(0,0,0,0.04);
        border: 1px solid #E2E8F0;
    }
    .finding-card-critical {
        border-left: 6px solid #DC2626 !important;
        background: #FEF2F2;
    }
    .finding-card-high {
        border-left: 6px solid #EA580C !important;
        background: #FFF7ED;
    }
    .finding-card-medium {
        border-left: 6px solid #D97706 !important;
        background: #FFFBEB;
    }
    .finding-card-low {
        border-left: 6px solid #16A34A !important;
        background: #F0FDF4;
    }
    .badge-critical { background: #DC2626; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; }
    .badge-high { background: #EA580C; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; }
    .badge-medium { background: #D97706; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; }
    .badge-low { background: #16A34A; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; }
    .context-box {
        background: #F1F5F9;
        font-family: monospace;
        padding: 6px 10px;
        border-radius: 4px;
        font-size: 12px;
        color: #1E293B;
        display: block;
        margin: 6px 0;
    }
</style>
""", unsafe_allow_html=True)


# Initialize Analyzer Engine in Session
@st.cache_resource
def get_engine():
    return PrivacyAnalyzerEngine(context_window=60)

engine = get_engine()

# Sidebar: Controls, Documentation & Samples
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("PrivacyGuard")
    st.caption("Personal Data Privacy Risk Analyzer v1.0")

    st.markdown("---")
    st.markdown("### ⚙️ Engine Settings")
    context_window = st.slider("Context Window Size (chars)", min_value=30, max_value=120, value=60, step=10)
    allow_unmask = st.checkbox("Enable Raw Value Inspection (Audit Mode)", value=False)
    if allow_unmask:
        st.warning("⚠️ Raw values will be visible. Ensure you have proper authorization.")

    st.markdown("---")
    st.markdown("### 🧪 Quick Test Samples")
    sample_choice = st.selectbox(
        "Load a demo document:",
        [
            "None (Upload custom file)",
            "Sample Resume with PII (.txt)",
            "Sample Contract (.docx)",
            "Sample Incident Report (.pdf)",
            "Clean Public Announcement (.txt)"
        ]
    )

    st.markdown("---")
    st.markdown("### 📖 About the Technology")
    st.info(
        "**Rule-based NLP Engine**\n\n"
        "- **Pattern Detection:** Regex (`re`) with algorithmic checksum validation\n"
        "- **Context Analysis:** Keyword & window-matching rules\n"
        "- **Document Extraction:** PyMuPDF, python-docx, UTF-8\n"
        "- **Scoring:** Multi-factor heuristic risk calculation"
    )

# Header Section
st.markdown('<div class="main-title">🛡️ PrivacyGuard</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Personal Data Privacy Risk Analyzer for Documents</div>', unsafe_allow_html=True)

# 1. Upload your document
st.markdown("### 1. Upload your document")

uploaded_file = st.file_uploader(
    "Drag and drop your file here",
    type=["pdf", "docx", "txt"],
    help="Supports PDF documents, Microsoft Word files (.docx), and plain text (.txt)."
)

file_bytes = None
filename = ""

# Handle Sample selection vs File upload
samples_dir = Path(__file__).parent / "samples"
if sample_choice == "Sample Resume with PII (.txt)":
    sample_path = samples_dir / "sample_resume.txt"
    if sample_path.exists():
        file_bytes = sample_path.read_bytes()
        filename = "sample_resume.txt"
        st.info("📄 Loaded built-in sample document: `sample_resume.txt`")
elif sample_choice == "Sample Contract (.docx)":
    sample_path = samples_dir / "sample_contract.docx"
    if sample_path.exists():
        file_bytes = sample_path.read_bytes()
        filename = "sample_contract.docx"
        st.info("📄 Loaded built-in sample document: `sample_contract.docx`")
elif sample_choice == "Sample Incident Report (.pdf)":
    sample_path = samples_dir / "sample_policy.pdf"
    if sample_path.exists():
        file_bytes = sample_path.read_bytes()
        filename = "sample_policy.pdf"
        st.info("📄 Loaded built-in sample document: `sample_policy.pdf`")
elif sample_choice == "Clean Public Announcement (.txt)":
    sample_path = samples_dir / "public_announcement.txt"
    if sample_path.exists():
        file_bytes = sample_path.read_bytes()
        filename = "public_announcement.txt"
        st.info("📄 Loaded built-in sample document: `public_announcement.txt`")

if uploaded_file is not None:
    file_bytes = uploaded_file.getvalue()
    filename = uploaded_file.name

# Run Analysis when document is present
if file_bytes is not None and filename:
    with st.spinner("Analyzing document structure, evaluating regex patterns, and matching context windows..."):
        try:
            result = engine.analyze_document(file_bytes=file_bytes, filename=filename)
        except Exception as e:
            st.error(f"Error parsing document: {str(e)}")
            st.stop()

    summary = result.summary

    st.markdown("---")

    # 2. Analysis summary
    st.markdown("### 2. Analysis summary")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{summary.total_findings}</div>
            <div class="metric-label">Findings</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{summary.total_categories}</div>
            <div class="metric-label">Categories</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        score_color = "#16A34A" if summary.risk_score <= 25 else "#D97706" if summary.risk_score <= 55 else "#EA580C" if summary.risk_score <= 79 else "#DC2626"
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: {score_color};">{summary.risk_score}/100</div>
            <div class="metric-label">Risk score</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        tier_badges = {
            "Low": "🟢 Low Risk",
            "Medium": "🟡 Medium Risk",
            "High": "🟠 High Risk",
            "Critical": "🔴 Critical Risk"
        }
        badge = tier_badges.get(summary.risk_tier, summary.risk_tier)
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="font-size: 1.5rem; line-height: 2.2rem;">{badge}</div>
            <div class="metric-label">Threat Level</div>
        </div>
        """, unsafe_allow_html=True)

    st.write("")
    st.progress(summary.risk_score / 100.0)
    st.caption(f"**Exposure Summary:** {summary.exposure_summary}")

    # Charts / Breakdown
    if summary.category_counts:
        with st.expander("📊 View Category & Severity Breakdown", expanded=False):
            chart_col1, chart_col2 = st.columns(2)
            with chart_col1:
                st.markdown("**Findings by Category**")
                cat_df = pd.DataFrame(
                    list(summary.category_counts.items()),
                    columns=["Category", "Count"]
                ).sort_values("Count", ascending=False)
                st.bar_chart(cat_df.set_index("Category"))

            with chart_col2:
                st.markdown("**Findings by Severity**")
                sev_df = pd.DataFrame(
                    list(summary.severity_counts.items()),
                    columns=["Severity", "Count"]
                )
                st.bar_chart(sev_df.set_index("Severity"))

    st.markdown("---")

    # 3. Detected sensitive information
    st.markdown(f"### 3. Detected sensitive information ({summary.total_findings})")

    if not result.findings:
        st.success("✅ **Clean Document:** No sensitive personal information patterns or risky keywords were detected.")
    else:
        # Filter controls
        f_col1, f_col2 = st.columns([2, 2])
        with f_col1:
            all_cats = ["All Categories"] + sorted(list(summary.category_counts.keys()))
            selected_cat = st.selectbox("Filter by Category:", all_cats)
        with f_col2:
            selected_sev = st.selectbox("Filter by Risk Level:", ["All Levels", "Critical", "High", "Medium", "Low"])

        filtered_findings = result.findings
        if selected_cat != "All Categories":
            filtered_findings = [f for f in filtered_findings if f.category == selected_cat]
        if selected_sev != "All Levels":
            filtered_findings = [f for f in filtered_findings if f.risk_level == selected_sev]

        # Display tabs: Card View vs Table View
        tab_cards, tab_table = st.tabs(["🗂️ Card View (Mockup Style)", "📋 Detailed Audit Table"])

        with tab_cards:
            for f in filtered_findings:
                badge_class = f"badge-{f.risk_level.lower()}"
                card_class = f"finding-card finding-card-{f.risk_level.lower()}"
                display_val = f.raw_value if allow_unmask else f.masked_value

                st.markdown(f"""
                <div class="{card_class}">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-weight: 700; font-size: 16px; color: #1E293B;">{f.category}</span>
                        <span class="{badge_class}">{f.risk_level.upper()}</span>
                    </div>
                    <div style="font-size: 18px; font-weight: 600; color: #0F172A; margin: 8px 0; font-family: monospace;">
                        {display_val}
                    </div>
                    <div style="font-size: 13px; color: #64748B;">
                        📍 <strong>Location:</strong> {f.location} &nbsp;|&nbsp; ℹ️ <strong>Reason:</strong> {f.reason}
                    </div>
                    <div class="context-box">
                        <strong>Context Window:</strong> {f.context_snippet}
                    </div>
                    <div style="font-size: 12px; color: #475569; margin-top: 4px;">
                        💡 <strong>Recommendation:</strong> {f.recommendation}
                    </div>
                </div>
                """, unsafe_allow_html=True)

        with tab_table:
            table_data = []
            for f in filtered_findings:
                table_data.append({
                    "Category": f.category,
                    "Value": f.raw_value if allow_unmask else f.masked_value,
                    "Risk Level": f.risk_level,
                    "Location": f.location,
                    "Detection Reason": f.reason,
                    "Context Notes": f.context_notes,
                    "Recommendation": f.recommendation
                })
            df_table = pd.DataFrame(table_data)
            st.dataframe(df_table, use_container_width=True)

    st.markdown("---")

    # 4. Recommendations & Downloadable Reports
    st.markdown("### 4. Remediation Recommendations & Downloadable Reports")

    col_rec, col_dl = st.columns([3, 2])

    with col_rec:
        st.markdown("#### 🛠️ Recommended Actions")
        for idx, rec in enumerate(summary.recommendations, 1):
            st.markdown(f"**{idx}.** {rec}")

    with col_dl:
        st.markdown("#### 📥 Export Audit Reports")
        st.caption("Download reports in your preferred format for compliance and remediation tracking:")

        # Generate report strings
        csv_report = ReportGenerator.generate_csv(result)
        json_report = ReportGenerator.generate_json(result)
        md_report = ReportGenerator.generate_markdown(result)
        html_report = ReportGenerator.generate_html(result)

        base_name = os.path.splitext(filename)[0]

        st.download_button(
            label="📄 Download Executive Report (.md)",
            data=md_report,
            file_name=f"{base_name}_privacy_report.md",
            mime="text/markdown",
            use_container_width=True
        )

        st.download_button(
            label="📊 Download CSV Findings Table (.csv)",
            data=csv_report,
            file_name=f"{base_name}_privacy_findings.csv",
            mime="text/csv",
            use_container_width=True
        )

        st.download_button(
            label="🌐 Download Formatted HTML Report (.html)",
            data=html_report,
            file_name=f"{base_name}_privacy_report.html",
            mime="text/html",
            use_container_width=True
        )

        st.download_button(
            label="⚙️ Download Machine-Readable JSON (.json)",
            data=json_report,
            file_name=f"{base_name}_privacy_audit.json",
            mime="application/json",
            use_container_width=True
        )

else:
    # Illustrative placeholder when no file is uploaded yet
    st.info("👆 Please upload a document (PDF, DOCX, TXT) above or select a demo sample from the sidebar to begin analysis.")

    st.markdown("#### Preview of expected analysis layout:")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">8</div>
            <div class="metric-label">Findings (Example)</div>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">4</div>
            <div class="metric-label">Categories (Example)</div>
        </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value" style="color: #EA580C;">65/100</div>
            <div class="metric-label">Risk score (Example)</div>
        </div>
        """, unsafe_allow_html=True)
