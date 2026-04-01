#!/usr/bin/env python3
"""
Generate prevalence artifacts from the Incident_Extraction_v0.X.xlsx workbook.

Outputs:
- {version}_Prevalence_Snapshot.docx
- {version}_Misconfiguration_Matrix.docx
- {version}_Prevalence_Brief.docx

Usage (local):
  python generate_artifacts.py --xlsx Incident_Extraction_v0.X.xlsx --out_dir . --version v0.X

Notes:
- Assumes the workbook contains an "Incident_Extraction" sheet with v0.X headers.
- Requires: pandas, openpyxl, python-docx
"""
import argparse
import logging
import re
import datetime as dt
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

import pandas as pd
import openpyxl
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

# ============================================================================
# CONSTANTS
# ============================================================================

# Colors
COLOR_PRIMARY_BLUE = RGBColor(0x1F, 0x4E, 0x79)
COLOR_SECONDARY_GRAY = RGBColor(0x55, 0x55, 0x55)
COLOR_HEADER_BG = "EDEDED"

# Font sizes (pt)
FONT_SIZE_TITLE = 24
FONT_SIZE_SUBTITLE = 14
FONT_SIZE_H1 = 16
FONT_SIZE_H2 = 13
FONT_SIZE_H3 = 11
FONT_SIZE_NORMAL = 11
FONT_SIZE_SMALL = 10

# Table column widths (inches)
STANDARD_COL_WIDTHS = [Inches(4.5), Inches(0.75), Inches(0.75)]
MATRIX_COL_WIDTHS = [Inches(1.65), Inches(0.95), Inches(0.95), Inches(1.55), Inches(1.4)]

# Cell margins (twips)
DEFAULT_CELL_MARGINS = {"top": 80, "start": 100, "bottom": 80, "end": 100}

# Schema requirements
REQUIRED_COLUMNS = {
    "Incident_Extraction": [
        "Incident_ID", "Source_Date", "Attack_Type", "IdP_Context",
        "Impact_Primary", "Entry_Vector", "Source_Org", "Misconfig_1",
        "Misconfig_2", "Controls_1", "Controls_2", "Confidence"
    ]
}

PICKLIST_COLUMNS = {
    "attack": 1,
    "entry": 2,
    "misconfig": 3,
    "controls": 4,
    "idp": 5,
    "flow": 6,
    "impact": 7,
}

# ============================================================================
# LOGGING
# ============================================================================

def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure logging with consistent format."""
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    if not logger.handlers:
        logger.addHandler(handler)
    return logger

logger = setup_logging()

# ============================================================================
# DOCUMENT STYLING
# ============================================================================

def set_cell_shading(cell, fill: str) -> None:
    """Apply background shading to a table cell."""
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tcPr.append(shd)


def set_cell_margins(
    cell,
    top: int = DEFAULT_CELL_MARGINS["top"],
    start: int = DEFAULT_CELL_MARGINS["start"],
    bottom: int = DEFAULT_CELL_MARGINS["bottom"],
    end: int = DEFAULT_CELL_MARGINS["end"],
) -> None:
    """Set cell margins in twips."""
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    tcMar = tcPr.find(qn("w:tcMar"))
    if tcMar is None:
        tcMar = OxmlElement("w:tcMar")
        tcPr.append(tcMar)
    for m, v in (("top", top), ("start", start), ("bottom", bottom), ("end", end)):
        node = tcMar.find(qn(f"w:{m}"))
        if node is None:
            node = OxmlElement(f"w:{m}")
            tcMar.append(node)
        node.set(qn("w:w"), str(v))
        node.set(qn("w:type"), "dxa")


def style_table(table) -> None:
    """Apply standard styling to table."""
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    for row in table.rows:
        for cell in row.cells:
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            set_cell_margins(cell)


def apply_doc_style(doc: Document) -> None:
    """Apply consistent styling to document."""
    styles = doc.styles

    # Title style
    if "Title" in styles:
        st = styles["Title"]
        st.font.name = "Calibri"
        st.font.size = Pt(FONT_SIZE_TITLE)
        st.font.bold = True
        st.font.color.rgb = COLOR_PRIMARY_BLUE

    # Heading styles
    heading_sizes = {
        "Heading 1": FONT_SIZE_H1,
        "Heading 2": FONT_SIZE_H2,
        "Heading 3": FONT_SIZE_H3,
    }
    for name, size in heading_sizes.items():
        if name in styles:
            st = styles[name]
            st.font.name = "Calibri"
            st.font.bold = True
            st.font.color.rgb = COLOR_PRIMARY_BLUE
            st.font.size = Pt(size)

    # Normal style
    st = styles["Normal"]
    st.font.name = "Calibri"
    st.font.size = Pt(FONT_SIZE_NORMAL)


# ============================================================================
# DATA UTILITIES
# ============================================================================

def pct(n: int, total: int) -> float:
    """Calculate percentage with one decimal place."""
    return round(100 * n / total, 1) if total else 0.0


def count_table(
    series: pd.Series,
    categories: Optional[List[str]] = None,
) -> Tuple[List[Tuple[str, int, float]], int]:
    """
    Generate count table from series.
    
    Returns:
        (rows, total_count) where rows = [(category, count, percentage), ...]
    """
    ser = series.dropna().astype(str).str.strip()
    counts = Counter(ser)
    
    if categories is None:
        categories = sorted(counts.keys(), key=lambda k: (-counts[k], k))
    
    rows = []
    for cat in categories:
        n = counts.get(cat, 0)
        rows.append((cat, n, pct(n, len(ser))))
    
    return rows, len(ser)


def parse_year(x: Any) -> Optional[int]:
    """Extract year from date or string."""
    if pd.isna(x):
        return None
    if isinstance(x, (dt.date, dt.datetime)):
        return x.year
    m = re.search(r"(\d{4})", str(x))
    return int(m.group(1)) if m else None


# ============================================================================
# DATA LOADING & VALIDATION
# ============================================================================

def load_workbook_safe(xlsx_path: str) -> openpyxl.Workbook:
    """Load workbook with error handling."""
    try:
        logger.info(f"Loading workbook: {xlsx_path}")
        wb = openpyxl.load_workbook(xlsx_path, data_only=True)
        return wb
    except FileNotFoundError as e:
        logger.error(f"Workbook not found: {xlsx_path}")
        raise FileNotFoundError(f"Workbook not found: {xlsx_path}") from e
    except Exception as e:
        logger.error(f"Failed to load workbook: {e}")
        raise ValueError(f"Invalid Excel file: {xlsx_path}") from e


def validate_dataframe(df: pd.DataFrame, required_cols: List[str]) -> None:
    """Verify all required columns exist."""
    missing = set(required_cols) - set(df.columns)
    if missing:
        logger.error(f"Missing required columns: {missing}")
        raise ValueError(f"Missing required columns: {missing}")
    logger.info(f"DataFrame validation passed ({len(df)} rows)")


def read_picklists(wb: openpyxl.Workbook) -> Dict[str, List[str]]:
    """Extract picklists from Picklists sheet."""
    try:
        pick = wb["Picklists"]
        logger.info("Reading picklists")
    except KeyError as e:
        logger.error("Picklists sheet not found")
        raise KeyError("Picklists sheet not found") from e

    def col_values(col_idx: int, max_rows: int = 500) -> List[str]:
        vals = []
        for r in range(2, max_rows + 1):
            v = pick.cell(r, col_idx).value
            if v is None or str(v).strip() == "":
                break
            vals.append(str(v).strip())
        return vals

    picklists = {
        key: col_values(col_idx) for key, col_idx in PICKLIST_COLUMNS.items()
    }
    logger.info(f"Loaded {len(picklists)} picklist categories")
    return picklists


def load_incidents(wb: openpyxl.Workbook) -> pd.DataFrame:
    """Load incidents from Incident_Extraction sheet."""
    try:
        ws = wb["Incident_Extraction"]
        logger.info("Reading Incident_Extraction sheet")
    except KeyError as e:
        logger.error("Incident_Extraction sheet not found")
        raise KeyError("Incident_Extraction sheet not found") from e

    headers = [c.value for c in ws[1]]
    rows = []
    for r in ws.iter_rows(min_row=2, values_only=True):
        if r and any(x is not None and str(x).strip() != "" for x in r):
            rows.append(r[: len(headers)])

    df = pd.DataFrame(rows, columns=headers)
    validate_dataframe(df, REQUIRED_COLUMNS["Incident_Extraction"])
    logger.info(f"Loaded {len(df)} incidents")
    return df


# ============================================================================
# DATA AGGREGATION
# ============================================================================

def compute_all_counters(df: pd.DataFrame) -> Dict[str, Counter]:
    """Pre-compute all counters to avoid repeated iterations."""
    logger.info("Computing aggregate counters")
    counters = {
        "misconfig_any": Counter(),
        "controls_any": Counter(),
    }

    for _, row in df.iterrows():
        # Aggregate misconfiguration counts
        for col in ["Misconfig_1", "Misconfig_2"]:
            val = row[col]
            if val is not None and str(val).strip():
                counters["misconfig_any"][str(val).strip()] += 1

        # Aggregate control counts
        for col in ["Controls_1", "Controls_2"]:
            val = row[col]
            if val is not None and str(val).strip():
                counters["controls_any"][str(val).strip()] += 1

    return counters


def representative_ids_for_misconfig(
    df: pd.DataFrame, cat: str, max_n: int = 4
) -> List[str]:
    """Get representative incident IDs for a misconfiguration category."""
    sub = df[(df["Misconfig_1"] == cat) | (df["Misconfig_2"] == cat)].copy()
    
    if sub.empty:
        return []

    conf_order = {"High": 0, "Medium": 1, "Low": 2}
    sub["conf_rank"] = sub["Confidence"].map(
        lambda x: conf_order.get(str(x).strip(), 9)
    )
    sub["date"] = pd.to_datetime(sub["Source_Date"], errors="coerce")
    sub = sub.sort_values(by=["conf_rank", "date"], ascending=[True, False])
    return sub["Incident_ID"].head(max_n).tolist()


def common_controls_for_misconfig(
    df: pd.DataFrame, cat: str, max_n: int = 3
) -> List[str]:
    """Get most common controls for a misconfiguration category."""
    sub = df[(df["Misconfig_1"] == cat) | (df["Misconfig_2"] == cat)]
    counts = Counter()
    for _, r in sub.iterrows():
        for c in ["Controls_1", "Controls_2"]:
            v = r[c]
            if v is not None and str(v).strip():
                counts[str(v).strip()] += 1
    return [k for k, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:max_n]]


# ============================================================================
# TABLE BUILDING
# ============================================================================

def add_table(
    doc: Document,
    title: Optional[str],
    rows: List[Tuple],
    col_widths: List,
    header: Tuple[str, ...],
) -> Any:
    """
    Add a formatted table to document.
    
    Args:
        doc: Document object
        title: Optional heading for table
        rows: List of tuples representing table rows
        col_widths: List of Inches() objects for column widths
        header: Tuple of header strings
    """
    if title:
        p = doc.add_paragraph(title)
        p.style = "Heading 2"

    table = doc.add_table(rows=1 + len(rows), cols=len(header))
    style_table(table)

    # Style header row
    hdr_cells = table.rows[0].cells
    for j, h in enumerate(header):
        hdr_cells[j].text = str(h)
        for run in hdr_cells[j].paragraphs[0].runs:
            run.font.bold = True
        set_cell_shading(hdr_cells[j], COLOR_HEADER_BG)
        alignment = WD_ALIGN_PARAGRAPH.CENTER if j > 0 else WD_ALIGN_PARAGRAPH.LEFT
        hdr_cells[j].paragraphs[0].alignment = alignment

    # Fill data rows
    for i, row in enumerate(rows, start=1):
        cells = table.rows[i].cells
        for j, val in enumerate(row):
            if j == 2 and isinstance(val, (int, float)):
                cells[j].text = f"{val:.1f}%"
            else:
                cells[j].text = str(val)
            alignment = WD_ALIGN_PARAGRAPH.CENTER if j > 0 else WD_ALIGN_PARAGRAPH.LEFT
            cells[j].paragraphs[0].alignment = alignment

    # Apply column widths
    for j, w in enumerate(col_widths):
        for r in table.rows:
            r.cells[j].width = w

    return table


def add_header_section(
    doc: Document,
    title: str,
    subtitle: str,
    gen_date: str,
    meta_text: str,
) -> None:
    """Add title and metadata section to document."""
    doc.add_paragraph(title, style="Title")
    sub = doc.add_paragraph(subtitle)
    sub.runs[0].font.size = Pt(FONT_SIZE_SUBTITLE)
    sub.runs[0].font.color.rgb = COLOR_PRIMARY_BLUE
    
    meta = doc.add_paragraph()
    m = meta.add_run(f"Generated: {gen_date}\n{meta_text}")
    m.font.size = Pt(FONT_SIZE_SMALL)
    m.font.color.rgb = COLOR_SECONDARY_GRAY


# ============================================================================
# MISCONFIGURATION DEFINITIONS
# ============================================================================

MISCONFIG_DEFINITIONS = {
    "Consent policy too permissive": (
        "Delegated consent is broadly allowed, enabling attacker-controlled apps "
        "to obtain high-value permissions with limited friction."
    ),
    "Admin consent governance weak": (
        "Admin consent can be granted too easily or without review, enabling "
        "high-privilege delegated/app permissions at scale."
    ),
    "App trust controls not enforced": (
        "Publisher/trust signals and app reputation controls are not used to "
        "block or scrutinize risky apps."
    ),
    "Over-privileged scopes/roles": (
        "Apps/users hold permissions beyond business need (high-risk OAuth scopes, "
        "app-only roles, Azure roles)."
    ),
    "Token lifecycle controls weak": (
        "Long-lived or poorly governed tokens materially extend attacker access."
    ),
    "OAuth client credential hygiene weak": (
        "Client secrets/certs are poorly protected/rotated, or new credentials "
        "can be added without sufficient governance."
    ),
    "OAuth flow / client hardening gaps": (
        "Risky flows or weak client constraints enable token acquisition or misuse."
    ),
    "Workload identity / domain-wide delegation risky": (
        "High-privilege workload identity patterns are enabled without sufficient guardrails."
    ),
    "Third-party integration governance weak": (
        "Trusted integrations are not inventory-managed/recertified; blast radius "
        "is not constrained."
    ),
    "Monitoring / audit visibility insufficient": (
        "Logging/retention/detection coverage is inadequate to surface suspicious "
        "OAuth/app events or downstream API abuse."
    ),
}

# ============================================================================
# DOCUMENT GENERATION
# ============================================================================

def build_prevalence_snapshot(
    doc: Document,
    df: pd.DataFrame,
    picks: Dict[str, List[str]],
    gen_date: str,
    version: str,
) -> None:
    """Build Prevalence Snapshot document."""
    total = len(df)
    
    # Compute aggregate tables
    years = df["Source_Date"].apply(parse_year)
    years_counts = Counter(years.dropna())
    year_rows = [
        (str(y), years_counts[y], pct(years_counts[y], total))
        for y in sorted(years_counts.keys())
    ]

    attack_rows, _ = count_table(df["Attack_Type"])
    idp_rows, _ = count_table(df["IdP_Context"])
    impact_rows, _ = count_table(df["Impact_Primary"])
    entry_rows, _ = count_table(df["Entry_Vector"])
    org_rows, _ = count_table(df["Source_Org"])
    mis1_rows, _ = count_table(df["Misconfig_1"], categories=picks["misconfig"])

    counters = compute_all_counters(df)
    mis_any_rows = [
        (cat, counters["misconfig_any"].get(cat, 0), 
         pct(counters["misconfig_any"].get(cat, 0), total))
        for cat in picks["misconfig"]
    ]
    ctrl_any_rows = [
        (cat, counters["controls_any"].get(cat, 0),
         pct(counters["controls_any"].get(cat, 0), total))
        for cat in picks["controls"]
    ]

    # Header
    add_header_section(
        doc,
        f"Prevalence Snapshot ({version})",
        "Mapping and Mitigating SaaS OAuth Post‑SSO Abuse",
        gen_date,
        f"Data source: Incident_Extraction_Template_{version}.xlsx (Incident_Extraction sheet)\n"
        f"Schema: Incident_Extraction_Coding_Schema_{version}",
    )

    # Executive highlights
    doc.add_paragraph("Executive highlights", style="Heading 1")
    consent_n = next(
        (n for k, n, _ in attack_rows if k.startswith("OAuth consent phishing")), 0
    )
    device_n = next(
        (n for k, n, _ in attack_rows if k.startswith("Device code phishing")), 0
    )
    exfil_n = next((n for k, n, _ in impact_rows if k == "Data exfiltration"), 0)
    primary_flow_n = next(
        (n for k, n, _ in mis1_rows if k == "OAuth flow / client hardening gaps"), 0
    )
    det_any = counters["controls_any"].get("Detection on anomalous OAuth/API behavior", 0)

    highlights = [
        f"Total incidents coded: {total} (2022–2026).",
        f"Top attack types: Consent phishing ({consent_n}/{total}) and device code phishing ({device_n}/{total}).",
        f"Primary impact is data exfiltration ({exfil_n}/{total}).",
        f"Primary misconfiguration signal: OAuth flow / client hardening gaps ({primary_flow_n}/{total}).",
        f"Most frequent control gap (any-occurrence): Detection on anomalous OAuth/API behavior ({det_any}/{total}).",
    ]
    for h in highlights:
        doc.add_paragraph(h, style="List Bullet")

    # Dataset overview
    doc.add_paragraph("Dataset overview", style="Heading 1")
    add_table(
        doc,
        "By year (Source_Date)",
        year_rows,
        STANDARD_COL_WIDTHS,
        ("Year", "n", "%"),
    )
    add_table(
        doc,
        "By publisher (Source_Org)",
        org_rows,
        STANDARD_COL_WIDTHS,
        ("Source_Org", "n", "%"),
    )

    # Core prevalence
    doc.add_paragraph("Core prevalence (all incidents)", style="Heading 1")
    add_table(doc, "Attack_Type", attack_rows, STANDARD_COL_WIDTHS, ("Attack_Type", "n", "%"))
    add_table(doc, "IdP_Context", idp_rows, STANDARD_COL_WIDTHS, ("IdP_Context", "n", "%"))
    add_table(doc, "Impact_Primary", impact_rows, STANDARD_COL_WIDTHS, ("Impact_Primary", "n", "%"))
    add_table(doc, "Entry_Vector", entry_rows, STANDARD_COL_WIDTHS, ("Entry_Vector", "n", "%"))

    # Misconfiguration prevalence
    doc.add_paragraph("Misconfiguration prevalence", style="Heading 1")
    add_table(
        doc,
        "Misconfig (primary-only: Misconfig_1)",
        mis1_rows,
        STANDARD_COL_WIDTHS,
        ("Misconfig", "n", "%"),
    )
    add_table(
        doc,
        "Misconfig (any-occurrence: Misconfig_1 OR Misconfig_2)",
        mis_any_rows,
        STANDARD_COL_WIDTHS,
        ("Misconfig", "n", "%"),
    )

    # Controls prevalence
    doc.add_paragraph("Controls prevalence", style="Heading 1")
    add_table(
        doc,
        "Controls (primary-only: Controls_1)",
        [row for row in count_table(df["Controls_1"], categories=picks["controls"])[0]],
        STANDARD_COL_WIDTHS,
        ("Controls", "n", "%"),
    )
    add_table(
        doc,
        "Controls (any-occurrence: Controls_1 OR Controls_2)",
        ctrl_any_rows,
        STANDARD_COL_WIDTHS,
        ("Controls", "n", "%"),
    )

    logger.info("Prevalence Snapshot document built successfully")


def build_misconfiguration_matrix(
    doc: Document,
    df: pd.DataFrame,
    picks: Dict[str, List[str]],
    gen_date: str,
    version: str,
) -> None:
    """Build Misconfiguration Matrix document."""
    total = len(df)

    add_header_section(
        doc,
        f"Misconfiguration Matrix ({version})",
        "Mapping and Mitigating SaaS OAuth Post‑SSO Abuse",
        gen_date,
        f"Population: {total} incidents (2023–2026)\n"
        "Primary-only uses Misconfig_1 / Controls_1; Any-occurrence uses _1 OR _2.",
    )

    # Misconfiguration definitions
    doc.add_paragraph("Misconfiguration categories (short definitions)", style="Heading 1")
    for cat in [c for c in picks["misconfig"] if c != "Other / Unknown"]:
        if cat not in MISCONFIG_DEFINITIONS:
            continue
        p = doc.add_paragraph()
        r = p.add_run(f"{cat}: ")
        r.bold = True
        p.add_run(MISCONFIG_DEFINITIONS[cat])

    # Build matrix table
    doc.add_paragraph("Matrix (prevalence + representative cases)", style="Heading 1")
    cats = [c for c in picks["misconfig"] if c != "Other / Unknown"]
    headers = [
        "Misconfiguration",
        "Primary n (%)",
        "Any n (%)",
        "Representative incidents",
        "Common controls (top)",
    ]

    counters = compute_all_counters(df)
    table = doc.add_table(rows=1 + len(cats), cols=len(headers))
    style_table(table)

    # Style header
    for j, h in enumerate(headers):
        cell = table.rows[0].cells[j]
        cell.text = h
        for r in cell.paragraphs[0].runs:
            r.font.bold = True
        set_cell_shading(cell, COLOR_HEADER_BG)
        alignment = WD_ALIGN_PARAGRAPH.CENTER if j in (1, 2) else WD_ALIGN_PARAGRAPH.LEFT
        cell.paragraphs[0].alignment = alignment

    # Fill rows
    for i, cat in enumerate(cats, start=1):
        primary_n = int((df["Misconfig_1"] == cat).sum())
        any_n = counters["misconfig_any"].get(cat, 0)
        reps = ", ".join(representative_ids_for_misconfig(df, cat, 4)) if any_n else ""
        ctrls = ", ".join(common_controls_for_misconfig(df, cat, 3)) if any_n else ""

        row = table.rows[i].cells
        row[0].text = cat
        row[1].text = f"{primary_n} ({pct(primary_n, total):.1f}%)"
        row[2].text = f"{any_n} ({pct(any_n, total):.1f}%)"
        row[3].text = reps
        row[4].text = ctrls

        row[1].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        row[2].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

    # Apply column widths
    for j, w in enumerate(MATRIX_COL_WIDTHS):
        for r in table.rows:
            r.cells[j].width = w

    # Apply small font to all cells
    for row in table.rows:
        for cell in row.cells:
            for p in cell.paragraphs:
                for run in p.runs:
                    run.font.size = Pt(FONT_SIZE_SMALL)

    logger.info("Misconfiguration Matrix document built successfully")


def build_prevalence_brief(
    doc: Document,
    df: pd.DataFrame,
    picks: Dict[str, List[str]],
    gen_date: str,
    version: str,
) -> None:
    """Build Prevalence Brief document."""
    total = len(df)

    add_header_section(
        doc,
        f"Prevalence Brief ({version})",
        "SaaS OAuth Post‑SSO Abuse in Public Reporting (2022–2026)",
        gen_date,
        f"Dataset: {total} incidents coded in Incident_Extraction_Template_{version}.xlsx",
    )

    # Scope and method
    doc.add_paragraph("Scope and method", style="Heading 1")
    doc.add_paragraph(
        "This brief summarizes a curated dataset of publicly reported incidents (2023–2026) "
        "that explicitly describe OAuth-enabled post‑SSO abuse in SaaS/IdP contexts. "
        "Each row represents one incident/campaign/case study and is coded using the v0.X schema. "
        "Prevalence is reported in two views: primary-only (Misconfig_1/Controls_1) and "
        "any-occurrence (_1 OR _2)."
    )

    # Key findings (same highlights as snapshot)
    doc.add_paragraph("Key findings", style="Heading 1")
    attack_rows, _ = count_table(df["Attack_Type"])
    impact_rows, _ = count_table(df["Impact_Primary"])
    mis1_rows, _ = count_table(df["Misconfig_1"], categories=picks["misconfig"])
    counters = compute_all_counters(df)

    consent_n = next(
        (n for k, n, _ in attack_rows if k.startswith("OAuth consent phishing")), 0
    )
    device_n = next(
        (n for k, n, _ in attack_rows if k.startswith("Device code phishing")), 0
    )
    exfil_n = next((n for k, n, _ in impact_rows if k == "Data exfiltration"), 0)
    primary_flow_n = next(
        (n for k, n, _ in mis1_rows if k == "OAuth flow / client hardening gaps"), 0
    )
    det_any = counters["controls_any"].get("Detection on anomalous OAuth/API behavior", 0)

    highlights = [
        f"Total incidents coded: {total} (2022–2026).",
        f"Top attack types: Consent phishing ({consent_n}/{total}) and device code phishing ({device_n}/{total}).",
        f"Primary impact is data exfiltration ({exfil_n}/{total}).",
        f"Primary misconfiguration signal: OAuth flow / client hardening gaps ({primary_flow_n}/{total}).",
        f"Most frequent control gap (any-occurrence): Detection on anomalous OAuth/API behavior ({det_any}/{total}).",
    ]
    for h in highlights:
        doc.add_paragraph(h, style="List Bullet")

    # Prevalence tables
    doc.add_paragraph("Prevalence tables", style="Heading 1")
    add_table(doc, "Attack_Type", attack_rows, STANDARD_COL_WIDTHS, ("Attack_Type", "n", "%"))
    add_table(doc, "Impact_Primary", impact_rows, STANDARD_COL_WIDTHS, ("Impact_Primary", "n", "%"))
    add_table(doc, "Misconfig (primary-only)", mis1_rows, STANDARD_COL_WIDTHS, ("Misconfig", "n", "%"))

    # Limitations
    doc.add_paragraph("Limitations", style="Heading 1")
    limitations = [
        "Public-reporting bias: Entra/M365 incidents and Microsoft-centric reporting are overrepresented.",
        "Outcome ambiguity: some sources document attempted campaigns with limited confirmation of data theft; Confidence reflects this.",
        "Taxonomy fit: rare mechanisms (e.g., signing-key-based token forgery) require best-fit mapping in Attack_Type while preserving detail in Notes.",
    ]
    for lim in limitations:
        doc.add_paragraph(lim, style="List Bullet")

    logger.info("Prevalence Brief document built successfully")


def build_docs(
    df: pd.DataFrame,
    picks: Dict[str, List[str]],
    out_dir: str,
    version: str = "v0.X",
) -> None:
    """Generate all three artifacts."""
    gen_date = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    logger.info(f"Generating documents to {out_dir}")

    # Snapshot
    logger.info("Building Prevalence Snapshot")
    doc = Document()
    apply_doc_style(doc)
    build_prevalence_snapshot(doc, df, picks, gen_date, version)
    snapshot_file = out_path / f"{version}_Prevalence_Snapshot.docx"
    doc.save(str(snapshot_file))
    logger.info(f"Saved: {snapshot_file}")

    # Misconfiguration Matrix
    logger.info("Building Misconfiguration Matrix")
    mdoc = Document()
    apply_doc_style(mdoc)
    build_misconfiguration_matrix(mdoc, df, picks, gen_date, version)
    matrix_file = out_path / f"{version}_Misconfiguration_Matrix.docx"
    mdoc.save(str(matrix_file))
    logger.info(f"Saved: {matrix_file}")

    # Prevalence Brief
    logger.info("Building Prevalence Brief")
    bdoc = Document()
    apply_doc_style(bdoc)
    build_prevalence_brief(bdoc, df, picks, gen_date, version)
    brief_file = out_path / f"{version}_Prevalence_Brief.docx"
    bdoc.save(str(brief_file))
    logger.info(f"Saved: {brief_file}")

    logger.info("✓ All documents generated successfully")


# ============================================================================
# MAIN
# ============================================================================

def main() -> None:
    """Main entry point."""
    ap = argparse.ArgumentParser(
        description="Generate prevalence artifacts from Incident_Extraction workbook."
    )
    ap.add_argument(
        "--xlsx",
        required=True,
        help="Path to Incident_Extraction_v0.X.xlsx workbook",
    )
    ap.add_argument(
        "--out_dir",
        default=".",
        help="Output directory for generated documents",
    )
    ap.add_argument(
        "--version",
        default="v0.X",
        help="Schema version (e.g., v0.1, v0.2)",
    )
    ap.add_argument(
        "--log_level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level",
    )

    args = ap.parse_args()
    setup_logging(getattr(logging, args.log_level))

    try:
        logger.info(f"Starting artifact generation with version: {args.version}")
        wb = load_workbook_safe(args.xlsx)
        picks = read_picklists(wb)
        df = load_incidents(wb)
        build_docs(df, picks, args.out_dir, args.version)
        logger.info("✓ Generation complete")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main()