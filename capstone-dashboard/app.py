from pathlib import Path

import pandas as pd
import streamlit as st
import plotly.express as px

# -------------------------------------------------------------------
# Page setup
# -------------------------------------------------------------------

st.set_page_config(
    page_title="SaaS OAuth Abuse Analysis Dashboard",
    page_icon="🔐",
    layout="wide",
)

LOGO_PATH = Path("capstone-dashboard/data/uw_logo.png")

if LOGO_PATH.exists():
    st.logo(str(LOGO_PATH), size="large")

DATA_PATH = Path("capstone-dashboard/data/Sanitized_Export.csv")
COVERAGE_PATH = Path("capstone-dashboard/data/Defense_Coverage_Matrix.xlsx")

REQUIRED_COLUMNS = [
    "Incident_ID",
    "Source_Date",
    "IdP_Context",
    "SaaS_Context",
    "Attack_Type",
    "Entry_Vector",
    "OAuth_Flow",
    "Token_Artifacts",
    "Misconfig_1",
    "Misconfig_2",
    "Controls_1",
    "Controls_2",
    "Impact_Primary",
    "Confidence",
]

OPTIONAL_COLUMNS = [
    "Source_URL",
]

COVERAGE_SUMMARY_COLUMNS = [
    "Misconfiguration Category",
    "Primary Control Family",
    "Coverage Purpose",
    "Default Posture Question",
    "Recommended Hardened Baseline",
    "Residual Gap / Process Need",
    "Blueprint Tier",
]

PLATFORM_TRACKER_COLUMNS = [
    "Misconfiguration Category",
    "Primary Control Family",
    "Platform",
    "Native Control Exists?",
    "Default Coverage",
    "Hardened Coverage",
    "Evidence / Notes / URL",
]

# -------------------------------------------------------------------
# Data loading
# -------------------------------------------------------------------

@st.cache_data
def load_data(path: Path) -> pd.DataFrame:
    if not path.exists():
        st.error(f"Dataset not found: {path}")
        st.stop()

    df = pd.read_csv(path)
    df.columns = [str(col).strip() for col in df.columns]

    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.write("Available columns:", list(df.columns))
        st.stop()

    for col in OPTIONAL_COLUMNS:
        if col not in df.columns:
            df[col] = ""

    df["Source_Date"] = pd.to_datetime(df["Source_Date"], errors="coerce")
    df["Source_Year"] = df["Source_Date"].dt.year

    text_cols = df.select_dtypes(include=["object", "string"]).columns
    df[text_cols] = df[text_cols].fillna("").apply(
        lambda col: col.map(lambda x: x.strip() if isinstance(x, str) else x)
    )

    return df

@st.cache_data
def load_coverage_matrix(path: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load the Defense Coverage Matrix workbook.

    The template uses three title/helper rows, so the real table headers start on row 4.
    This function returns:
      1. Summary Matrix: one row per misconfiguration category.
      2. Platform Tracker: optional vendor-evidence tracker.
    """
    empty_summary = pd.DataFrame(columns=COVERAGE_SUMMARY_COLUMNS)
    empty_tracker = pd.DataFrame(columns=PLATFORM_TRACKER_COLUMNS)

    if not path.exists():
        return empty_summary, empty_tracker

    try:
        summary = pd.read_excel(path, sheet_name="Summary Matrix", header=3)
    except Exception as exc:
        st.warning(f"Could not load Summary Matrix from {path}: {exc}")
        return empty_summary, empty_tracker

    try:
        tracker = pd.read_excel(path, sheet_name="Platform Tracker", header=3)
    except Exception:
        tracker = empty_tracker.copy()

    summary.columns = [str(col).strip() for col in summary.columns]
    tracker.columns = [str(col).strip() for col in tracker.columns]

    summary = summary.dropna(how="all")
    tracker = tracker.dropna(how="all")

    if "Misconfiguration Category" in summary.columns:
        summary = summary[summary["Misconfiguration Category"].notna()].copy()

    if "Misconfiguration Category" in tracker.columns:
        tracker = tracker[tracker["Misconfiguration Category"].notna()].copy()

    for required_col in COVERAGE_SUMMARY_COLUMNS:
        if required_col not in summary.columns:
            summary[required_col] = ""

    for required_col in PLATFORM_TRACKER_COLUMNS:
        if required_col not in tracker.columns:
            tracker[required_col] = ""

    summary = summary[COVERAGE_SUMMARY_COLUMNS]
    tracker = tracker[PLATFORM_TRACKER_COLUMNS]

    for frame in [summary, tracker]:
        text_cols = frame.select_dtypes(include=["object", "str", "string"]).columns
        frame[text_cols] = frame[text_cols].fillna("").apply(
            lambda col: col.map(lambda x: x.strip() if isinstance(x, str) else x)
        )

    return summary, tracker

df = load_data(DATA_PATH)
coverage_summary_df, platform_tracker_df = load_coverage_matrix(COVERAGE_PATH)

# -------------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------------

def top_n_with_other(
    counts_df: pd.DataFrame,
    category_col: str,
    value_col: str,
    n: int = 5,
) -> pd.DataFrame:
    if len(counts_df) <= n:
        return counts_df.copy()

    top = counts_df.head(n).copy()
    other_count = counts_df.iloc[n:][value_col].sum()

    other = pd.DataFrame(
        [{category_col: "Other", value_col: other_count}]
    )

    return pd.concat([top, other], ignore_index=True)

def short_label(value: str, max_len: int = 42) -> str:
    value = str(value)
    return value if len(value) <= max_len else value[: max_len - 3] + "..."

def count_series(series: pd.Series, denominator: int | None = None) -> pd.DataFrame:
    clean = series.dropna()
    clean = clean[clean.astype(str).str.strip() != ""]
    total = denominator if denominator is not None else len(clean)

    counts = clean.value_counts().reset_index()
    counts.columns = ["Category", "Count"]
    counts["Percent"] = (counts["Count"] / total * 100).round(1) if total else 0.0
    return counts

def any_occurrence_count(data: pd.DataFrame, col1: str, col2: str, label: str) -> pd.DataFrame:
    values = []

    for _, row in data.iterrows():
        seen = set()
        for col in [col1, col2]:
            value = str(row.get(col, "")).strip()
            if value and value not in seen:
                values.append(value)
                seen.add(value)

    if not values:
        return pd.DataFrame(columns=[label, "Count", "Percent"])

    result = pd.Series(values).value_counts().reset_index()
    result.columns = [label, "Count"]
    result["Percent"] = (result["Count"] / len(data) * 100).round(1) if len(data) else 0.0
    return result

def get_any_occurrence_values(data: pd.DataFrame, col1: str, col2: str) -> set[str]:
    values = set()
    for _, row in data.iterrows():
        for col in [col1, col2]:
            value = str(row.get(col, "")).strip()
            if value:
                values.add(value)
    return values

def coverage_for_misconfigs(
    coverage_summary: pd.DataFrame,
    misconfigs: set[str] | list[str],
) -> pd.DataFrame:
    if coverage_summary.empty:
        return coverage_summary.copy()

    misconfig_set = {str(value).strip() for value in misconfigs if str(value).strip()}
    return coverage_summary[
        coverage_summary["Misconfiguration Category"].isin(misconfig_set)
    ].copy()

def apply_filters(data: pd.DataFrame) -> pd.DataFrame:
    filtered = data.copy()

    with st.sidebar:
        st.header("Filters")

        years = sorted([int(y) for y in filtered["Source_Year"].dropna().unique()])
        if years:
            selected_years = st.multiselect("Source year", years, default=years)
            if selected_years:
                filtered = filtered[filtered["Source_Year"].isin(selected_years)]

        idps = sorted([x for x in filtered["IdP_Context"].dropna().unique() if x])
        selected_idps = st.multiselect("IdP context", idps, default=idps)
        if selected_idps:
            filtered = filtered[filtered["IdP_Context"].isin(selected_idps)]

        attack_types = sorted([x for x in filtered["Attack_Type"].dropna().unique() if x])
        selected_attacks = st.multiselect("Attack type", attack_types, default=attack_types)
        if selected_attacks:
            filtered = filtered[filtered["Attack_Type"].isin(selected_attacks)]

        confidence_values = sorted([x for x in filtered["Confidence"].dropna().unique() if x])
        selected_confidence = st.multiselect("Confidence", confidence_values, default=confidence_values)
        if selected_confidence:
            filtered = filtered[filtered["Confidence"].isin(selected_confidence)]

    return filtered

def donut_chart(counts_df: pd.DataFrame, names_col: str, values_col: str, title: str):
    fig = px.pie(
        counts_df,
        names=names_col,
        values=values_col,
        hole=0.45,
        title=title,
    )
    fig.update_traces(textposition="inside", textinfo="percent")
    fig.update_layout(
        showlegend=True,
        title_font_size=24,
        font_size=16,
        margin=dict(t=60, b=20, l=20, r=20),
    )
    return fig

def dot_escape(value: str) -> str:
    """Escape text for Graphviz node labels."""
    return str(value).replace('"', "'").replace("\n", " ")


def defense_flow_diagram(
    misconfiguration: str,
    control_family: str,
    blueprint_tier: str,
):
    """Render a simple risk-to-defense flow diagram."""
    misconfiguration = dot_escape(misconfiguration)
    control_family = dot_escape(control_family)
    blueprint_tier = dot_escape(blueprint_tier)

    return f"""
    digraph {{
        graph [
            rankdir=LR,
            bgcolor="transparent",
            pad="0.25",
            nodesep="0.6",
            ranksep="0.7"
        ]

        node [
            shape=box,
            style="rounded,filled",
            fontname="Arial",
            fontsize=14,
            margin="0.18,0.12",
            fillcolor="#F8FAFC",
            color="#CBD5E1"
        ]

        edge [
            color="#64748B",
            arrowsize=0.8
        ]

        attack [
            label="OAuth abuse pattern"
        ]

        misconfig [
            label="Misconfiguration\\n{misconfiguration}",
            fillcolor="#FEF3C7"
        ]

        control [
            label="Primary control family\\n{control_family}",
            fillcolor="#DBEAFE"
        ]

        baseline [
            label="Recommended hardened baseline",
            fillcolor="#DCFCE7"
        ]

        gap [
            label="Residual gap / process need",
            fillcolor="#FEE2E2"
        ]

        tier [
            label="Blueprint tier\\n{blueprint_tier}",
            fillcolor="#EDE9FE"
        ]

        attack -> misconfig -> control -> baseline -> gap -> tier
    }}
    """


def add_incident_counts_to_coverage(
    coverage_df: pd.DataFrame,
    incidents_df: pd.DataFrame,
) -> pd.DataFrame:
    """Add any-occurrence incident counts to Defense Coverage Matrix rows."""
    if coverage_df.empty:
        return coverage_df.copy()

    misconfig_counts = any_occurrence_count(
        incidents_df,
        "Misconfig_1",
        "Misconfig_2",
        "Misconfiguration",
    )

    if misconfig_counts.empty:
        output = coverage_df.copy()
        output["Incident Count"] = 0
        output["Incident Percent"] = 0.0
        return output

    count_map = dict(zip(misconfig_counts["Misconfiguration"], misconfig_counts["Count"]))
    percent_map = dict(zip(misconfig_counts["Misconfiguration"], misconfig_counts["Percent"]))

    output = coverage_df.copy()
    output["Incident Count"] = output["Misconfiguration Category"].map(count_map).fillna(0).astype(int)
    output["Incident Percent"] = output["Misconfiguration Category"].map(percent_map).fillna(0.0)

    return output

def horizontal_bar(counts_df: pd.DataFrame, category_col: str, value_col: str, title: str):
    chart_df = counts_df.sort_values(value_col, ascending=True)
    fig = px.bar(
        chart_df,
        x=value_col,
        y=category_col,
        orientation="h",
        title=title,
        text=value_col,
    )
    fig.update_layout(
        title_font_size=24,
        font_size=16,
        margin=dict(t=60, b=30, l=20, r=20),
        yaxis_title="",
        xaxis_title="Count",
    )
    return fig

def year_count_chart(data: pd.DataFrame, title: str):
    yearly = (
        data.dropna(subset=["Source_Year"])
        .groupby("Source_Year")
        .size()
        .reset_index(name="Count")
    )
    yearly["Source_Year"] = yearly["Source_Year"].astype(int).astype(str)

    fig = px.line(
        yearly,
        x="Source_Year",
        y="Count",
        markers=True,
        title=title,
    )
    fig.update_layout(
        title_font_size=24,
        font_size=16,
        xaxis_title="Year",
        yaxis_title="Number of coded incidents",
        margin=dict(t=60, b=30, l=20, r=20),
    )
    return fig


def stacked_year_bar(data: pd.DataFrame, category_col: str, title: str, top_n: int = 5):
    clean = data.dropna(subset=["Source_Year"]).copy()
    clean = clean[clean[category_col].astype(str).str.strip() != ""]

    top_categories = clean[category_col].value_counts().head(top_n).index.tolist()
    clean[category_col] = clean[category_col].where(
        clean[category_col].isin(top_categories),
        "Other",
    )

    grouped = (
        clean.groupby(["Source_Year", category_col])
        .size()
        .reset_index(name="Count")
    )
    grouped["Source_Year"] = grouped["Source_Year"].astype(int).astype(str)

    fig = px.bar(
        grouped,
        x="Source_Year",
        y="Count",
        color=category_col,
        title=title,
    )
    fig.update_layout(
        title_font_size=24,
        font_size=16,
        xaxis_title="Year",
        yaxis_title="Number of coded incidents",
        legend_title="",
        margin=dict(t=60, b=30, l=20, r=20),
    )
    return fig


def category_heatmap(
    data: pd.DataFrame,
    row_col: str,
    col_col: str,
    title: str,
):
    clean = data.copy()
    clean = clean[
        (clean[row_col].astype(str).str.strip() != "")
        & (clean[col_col].astype(str).str.strip() != "")
    ]

    if clean.empty:
        return None

    pivot = pd.crosstab(clean[row_col], clean[col_col])

    fig = px.imshow(
        pivot,
        text_auto=True,
        aspect="auto",
        title=title,
    )
    fig.update_layout(
        title_font_size=24,
        font_size=15,
        xaxis_title=col_col.replace("_", " "),
        yaxis_title=row_col.replace("_", " "),
        margin=dict(t=60, b=30, l=20, r=20),
    )
    return fig


def any_occurrence_long(
    data: pd.DataFrame,
    col1: str,
    col2: str,
    label: str,
) -> pd.DataFrame:
    rows = []

    for _, row in data.iterrows():
        seen = set()
        for col in [col1, col2]:
            value = str(row.get(col, "")).strip()
            if value and value not in seen:
                rows.append(
                    {
                        "Incident_ID": row["Incident_ID"],
                        "Source_Year": row["Source_Year"],
                        label: value,
                    }
                )
                seen.add(value)

    return pd.DataFrame(rows)

filtered_df = apply_filters(df)

# -------------------------------------------------------------------
# App title
# -------------------------------------------------------------------

st.title("SaaS OAuth Abuse Analysis Dashboard")

st.markdown(
    """
#### This dashboard provides an interactive view of the 32 analyzed OAuth related incidents.
"""
)

# -------------------------------------------------------------------
# Tabs
# -------------------------------------------------------------------

tab_problem, tab_board, tab_trends, tab_defense, tab_findings, tab_scenario, tab_incidents, tab_method = st.tabs(
    [
        "The Problem",
        "Board Briefing",
        "Trends + Risk Lens",
        "Defense Coverage Matrix",
        "Findings Explorer",
        "Scenario Walkthrough",
        "Incident Explorer",
        "Analyst Appendix",
    ]
)

# -------------------------------------------------------------------
# The Problem
# -------------------------------------------------------------------

with tab_problem:
    st.markdown("# The Problem")

    st.info(
        "OAuth is the mechanism that lets one application access another service without sharing a user’s password. "
        "That convenience also creates a security problem: if an attacker tricks a user, compromises an app, or steals a token, "
        "they may keep access even after the normal login event is over."
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.container(border=True).markdown(
            "### 1. User or admin authorizes access\n"
            "A person signs in or approves an app request."
        )

    with col2:
        st.container(border=True).markdown(
            "### 2. App receives a token\n"
            "The token becomes the app’s permission to call APIs."
        )

    with col3:
        st.container(border=True).markdown(
            "### 3. Attacker abuses that trust\n"
            "If the app, token, or consent process is weak, access can persist."
        )

    st.markdown("## Why this matters")
    st.markdown(
        """
        Security teams often know how to respond to suspicious logins, malware, or endpoint alerts.
        OAuth abuse is harder because the activity can look like normal application access.
        This project turns scattered public incident reporting into a vendor-neutral view of:
        
        - which OAuth abuse patterns appear most often,
        - which misconfigurations enable them,
        - and which controls reduce the risk.
        """
    )

    st.markdown("## OAuth flow, simplified")
    st.image("capstone-dashboard/data/OAuth_Flow_UML.png")
    st.caption(
        "Simplified OAuth flow: the user authorizes an application, the application receives a token, and the token is used to access SaaS resources."
    )

# -------------------------------------------------------------------
# Board Briefing
# -------------------------------------------------------------------

with tab_board:
    st.markdown("# Board Briefing")
    st.markdown(
        "Summary of SaaS OAuth abuse patterns, mapped to practical defense priorities."
    )

    st.markdown("## How to read this dashboard")

    read_col1, read_col2, read_col3 = st.columns(3)

    with read_col1:
        st.container(border=True).markdown(
            "### Prevalence\n"
            "Which OAuth abuse patterns appear most often in the coded public reports?"
        )

    with read_col2:
        st.container(border=True).markdown(
            "### Misconfiguration\n"
            "Which tenant or application settings helped make the abuse possible?"
        )

    with read_col3:
        st.container(border=True).markdown(
            "### Defense coverage\n"
            "Which controls reduce the risk, and where do residual gaps remain?"
        )

    total_incidents = len(filtered_df)
    date_min = filtered_df["Source_Date"].min()
    date_max = filtered_df["Source_Date"].max()

    attack_counts = count_series(filtered_df["Attack_Type"], total_incidents)
    impact_counts = count_series(filtered_df["Impact_Primary"], total_incidents)
    idp_counts = count_series(filtered_df["IdP_Context"], total_incidents)
    misconfig_any = any_occurrence_count(
        filtered_df, "Misconfig_1", "Misconfig_2", "Misconfiguration"
    )
    controls_any = any_occurrence_count(
        filtered_df, "Controls_1", "Controls_2", "Control Gap"
    )

    top_attack_row = attack_counts.iloc[0] if not attack_counts.empty else None
    top_misconfig_row = misconfig_any.iloc[0] if not misconfig_any.empty else None
    top_control_row = controls_any.iloc[0] if not controls_any.empty else None

    kpi1, kpi2, kpi3, kpi4 = st.columns(4)

    kpi1.metric("Coded Incidents", total_incidents)

    if top_attack_row is not None:
        kpi2.metric(
            "Top Attack Pattern",
            short_label(top_attack_row["Category"]),
            f"{top_attack_row['Count']} cases / {top_attack_row['Percent']}%",
        )
    else:
        kpi2.metric("Top Attack Pattern", "N/A")

    if top_misconfig_row is not None:
        kpi3.metric(
            "Top Misconfiguration",
            short_label(top_misconfig_row["Misconfiguration"]),
            f"{top_misconfig_row['Count']} cases / {top_misconfig_row['Percent']}%",
        )
    else:
        kpi3.metric("Top Misconfiguration", "N/A")

    if top_control_row is not None:
        kpi4.metric(
            "Top Control Gap",
            short_label(top_control_row["Control Gap"]),
            f"{top_control_row['Count']} cases / {top_control_row['Percent']}%",
        )
    else:
        kpi4.metric("Top Control Gap", "N/A")

    if pd.notna(date_min) and pd.notna(date_max):
        st.caption(f"Filtered date range: {date_min.date()} to {date_max.date()}")

    st.divider()

    chart_col1, chart_col2 = st.columns(2)
    
    st.markdown("## High-level trend")

    if not filtered_df.empty:
        st.plotly_chart(
            year_count_chart(
                filtered_df,
                "Coded OAuth Abuse Reports Over Time",
            ),
            width="stretch",
        )

    with chart_col1:
        if not attack_counts.empty:
            st.plotly_chart(
                donut_chart(
                    top_n_with_other(attack_counts, "Category", "Count", n=5),
                    "Category",
                    "Count",
                    "Attack Type Share",
                ),
                width="stretch",
            )
        else:
            st.info("No attack type data available for the current filters.")

    with chart_col2:
        if not impact_counts.empty:
            st.plotly_chart(
                donut_chart(
                    top_n_with_other(impact_counts, "Category", "Count", n=5),
                    "Category",
                    "Count",
                    "Primary Impact Share",
                ),
                width="stretch",
            )
        else:
            st.info("No impact data available for the current filters.")

    chart_col3, chart_col4 = st.columns(2)

    with chart_col3:
        if not idp_counts.empty:
            st.plotly_chart(
                donut_chart(
                    top_n_with_other(idp_counts, "Category", "Count", n=5),
                    "Category",
                    "Count",
                    "IdP Context Share",
                ),
                width="stretch",
            )
        else:
            st.info("No IdP context data available for the current filters.")

    with chart_col4:
        if not controls_any.empty:
            st.plotly_chart(
                horizontal_bar(
                    controls_any.head(8),
                    "Control Gap",
                    "Count",
                    "Most Frequent Control Gaps",
                ),
                width="stretch",
            )
        else:
            st.info("No control gap data available for the current filters.")

    st.markdown("## Main Finding")
    st.info(
        "OAuth abuse is not only an authentication issue. The recurring risk pattern is weak application governance, token control, and post-consent visibility. The Defense Coverage Matrix turns those patterns into hardening priorities."
    )

    if not coverage_summary_df.empty:
        st.markdown("## Defense Matrix Priority")
        start_here_count = int(
            (coverage_summary_df["Blueprint Tier"].str.strip() == "Start Here").sum()
        )
        st.success(
            f"The Defense Coverage Matrix currently identifies {start_here_count} Start Here control categories. Use the Defense Coverage Matrix tab as the main hardening roadmap."
        )

# -------------------------------------------------------------------
# Trends + Risk Lens
# -------------------------------------------------------------------

with tab_trends:
    st.markdown("# Trends + Risk Lens")
    st.markdown(
        "Security-focused analytics that show how OAuth abuse patterns, misconfigurations, and control gaps appear across the coded dataset."
    )

    total_incidents = len(filtered_df)

    if total_incidents == 0:
        st.info("No incidents match the current filters.")
    else:
        st.markdown("## Reporting trend over time")

        trend_col1, trend_col2 = st.columns(2)

        with trend_col1:
            st.plotly_chart(
                year_count_chart(
                    filtered_df,
                    "Coded Incidents by Year",
                ),
                width="stretch",
            )

        with trend_col2:
            st.plotly_chart(
                stacked_year_bar(
                    filtered_df,
                    "Attack_Type",
                    "Attack Types Over Time",
                    top_n=5,
                ),
                width="stretch",
            )

        st.info(
            "Use this view carefully: the chart shows trends in public reporting, not the true global rate of OAuth abuse. "
            "It is still useful for showing which techniques recur across published incidents."
        )

        st.divider()

        st.markdown("## Security risk lens")

        heatmap_col1, heatmap_col2 = st.columns(2)

        with heatmap_col1:
            fig = category_heatmap(
                filtered_df,
                "Attack_Type",
                "Impact_Primary",
                "Attack Type by Primary Impact",
            )
            if fig:
                st.plotly_chart(fig, width="stretch")
            else:
                st.info("Not enough data to build attack-impact heatmap.")

        with heatmap_col2:
            fig = category_heatmap(
                filtered_df,
                "Attack_Type",
                "IdP_Context",
                "Attack Type by IdP Context",
            )
            if fig:
                st.plotly_chart(fig, width="stretch")
            else:
                st.info("Not enough data to build attack-IdP heatmap.")

        st.divider()

        st.markdown("## Misconfiguration and control-gap trends")

        misconfig_long = any_occurrence_long(
            filtered_df,
            "Misconfig_1",
            "Misconfig_2",
            "Misconfiguration",
        )

        controls_long = any_occurrence_long(
            filtered_df,
            "Controls_1",
            "Controls_2",
            "Control Gap",
        )

        trend_col3, trend_col4 = st.columns(2)

        with trend_col3:
            if not misconfig_long.empty:
                st.plotly_chart(
                    stacked_year_bar(
                        misconfig_long,
                        "Misconfiguration",
                        "Misconfigurations Over Time",
                        top_n=5,
                    ),
                    width="stretch",
                )
            else:
                st.info("No misconfiguration trend data available.")

        with trend_col4:
            if not controls_long.empty:
                st.plotly_chart(
                    stacked_year_bar(
                        controls_long,
                        "Control Gap",
                        "Control Gaps Over Time",
                        top_n=5,
                    ),
                    width="stretch",
                )
            else:
                st.info("No control-gap trend data available.")

        st.warning(
            "Interpretation note: these are trends in public reporting, not confirmed prevalence across all organizations. "
            "The value is in identifying recurring patterns and defensive priorities."
        )

        st.divider()

        st.markdown("## What this suggests for defenders")

        insight_col1, insight_col2, insight_col3 = st.columns(3)

        with insight_col1:
            st.container(border=True).markdown(
                "### Prioritize app governance\n"
                "Repeated OAuth abuse patterns point to the need for stronger consent review, app inventory, and app approval workflows."
            )

        with insight_col2:
            st.container(border=True).markdown(
                "### Treat tokens as access paths\n"
                "OAuth tokens and refresh tokens should be treated as durable access artifacts, not just temporary byproducts of login."
            )

        with insight_col3:
            st.container(border=True).markdown(
                "### Monitor API behavior\n"
                "Detection should look beyond sign-in events and include suspicious OAuth grants, app changes, and abnormal SaaS API usage."
            )

# -------------------------------------------------------------------
# Findings Explorer
# -------------------------------------------------------------------

with tab_findings:
    st.markdown("# Findings Explorer")
    st.markdown(
        "Select a finding to see its frequency, supporting incidents, and — when applicable — Defense Coverage Matrix alignment."
    )

    total_incidents = len(filtered_df)

    attack_counts = count_series(filtered_df["Attack_Type"], total_incidents)
    impact_counts = count_series(filtered_df["Impact_Primary"], total_incidents)
    entry_counts = count_series(filtered_df["Entry_Vector"], total_incidents)
    misconfig_any = any_occurrence_count(
        filtered_df, "Misconfig_1", "Misconfig_2", "Misconfiguration"
    )
    controls_any = any_occurrence_count(
        filtered_df, "Controls_1", "Controls_2", "Control Gap"
    )

    finding_type = st.radio(
        "Finding type",
        ["Attack Type", "Entry Vector", "Misconfiguration", "Control Gap", "Impact"],
        horizontal=True,
    )

    if finding_type == "Attack Type":
        source_df = attack_counts.copy()
        label_col = "Category"
        source_column = "Attack_Type"
    elif finding_type == "Entry Vector":
        source_df = entry_counts.copy()
        label_col = "Category"
        source_column = "Entry_Vector"
    elif finding_type == "Misconfiguration":
        source_df = misconfig_any.rename(columns={"Misconfiguration": "Category"})
        label_col = "Category"
        source_column = None
    elif finding_type == "Control Gap":
        source_df = controls_any.rename(columns={"Control Gap": "Category"})
        label_col = "Category"
        source_column = None
    else:
        source_df = impact_counts.copy()
        label_col = "Category"
        source_column = "Impact_Primary"

    if source_df.empty:
        st.info("No findings available for the current filters.")
    else:
        selected_finding = st.selectbox(
            "Select finding",
            source_df[label_col].astype(str).tolist(),
        )

        selected_row = source_df[source_df[label_col] == selected_finding].iloc[0]

        metric_col1, metric_col2, metric_col3 = st.columns(3)
        metric_col1.metric("Finding", selected_finding)
        metric_col2.metric("Cases", int(selected_row["Count"]))
        metric_col3.metric("Share of Filtered Dataset", f"{selected_row['Percent']}%")

        st.plotly_chart(
            horizontal_bar(
                source_df.head(10),
                label_col,
                "Count",
                f"Top {finding_type} Findings",
            ),
            width="stretch",
        )

        st.divider()

        if finding_type == "Misconfiguration":
            supporting = filtered_df[
                (filtered_df["Misconfig_1"] == selected_finding)
                | (filtered_df["Misconfig_2"] == selected_finding)
            ]

            st.markdown("## Defense Coverage Matrix Alignment")
            coverage = coverage_for_misconfigs(coverage_summary_df, [selected_finding])

            if not coverage.empty:
                for _, row in coverage.iterrows():
                    with st.container(border=True):
                        st.markdown(f"### {row['Misconfiguration Category']}")
                        st.markdown(f"**Primary Control Family:** {row['Primary Control Family']}")
                        st.markdown(f"**Coverage Purpose:** {row['Coverage Purpose']}")
                        st.markdown(f"**Blueprint Tier:** {row['Blueprint Tier']}")

                        with st.expander("Recommended hardened baseline"):
                            st.write(row["Recommended Hardened Baseline"])

                        with st.expander("Residual gap / process need"):
                            st.write(row["Residual Gap / Process Need"])
            else:
                st.warning("No matching Defense Coverage Matrix row found for this misconfiguration.")

        elif finding_type == "Control Gap":
            supporting = filtered_df[
                (filtered_df["Controls_1"] == selected_finding)
                | (filtered_df["Controls_2"] == selected_finding)
            ]

        else:
            supporting = filtered_df[filtered_df[source_column] == selected_finding]

        st.markdown("## Supporting Incidents")

        supporting_columns = [
            "Incident_ID",
            "Source_Date",
            "IdP_Context",
            "SaaS_Context",
            "Attack_Type",
            "Entry_Vector",
            "Misconfig_1",
            "Misconfig_2",
            "Controls_1",
            "Controls_2",
            "Impact_Primary",
            "Confidence",
            "Source_URL",
        ]

        supporting_view = supporting[supporting_columns].copy()
        supporting_view["Source_Date"] = supporting_view["Source_Date"].dt.date

        st.dataframe(
            supporting_view,
            width="stretch",
            hide_index=True,
            column_config={
                "Source_URL": st.column_config.LinkColumn("Source URL"),
            },
        )

# -------------------------------------------------------------------
# Incident Explorer
# -------------------------------------------------------------------

with tab_incidents:
    st.subheader("Incident Explorer")

    display_columns = [
        "Incident_ID",
        "Source_Date",
        "IdP_Context",
        "SaaS_Context",
        "Attack_Type",
        "Entry_Vector",
        "Misconfig_1",
        "Misconfig_2",
        "Controls_1",
        "Controls_2",
        "Impact_Primary",
        "Confidence",
        "Source_URL",
    ]

    incident_table = filtered_df[display_columns].copy()
    incident_table["Source_Date"] = incident_table["Source_Date"].dt.date

    st.dataframe(
        incident_table,
        width="stretch",
        hide_index=True,
        column_config={
            "Source_URL": st.column_config.LinkColumn("Source URL"),
        },
    )

# -------------------------------------------------------------------
# Defense Coverage Matrix
# -------------------------------------------------------------------

with tab_defense:
    st.markdown("# Defense Coverage Matrix")
    st.markdown(
        "Use this view to translate OAuth abuse patterns into practical hardening decisions."
    )

    if coverage_summary_df.empty:
        st.warning(
            "Defense Coverage Matrix workbook not found or not readable. "
            "Place it at `capstone-dashboard/data/Defense_Coverage_Matrix.xlsx`."
        )
        st.code(
            "project-root/\n"
            "├── app.py\n"
            "└── capstone-dashboard/\n"
            "    └── data/\n"
            "        ├── Sanitized_Export.csv\n"
            "        └── Defense_Coverage_Matrix.xlsx",
            language="text",
        )
    else:
        filtered_misconfigs = get_any_occurrence_values(
            filtered_df,
            "Misconfig_1",
            "Misconfig_2",
        )

        incident_coverage_df = coverage_for_misconfigs(
            coverage_summary_df,
            filtered_misconfigs,
        )

        missing_matrix_rows = sorted(
            filtered_misconfigs - set(coverage_summary_df["Misconfiguration Category"])
        )

        coverage_with_counts = add_incident_counts_to_coverage(
            coverage_summary_df,
            filtered_df,
        )

        incident_coverage_with_counts = add_incident_counts_to_coverage(
            incident_coverage_df,
            filtered_df,
        )

        st.markdown("## How to read this matrix")

        read_col1, read_col2, read_col3 = st.columns(3)

        with read_col1:
            st.container(border=True).markdown(
                "### Risk pattern\n"
                "Which misconfiguration shows up in the coded incidents?"
            )

        with read_col2:
            st.container(border=True).markdown(
                "### Defense coverage\n"
                "Which control family reduces or detects that risk?"
            )

        with read_col3:
            st.container(border=True).markdown(
                "### Remaining gap\n"
                "What still requires process, monitoring, review, or operational response?"
            )

        st.divider()

        metric1, metric2, metric3, metric4 = st.columns(4)

        metric1.metric("Matrix Categories", len(coverage_summary_df))
        metric2.metric("Relevant to Current Filters", len(incident_coverage_df))
        metric3.metric(
            "Start Here Controls",
            int((coverage_summary_df["Blueprint Tier"].str.strip() == "Start Here").sum()),
        )
        metric4.metric(
            "Residual Gaps",
            int(coverage_summary_df["Residual Gap / Process Need"].astype(bool).sum()),
        )

        st.divider()

        st.markdown("## Risk-to-defense flow")

        view_mode = st.radio(
            "Coverage scope",
            ["Only risks present in current filters", "All matrix categories"],
            horizontal=True,
        )

        base_coverage_df = (
            incident_coverage_with_counts
            if view_mode == "Only risks present in current filters"
            else coverage_with_counts
        )

        if base_coverage_df.empty:
            st.info("No Defense Coverage Matrix rows match the current filters.")
        else:
            base_coverage_df = base_coverage_df.sort_values(
                ["Incident Count", "Blueprint Tier", "Misconfiguration Category"],
                ascending=[False, True, True],
            )

            selected_category = st.selectbox(
                "Select a misconfiguration category",
                base_coverage_df["Misconfiguration Category"].tolist(),
            )

            selected_row = base_coverage_df[
                base_coverage_df["Misconfiguration Category"] == selected_category
            ].iloc[0]

            st.graphviz_chart(
                defense_flow_diagram(
                    selected_row["Misconfiguration Category"],
                    selected_row["Primary Control Family"],
                    selected_row["Blueprint Tier"],
                ),
                use_container_width=True,
            )

            st.markdown("## Defense action card")

            action_col1, action_col2 = st.columns([1, 1])

            with action_col1:
                st.container(border=True).markdown(
                    f"### Selected risk pattern\n"
                    f"**{selected_row['Misconfiguration Category']}**\n\n"
                    f"**Observed in filtered dataset:** "
                    f"{selected_row['Incident Count']} incident(s) "
                    f"({selected_row['Incident Percent']}%)\n\n"
                    f"**Primary control family:**  \n"
                    f"{selected_row['Primary Control Family']}\n\n"
                    f"**Blueprint tier:**  \n"
                    f"{selected_row['Blueprint Tier']}"
                )

            with action_col2:
                st.container(border=True).markdown(
                    f"### What this control is trying to do\n"
                    f"{selected_row['Coverage Purpose']}"
                )

            baseline_col, gap_col = st.columns(2)

            with baseline_col:
                st.markdown("### Recommended hardened baseline")
                st.success(selected_row["Recommended Hardened Baseline"])

            with gap_col:
                st.markdown("### Residual gap / process need")
                st.warning(selected_row["Residual Gap / Process Need"])

            with st.expander("Show default posture question"):
                st.write(selected_row["Default Posture Question"])

            st.divider()

            st.markdown("## Matrix coverage overview")

            chart_col1, chart_col2 = st.columns(2)

            with chart_col1:
                tier_counts = (
                    base_coverage_df["Blueprint Tier"]
                    .value_counts()
                    .reset_index()
                )
                tier_counts.columns = ["Blueprint Tier", "Count"]

                st.plotly_chart(
                    horizontal_bar(
                        tier_counts,
                        "Blueprint Tier",
                        "Count",
                        "Controls by Blueprint Tier",
                    ),
                    width="stretch",
                )

            with chart_col2:
                incident_rank = base_coverage_df[
                    base_coverage_df["Incident Count"] > 0
                ][
                    ["Misconfiguration Category", "Incident Count"]
                ].sort_values("Incident Count", ascending=False)

                if not incident_rank.empty:
                    st.plotly_chart(
                        horizontal_bar(
                            incident_rank.head(10),
                            "Misconfiguration Category",
                            "Incident Count",
                            "Risk Patterns Seen in Current Dataset",
                        ),
                        width="stretch",
                    )
                else:
                    st.info("No incident-linked matrix categories for the current filters.")

            if missing_matrix_rows:
                st.warning(
                    "Some filtered incident misconfiguration categories are not represented in the Defense Coverage Matrix: "
                    + ", ".join(missing_matrix_rows)
                )

            st.divider()

            with st.expander("Show full Defense Coverage Matrix"):
                st.dataframe(
                    base_coverage_df[
                        [
                            "Misconfiguration Category",
                            "Incident Count",
                            "Incident Percent",
                            "Primary Control Family",
                            "Coverage Purpose",
                            "Default Posture Question",
                            "Recommended Hardened Baseline",
                            "Residual Gap / Process Need",
                            "Blueprint Tier",
                        ]
                    ],
                    width="stretch",
                    hide_index=True,
                    column_config={
                        "Default Posture Question": st.column_config.TextColumn(width="large"),
                        "Recommended Hardened Baseline": st.column_config.TextColumn(width="large"),
                        "Residual Gap / Process Need": st.column_config.TextColumn(width="large"),
                    },
                )

                st.download_button(
                    "Download current matrix view as CSV",
                    data=base_coverage_df.to_csv(index=False).encode("utf-8"),
                    file_name="defense_coverage_matrix_view.csv",
                    mime="text/csv",
                )

        if not platform_tracker_df.empty:
            with st.expander("Show optional platform evidence tracker"):
                platform_col1, platform_col2 = st.columns(2)

                with platform_col1:
                    platforms = sorted([x for x in platform_tracker_df["Platform"].unique() if x])
                    selected_platforms = st.multiselect("Platform", platforms, default=platforms)

                with platform_col2:
                    tracker_misconfigs = sorted(
                        [x for x in platform_tracker_df["Misconfiguration Category"].unique() if x]
                    )
                    default_tracker_misconfigs = [
                        x for x in tracker_misconfigs if x in filtered_misconfigs
                    ] or tracker_misconfigs
                    selected_tracker_misconfigs = st.multiselect(
                        "Misconfiguration category",
                        tracker_misconfigs,
                        default=default_tracker_misconfigs,
                    )

                tracker_view = platform_tracker_df.copy()

                if selected_platforms:
                    tracker_view = tracker_view[tracker_view["Platform"].isin(selected_platforms)]

                if selected_tracker_misconfigs:
                    tracker_view = tracker_view[
                        tracker_view["Misconfiguration Category"].isin(selected_tracker_misconfigs)
                    ]

                st.dataframe(
                    tracker_view,
                    width="stretch",
                    hide_index=True,
                    column_config={
                        "Evidence / Notes / URL": st.column_config.LinkColumn(
                            "Evidence / Notes / URL"
                        ),
                    },
                )

# -------------------------------------------------------------------
# Analyst Appendix
# -------------------------------------------------------------------

with tab_method:
    st.markdown("# Analyst Appendix")
    st.markdown(
        "Raw prevalence tables and coding views for analyst review. This section supports transparency but is intentionally separated from the board-facing view."
    )

    total_incidents = len(filtered_df)

    st.markdown("## Prevalence Tables")

    appendix_section = st.selectbox(
        "Select table",
        [
            "Attack Types",
            "Entry Vectors",
            "Primary Misconfigurations",
            "Any-Occurrence Misconfigurations",
            "Primary Control Gaps",
            "Any-Occurrence Control Gaps",
            "Confidence",
            "IdP Context",
        ],
    )

    if appendix_section == "Attack Types":
        table_df = count_series(filtered_df["Attack_Type"], total_incidents)
        chart_col = "Category"
    elif appendix_section == "Entry Vectors":
        table_df = count_series(filtered_df["Entry_Vector"], total_incidents)
        chart_col = "Category"
    elif appendix_section == "Primary Misconfigurations":
        table_df = count_series(filtered_df["Misconfig_1"], total_incidents)
        chart_col = "Category"
    elif appendix_section == "Any-Occurrence Misconfigurations":
        table_df = any_occurrence_count(
            filtered_df, "Misconfig_1", "Misconfig_2", "Misconfiguration"
        )
        chart_col = "Misconfiguration"
    elif appendix_section == "Primary Control Gaps":
        table_df = count_series(filtered_df["Controls_1"], total_incidents)
        chart_col = "Category"
    elif appendix_section == "Any-Occurrence Control Gaps":
        table_df = any_occurrence_count(
            filtered_df, "Controls_1", "Controls_2", "Control Gap"
        )
        chart_col = "Control Gap"
    elif appendix_section == "Confidence":
        table_df = count_series(filtered_df["Confidence"], total_incidents)
        chart_col = "Category"
    else:
        table_df = count_series(filtered_df["IdP_Context"], total_incidents)
        chart_col = "Category"

    st.dataframe(table_df, width="stretch", hide_index=True)

    if not table_df.empty:
        st.plotly_chart(
            horizontal_bar(table_df, chart_col, "Count", appendix_section),
            width="stretch",
        )

    st.download_button(
        "Download filtered incidents as CSV",
        data=filtered_df.to_csv(index=False).encode("utf-8"),
        file_name="filtered_incidents.csv",
        mime="text/csv",
    )

# -------------------------------------------------------------------
# Scenario Walkthrough
# -------------------------------------------------------------------

with tab_scenario:
    st.subheader("Scenario Walkthrough")

    incident_ids = filtered_df["Incident_ID"].dropna().astype(str).sort_values().tolist()

    if not incident_ids:
        st.info("No incidents match the current filters.")
    else:
        selected_incident = st.selectbox("Select an incident", incident_ids)

        row = filtered_df[filtered_df["Incident_ID"].astype(str) == selected_incident].iloc[0]

        st.markdown(f"### {row['Incident_ID']}")

        st.markdown("## Scenario Path")

        path_col1, path_col2, path_col3, path_col4 = st.columns(4)

        with path_col1:
            st.container(border=True).markdown(
                f"### 1. Entry\n**{row['Entry_Vector'] or 'N/A'}**"
            )

        with path_col2:
            st.container(border=True).markdown(
                f"### 2. OAuth Abuse\n**{row['Attack_Type'] or 'N/A'}**"
            )

        with path_col3:
            st.container(border=True).markdown(
                f"### 3. Misconfiguration\n**{row['Misconfig_1'] or 'N/A'}**"
            )

        with path_col4:
            st.container(border=True).markdown(
                f"### 4. Control Gap\n**{row['Controls_1'] or 'N/A'}**"
            )

        st.divider()

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### Technical Context")
            st.write(f"**OAuth Flow:** {row['OAuth_Flow'] or 'N/A'}")
            st.write(f"**Token Artifacts:** {row['Token_Artifacts'] or 'N/A'}")
            st.write(f"**Impact:** {row['Impact_Primary'] or 'N/A'}")

        with col2:
            st.markdown("### Coding Context")
            st.write(f"**Secondary Misconfiguration:** {row['Misconfig_2'] or 'N/A'}")
            st.write(f"**Secondary Control Gap:** {row['Controls_2'] or 'N/A'}")
            st.write(f"**Confidence:** {row['Confidence'] or 'N/A'}")

        if not coverage_summary_df.empty:
            st.markdown("#### Defense Coverage Matrix Alignment")
            incident_misconfigs = [row["Misconfig_1"], row["Misconfig_2"]]
            scenario_coverage = coverage_for_misconfigs(coverage_summary_df, incident_misconfigs)

            if not scenario_coverage.empty:
                st.dataframe(
                    scenario_coverage[
                        [
                            "Misconfiguration Category",
                            "Primary Control Family",
                            "Coverage Purpose",
                            "Recommended Hardened Baseline",
                            "Residual Gap / Process Need",
                            "Blueprint Tier",
                        ]
                    ],
                    width="stretch",
                    hide_index=True,
                )
            else:
                st.info("No Defense Coverage Matrix rows match this incident's coded misconfigurations.")

        st.markdown("#### SOC Runbook Alignment")

        st.markdown(
            """
1. **Detect:** Review suspicious OAuth grants, app activity, token usage, and API behavior.
2. **Triage:** Confirm affected user, app, scopes, SaaS context, and token artifacts.
3. **Contain/Revoke:** Disable malicious or compromised app access, revoke sessions/tokens, and rotate exposed credentials.
4. **Recover:** Re-establish least privilege, review related app grants, and restore trusted access paths.
5. **Lessons Learned:** Map the incident back to the misconfiguration and control gap categories.
"""
        )

        if row["Source_URL"]:
            st.link_button("Open Source Report", row["Source_URL"])
