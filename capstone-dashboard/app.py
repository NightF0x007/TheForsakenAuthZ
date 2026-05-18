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

filtered_df = apply_filters(df)


# -------------------------------------------------------------------
# App title
# -------------------------------------------------------------------

st.title("SaaS OAuth Post-SSO Abuse Analysis Dashboard")

st.markdown(
    """
This dashboard provides an interactive view of the coded incident dataset, prevalence analysis,
misconfiguration taxonomy, control-gap mapping, and Defense Coverage Matrix for the capstone project.
"""
)


# -------------------------------------------------------------------
# Tabs
# -------------------------------------------------------------------

tab_board, tab_defense, tab_findings, tab_scenario, tab_incidents, tab_method = st.tabs(
    [
        "Board Briefing",
        "Defense Coverage Matrix",
        "Findings Explorer",
        "Scenario Walkthrough",
        "Incident Explorer",
        "Analyst Appendix",
    ]
)


# -------------------------------------------------------------------
# Board Briefing
# -------------------------------------------------------------------

with tab_board:
    st.markdown("# Board Briefing")
    st.markdown(
        "Decision-focused summary of SaaS OAuth post-SSO abuse patterns, mapped to practical defense priorities."
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
    st.subheader("Defense Coverage Matrix")

    st.markdown(
        """
This tab connects the coded misconfiguration taxonomy to vendor-neutral defense coverage.
Use it as the dashboard version of the capstone Defense Coverage Matrix: what control family applies,
what it is supposed to cover, what the hardened baseline should be, and what residual gap remains.
"""
    )

    if coverage_summary_df.empty:
        st.warning(
            "Defense Coverage Matrix workbook not found or not readable. "
            "Place it at `data/Defense_Coverage_Matrix.xlsx`."
        )
        st.code(
            "project-root/\n"
            "├── app.py\n"
            "└── data/\n"
            "    ├── Sanitized_Export.csv\n"
            "    └── Defense_Coverage_Matrix.xlsx",
            language="text",
        )
    else:
        filtered_misconfigs = get_any_occurrence_values(filtered_df, "Misconfig_1", "Misconfig_2")
        incident_coverage_df = coverage_for_misconfigs(coverage_summary_df, filtered_misconfigs)
        missing_matrix_rows = sorted(
            filtered_misconfigs - set(coverage_summary_df["Misconfiguration Category"])
        )

        metric1, metric2, metric3, metric4 = st.columns(4)
        metric1.metric("Matrix Categories", len(coverage_summary_df))
        metric2.metric("Categories in Current Filters", len(incident_coverage_df))
        metric3.metric(
            "Start Here Controls",
            int((coverage_summary_df["Blueprint Tier"].str.strip() == "Start Here").sum()),
        )
        metric4.metric(
            "Residual Gaps Documented",
            int(coverage_summary_df["Residual Gap / Process Need"].astype(bool).sum()),
        )

        view_mode = st.radio(
            "Coverage view",
            ["Only categories present in current filters", "All matrix categories"],
            horizontal=True,
        )

        base_coverage_df = (
            incident_coverage_df
            if view_mode == "Only categories present in current filters"
            else coverage_summary_df.copy()
        )

        filter_col1, filter_col2 = st.columns(2)
        with filter_col1:
            tiers = sorted([x for x in base_coverage_df["Blueprint Tier"].unique() if x])
            selected_tiers = st.multiselect("Blueprint tier", tiers, default=tiers)
        with filter_col2:
            purposes = sorted([x for x in base_coverage_df["Coverage Purpose"].unique() if x])
            selected_purposes = st.multiselect("Coverage purpose", purposes, default=purposes)

        filtered_coverage_view = base_coverage_df.copy()
        if selected_tiers:
            filtered_coverage_view = filtered_coverage_view[
                filtered_coverage_view["Blueprint Tier"].isin(selected_tiers)
            ]
        if selected_purposes:
            filtered_coverage_view = filtered_coverage_view[
                filtered_coverage_view["Coverage Purpose"].isin(selected_purposes)
            ]

        st.markdown("## Priority Controls: Start Here")

        start_here_df = filtered_coverage_view[
            filtered_coverage_view["Blueprint Tier"].str.strip() == "Start Here"
        ].copy()

        if start_here_df.empty:
            st.info("No Start Here controls are present in the current coverage view.")
        else:
            for _, row in start_here_df.iterrows():
                with st.container(border=True):
                    st.markdown(f"### {row['Misconfiguration Category']}")
                    st.markdown(f"**Primary Control Family:** {row['Primary Control Family']}")
                    st.markdown(f"**Coverage Purpose:** {row['Coverage Purpose']}")

                    with st.expander("Default posture question"):
                        st.write(row["Default Posture Question"])

                    with st.expander("Recommended hardened baseline"):
                        st.write(row["Recommended Hardened Baseline"])

                    with st.expander("Residual gap / process need"):
                        st.write(row["Residual Gap / Process Need"])

        st.markdown("### Coverage Summary")
        st.dataframe(
            filtered_coverage_view,
            width="stretch",
            hide_index=True,
            column_config={
                "Default Posture Question": st.column_config.TextColumn(width="large"),
                "Recommended Hardened Baseline": st.column_config.TextColumn(width="large"),
                "Residual Gap / Process Need": st.column_config.TextColumn(width="large"),
            },
        )

        if not filtered_coverage_view.empty:
            st.markdown("### Blueprint Tier Distribution")
            tier_counts = filtered_coverage_view["Blueprint Tier"].value_counts().reset_index()
            tier_counts.columns = ["Blueprint Tier", "Count"]
            st.plotly_chart(
                horizontal_bar(
                    tier_counts,
                    "Blueprint Tier",
                    "Count",
                    "Blueprint Tier Distribution",
                ),
                width="stretch",
            )

            st.download_button(
                "Download current coverage view as CSV",
                data=filtered_coverage_view.to_csv(index=False).encode("utf-8"),
                file_name="filtered_defense_coverage_matrix.csv",
                mime="text/csv",
            )

        if missing_matrix_rows:
            st.warning(
                "The current filtered incidents include misconfiguration categories that are not in the Defense Coverage Matrix: "
                + ", ".join(missing_matrix_rows)
            )

        if not platform_tracker_df.empty:
            st.markdown("### Optional Platform Evidence Tracker")
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

            st.dataframe(tracker_view, width="stretch", hide_index=True)

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
