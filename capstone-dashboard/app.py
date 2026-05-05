from pathlib import Path

import pandas as pd
import streamlit as st

# -------------------------------------------------------------------
# Page setup
# -------------------------------------------------------------------

st.set_page_config(
    page_title="SaaS OAuth Abuse Analysis Dashboard",
    page_icon="🔐",
    layout="wide",
)

DATA_PATH = Path("data/Sanitized_Export.csv")
COVERAGE_PATH = Path("data/Defense_Coverage_Matrix.xlsx")

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

    text_cols = df.select_dtypes(include="object").columns
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
        text_cols = frame.select_dtypes(include="object").columns
        frame[text_cols] = frame[text_cols].fillna("").apply(
            lambda col: col.map(lambda x: x.strip() if isinstance(x, str) else x)
        )

    return summary, tracker


df = load_data(DATA_PATH)
coverage_summary_df, platform_tracker_df = load_coverage_matrix(COVERAGE_PATH)


# -------------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------------

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

tab_overview, tab_prevalence, tab_incidents, tab_misconfigs, tab_defense, tab_scenario = st.tabs(
    [
        "Overview",
        "Prevalence Analysis",
        "Incident Explorer",
        "Misconfiguration + Controls",
        "Defense Coverage Matrix",
        "Scenario Walkthrough",
    ]
)


# -------------------------------------------------------------------
# Overview
# -------------------------------------------------------------------

with tab_overview:
    st.subheader("Executive Summary")

    total_incidents = len(filtered_df)
    date_min = filtered_df["Source_Date"].min()
    date_max = filtered_df["Source_Date"].max()

    top_attack = (
        filtered_df["Attack_Type"].value_counts().idxmax()
        if not filtered_df["Attack_Type"].dropna().empty
        else "N/A"
    )

    top_idp = (
        filtered_df["IdP_Context"].value_counts().idxmax()
        if not filtered_df["IdP_Context"].dropna().empty
        else "N/A"
    )

    top_impact = (
        filtered_df["Impact_Primary"].value_counts().idxmax()
        if not filtered_df["Impact_Primary"].dropna().empty
        else "N/A"
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Incidents", total_incidents)
    col2.metric("Top IdP Context", top_idp)
    col3.metric("Top Attack Type", top_attack)
    col4.metric("Top Impact", top_impact)

    if pd.notna(date_min) and pd.notna(date_max):
        st.caption(f"Filtered date range: {date_min.date()} to {date_max.date()}")

    st.markdown("### Dataset by Year")
    year_counts = count_series(filtered_df["Source_Year"].astype("Int64").astype(str), len(filtered_df))
    if not year_counts.empty:
        st.bar_chart(year_counts.set_index("Category")["Count"])
    else:
        st.info("No year data available for the current filters.")

    st.markdown("### Confidence Distribution")
    confidence_counts = count_series(filtered_df["Confidence"], len(filtered_df))
    if not confidence_counts.empty:
        st.bar_chart(confidence_counts.set_index("Category")["Count"])
    else:
        st.info("No confidence data available for the current filters.")


# -------------------------------------------------------------------
# Prevalence Analysis
# -------------------------------------------------------------------

with tab_prevalence:
    st.subheader("Prevalence Analysis")

    st.markdown("### Attack Types")
    attack_counts = count_series(filtered_df["Attack_Type"], len(filtered_df))
    st.dataframe(attack_counts, use_container_width=True, hide_index=True)
    if not attack_counts.empty:
        st.bar_chart(attack_counts.set_index("Category")["Count"])

    st.markdown("### Entry Vectors")
    entry_counts = count_series(filtered_df["Entry_Vector"], len(filtered_df))
    st.dataframe(entry_counts, use_container_width=True, hide_index=True)
    if not entry_counts.empty:
        st.bar_chart(entry_counts.set_index("Category")["Count"])

    st.markdown("### Primary Misconfigurations")
    misconfig_primary = count_series(filtered_df["Misconfig_1"], len(filtered_df))
    st.dataframe(misconfig_primary, use_container_width=True, hide_index=True)
    if not misconfig_primary.empty:
        st.bar_chart(misconfig_primary.set_index("Category")["Count"])

    st.markdown("### Any-Occurrence Misconfigurations")
    misconfig_any = any_occurrence_count(filtered_df, "Misconfig_1", "Misconfig_2", "Misconfiguration")
    st.dataframe(misconfig_any, use_container_width=True, hide_index=True)
    if not misconfig_any.empty:
        st.bar_chart(misconfig_any.set_index("Misconfiguration")["Count"])

    st.markdown("### Primary Control Gaps")
    controls_primary = count_series(filtered_df["Controls_1"], len(filtered_df))
    st.dataframe(controls_primary, use_container_width=True, hide_index=True)
    if not controls_primary.empty:
        st.bar_chart(controls_primary.set_index("Category")["Count"])

    st.markdown("### Any-Occurrence Control Gaps")
    controls_any = any_occurrence_count(filtered_df, "Controls_1", "Controls_2", "Control Gap")
    st.dataframe(controls_any, use_container_width=True, hide_index=True)
    if not controls_any.empty:
        st.bar_chart(controls_any.set_index("Control Gap")["Count"])


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
        use_container_width=True,
        hide_index=True,
    )


# -------------------------------------------------------------------
# Misconfiguration + Controls
# -------------------------------------------------------------------

with tab_misconfigs:
    st.subheader("Misconfiguration and Control Mapping")

    st.markdown(
        """
The primary-only view uses `Misconfig_1` and `Controls_1` for dominant-pattern analysis.
The any-occurrence view treats a category as present when it appears in either `_1` or `_2`.
"""
    )

    misconfig_any = any_occurrence_count(filtered_df, "Misconfig_1", "Misconfig_2", "Misconfiguration")
    controls_any = any_occurrence_count(filtered_df, "Controls_1", "Controls_2", "Control Gap")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Misconfigurations")
        st.dataframe(misconfig_any, use_container_width=True, hide_index=True)

    with col2:
        st.markdown("### Control Gaps")
        st.dataframe(controls_any, use_container_width=True, hide_index=True)

    st.markdown("### Misconfiguration to Control Pairings")

    pair_rows = []

    for _, row in filtered_df.iterrows():
        misconfigs = [row["Misconfig_1"], row["Misconfig_2"]]
        controls = [row["Controls_1"], row["Controls_2"]]

        for misconfig in misconfigs:
            for control in controls:
                if str(misconfig).strip() and str(control).strip():
                    pair_rows.append(
                        {
                            "Misconfiguration": misconfig,
                            "Control Gap": control,
                            "Incident_ID": row["Incident_ID"],
                        }
                    )

    if pair_rows:
        pair_df = pd.DataFrame(pair_rows)
        pair_counts = (
            pair_df.groupby(["Misconfiguration", "Control Gap"])
            .size()
            .reset_index(name="Count")
            .sort_values("Count", ascending=False)
        )
        st.dataframe(pair_counts, use_container_width=True, hide_index=True)
    else:
        st.info("No misconfiguration/control pairings found for the current filters.")


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
            int((coverage_summary_df["Blueprint Tier"] == "Start Here").sum()),
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

        st.markdown("### Coverage Summary")
        st.dataframe(
            filtered_coverage_view,
            use_container_width=True,
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
            st.bar_chart(tier_counts.set_index("Blueprint Tier")["Count"])

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

            st.dataframe(tracker_view, use_container_width=True, hide_index=True)


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

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### Attack Chain")
            st.write(f"**Entry Vector:** {row['Entry_Vector']}")
            st.write(f"**Attack Type:** {row['Attack_Type']}")
            st.write(f"**OAuth Flow:** {row['OAuth_Flow']}")
            st.write(f"**Token Artifacts:** {row['Token_Artifacts']}")
            st.write(f"**Impact:** {row['Impact_Primary']}")

        with col2:
            st.markdown("#### Control Analysis")
            st.write(f"**Primary Misconfiguration:** {row['Misconfig_1']}")
            st.write(f"**Secondary Misconfiguration:** {row['Misconfig_2'] or 'N/A'}")
            st.write(f"**Primary Control Gap:** {row['Controls_1']}")
            st.write(f"**Secondary Control Gap:** {row['Controls_2'] or 'N/A'}")
            st.write(f"**Confidence:** {row['Confidence']}")

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
                    use_container_width=True,
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
