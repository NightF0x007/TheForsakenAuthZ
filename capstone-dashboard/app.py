import pandas as pd
import streamlit as st
from pathlib import Path

# -------------------------------------------------------------------
# Page setup
# -------------------------------------------------------------------

st.set_page_config(
    page_title="SaaS OAuth Abuse Analysis Dashboard",
    page_icon="🔐",
    layout="wide",
)

DATA_PATH = Path("data/Sanitized_Export.csv")

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


# -------------------------------------------------------------------
# Data loading
# -------------------------------------------------------------------

@st.cache_data
def load_data(path: Path) -> pd.DataFrame:
    if not path.exists():
        st.error(f"Dataset not found: {path}")
        st.stop()

    df = pd.read_csv(path)
    df.column = [str(col).strip() for col in df.columns]

    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.write("Available columsn:", list(df.columns))
        st.stop()
    # Add additional columns as blanks when they are not present
    for col in OPTIONAL_COLUMNS:
        if col not in df.columns:
            df[col] = ""

    df["Source_Date"] = pd.to_datetime(df["Source_Date"], errors="coerce")
    df["Source_Year"] = df["Source_Date"].dt.year

    # Normalize blank fields
    text_cols = df.select_dtypes(include="object").columns
    df[text_cols] = df[text_cols].fillna("").map(lambda x: x.strip() if isinstance(x, str) else x)

    return df


df = load_data(DATA_PATH)


# -------------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------------

def count_series(series: pd.Series) -> pd.DataFrame:
    clean = series.dropna()
    clean = clean[clean.astype(str).str.strip() != ""]
    total = len(df)

    counts = clean.value_counts().reset_index()
    counts.columns = ["Category", "Count"]
    counts["Percent"] = (counts["Count"] / total * 100).round(1)
    return counts


def any_occurrence_count(col1: str, col2: str, label: str) -> pd.DataFrame:
    values = []

    for _, row in df.iterrows():
        seen = set()
        for col in [col1, col2]:
            value = str(row.get(col, "")).strip()
            if value and value not in seen:
                values.append(value)
                seen.add(value)

    result = pd.Series(values).value_counts().reset_index()
    result.columns = [label, "Count"]
    result["Percent"] = (result["Count"] / len(df) * 100).round(1)
    return result


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
misconfiguration taxonomy, and control-gap mapping for the capstone project.
"""
)


# -------------------------------------------------------------------
# Tabs
# -------------------------------------------------------------------

tab_overview, tab_prevalence, tab_incidents, tab_misconfigs, tab_scenario = st.tabs(
    [
        "Overview",
        "Prevalence Analysis",
        "Incident Explorer",
        "Misconfiguration + Controls",
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
    year_counts = count_series(filtered_df["Source_Year"].astype("Int64").astype(str))
    st.bar_chart(year_counts.set_index("Category")["Count"])

    st.markdown("### Confidence Distribution")
    confidence_counts = count_series(filtered_df["Confidence"])
    st.bar_chart(confidence_counts.set_index("Category")["Count"])


# -------------------------------------------------------------------
# Prevalence Analysis
# -------------------------------------------------------------------

with tab_prevalence:
    st.subheader("Prevalence Analysis")

    st.markdown("### Attack Types")
    attack_counts = count_series(filtered_df["Attack_Type"])
    st.dataframe(attack_counts, use_container_width=True, hide_index=True)
    st.bar_chart(attack_counts.set_index("Category")["Count"])

    st.markdown("### Entry Vectors")
    entry_counts = count_series(filtered_df["Entry_Vector"])
    st.dataframe(entry_counts, use_container_width=True, hide_index=True)
    st.bar_chart(entry_counts.set_index("Category")["Count"])

    st.markdown("### Primary Misconfigurations")
    misconfig_primary = count_series(filtered_df["Misconfig_1"])
    st.dataframe(misconfig_primary, use_container_width=True, hide_index=True)
    st.bar_chart(misconfig_primary.set_index("Category")["Count"])

    st.markdown("### Any-Occurrence Misconfigurations")
    misconfig_any = any_occurrence_count("Misconfig_1", "Misconfig_2", "Misconfiguration")
    st.dataframe(misconfig_any, use_container_width=True, hide_index=True)
    st.bar_chart(misconfig_any.set_index("Misconfiguration")["Count"])

    st.markdown("### Primary Control Gaps")
    controls_primary = count_series(filtered_df["Controls_1"])
    st.dataframe(controls_primary, use_container_width=True, hide_index=True)
    st.bar_chart(controls_primary.set_index("Category")["Count"])

    st.markdown("### Any-Occurrence Control Gaps")
    controls_any = any_occurrence_count("Controls_1", "Controls_2", "Control Gap")
    st.dataframe(controls_any, use_container_width=True, hide_index=True)
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

    misconfig_any = any_occurrence_count("Misconfig_1", "Misconfig_2", "Misconfiguration")
    controls_any = any_occurrence_count("Controls_1", "Controls_2", "Control Gap")

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
