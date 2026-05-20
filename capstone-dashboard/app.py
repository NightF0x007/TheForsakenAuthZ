from pathlib import Path
import hashlib
import re

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

URL_PATTERN = re.compile(r"https?://[^\s,;|]+")


def extract_urls(value: object) -> list[str]:
    """Extract one or more URLs from a CSV/Excel cell."""
    if value is None or pd.isna(value):
        return []

    text = str(value).strip()
    if not text:
        return []

    urls = []
    for match in URL_PATTERN.findall(text):
        cleaned = match.strip().rstrip(".,;)\"]}")
        if cleaned and cleaned not in urls:
            urls.append(cleaned)
    return urls


def source_count_label(value: object) -> str:
    """Return a compact table-friendly source count."""
    count = len(extract_urls(value))
    if count == 0:
        return "No source"
    if count == 1:
        return "1 source"
    return f"{count} sources"


def add_source_count_column(data: pd.DataFrame) -> pd.DataFrame:
    """Replace raw Source_URL display with a readable source count."""
    output = data.copy()
    if "Source_URL" in output.columns:
        output["Sources"] = output["Source_URL"].apply(source_count_label)
        output = output.drop(columns=["Source_URL"])
    return output


def render_source_links(source_value: object, empty_message: str = "No source URL available.") -> None:
    """Render each source URL as its own link button."""
    urls = extract_urls(source_value)

    if not urls:
        st.info(empty_message)
        return

    if len(urls) == 1:
        st.link_button("Open source report", urls[0])
        return

    st.markdown("**Source reports**")
    source_cols = st.columns(min(len(urls), 3))
    for idx, url in enumerate(urls, start=1):
        with source_cols[(idx - 1) % len(source_cols)]:
            st.link_button(f"Open source {idx}", url)


def render_source_selector(
    data: pd.DataFrame,
    key_prefix: str,
    label: str = "Open source report(s) for incident",
) -> None:
    """Let the viewer select an incident and open one or more source URLs."""
    if data.empty or "Incident_ID" not in data.columns or "Source_URL" not in data.columns:
        return

    options = data["Incident_ID"].dropna().astype(str).sort_values().tolist()
    if not options:
        return

    with st.expander("Open source report(s)", expanded=False):
        selected_incident = st.selectbox(label, options, key=f"{key_prefix}_source_select")
        source_value = data.loc[
            data["Incident_ID"].astype(str) == selected_incident,
            "Source_URL",
        ].iloc[0]
        render_source_links(source_value)

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

def blueprint_tier_guide():
    """Explain Blueprint Tier values in plain language."""
    tier_col1, tier_col2, tier_col3 = st.columns(3)

    with tier_col1:
        st.container(border=True).markdown(
            "### Start Here\n"
            "Baseline controls that reduce the most common or highest-impact OAuth abuse paths "
            "with the lowest implementation complexity. These are the first controls a small or "
            "resource-constrained organization should prioritize."
        )

    with tier_col2:
        st.container(border=True).markdown(
            "### Next\n"
            "Follow-on controls that improve governance, detection, review, and response after "
            "the baseline is in place. These often require more coordination across identity, "
            "SaaS administration, and SOC workflows."
        )

    with tier_col3:
        st.container(border=True).markdown(
            "### Advanced\n"
            "Higher-maturity controls that require deeper engineering, tuning, automation, or "
            "ongoing operational ownership. These are valuable, but they are not the first "
            "dependency for most organizations."
        )

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

SCHEMA_DICTIONARY = {
    "Attack Types": [
        {
            "Value": "Malicious OAuth app / delegated consent abuse",
            "Definition": "Victim grants delegated permissions to an attacker-controlled OAuth app.",
            "Use when": "Consent is the key enabling step and the app is newly malicious or attacker-controlled.",
        },
        {
            "Value": "Compromised legitimate OAuth app (trusted integration abuse)",
            "Definition": "A legitimate, already-trusted integration is abused through stolen tokens, secrets, or vendor compromise.",
            "Use when": "The abused identity is an existing trusted app or integration rather than a newly malicious app.",
        },
        {
            "Value": "Bearer token replay (stolen access/refresh token)",
            "Definition": "Attacker reuses a stolen bearer artifact to access APIs or resources.",
            "Use when": "Replay of a stolen user/session-level access token or refresh token is the core mechanism.",
        },
        {
            "Value": "Device code phishing (device authorization grant abuse)",
            "Definition": "Victim completes a device-code flow using an attacker-provided code.",
            "Use when": "The device authorization flow yields tokens to the attacker.",
        },
        {
            "Value": "Authorization code interception attack (redirect/code interception)",
            "Definition": "Authorization code or authorization response is captured before token issuance.",
            "Use when": "The primary mechanism is redirect/code interception, open redirect chaining, or missing PKCE-style hardening.",
        },
        {
            "Value": "Client credentials compromise (client secret/certificate)",
            "Definition": "A workload or application credential is compromised and used for unattended API access.",
            "Use when": "Client secret, certificate, or equivalent app credential compromise is the OAuth abuse mechanism.",
        },
        {
            "Value": "Workload identity abuse (domain-wide delegation/service principal)",
            "Definition": "High-privilege workload identity mechanisms are abused to access APIs at scale.",
            "Use when": "Privileged delegation, app-only access, or service principal access is the core abuse mechanism.",
        },
        {
            "Value": "Cross-app OAuth attack (COAT/CORF) via integration platform",
            "Definition": "An integration-platform design flaw enables cross-app pivoting or authorization confusion.",
            "Use when": "An integration platform mediates the abuse across connected apps.",
        },
        {
            "Value": "Token forgery / signing-key abuse (forged JWT/bearer token)",
            "Definition": "Attacker forges or signs tokens because signing material, issuer trust, or validation assumptions are compromised.",
            "Use when": "The source describes forged JWTs, signing-key compromise, or issuer/validation trust failure as the token mechanism.",
        },
        {
            "Value": "Other / Unknown",
            "Definition": "The OAuth mechanism cannot be confidently mapped to a defined category.",
            "Use when": "The report still meets inclusion criteria but the exact OAuth mechanism is unclear. Use sparingly.",
        },
    ],
    "Entry Vectors": [
        {
            "Value": "User interaction (phishing/social engineering)",
            "Definition": "Victim user performs an action to complete authentication or authorization.",
            "Use when": "A non-admin user clicks, signs in, approves, follows device-code instructions, or otherwise interacts with attacker-controlled content.",
        },
        {
            "Value": "Admin interaction (consent/social engineering)",
            "Definition": "An administrator or high-privilege role performs the enabling action.",
            "Use when": "Admin consent, admin-completed authentication, or admin approval is central to the chain.",
        },
        {
            "Value": "Compromised account",
            "Definition": "Attacker gains control of a user or admin account and uses it to grant consent, modify apps, or access SaaS data.",
            "Use when": "The earliest enabling step is account compromise rather than OAuth consent itself.",
        },
        {
            "Value": "Token stolen (endpoint/logs/session artifacts)",
            "Definition": "Attacker obtains tokens or session artifacts without a fresh authorization action.",
            "Use when": "Tokens are stolen from browser storage, logs, proxies, malware, endpoint compromise, or session artifacts.",
        },
        {
            "Value": "Leaked client secret / credential",
            "Definition": "Attacker obtains a workload or app credential.",
            "Use when": "The initial access material is a client secret, certificate, API key, service principal credential, or similar app credential.",
        },
        {
            "Value": "Third-party integration compromise",
            "Definition": "Access originates from compromise of a legitimate vendor or integration with existing tenant access.",
            "Use when": "The attack begins through supply-chain or integration compromise rather than the victim tenant directly.",
        },
        {
            "Value": "Provider / IdP-side key or credential compromise",
            "Definition": "A provider-side identity key, signing credential, or equivalent trust anchor is compromised.",
            "Use when": "The source identifies IdP/provider-side key material or signing infrastructure as the initial enabling material.",
        },
        {
            "Value": "Other / Unknown",
            "Definition": "The initial access path is not specific enough to classify.",
            "Use when": "The report supports inclusion overall but does not explain the earliest access or authorization acquisition step.",
        },
    ],
    "Misconfigurations": [
        {
            "Value": "User consent policy too permissive",
            "Definition": "Delegated user consent is allowed too broadly, enabling risky app access with limited friction.",
            "Use when": "User consent for sensitive scopes or low-friction app approval is the enabling weakness.",
        },
        {
            "Value": "Admin consent governance weak",
            "Definition": "Admin consent can be granted too easily or without adequate review.",
            "Use when": "Admin approval is the pivotal enabling step and governance around that approval is weak.",
        },
        {
            "Value": "App trust restrictions weak",
            "Definition": "Trust gates such as publisher verification, allowlisting, or tenant restrictions are not enforced.",
            "Use when": "An untrusted or weakly verified app could operate because trust controls were missing or insufficient.",
        },
        {
            "Value": "Over-privileged scopes/roles",
            "Definition": "OAuth scopes, app-only permissions, impersonation rights, or cloud roles exceed business need.",
            "Use when": "Excessive permissions materially increase privilege, reach, persistence, or blast radius.",
        },
        {
            "Value": "Token lifecycle controls weak",
            "Definition": "Token lifetime, reuse, rotation, or revocation behavior materially extends attacker access.",
            "Use when": "Refresh-token persistence or revocation limitations are central to the attack chain.",
        },
        {
            "Value": "Credential / key material hygiene weak",
            "Definition": "Client secrets, certificates, signing material, or app credentials are poorly protected, managed, or rotated.",
            "Use when": "Secret, certificate, or key handling is the enabling condition.",
        },
        {
            "Value": "OAuth flow / client hardening gaps",
            "Definition": "Risky flows or weak client constraints enable token acquisition or misuse.",
            "Use when": "Device code abuse, missing PKCE, weak redirect URI constraints, or legacy flow enablement dominate.",
        },
        {
            "Value": "Workload identity / domain-wide delegation risky",
            "Definition": "High-privilege workload identity patterns are enabled without sufficient guardrails.",
            "Use when": "Tenant-wide app access, app-only access, or delegated workload patterns are the core enabler.",
        },
        {
            "Value": "Third-party integration governance weak",
            "Definition": "Trusted integrations are not sufficiently inventoried, constrained, owned, or re-certified.",
            "Use when": "A legitimate integration’s posture, permissions, or governance is the real gap.",
        },
        {
            "Value": "Monitoring / audit visibility insufficient",
            "Definition": "Logging, retention, or visibility is inadequate to surface suspicious OAuth/app activity or downstream API abuse.",
            "Use when": "The source identifies a real visibility failure, missing logging, missing retention, or central monitoring gap.",
        },
        {
            "Value": "Token validation / issuer trust failure",
            "Definition": "Token validation, issuer binding, signing-key trust, or accepted issuer assumptions are insufficient.",
            "Use when": "Forged tokens, signing-key compromise, or issuer trust failure is the core weakness.",
        },
        {
            "Value": "OAuth app governance weak",
            "Definition": "Governance over who can create, register, credential, or materially modify OAuth applications is insufficient.",
            "Use when": "Attacker success depends on easy app creation, credential addition, or weak review of app-object changes.",
        },
        {
            "Value": "Other / Unknown",
            "Definition": "The enabling weakness cannot be confidently mapped to a defined category.",
            "Use when": "The source supports inclusion but does not provide enough detail for a defensible misconfiguration label.",
        },
    ],
    "Control Gaps": [
        {
            "Value": "User consent restrictions / risk-based approval",
            "Definition": "Controls that constrain delegated user consent through restrictions, approval workflows, or risk-based gating.",
            "Use when": "User consent was too easy or risky permissions should have required review.",
        },
        {
            "Value": "Admin consent approval workflow",
            "Definition": "Controls that impose review, verification, and approval gates for privileged consent.",
            "Use when": "Admin-granted permissions were central to the chain.",
        },
        {
            "Value": "Periodic OAuth app access review (inventory + recertification)",
            "Definition": "Routine inventorying and recertification of OAuth apps, integrations, owners, and permissions.",
            "Use when": "Trusted access persisted without periodic review or ownership accountability.",
        },
        {
            "Value": "App allowlisting / tenant restrictions",
            "Definition": "Only approved apps, tenants, or publishers are permitted.",
            "Use when": "Arbitrary apps, tenants, publishers, or integrations should not have been allowed.",
        },
        {
            "Value": "Trusted publisher enforcement (publisher verification)",
            "Definition": "Trust gating based on verified publisher identity or equivalent app reputation signals.",
            "Use when": "Unverified publishers or weak trust signals enabled risky app access.",
        },
        {
            "Value": "Restrict who can register OAuth apps",
            "Definition": "Tenant policy limits who can create, register, credential, or modify OAuth clients.",
            "Use when": "Low-privilege or inappropriate actors could register or modify apps.",
        },
        {
            "Value": "Least-privilege scope policy (limit high-risk scopes)",
            "Definition": "Policies and processes constrain permissions, scopes, and roles to business need.",
            "Use when": "Impact depends on excessive delegated permissions, app-only rights, impersonation, or broad cloud roles.",
        },
        {
            "Value": "Conditional Access / Policy-based access restrictions (session/device/location/flow)",
            "Definition": "Policy-based restrictions on sessions, devices, locations, and risky authentication or authorization flows.",
            "Use when": "Prevention depends on policy conditions or blocking risky flows.",
        },
        {
            "Value": "Token revocation + session termination playbook",
            "Definition": "Operational ability to rapidly revoke tokens, terminate sessions, and disable malicious app access.",
            "Use when": "Containment speed or practiced revocation workflows materially affect response.",
        },
        {
            "Value": "Refresh token lifetime / rotation policy",
            "Definition": "Controls that reduce the persistence value of refresh tokens through lifetime, rotation, or reuse controls.",
            "Use when": "Refresh-token longevity or replay value is central.",
        },
        {
            "Value": "Credential / key material management (storage + rotation)",
            "Definition": "Secure storage, restricted access, rotation cadence, and monitoring for client credentials and key material.",
            "Use when": "Client secret, certificate, API key, or signing material compromise is causal.",
        },
        {
            "Value": "OAuth client hardening (PKCE, redirect URI constraints, disable legacy flows)",
            "Definition": "Client-configuration hardening that prevents unsafe flows, response interception, or weak OAuth client behavior.",
            "Use when": "Flow/client hardening is the prevention story.",
        },
        {
            "Value": "Domain-wide delegation / workload identity governance",
            "Definition": "Guardrails on privileged workload identities, service principals, app-only access, and tenant-wide delegation.",
            "Use when": "The core problem is an overly powerful or weakly governed workload identity mechanism.",
        },
        {
            "Value": "Logging enabled + adequate retention",
            "Definition": "Relevant audit logging is enabled and retained long enough for detection and investigation.",
            "Use when": "Logging gaps harmed detection, investigation, or response.",
        },
        {
            "Value": "Alerting on consent/app changes",
            "Definition": "Alerts on app registration, consent grants, permission changes, or credential additions.",
            "Use when": "Material configuration changes occurred without timely alerts.",
        },
        {
            "Value": "Detection on anomalous OAuth/API behavior",
            "Definition": "Behavioral detection and hunting for suspicious OAuth usage and abnormal SaaS API activity.",
            "Use when": "Anomaly-based detection is the key missing layer after access is granted.",
        },
        {
            "Value": "Token validation / issuer-binding hardening",
            "Definition": "Controls that bind tokens to expected issuers, keys, audiences, tenants, and validation requirements.",
            "Use when": "Forged tokens, issuer confusion, or validation trust failure is the defensive gap.",
        },
        {
            "Value": "Other / Unknown",
            "Definition": "The defensive gap is implied but not specific enough to map.",
            "Use when": "The source supports a control gap but does not provide enough specificity for a defined category.",
        },
    ],
    "Primary Impacts": [
        {
            "Value": "Data exfiltration",
            "Definition": "Unauthorized access to or theft of business data, mail, files, repositories, records, or SaaS content.",
            "Use when": "The main outcome is access to or extraction of data.",
        },
        {
            "Value": "Email abuse (phishing/spam/BEC)",
            "Definition": "Abuse of mail access to send spam, phishing, business email compromise, or related messaging abuse.",
            "Use when": "The primary outcome is email or messaging abuse rather than data theft alone.",
        },
        {
            "Value": "Persistence / stealth access",
            "Definition": "Durable access that allows the attacker to remain present or re-enter without normal sign-in activity.",
            "Use when": "The main concern is continuing access through tokens, apps, integrations, or workload identities.",
        },
        {
            "Value": "Privilege escalation / admin takeover",
            "Definition": "The attacker gains administrative capability, expands privileges, or takes over privileged tenant/app control.",
            "Use when": "Privilege growth or administrative control is the primary operational impact.",
        },
        {
            "Value": "Resource hijacking",
            "Definition": "Cloud, SaaS, or compute resources are abused for attacker-controlled activity.",
            "Use when": "The primary outcome is unauthorized use of resources, such as compute, automation, or infrastructure abuse.",
        },
        {
            "Value": "Financial fraud",
            "Definition": "The attack directly enables payment fraud, financial theft, or fraudulent business transactions.",
            "Use when": "Financial loss or fraud is the primary business impact.",
        },
        {
            "Value": "Other / Unknown",
            "Definition": "The primary impact is unclear or does not fit the defined categories.",
            "Use when": "The source supports inclusion but does not specify a clear primary outcome.",
        },
    ],
}


def render_schema_dictionary() -> None:
    """Render selected controlled vocabulary definitions in the Appendix."""
    st.markdown("### Controlled Vocabulary Definitions")
    st.caption(
        "Use this reference to interpret the category labels used in charts, tables, and scenario walkthroughs."
    )

    selected_dictionary = st.selectbox(
        "Select definition set",
        list(SCHEMA_DICTIONARY.keys()),
        key="schema_dictionary_select",
    )

    dictionary_df = pd.DataFrame(SCHEMA_DICTIONARY[selected_dictionary])
    st.dataframe(
        dictionary_df,
        width="stretch",
        hide_index=True,
        column_config={
            "Value": st.column_config.TextColumn(width="medium"),
            "Definition": st.column_config.TextColumn(width="large"),
            "Use when": st.column_config.TextColumn(width="large"),
        },
    )


def schema_guide():
    """Show selected coding schema content for dashboard readers."""

    st.markdown("## Coding Schema Guide")
    st.markdown(
        "This section explains how to read the coded incident dataset without requiring the full schema document."
    )

    st.markdown("### Core coding rules")

    rule_col1, rule_col2, rule_col3 = st.columns(3)

    with rule_col1:
        st.container(border=True).markdown(
            "### Unit of analysis\n"
            "One row represents one OAuth-enabled attack chain in a public incident, campaign, or case study."
        )

    with rule_col2:
        st.container(border=True).markdown(
            "### Attack Type\n"
            "The OAuth abuse mechanism being analyzed, not necessarily the earliest step in the incident."
        )

    with rule_col3:
        st.container(border=True).markdown(
            "### Entry Vector\n"
            "How the attacker first obtained the access, authorization material, or position used to launch the OAuth abuse."
        )

    st.markdown("### Primary vs. secondary fields")

    primary_col, secondary_col = st.columns(2)

    with primary_col:
        st.info(
            "**_1 fields** identify the dominant explanation used for prevalence and ranking. "
            "Examples: Misconfig_1 and Controls_1."
        )

    with secondary_col:
        st.warning(
            "**_2 fields** identify a material co-enabler or co-gap. "
            "They should not be treated as optional detail or generic best-practice recommendations."
        )

    st.markdown("### How analysis views differ")

    view_df = pd.DataFrame(
        [
            {
                "View": "Primary-only",
                "Uses": "Prevalence, ranking, dominant-pattern summaries",
                "Rule": "Use Misconfig_1 and Controls_1 only",
            },
            {
                "View": "Any-occurrence",
                "Uses": "Sensitivity checks, matrix alignment, defense mapping",
                "Rule": "Treat a category as present if it appears in _1 OR _2",
            },
        ]
    )

    st.dataframe(view_df, width="stretch", hide_index=True)

    st.markdown("### Field Definitions")

    fields_df = pd.DataFrame(
        [
            {
                "Field": "Incident_ID",
                "Definition": "Unique identifier for the coded incident or campaign.",
            },
            {
                "Field": "Source_Date",
                "Definition": "Publication date of the source report.",
            },
            {
                "Field": "IdP_Context",
                "Definition": "Identity provider or identity environment involved.",
            },
            {
                "Field": "SaaS_Context",
                "Definition": "Target SaaS platform or application context.",
            },
            {
                "Field": "Attack_Type",
                "Definition": "OAuth-enabled abuse mechanism being analyzed.",
            },
            {
                "Field": "Entry_Vector",
                "Definition": "How the attacker first obtained access or authorization material.",
            },
            {
                "Field": "OAuth_Flow",
                "Definition": "OAuth grant type or flow if the source identifies it.",
            },
            {
                "Field": "Token_Artifacts",
                "Definition": "Access token, refresh token, client secret, certificate, or related artifact involved.",
            },
            {
                "Field": "Misconfig_1 / Misconfig_2",
                "Definition": "Dominant and material secondary enabling misconfiguration.",
            },
            {
                "Field": "Controls_1 / Controls_2",
                "Definition": "Dominant and material secondary missing or weak control.",
            },
            {
                "Field": "Impact_Primary",
                "Definition": "Main observed business or operational impact.",
            },
            {
                "Field": "Confidence",
                "Definition": "Strength of evidence for the coded row.",
            },
        ]
    )

    st.dataframe(fields_df, width="stretch", hide_index=True)

    render_schema_dictionary()

    st.markdown("### Confidence Guide")

    confidence_df = pd.DataFrame(
        [
            {
                "Confidence": "High",
                "Meaning": "Explicitly stated by the source.",
            },
            {
                "Confidence": "Medium",
                "Meaning": "Strongly implied by the source or incident timeline.",
            },
            {
                "Confidence": "Low",
                "Meaning": "Inferred or unclear; use sparingly and explain uncertainty when needed.",
            },
        ]
    )

    st.dataframe(confidence_df, width="stretch", hide_index=True)

def render_findings_explorer() -> None:
    """Render the supporting-evidence drilldown used inside Risk Patterns."""
    st.markdown("### Supporting Evidence Explorer")
    st.markdown(
        "Select a finding to see its frequency, supporting incidents, and Defense Coverage Matrix alignment."
    )

    with st.expander("How to interpret these finding types", expanded=False):
        st.markdown(
            """
            **Attack Type** = the OAuth abuse mechanism being analyzed, such as consent phishing, device code phishing, token replay, or trusted integration abuse.

            **Entry Vector** = how the attacker first obtained the access, authorization material, or position needed to launch the OAuth abuse.

            **Misconfiguration** = the tenant, app, token, or governance weakness that made the abuse possible.

            **Control Gap** = the missing or weak defensive control that would prevent, detect, or contain the abuse.

            **Impact** = the primary business or operational outcome observed in the incident.
            """
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
        supporting_display = add_source_count_column(supporting_view)

        st.dataframe(
            supporting_display,
            width="stretch",
            hide_index=True,
        )

        render_source_selector(
            supporting_view,
            key_prefix=f"supporting_{finding_type}",
        )


def render_incident_table() -> None:
    """Render the full filtered incident table used in the Appendix."""
    st.markdown("### Full Incident Table")

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
    incident_display = add_source_count_column(incident_table)

    st.dataframe(
        incident_display,
        width="stretch",
        hide_index=True,
    )

    render_source_selector(
        incident_table,
        key_prefix="appendix_incidents",
    )

filtered_df = apply_filters(df)

# -------------------------------------------------------------------
# App title
# -------------------------------------------------------------------

st.title("SaaS OAuth Abuse Analysis Dashboard")

st.markdown(
    """
#### This dashboard provides an interactive view of the 32 analyzed OAuth related reports.
"""
)

# -------------------------------------------------------------------
# Tabs
# -------------------------------------------------------------------

tab_problem, tab_board, tab_trends, tab_defense, tab_scenario, tab_appendix = st.tabs(
    [
        "The Problem",
        "Executive Summary",
        "Risk Patterns",
        "Defense Roadmap",
        "Scenario Walkthrough",
        "Appendix",
    ]
)

# -------------------------------------------------------------------
# The Problem
# -------------------------------------------------------------------

with tab_problem:
    st.markdown("# The Problem")

    st.info(
        "OAuth-based access is difficult to investigate because it often appears as trusted application activity, "
        "token use, or API access rather than a clearly malicious login. The core problem is not simply that attackers "
        "can act after login; it is that defenders may struggle to identify which app, token, permission, or integration "
        "created the access path and which control should reduce the risk."
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.container(border=True).markdown(
            "### 1. Activity looks trusted\n"
            "The event may appear as normal app access, token use, or API activity."
        )

    with col2:
        st.container(border=True).markdown(
            "### 2. Root cause is unclear\n"
            "Investigators must determine whether the issue is consent, app governance, token theft, workload identity, or integration compromise."
        )

    with col3:
        st.container(border=True).markdown(
            "### 3. Response is fragmented\n"
            "Containment may require revoking tokens, disabling apps, rotating credentials, reviewing grants, and updating controls."
        )

    st.markdown("## Why this matters")
    st.markdown(
        """
        Traditional investigation often starts with sign-in events, endpoint alerts, or malware indicators.
        OAuth abuse can be harder because the suspicious activity may occur through approved applications,
        delegated permissions, refresh tokens, service principals, or trusted integrations.

        This project helps security teams answer three practical questions:

        - **What happened?** Identify the OAuth abuse mechanism and entry vector.
        - **Why did it work?** Map the incident to a misconfiguration or control gap.
        - **What should we do next?** Use the Defense Roadmap and SOC runbook steps to guide hardening and response.
        """
    )

    st.markdown("## OAuth flow, simplified")
    st.image("capstone-dashboard/data/OAuth_Flow_UML.png")
    st.caption(
        "Simplified OAuth flow: the user authorizes an application, the application receives a token, and the token is used to access SaaS resources."
    )

# -------------------------------------------------------------------
# Executive Summary
# -------------------------------------------------------------------

with tab_board:
    st.markdown("# Executive Summary")
    st.markdown(
        "Summary of what the coded public reports suggest, why it matters, and where the dashboard goes next."
    )

    total_incidents = len(filtered_df)
    date_min = filtered_df["Source_Date"].min()
    date_max = filtered_df["Source_Date"].max()

    attack_counts = count_series(filtered_df["Attack_Type"], total_incidents)
    impact_counts = count_series(filtered_df["Impact_Primary"], total_incidents)
    misconfig_any = any_occurrence_count(
        filtered_df, "Misconfig_1", "Misconfig_2", "Misconfiguration"
    )
    controls_any = any_occurrence_count(
        filtered_df, "Controls_1", "Controls_2", "Control Gap"
    )

    top_attack_row = attack_counts.iloc[0] if not attack_counts.empty else None
    top_impact_row = impact_counts.iloc[0] if not impact_counts.empty else None
    top_misconfig_row = misconfig_any.iloc[0] if not misconfig_any.empty else None
    top_control_row = controls_any.iloc[0] if not controls_any.empty else None

    st.info(
        "**Bottom line:** OAuth abuse should be treated as an application-governance and token-control problem, "
        "not only as a login problem. The recurring pattern in the coded reports is that attackers exploit trusted "
        "apps, delegated permissions, tokens, or weak visibility after normal authentication has already occurred."
    )

    st.markdown("## What this summary answers")

    purpose_col1, purpose_col2, purpose_col3 = st.columns(3)

    with purpose_col1:
        st.container(border=True).markdown(
            "### 1. What showed up?\n"
            "The most common OAuth abuse patterns and observed impacts in the coded public reports."
        )

    with purpose_col2:
        st.container(border=True).markdown(
            "### 2. What enabled it?\n"
            "The recurring misconfigurations and control gaps that made abuse more viable or harder to detect."
        )

    with purpose_col3:
        st.container(border=True).markdown(
            "### 3. What should defenders do?\n"
            "Use the Defense Roadmap to turn the findings into prioritized hardening and response actions."
        )

    st.divider()

    kpi1, kpi2, kpi3, kpi4 = st.columns(4)

    kpi1.metric("Coded Reports", total_incidents)

    if top_attack_row is not None:
        kpi2.metric(
            "Top Abuse Pattern",
            short_label(top_attack_row["Category"]),
            f"{top_attack_row['Count']} cases / {top_attack_row['Percent']}%",
        )
    else:
        kpi2.metric("Top Abuse Pattern", "N/A")

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
        st.caption(
            f"Filtered source-publication range: {date_min.date()} to {date_max.date()}. "
            "Counts reflect the current sidebar filters."
        )

    st.warning(
        "Interpretation note: this dashboard summarizes public reporting, not confirmed global incident prevalence. "
        "The value is in identifying recurring patterns and practical defense priorities."
    )

    st.divider()

    st.markdown("## Key findings at a glance")

    finding_col1, finding_col2 = st.columns([1, 1])

    with finding_col1:
        if not attack_counts.empty:
            st.plotly_chart(
                donut_chart(
                    top_n_with_other(attack_counts, "Category", "Count", n=15),
                    "Category",
                    "Count",
                    "OAuth Abuse Pattern Share",
                ),
                width="stretch",
            )
        else:
            st.info("No attack type data available for the current filters.")

    with finding_col2:
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

    with st.expander("Impact Distribution", expanded=False):
        if top_impact_row is not None:
            st.markdown(
                f"**Most common primary impact:** {top_impact_row['Category']} "
                f"({top_impact_row['Count']} cases / {top_impact_row['Percent']}%)."
            )
        if not impact_counts.empty:
            st.plotly_chart(
                donut_chart(
                    top_n_with_other(impact_counts, "Category", "Count", n=15),
                    "Category",
                    "Count",
                    "Primary Impact Share",
                ),
                width="stretch",
            )
        else:
            st.info("No impact data available for the current filters.")

    st.divider()

    st.markdown("## Recommended next steps")

    action_col1, action_col2, action_col3 = st.columns(3)

    with action_col1:
        st.container(border=True).markdown(
            "### Next: Risk Patterns\n"
            "Use the **Risk Patterns** tab above to see how attack types, misconfigurations, "
            "and control gaps recur over time and across the coded reports."
        )

    with action_col2:
        st.container(border=True).markdown(
            "### Then: Defense Roadmap\n"
            "Use the **Defense Roadmap** tab above to map a selected misconfiguration to a "
            "control family, hardened baseline, residual gap, and implementation tier."
        )

    with action_col3:
        st.container(border=True).markdown(
            "### Demo: Scenario Walkthrough\n"
            "Use the **Scenario Walkthrough** tab above to follow one incident from entry vector "
            "to OAuth abuse, misconfiguration, control gap, and SOC response steps."
        )

# -------------------------------------------------------------------
# Risk Patterns
# -------------------------------------------------------------------

with tab_trends:
    st.markdown("# Risk Patterns")
    st.markdown(
        "This view connects the coded public reports to security implications. "
        "It does **not** measure global OAuth abuse prevalence. Instead, it shows which techniques, "
        "enablers, and control gaps recur often enough to guide defensive prioritization."
    )

    total_incidents = len(filtered_df)

    if total_incidents == 0:
        st.info("No incidents match the current filters.")
    else:
        attack_counts = count_series(filtered_df["Attack_Type"], total_incidents)
        entry_counts = count_series(filtered_df["Entry_Vector"], total_incidents)
        impact_counts = count_series(filtered_df["Impact_Primary"], total_incidents)

        st.markdown("## What this answers")

        answer_col1, answer_col2, answer_col3 = st.columns(3)

        with answer_col1:
            st.container(border=True).markdown(
                "### 1. Which techniques recur?\n"
                "Attack patterns show the OAuth abuse mechanisms that appear repeatedly across the coded reports."
            )

        with answer_col2:
            st.container(border=True).markdown(
                "### 2. What do they affect?\n"
                "Impact and context views show how those techniques connect to business outcomes and identity/SaaS environments."
            )

        with answer_col3:
            st.container(border=True).markdown(
                "### 3. What should defenders prioritize?\n"
                "Misconfiguration and control-gap trends point toward the Defense Roadmap and hardening priorities."
            )

        st.warning(
            "Interpretation note: these are trends in public reporting, not confirmed prevalence across all organizations. "
            "The value is in identifying recurring patterns and defense priorities, not estimating the true global incident rate."
        )

        st.divider()

        st.markdown("## Public Reporting Trend")
        st.caption(
            "This section shows when the coded reports were published and which OAuth abuse mechanisms recur across years. "
            "Use it to discuss pattern recurrence, not absolute incident volume."
        )

        trend_col1, trend_col2 = st.columns(2)

        with trend_col1:
            st.plotly_chart(
                year_count_chart(
                    filtered_df,
                    "Coded Reports by Year",
                ),
                width="stretch",
            )

        with trend_col2:
            st.plotly_chart(
                stacked_year_bar(
                    filtered_df,
                    "Attack_Type",
                    "Top OAuth Abuse Patterns Over Time",
                    top_n=5,
                ),
                width="stretch",
            )

        st.info(
            "Why this matters: recurring techniques across public reports suggest where defenders should focus monitoring, "
            "hardening, and tabletop planning. A spike or gap in reporting may reflect disclosure patterns as much as attacker activity."
        )

        st.divider()

        st.markdown("## Recurring OAuth Abuse Mechanisms")
        st.caption(
            "Attack Type describes the OAuth abuse mechanism. Entry Vector describes how the attacker first obtained the access, "
            "authorization material, or user/admin interaction needed to launch that mechanism."
        )

        mechanism_col1, mechanism_col2 = st.columns(2)

        with mechanism_col1:
            if not attack_counts.empty:
                st.plotly_chart(
                    horizontal_bar(
                        attack_counts.head(8),
                        "Category",
                        "Count",
                        "Top Attack Types",
                    ),
                    width="stretch",
                )
            else:
                st.info("No attack type data available for the current filters.")

        with mechanism_col2:
            if not entry_counts.empty:
                st.plotly_chart(
                    horizontal_bar(
                        entry_counts.head(8),
                        "Category",
                        "Count",
                        "Top Entry Vectors",
                    ),
                    width="stretch",
                )
            else:
                st.info("No entry vector data available for the current filters.")

        st.info(
            "Why this matters: separating the OAuth mechanism from the initial access path prevents the dashboard from treating all phishing, "
            "token theft, or account compromise as the same security problem. The defensive response depends on both fields."
        )

        st.divider()

        st.markdown("## Security Impact")
        st.caption(
            "These cross-tabs help connect OAuth abuse mechanisms to observed impact and identity-provider context. "
            "Sparse cells are expected because this is a small curated public-reporting dataset."
        )

        with st.expander("Impact and Context cross-tabs", expanded=True):
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

        if not impact_counts.empty:
            top_impact = impact_counts.iloc[0]
            st.info(
                f"Why this matters: the most common primary impact in the current filtered view is "
                f"**{top_impact['Category']}** ({top_impact['Count']} cases / {top_impact['Percent']}%). "
                "Impact context helps translate technical OAuth abuse into business and operational risk."
            )

        st.divider()

        st.markdown("## Recurring Enablers and Defense Gaps")
        st.caption(
            "This section uses any-occurrence logic: a category counts if it appears in either the primary field or the material secondary field. "
            "That is appropriate for defense mapping because secondary co-enablers can still materially affect privilege, persistence, scale, or blast radius."
        )

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

        st.info(
            "Why this matters: misconfiguration trends show the conditions that made abuse viable or more damaging. "
            "Control-gap trends show where prevention, detection, or response capabilities were missing or weak. "
            "Together, they explain why the Defense Roadmap focuses on governance, token controls, visibility, and response readiness."
        )

        st.divider()

        st.markdown("## What this suggests for defenders")

        insight_col1, insight_col2, insight_col3 = st.columns(3)

        with insight_col1:
            st.container(border=True).markdown(
                "### Govern apps and consent\n"
                "Repeated OAuth abuse patterns point to stronger consent review, app inventory, publisher/trust checks, and app approval workflows."
            )

        with insight_col2:
            st.container(border=True).markdown(
                "### Treat tokens as access paths\n"
                "OAuth tokens, refresh tokens, client credentials, and workload identities should be treated as durable access artifacts, not login byproducts."
            )

        with insight_col3:
            st.container(border=True).markdown(
                "### Monitor OAuth and API behavior\n"
                "Detection should look beyond sign-in events and include suspicious grants, app changes, credential additions, and abnormal SaaS API usage."
            )

        st.divider()

        with st.expander("Validate a pattern with supporting incidents", expanded=False):
            st.markdown(
                "Use this drilldown to select a finding, see the supporting coded incidents, and connect the pattern back to source reporting."
            )
            render_findings_explorer()

# -------------------------------------------------------------------
# Defense Roadmap
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

        st.markdown("## Blueprint tier guide")
        blueprint_tier_guide()

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
                width='stretch',
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
                st.markdown("### Recommended Hardened Baseline")
                st.success(selected_row["Recommended Hardened Baseline"])

            with gap_col:
                st.markdown("### Residual Gap / Process Need")
                st.warning(selected_row["Residual Gap / Process Need"])

            with st.expander("Default Posture Question"):
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

            with st.expander("Full Defense Coverage Matrix"):
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
            with st.expander("Platform Evidence Tracker"):
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
                        "Evidence / Notes / URL": st.column_config.TextColumn(
                            "Evidence / Notes / URL",
                            width="large",
                        ),
                    },
                )

                if not tracker_view.empty:
                    tracker_view = tracker_view.reset_index(drop=True)
                    tracker_options = [
                        f"{idx + 1}. {row['Platform']} — {row['Misconfiguration Category']}"
                        for idx, row in tracker_view.iterrows()
                    ]
                    selected_tracker = st.selectbox(
                        "View full platform evidence / notes",
                        tracker_options,
                        key="platform_evidence_detail",
                    )
                    selected_idx = tracker_options.index(selected_tracker)
                    evidence_row = tracker_view.iloc[selected_idx]

                    st.markdown("#### Platform evidence detail")
                    st.markdown(f"**Platform:** {evidence_row['Platform']}")
                    st.markdown(f"**Misconfiguration:** {evidence_row['Misconfiguration Category']}")
                    st.markdown(f"**Native control exists?:** {evidence_row['Native Control Exists?']}")
                    st.markdown(f"**Default coverage:** {evidence_row['Default Coverage']}")
                    st.markdown(f"**Hardened coverage:** {evidence_row['Hardened Coverage']}")
                    evidence_text = str(evidence_row["Evidence / Notes / URL"])
                    evidence_key = hashlib.md5(
                        f"{selected_tracker}|{evidence_text}".encode("utf-8")
                    ).hexdigest()[:12]

                    st.text_area(
                        "Full evidence / notes / URL",
                        value=evidence_text,
                        height=160,
                        disabled=True,
                        key=f"platform_evidence_text_{evidence_key}",
                    )
                    render_source_links(
                        evidence_text,
                        empty_message="No URL detected in the evidence field.",
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

        with st.expander("Why these steps are separated", expanded=False):
            st.markdown(
                """
                The dashboard separates the initial access path from the OAuth abuse mechanism.

                - **Entry** shows how the attacker first obtained access, authorization material, or user/admin interaction.
                - **OAuth Abuse** shows the OAuth-specific mechanism being analyzed.
                - **Misconfiguration** shows the enabling weakness.
                - **Control Gap** shows the missing or weak defense.
                """
            )

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

        render_source_links(row.get("Source_URL", ""))

# -------------------------------------------------------------------
# Appendix
# -------------------------------------------------------------------

with tab_appendix:
    st.markdown("# Appendix")
    st.markdown(
        "Raw prevalence tables and coding views for review."
    )

    with st.expander("Coding Schema Guide", expanded=True):
        schema_guide()

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

    with st.expander("Full Incident Table", expanded=False):
        render_incident_table()

    st.download_button(
        "Download filtered incidents as CSV",
        data=filtered_df.to_csv(index=False).encode("utf-8"),
        file_name="filtered_incidents.csv",
        mime="text/csv",
    )
