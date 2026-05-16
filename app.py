import streamlit as st
from streamlit_autorefresh import st_autorefresh
from auth import USERS
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
if "authenticated" not in st.session_state:

    st.session_state.authenticated = False

if not st.session_state.authenticated:

    st.title("SOC Analyst Login")

    username = st.text_input(
        "Username"
    )

    password = st.text_input(
        "Password",
        type="password"
    )

    if st.button(
        "Login",
        key="login_button"
    ):

        if username in USERS:

            if USERS[username]["password"] == password:

                st.session_state.authenticated = True

                st.session_state.username = username

                st.session_state.role = USERS[username]["role"]

                st.success(
                    "Login successful!"
                )

                st.rerun()

            else:

                st.error(
                    "Invalid password"
                )

        else:

            st.error(
                "Invalid username"
            )

    st.stop()
col1, col2, col3 = st.columns([3, 2, 1])

with col1:

    st.markdown(
        f"### Logged in as: "
        f"{st.session_state.username}"
    )

with col2:

    st.markdown(
        f"### Role: "
        f"{st.session_state.role}"
    )

with col3:

    if st.button(
        "Logout",
        key="logout_button"
    ):

        st.session_state.clear()

        st.rerun()

        st.session_state.authenticated = False

        st.session_state.username = ""

        st.session_state.role = ""

        st.rerun()
location_coords = {
    "New York": {"lat": 40.7128, "lon": -74.0060},
    "California": {"lat": 36.7783, "lon": -119.4179},
    "Texas": {"lat": 31.9686, "lon": -99.9018},
    "Florida": {"lat": 27.6648, "lon": -81.5158},
    "London": {"lat": 51.5074, "lon": -0.1278},
    "Germany": {"lat": 51.1657, "lon": 10.4515},
    "China": {"lat": 35.8617, "lon": 104.1954},
    "Russia": {"lat": 61.5240, "lon": 105.3188}
}

from detections.impossible_travel import (
    detect_impossible_travel
)

from detections.after_hours_access import (
    load_logs,
    detect_after_hours_access
)

from ml.anomaly_detection import (
    detect_anomalies
)

from database import (
    initialize_database,
    save_case,
    load_cases
)
st.set_page_config(
    page_title="AI Insider Threat Detection Platform",
    layout="wide"
)
initialize_database()
# Auto refresh every 10 seconds
st_autorefresh(
    interval=10 * 1000,
    key="threatdashboardrefresh"
)
st.title("AI Insider Threat Detection Platform")
# Auto Refresh Every 30 Seconds
st_autorefresh(
    interval=30000,
    key="threat_dashboard_refresh"
)
st.subheader("Security Operations Dashboard")

# Load logs
logs = load_logs()

# Run detections
travel_alerts = detect_impossible_travel(logs)

after_hours_alerts = detect_after_hours_access(logs)

anomaly_alerts = detect_anomalies(logs)

alerts_df = pd.concat([
    pd.DataFrame(travel_alerts),
    pd.DataFrame(after_hours_alerts),
    pd.DataFrame(anomaly_alerts)
], ignore_index=True)

anomaly_results = pd.DataFrame(anomaly_alerts)

# Use combined alerts dataframe
df = alerts_df.fillna("")
# MITRE ATT&CK Mapping
mitre_mapping = {
    "Impossible Travel":
        "T1078 - Valid Accounts",

    "After Hours Access":
        "T1078 - Valid Accounts",

    "Data Exfiltration":
        "T1567 - Exfiltration Over Web Service",

    "Privilege Escalation":
        "T1548 - Abuse Elevation Control Mechanism",

    "USB Activity":
        "T1091 - Replication Through Removable Media",

    "ML Anomaly":
        "T1087 - Account Discovery"
}

df["mitre_technique"] = (
    df["alert_type"]
    .map(mitre_mapping)
)
df = df.fillna("")

# Convert timestamps
df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    errors="coerce"
)

# Metrics
col1, col2, col3 = st.columns(3)
# Metrics
col1, col2, col3 = st.columns(3)

col1.metric("Total Alerts", len(df))

high_alerts = len(
    df[df["severity"] == "HIGH"]
)

medium_alerts = len(
    df[df["severity"] == "MEDIUM"]
)

col2.metric("High Severity", high_alerts)

col3.metric("Medium Severity", medium_alerts)

st.divider()

# Severity Distribution Chart
st.subheader("Threat Severity Distribution")

severity_counts = (
    df["severity"]
    .value_counts()
    .reset_index()
)

severity_counts.columns = [
    "Severity",
    "Count"
]

fig = px.bar(
    severity_counts,
    x="Severity",
    y="Count",
    title="Alerts by Severity",
)

st.plotly_chart(
    fig,
    use_container_width=True
)

# Threat Geography Map
st.divider()

st.subheader("Impossible Travel Threat Map")

travel_df = df[
    df["alert_type"] == "Impossible Travel"
    
].copy()
st.write(travel_df)
...
# Threat Investigation Panel
st.divider()

st.subheader("Threat Investigation Panel")

selected_user = st.selectbox(
    "Select User to Investigate",
    df["user"].unique()
)
user_data = df[
    df["user"] == selected_user
]
st.text_area(
    "Investigation Notes",
    key="case_notes"
)

case_status = st.selectbox(
    "Case Status",
    [
        "New",
        "Acknowledged",
        "Investigating",
        "Escalated",
        "Closed",
        "False Positive"
    ],
    key="investigation_status_selectbox"
)

assigned_analyst = st.selectbox(
    "Assign Analyst",
    [
        "Analyst 1",
        "Analyst 2",
        "SOC Lead",
        "Threat Hunter"
    ],
    key="investigation_analyst_selectbox"
)
if st.button("Save Investigation Case"):

    save_case(
        user=selected_user,
        alert_type=", ".join(
            user_data["alert_type"].astype(str).unique()
        ),
        risk_score=float(
            user_data["risk_score"].mean()
        ),
        notes=st.session_state.case_notes,
        status=case_status,
        assigned_to=assigned_analyst
    )
    st.success(
        "Investigation case saved successfully."
    )

invest_col1, invest_col2, invest_col3 = st.columns(3)

invest_col1.metric(
    "Total Alerts",
    len(user_data)
)

invest_col2.metric(
    "Average Risk Score",
    round(
        user_data["risk_score"].mean(),
        2
    )
)

invest_col3.metric(
    "Highest Severity",
    user_data["severity"].max()
)
# Sidebar Filters
severity_filter = st.selectbox(
    "Filter by Severity",
    ["ALL"] + list(df["severity"].dropna().unique())
)

alert_filter = st.selectbox(
    "Filter by Alert Type",
    ["ALL"] + list(df["alert_type"].dropna().unique())
)
# Severity Filter
severity_filter = st.multiselect(
    "Filter by Severity",
    options=df["severity"].dropna().unique(),
    default=df["severity"].dropna().unique()
)

filtered_df = df[
    df["severity"].isin(severity_filter)
]
filtered_df = df.copy()

# Apply Severity Filter
if severity_filter != "ALL":
    filtered_df = filtered_df[
    filtered_df["severity"].isin(severity_filter)
]

# Apply Alert Type Filter
if alert_filter != "ALL":
    filtered_df = filtered_df[
        filtered_df["alert_type"] == alert_filter
    ]

st.subheader("Case Management")

selected_alert = st.selectbox(
    "Select Alert to Investigate",
    filtered_df.index
)

selected_alert_data = filtered_df.loc[
    selected_alert
]

st.write(selected_alert_data)

case_status = st.selectbox(
    "Case Status",
    [
        "Open",
        "Investigating",
        "Escalated",
        "Resolved"
    ]
)

analyst_notes = st.text_area(
    "Analyst Notes"
)

if st.button(
    "Save Investigation",
    key="investigation_save_button"
):

    if not filtered_df.empty:

        selected_alert = filtered_df.iloc[0]

        save_case(
            selected_alert["user"],
            selected_alert["alert_type"],
            selected_alert["risk_score"],
            analyst_notes,
            case_status
        )

        st.success(
            f"Investigation for {selected_user} saved successfully."
        )
st.divider()
# Saved Investigation Cases
st.divider()

st.subheader("Saved Investigation Cases")

saved_cases = load_cases()

if saved_cases:

    import pandas as pd

    cases_df = pd.DataFrame(
        saved_cases,
        columns=[
            "ID",
            "User",
            "Alert Type",
            "Risk Score",
            "Notes",
            "Status",
            "Assigned To",
            "Created At"
        ]
    )

    # Case Status Metrics
    open_cases = len(
        cases_df[cases_df["Status"] == "Open"]
    )

    investigating_cases = len(
        cases_df[cases_df["Status"] == "Investigating"]
    )

    escalated_cases = len(
        cases_df[cases_df["Status"] == "Escalated"]
    )

    resolved_cases = len(
        cases_df[cases_df["Status"] == "Resolved"]
    )

    case_col1, case_col2, case_col3, case_col4 = st.columns(4)

    case_col1.metric(
        "Open Cases",
        open_cases
    )

    case_col2.metric(
        "Investigating",
        investigating_cases
    )

    case_col3.metric(
        "Escalated",
        escalated_cases
    )

    case_col4.metric(
        "Resolved",
        resolved_cases
    )

    st.divider()
# Analyst Workload Metrics
st.subheader("Analyst Workload")

analyst_counts = (
    cases_df["Assigned To"]
    .value_counts()
)

analyst_cols = st.columns(
    len(analyst_counts)
)

for i, (analyst, count) in enumerate(
    analyst_counts.items()
):

    analyst_cols[i].metric(
        analyst,
        count
    )

st.divider()
def highlight_risk(val):
        if val >= 80:
           return "background-color: red; color: white"
        elif val >= 50:
           return "background-color: orange; color: black"
        else:
           return "background-color: green; color: white"


styled_df = cases_df.style.map(
    highlight_risk,
    subset=["Risk Score"]
)
# Case Search and Filtering
case_search = st.text_input(
    "Search Cases by User"
)

case_status_filter = st.selectbox(
    "Filter Cases by Status",
    ["All"] + list(cases_df["Status"].unique())
)

filtered_cases_df = cases_df.copy()

# Apply search filter
if case_search:

    filtered_cases_df = filtered_cases_df[
        filtered_cases_df["User"]
        .str.contains(case_search, case=False)
    ]

# Apply status filter
if case_status_filter != "All":

    filtered_cases_df = filtered_cases_df[
        filtered_cases_df["Status"] == case_status_filter
    ]

styled_df = filtered_cases_df.style.map(
    highlight_risk,
    subset=["Risk Score"]
)
st.dataframe(
    styled_df,
    use_container_width=True
)

st.info("No saved investigations yet.")

columns=[
    "ID",
    "User",
    "Alert Type",
    "Risk Score",
    "MITRE Technique",
    "Notes",
    "Status",
    "Created At"
]
# KPI Metrics
critical_alerts = len(
    filtered_df[
        filtered_df["severity"] == "CRITICAL"
    ]
)

high_alerts = len(
    filtered_df[
        filtered_df["severity"] == "HIGH"
    ]
)

medium_alerts = len(
    filtered_df[
        filtered_df["severity"] == "MEDIUM"
    ]
)

total_alerts = len(filtered_df)

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Alerts",
    total_alerts
)

col2.metric(
    "Critical Alerts",
    critical_alerts
)

col3.metric(
    "High Alerts",
    high_alerts
)

col4.metric(
    "Medium Alerts",
    medium_alerts
)
# Severity Distribution Chart

severity_counts = filtered_df["severity"].value_counts()

fig = px.pie(
    values=severity_counts.values,
    names=severity_counts.index,
    title="Threat Severity Distribution"
)

st.plotly_chart(
    fig,
    use_container_width=True
)
# Threat Geography Map
st.divider()

st.subheader("Impossible Travel Threat Map")

travel_df = df[
    df["alert_type"] == "Impossible Travel"
].copy()

fig_map = go.Figure()

for _, row in travel_df.iterrows():

    from_loc = row["from_location"]
    to_loc = row["to_location"]

    if (
        from_loc in location_coords and
        to_loc in location_coords
    ):

        fig_map.add_trace(
            go.Scattergeo(
                lon=[
                    location_coords[from_loc]["lon"],
                    location_coords[to_loc]["lon"]
                ],
                lat=[
                    location_coords[from_loc]["lat"],
                    location_coords[to_loc]["lat"]
                ],
                mode="lines+markers",
                line=dict(width=2),
                marker=dict(size=6),
                name=f"{from_loc} → {to_loc}"
            )
        )

fig_map.update_layout(
    geo=dict(
        projection_type="natural earth",
        showland=True
    ),
    height=600
)

st.plotly_chart(
    fig_map,
    use_container_width=True
)
st.subheader("Detected Threats")

def highlight_severity(row):

    severity = row["severity"]

    if severity == "CRITICAL":
        return ["background-color: red"] * len(row)

    elif severity == "HIGH":
        return ["background-color: orange"] * len(row)

    elif severity == "MEDIUM":
        return ["background-color: yellow"] * len(row)

    else:
        return ["background-color: lightgreen"] * len(row)

styled_df = filtered_df.style.apply(
    highlight_severity,
    axis=1
)

st.dataframe(
    styled_df,
    use_container_width=True
)
# Export Cases
csv = filtered_cases_df.to_csv(
    index=False
).encode("utf-8")

st.download_button(
    label="Download Cases as CSV",
    data=csv,
    file_name="investigation_cases.csv",
    mime="text/csv",
    key="download_cases_csv"
)
# Threat Timeline

timeline_df = filtered_df.copy()

timeline_df["timestamp"] = pd.to_datetime(
    timeline_df["timestamp"],
    errors="coerce"
)

timeline_df = timeline_df.dropna(
    subset=["timestamp"]
)

timeline_counts = (
    timeline_df
    .groupby(
        timeline_df["timestamp"].dt.hour
    )
    .size()
    .reset_index(name="alert_count")
)

fig_timeline = px.line(
    timeline_counts,
    x="timestamp",
    y="alert_count",
    title="Threat Activity Timeline"
)

st.plotly_chart(
    fig_timeline,
    use_container_width=True
)
# Threat Location Map

map_df = filtered_df.copy()

map_df["lat"] = map_df["location"].map(
    lambda x: location_coords.get(
        x,
        {}
    ).get("lat")
)

map_df["lon"] = map_df["location"].map(
    lambda x: location_coords.get(
        x,
        {}
    ).get("lon")
)

map_df = map_df.dropna(
    subset=["lat", "lon"]
)

if not map_df.empty:

    st.subheader("Threat Activity Map")

    st.map(
        map_df[["lat", "lon"]]
    )
st.subheader("Top Risky Users")

user_risk = (
    df.groupby("user")["risk_score"]
    .sum()
    .reset_index()
)

user_risk = user_risk.sort_values(
    by="risk_score",
    ascending=False
)

st.dataframe(
    user_risk,
    use_container_width=True
)# Risk Leaderboard Chart
# Analyst Investigation Panel
st.divider()

st.subheader("Investigate User Activity")

selected_user = st.selectbox(
    "Select User",
    sorted(df["user"].dropna().unique())
)

user_activity = df[
    df["user"] == selected_user
]

st.write(
    f"Showing activity for: {selected_user}"
)

st.dataframe(
    user_activity,
    use_container_width=True
)
# Investigation Workflow
st.divider()

st.subheader("Investigation Notes")

investigation_status = st.selectbox(
    "Case Status",
    [
        "New",
        "Acknowledged",
        "Investigating",
        "Escalated",
        "Closed",
        "False Positive"
    ],
    key="case_status_selectbox"
)

assigned_analyst = st.selectbox(
    "Assign Analyst",
    [
        "Analyst 1",
        "Analyst 2",
        "SOC Lead",
        "Threat Hunter"
    ],
    key="assigned_analyst_selectbox"
)

analyst_notes = st.text_area(
    "Analyst Notes",
    placeholder="Enter investigation findings..."
)

if st.button("Save Investigation"):

    st.success(
        f"Investigation for {selected_user} saved successfully."
    )

    st.write("Status:", investigation_status)

    st.write("Notes:", analyst_notes)
fig_users = px.bar(
    user_risk,
    x="user",
    y="risk_score",
    title="Top Risky Users"
)

st.plotly_chart(
    fig_users,
    use_container_width=True
)
# Alerts Over Time
st.divider()

st.subheader("Alerts Over Time")

timeline_df = (
    df.dropna(subset=["timestamp"])
    .copy()
)

# Timeline chart cleanup
timeline_df = filtered_df.copy()

# Remove empty timestamps
timeline_df = timeline_df.dropna(subset=["timestamp"])

# Convert timestamps properly
timeline_df["timestamp"] = pd.to_datetime(
    timeline_df["timestamp"],
    errors="coerce"
)

# Remove invalid timestamps
timeline_df = timeline_df.dropna(subset=["timestamp"])

# Group alerts over time
timeline_df["hour"] = (
    timeline_df["timestamp"]
    .dt.floor("h")
)

timeline_data = (
    timeline_df.groupby("hour")
    .size()
    .reset_index(name="alert_count")
)

# Sort timestamps
timeline_data = timeline_data.sort_values("hour")
# Create line chart
fig = px.line(
    timeline_data,
    x="hour",
    y="alert_count",
    title="Threat Activity Timeline",
    markers=True
)

st.plotly_chart(
    fig,
    use_container_width=True
)
# Threat Geography Map
st.divider()

st.subheader("Impossible Travel Threat Map")

travel_df = df[
    df["alert_type"] == "Impossible Travel"
].copy()

fig_map = go.Figure()

for _, row in travel_df.iterrows():

    from_loc = row.get("from_location")
    to_loc = row.get("to_location")

    if (
        from_loc in location_coords and
        to_loc in location_coords
    ):

        fig_map.add_trace(
            go.Scattergeo(
                locationmode="country names",
                lon=[
                    location_coords[from_loc]["lon"],
                    location_coords[to_loc]["lon"]
                ],
                lat=[
                    location_coords[from_loc]["lat"],
                    location_coords[to_loc]["lat"]
                ],
                mode="lines+markers",
                line=dict(width=2),
                marker=dict(size=6),
                name=f"{from_loc} → {to_loc}"
            )
        )

fig_map.update_layout(
    geo=dict(
        showland=True,
    ),
    height=600,
    title="Impossible Travel Activity"
)

st.plotly_chart(
    fig_map,
    use_container_width=True
)
# AI Anomaly Detection
st.divider()

st.subheader("AI Detected Anomalous Users")

anomalies_only = anomaly_results[
    anomaly_results["is_anomaly"] == True
]

st.dataframe(
    anomalies_only,
    use_container_width=True
)

# Anomaly Visualization
fig_anomaly = px.bar(
    anomaly_results,
    x="user",
    y="risk_score",
    color="is_anomaly",
    title="AI Behavioral Anomaly Detection"
)

st.plotly_chart(
    fig_anomaly,
    use_container_width=True
)
# Admin Panel
if st.session_state.role == "Administrator":

    st.divider()

    st.subheader("Administrator Controls")

    st.success(
        "Admin access enabled."
    )

    st.write(
        "Platform management tools "
        "will appear here."
    )