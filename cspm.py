import streamlit as st
import pandas as pd
import datetime

# Page Configuration
st.set_page_config(page_title="Cloud Security & Entitlement Manager", layout="wide")

# --- CUSTOM CSS FOR DASHBOARD VISUALS ---
st.markdown("""
    <style>
    /* Metric Button Styles */
    div.stButton > button {
        width: 100%;
        height: 100px;
        border-radius: 5px;
        border: 1px solid #444;
    }
    
    /* Age Card Styles */
    .age-container {
        display: flex;
        justify-content: space-between;
        background-color: #0e1117;
        padding: 10px;
        border-radius: 10px;
    }
    .age-card {
        flex: 1;
        background-color: #1e2129;
        border: 1px solid #333;
        margin: 0 10px;
        padding: 15px;
        border-radius: 8px;
        text-align: center;
        min-width: 150px;
    }
    .age-value {
        font-size: 28px;
        font-weight: bold;
        color: #ff4b4b;
        margin-bottom: 2px;
    }
    .age-label {
        font-size: 14px;
        color: #ffffff;
        font-weight: 500;
    }
    .age-sla {
        font-size: 11px;
        color: #888;
        margin-top: 5px;
    }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Cloud Security & Entitlement Manager")

# Initialize session state
if 'cspm_results' not in st.session_state:
    st.session_state['cspm_results'] = pd.DataFrame()
if 'ciem_results' not in st.session_state:
    st.session_state['ciem_results'] = pd.DataFrame()
if 'dspm_vulnerability_results' not in st.session_state:
    st.session_state['dspm_vulnerability_results'] = pd.DataFrame()
if 'last_scan_time' not in st.session_state:
    st.session_state['last_scan_time'] = "Never"
if 'schedule_enabled' not in st.session_state:
    st.session_state['schedule_enabled'] = False

# --- HELPER FUNCTIONS ---
def run_automated_scan():
    """Logic to simulate data population"""
    cspm_data = [{"Resource": "s3-finance-bucket", "Type": "S3", "Severity": "Critical", "Days Open": 12}]
    ciem_data = [{"Resource": "admin-user-01", "Type": "IAM User", "Severity": "High", "Days Open": 45}]
    dspm_vuln_data = [{"Resource": "s3-customer-pii", "Type": "DSPM", "Severity": "Critical", "Days Open": 2}]
    
    st.session_state['cspm_results'] = pd.DataFrame(cspm_data)
    st.session_state['ciem_results'] = pd.DataFrame(ciem_data)
    st.session_state['dspm_vulnerability_results'] = pd.DataFrame(dspm_vuln_data)
    st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def display_age_card(label, value, sla):
    return f"""
        <div class="age-card">
            <div class="age-value">{value} <span style="font-size:14px">days</span></div>
            <div class="age-label">{label}</div>
            <div class="age-sla">SLA: {sla} days</div>
        </div>
    """

# Main Tabs
tabs_list = ["📊 Executive Dashboard", "🔌 Cloud Integration", "🔍 CSPM & Risk", "📋 Results"]
active_tab = st.tabs(tabs_list)

# --- TAB 1: EXECUTIVE DASHBOARD ---
with active_tab[0]:
    st.header("Security Posture Overview")
    if not st.session_state['cspm_results'].empty:
        all_findings = pd.concat([st.session_state['cspm_results'], st.session_state['ciem_results'], st.session_state['dspm_vulnerability_results']])
        st.markdown(f'<div class="age-container">{display_age_card("Critical", 15, 30)}</div>', unsafe_allow_html=True)
    else:
        st.info("No data available. Please connect and run a scan.")

# --- TAB 2: CLOUD INTEGRATION (FIXED) ---
with active_tab[1]:
    st.header("Connectivity & Automation")
    
    col_cred, col_sched = st.columns(2)
    
    with col_cred:
        st.subheader("Cloud Credentials")
        aws_id = st.text_input("AWS Access Key ID", type="password", placeholder="AKIA...")
        aws_secret = st.text_input("AWS Secret Access Key", type="password", placeholder="wJalrXU...")
        region = st.selectbox("Region", ["us-east-1", "us-west-2", "eu-central-1"], index=0)
        
        if st.button("Connect AWS"):
            if aws_id and aws_secret:
                st.success("Connection Successful!")
                run_automated_scan() # Simulate data on connection
            else:
                st.error("Please enter credentials.")

    with col_sched:
        st.subheader("🗓️ Scan Scheduler")
        st.write("Automatically refresh security data.")
        interval = st.selectbox("Scan Interval", ["Every 1 Hour", "Every 6 Hours", "Daily"])
        
        if not st.session_state['schedule_enabled']:
            if st.button("Enable Scheduler"):
                st.session_state['schedule_enabled'] = True
                st.rerun()
        else:
            st.success(f"Periodic Scanning is ACTIVE ({interval})")
            if st.button("Disable Scheduler"):
                st.session_state['schedule_enabled'] = False
                st.rerun()

# Placeholder for remaining tabs
with active_tab[2]:
    st.header("CSPM & Risk Analysis")
    st.dataframe(st.session_state['cspm_results'], use_container_width=True)

with active_tab[3]:
    st.header("Scan Results & Remediation")
    st.write("Full audit logs and automation artifacts appear here.")
