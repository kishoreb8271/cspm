import streamlit as st
import pandas as pd
import boto3
import io
import datetime
import time

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
    
    /* Average Age Card Styles */
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
if 'active_tab_index' not in st.session_state:
    st.session_state['active_tab_index'] = 0
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
    """Logic to simulate a background periodic scan with Aging data"""
    # 1. CSPM & Toxic Combinations (Added 'Days Open')
    cspm_data = [
        {"Resource": "s3-finance-bucket", "Type": "S3", "Severity": "Critical", "Issue": "Public Read Access", "Remediation": "Block", "Days Open": 12},
        {"Resource": "ec2-web-server", "Type": "Toxic Combination", "Severity": "Critical", "Issue": "Vulnerable + Admin Access", "Remediation": "Isolate", "Days Open": 4}
    ]
    
    # 2. CIEM
    ciem_data = [
        {"Resource": "admin-user-01", "Type": "IAM User", "Severity": "High", "Issue": "MFA Disabled", "Remediation": "Enable MFA", "Days Open": 45}
    ]

    # 3. DSPM & Vulnerability
    dspm_vuln_data = [
        {"Resource": "s3-customer-pii", "Type": "DSPM", "Severity": "Critical", "Issue": "Unencrypted PII", "Remediation": "Encrypt", "Days Open": 2},
        {"Resource": "ec2-prod-app", "Type": "Vulnerability", "Severity": "High", "Issue": "CVE-2023-XXXX", "Remediation": "Patch AMI", "Days Open": 82},
        {"Resource": "lambda-payment", "Type": "Secrets", "Severity": "Medium", "Issue": "Hardcoded Key", "Remediation": "Secrets Manager", "Days Open": 156}
    ]
    
    st.session_state['cspm_results'] = pd.DataFrame(cspm_data)
    st.session_state['ciem_results'] = pd.DataFrame(ciem_data)
    st.session_state['dspm_vulnerability_results'] = pd.DataFrame(dspm_vuln_data)
    st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def go_to_results():
    st.session_state['active_tab_index'] = 5

def display_age_card(label, value, sla):
    """HTML Render for the Age Metric Card"""
    return f"""
        <div class="age-card">
            <div class="age-value">{value} <span style="font-size:14px">days</span></div>
            <div class="age-label">{label}</div>
            <div class="age-sla">SLA: {sla} days</div>
        </div>
    """

# Main Tabs
tabs_list = ["📊 Executive Dashboard", "🔌 Cloud Integration", "🔍 CSPM & Risk", "🔑 CIEM", "🛡️ DSPM", "📋 Results"]
active_tab = st.tabs(tabs_list)

# --- TAB 1: EXECUTIVE DASHBOARD ---
with active_tab[0]:
    st.header("Security Posture Overview")
    st.caption(f"⏱️ Last Periodic Scan: {st.session_state['last_scan_time']}")
    
    all_findings = pd.concat([
        st.session_state['cspm_results'], 
        st.session_state['ciem_results'],
        st.session_state['dspm_vulnerability_results']
    ], ignore_index=True)
    
    if not all_findings.empty:
        # 1. PRIMARY METRIC BUTTONS
        crit = len(all_findings[all_findings['Severity'] == 'Critical'])
        high = len(all_findings[all_findings['Severity'] == 'High'])
        toxic = len(st.session_state['cspm_results'][st.session_state['cspm_results']['Type'] == 'Toxic Combination'])
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            if st.button(f"🚨 Critical Issues\n\n{crit}"): go_to_results(); st.rerun()
        with col2:
            if st.button(f"⚠️ High Risk\n\n{high}"): go_to_results(); st.rerun()
        with col3:
            if st.button(f"☣️ Toxic Combos\n\n{toxic}"): go_to_results(); st.rerun()
        with col4:
            if st.button(f"📋 Total Findings\n\n{len(all_findings)}"): go_to_results(); st.rerun()

        st.divider()

        # 2. AVERAGE ISSUE AGE SECTION (New Visual)
        st.subheader("Average Issue Age")
        
        # Calculation logic
        avg_crit = int(all_findings[all_findings['Severity'] == 'Critical']['Days Open'].mean()) if crit > 0 else 0
        avg_high = int(all_findings[all_findings['Severity'] == 'High']['Days Open'].mean()) if high > 0 else 0
        
        # Displaying the row of cards
        age_html = f"""
        <div class="age-container">
            {display_age_card("Critical Issues", avg_crit, 30)}
            {display_age_card("High Issues", avg_high, 60)}
            {display_age_card("Medium Issues", 156, 100)}
            {display_age_card("Low Issues", 241, 180)}
        </div>
        """
        st.markdown(age_html, unsafe_allow_html=True)

        st.divider()
        
        # 3. DISTRIBUTION CHART
        severity_dist = all_findings['Severity'].value_counts().reset_index()
        severity_dist.columns = ['Severity', 'Count']
        st.subheader("Risk Distribution Across All Modules")
        st.bar_chart(severity_dist, x="Severity", y="Count", color="#ff4b4b")
    else:
        st.info("Please run a scan from the specialized tabs or enable the scheduler.")

# [Rest of the tabs (Integration, CSPM, CIEM, DSPM, Results) follow the same logic as your previous version]
