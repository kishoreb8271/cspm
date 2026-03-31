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
    /* Average Age Gauge-style box */
    .age-card {
        background-color: #1e1e1e;
        border: 1px solid #333;
        padding: 15px;
        border-radius: 10px;
        text-align: center;
    }
    .age-value {
        font-size: 24px;
        font-weight: bold;
        color: #ff4b4b;
    }
    .age-label {
        font-size: 14px;
        color: #888;
    }
    .sla-label {
        font-size: 10px;
        color: #555;
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
    """Logic to simulate background scan including 'Days Open' for aging data"""
    # Added "Days Open" to findings
    cspm_data = [
        {"Resource": "s3-finance-bucket", "Type": "S3", "Severity": "Critical", "Issue": "Public Read Access", "Remediation": "Block", "Days Open": 12},
        {"Resource": "ec2-web-server", "Type": "Toxic Combo", "Severity": "Critical", "Issue": "Vulnerable + Admin", "Remediation": "Isolate", "Days Open": 5}
    ]
    
    ciem_data = [
        {"Resource": "admin-user-01", "Type": "IAM User", "Severity": "High", "Issue": "MFA Disabled", "Remediation": "Enable MFA", "Days Open": 45}
    ]

    dspm_vuln_data = [
        {"Resource": "s3-customer-pii", "Type": "DSPM", "Severity": "Critical", "Issue": "Unencrypted PII", "Remediation": "Encrypt", "Days Open": 2},
        {"Resource": "ec2-prod-app", "Type": "Vulnerability", "Severity": "High", "Issue": "CVE-2023-XXXX", "Remediation": "Patch", "Days Open": 89},
        {"Resource": "lambda-pay", "Type": "Secrets", "Severity": "Critical", "Issue": "Hardcoded Key", "Remediation": "Rotate", "Days Open": 1}
    ]
    
    st.session_state['cspm_results'] = pd.DataFrame(cspm_data)
    st.session_state['ciem_results'] = pd.DataFrame(ciem_data)
    st.session_state['dspm_vulnerability_results'] = pd.DataFrame(dspm_vuln_data)
    st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def go_to_results():
    st.session_state['active_tab_index'] = 5

def display_age_card(label, days, sla):
    """Renders the age card visually similar to the reference image"""
    st.markdown(f"""
        <div class="age-card">
            <div class="age-value">{days} <span style="font-size:14px">days</span></div>
            <div class="age-label">{label}</div>
            <div class="sla-label">SLA: {sla} days</div>
        </div>
    """, unsafe_allow_html=True)

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
        # 1. Primary Metrics
        crit = len(all_findings[all_findings['Severity'] == 'Critical'])
        high = len(all_findings[all_findings['Severity'] == 'High'])
        toxic = len(st.session_state['cspm_results'][st.session_state['cspm_results']['Type'] == 'Toxic Combo'])
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            if st.button(f"🚨 Critical\n\n{crit}"): go_to_results(); st.rerun()
        with col2:
            if st.button(f"⚠️ High\n\n{high}"): go_to_results(); st.rerun()
        with col3:
            if st.button(f"☣️ Toxic\n\n{toxic}"): go_to_results(); st.rerun()
        with col4:
            if st.button(f"📋 Total\n\n{len(all_findings)}"): go_to_results(); st.rerun()

        st.divider()

        # 2. AVERAGE ISSUE AGE SECTION (As requested)
        st.subheader("Average Issue Age")
        age_col1, age_col2, age_col3, age_col4 = st.columns(4)
        
        # Calculating actual averages from the dataframe
        avg_crit = int(all_findings[all_findings['Severity'] == 'Critical']['Days Open'].mean())
        avg_high = int(all_findings[all_findings['Severity'] == 'High']['Days Open'].mean())
        
        with age_col1:
            display_age_card("Critical Issues", avg_crit, 30)
        with age_col2:
            display_age_card("High Issues", avg_high, 60)
        with age_col3:
            display_age_card("Medium Issues", 161, 100) # Mock
        with age_col4:
            display_age_card("Low Issues", 258, 180) # Mock

        st.divider()
        
        # 3. Distribution Chart
        severity_dist = all_findings['Severity'].value_counts().reset_index()
        severity_dist.columns = ['Severity', 'Count']
        st.subheader("Issue Distribution")
        st.bar_chart(severity_dist, x="Severity", y="Count", color="#ff4b4b")
    else:
        st.info("Run a scan to see dashboard data.")

# (Rest of the tabs remain functionally same as previous version...)
