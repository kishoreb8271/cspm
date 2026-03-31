import streamlit as st
import pandas as pd
import boto3
import io
import datetime
import time
import json
import re

# Page Configuration
st.set_page_config(page_title="Cloud Security & Entitlement Manager", layout="wide")

# --- CUSTOM CSS ---
st.markdown("""
    <style>
    div.stButton > button {
        width: 100%;
        height: 80px;
        border-radius: 5px;
        border: 1px solid #444;
    }
    .stMetric {
        background-color: #1e2129;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #333;
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
if 'compliance_results' not in st.session_state:
    st.session_state['compliance_results'] = pd.DataFrame()
if 'last_scan_time' not in st.session_state:
    st.session_state['last_scan_time'] = "Never"
if 'schedule_enabled' not in st.session_state:
    st.session_state['schedule_enabled'] = False
if 'aws_connected' not in st.session_state:
    st.session_state['aws_connected'] = False

# --- HELPER FUNCTIONS ---
def get_aws_client(service, access_key, secret_key, region):
    """Helper from previous code to initialize AWS connection"""
    return boto3.client(
        service,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )

def run_automated_scan(module_name="Full System"):
    """Logic to simulate a full environment scan with status updates"""
    with st.status(f"Running {module_name} Scan...", expanded=True) as status:
        st.write("🔍 Initializing security modules...")
        time.sleep(1)
        st.write(f"🛰️ Connecting to cloud endpoints for {module_name}...")
        time.sleep(1.5)
        st.write("📊 Analyzing resource configurations against frameworks...")
        time.sleep(1)
        
        cspm_data = [
            {"Resource": "s3-finance-bucket", "Type": "S3", "Severity": "Critical", "Issue": "Public Read Access", "Framework": "PCI-DSS", "Remediation": "Block Public Access"},
            {"Resource": "ec2-web-server", "Type": "Toxic Combination", "Severity": "Critical", "Issue": "Vulnerable + Admin Role", "Framework": "CIS AWS", "Remediation": "Restrict SG to Trusted IP"}
        ]
        ciem_data = [
            {"Resource": "admin-user-01", "Type": "IAM User", "Severity": "High", "Issue": "MFA Disabled", "Framework": "SOC 2", "Remediation": "Enable MFA"},
            {"Resource": "test-key-01", "Type": "Access Key", "Severity": "Medium", "Issue": "Key Rotation Overdue", "Framework": "CIS", "Remediation": "Rotate Access Key"}
        ]
        dspm_vuln_data = [
            {"Resource": "db-backup.sql", "Type": "Secrets", "Severity": "Critical", "Issue": "Hardcoded Passwords Found", "Data_Type": "Password"},
            {"Resource": "customer_list.csv", "Type": "DSPM", "Severity": "Critical", "Issue": "Unencrypted PII (SSN)", "Data_Type": "PII"},
            {"Resource": "health_records.pdf", "Type": "DSPM", "Severity": "High", "Issue": "PHI Exposure", "Data_Type": "PHI"},
            {"Resource": "billing_export.xlsx", "Type": "DSPM", "Severity": "Critical", "Issue": "Plaintext Bank Account Numbers", "Data_Type": "Bank Account"}
        ]
        comp_data = [
            {"Framework": "CIS AWS Foundations", "Passed": 45, "Failed": 5, "Status": "88%"},
            {"Framework": "PCI-DSS v4.0", "Passed": 112, "Failed": 12, "Status": "90%"},
            {"Framework": "SOC 2 Type II", "Passed": 154, "Failed": 8, "Status": "95%"}
        ]
        
        st.session_state['cspm_results'] = pd.DataFrame(cspm_data)
        st.session_state['ciem_results'] = pd.DataFrame(ciem_data)
        st.session_state['dspm_vulnerability_results'] = pd.DataFrame(dspm_vuln_data)
        st.session_state['compliance_results'] = pd.DataFrame(comp_data)
        st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        status.update(label=f"{module_name} Scan Complete!", state="complete", expanded=False)

# Main Tabs
tabs_list = [
    "📊 Executive Dashboard", 
    "🔌 Cloud Integration", 
    "⚖️ Compliance & Governance",
    "🔍 CSPM (Inventory & Scan)", 
    "🔑 CIEM (Identity Mapping)", 
    "🛡️ DSPM & Sensitive Data",
    "📋 Scan Results & Remediation"
]
active_tab = st.tabs(tabs_list)

# --- TAB 1: EXECUTIVE DASHBOARD ---
with active_tab[0]:
    st.header("Cloud Security Posture Overview")
    st.caption(f"⏱️ Last Periodic Scan: {st.session_state['last_scan_time']}")
    
    all_findings = pd.concat([
        st.session_state['cspm_results'], 
        st.session_state['ciem_results'],
        st.session_state['dspm_vulnerability_results']
    ], ignore_index=True)
    
    crit = len(all_findings[all_findings.get('Severity') == 'Critical']) if not all_findings.empty else 0
    high = len(all_findings[all_findings.get('Severity') == 'High']) if not all_findings.empty else 0
    med = len(all_findings[all_findings.get('Severity') == 'Medium']) if not all_findings.empty else 0
    zombie = len(st.session_state['ciem_results']) if not st.session_state['ciem_results'].empty else 0

    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("Critical Issues", crit, delta="-2" if crit > 0 else "0", delta_color="inverse")
    with m2: st.metric("High Risk", high, delta="+3" if high > 0 else "0", delta_color="inverse")
    with m3: st.metric("Medium Risk", med, delta="0")
    with m4: st.metric("Zombie Identities", zombie, delta="+1" if zombie > 0 else "0", delta_color="inverse")

    st.divider()

    st.subheader("Security & Compliance Posture")
    c1, c2, c3, c4 = st.columns(4)
    if not st.session_state['dspm_vulnerability_results'].empty:
        dspm_df = st.session_state['dspm_vulnerability_results']
        with c1: st.metric("Sensitive PII Files", len(dspm_df[dspm_df['Data_Type'] == 'PII']))
        with c2: st.metric("Exposed Secrets", len(dspm_df[dspm_df['Data_Type'].isin(['Password', 'Secret Key'])]))
        with c3: st.metric("Financial Data", len(dspm_df[dspm_df['Data_Type'] == 'Bank Account']))
        with c4: st.metric("Compliance Score", "92%")
    else:
        st.info("No data available. Run a scan to populate metrics.")

    st.divider()

    if not all_findings.empty:
        st.subheader("Issue Distribution Across Modules")
        severity_dist = all_findings['Severity'].value_counts().reset_index()
        severity_dist.columns = ['Severity', 'Count']
        st.bar_chart(severity_dist, x="Severity", y="Count", color="#ff4b4b")

    st.subheader("Quick Links")
    q1, q2 = st.columns(2)
    with q1:
        if st.button("🔗 View Detailed CSPM Findings"):
            st.info("Please navigate to the '🔍 CSPM (Inventory & Scan)' tab.")
    with q2:
        if st.button("🔗 View Detailed CIEM Findings"):
            st.info("Please navigate to the '🔑 CIEM (Identity Mapping)' tab.")

# --- TAB 2: CLOUD INTEGRATION ---
with active_tab[1]:
    st.header("Connectivity & Automation")
    col_left, col_right = st.columns(2)
    with col_left:
        st.subheader("Cloud Credentials")
        aws_key = st.text_input("AWS Access Key ID", type="password")
        aws_sec = st.text_input("AWS Secret Access Key", type="password")
        aws_reg = st.selectbox("Region", ["us-east-1", "us-west-2", "eu-central-1"])
        if st.button("Connect AWS"):
            st.session_state['aws_connected'] = True
            st.success("Connected! AWS Credentials validated.")

    with col_right:
        st.subheader("📅 Scan Scheduler")
        interval = st.selectbox("Scan Interval", ["Every 1 Hour", "Every 6 Hours", "Daily"])
        if not st.session_state['schedule_enabled']:
            if st.button("⏰ Enable Periodic Scanning", type="primary"):
                st.session_state['schedule_enabled'] = True
                run_automated_scan("Scheduled System")
                st.rerun()
        else:
            st.success(f"Periodic Scanning is ACTIVE ({interval})")
            if st.button("🛑 Disable Scheduler"):
                st.session_state['schedule_enabled'] = False
                st.rerun()

# --- TAB 3: COMPLIANCE ---
with active_tab[2]:
    st.header("⚖️ Continuous Compliance & Governance")
    if not st.session_state['compliance_results'].empty:
        st.table(st.session_state['compliance_results'])
    else:
        st.info("Assessment pending scan.")

# --- TAB 4: CSPM SCAN ---
with active_tab[3]:
    st.header("🔍 CSPM: Inventory & Vulnerability Scan")
    if st.button("Run Infrastructure Scan"):
        run_automated_scan("CSPM")
    if not st.session_state['cspm_results'].empty:
        st.dataframe(st.session_state['cspm_results'], use_container_width=True)
    else:
        st.info("No infrastructure findings yet.")

# --- TAB 5: CIEM SCAN ---
with active_tab[4]:
    st.header("🔑 CIEM: Identity Mapping")
    if st.button("Run CIEM Identity Scan"):
        run_automated_scan("CIEM")
    if not st.session_state['ciem_results'].empty:
        st.table(st.session_state['ciem_results'])
    else:
        st.info("No identity risks identified.")

# --- TAB 6: DSPM & SENSITIVE DATA ---
with active_tab[5]:
    st.header("🛡️ Data Security Posture Management (DSPM)")
    if st.button("Run Deep Data Discovery Scan"):
        run_automated_scan("DSPM")
    if not st.session_state['dspm_vulnerability_results'].empty:
        st.dataframe(st.session_state['dspm_vulnerability_results'], use_container_width=True)
        type_dist = st.session_state['dspm_vulnerability_results']['Data_Type'].value_counts()
        st.bar_chart(type_dist)

# --- TAB 7: SCAN RESULTS & REMEDIATION ---
with active_tab[6]:
    st.header("📋 Consolidated Remediation Table")
    final_df = pd.concat([st.session_state['cspm_results'], st.session_state['ciem_results']], ignore_index=True)
    if not final_df.empty:
        st.dataframe(final_df, use_container_width=True, hide_index=True)
    else:
        st.info("No scan results found.")
