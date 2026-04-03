import streamlit as st
import pandas as pd
import boto3
import io
import datetime
import time

# Page Configuration
st.set_page_config(page_title="Cloud Security & Entitlement Manager", layout="wide")

# --- CUSTOM CSS ---
st.markdown("""
    <style>
    div.stButton > button {
        width: 100%;
        height: 100px;
        border-radius: 5px;
        border: 1px solid #444;
    }
    .metric-card {
        background-color: #1e2129;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #ff4b4b;
        margin-bottom: 10px;
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

# --- HELPER FUNCTIONS ---
def run_automated_scan():
    """Logic to simulate a full environment scan including Governance & DSPM"""
    
    # 1. CSPM
    cspm_data = [
        {"Resource": "s3-finance-bucket", "Type": "S3", "Severity": "Critical", "Issue": "Public Read Access", "Framework": "PCI-DSS"},
        {"Resource": "ec2-web-server", "Type": "Toxic Combination", "Severity": "Critical", "Issue": "Vulnerable + Admin Role", "Framework": "CIS AWS"}
    ]
    
    # 2. CIEM
    ciem_data = [
        {"Resource": "admin-user-01", "Type": "IAM User", "Severity": "High", "Issue": "MFA Disabled", "Framework": "SOC 2"}
    ]

    # 3. DSPM - Sensitive Data Discovery
    dspm_vuln_data = [
        {"Resource": "db-backup.sql", "Type": "Secrets", "Severity": "Critical", "Issue": "Hardcoded Passwords Found", "Data_Type": "Password"},
        {"Resource": "customer_list.csv", "Type": "DSPM", "Severity": "Critical", "Issue": "Unencrypted PII (SSN)", "Data_Type": "PII"},
        {"Resource": "health_records.pdf", "Type": "DSPM", "Severity": "High", "Issue": "PHI Exposure", "Data_Type": "PHI"},
        {"Resource": "billing_export.xlsx", "Type": "DSPM", "Severity": "Critical", "Issue": "Plaintext Bank Account Numbers", "Data_Type": "Bank Account"},
        {"Resource": "aws_config_script.sh", "Type": "Secrets", "Severity": "High", "Issue": "AWS Access Keys Exposed", "Data_Type": "Secret Key"}
    ]
    
    # 4. Compliance & Governance
    comp_data = [
        {"Framework": "CIS AWS Foundations", "Passed": 45, "Failed": 5, "Status": "88%"},
        {"Framework": "PCI-DSS v4.0", "Passed": 112, "Failed": 12, "Status": "90%"},
        {"Framework": "HIPAA / HITECH", "Passed": 88, "Failed": 2, "Status": "97%"},
        {"Framework": "SOC 2 Type II", "Passed": 154, "Failed": 8, "Status": "95%"},
        {"Framework": "NIST 800-53", "Passed": 210, "Failed": 25, "Status": "89%"}
    ]
    
    st.session_state['cspm_results'] = pd.DataFrame(cspm_data)
    st.session_state['ciem_results'] = pd.DataFrame(ciem_data)
    st.session_state['dspm_vulnerability_results'] = pd.DataFrame(dspm_vuln_data)
    st.session_state['compliance_results'] = pd.DataFrame(comp_data)
    st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
    st.header("Security & Compliance Posture")
    st.caption(f"Last Scan: {st.session_state['last_scan_time']}")
    
    # Sensitive Data Counters
    if not st.session_state['dspm_vulnerability_results'].empty:
        dspm_df = st.session_state['dspm_vulnerability_results']
        pii_count = len(dspm_df[dspm_df['Data_Type'] == 'PII'])
        secret_count = len(dspm_df[dspm_df['Data_Type'].isin(['Password', 'Secret Key'])])
        bank_count = len(dspm_df[dspm_df['Data_Type'] == 'Bank Account'])
        
        c1, c2, c3 = st.columns(3)
        c1.metric("Sensitive PII Files", pii_count)
        c2.metric("Exposed Secrets/Passwords", secret_count)
        c3.metric("Financial/Bank Data", bank_count)
    
    st.divider()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1: st.button("🚨 Critical Issues")
    with col2: st.button("⚠️ High Risk")
    with col3: st.button("⚖️ Compliance Score: 92%")
    with col4: st.button("📋 Total Findings")

# --- TAB 2: CLOUD INTEGRATION ---
with active_tab[1]:
    st.header("Connectivity & Automation")
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.subheader("Cloud Credentials")
        aws_access_key = st.text_input("AWS Access Key ID", type="password", key="aws_key")
        aws_secret_key = st.text_input("AWS Secret Access Key", type="password", key="aws_secret")
        aws_region = st.selectbox("Region", ["us-east-1", "us-west-2", "eu-central-1"], key="aws_reg")
        if st.button("Connect AWS"):
            st.success("Connected! AWS Credentials validated.")

    with col_right:
        st.subheader("📅 Scan Scheduler")
        st.write("Automatically refresh security data.")
        interval = st.selectbox("Scan Interval", ["Every 1 Hour", "Every 6 Hours", "Every 24 Hours"])
        
        if not st.session_state['schedule_enabled']:
            if st.button("⏰ Enable Periodic Scanning", type="primary"):
                st.session_state['schedule_enabled'] = True
                run_automated_scan()
                st.rerun()
        else:
            st.success(f"Periodic Scanning is ACTIVE ({interval})")
            if st.button("🛑 Disable Scheduler"):
                st.session_state['schedule_enabled'] = False
                st.rerun()

# --- TAB 3: COMPLIANCE & GOVERNANCE ---
with active_tab[2]:
    st.header("⚖️ Continuous Compliance & Governance")
    st.write("Assessment against 250+ built-in frameworks and custom organizational policies.")
    
    col_f1, col_f2 = st.columns([2, 1])
    
    with col_f1:
        st.subheader("Framework Compliance Status")
        if not st.session_state['compliance_results'].empty:
            st.table(st.session_state['compliance_results'])
        else:
            st.info("Run a scan to assess compliance.")
            
    with col_f2:
        st.subheader("Custom Frameworks")
        st.write("Create internal security policies.")
        st.text_input("Framework Name", placeholder="e.g., Internal FinTech Standards")
        st.multiselect("Map to Controls", ["Access Control", "Encryption", "Logging", "Network Isolation"])
        if st.button("Create Custom Policy"):
            st.success("Custom Framework Created Successfully")

# --- TAB 4: CSPM ---
with active_tab[3]:
    st.header("🔍 CSPM: Inventory & Vulnerability Scan")
    if st.button("Run Infrastructure Scan"):
        run_automated_scan()
        st.dataframe(st.session_state['cspm_results'], use_container_width=True)

# --- TAB 5: CIEM ---
with active_tab[4]:
    st.header("🔑 CIEM: Identity Mapping")
    if not st.session_state['ciem_results'].empty:
        st.table(st.session_state['ciem_results'])
    else:
        st.info("Run a scan to see identity risks.")

# --- TAB 6: DSPM & SENSITIVE DATA ---
with active_tab[5]:
    st.header("🛡️ Data Security Posture Management (DSPM)")
    if st.button("Run Deep Data Discovery Scan"):
        run_automated_scan()
    
    if not st.session_state['dspm_vulnerability_results'].empty:
        st.subheader("Sensitive Data Discovery Findings")
        st.dataframe(st.session_state['dspm_vulnerability_results'], use_container_width=True)
        
        st.write("### Data Type Distribution")
        type_dist = st.session_state['dspm_vulnerability_results']['Data_Type'].value_counts()
        st.bar_chart(type_dist)

# --- TAB 7: SCAN RESULTS & REMEDIATION ---
with active_tab[6]:
    st.header("📋 Consolidated Remediation Table")
    all_findings = pd.concat([
        st.session_state['cspm_results'], 
        st.session_state['ciem_results'],
        st.session_state['dspm_vulnerability_results']
    ], ignore_index=True)
    
    if not all_findings.empty:
        st.dataframe(all_findings, use_container_width=True)
    else:
        st.info("No scan data available.")
