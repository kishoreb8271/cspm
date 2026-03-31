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
    return boto3.client(
        service,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )

def run_automated_scan(module_name="Full System"):
    """Logic to simulate a full environment scan with AI-driven DSPM updates"""
    with st.status(f"Running {module_name} Scan...", expanded=True) as status:
        st.write("🔍 Initializing security modules...")
        time.sleep(1)
        st.write(f"🛰️ Connecting to cloud endpoints for {module_name}...")
        time.sleep(1)
        
        # New AI Step for DSPM
        if module_name in ["DSPM", "Full System", "Scheduled System"]:
            st.write("🤖 AI Agent: Scanning object contents for sensitive patterns (PII/PHI/Secrets)...")
            time.sleep(2)
        
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
        
        # Updated DSPM Data with File Name and Path
        dspm_vuln_data = [
            {"File Name": "db-backup.sql", "File Path": "s3://prod-backups/sql/", "Severity": "Critical", "Issue": "Hardcoded Passwords Found", "Data_Type": "Password", "AI_Confidence": "99%"},
            {"File Name": "customer_list.csv", "File Path": "s3://marketing-data/exports/", "Severity": "Critical", "Issue": "Unencrypted PII (SSN)", "Data_Type": "PII", "AI_Confidence": "96%"},
            {"File Name": "health_records.pdf", "File Path": "s3://hr-portal/medical-2024/", "Severity": "High", "Issue": "PHI Exposure", "Data_Type": "PHI", "AI_Confidence": "92%"},
            {"File Name": "billing_export.xlsx", "File Path": "s3://finance-logs/billing/", "Severity": "Critical", "Issue": "Plaintext Bank Account Numbers", "Data_Type": "Bank Account", "AI_Confidence": "98%"}
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
    
    # Calculate Metrics
    all_findings_count = len(st.session_state['cspm_results']) + len(st.session_state['ciem_results']) + len(st.session_state['dspm_vulnerability_results'])
    
    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("Critical Issues", "5", delta="-2", delta_color="inverse")
    with m2: st.metric("High Risk", "3", delta="+1", delta_color="inverse")
    with m3: st.metric("Medium Risk", "1", delta="0")
    with m4: st.metric("Sensitive Data Files", len(st.session_state['dspm_vulnerability_results']))

    st.divider()
    st.subheader("Security & Compliance Posture")
    c1, c2, c3, c4 = st.columns(4)
    if not st.session_state['dspm_vulnerability_results'].empty:
        df = st.session_state['dspm_vulnerability_results']
        with c1: st.metric("PII Findings", len(df[df['Data_Type'] == 'PII']))
        with c2: st.metric("Secrets Exposed", len(df[df['Data_Type'] == 'Password']))
        with c3: st.metric("Financial Records", len(df[df['Data_Type'] == 'Bank Account']))
        with c4: st.metric("AI Confidence Avg", "96%")
    else:
        st.info("No data available. Run a scan in the DSPM tab.")

# --- TAB 2: CLOUD INTEGRATION ---
with active_tab[1]:
    st.header("Connectivity & Automation")
    col_left, col_right = st.columns(2)
    with col_left:
        st.subheader("Cloud Credentials")
        st.text_input("AWS Access Key ID", type="password")
        st.text_input("AWS Secret Access Key", type="password")
        st.selectbox("Region", ["us-east-1", "us-west-2"])
        if st.button("Connect AWS"):
            st.session_state['aws_connected'] = True
            st.success("Connected!")
    with col_right:
        st.subheader("📅 Scan Scheduler")
        if st.button("⏰ Run Full System Scan Now", type="primary"):
            run_automated_scan("Full System")

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
    st.dataframe(st.session_state['cspm_results'], use_container_width=True)

# --- TAB 5: CIEM SCAN ---
with active_tab[4]:
    st.header("🔑 CIEM: Identity Mapping")
    if st.button("Run CIEM Identity Scan"):
        run_automated_scan("CIEM")
    st.table(st.session_state['ciem_results'])

# --- TAB 6: DSPM & SENSITIVE DATA ---
with active_tab[5]:
    st.header("🛡️ AI-Powered Data Security (DSPM)")
    st.write("Using AI Agents to scan and classify sensitive information across storage buckets.")
    
    if st.button("Run AI Deep Data Discovery"):
        run_automated_scan("DSPM")
    
    if not st.session_state['dspm_vulnerability_results'].empty:
        # Display the results with File Names and Paths
        st.subheader("Sensitive Data Inventory")
        st.dataframe(
            st.session_state['dspm_vulnerability_results'], 
            use_container_width=True,
            column_config={
                "File Path": st.column_config.TextColumn("Storage Location (Path)"),
                "AI_Confidence": st.column_config.ProgressColumn("AI Confidence Score", min_value=0, max_value=100, format="%d%%")
            }
        )
    else:
        st.info("No sensitive data discovered. Run the AI Scan to start.")

# --- TAB 7: SCAN RESULTS & REMEDIATION ---
with active_tab[6]:
    st.header("📋 Consolidated Remediation Table")
    if not st.session_state['cspm_results'].empty:
        st.write("Infrastructure & Identity Remediation")
        final_df = pd.concat([st.session_state['cspm_results'], st.session_state['ciem_results']], ignore_index=True)
        st.dataframe(final_df, use_container_width=True, hide_index=True)
