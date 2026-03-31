import streamlit as st
import pandas as pd
import boto3
import datetime
import json
import re

# Page Configuration
st.set_page_config(page_title="Cloud Security & Entitlement Manager", layout="wide")

st.title("🛡️ Cloud Security & Entitlement Manager")

# Initialize session state for navigation and results
if 'active_tab' not in st.session_state:
    st.session_state['active_tab'] = "📊 Executive Dashboard"
if 'cspm_results' not in st.session_state:
    st.session_state['cspm_results'] = pd.DataFrame()
if 'ciem_results' not in st.session_state:
    st.session_state['ciem_results'] = pd.DataFrame()

# Main Tabs
tabs = ["📊 Executive Dashboard", "🔌 Cloud Integration", "🔍 CSPM (Inventory & Scan)", "🔑 CIEM (Identity Mapping)", "📋 Scan Results & Remediation"]
tab_dash, tab_integ, tab_cspm, tab_ciem, tab_results = st.tabs(tabs)

# --- HELPER: AWS AUTHENTICATION ---
def get_aws_client(service, access_key, secret_key, region):
    return boto3.client(
        service,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )

# --- TAB 1: EXECUTIVE DASHBOARD (REAL-TIME MAPPING) ---
with tab_dash:
    st.header("Security Posture Overview")
    
    # Calculate Real-time Metrics
    all_findings = pd.concat([st.session_state['cspm_results'], st.session_state['ciem_results']], ignore_index=True)
    
    critical_count = len(all_findings[all_findings.get('Severity') == 'Critical']) if not all_findings.empty else 0
    high_count = len(all_findings[all_findings.get('Severity') == 'High']) if not all_findings.empty else 0
    medium_count = len(all_findings[all_findings.get('Severity') == 'Medium']) if not all_findings.empty else 0
    zombie_ids = len(st.session_state['ciem_results']) if not st.session_state['ciem_results'].empty else 0

    # Display Metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Critical Issues", critical_count, delta="-2" if critical_count > 0 else "0", delta_color="inverse")
    with col2:
        st.metric("High Risk", high_count, delta="+5" if high_count > 0 else "0", delta_color="inverse")
    with col3:
        st.metric("Medium Risk", medium_count, delta="0")
    with col4:
        st.metric("Zombie Identities", zombie_ids, delta="+1" if zombie_ids > 0 else "0", delta_color="inverse")

    st.divider()
    
    # Real-time Issue Distribution Chart
    if not all_findings.empty:
        severity_dist = all_findings['Severity'].value_counts().reset_index()
        severity_dist.columns = ['Severity', 'Count']
        st.subheader("Issue Distribution")
        st.bar_chart(severity_dist, x="Severity", y="Count", color="#ff4b4b")
    else:
        st.info("Run scans to see visual distribution.")

    # Redirection Links
    st.write("---")
    st.subheader("Quick Links")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("🔗 View Detailed CSPM Findings"):
            st.info("Please click the '🔍 CSPM (Inventory & Scan)' tab above.")
    with c2:
        if st.button("🔗 View Detailed CIEM Findings"):
            st.info("Please click the '🔑 CIEM (Identity Mapping)' tab above.")

# --- TAB 2: CLOUD INTEGRATION ---
with tab_integ:
    st.header("Connect Cloud Providers")
    aws_access_key = st.text_input("AWS Access Key ID", type="password")
    aws_secret_key = st.text_input("AWS Secret Access Key", type="password")
    aws_region = st.selectbox("Region", ["us-east-1", "us-west-2"])
    if st.button("Connect AWS"):
        st.session_state['aws_connected'] = True
        st.session_state['aws_creds'] = {'key': aws_access_key, 'secret': aws_secret_key, 'region': aws_region}
        st.success("Connected!")

# --- TAB 3: CSPM SCAN ---
with tab_cspm:
    st.header("CSPM Discovery")
    if st.button("Run CSPM Scan"):
        # Mocking real-time detection based on logic
        data = [
            {"Resource": "s3-finance-bucket", "Type": "S3", "Severity": "Critical", "Issue": "Public Read Access", "Remediation": "Block Public Access"},
            {"Resource": "ec2-web-server", "Type": "EC2", "Severity": "High", "Issue": "Port 22 Open", "Remediation": "Restrict SG to Trusted IP"}
        ]
        st.session_state['cspm_results'] = pd.DataFrame(data)
        st.dataframe(st.session_state['cspm_results'], use_container_width=True)

# --- TAB 4: CIEM SCAN ---
with tab_ciem:
    st.header("CIEM Mapping")
    if st.button("Run CIEM Scan"):
        # Mocking real-time identity issues
        data = [
            {"Resource": "admin-user-01", "Type": "IAM User", "Severity": "High", "Issue": "MFA Disabled", "Remediation": "Enable MFA"},
            {"Resource": "test-key-01", "Type": "Access Key", "Severity": "Medium", "Issue": "Key Rotation Overdue", "Remediation": "Rotate Access Key"}
        ]
        st.session_state['ciem_results'] = pd.DataFrame(data)
        st.table(st.session_state['ciem_results'])

# --- TAB 5: SCAN RESULTS & REMEDIATION ---
with tab_results:
    st.header("Consolidated Remediation Table")
    final_df = pd.concat([st.session_state['cspm_results'], st.session_state['ciem_results']], ignore_index=True)
    if not final_df.empty:
        st.dataframe(final_df, use_container_width=True, hide_index=True)
    else:
        st.info("No scan results found.")
