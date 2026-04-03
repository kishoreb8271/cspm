import streamlit as st
import pandas as pd
import boto3
import datetime
import json
import re

# Page Configuration
st.set_page_config(page_title="Cloud Security & Entitlement Manager", layout="wide")

st.title("🛡️ Cloud Security & Entitlement Manager")

# Create the main tabs
tab_dash, tab_integ, tab_cspm, tab_ciem, tab_results = st.tabs([
    "📊 Executive Dashboard",
    "🔌 Cloud Integration", 
    "🔍 CSPM (Inventory & Scan)",
    "🔑 CIEM (Identity Mapping)",
    "📋 Scan Results & Remediation"
])

# --- HELPER: AWS AUTHENTICATION ---
def get_aws_client(service, access_key, secret_key, region):
    return boto3.client(
        service,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )

# --- HELPER: PLAIN TEXT SECRET IDENTIFIER ---
def scan_for_plain_text_secrets(data_str):
    # Regex for standard AWS Access Key IDs and generic high-entropy strings
    patterns = [
        r"(?i)aws_access_key_id[=: ]+[\"']?(AKIA[0-9A-Z]{16})[\"']?",
        r"(?i)aws_secret_access_key[=: ]+[\"']?([A-Za-z0-9/+=]{40})[\"']?"
    ]
    findings = []
    for pattern in patterns:
        if re.search(pattern, data_str):
            findings.append("Potential Plain-text AWS Credentials Found")
    return findings

# --- TAB 1: EXECUTIVE DASHBOARD ---
with tab_dash:
    st.header("Security Posture Overview")
    
    # Visualization Metrics (Mock values if scan hasn't run)
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Critical Issues", "15", "-2", delta_color="inverse")
    with col2:
        st.metric("High Risk", "123", "+5", delta_color="inverse")
    with col3:
        st.metric("Medium Risk", "355", "0")
    with col4:
        st.metric("Zombie Identities", "8", "+1", delta_color="inverse")

    st.divider()
    
    # Charting Simulation
    chart_data = pd.DataFrame({
        "Severity": ["Critical", "High", "Medium", "Low"],
        "Count": [15, 123, 355, 534]
    })
    st.subheader("Issue Distribution")
    st.bar_chart(chart_data, x="Severity", y="Count", color="#ff4b4b")

# --- TAB 2: CLOUD INTEGRATION ---
with tab_integ:
    st.header("Connect Cloud Providers")
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("AWS Configuration")
        aws_access_key = st.text_input("AWS Access Key ID", type="password", key="aws_key")
        aws_secret_key = st.text_input("AWS Secret Access Key", type="password", key="aws_secret")
        aws_region = st.selectbox("Region", ["us-east-1", "us-west-2", "eu-central-1"], key="aws_reg")
        
        # Secret Scanning Check
        if aws_access_key:
            findings = scan_for_plain_text_secrets(f"aws_access_key_id={aws_access_key}")
            if findings:
                st.warning("⚠️ Warning: Secret scanning detected potential plain-text keys in memory.")

        if st.button("Connect AWS"):
            try:
                sts = get_aws_client('sts', aws_access_key, aws_secret_key, aws_region)
                account = sts.get_caller_identity()['Account']
                st.success(f"Connected to AWS Account: {account}")
                st.session_state['aws_connected'] = True
                st.session_state['aws_creds'] = {'key': aws_access_key, 'secret': aws_secret_key, 'region': aws_region}
            except Exception as e:
                st.error(f"Connection failed: {e}")

# --- TAB 3: CSPM (INVENTORY) ---
with tab_cspm:
    st.header("CSPM: Resource Discovery")
    if st.button("Run CSPM Discovery Scan"):
        if 'aws_connected' in st.session_state:
            creds = st.session_state['aws_creds']
            inventory_data = []
            
            with st.spinner("Scanning for CSPM violations..."):
                # EC2 / S3 / Lambda Logic
                try:
                    ec2 = get_aws_client('ec2', creds['key'], creds['secret'], creds['region'])
                    instances = ec2.describe_instances()
                    for res in instances.get('Reservations', []):
                        for ins in res.get('Instances', []):
                            inventory_data.append({
                                "Resource": ins['InstanceId'], 
                                "Type": "EC2", 
                                "Issue": "Unrestricted SSH Access", 
                                "Remediation": "Modify Security Group rules to restrict Port 22."
                            })
                except Exception: pass
                
                try:
                    s3 = get_aws_client('s3', creds['key'], creds['secret'], creds['region'])
                    buckets = s3.list_buckets()
                    for b in buckets.get('Buckets', []):
                        inventory_data.append({
                            "Resource": b['Name'], 
                            "Type": "S3", 
                            "Issue": "Public Access Enabled", 
                            "Remediation": "Apply 'Block Public Access' policy."
                        })
                except Exception: pass

            st.session_state['cspm_results'] = pd.DataFrame(inventory_data)
            st.dataframe(st.session_state['cspm_results'], use_container_width=True)
        else:
            st.warning("Connect AWS first.")

# --- TAB 4: CIEM ---
with tab_ciem:
    st.header("CIEM: Identity & Entitlement Analysis")
    if st.button("Run Identity Scan"):
        if 'aws_connected' in st.session_state:
            creds = st.session_state['aws_creds']
            iam_data = []
            try:
                iam = get_aws_client('iam', creds['key'], creds['secret'], creds['region'])
                users = iam.list_users()
                for user in users.get('Users', []):
                    iam_data.append({
                        "Resource": user['UserName'], 
                        "Type": "IAM User", 
                        "Issue": "MFA Not Enabled", 
                        "Remediation": "Enforce MFA for this identity."
                    })
                st.session_state['ciem_results'] = pd.DataFrame(iam_data)
                st.table(st.session_state['ciem_results'])
            except Exception as e:
                st.error(f"CIEM Scan Failed: {e}")

# --- TAB 5: SCAN RESULTS & REMEDIATION ---
with tab_results:
    st.header("Consolidated Remediation Table")
    
    # Combine CSPM and CIEM results for the table
    all_results = []
    if 'cspm_results' in st.session_state:
        all_results.append(st.session_state['cspm_results'])
    if 'ciem_results' in st.session_state:
        all_results.append(st.session_state['ciem_results'])
        
    if all_results:
        final_df = pd.concat(all_results)
        st.subheader("Identified Issues & Fixes")
        st.dataframe(final_df, use_container_width=True, hide_index=True)
        
        st.divider()
        selected = st.selectbox("Generate Automation Script for:", final_df["Resource"])
        # Code generation logic...
        st.code(f"# Remediation script for {selected}\naws security-command-fix --resource {selected}", language="bash")
    else:
        st.info("Run CSPM or CIEM scans to populate this table.")
