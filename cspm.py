import streamlit as st
import pandas as pd
import boto3
import io
import datetime
import time
import json
import re
from PIL import Image

# Page Configuration
st.set_page_config(page_title="Cloud Security & Entitlement Manager", layout="wide")

# --- CUSTOM CSS ---
st.markdown("""
    <style>
    div.stButton > button { width: 100%; height: 60px; border-radius: 5px; border: 1px solid #444; }
    [data-testid="stMetric"] { background-color: #1e2129; padding: 15px; border-radius: 10px; border: 1px solid #333; }
    .cnapp-card { background-color: #ff4b4b; color: white; padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 10px; }
    .cnapp-card h2 { margin: 0; font-size: 2rem; color: white; }
    .cnapp-card p { margin: 0; font-size: 0.8rem; font-weight: bold; text-transform: uppercase; }
    .insight-box { background-color: #1e2129; border-left: 5px solid #ff4b4b; padding: 12px; margin-bottom: 10px; font-size: 0.85rem; border-radius: 4px; }
    </style>
    """, unsafe_allow_html=True)

# --- AUTHENTICATION ---
if 'authenticated' not in st.session_state: 
    st.session_state['authenticated'] = False
if 'user_role' not in st.session_state: 
    st.session_state['user_role'] = None
if 'user_db' not in st.session_state:
    st.session_state['user_db'] = pd.DataFrame([{"Username": "admin", "Password": "AdminPassword@123", "Role": "Admin"}])

def login_page():
    st.markdown("<h2 style='text-align: center;'>🔐 Console Login</h2>", unsafe_allow_html=True)
    with st.container():
        col1, col2, col3 = st.columns([1,2,1])
        with col2:
            user = st.text_input("Username")
            pw = st.text_input("Password", type="password")
            if st.button("Login"):
                db = st.session_state['user_db']
                match = db[(db['Username'] == user) & (db['Password'] == pw)]
                if not match.empty:
                    st.session_state['authenticated'] = True
                    st.session_state['user_role'] = match.iloc[0]['Role']
                    st.rerun()
                else: 
                    st.error("Invalid credentials")

if not st.session_state['authenticated']:
    login_page()
else:
    # --- APP LOGIC ---
    st.sidebar.success(f"User: {st.session_state['user_role']}")
    if st.sidebar.button("Logout"):
        st.session_state['authenticated'] = False
        st.rerun()

    # --- SESSION STATE INITIALIZATION (FIXED) ---
    keys = ['integrations', 'cspm_results', 'ciem_results', 'dspm_results', 'compliance_results']
    for key in keys:
        if key not in st.session_state:
            st.session_state[key] = {} if key == 'integrations' else pd.DataFrame()
    
    if 'last_scan_time' not in st.session_state:
        st.session_state['last_scan_time'] = "Never"

    def get_aws_client(service, creds):
        return boto3.client(service, aws_access_key_id=creds['key'], aws_secret_access_key=creds['secret'], region_name=creds['region'])

    def run_real_time_scan(module_name="Full System"):
        if not st.session_state['integrations']:
            st.warning("Please connect a Cloud Account first.")
            return

        res_cspm, res_ciem, res_dspm = [], [], []

        with st.status(f"🚀 Scanning {module_name}...", expanded=True) as status:
            for acc, creds in st.session_state['integrations'].items():
                if creds.get('provider') == "AWS":
                    try:
                        s3 = get_aws_client('s3', creds)
                        buckets = s3.list_buckets()['Buckets']
                        for b in buckets:
                            b_name = b['Name']
                            res_cspm.append({"Resource": b_name, "Type": "S3", "Severity": "High", "Issue": "Public Access Check Required", "Framework": "NIST", "Remediation": "Apply Bucket Policy"})
                            
                            # REAL-TIME DSPM CONTENT SCANNING
                            st.write(f"🔍 Inspecting objects in {b_name}...")
                            objs = s3.list_objects_v2(Bucket=b_name, MaxKeys=5)
                            if 'Contents' in objs:
                                for o in objs['Contents']:
                                    key = o['Key']
                                    raw = s3.get_object(Bucket=b_name, Key=key)['Body'].read().decode('utf-8', errors='ignore')
                                    
                                    # PII & Secret Detection Logic
                                    findings = []
                                    if re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', raw): 
                                        findings.append(("PII", "Email Exposure", "High"))
                                    if re.search(r'([^A-Z0-9])[A-Z0-9]{40}(?![A-Z0-9])', raw): 
                                        findings.append(("Secret", "AWS Secret Key Found", "Critical"))
                                    
                                    for d_type, issue, sev in findings:
                                        res_dspm.append({
                                            "Resource": f"s3://{b_name}/{key}", "Object": key, "Bucket": b_name,
                                            "Data_Class": d_type, "Issue": issue, "Severity": sev,
                                            "Lineage": f"Internet -> S3 Bucket -> {acc}", 
                                            "Governance": "GDPR / PCI-DSS", 
                                            "Remediation": f"Move {key} to private vault and rotate keys."
                                        })
                    except Exception as e: 
                        st.error(f"Scan Error: {e}")

            st.session_state['cspm_results'] = pd.DataFrame(res_cspm)
            st.session_state['dspm_results'] = pd.DataFrame(res_dspm)
            st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            status.update(label="Scan Complete!", state="complete")

    tabs = st.tabs(["🤖 Dashboard", "🔌 Integration", "🛡️ DSPM", "🔍 CSPM", "🔑 CIEM", "🛠️ Remediation"])

    with tabs[0]:
        st.header("Executive Security Overview")
        st.metric("Total Sensitive Data Findings", len(st.session_state['dspm_results']))

    with tabs[1]:
        st.header("Cloud Connectivity")
        with st.form("add_aws"):
            acc_id = st.text_input("Account Name")
            key = st.text_input("Access Key", type="password")
            sec = st.text_input("Secret Key", type="password")
            if st.form_submit_button("Connect AWS"):
                st.session_state['integrations'][acc_id] = {'provider': 'AWS', 'key': key, 'secret': sec, 'region': 'us-east-1'}
                st.success(f"Connected to {acc_id}")

    with tabs[2]:
        st.header("🛡️ DSPM Control Center")
        if st.button("🔍 Run Real-Time Discovery Scan"):
            run_real_time_scan("DSPM")
        
        if not st.session_state['dspm_results'].empty:
            df = st.session_state['dspm_results']
            d_tabs = st.tabs(["📁 Discovery", "🧬 Lineage", "🔥 Risk", "📜 Governance", "🛠️ Remediation Logs"])
            
            with d_tabs[0]: 
                st.subheader("Data Inventory")
                st.dataframe(df[['Resource', 'Data_Class', 'Object']], use_container_width=True)
            with d_tabs[1]: 
                st.subheader("Data Lineage & Flow")
                st.table(df[['Resource', 'Lineage']])
            with d_tabs[2]: 
                st.subheader("Risk Prioritization")
                st.dataframe(df[['Resource', 'Issue', 'Severity']], use_container_width=True)
            with d_tabs[3]: 
                st.subheader("Governance Mapping")
                st.dataframe(df[['Resource', 'Governance']], use_container_width=True)
            with d_tabs[4]:
                st.subheader("Actionable Remediation")
                for _, r in df.iterrows():
                    st.warning(f"**Target:** {r['Resource']}\n\n**Action:** {r['Remediation']}")
        else:
            st.info("No data discovered yet. Connect an account and run a scan.")

    with tabs[3]:
        st.header("CSPM Findings")
        st.dataframe(st.session_state['cspm_results'])

    with tabs[5]:
        st.header("Master Remediation Table")
        all_res = pd.concat([st.session_state['cspm_results'], st.session_state['dspm_results']], ignore_index=True)
        st.dataframe(all_res, use_container_width=True)
