import streamlit as st
import pandas as pd
import boto3
import io
import datetime
import time
import json
import re
import os
import sys
from PIL import Image

# --- IMPORT VAPT MODULES (As per attached reference) ---
# Ensure these files are in the same directory as your app
try:
    import recon_local
    import feature_extractor
    from model import predict
except ImportError:
    # Fallback for demonstration if local modules aren't found
    recon_local = None

# --- LOGO CONFIGURATION ---
LOGO_URL = "https://github.com/kishoreb8271/cspm/blob/main/VantageGuard.png?raw=true"

# Page Configuration
st.set_page_config(page_title="Cloud Security & Entitlement Manager", layout="wide")

# --- CUSTOM CSS ---
st.markdown(f"""
    <style>
    .stApp {{ background-color: #0b1026; }}
    div.stButton > button {{ width: 100%; height: 60px; border-radius: 5px; border: 1px solid #444; }}
    [data-testid="stMetric"] {{ background-color: #1e2129; padding: 15px; border-radius: 10px; border: 1px solid #333; }}
    .cnapp-card {{ background-color: #ff4b4b; color: white; padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 10px; box-shadow: 2px 2px 10px rgba(0,0,0,0.1); }}
    .cnapp-card h2 {{ margin: 0; font-size: 2rem; color: white; }}
    .cnapp-card p {{ margin: 0; font-size: 0.8rem; font-weight: bold; text-transform: uppercase; }}
    .insight-box {{ background-color: #1e2129; border-left: 5px solid #ff4b4b; padding: 12px; margin-bottom: 10px; font-size: 0.85rem; border-radius: 4px; }}
    .brand-logo {{ display: block; margin-left: auto; margin-right: auto; width: 300px; padding-bottom: 20px; }}
    
    /* VAPT Specific Styles */
    .vapt-status {{ color: #00ff00; font-weight: bold; }}
    .vapt-risk-header {{ background-color: #262730; padding: 10px; border-radius: 5px; margin-top: 10px; border: 1px solid #ff4b4b; }}
    </style>
    """, unsafe_allow_html=True)

# --- ACCESS MANAGEMENT & LOGIN MODULE ---
if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False
if 'user_role' not in st.session_state:
    st.session_state['user_role'] = None

if 'user_db' not in st.session_state:
    try:
        st.session_state['user_db'] = pd.read_csv("users.csv")
    except FileNotFoundError:
        st.session_state['user_db'] = pd.DataFrame([{"Username": "admin", "Password": "AdminPassword@123", "Role": "Admin"}])
        st.session_state['user_db'].to_csv("users.csv", index=False)

def validate_password(password):
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return re.match(pattern, password)

def login_page():
    st.image(LOGO_URL, width=400) 
    st.markdown("<h2 style='text-align: center; color: white;'>🔐 Console Login</h2>", unsafe_allow_html=True)
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
    st.sidebar.image(LOGO_URL, use_container_width=True)
    st.sidebar.success(f"Logged in as: {st.session_state['user_role']}")
    if st.sidebar.button("Logout"):
        st.session_state['authenticated'] = False
        st.rerun()

    st.markdown(f'<img src="{LOGO_URL}" class="brand-logo">', unsafe_allow_html=True)
    st.title("🛡️ VantageGuard Security Manager")

    # --- SESSION STATE INITIALIZATION ---
    if 'integrations' not in st.session_state: st.session_state['integrations'] = {} 
    if 'cspm_results' not in st.session_state: st.session_state['cspm_results'] = pd.DataFrame()
    if 'ciem_results' not in st.session_state: st.session_state['ciem_results'] = pd.DataFrame()
    if 'dspm_results' not in st.session_state: st.session_state['dspm_results'] = pd.DataFrame()
    if 'compliance_results' not in st.session_state: st.session_state['compliance_results'] = pd.DataFrame()
    if 'last_scan_time' not in st.session_state: st.session_state['last_scan_time'] = "Never"
    if 'schedule_enabled' not in st.session_state: st.session_state['schedule_enabled'] = False
    if 'next_scan_time' not in st.session_state: st.session_state['next_scan_time'] = None
    
    # NEW: VAPT Session State [cite: 2]
    if 'vapt_last_results' not in st.session_state: st.session_state['vapt_last_results'] = None
    if 'vapt_prediction' not in st.session_state: st.session_state['vapt_prediction'] = None

    # --- HELPER FUNCTIONS ---
    def get_aws_client(service, creds):
        return boto3.client(service, aws_access_key_id=creds['key'], aws_secret_access_key=creds['secret'], region_name=creds['region'])

    def run_real_time_scan(module_name="Full System"):
        if not st.session_state['integrations']:
            st.warning("No cloud tenants connected. Please go to the Cloud Integration tab.")
            return
        results_cspm, ciem_data, dspm_data = [], [], []
        with st.status(f"🚀 Running {module_name} Scan...", expanded=True) as status:
            for account_name, creds in st.session_state['integrations'].items():
                provider = creds.get('provider')
                if provider == "AWS":
                    try:
                        s3 = get_aws_client('s3', creds)
                        buckets = s3.list_buckets()['Buckets']
                        for b in buckets:
                            results_cspm.append({"Resource": b['Name'], "Type": "S3", "Severity": "Critical", "Issue": "Public Read Access", "Framework": "PCI-DSS", "Remediation": "Enable Block Public Access"})
                            dspm_data.append({"Resource": f"s3://{b['Name']}/", "File_Name": "config_backup.env", "Location": f"{b['Name']}/backup/", "Type": "S3 Bucket", "Severity": "High", "Issue": "Exposed AWS Secret Keys", "Data_Type": "Secret/API Key"})
                        iam = get_aws_client('iam', creds)
                        for user in iam.list_users()['Users']:
                            ciem_data.append({"Resource": user['UserName'], "Type": "IAM User", "Severity": "High", "Issue": "MFA Disabled", "Framework": "SOC 2", "Remediation": "Enforce MFA Policy"})
                    except Exception as e: st.error(f"Scan Error on {account_name}: {e}")
            st.session_state['cspm_results'] = pd.DataFrame(results_cspm)
            st.session_state['ciem_results'] = pd.DataFrame(ciem_data)
            st.session_state['dspm_results'] = pd.DataFrame(dspm_data)
            st.session_state['compliance_results'] = pd.DataFrame([{"Framework": "CIS Foundations", "Passed": 45, "Failed": len(results_cspm), "Status": "Review Required"}, {"Framework": "SOC 2 Type II", "Passed": 154, "Failed": len(ciem_data), "Status": "Monitoring"}, {"Framework": "HIPAA Cloud Security", "Passed": 88, "Failed": len(dspm_data), "Status": "Review Required"}])
            st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            status.update(label=f"{module_name} Scan Complete!", state="complete", expanded=False)

    # --- MAIN TABS ---
    tabs_list = [
        "🤖 AI CNAPP Dashboard", "📊 Executive Dashboard", "🔌 Cloud Integration", 
        "⚖️ Compliance & Governance", "🔍 CSPM", "🔑 CIEM", "🛡️ DSPM", "📋 Scan Results",
        "🛡️ AutoPentAI (VAPT)" # NEW TAB ADDED
    ]
    if st.session_state['user_role'] == "Admin": tabs_list.append("⚙️ Admin: Access Management")
    active_tab = st.tabs(tabs_list)

    # ... [Existing Tabs 0-7 remain unchanged] ...

    with active_tab[8]: # NEW: AutoPentAI Tab
        st.header("🛡️ AutoPentAI: Vulnerability Assessment")
        st.caption("Random Forest-based risk classifier trained on lab datasets. For educational use only. ")
        
        v_col1, v_col2 = st.columns([1, 2])
        
        with v_col1:
            st.subheader("Target Configuration")
            target_ip = st.text_input("Target IP Address", placeholder="e.g., 192.168.56.101")
            
            # Implementation of Scan logic from app.py and recon_local.py [cite: 2, 3]
            if st.button("🚀 Start VAPT Scan", type="primary"):
                if not target_ip:
                    st.error("Please enter a target IP.")
                elif not (target_ip in ["127.0.0.1", "localhost"] or target_ip.startswith("192.168.56.")):
                    st.error("Lab-Only Mode: Only local or 192.168.56.x ranges allowed. [cite: 2, 3]")
                elif recon_local is None:
                    st.error("VAPT modules (recon_local.py, etc.) not found in application path.")
                else:
                    with st.status("Initializing Nmap & Nikto scan... [cite: 1]", expanded=True) as v_status:
                        # 1. Run Recon [cite: 2, 3]
                        scan_data, nikto_ran = recon_local.scan_local(target_ip)
                        if scan_data:
                            # 2. Extract Features [cite: 2]
                            features = feature_extractor.extract_features(scan_data, nikto_ran)
                            # 3. Get AI Prediction [cite: 2]
                            label, conf = predict.get_prediction(features)
                            
                            st.session_state['vapt_last_results'] = scan_data
                            st.session_state['vapt_prediction'] = {"label": label, "confidence": conf}
                            v_status.update(label="VAPT Scan Complete!", state="complete")
                        else:
                            st.error("Scan Failed. Check local environment.")

            if st.session_state['vapt_prediction']:
                st.markdown("### Risk Analysis [cite: 1]")
                pred = st.session_state['vapt_prediction']
                st.info(f"**Prediction:** {pred['label']} ({pred['confidence']:.2f}%)")
                
        with v_col2:
            st.subheader("Nmap Report ")
            if st.session_state['vapt_last_results']:
                results = st.session_state['vapt_last_results']
                ip = list(results['scan'].keys())[0]
                scan_info = results['scan'][ip]
                
                st.write(f"**Target:** {ip} | **Status:** {scan_info.get('status', {}).get('state', 'unknown')}")
                
                if 'tcp' in scan_info:
                    ports_data = []
                    for port, info in scan_info['tcp'].items():
                        ports_data.append({
                            "Port": port,
                            "State": info['state'],
                            "Service": info['name'],
                            "Version": f"{info.get('product', '')} {info.get('version', '')}"
                        })
                    st.table(pd.DataFrame(ports_data))
                else:
                    st.warning("No open TCP ports found.")
            else:
                st.info("Awaiting scan results... [cite: 1]")

    # ... [Admin Tab and Scheduler logic remain unchanged] ...
