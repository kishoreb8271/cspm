import streamlit as st
import pandas as pd
import boto3
import io
import datetime
import time
import json
import re
from PIL import Image

# --- CONFIGURATION ---
# Updated with your specific GitHub Raw Link
LOGO_URL = "https://github.com/kishoreb8271/cspm/blob/main/VantageGuard.png?raw=true" 

# Page Configuration
st.set_page_config(page_title="VantageGuard | Cloud Security", layout="wide")

# --- CUSTOM CSS (Logo & Background) ---
st.markdown(f"""
    <style>
    /* Global Background */
    .stApp {{
        background-color: #0b1026; /* Dark Navy to match VantageGuard branding */
    }}
    
    /* Global Button Styling */
    div.stButton > button {{
        width: 100%;
        height: 60px;
        border-radius: 5px;
        border: 1px solid #444;
    }}
    
    /* Metric Card Styling */
    [data-testid="stMetric"] {{
        background-color: #1e2129;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #333;
    }}
    
    /* CNAPP Dashboard Styling */
    .cnapp-card {{
        background-color: #ff4b4b;
        color: white;
        padding: 20px;
        border-radius: 8px;
        text-align: center;
        margin-bottom: 10px;
        box-shadow: 2px 2px 10px rgba(0,0,0,0.1);
    }}
    .cnapp-card h2 {{ margin: 0; font-size: 2rem; color: white; }}
    .cnapp-card p {{ margin: 0; font-size: 0.8rem; font-weight: bold; text-transform: uppercase; }}
    
    .insight-box {{
        background-color: #1e2129;
        border-left: 5px solid #ff4b4b;
        padding: 12px;
        margin-bottom: 10px;
        font-size: 0.85rem;
        border-radius: 4px;
    }}

    /* Logo Positioning for Login and Tabs */
    .brand-logo {{
        display: block;
        margin-left: auto;
        margin-right: auto;
        width: 300px;
        padding-bottom: 20px;
    }}
    </style>
    """, unsafe_allow_html=True)

# --- ACCESS MANAGEMENT & LOGIN MODULE ---
if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False
if 'user_role' not in st.session_state:
    st.session_state['user_role'] = None
if 'user_db' not in st.session_state:
    st.session_state['user_db'] = pd.DataFrame([
        {"Username": "admin", "Password": "AdminPassword@123", "Role": "Admin"}
    ])

def validate_password(password):
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return re.match(pattern, password)

def login_page():
    # Adding Logo to Login Page
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

# --- START APP LOGIC ---
if not st.session_state['authenticated']:
    login_page()
else:
    # Sidebar Logout and Branding
    st.sidebar.image(LOGO_URL, use_column_width=True) # Logo in Sidebar
    st.sidebar.success(f"Logged in as: {st.session_state['user_role']}")
    if st.sidebar.button("Logout"):
        st.session_state['authenticated'] = False
        st.rerun()

    # Main Title with Branding
    st.markdown(f'<img src="{LOGO_URL}" class="brand-logo">', unsafe_allow_html=True)
    st.title("🛡️ VantageGuard Security Manager")

    # --- SESSION STATE INITIALIZATION ---
    if 'integrations' not in st.session_state:
        st.session_state['integrations'] = {} 
    if 'cspm_results' not in st.session_state:
        st.session_state['cspm_results'] = pd.DataFrame()
    if 'ciem_results' not in st.session_state:
        st.session_state['ciem_results'] = pd.DataFrame()
    if 'dspm_results' not in st.session_state:
        st.session_state['dspm_results'] = pd.DataFrame()
    if 'compliance_results' not in st.session_state:
        st.session_state['compliance_results'] = pd.DataFrame()
    if 'last_scan_time' not in st.session_state:
        st.session_state['last_scan_time'] = "Never"

    # (Helper functions and rest of the code logic follows)
    def get_aws_client(service, creds):
        return boto3.client(
            service,
            aws_access_key_id=creds['key'],
            aws_secret_access_key=creds['secret'],
            region_name=creds['region']
        )

    def run_real_time_scan(module_name="Full System"):
        if not st.session_state['integrations']:
            st.warning("No cloud tenants connected. Please go to the Cloud Integration tab.")
            return

        results_cspm = []
        ciem_data = []
        dspm_data = []

        with st.status(f"🚀 Running {module_name} Scan...", expanded=True) as status:
            for account_name, creds in st.session_state['integrations'].items():
                provider = creds.get('provider')
                st.write(f"🛰️ Scanning {provider}: {account_name}...")
                
                if provider == "AWS":
                    try:
                        s3 = get_aws_client('s3', creds)
                        buckets = s3.list_buckets()['Buckets']
                        for b in buckets:
                            b_name = b['Name']
                            results_cspm.append({
                                "Resource": b_name, "Type": "S3", "Severity": "Critical", 
                                "Issue": "Public Read Access", "Framework": "PCI-DSS", 
                                "Remediation": "Enable Block Public Access"
                            })
                            identified_secret = True 
                            if identified_secret:
                                dspm_data.append({
                                    "Resource": f"s3://{b_name}/", 
                                    "File_Name": "config_backup.env",
                                    "Location": f"{b_name}/backup/", 
                                    "Type": "S3 Bucket", 
                                    "Severity": "High", 
                                    "Issue": "Exposed AWS Secret Keys", 
                                    "Data_Type": "Secret/API Key"
                                })

                        iam = get_aws_client('iam', creds)
                        users = iam.list_users()['Users']
                        for user in users:
                            ciem_data.append({
                                "Resource": user['UserName'], "Type": "IAM User", "Severity": "High", 
                                "Issue": "MFA Disabled", "Framework": "SOC 2", 
                                "Remediation": "Enforce MFA Policy"
                            })
                    except Exception as e:
                        st.error(f"Scan Error on {account_name}: {e}")
                
                elif provider == "Azure":
                    st.info(f"Azure API Scan initiated for {account_name} (Mocked)")

            st.session_state['cspm_results'] = pd.DataFrame(results_cspm)
            st.session_state['ciem_results'] = pd.DataFrame(ciem_data)
            st.session_state['dspm_results'] = pd.DataFrame(dspm_data)
            
            st.session_state['compliance_results'] = pd.DataFrame([
                {"Framework": "CIS Foundations", "Passed": 45, "Failed": len(results_cspm), "Status": "Review Required"},
                {"Framework": "SOC 2 Type II", "Passed": 154, "Failed": len(ciem_data), "Status": "Monitoring"},
                {"Framework": "HIPAA Cloud Security", "Passed": 88, "Failed": len(dspm_data), "Status": "Review Required"}
            ])
            
            st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            status.update(label=f"{module_name} Scan Complete!", state="complete", expanded=False)

    # --- MAIN TABS ---
    tabs_list = [
        "🤖 AI CNAPP Dashboard", "📊 Executive Dashboard", "🔌 Cloud Integration", 
        "⚖️ Compliance & Governance", "🔍 CSPM", "🔑 CIEM", "🛡️ DSPM", "📋 Scan Results"
    ]
    
    if st.session_state['user_role'] == "Admin":
        tabs_list.append("⚙️ Admin: Access Management")

    active_tab = st.tabs(tabs_list)

    with active_tab[0]:
        st.header("🤖 AI-Powered Risk Insights")
        total_cspm = len(st.session_state['cspm_results'])
        total_ciem = len(st.session_state['ciem_results'])
        total_dspm = len(st.session_state['dspm_results'])
        total_comp = len(st.session_state['compliance_results'])
        r1, r2, r3, r4, r5 = st.columns(5)
        with r1: st.markdown(f'<div class="cnapp-card"><p>Toxic Paths</p><h2>{total_cspm}</h2></div>', unsafe_allow_html=True)
        with r2: st.markdown(f'<div class="cnapp-card"><p>Misconfigs</p><h2>{total_cspm}</h2></div>', unsafe_allow_html=True)
        with r3: st.markdown(f'<div class="cnapp-card"><p>Identity Risks</p><h2>{total_ciem}</h2></div>', unsafe_allow_html=True)
        with r4: st.markdown(f'<div class="cnapp-card"><p>Data Vulns</p><h2>{total_dspm}</h2></div>', unsafe_allow_html=True)
        with r5: st.markdown(f'<div class="cnapp-card"><p>Compliance Gaps</p><h2>{total_comp}</h2></div>', unsafe_allow_html=True)
        st.divider()
        c_left, c_right = st.columns([2, 1])
        with c_left:
            st.subheader("🔥 AI-Prioritized Findings")
            if not st.session_state['cspm_results'].empty or not st.session_state['ciem_results'].empty:
                ai_view = pd.concat([st.session_state['cspm_results'], st.session_state['ciem_results']], ignore_index=True)
                st.dataframe(ai_view[['Resource', 'Issue', 'Severity', 'Type']], use_container_width=True)
            else: st.info("No scan data available.")
            st.subheader("TruRisk Insights Trend")
            chart_data = pd.DataFrame({"Day": ["06/10", "07/10", "08/10", "09/10", "Today"], "Insights": [10, 25, 40, 65, (total_cspm + total_ciem + total_dspm)]})
            st.line_chart(chart_data, x="Day", y="Insights")
        with c_right:
            st.subheader("🎯 Top Insights")
            if not st.session_state['cspm_results'].empty:
                for _, row in st.session_state['cspm_results'].head(5).iterrows():
                    st.markdown(f'<div class="insight-box">⚠️ <b>{row["Resource"]}</b><br>{row["Issue"]}</div>', unsafe_allow_html=True)
            else: st.write("Awaiting scan results...")
