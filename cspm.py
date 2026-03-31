import streamlit as st
import pandas as pd
import boto3
import datetime
import time

# Page Configuration
st.set_page_config(page_title="Cloud Security & Entitlement Manager", layout="wide")

# --- CUSTOM CSS ---
st.markdown("""
    <style>
    div.stButton > button { width: 100%; height: 80px; border-radius: 5px; border: 1px solid #444; }
    .stMetric { background-color: #1e2129; padding: 15px; border-radius: 10px; border: 1px solid #333; }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Cloud Security & Entitlement Manager")

# Initialize session state
for key in ['cspm_results', 'ciem_results', 'dspm_vulnerability_results', 'compliance_results']:
    if key not in st.session_state: st.session_state[key] = pd.DataFrame()
if 'last_scan_time' not in st.session_state: st.session_state['last_scan_time'] = "Never"
if 'aws_connected' not in st.session_state: st.session_state['aws_connected'] = False

# --- REAL-TIME AWS SCAN LOGIC ---
def fetch_real_aws_data():
    """Fetches real data using the credentials stored in session state"""
    if not st.session_state.get('aws_creds'):
        st.error("No AWS Credentials found. Please connect in the 'Cloud Integration' tab.")
        return
    
    creds = st.session_state['aws_creds']
    
    # 1. CSPM Scan: S3 Public Access Check
    cspm_list = []
    try:
        s3 = boto3.client('s3', **creds)
        buckets = s3.list_buckets()['Buckets']
        for b in buckets:
            name = b['Name']
            try:
                # Check for public access block
                status = s3.get_public_access_block(Bucket=name)
                is_public = not all(status['PublicAccessBlockConfiguration'].values())
            except:
                is_public = True # Assume public if config is missing
            
            if is_public:
                cspm_list.append({
                    "Resource": name, "Type": "S3", "Severity": "High", 
                    "Issue": "Public Access Potential", "Framework": "CIS", 
                    "Remediation": "Enable Block Public Access"
                })
    except Exception as e:
        st.warning(f"S3 Scan Error: {e}")

    # 2. CIEM Scan: IAM MFA Check
    ciem_list = []
    try:
        iam = boto3.client('iam', **creds)
        users = iam.list_users()['Users']
        for u in users:
            mfa = iam.list_mfa_devices(UserName=u['UserName'])['MfaDevices']
            if not mfa:
                ciem_list.append({
                    "Resource": u['UserName'], "Type": "IAM User", "Severity": "Medium", 
                    "Issue": "MFA Disabled", "Framework": "Best Practice", 
                    "Remediation": "Enable MFA"
                })
    except Exception as e:
        st.warning(f"IAM Scan Error: {e}")

    # Update State
    st.session_state['cspm_results'] = pd.DataFrame(cspm_list)
    st.session_state['ciem_results'] = pd.DataFrame(ciem_list)
    st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def run_automated_scan(module_name="Full System"):
    with st.status(f"Scanning {module_name}...", expanded=True) as status:
        if not st.session_state['aws_connected']:
            st.error("Please connect your AWS account first.")
            status.update(label="Scan Failed", state="error")
            return
            
        st.write("🛰️ Querying AWS APIs for real-time inventory...")
        fetch_real_aws_data()
        time.sleep(1)
        status.update(label=f"{module_name} Scan Complete!", state="complete", expanded=False)

# Main Tabs
active_tab = st.tabs(["📊 Dashboard", "🔌 Cloud Integration", "🔍 CSPM", "🔑 CIEM", "📋 Results"])

# --- TAB: CLOUD INTEGRATION (CRITICAL FOR REAL DATA) ---
with active_tab[1]:
    st.header("Connectivity")
    aws_key = st.text_input("AWS Access Key ID", type="password")
    aws_sec = st.text_input("AWS Secret Access Key", type="password")
    aws_reg = st.selectbox("Region", ["us-east-1", "us-west-2"])
    
    if st.button("Connect AWS"):
        # Store creds for the session
        st.session_state['aws_creds'] = {
            'aws_access_key_id': aws_key,
            'aws_secret_access_key': aws_sec,
            'region_name': aws_reg
        }
        st.session_state['aws_connected'] = True
        st.success("Credentials Stored! You can now run real scans.")

# --- TAB: DASHBOARD ---
with active_tab[0]:
    st.header("Executive Overview")
    st.caption(f"Last Scan: {st.session_state['last_scan_time']}")
    
    c1, c2 = st.columns(2)
    with c1: st.metric("Live S3 Risks", len(st.session_state['cspm_results']))
    with c2: st.metric("Users without MFA", len(st.session_state['ciem_results']))
    
    if not st.session_state['cspm_results'].empty:
        st.bar_chart(st.session_state['cspm_results']['Resource'])

# --- TAB: CSPM ---
with active_tab[2]:
    if st.button("Run Real Infrastructure Scan"):
        run_automated_scan("CSPM")
    st.dataframe(st.session_state['cspm_results'], use_container_width=True)

# --- TAB: CIEM ---
with active_tab[3]:
    if st.button("Run Real Identity Scan"):
        run_automated_scan("CIEM")
    st.dataframe(st.session_state['ciem_results'], use_container_width=True)

# --- TAB: RESULTS ---
with active_tab[4]:
    st.header("Remediation Plan")
    combined = pd.concat([st.session_state['cspm_results'], st.session_state['ciem_results']])
    st.dataframe(combined, use_container_width=True)
