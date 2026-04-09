import streamlit as st
import pandas as pd
import boto3
import datetime
import re

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
    .cnapp-card {{ background-color: #ff4b4b; color: white; padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 10px; }}
    .cnapp-card h2 {{ margin: 0; font-size: 2rem; color: white; }}
    .cnapp-card p {{ margin: 0; font-size: 0.8rem; font-weight: bold; text-transform: uppercase; }}
    .insight-box {{ background-color: #1e2129; border-left: 5px solid #ff4b4b; padding: 12px; margin-bottom: 10px; font-size: 0.85rem; border-radius: 4px; }}
    .brand-logo {{ display: block; margin-left: auto; margin-right: auto; width: 300px; padding-bottom: 20px; }}
    </style>
    """, unsafe_allow_html=True)

# --- SESSION STATE INITIALIZATION ---
if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False
if 'user_role' not in st.session_state:
    st.session_state['user_role'] = None
if 'user_db' not in st.session_state:
    st.session_state['user_db'] = pd.DataFrame([{"Username": "admin", "Password": "AdminPassword@123", "Role": "Admin"}])
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

# --- HELPER FUNCTIONS ---
def get_aws_client(service, creds):
    return boto3.client(
        service,
        aws_access_key_id=creds['key'],
        aws_secret_access_key=creds['secret'],
        region_name=creds['region']
    )

def scan_content_for_pii(content):
    findings = []
    patterns = {
        "PII (Email/SSN)": r"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b|\b\d{3}-\d{2}-\d{4}\b)",
        "PCI (Credit Card)": r"\b(?:\d[ -]*?){13,16}\b",
        "Secret/API Key": r"(?:key|secret|password|token)[-|_| ]*[:|=][-|_| ]*([A-Za-z0-9/+=]{16,})"
    }
    for label, pattern in patterns.items():
        if re.search(pattern, content, re.IGNORECASE):
            findings.append(label)
    return findings

def run_real_time_scan(module_name="Full System"):
    if not st.session_state['integrations']:
        st.warning("No cloud tenants connected. Please go to the Cloud Integration tab.")
        return

    results_cspm, ciem_data, dspm_data = [], [], []

    with st.status(f"🚀 Running {module_name} Scan...", expanded=True) as status:
        for account_name, creds in st.session_state['integrations'].items():
            if creds.get('provider') == "AWS":
                try:
                    s3 = get_aws_client('s3', creds)
                    buckets = s3.list_buckets()['Buckets']
                    for b in buckets:
                        b_name = b['Name']
                        st.write(f"📂 Scanning Bucket: {b_name}")
                        
                        # CSPM Check
                        try:
                            p_access = s3.get_public_access_block(Bucket=b_name)
                            is_public = not all(p_access['PublicAccessBlockConfiguration'].values())
                        except:
                            is_public = True
                        
                        if is_public:
                            results_cspm.append({
                                "Resource": b_name, "Type": "S3", "Severity": "Critical", 
                                "Issue": "Public Access Enabled", "Framework": "PCI-DSS", 
                                "Remediation": "Enable Block Public Access"
                            })

                        # DSPM Check
                        objects = s3.list_objects_v2(Bucket=b_name, MaxKeys=10)
                        if 'Contents' in objects:
                            for obj in objects['Contents']:
                                if obj['Key'].endswith(('.txt', '.csv', '.json', '.env')):
                                    file_obj = s3.get_object(Bucket=b_name, Key=obj['Key'])
                                    body = file_obj['Body'].read().decode('utf-8', errors='ignore')
                                    found = scan_content_for_pii(body)
                                    for f in found:
                                        dspm_data.append({"Resource": b_name, "File_Name": obj['Key'], "Severity": "High", "Issue": f"Sensitive {f} Found"})

                    # CIEM Check
                    iam = get_aws_client('iam', creds)
                    for user in iam.list_users()['Users']:
                        ciem_data.append({"Resource": user['UserName'], "Type": "IAM User", "Severity": "Medium", "Issue": "MFA Status Unverified"})

                except Exception as e:
                    st.error(f"Error on {account_name}: {e}")

        st.session_state['cspm_results'] = pd.DataFrame(results_cspm)
        st.session_state['ciem_results'] = pd.DataFrame(ciem_data)
        st.session_state['dspm_results'] = pd.DataFrame(dspm_data)
        st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status.update(label="Scan Complete!", state="complete", expanded=False)

# --- APP LAYOUT ---
if not st.session_state['authenticated']:
    st.image(LOGO_URL, width=400)
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
    st.sidebar.image(LOGO_URL, use_container_width=True)
    if st.sidebar.button("Logout"):
        st.session_state['authenticated'] = False
        st.rerun()

    tabs = st.tabs(["🤖 AI Dashboard", "🔌 Integration", "🔍 CSPM", "🔑 CIEM", "🛡️ DSPM"])

    with tabs[1]:
        st.header("Connect AWS Account")
        acc_name = st.text_input("Account Name")
        key_id = st.text_input("Access Key ID")
        secret_key = st.text_input("Secret Access Key", type="password")
        reg = st.selectbox("Region", ["us-east-1", "us-west-2"])
        if st.button("Add AWS Connection"):
            st.session_state['integrations'][acc_name] = {'provider': 'AWS', 'key': key_id, 'secret': secret_key, 'region': reg}
            st.success("Connection Saved!")

    with tabs[2]:
        if st.button("⚡ Run CSPM Scan"): run_real_time_scan("CSPM")
        st.dataframe(st.session_state['cspm_results'], use_container_width=True)

    with tabs[3]:
        if st.button("Run CIEM Scan"): run_real_time_scan("CIEM")
        st.dataframe(st.session_state['ciem_results'], use_container_width=True)

    with tabs[4]:
        st.header("DSPM Real-Time Discovery")
        rt_toggle = st.toggle("Enable Real-Time Data Discovery")
        if rt_toggle:
            run_real_time_scan("DSPM")
        st.dataframe(st.session_state['dspm_results'], use_container_width=True)
