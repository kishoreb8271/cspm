import streamlit as st
import pandas as pd
import boto3
import io
import datetime
import time
import json
import re
from PIL import Image

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
    </style>
    """, unsafe_allow_html=True)

# --- SESSION STATE INITIALIZATION ---
states = ['authenticated', 'user_role', 'integrations', 'cspm_results', 'ciem_results', 
          'dspm_results', 'compliance_results', 'last_scan_time', 'schedule_enabled', 'next_scan_time']
for s in states:
    if s not in st.session_state:
        if s == 'authenticated': st.session_state[s] = False
        elif s == 'integrations': st.session_state[s] = {}
        elif s in ['cspm_results', 'ciem_results', 'dspm_results', 'compliance_results']: st.session_state[s] = pd.DataFrame()
        elif s == 'last_scan_time': st.session_state[s] = "Never"
        else: st.session_state[s] = None

if 'user_db' not in st.session_state:
    st.session_state['user_db'] = pd.DataFrame([{"Username": "admin", "Password": "AdminPassword@123", "Role": "Admin"}])

# --- CORE LOGIC FUNCTIONS ---
def get_aws_client(service, creds):
    return boto3.client(service, aws_access_key_id=creds['key'], aws_secret_access_key=creds['secret'], region_name=creds['region'])

def scan_s3_content_realtime(s3_client, bucket_name, object_key):
    """Regex-based PII and Secret scanner for S3 objects."""
    patterns = {
        "PII (SSN)": r"\b\d{3}-\d{2}-\d{4}\b",
        "PII (Email)": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "Secret (AWS Key)": r"AKIA[0-9A-Z]{16}"
    }
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=object_key, Range='bytes=0-1024')
        content = response['Body'].read().decode('utf-8')
        findings = [label for label, regex in patterns.items() if re.search(regex, content)]
        return ", ".join(findings) if findings else None
    except: return None

def execute_remediation(account_name, resource_id, fix_type):
    """Live remediation engine to fix cloud misconfigurations."""
    creds = st.session_state['integrations'].get(account_name)
    if not creds: return False
    try:
        if fix_type == "Public S3":
            s3 = get_aws_client('s3', creds)
            s3.put_public_access_block(Bucket=resource_id, PublicAccessBlockConfiguration={'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': True, 'RestrictPublicBuckets': True})
        elif fix_type == "Open SSH":
            ec2 = get_aws_client('ec2', creds)
            ec2.revoke_security_group_ingress(GroupId=resource_id, IpProtocol='tcp', FromPort=22, ToPort=22, CidrIp='0.0.0.0/0')
        return True
    except Exception as e:
        st.error(f"Fix Failed: {e}")
        return False

def run_real_time_scan(module_name="Global"):
    if not st.session_state['integrations']:
        st.warning("No integrations found.")
        return

    res_cspm, res_ciem, res_dspm = [], [], []

    with st.status(f"🚀 Performing {module_name} Real-Time Scan...", expanded=True) as status:
        for account, creds in st.session_state['integrations'].items():
            if creds['provider'] == "AWS":
                try:
                    s3, iam, ec2 = get_aws_client('s3', creds), get_aws_client('iam', creds), get_aws_client('ec2', creds)
                    
                    # 1. EC2 & Network Scanning
                    st.write(f"🔍 Scanning EC2 Resources in {account}...")
                    sgs = ec2.describe_security_groups()['SecurityGroups']
                    for sg in sgs:
                        for perm in sg.get('IpPermissions', []):
                            if any(range.get('CidrIp') == '0.0.0.0/0' for range in perm.get('IpRanges', [])):
                                res_cspm.append({"Account": account, "Resource": sg['GroupId'], "Type": "Security Group", "Severity": "High", "Issue": "Inbound 0.0.0.0/0", "Fix_ID": "Open SSH", "Remediation": "Revoke Public Access"})

                    # 2. S3 & DSPM Regex Scanning
                    st.write(f"🔍 Scanning S3 Buckets in {account}...")
                    buckets = s3.list_buckets()['Buckets']
                    for b in buckets:
                        bn = b['Name']
                        objs = s3.list_objects_v2(Bucket=bn, MaxKeys=3).get('Contents', [])
                        for obj in objs:
                            found = scan_s3_content_realtime(s3, bn, obj['Key'])
                            if found:
                                res_dspm.append({"Account": account, "Provider": "AWS", "Resource": bn, "File_Name": obj['Key'], "Type": "S3 Object", "Severity": "Critical", "Issue": f"Exposed {found}", "Governance": "GDPR", "Remediation_Step": "Quarantine Object"})

                    # 3. IAM & CIEM Scanning
                    st.write(f"🔍 Scanning Identity Risks in {account}...")
                    users = iam.list_users()['Users']
                    for u in users:
                        un = u['UserName']
                        mfa = iam.list_mfa_devices(UserName=un)['MFADevices']
                        if not mfa:
                            res_ciem.append({"Account": account, "Resource": un, "Type": "IAM User", "Severity": "High", "Issue": "MFA Disabled", "Framework": "CIS", "Remediation": "Enforce MFA"})

                except Exception as e: st.error(f"Error on {account}: {e}")

        st.session_state['cspm_results'] = pd.DataFrame(res_cspm)
        st.session_state['ciem_results'] = pd.DataFrame(res_ciem)
        st.session_state['dspm_results'] = pd.DataFrame(res_dspm)
        st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%H:%M:%S")
        status.update(label="Global Scan Complete!", state="complete")

# --- UI LOGIC (SIMPLIFIED FOR MERGE) ---
def validate_password(password):
    return re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", password)

if not st.session_state['authenticated']:
    st.image(LOGO_URL, width=400)
    user = st.text_input("Username")
    pw = st.text_input("Password", type="password")
    if st.button("Login"):
        match = st.session_state['user_db'][(st.session_state['user_db']['Username'] == user) & (st.session_state['user_db']['Password'] == pw)]
        if not match.empty:
            st.session_state['authenticated'], st.session_state['user_role'] = True, match.iloc[0]['Role']
            st.rerun()
else:
    st.sidebar.image(LOGO_URL, use_container_width=True)
    if st.sidebar.button("Logout"): 
        st.session_state['authenticated'] = False
        st.rerun()

    st.markdown(f'<img src="{LOGO_URL}" class="brand-logo">', unsafe_allow_html=True)
    st.title("🛡️ VantageGuard Security Manager")

    tabs = st.tabs(["🤖 AI Dashboard", "🔌 Cloud Integration", "🔍 CSPM", "🔑 CIEM", "🛡️ DSPM", "🛠️ Remediation Console"])

    with tabs[1]: # Cloud Integration
        col_l, col_r = st.columns(2)
        with col_l:
            st.subheader("Connect AWS")
            acc = st.text_input("Account ID")
            ak = st.text_input("Access Key", type="password")
            sk = st.text_input("Secret Key", type="password")
            reg = st.selectbox("Region", ["us-east-1", "us-west-2"])
            if st.button("Add AWS"):
                st.session_state['integrations'][acc] = {'provider': 'AWS', 'key': ak, 'secret': sk, 'region': reg}
                st.success("Connected!")
        with col_r:
            st.subheader("Active Connections")
            st.write(list(st.session_state['integrations'].keys()))

    with tabs[2]: # CSPM
        if st.button("⚡ Run Infrastructure Scan"): run_real_time_scan("CSPM")
        st.dataframe(st.session_state['cspm_results'], use_container_width=True)

    with tabs[5]: # Remediation Console
        st.header("🛠️ Active Remediation Engine")
        all_issues = pd.concat([st.session_state['cspm_results'], st.session_state['ciem_results']], ignore_index=True)
        if not all_issues.empty:
            for i, row in all_issues.iterrows():
                with st.expander(f"Fix: {row['Issue']} on {row['Resource']}"):
                    st.write(f"Account: {row['Account']}")
                    if st.button(f"Execute Fix: {row.get('Fix_ID', 'Standard Remediation')}", key=f"remed_{i}"):
                        if execute_remediation(row['Account'], row['Resource'], row.get('Fix_ID')):
                            st.success("Fixed!")
        else: st.info("No issues pending remediation.")

    # Shared Logic: Scheduled Scans
    if st.session_state['schedule_enabled'] and st.session_state['next_scan_time']:
        if datetime.datetime.now() >= st.session_state['next_scan_time']:
            run_real_time_scan("Scheduled")
            st.rerun()
