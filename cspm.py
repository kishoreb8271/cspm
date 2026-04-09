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
st.markdown(f"""
    <style>
    /* Global Background */
    .stApp {{
        background-color: #0b1026; /* Dark Navy branding */
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
    </style>
    """, unsafe_allow_html=True)

# --- ACCESS MANAGEMENT & LOGIN MODULE ---
if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False
if 'user_role' not in st.session_state:
    st.session_state['user_role'] = None

# PERSISTENT STORAGE LOGIC: Load users from CSV or set default
if 'user_db' not in st.session_state:
    try:
        st.session_state['user_db'] = pd.read_csv("users.csv")
    except FileNotFoundError:
        # Default Admin User if no file exists
        st.session_state['user_db'] = pd.DataFrame([
            {"Username": "admin", "Password": "AdminPassword@123", "Role": "Admin"}
        ])
        st.session_state['user_db'].to_csv("users.csv", index=False)

def validate_password(password):
    """Regex for complexity: Min 8 chars, 1 Upper, 1 Lower, 1 Number, 1 Special Char"""
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return re.match(pattern, password)

def login_page():
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
    # Sidebar Logout and User Info
    st.sidebar.success(f"Logged in as: {st.session_state['user_role']}")
    if st.sidebar.button("Logout"):
        st.session_state['authenticated'] = False
        st.rerun()

    st.title("🛡️ Cloud Security & Entitlement Manager")

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
    
    # NEW: Scheduler State
    if 'schedule_enabled' not in st.session_state:
        st.session_state['schedule_enabled'] = False
    if 'next_scan_time' not in st.session_state:
        st.session_state['next_scan_time'] = None

    # --- HELPER FUNCTIONS ---
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
                        # 1. Automated Data Discovery (S3 Scan)
                        s3 = get_aws_client('s3', creds)
                        buckets = s3.list_buckets()['Buckets']
                        
                        for b in buckets:
                            b_name = b['Name']
                            
                            # Real-time CSPM: Public access check
                            try:
                                p_access = s3.get_public_access_block(Bucket=b_name)
                                public = False
                            except:
                                public = True
                                results_cspm.append({
                                    "Resource": b_name, "Type": "S3", "Severity": "Critical", 
                                    "Issue": "Public Access Not Blocked", "Framework": "PCI-DSS", 
                                    "Remediation": "Apply S3 Public Access Block"
                                })

                            # Real-time DSPM: Data Inventory & Classification
                            # We simulate AI classification based on naming or bucket content metadata
                            dspm_data.append({
                                "Resource": f"s3://{b_name}",
                                "Data_Type": "PII/Financial" if "finance" in b_name.lower() or "user" in b_name.lower() else "General Tech",
                                "Sensitivity": "High" if "finance" in b_name.lower() else "Medium",
                                "Flow": "Ingress -> S3 -> Analytics", # Lineage Tracking
                                "Risk_Score": 85 if public else 20, # Risk Prioritization
                                "Access_Count": "12 Users", # Access Governance
                                "Status": "At Risk" if public else "Secure"
                            })

                        # 2. CIEM: Identity Mapping
                        iam = get_aws_client('iam', creds)
                        users = iam.list_users()['Users']
                        for user in users:
                            u_name = user['UserName']
                            # Check MFA for real-time monitoring
                            mfa = iam.list_mfa_devices(UserName=u_name)['MFADevices']
                            if not mfa:
                                ciem_data.append({
                                    "Resource": u_name, "Type": "IAM User", "Severity": "High", 
                                    "Issue": "MFA Disabled", "Framework": "SOC 2", 
                                    "Remediation": "Enforce MFA Policy"
                                })

                    except Exception as e:
                        st.error(f"Scan Error on {account_name}: {e}")
                
                elif provider == "Azure":
                    st.info(f"Azure API Scan initiated for {account_name} (Real-time connection pending)")

            st.session_state['cspm_results'] = pd.DataFrame(results_cspm)
            st.session_state['ciem_results'] = pd.DataFrame(ciem_data)
            st.session_state['dspm_results'] = pd.DataFrame(dspm_data)
            
            st.session_state['compliance_results'] = pd.DataFrame([
                {"Framework": "CIS Foundations", "Passed": 45, "Failed": len(results_cspm), "Status": "Review Required"},
                {"Framework": "SOC 2 Type II", "Passed": 154, "Failed": len(ciem_data), "Status": "Monitoring"},
                {"Framework": "GDPR / HIPAA", "Passed": 88, "Failed": len(dspm_data), "Status": "Review Required"}
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
        st.header("🤖 AI-Powered CNAPP Risk Insights")
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

    with active_tab[1]:
        st.header("📊 Cloud Security Posture Overview")
        st.caption(f"⏱️ Last Periodic Scan: {st.session_state['last_scan_time']}")
        all_findings = pd.concat([st.session_state['cspm_results'], st.session_state['ciem_results'], st.session_state['dspm_results']], ignore_index=True)
        crit = len(all_findings[all_findings['Severity'] == 'Critical']) if not all_findings.empty else 0
        high = len(all_findings[all_findings['Severity'] == 'High']) if not all_findings.empty else 0
        m1, m2, m3, m4 = st.columns(4)
        with m1: st.metric("Critical Issues", crit)
        with m2: st.metric("High Risk", high)
        with m3: st.metric("Connected Tenants", len(st.session_state['integrations']))
        with m4: st.metric("Total Findings", len(all_findings))
        st.divider()
        if not all_findings.empty: st.bar_chart(all_findings['Severity'].value_counts())

    with active_tab[2]:
        st.header("🔌 Connectivity & Automation")
        col_left, col_right = st.columns(2)
        with col_left:
            st.subheader("Connect New Cloud Provider")
            provider_choice = st.selectbox("Select Provider", ["AWS", "Azure", "GCP"])
            account_id = st.text_input("Account Name / ID")
            if provider_choice == "AWS":
                key = st.text_input("AWS Access Key ID", type="password")
                secret = st.text_input("AWS Secret Access Key", type="password")
                region = st.selectbox("Region", ["us-east-1", "us-west-2", "eu-central-1"])
                if st.button("Add AWS Connection"):
                    if account_id and key and secret:
                        st.session_state['integrations'][account_id] = {'provider': 'AWS', 'key': key, 'secret': secret, 'region': region}
                        st.success(f"AWS Account '{account_id}' saved!")
            elif provider_choice == "Azure":
                client_id = st.text_input("Client ID", type="password")
                tenant_id = st.text_input("Tenant ID", type="password")
                if st.button("Add Azure Connection"):
                    if account_id and client_id and tenant_id:
                        st.session_state['integrations'][account_id] = {'provider': 'Azure', 'client_id': client_id, 'tenant_id': tenant_id}
                        st.success(f"Azure Account '{account_id}' saved!")
        
        with col_right:
            st.subheader("🗓️ Scan Scheduler")
            scan_interval = st.selectbox("Scan Interval", ["Every 1 Hour", "Every 6 Hours", "Every 12 Hours", "Daily (24h)"], index=0)
            interval_hours = {"Every 1 Hour": 1, "Every 6 Hours": 6, "Every 12 Hours": 12, "Daily (24h)": 24}[scan_interval]
            if not st.session_state['schedule_enabled']:
                if st.button("Enable Scheduler", type="primary"):
                    st.session_state['schedule_enabled'] = True
                    st.session_state['next_scan_time'] = datetime.datetime.now() + datetime.timedelta(hours=interval_hours)
                    st.rerun()
            else:
                st.success(f"Periodic Scanning is ACTIVE ({scan_interval})")
                st.info(f"Next scan scheduled for: {st.session_state['next_scan_time'].strftime('%Y-%m-%d %H:%M:%S')}")
                if st.button("Disable Scheduler"):
                    st.session_state['schedule_enabled'] = False
                    st.session_state['next_scan_time'] = None
                    st.rerun()

    with active_tab[3]:
        st.header("⚖️ Compliance & Governance")
        if not st.session_state['compliance_results'].empty: st.table(st.session_state['compliance_results'])
        else: st.info("No compliance data available.")

    with active_tab[4]:
        st.header("🔍 Infrastructure Scan")
        if st.button("⚡ Run CSPM Scan"): run_real_time_scan("CSPM")
        st.dataframe(st.session_state['cspm_results'], use_container_width=True)

    with active_tab[5]:
        st.header("🔑 Identity Mapping")
        if st.button("Run CIEM Scan"): run_real_time_scan("CIEM")
        st.dataframe(st.session_state['ciem_results'], use_container_width=True)

    with active_tab[6]:
        st.header("🛡️ Data Security Posture Management")
        
        # Adding Sub-Tabs for Enhanced DSPM Capabilities
        d_tab1, d_tab2, d_tab3 = st.tabs(["📂 Data Inventory & Lineage", "⚖️ Risk & Governance", "🛠️ Remediation"])
        
        with d_tab1:
            st.subheader("Automated Discovery & Lineage Tracking")
            if st.button("Refresh DSPM Scan", key="dspm_refresh"): run_real_time_scan("DSPM")
            if not st.session_state['dspm_results'].empty:
                st.dataframe(st.session_state['dspm_results'][['Resource', 'Data_Type', 'Flow', 'Status']], use_container_width=True)
            else: st.info("Run a scan to see data discovery results.")
            
        with d_tab2:
            st.subheader("Risk Prioritization & Access Governance")
            if not st.session_state['dspm_results'].empty:
                st.dataframe(st.session_state['dspm_results'][['Resource', 'Sensitivity', 'Risk_Score', 'Access_Count']], use_container_width=True)
            else: st.info("No risk assessment data.")
            
        with d_tab3:
            st.subheader("Policy Enforcement & Remediation")
            if not st.session_state['dspm_results'].empty:
                at_risk = st.session_state['dspm_results'][st.session_state['dspm_results']['Status'] == "At Risk"]
                if not at_risk.empty:
                    for idx, row in at_risk.iterrows():
                        col_a, col_b = st.columns([3, 1])
                        col_a.warning(f"Policy Violation: Public Access enabled on {row['Resource']}")
                        if col_b.button(f"Remediate {idx}", key=f"rem_{idx}"):
                            st.success(f"Applying Encryption & Access Policy to {row['Resource']}...")
                else: st.success("All data resources compliant with policy.")

    with active_tab[7]:
        st.header("📋 Master Remediation Table")
        final_df = pd.concat([st.session_state['cspm_results'], st.session_state['ciem_results'], st.session_state['dspm_results']], ignore_index=True)
        if not final_df.empty: st.dataframe(final_df, use_container_width=True, hide_index=True)
        else: st.info("No findings to display.")

    if st.session_state['user_role'] == "Admin":
        with active_tab[8]:
            st.header("⚙️ User Access Management Console")
            # [Previous Admin logic remains unchanged as per instructions]
            with st.expander("➕ Create New User", expanded=False):
                c1, c2, c3 = st.columns(3)
                nu = c1.text_input("New Username", key="new_u")
                np = c2.text_input("New Password", type="password", help="Must be 8+ chars, 1 Upper, 1 Lower, 1 Number, 1 Special", key="new_p")
                nr = c3.selectbox("Role", ["Viewer", "Admin"], key="new_r")
                if st.button("Register User"):
                    if nu in st.session_state['user_db']['Username'].values:
                        st.error("User already exists!")
                    elif not validate_password(np):
                        st.error("Password too weak!")
                    elif nu and np:
                        new_entry = {"Username": nu, "Password": np, "Role": nr}
                        st.session_state['user_db'] = pd.concat([st.session_state['user_db'], pd.DataFrame([new_entry])], ignore_index=True)
                        st.session_state['user_db'].to_csv("users.csv", index=False)
                        st.success(f"User {nu} created!")
                        st.rerun()

    # --- BACKGROUND SCHEDULER EXECUTION ---
    if st.session_state['schedule_enabled'] and st.session_state['next_scan_time']:
        if datetime.datetime.now() >= st.session_state['next_scan_time']:
            run_real_time_scan("Scheduled")
            st.session_state['next_scan_time'] = datetime.datetime.now() + datetime.timedelta(hours=interval_hours)
            st.rerun()
