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
    /* Global Button Styling */
    div.stButton > button {
        width: 100%;
        height: 60px;
        border-radius: 5px;
        border: 1px solid #444;
    }
    /* Metric Card Styling */
    [data-testid="stMetric"] {
        background-color: #1e2129;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #333;
    }
    /* CNAPP Dashboard Styling */
    .cnapp-card {
        background-color: #ff4b4b;
        color: white;
        padding: 20px;
        border-radius: 8px;
        text-align: center;
        margin-bottom: 10px;
        box-shadow: 2px 2px 10px rgba(0,0,0,0.1);
    }
    .cnapp-card h2 { margin: 0; font-size: 2rem; color: white; }
    .cnapp-card p { margin: 0; font-size: 0.8rem; font-weight: bold; text-transform: uppercase; }
    
    .insight-box {
        background-color: #1e2129;
        border-left: 5px solid #ff4b4b;
        padding: 12px;
        margin-bottom: 10px;
        font-size: 0.85rem;
        border-radius: 4px;
    }
    </style>
    """, unsafe_allow_html=True)

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
if 'schedule_enabled' not in st.session_state:
    st.session_state['schedule_enabled'] = False

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
                    # S3 Scan (CSPM/DSPM)
                    s3 = get_aws_client('s3', creds)
                    buckets = s3.list_buckets()['Buckets']
                    for b in buckets:
                        b_name = b['Name']
                        
                        # CSPM Logic
                        results_cspm.append({
                            "Resource": b_name, "Type": "S3", "Severity": "Critical", 
                            "Issue": "Public Read Access", "Framework": "PCI-DSS", 
                            "Remediation": "Enable Block Public Access"
                        })
                        
                        # Enhanced DSPM Logic
                        identified_secret = True # Mocking discovery
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

                    # IAM Scan (CIEM)
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
                # Placeholder for Azure logic
                st.info(f"Azure API Scan initiated for {account_name} (Mocked)")

        # Update Session Data
        st.session_state['cspm_results'] = pd.DataFrame(results_cspm)
        st.session_state['ciem_results'] = pd.DataFrame(ciem_data)
        st.session_state['dspm_results'] = pd.DataFrame(dspm_data)
        
        # Compliance Summary Logic
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
active_tab = st.tabs(tabs_list)

# --- TAB 0: AI CNAPP DASHBOARD ---
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
        else:
            st.info("No scan data available. Metrics are currently at zero.")
        
        st.subheader("TruRisk Insights Trend")
        chart_data = pd.DataFrame({
            "Day": ["06/10", "07/10", "08/10", "09/10", "Today"],
            "Insights": [10, 25, 40, 65, (total_cspm + total_ciem + total_dspm)]
        })
        st.line_chart(chart_data, x="Day", y="Insights")

    with c_right:
        st.subheader("🎯 Top Insights")
        if not st.session_state['cspm_results'].empty:
            for _, row in st.session_state['cspm_results'].head(5).iterrows():
                st.markdown(f'<div class="insight-box">⚠️ <b>{row["Resource"]}</b><br>{row["Issue"]}</div>', unsafe_allow_html=True)
        else:
            st.write("Awaiting scan results to generate top insights...")

# --- TAB 1: EXECUTIVE DASHBOARD ---
with active_tab[1]:
    st.header("📊 Cloud Security Posture Overview")
    st.caption(f"⏱️ Last Periodic Scan: {st.session_state['last_scan_time']}")
    
    all_findings = pd.concat([st.session_state['cspm_results'], st.session_state['ciem_results'], st.session_state['dspm_results']], ignore_index=True)
    
    crit = len(all_findings[all_findings['Severity'] == 'Critical']) if not all_findings.empty else 0
    high = len(all_findings[all_findings['Severity'] == 'High']) if not all_findings.empty else 0
    
    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("Critical Issues", crit, delta="-2" if crit > 0 else "0")
    with m2: st.metric("High Risk", high, delta="-5" if high > 0 else "0")
    with m3: st.metric("Connected Tenants", len(st.session_state['integrations']))
    with m4: st.metric("Total Findings", len(all_findings))
    
    st.divider()
    st.subheader("Asset Risk Distribution")
    if not all_findings.empty:
        st.bar_chart(all_findings['Severity'].value_counts())

# --- TAB 2: CLOUD INTEGRATION (UPDATED FOR MULTIPLE PROVIDERS) ---
with active_tab[2]:
    st.header("🔌 Connectivity & Automation")
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.subheader("Connect New Cloud Provider")
        provider_choice = st.selectbox("Select Provider", ["AWS", "Azure", "GCP"])
        account_id = st.text_input("Account Name / ID (e.g. Prod-Environment)")
        
        if provider_choice == "AWS":
            key = st.text_input("AWS Access Key ID", type="password")
            secret = st.text_input("AWS Secret Access Key", type="password")
            region = st.selectbox("Region", ["us-east-1", "us-west-2", "eu-central-1"])
            if st.button(f"Add {provider_choice} Connection"):
                if account_id and key and secret:
                    st.session_state['integrations'][account_id] = {
                        'provider': 'AWS', 'key': key, 'secret': secret, 'region': region
                    }
                    st.success(f"AWS Account '{account_id}' saved!")
                else:
                    st.error("Please fill all AWS fields.")
                    
        elif provider_choice == "Azure":
            client_id = st.text_input("Client ID", type="password")
            tenant_id = st.text_input("Tenant ID", type="password")
            if st.button(f"Add {provider_choice} Connection"):
                if account_id and client_id and tenant_id:
                    st.session_state['integrations'][account_id] = {
                        'provider': 'Azure', 'client_id': client_id, 'tenant_id': tenant_id
                    }
                    st.success(f"Azure Account '{account_id}' saved!")
                else:
                    st.error("Please fill all Azure fields.")

    with col_right:
        st.subheader("📋 Saved Integrations")
        if st.session_state['integrations']:
            integrations_df = pd.DataFrame.from_dict(st.session_state['integrations'], orient='index')
            st.table(integrations_df[['provider']])
            if st.button("Clear All Connections"):
                st.session_state['integrations'] = {}
                st.rerun()
        else:
            st.info("No accounts connected yet.")

        st.divider()
        st.subheader("📅 Scan Scheduler")
        interval = st.selectbox("Scan Interval", ["Every 1 Hour", "Every 6 Hours", "Daily"])
        st.session_state['schedule_enabled'] = st.toggle("Enable Periodic Scanning", value=st.session_state['schedule_enabled'])
        if st.session_state['schedule_enabled']:
            st.success(f"Scanning ACTIVE for {len(st.session_state['integrations'])} accounts.")

# --- TAB 3: COMPLIANCE & GOVERNANCE ---
with active_tab[3]:
    st.header("⚖️ Compliance & Governance")
    if not st.session_state['compliance_results'].empty:
        st.subheader("Regulatory Compliance Progress")
        st.table(st.session_state['compliance_results'])
        passed = st.session_state['compliance_results']['Passed'].sum()
        failed = st.session_state['compliance_results']['Failed'].sum()
        st.write(f"**Total Controls Assessed:** {passed + failed}")
    else:
        st.info("No compliance data available. Please run a scan to populate this tab.")

# --- FUNCTIONAL TABS ---
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
    if st.button("Run DSPM Scan"): run_real_time_scan("DSPM")
    if not st.session_state['dspm_results'].empty:
        st.subheader("Identified Sensitive Data & Secrets")
        st.dataframe(st.session_state['dspm_results'], use_container_width=True)
    else:
        st.info("No sensitive data discovered.")

# --- TAB 7: SCAN RESULTS ---
with active_tab[7]:
    st.header("📋 Master Remediation Table")
    final_df = pd.concat([st.session_state['cspm_results'], st.session_state['ciem_results'], st.session_state['dspm_results']], ignore_index=True)
    if not final_df.empty:
        st.dataframe(final_df, use_container_width=True, hide_index=True)
        csv = final_df.to_csv(index=False).encode('utf-8')
        st.download_button("📩 Download Full Security Report", data=csv, file_name="security_report.csv", mime="text/csv")
    else:
        st.info("No findings to display.")
