import streamlit as st
import pandas as pd
import boto3
import io
import datetime
import time
import json
import re

# Page Configuration
st.set_page_config(page_title="Cloud Security & Entitlement Manager", layout="wide")

# --- CUSTOM CSS ---
st.markdown("""
    <style>
    div.stButton > button {
        width: 100%;
        height: 80px;
        border-radius: 5px;
        border: 1px solid #444;
    }
    .stMetric {
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
        border-radius: 5px;
        text-align: center;
        margin-bottom: 10px;
    }
    .cnapp-card h2 { margin: 0; font-size: 2.5rem; }
    .cnapp-card p { margin: 0; font-size: 0.9rem; font-weight: bold; }
    
    .insight-box {
        background-color: #1e2129;
        border-left: 5px solid #ff4b4b;
        padding: 10px;
        margin-bottom: 8px;
        font-size: 0.85rem;
    }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Cloud Security & Entitlement Manager")

# Initialize session state
if 'integrations' not in st.session_state:
    st.session_state['integrations'] = {} 
if 'cspm_results' not in st.session_state:
    st.session_state['cspm_results'] = pd.DataFrame()
if 'ciem_results' not in st.session_state:
    st.session_state['ciem_results'] = pd.DataFrame()
if 'dspm_vulnerability_results' not in st.session_state:
    st.session_state['dspm_vulnerability_results'] = pd.DataFrame()
if 'compliance_results' not in st.session_state:
    st.session_state['compliance_results'] = pd.DataFrame()
if 'last_scan_time' not in st.session_state:
    st.session_state['last_scan_time'] = "Never"
if 'schedule_enabled' not in st.session_state:
    st.session_state['schedule_enabled'] = False

# --- HELPER FUNCTIONS ---
def get_aws_client(service, access_key, secret_key, region):
    return boto3.client(
        service,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )

def run_real_time_scan(module_name="Full System"):
    """Logic to simulate a full environment scan based on connected integrations"""
    results_cspm = []
    
    if not st.session_state['integrations']:
        st.warning("No cloud tenants connected. Please go to the Cloud Integration tab.")
        return

    with st.status(f"🚀 Running {module_name} Scan...", expanded=True) as status:
        st.write("🔍 Initializing security modules...")
        
        for provider, creds in st.session_state['integrations'].items():
            st.write(f"🛰️ Connecting to {provider} (Tenant: {creds.get('account_id')})...")
            time.sleep(1)
            
            if provider == "AWS":
                results_cspm.append({"Resource": "s3-finance-bucket", "Type": "S3", "Severity": "Critical", "Issue": "Public Read Access", "Framework": "PCI-DSS", "Remediation": "Block Public Access"})
                results_cspm.append({"Resource": "ec2-web-server", "Type": "Toxic Combination", "Severity": "Critical", "Issue": "Vulnerable + Admin Role", "Framework": "CIS AWS", "Remediation": "Restrict SG to Trusted IP"})
            elif provider == "Azure":
                results_cspm.append({"Resource": "azure-vm-prod", "Type": "Compute", "Severity": "High", "Issue": "NSG Open to Internet", "Framework": "CIS Azure", "Remediation": "Restrict Inbound Rules"})

        # Mocked data for other modules to maintain app flow
        ciem_data = [{"Resource": "admin-user-01", "Type": "IAM User", "Severity": "High", "Issue": "MFA Disabled", "Framework": "SOC 2", "Remediation": "Enable MFA"}]
        dspm_vuln_data = [{"Resource": "customer_list.csv", "Type": "DSPM", "Severity": "Critical", "Issue": "Unencrypted PII (SSN)", "Data_Type": "PII"}]
        comp_data = [{"Framework": "CIS Foundations", "Passed": 45, "Failed": 5, "Status": "88%"}, {"Framework": "SOC 2 Type II", "Passed": 154, "Failed": 8, "Status": "95%"}]
        
        st.session_state['cspm_results'] = pd.DataFrame(results_cspm)
        st.session_state['ciem_results'] = pd.DataFrame(ciem_data)
        st.session_state['dspm_vulnerability_results'] = pd.DataFrame(dspm_vuln_data)
        st.session_state['compliance_results'] = pd.DataFrame(comp_data)
        st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        status.update(label=f"{module_name} Scan Complete!", state="complete", expanded=False)

# Main Tabs
tabs_list = [
    "🤖 AI CNAPP Dashboard",
    "📊 Executive Dashboard", 
    "🔌 Cloud Integration", 
    "⚖️ Compliance & Governance",
    "🔍 CSPM (Inventory & Scan)", 
    "🔑 CIEM (Identity Mapping)", 
    "🛡️ DSPM & Sensitive Data",
    "📋 Scan Results & Remediation"
]
active_tab = st.tabs(tabs_list)

# --- NEW TAB: AI CNAPP DASHBOARD ---
with active_tab[0]:
    st.header("🤖 AI-Powered CNAPP Risk Insights")
    
    # Top Critical Widgets (Qualys Style)
    r1, r2, r3, r4, r5 = st.columns(5)
    with r1: st.markdown('<div class="cnapp-card"><p>Vulnerable Public Instances</p><h2>11</h2></div>', unsafe_allow_html=True)
    with r2: st.markdown('<div class="cnapp-card"><p>Critical Misconfigs</p><h2>137</h2></div>', unsafe_allow_html=True)
    with r3: st.markdown('<div class="cnapp-card"><p>Active Threats</p><h2>2</h2></div>', unsafe_allow_html=True)
    with r4: st.markdown('<div class="cnapp-card"><p>Perimeter Vulns</p><h2>100</h2></div>', unsafe_allow_html=True)
    with r5: st.markdown('<div class="cnapp-card"><p>Images with Malware</p><h2>10</h2></div>', unsafe_allow_html=True)

    st.divider()

    c_left, c_right = st.columns([2, 1])

    with c_left:
        st.subheader("🔥 AI-Prioritized Attack Paths")
        path_data = [
            {"Path": "Public VM → Critical Vulnerability → Admin IAM Role → RDS Data", "Risk Score": 961},
            {"Path": "Open S3 Bucket → PII Discovery → Lateral Movement to Lambda", "Risk Score": 952},
            {"Path": "Zombie Identity → No MFA → Root Account Access", "Risk Score": 947}
        ]
        st.table(pd.DataFrame(path_data))
        
        st.subheader("TruRisk Insights Trend")
        chart_data = pd.DataFrame({
            "Day": ["06/10", "07/10", "08/10", "09/10", "Today"],
            "Insights": [80, 85, 90, 95, 101]
        })
        st.line_chart(chart_data, x="Day", y="Insights")

    with c_right:
        st.subheader("🎯 Top TruRisk Insights")
        insights = [
            "Public VMs with malware & risky IAM credentials",
            "Public VM associated with ransomware (No encryption)",
            "Critical exploitable vulnerability with full access to S3",
            "Public VM with admin privilege allowed creation of IAM artifacts",
            "Workloads with AWS Secret Keys that can access PII"
        ]
        for ins in insights:
            st.markdown(f'<div class="insight-box">⚠️ {ins}</div>', unsafe_allow_html=True)
        
        if st.button("Generate Detailed AI Risk Report"):
            st.toast("Generating AI Report...")

# --- TAB 1: EXECUTIVE DASHBOARD ---
with active_tab[1]:
    st.header("Cloud Security Posture Overview")
    st.caption(f"⏱️ Last Periodic Scan: {st.session_state['last_scan_time']}")
    
    all_findings = pd.concat([
        st.session_state['cspm_results'], 
        st.session_state['ciem_results'],
        st.session_state['dspm_vulnerability_results']
    ], ignore_index=True)
    
    crit = len(all_findings[all_findings.get('Severity') == 'Critical']) if not all_findings.empty else 0
    high = len(all_findings[all_findings.get('Severity') == 'High']) if not all_findings.empty else 0
    tenants = len(st.session_state['integrations'])
    zombie = len(st.session_state['ciem_results']) if not st.session_state['ciem_results'].empty else 0

    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("Critical Issues", crit)
    with m2: st.metric("High Risk", high)
    with m3: st.metric("Connected Tenants", tenants)
    with m4: st.metric("Zombie Identities", zombie)

    st.divider()

    if not st.session_state['dspm_vulnerability_results'].empty:
        st.subheader("Security & Compliance Posture")
        c1, c2, c3, c4 = st.columns(4)
        dspm_df = st.session_state['dspm_vulnerability_results']
        with c1: st.metric("Sensitive PII Files", len(dspm_df[dspm_df['Data_Type'] == 'PII']))
        with c2: st.metric("Exposed Secrets", len(dspm_df[dspm_df['Data_Type'].isin(['Password', 'Secret Key'])]))
        with c3: st.metric("Financial Data", len(dspm_df[dspm_df['Data_Type'] == 'Bank Account']))
        with c4: st.metric("Compliance Score", "92%")
    else:
        st.info("No data available. Connect a provider and run a scan.")

# --- TAB 2: CLOUD INTEGRATION ---
with active_tab[2]:
    st.header("Connect Cloud Providers")
    st.info("Enter credentials to save integrations for continuous scanning.")
    
    provider = st.selectbox("Select Cloud Provider", ["AWS", "Azure", "GCP"])
    
    with st.container(border=True):
        if provider == "AWS":
            c1, c2 = st.columns(2)
            acc_key = c1.text_input("Access Key ID", type="password")
            sec_key = c2.text_input("Secret Access Key", type="password")
            region = st.selectbox("Default Region", ["us-east-1", "us-west-2", "eu-central-1"])
            
            if st.button(f"Save {provider} Integration"):
                st.session_state['integrations']['AWS'] = {
                    "key": acc_key, "region": region, "account_id": "AWS-Production-01"
                }
                st.success("AWS Integration Saved!")

        elif provider == "Azure":
            t_id = st.text_input("Tenant ID", type="password")
            c_id = st.text_input("Client ID", type="password")
            if st.button(f"Save {provider} Integration"):
                st.session_state['integrations']['Azure'] = {
                    "tenant": t_id, "account_id": "Azure-Enterprise-Sub"
                }
                st.success("Azure Integration Saved!")
        
        elif provider == "GCP":
            project_id = st.text_input("Project ID")
            if st.button(f"Save {provider} Integration"):
                st.session_state['integrations']['GCP'] = {
                    "project": project_id, "account_id": project_id
                }
                st.success("GCP Integration Saved!")

    if st.session_state['integrations']:
        st.divider()
        st.subheader("Active Connections")
        for p in st.session_state['integrations']:
            st.write(f"✅ **{p}**: Connected (ID: {st.session_state['integrations'][p]['account_id']})")

# --- TAB 3: COMPLIANCE ---
with active_tab[3]:
    st.header("⚖️ Continuous Compliance & Governance")
    if not st.session_state['compliance_results'].empty:
        st.table(st.session_state['compliance_results'])
    else:
        st.info("Assessment pending scan.")

# --- TAB 4: CSPM SCAN ---
with active_tab[4]:
    st.header("🔍 CSPM: Inventory & Vulnerability Scan")
    if st.button("⚡ Run Real-Time Infrastructure Scan"):
        run_real_time_scan("CSPM")
    if not st.session_state['cspm_results'].empty:
        st.dataframe(st.session_state['cspm_results'], use_container_width=True)
    else:
        st.info("No infrastructure findings yet.")

# --- TAB 5: CIEM SCAN ---
with active_tab[5]:
    st.header("🔑 CIEM: Identity Mapping")
    if st.button("Run CIEM Identity Scan"):
        run_real_time_scan("CIEM")
    if not st.session_state['ciem_results'].empty:
        st.table(st.session_state['ciem_results'])
    else:
        st.info("No identity risks identified.")

# --- TAB 6: DSPM & SENSITIVE DATA ---
with active_tab[6]:
    st.header("🛡️ Data Security Posture Management (DSPM)")
    if st.button("Run Deep Data Discovery Scan"):
        run_real_time_scan("DSPM")
    if not st.session_state['dspm_vulnerability_results'].empty:
        st.dataframe(st.session_state['dspm_vulnerability_results'], use_container_width=True)
        type_dist = st.session_state['dspm_vulnerability_results']['Data_Type'].value_counts()
        st.bar_chart(type_dist)

# --- TAB 7: SCAN RESULTS & REMEDIATION ---
with active_tab[7]:
    st.header("📋 Consolidated Remediation Table")
    final_df = pd.concat([st.session_state['cspm_results'], st.session_state['ciem_results']], ignore_index=True)
    if not final_df.empty:
        st.dataframe(final_df, use_container_width=True, hide_index=True)
    else:
        st.info("No scan results found.")
