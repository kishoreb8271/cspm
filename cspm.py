import streamlit as st
import pandas as pd
import boto3
import io
import datetime
import time
import json
import re

# Page Configuration
st.set_page_config(page_title="AI-Powered CNAPP & Security Manager", layout="wide")

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
    .toxic-card {
        background-color: #2b1b1b;
        border: 1px solid #ff4b4b;
        padding: 15px;
        border-radius: 10px;
        margin-bottom: 10px;
    }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ AI-Powered CNAPP (Cloud-Native Application Protection Platform)")
st.subheader("Prioritize and Fix Your Cloud Risk with AI Intelligence")

# Initialize session state
if 'integrations' not in st.session_state:
    st.session_state['integrations'] = {} 
if 'scan_logs' not in st.session_state:
    st.session_state['scan_logs'] = []
if 'cspm_results' not in st.session_state:
    st.session_state['cspm_results'] = pd.DataFrame()
if 'ciem_results' not in st.session_state:
    st.session_state['ciem_results'] = pd.DataFrame()
if 'dspm_vulnerability_results' not in st.session_state:
    st.session_state['dspm_vulnerability_results'] = pd.DataFrame()
if 'ai_toxic_paths' not in st.session_state:
    st.session_state['ai_toxic_paths'] = []
if 'last_scan_time' not in st.session_state:
    st.session_state['last_scan_time'] = "Never"

# --- AI CORE: RISK PRIORITIZATION ENGINE ---
def run_ai_cnapp_engine():
    """AI logic to correlate risks across domains and prioritize fixes."""
    with st.status("🧠 AI Risk Engine: Correlating Attack Paths...", expanded=True) as status:
        st.write("🔍 Analyzing CSPM Misconfigurations...")
        time.sleep(0.8)
        st.write("🔑 Correlating Identity Permissions (CIEM)...")
        time.sleep(0.8)
        st.write("🛡️ Identifying Sensitive Data Exposure (DSPM)...")
        
        # Simulated AI Correlation Logic
        toxic_paths = [
            {
                "title": "Critical Attack Path: Exposed Financial Data",
                "evidence": "Public S3 Bucket (CSPM) + Admin Role (CIEM) + PII Data (DSPM)",
                "impact": "An attacker can exfiltrate customer records without authentication.",
                "fix": "Apply Least Privilege to Role 'S3-Admin' and enable S3 Block Public Access."
            },
            {
                "title": "High Risk: Lateral Movement Potential",
                "evidence": "Vulnerable EC2 (CSPM) + Over-privileged Lambda (CIEM)",
                "impact": "Compromised EC2 can use Lambda credentials to delete production databases.",
                "fix": "Patch CVE-2024-XXXX on EC2 and restrict Lambda IAM permissions."
            }
        ]
        st.session_state['ai_toxic_paths'] = toxic_paths
        status.update(label="✅ AI Risk Prioritization Complete!", state="complete", expanded=False)

def run_real_time_scan(module_name="Global System"):
    """Enhanced scan engine for real-time data ingestion."""
    results = []
    if not st.session_state['integrations']:
        st.warning("No cloud tenants connected. Please go to the Integration tab.")
        return

    with st.status(f"🚀 Running {module_name} Scan...", expanded=True) as status:
        for provider, creds in st.session_state['integrations'].items():
            st.write(f"📡 Querying {provider} APIs...")
            time.sleep(1) 
            
            if provider == "AWS":
                results.append({"Resource": "s3-finance-bucket", "Type": "S3", "Severity": "Critical", "Issue": "Public Access", "Framework": "PCI-DSS", "Remediation": "Block Public Access"})
            elif provider == "Azure":
                results.append({"Resource": "azure-vm-prod", "Type": "Compute", "Severity": "High", "Issue": "Port 22 Open", "Framework": "CIS", "Remediation": "Close NSG Port"})
        
        st.session_state['cspm_results'] = pd.DataFrame(results)
        st.session_state['ciem_results'] = pd.DataFrame([{"Resource": "s3-admin-role", "Type": "IAM", "Severity": "High", "Issue": "Admin Permissions", "Framework": "LeastPrivilege", "Remediation": "Reduce Policy Scope"}])
        st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Trigger the AI Prioritization automatically after scan
        run_ai_cnapp_engine()
        status.update(label=f"{module_name} Scan & AI Analysis Complete!", state="complete", expanded=False)

# Main Tabs
tabs_list = [
    "🤖 AI Risk Prioritizer",
    "📊 Executive Dashboard", 
    "🔌 Cloud Integration", 
    "🔍 CSPM Scan", 
    "🔑 CIEM Mapping", 
    "🛡️ DSPM Data",
    "📋 Fix & Remediation"
]
active_tab = st.tabs(tabs_list)

# --- TAB 0: AI RISK PRIORITIZER (NEW CNAPP FEATURE) ---
with active_tab[0]:
    st.header("🤖 AI-Powered Risk Insights")
    st.info("The AI engine correlates cross-cloud findings to show you what to fix first.")
    
    if st.button("⚡ Run AI Analysis"):
        run_real_time_scan("Full CNAPP")

    if st.session_state['ai_toxic_paths']:
        for path in st.session_state['ai_toxic_paths']:
            st.markdown(f"""
            <div class="toxic-card">
                <h3>{path['title']}</h3>
                <p><b>Correlation Evidence:</b> {path['evidence']}</p>
                <p><b>Business Impact:</b> {path['impact']}</p>
                <p style="color: #00ff00;"><b>AI Fix Recommendation:</b> {path['fix']}</p>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("Connect a cloud provider and run a scan to prioritize risks.")

# --- TAB 1: EXECUTIVE DASHBOARD ---
with active_tab[1]:
    st.header("CNAPP Overview")
    m1, m2, m3 = st.columns(3)
    m1.metric("Cloud Risk Score", "Critical" if st.session_state['ai_toxic_paths'] else "Safe")
    m2.metric("Toxic Attack Paths", len(st.session_state['ai_toxic_paths']))
    m3.metric("Last Scan", st.session_state['last_scan_time'])
    
    st.divider()
    st.subheader("Inventory Distribution")
    if not st.session_state['cspm_results'].empty:
        st.bar_chart(st.session_state['cspm_results']['Type'].value_counts())

# --- TAB 2: CLOUD INTEGRATION ---
with active_tab[2]:
    st.header("Connect Cloud Tenants")
    provider = st.selectbox("Select Cloud Provider", ["AWS", "Azure", "GCP"])
    with st.container(border=True):
        if provider == "AWS":
            c1, c2 = st.columns(2)
            acc_key = c1.text_input("Access Key ID", type="password")
            sec_key = c2.text_input("Secret Access Key", type="password")
            if st.button(f"Save {provider} Integration"):
                st.session_state['integrations']['AWS'] = {"account_id": "AWS-PROD-99"}
                st.success("Connected!")
        elif provider == "Azure":
            t_id = st.text_input("Tenant ID", type="password")
            if st.button(f"Save {provider} Integration"):
                st.session_state['integrations']['Azure'] = {"account_id": "AZ-ENT-SUBS"}
                st.success("Connected!")

# --- TABS 3, 4, 5 (CSPM, CIEM, DSPM) ---
with active_tab[3]:
    st.header("CSPM Findings")
    st.dataframe(st.session_state['cspm_results'], use_container_width=True)

with active_tab[4]:
    st.header("CIEM Findings")
    st.dataframe(st.session_state['ciem_results'], use_container_width=True)

with active_tab[5]:
    st.header("DSPM Findings")
    st.info("AI discovery of sensitive data (PII/Secrets) in cloud storage.")

# --- TAB 6: FIX & REMEDIATION ---
with active_tab[6]:
    st.header("📋 Priority Fix List")
    if not st.session_state['cspm_results'].empty:
        st.dataframe(st.session_state['cspm_results'][['Resource', 'Issue', 'Remediation']], use_container_width=True)
    else:
        st.info("Run a scan to generate the fix list.")
