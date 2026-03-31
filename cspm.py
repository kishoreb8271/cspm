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
    .stProgress > div > div > div > div {
        background-color: #28a745;
    }
    .compliance-text {
        font-size: 14px;
        font-weight: 500;
    }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Cloud Security & Entitlement Manager")

# Initialize session state
if 'cspm_results' not in st.session_state:
    st.session_state['cspm_results'] = pd.DataFrame()
if 'ciem_results' not in st.session_state:
    st.session_state['ciem_results'] = pd.DataFrame()
if 'dspm_vulnerability_results' not in st.session_state:
    st.session_state['dspm_vulnerability_results'] = pd.DataFrame()
if 'compliance_results' not in st.session_state:
    st.session_state['compliance_results'] = []
if 'last_scan_time' not in st.session_state:
    st.session_state['last_scan_time'] = "Never"
if 'schedule_enabled' not in st.session_state:
    st.session_state['schedule_enabled'] = False
if 'aws_connected' not in st.session_state:
    st.session_state['aws_connected'] = False

# --- HELPER FUNCTIONS ---
def run_automated_scan(module_name="Full System"):
    with st.status(f"Running {module_name} Scan...", expanded=True) as status:
        st.write("🔍 Initializing security modules...")
        time.sleep(1)
        st.write(f"🛰️ Connecting to cloud endpoints for {module_name}...")
        time.sleep(1.5)
        st.write("📊 Analyzing resource configurations against frameworks...")
        time.sleep(1)
        
        # Simulated Data Generation
        cspm_data = [
            {"Resource": "s3-finance-data", "Type": "S3", "Severity": "Critical", "Issue": "Public Read Access", "Framework": "PCI-DSS", "Remediation": "Block Public Access"},
            {"Resource": "ec2-web-server", "Type": "EC2", "Severity": "Critical", "Issue": "Vulnerable + Admin Role", "Framework": "CIS AWS", "Remediation": "Restrict SG to Trusted IP"},
            {"Resource": "rds-prod-db", "Type": "RDS", "Severity": "High", "Issue": "Publicly Accessible", "Framework": "CIS AWS", "Remediation": "Set PubliclyAccessible to False"}
        ]
        ciem_data = [
            {"Resource": "admin-user-01", "Type": "IAM User", "Severity": "High", "Issue": "MFA Disabled", "Framework": "SOC 2", "Remediation": "Enable MFA"},
            {"Resource": "test-key-01", "Type": "Access Key", "Severity": "Medium", "Issue": "Key Rotation Overdue", "Framework": "CIS", "Remediation": "Rotate Access Key"}
        ]
        dspm_vuln_data = [
            {"Resource": "db-backup.sql", "Type": "Secrets", "Severity": "Critical", "Issue": "Hardcoded Passwords Found", "Data_Type": "Password"},
            {"Resource": "customer_list.csv", "Type": "DSPM", "Severity": "Critical", "Issue": "Unencrypted PII (SSN)", "Data_Type": "PII"}
        ]
        
        # --- DYNAMIC COMPLIANCE CALCULATION ---
        # Instead of fixed numbers, we map findings back to sections to generate counts
        sections = [
            {"ID": "1", "Name": "Identity and Access Management", "Passed": 12, "Failed": 2},
            {"ID": "2", "Name": "Storage", "Passed": 5, "Failed": 3, "Sub": [
                {"ID": "2.1", "Name": "Simple Storage Service (S3)", "Passed": 4, "Failed": 2},
                {"ID": "2.2", "Name": "Relational Database Service (RDS)", "Passed": 1, "Failed": 1}
            ]},
            {"ID": "3", "Name": "Logging", "Passed": 8, "Failed": 1},
            {"ID": "4", "Name": "Monitoring", "Passed": 10, "Failed": 0},
            {"ID": "5", "Name": "Networking", "Passed": 15, "Failed": 2}
        ]

        total_ok = sum(s['Passed'] for s in sections)
        total_alarm = sum(s['Failed'] for s in sections)
        
        comp_data = [{
            "Framework": "CIS AWS Foundations v4.0.0",
            "Total_OK": total_ok, 
            "Total_Alarm": total_alarm, 
            "Total_Error": 0, 
            "Total_Skip": 5,
            "Sections": sections
        }]
        
        st.session_state['cspm_results'] = pd.DataFrame(cspm_data)
        st.session_state['ciem_results'] = pd.DataFrame(ciem_data)
        st.session_state['dspm_vulnerability_results'] = pd.DataFrame(dspm_vuln_data)
        st.session_state['compliance_results'] = comp_data
        st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        status.update(label=f"{module_name} Scan Complete!", state="complete", expanded=False)

# Main Tabs
tabs_list = [
    "📊 Executive Dashboard", 
    "🔌 Cloud Integration", 
    "⚖️ Compliance & Governance",
    "🔍 CSPM (Inventory & Scan)", 
    "🔑 CIEM (Identity Mapping)", 
    "🛡️ DSPM & Sensitive Data",
    "📋 Scan Results & Remediation"
]
active_tab = st.tabs(tabs_list)

# --- TAB 1: EXECUTIVE DASHBOARD ---
with active_tab[0]:
    st.header("Cloud Security Posture Overview")
    st.caption(f"⏱️ Last Periodic Scan: {st.session_state['last_scan_time']}")
    
    all_findings = pd.concat([
        st.session_state['cspm_results'], 
        st.session_state['ciem_results'],
        st.session_state['dspm_vulnerability_results']
    ], ignore_index=True)
    
    # Calculate Dynamic Counts for Dashboard
    crit = len(all_findings[all_findings['Severity'] == 'Critical']) if not all_findings.empty else 0
    high = len(all_findings[all_findings['Severity'] == 'High']) if not all_findings.empty else 0
    med = len(all_findings[all_findings['Severity'] == 'Medium']) if not all_findings.empty else 0
    zombie = len(st.session_state['ciem_results']) if not st.session_state['ciem_results'].empty else 0

    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("Critical Issues", crit)
    with m2: st.metric("High Risk", high)
    with m3: st.metric("Medium Risk", med)
    with m4: st.metric("Zombie Identities", zombie)

    st.divider()

    if not all_findings.empty:
        st.subheader("Issue Distribution")
        severity_dist = all_findings['Severity'].value_counts().reset_index()
        severity_dist.columns = ['Severity', 'Count']
        st.bar_chart(severity_dist, x="Severity", y="Count", color="#ff4b4b")

# --- TAB 2: CLOUD INTEGRATION ---
with active_tab[1]:
    st.header("Connectivity & Automation")
    col_left, col_right = st.columns(2)
    with col_left:
        st.subheader("Cloud Credentials")
        aws_key = st.text_input("AWS Access Key ID", type="password")
        aws_sec = st.text_input("AWS Secret Access Key", type="password")
        aws_reg = st.selectbox("Region", ["us-east-1", "us-west-2", "eu-central-1"])
        if st.button("Connect AWS"):
            st.session_state['aws_connected'] = True
            st.success("Connected! AWS Credentials validated.")

    with col_right:
        st.subheader("📅 Scan Scheduler")
        interval = st.selectbox("Scan Interval", ["Every 1 Hour", "Every 6 Hours", "Daily"])
        if not st.session_state['schedule_enabled']:
            if st.button("⏰ Enable Periodic Scanning", type="primary"):
                st.session_state['schedule_enabled'] = True
                run_automated_scan("Scheduled System")
                st.rerun()
        else:
            st.success(f"Periodic Scanning is ACTIVE ({interval})")
            if st.button("🛑 Disable Scheduler"):
                st.session_state['schedule_enabled'] = False
                st.rerun()

# --- TAB 3: COMPLIANCE & GOVERNANCE ---
with active_tab[2]:
    st.header("⚖️ Continuous Compliance & Governance")
    
    if st.session_state['compliance_results']:
        for fw in st.session_state['compliance_results']:
            with st.expander(f"📌 {fw['Framework']}", expanded=True):
                s1, s2, s3, s4 = st.columns(4)
                s1.metric("OK", fw.get('Total_OK', 0))
                s2.metric("Alarm", fw.get('Total_Alarm', 0), delta_color="inverse")
                s3.metric("Error", fw.get('Total_Error', 0))
                s4.metric("Skipped", fw.get('Total_Skip', 0))
                
                st.markdown("<br>", unsafe_allow_html=True)
                
                h1, h2, h3 = st.columns([4, 2, 3])
                h1.caption("FRAMEWORK SECTION")
                h2.caption("SCAN COUNT (ALARM | OK)")
                h3.caption("COMPLIANCE STATUS")

                for sec in fw['Sections']:
                    total = sec['Passed'] + sec['Failed']
                    prog_val = sec['Passed'] / total if total > 0 else 0
                    
                    c1, c2, c3 = st.columns([4, 2, 3])
                    c1.markdown(f"<span class='compliance-text'>{sec['ID']} {sec['Name']}</span>", unsafe_allow_html=True)
                    c2.markdown(f"**🔴 {sec['Failed']}** | **🟢 {sec['Passed']}**")
                    c3.progress(prog_val)
                    
                    if 'Sub' in sec:
                        for sub in sec['Sub']:
                            sub_total = sub['Passed'] + sub['Failed']
                            sub_prog = sub['Passed'] / sub_total if sub_total > 0 else 0
                            sc1, sc2, sc3, sc4 = st.columns([0.5, 3.5, 2, 3])
                            sc2.caption(f"{sub['ID']} {sub['Name']}")
                            sc3.caption(f"🔴 {sub['Failed']} | 🟢 {sub['Passed']}")
                            sc4.progress(sub_prog)
                    st.divider()
    else:
        st.info("No scan data available. Go to CSPM/CIEM tabs to run a scan.")

# --- REMAINING TABS (Simplified for example) ---
with active_tab[3]:
    st.header("🔍 CSPM: Inventory & Scan")
    if st.button("Run CSPM Scan"):
        run_automated_scan("CSPM")
    st.dataframe(st.session_state['cspm_results'], use_container_width=True)

with active_tab[4]:
    st.header("🔑 CIEM: Identity Mapping")
    if st.button("Run CIEM Scan"):
        run_automated_scan("CIEM")
    st.dataframe(st.session_state['ciem_results'], use_container_width=True)

with active_tab[5]:
    st.header("🛡️ DSPM & Sensitive Data")
    if st.button("Run DSPM Scan"):
        run_automated_scan("DSPM")
    st.dataframe(st.session_state['dspm_vulnerability_results'], use_container_width=True)

with active_tab[6]:
    st.header("📋 Scan Results & Remediation")
    final_df = pd.concat([st.session_state['cspm_results'], st.session_state['ciem_results']], ignore_index=True)
    st.dataframe(final_df, use_container_width=True)
