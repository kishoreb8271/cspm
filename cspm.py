import streamlit as st
import pandas as pd
import boto3
import io
import datetime
import time

# Page Configuration
st.set_page_config(page_title="Cloud Security & Entitlement Manager", layout="wide")

# --- CUSTOM CSS FOR CLICKABLE METRIC BUTTONS ---
st.markdown("""
    <style>
    div.stButton > button {
        width: 100%;
        height: 100px;
        border-radius: 5px;
        border: 1px solid #444;
    }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Cloud Security & Entitlement Manager")

# Initialize session state for navigation, results, and scheduling
if 'active_tab_index' not in st.session_state:
    st.session_state['active_tab_index'] = 0
if 'cspm_results' not in st.session_state:
    st.session_state['cspm_results'] = pd.DataFrame()
if 'ciem_results' not in st.session_state:
    st.session_state['ciem_results'] = pd.DataFrame()
if 'last_scan_time' not in st.session_state:
    st.session_state['last_scan_time'] = "Never"
if 'schedule_enabled' not in st.session_state:
    st.session_state['schedule_enabled'] = False

# --- HELPER FUNCTIONS ---
def run_automated_scan():
    """Logic to simulate a background periodic scan"""
    cspm_data = [
        {"Resource": "s3-finance-bucket", "Type": "S3", "Severity": "Critical", "Issue": "Public Read Access", "Remediation": "Block Public Access"},
        {"Resource": "ec2-web-server", "Type": "EC2", "Severity": "High", "Issue": "Port 22 Open", "Remediation": "Restrict SG to Trusted IP"}
    ]
    ciem_data = [
        {"Resource": "admin-user-01", "Type": "IAM User", "Severity": "High", "Issue": "MFA Disabled", "Remediation": "Enable MFA"}
    ]
    st.session_state['cspm_results'] = pd.DataFrame(cspm_data)
    st.session_state['ciem_results'] = pd.DataFrame(ciem_data)
    st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def go_to_results():
    st.session_state['active_tab_index'] = 4

# Main Tabs
tabs_list = ["📊 Executive Dashboard", "🔌 Cloud Integration", "🔍 CSPM (Inventory & Scan)", "🔑 CIEM (Identity Mapping)", "📋 Scan Results & Remediation"]
active_tab = st.tabs(tabs_list)

# --- TAB 1: EXECUTIVE DASHBOARD ---
with active_tab[0]:
    st.header("Security Posture Overview")
    st.caption(f"⏱️ Last Periodic Scan: {st.session_state['last_scan_time']}")
    
    all_findings = pd.concat([st.session_state['cspm_results'], st.session_state['ciem_results']], ignore_index=True)
    
    crit = len(all_findings[all_findings.get('Severity') == 'Critical']) if not all_findings.empty else 0
    high = len(all_findings[all_findings.get('Severity') == 'High']) if not all_findings.empty else 0
    med = len(all_findings[all_findings.get('Severity') == 'Medium']) if not all_findings.empty else 0
    zombie = len(st.session_state['ciem_results']) if not st.session_state['ciem_results'].empty else 0

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        if st.button(f"🚨 Critical Issues\n\n{crit}", key="btn_crit"):
            go_to_results(); st.rerun()
    with col2:
        if st.button(f"⚠️ High Risk\n\n{high}", key="btn_high"):
            go_to_results(); st.rerun()
    with col3:
        if st.button(f"🟡 Medium Risk\n\n{med}", key="btn_med"):
            go_to_results(); st.rerun()
    with col4:
        if st.button(f"🧟 Zombie Identities\n\n{zombie}", key="btn_zombie"):
            go_to_results(); st.rerun()

    st.divider()
    
    if not all_findings.empty:
        severity_dist = all_findings['Severity'].value_counts().reset_index()
        severity_dist.columns = ['Severity', 'Count']
        st.subheader("Issue Distribution")
        st.bar_chart(severity_dist, x="Severity", y="Count", color="#ff4b4b")
        
        csv = all_findings.to_csv(index=False).encode('utf-8')
        st.download_button(label="📥 Download Dashboard Report (CSV)", data=csv, 
                           file_name=f"security_report_{pd.Timestamp.now().strftime('%Y%m%d')}.csv", mime='text/csv')
    else:
        st.info("Run scans or enable scheduling to see data.")

# --- TAB 2: CLOUD INTEGRATION & SCHEDULER ---
with active_tab[1]:
    st.header("Connectivity & Automation")
    
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.subheader("Cloud Credentials")
        aws_access_key = st.text_input("AWS Access Key ID", type="password")
        aws_secret_key = st.text_input("AWS Secret Access Key", type="password")
        aws_region = st.selectbox("Region", ["us-east-1", "us-west-2"])
        if st.button("Connect AWS"):
            st.success("Connected!")

    with col_right:
        st.subheader("📅 Scan Scheduler")
        st.write("Automatically refresh security data.")
        interval = st.selectbox("Scan Interval", ["Every 1 Hour", "Every 6 Hours", "Every 24 Hours"])
        
        if not st.session_state['schedule_enabled']:
            if st.button("⏰ Enable Periodic Scanning", type="primary"):
                st.session_state['schedule_enabled'] = True
                run_automated_scan() # Run once immediately on enable
                st.rerun()
        else:
            st.success(f"Periodic Scanning is ACTIVE ({interval})")
            if st.button("🛑 Disable Scheduler"):
                st.session_state['schedule_enabled'] = False
                st.rerun()

# --- TAB 3: CSPM SCAN ---
with active_tab[2]:
    st.header("CSPM Discovery")
    if st.button("Run Manual CSPM Scan"):
        run_automated_scan()
        st.success("Manual Scan Complete")
        st.dataframe(st.session_state['cspm_results'], use_container_width=True)

# --- TAB 4: CIEM SCAN ---
with active_tab[3]:
    st.header("CIEM Mapping")
    if st.button("Run Manual CIEM Scan"):
        run_automated_scan()
        st.success("Manual Mapping Complete")
        st.table(st.session_state['ciem_results'])

# --- TAB 5: SCAN RESULTS & REMEDIATION ---
with active_tab[4]:
    st.header("Consolidated Remediation Table")
    final_df = pd.concat([st.session_state['cspm_results'], st.session_state['ciem_results']], ignore_index=True)
    if not final_df.empty:
        st.dataframe(final_df, use_container_width=True, hide_index=True)
    else:
        st.info("No scan results found. Scans are scheduled or can be run manually.")
