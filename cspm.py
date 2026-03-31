import streamlit as st
import pandas as pd

# Page Configuration
st.set_page_config(page_title="Cloud Security Assessment Tool", layout="wide")

st.title("🛡️ Cybersecurity Control & Scan Manager")

# Create the three main tabs
tab_integration, tab_scanner, tab_results = st.tabs([
    "Cloud Integration", 
    "Security Scan Run", 
    "Scan Results & Remediation"
])

# --- TAB 1: CLOUD INTEGRATION ---
with tab_integration:
    st.header("Connect Cloud Providers")
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("AWS Configuration")
        aws_access_key = st.text_input("AWS Access Key ID", type="password")
        aws_secret_key = st.text_input("AWS Secret Access Key", type="password")
        aws_region = st.selectbox("Region", ["us-east-1", "us-west-2", "eu-central-1"])
        if st.button("Connect AWS"):
            st.success("AWS Credentials validated (Simulation)")

    with col2:
        st.subheader("Azure Configuration")
        az_tenant_id = st.text_input("Tenant ID", type="password")
        az_client_id = st.text_input("Client ID", type="password")
        if st.button("Connect Azure"):
            st.info("Azure connection initialized")

# --- TAB 2: SECURITY SCAN RUN ---
with tab_scanner:
    st.header("Live Cloud Security Scanner")
    st.write("Trigger an online scan of your AWS environment against NIST 800-53 or CIS benchmarks.")
    
    scan_type = st.multiselect("Select Services to Scan", ["S3", "EC2", "IAM", "Lambda", "EKS"])
    
    if st.button("Run Security Scan"):
        with st.status("Scanning AWS Environment...", expanded=True) as status:
            st.write("Checking S3 Bucket Policies...")
            st.write("Analyzing IAM Roles for Over-privileged permissions...")
            st.write("Verifying Security Groups...")
            status.update(label="Scan Complete!", state="complete", expanded=False)
            st.session_state['scan_performed'] = True

# --- TAB 3: SCAN RESULTS & REMEDIATION ---
with tab_results:
    st.header("Analysis & Identified Gaps")
    
    # Mock Data for demonstration
    scan_data = {
        "Resource": ["iam-user-admin-01", "s3-finance-records", "ec2-public-instance"],
        "Risk Type": ["Over-privileged Permission", "Misconfiguration", "Exposed Port"],
        "Severity": ["High", "Critical", "Medium"],
        "Description": [
            "User has AdministratorAccess without MFA.",
            "Bucket allows Public Read Access.",
            "Port 22 (SSH) open to 0.0.0.0/0."
        ]
    }
    df = pd.DataFrame(scan_data)

    if 'scan_performed' in st.session_state:
        # Display the results table
        event = st.dataframe(df, use_container_width=True, hide_index=True)
        
        st.divider()
        st.subheader("Remediation Plan")
        
        # Selection logic for remediation
        selected_issue = st.selectbox("Select an identified issue to see the remediation plan:", df["Resource"])
        
        remediation_map = {
            "iam-user-admin-01": {
                "Plan": "1. Revoke AdministratorAccess. 2. Attach a Least-Privilege policy. 3. Enforce MFA via IAM Policy.",
                "Code": "aws iam create-virtual-mfa-device --virtual-mfa-device-name ..."
            },
            "s3-finance-records": {
                "Plan": "1. Enable 'Block Public Access' at the account level. 2. Update Bucket Policy to restrict access to VPC endpoints.",
                "Code": "aws s3api put-public-access-block --bucket s3-finance-records ..."
            },
            "ec2-public-instance": {
                "Plan": "1. Modify Security Group ingress rules. 2. Restrict Port 22 to specific Jump-Host IP addresses.",
                "Code": "aws ec2 revoke-security-group-ingress --group-id sg-12345 ..."
            }
        }

        if selected_issue:
            res = remediation_map[selected_issue]
            st.warning(f"**Strategy:** {res['Plan']}")
            with st.expander("Show CLI/Automation Artifact"):
                st.code(res['Code'], language="bash")
    else:
        st.info("Please run a scan in the 'Security Scan Run' tab to view results.")
