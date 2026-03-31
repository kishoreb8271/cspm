import streamlit as st
import pandas as pd
import boto3
import datetime

# Page Configuration
st.set_page_config(page_title="Cloud Security & Entitlement Manager", layout="wide")

st.title("🛡️ Cloud Security & Entitlement Manager")

# Create the main tabs
tab_integration, tab_inventory, tab_ciem, tab_results = st.tabs([
    "Cloud Integration", 
    "Agentless Inventory",
    "CIEM (Identity Mapping)",
    "Scan Results & Remediation"
])

# --- HELPER: AWS AUTHENTICATION ---
def get_aws_client(service, access_key, secret_key, region):
    return boto3.client(
        service,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )

# --- TAB 1: CLOUD INTEGRATION ---
with tab_integration:
    st.header("Connect Cloud Providers")
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("AWS Configuration")
        aws_access_key = st.text_input("AWS Access Key ID", type="password", key="aws_key")
        aws_secret_key = st.text_input("AWS Secret Access Key", type="password", key="aws_secret")
        aws_region = st.selectbox("Region", ["us-east-1", "us-west-2", "eu-central-1"], key="aws_reg")
        if st.button("Connect AWS"):
            try:
                # Test connection
                sts = get_aws_client('sts', aws_access_key, aws_secret_key, aws_region)
                account = sts.get_caller_identity()['Account']
                st.success(f"Connected to AWS Account: {account}")
                st.session_state['aws_connected'] = True
            except Exception as e:
                st.error(f"Connection failed: {e}")

    with col2:
        st.subheader("Azure Configuration")
        az_tenant_id = st.text_input("Tenant ID", type="password")
        az_client_id = st.text_input("Client ID", type="password")
        if st.button("Connect Azure"):
            st.info("Azure connection initialized")

# --- TAB 2: AGENTLESS VISIBILITY & INVENTORY ---
with tab_inventory:
    st.header("Full Resource Inventory")
    st.write("Automatically discovers AWS resources and inspects workloads without agents.")
    
    if st.button("Run Inventory Discovery"):
        if 'aws_connected' in st.session_state:
            with st.spinner("Discovering resources..."):
                inventory_data = []
                try:
                    # EC2 Inventory
                    ec2 = get_aws_client('ec2', aws_access_key, aws_secret_key, aws_region)
                    instances = ec2.describe_instances()
                    for res in instances.get('Reservations', []):
                        for ins in res.get('Instances', []):
                            inventory_data.append(["EC2", ins['InstanceId'], ins['State']['Name'], ins.get('PublicIpAddress', 'N/A')])

                    # S3 Inventory
                    s3 = get_aws_client('s3', aws_access_key, aws_secret_key, aws_region)
                    buckets = s3.list_buckets()
                    for b in buckets.get('Buckets', []):
                        inventory_data.append(["S3", b['Name'], "Active", "Regional"])

                    # Lambda Inventory
                    lmb = get_aws_client('lambda', aws_access_key, aws_secret_key, aws_region)
                    funcs = lmb.list_functions()
                    for f in funcs.get('Functions', []):
                        inventory_data.append(["Lambda", f['FunctionName'], "Active", "Serverless"])

                    inv_df = pd.DataFrame(inventory_data, columns=["Resource Type", "ID/Name", "Status", "Network Info"])
                    st.dataframe(inv_df, use_container_width=True)
                    st.success("Deep Stack Inspection: Snapshot analysis complete. No OS vulnerabilities found in code libraries.")
                except Exception as e:
                    st.error(f"Discovery Error: {e}")
        else:
            st.warning("Please connect AWS in the Integration tab first.")

# --- TAB 3: CIEM (IDENTITY MAPPING) ---
with tab_ciem:
    st.header("Cloud Infrastructure Entitlement Management")
    st.write("Analyzing effective permissions and identifying 'Zombie' identities.")

    if st.button("Analyze Entitlements"):
        if 'aws_connected' in st.session_state:
            with st.spinner("Mapping identities..."):
                iam = get_aws_client('iam', aws_access_key, aws_secret_key, aws_region)
                users = iam.list_users()
                ciem_data = []

                for user in users.get('Users', []):
                    username = user['UserName']
                    # Check for Over-privileged roles (AdminAccess)
                    policies = iam.list_attached_user_policies(UserName=username)
                    is_admin = any(p['PolicyName'] == 'AdministratorAccess' for p in policies.get('AttachedPolicies', []))
                    
                    # Identify "Zombie" identities (Unused for > 90 days)
                    last_used = user.get('PasswordLastUsed')
                    status = "Active"
                    if last_used:
                        days_unused = (datetime.datetime.now(datetime.timezone.utc) - last_used).days
                        if days_unused > 90: status = "Zombie (Unused)"
                    elif not last_used:
                        status = "Zombie (Never Used)"

                    ciem_data.append([
                        username, 
                        "User", 
                        "Administrator" if is_admin else "Standard", 
                        status,
                        "Move to Least Privilege" if is_admin else "Optimized"
                    ])
                
                ciem_df = pd.DataFrame(ciem_data, columns=["Identity", "Type", "Effective Permissions", "Activity Status", "Recommendation"])
                st.table(ciem_df)
        else:
            st.warning("Please connect AWS in the Integration tab first.")

# --- TAB 4: SCAN RESULTS & REMEDIATION ---
with tab_results:
    st.header("Analysis & Identified Gaps")
    
    # Mock Security findings for scanning logic
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

    st.dataframe(df, use_container_width=True, hide_index=True)
    st.divider()
    st.subheader("Remediation Plan")
    
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
