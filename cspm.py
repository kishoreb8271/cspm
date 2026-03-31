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
                sts = get_aws_client('sts', aws_access_key, aws_secret_key, aws_region)
                account = sts.get_caller_identity()['Account']
                st.success(f"Connected to AWS Account: {account}")
                st.session_state['aws_connected'] = True
                # Store credentials in session state for other tabs
                st.session_state['aws_creds'] = {
                    'key': aws_access_key,
                    'secret': aws_secret_key,
                    'region': aws_region
                }
            except Exception as e:
                st.error(f"Connection failed: {e}")

    with col2:
        st.subheader("Azure Configuration")
        st.info("Azure integration module coming soon.")

# --- TAB 2: AGENTLESS VISIBILITY & INVENTORY ---
with tab_inventory:
    st.header("Full Resource Inventory")
    st.write("Automatically discovers AWS resources. Missing resources may indicate insufficient IAM permissions.")
    
    if st.button("Run Inventory Discovery"):
        if 'aws_connected' in st.session_state:
            creds = st.session_state['aws_creds']
            inventory_data = []
            errors = []

            with st.spinner("Scanning environment..."):
                # 1. EC2 Discovery
                try:
                    ec2 = get_aws_client('ec2', creds['key'], creds['secret'], creds['region'])
                    instances = ec2.describe_instances()
                    for res in instances.get('Reservations', []):
                        for ins in res.get('Instances', []):
                            inventory_data.append(["EC2", ins['InstanceId'], ins['State']['Name'], ins.get('PublicIpAddress', 'N/A')])
                except Exception as e:
                    errors.append(f"EC2: {e}")

                # 2. S3 Discovery
                try:
                    s3 = get_aws_client('s3', creds['key'], creds['secret'], creds['region'])
                    buckets = s3.list_buckets()
                    for b in buckets.get('Buckets', []):
                        inventory_data.append(["S3", b['Name'], "Active", "Regional"])
                except Exception as e:
                    errors.append(f"S3: {e}")

                # 3. Lambda Discovery (The failing service)
                try:
                    lmb = get_aws_client('lambda', creds['key'], creds['secret'], creds['region'])
                    funcs = lmb.list_functions()
                    for f in funcs.get('Functions', []):
                        inventory_data.append(["Lambda", f['FunctionName'], "Active", "Serverless"])
                except Exception as e:
                    errors.append(f"Lambda: {e}")

            # Display Results
            if inventory_data:
                inv_df = pd.DataFrame(inventory_data, columns=["Resource Type", "ID/Name", "Status", "Network Info"])
                st.dataframe(inv_df, use_container_width=True)
            else:
                st.warning("No resources discovered. Check IAM permissions.")

            # Display specific permission gaps
            if errors:
                with st.expander("⚠️ View Permission Gaps (Access Denied Errors)"):
                    for err in errors:
                        st.error(err)
        else:
            st.warning("Please connect AWS in the Integration tab first.")

# --- TAB 3: CIEM (IDENTITY MAPPING) ---
with tab_ciem:
    st.header("Cloud Infrastructure Entitlement Management")
    
    if st.button("Analyze Entitlements"):
        if 'aws_connected' in st.session_state:
            creds = st.session_state['aws_creds']
            try:
                iam = get_aws_client('iam', creds['key'], creds['secret'], creds['region'])
                users = iam.list_users()
                ciem_data = []

                for user in users.get('Users', []):
                    username = user['UserName']
                    policies = iam.list_attached_user_policies(UserName=username)
                    is_admin = any(p['PolicyName'] == 'AdministratorAccess' for p in policies.get('AttachedPolicies', []))
                    
                    last_used = user.get('PasswordLastUsed')
                    status = "Active"
                    if last_used:
                        days = (datetime.datetime.now(datetime.timezone.utc) - last_used).days
                        if days > 90: status = "Zombie (Unused)"
                    else:
                        status = "Zombie (Never Used)"

                    ciem_data.append([username, "User", "Admin" if is_admin else "Standard", status])
                
                st.table(pd.DataFrame(ciem_data, columns=["Identity", "Type", "Permissions", "Status"]))
            except Exception as e:
                st.error(f"CIEM Scan Failed: {e}")
        else:
            st.warning("Please connect AWS first.")

# --- TAB 4: SCAN RESULTS & REMEDIATION ---
with tab_results:
    st.header("Analysis & Remediation")
    st.info("Select a resource from your inventory to generate a fix.")
