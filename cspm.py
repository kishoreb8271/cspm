import streamlit as st
import pandas as pd
import boto3
import datetime
import json

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
    st.write("Discovers resources and identifies permission gaps required for full visibility.")
    
    if st.button("Run Inventory Discovery"):
        if 'aws_connected' in st.session_state:
            creds = st.session_state['aws_creds']
            inventory_data = []
            permission_errors = []

            with st.spinner("Scanning environment..."):
                # 1. EC2 Discovery
                try:
                    ec2 = get_aws_client('ec2', creds['key'], creds['secret'], creds['region'])
                    instances = ec2.describe_instances()
                    for res in instances.get('Reservations', []):
                        for ins in res.get('Instances', []):
                            inventory_data.append(["EC2", ins['InstanceId'], ins['State']['Name'], ins.get('PublicIpAddress', 'N/A')])
                except Exception as e:
                    permission_errors.append(f"ec2:DescribeInstances")

                # 2. S3 Discovery
                try:
                    s3 = get_aws_client('s3', creds['key'], creds['secret'], creds['region'])
                    buckets = s3.list_buckets()
                    for b in buckets.get('Buckets', []):
                        inventory_data.append(["S3", b['Name'], "Active", "Regional"])
                except Exception as e:
                    permission_errors.append(f"s3:ListAllMyBuckets")

                # 3. Lambda Discovery
                try:
                    lmb = get_aws_client('lambda', creds['key'], creds['secret'], creds['region'])
                    funcs = lmb.list_functions()
                    for f in funcs.get('Functions', []):
                        inventory_data.append(["Lambda", f['FunctionName'], "Active", "Serverless"])
                except Exception as e:
                    permission_errors.append(f"lambda:ListFunctions")

            # Store for results tab
            st.session_state['inventory_df'] = pd.DataFrame(inventory_data, columns=["Resource Type", "ID/Name", "Status", "Network Info"])
            
            if inventory_data:
                st.dataframe(st.session_state['inventory_df'], use_container_width=True)
            
            # --- DYNAMIC PERMISSION FIX ---
            if permission_errors:
                st.divider()
                st.warning("⚠️ **Discovery Scan Incomplete: Missing Permissions**")
                st.write("To see all resources, add the following actions to your IAM Policy:")
                
                fix_policy = {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": permission_errors,
                        "Resource": "*"
                    }]
                }
                st.code(json.dumps(fix_policy, indent=4), language="json")
        else:
            st.warning("Please connect AWS in the Integration tab first.")

# --- TAB 3: CIEM ---
with tab_ciem:
    st.header("CIEM Analysis")
    if st.button("Analyze Entitlements"):
        if 'aws_connected' in st.session_state:
            creds = st.session_state['aws_creds']
            try:
                iam = get_aws_client('iam', creds['key'], creds['secret'], creds['region'])
                users = iam.list_users()
                ciem_data = []
                for user in users.get('Users', []):
                    # Simplified logic for example
                    ciem_data.append([user['UserName'], "User", "Active"])
                st.table(pd.DataFrame(ciem_data, columns=["Identity", "Type", "Status"]))
            except Exception as e:
                st.error(f"Scan Failed: {e}")

# --- TAB 4: SCAN RESULTS & REMEDIATION ---
with tab_results:
    st.header("Remediation Strategy")
    
    if 'inventory_df' in st.session_state and not st.session_state['inventory_df'].empty:
        df = st.session_state['inventory_df']
        
        # UI for remediation selection
        selected_resource = st.selectbox("Select a discovered resource to secure:", df["ID/Name"])
        resource_type = df[df["ID/Name"] == selected_resource]["Resource Type"].values[0]

        st.subheader(f"Security Plan for {selected_resource} ({resource_type})")
        
        # Dynamic Remediation Logic
        remediation_map = {
            "S3": {
                "Issue": "Public Access & Encryption Check",
                "Step": "Enable Default AES-256 Encryption and Block Public Access.",
                "Code": f"aws s3api put-public-access-block --bucket {selected_resource} --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'"
            },
            "EC2": {
                "Issue": "Security Group Audit",
                "Step": "Restricting SSH (Port 22) to authorized CIDR blocks only.",
                "Code": f"aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port 22 --cidr 0.0.0.0/0"
            },
            "Lambda": {
                "Issue": "Environment Secrets Exposure",
                "Step": "Move hardcoded environment variables to AWS Secrets Manager.",
                "Code": f"aws lambda update-function-configuration --function-name {selected_resource} --kms-key-arn <KMS_ARN>"
            }
        }

        plan = remediation_map.get(resource_type, {"Issue": "Standard Monitoring", "Step": "Review CloudWatch logs for unusual activity.", "Code": "# No specific CLI command available"})
        
        col1, col2 = st.columns(2)
        with col1:
            st.info(f"**Identified Risk:** {plan['Issue']}")
            st.write(f"**Action Item:** {plan['Step']}")
        with col2:
            st.write("**Automation Artifact:**")
            st.code(plan['Code'], language="bash")
    else:
        st.info("Run the 'Agentless Inventory' scan first to generate results.")
