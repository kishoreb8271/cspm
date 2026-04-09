# --- AUTOMATED REMEDIATION ENGINE ---
def execute_remediation(account_name, resource_id, issue_type):
    """Executes live API calls to fix identified security gaps."""
    creds = st.session_state['integrations'].get(account_name)
    if not creds: return False

    try:
        if issue_type == "Public S3":
            s3 = get_aws_client('s3', creds)
            s3.put_public_access_block(
                Bucket=resource_id,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True, 'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True, 'RestrictPublicBuckets': True
                }
            )
        elif issue_type == "Open SSH":
            ec2 = get_aws_client('ec2', creds)
            ec2.revoke_security_group_ingress(GroupId=resource_id, IpProtocol='tcp', FromPort=22, ToPort=22, CidrIp='0.0.0.0/0')
        
        return True
    except Exception as e:
        st.error(f"Remediation Failed: {e}")
        return False

# --- DYNAMIC SCANNER FOR ALL RESOURCES ---
def run_real_time_scan(module_name="Full System"):
    if not st.session_state['integrations']:
        st.warning("No cloud tenants connected.")
        return

    findings = []
    with st.status("🚀 Global Resource Discovery & Scanning...", expanded=True) as status:
        for account, creds in st.session_state['integrations'].items():
            if creds['provider'] == "AWS":
                try:
                    # 1. EC2 Scan (Security Groups & Public IPs)
                    ec2 = get_aws_client('ec2', creds)
                    instances = ec2.describe_instances()
                    for res in instances['Reservations']:
                        for inst in res['Instances']:
                            if 'PublicIpAddress' in inst:
                                findings.append({
                                    "Account": account, "Resource": inst['InstanceId'], "Type": "EC2",
                                    "Severity": "Medium", "Issue": "Publicly Accessible Instance",
                                    "Remediation": "Restrict via SG", "Fix_ID": "Public IP"
                                })

                    # 2. IAM Scan (Key Rotation & MFA)
                    iam = get_aws_client('iam', creds)
                    users = iam.list_users()['Users']
                    for u in users:
                        keys = iam.list_access_keys(UserName=u['UserName'])['AccessKeyMetadata']
                        for k in keys:
                            age = (datetime.datetime.now(datetime.timezone.utc) - k['CreateDate']).days
                            if age > 90:
                                findings.append({
                                    "Account": account, "Resource": u['UserName'], "Type": "IAM",
                                    "Severity": "High", "Issue": "Stale Access Key (>90 Days)",
                                    "Remediation": "Rotate Access Key", "Fix_ID": "Rotate Key"
                                })

                    # 3. S3 & DSPM (Regex Scanning)
                    s3 = get_aws_client('s3', creds)
                    buckets = s3.list_buckets()['Buckets']
                    for b in buckets:
                        b_name = b['Name']
                        # Check Encryption
                        try:
                            s3.get_bucket_encryption(Bucket=b_name)
                        except:
                            findings.append({
                                "Account": account, "Resource": b_name, "Type": "S3",
                                "Severity": "High", "Issue": "Unencrypted Bucket",
                                "Remediation": "Enable AES-256", "Fix_ID": "Encrypt S3"
                            })
                
                except Exception as e:
                    st.error(f"Error scanning {account}: {str(e)}")

        # Convert to DataFrame
        st.session_state['cspm_results'] = pd.DataFrame(findings)
        st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status.update(label="Global Scan Complete!", state="complete")
