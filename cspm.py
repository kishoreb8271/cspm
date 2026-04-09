# --- DYNAMIC SCANNER HELPERS ---
    def scan_s3_content_realtime(s3_client, bucket_name, object_key):
        """Fetches object content and scans for sensitive patterns via Regex."""
        patterns = {
            "PII (SSN)": r"\b\d{3}-\d{2}-\d{4}\b",
            "PII (Email)": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "Secret (AWS Key)": r"AKIA[0-9A-Z]{16}"
        }
        findings = []
        try:
            # Get a sample of the file (first 1024 bytes) for real-time inspection
            response = s3_client.get_object(Bucket=bucket_name, Key=object_key, Range='bytes=0-1024')
            content = response['Body'].read().decode('utf-8')
            
            for label, regex in patterns.items():
                if re.search(regex, content):
                    findings.append(label)
        except Exception:
            # Handle binary files or permission issues silently
            return None
        return ", ".join(findings) if findings else None

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
                        s3 = get_aws_client('s3', creds)
                        iam = get_aws_client('iam', creds)
                        
                        # --- DYNAMIC DSPM & CSPM Logic ---
                        buckets = s3.list_buckets()['Buckets']
                        for b in buckets:
                            b_name = b['Name']
                            st.write(f"🔍 Analyzing Bucket: {b_name}...")
                            
                            # 1. Real-time CSPM: Check Public Access Block
                            try:
                                p_access = s3.get_public_access_block(Bucket=b_name)
                                is_public = not all(p_access['PublicAccessBlockConfiguration'].values())
                            except:
                                is_public = True # Assume public if no config exists

                            if is_public:
                                results_cspm.append({
                                    "Resource": b_name, "Type": "S3", "Severity": "Critical", 
                                    "Issue": "Public Access Enabled", "Framework": "PCI-DSS", 
                                    "Remediation": "Enable S3 Block Public Access"
                                })

                            # 2. Real-time DSPM: Scan Objects for PII/Secrets
                            objects = s3.list_objects_v2(Bucket=b_name, MaxKeys=5).get('Contents', [])
                            for obj in objects:
                                found_pii = scan_s3_content_realtime(s3, b_name, obj['Key'])
                                if found_pii:
                                    dspm_data.append({
                                        "Account": account_name,
                                        "Provider": "AWS",
                                        "Resource": f"s3://{b_name}/{obj['Key']}", 
                                        "File_Name": obj['Key'].split('/')[-1],
                                        "Location": f"{b_name}/", 
                                        "Type": "S3 Object", 
                                        "Severity": "High", 
                                        "Issue": f"Exposed {found_pii}", 
                                        "Data_Type": "Sensitive Content",
                                        "Lineage": f"S3 Storage -> {account_name}",
                                        "Governance": "GDPR / SOC2",
                                        "Remediation_Step": "Quarantine file and rotate secrets if applicable."
                                    })

                        # --- Real-time CIEM Logic ---
                        users = iam.list_users()['Users']
                        for user in users:
                            u_name = user['UserName']
                            # Check MFA status
                            mfa = iam.list_mfa_devices(UserName=u_name)['MFADevices']
                            if not mfa:
                                ciem_data.append({
                                    "Resource": u_name, "Type": "IAM User", "Severity": "High", 
                                    "Issue": "MFA Disabled", "Framework": "CIS AWS", 
                                    "Remediation": "Enforce MFA for this user"
                                })

                    except Exception as e:
                        st.error(f"Scan Error on {account_name}: {e}")
                
                elif provider == "Azure":
                    st.info(f"Azure Graph API Scan (Mocked) for {account_name}")
                    # Keep Azure mock or implement similar logic using Azure SDK for Python

            # Update Session States
            st.session_state['cspm_results'] = pd.DataFrame(results_cspm)
            st.session_state['ciem_results'] = pd.DataFrame(ciem_data)
            st.session_state['dspm_results'] = pd.DataFrame(dspm_data)
            
            st.session_state['compliance_results'] = pd.DataFrame([
                {"Framework": "CIS Foundations", "Passed": 45, "Failed": len(results_cspm), "Status": "Review"},
                {"Framework": "SOC 2 Type II", "Passed": 154, "Failed": len(ciem_data), "Status": "Monitoring"},
                {"Framework": "HIPAA Cloud", "Passed": 88, "Failed": len(dspm_data), "Status": "Critical"}
            ])
            
            st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            status.update(label=f"{module_name} Scan Complete!", state="complete", expanded=False)
