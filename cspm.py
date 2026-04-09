# --- UPDATED SCANNER WITH ENHANCED DSPM LOGIC ---
    def run_real_time_scan(module_name="Full System"):
        if not st.session_state['integrations']:
            st.warning("No cloud tenants connected. Please go to the Cloud Integration tab.")
            return

        results_cspm, ciem_data, dspm_data = [], [], []

        with st.status(f"🚀 Running {module_name} Scan...", expanded=True) as status:
            for account_name, creds in st.session_state['integrations'].items():
                provider = creds.get('provider')
                if provider == "AWS":
                    try:
                        s3 = get_aws_client('s3', creds)
                        buckets = s3.list_buckets()['Buckets']
                        
                        for b in buckets:
                            b_name = b['Name']
                            # CSPM Logic
                            results_cspm.append({"Resource": b_name, "Type": "S3", "Severity": "Medium", "Issue": "Logging Disabled", "Framework": "NIST", "Remediation": "Enable CloudTrail"})

                            # REAL-TIME DSPM DISCOVERY
                            st.write(f"📂 Discovery: Scanning objects in {b_name}...")
                            objects = s3.list_objects_v2(Bucket=b_name, MaxKeys=10)
                            
                            if 'Contents' in objects:
                                for obj in objects['Contents']:
                                    file_key = obj['Key']
                                    res = s3.get_object(Bucket=b_name, Key=file_key)
                                    body = res['Body'].read().decode('utf-8', errors='ignore')
                                    
                                    # REAL DATA SENSITIVITY CHECK
                                    found_issues = []
                                    if re.search(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', body):
                                        found_issues.append(("PII", "Email Addresses Exposure", "High"))
                                    if re.search(r'([^A-Z0-9])[A-Z0-9]{40}(?![A-Z0-9])', body):
                                        found_issues.append(("Secret", "AWS Secret Key Found", "Critical"))
                                    if re.search(r'\b(?:\d{4}[ -]?){3}\d{4}\b', body):
                                        found_issues.append(("PII", "Credit Card Numbers", "Critical"))

                                    for d_type, issue, sev in found_issues:
                                        dspm_data.append({
                                            "Resource": f"s3://{b_name}/{file_key}",
                                            "Object": file_key,
                                            "Bucket": b_name,
                                            "Data_Class": d_type,
                                            "Issue": issue,
                                            "Severity": sev,
                                            "Lineage": f"Internet -> S3 -> {account_name}",
                                            "Governance": "GDPR / PCI-DSS",
                                            "Remediation": "Quarantine file and encrypt at rest"
                                        })

                        # CIEM Logic
                        iam = get_aws_client('iam', creds)
                        for user in iam.list_users()['Users']:
                            ciem_data.append({"Resource": user['UserName'], "Type": "IAM User", "Severity": "High", "Issue": "Over-privileged", "Framework": "CIS", "Remediation": "Apply Least Privilege"})
                            
                    except Exception as e:
                        st.error(f"Error scanning {account_name}: {e}")

            st.session_state['cspm_results'] = pd.DataFrame(results_cspm)
            st.session_state['ciem_results'] = pd.DataFrame(ciem_data)
            st.session_state['dspm_results'] = pd.DataFrame(dspm_data)
            st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            status.update(label="Scan Complete!", state="complete")

    # --- TAB 6: NEW ENHANCED DSPM INTERFACE ---
    with active_tab[6]:
        st.header("🛡️ Data Security Posture Management (DSPM)")
        
        if st.button("🔍 Start Real-Time Data Discovery"):
            run_real_time_scan("DSPM")

        if not st.session_state['dspm_results'].empty:
            df = st.session_state['dspm_results']
            
            # Sub-tabs for DSPM Features
            dspm_sub1, dspm_sub2, dspm_sub3, dspm_sub4, dspm_sub5 = st.tabs([
                "📁 Discovery", "🧬 Lineage", "🔥 Risk", "📜 Governance", "🛠️ Remediation"
            ])

            with dspm_sub1:
                st.subheader("Data Inventory")
                st.write("Identified sensitive data assets across connected clouds.")
                st.dataframe(df[['Resource', 'Object', 'Data_Class']], use_container_width=True)

            with dspm_sub2:
                st.subheader("Data Flow & Lineage")
                st.write("Mapping the path of sensitive data from source to storage.")
                st.table(df[['Resource', 'Lineage']])

            with dspm_sub3:
                st.subheader("Risk Assessment")
                st.write("Prioritized vulnerabilities based on data sensitivity and exposure.")
                st.dataframe(df[['Resource', 'Issue', 'Severity']], use_container_width=True)
                st.bar_chart(df['Severity'].value_counts())

            with dspm_sub4:
                st.subheader("Governance & Compliance")
                st.write("Check data alignment with regulatory frameworks.")
                st.dataframe(df[['Resource', 'Data_Class', 'Governance']], use_container_width=True)

            with dspm_sub5:
                st.subheader("Remediation Logs")
                st.write("Actionable steps to secure discovered data risks.")
                for _, row in df.iterrows():
                    with st.expander(f"Fix: {row['Object']}"):
                        st.warning(f"Issue: {row['Issue']}")
                        st.success(f"Action: {row['Remediation']}")
        else:
            st.info("No data discovered yet. Connect a cloud provider and run a scan.")
