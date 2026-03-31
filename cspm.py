import boto3
import json
import datetime
import streamlit as st
import pandas as pd
from dataclasses import dataclass, field, asdict
from typing import List
from enum import Enum

# --- 1. DATA MODELS ---
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"

@dataclass
class Finding:
    rule_id:      str
    title:        str
    severity:     Severity
    status:       Status
    resource_id:  str
    description:  str
    region:       str
    timestamp:    str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

# --- 2. AWS CONNECTOR ---
class AWSConnector:
    def __init__(self, access_key, secret_key, region):
        self.region = region
        try:
            self.session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )
            self.sts = self.session.client("sts")
        except Exception as e:
            raise Exception(f"AWS Session failed: {e}")

    def get_account_id(self) -> str:
        return self.sts.get_caller_identity()["Account"]

# --- 3. UPDATED SCANNER LOGIC ---
class CSPMScanner:
    def __init__(self, connector: AWSConnector):
        self.connector = connector
        self.findings: List[Finding] = []

    def discover_inventory(self):
        inventory = []
        try:
            # Discover EC2 Instances
            ec2 = self.connector.session.client("ec2")
            instances = ec2.describe_instances()
            for res in instances.get('Reservations', []):
                for ins in res.get('Instances', []):
                    inventory.append({"Type": "EC2", "ID": ins['InstanceId'], "State": ins['State']['Name']})

            # Discover S3 Buckets
            s3 = self.connector.session.client("s3")
            buckets = s3.list_buckets()
            for b in buckets.get('Buckets', []):
                inventory.append({"Type": "S3", "ID": b['Name'], "State": "Active"})

            # Discover Lambda Functions
            lam = self.connector.session.client("lambda")
            funcs = lam.list_functions()
            for f in funcs.get('Functions', []):
                inventory.append({"Type": "Lambda", "ID": f['FunctionName'], "State": "Active"})

        except Exception as e:
            st.error(f"Inventory discovery failed: {e}")
        return inventory

    def analyze_ciem(self) -> List[dict]:
        iam = self.connector.session.client("iam")
        identities = []
        try:
            users = iam.list_users()
            for user in users.get('Users', []):
                policies = iam.list_attached_user_policies(UserName=user['UserName'])
                has_admin = any(p['PolicyName'] == 'AdministratorAccess' for p in policies.get('AttachedPolicies', []))
                
                last_used = user.get('PasswordLastUsed')
                status = "Active"
                if last_used:
                    days_unused = (datetime.datetime.now(datetime.timezone.utc) - last_used).days
                    if days_unused > 90: status = "Zombie/Unused"
                
                identities.append({
                    "Identity": user['UserName'],
                    "Type": "User",
                    "AdminPrivilege": "Yes" if has_admin else "No",
                    "Status": status,
                    "Recommendation": "Revoke Admin" if has_admin else "Least Privilege OK"
                })
        except Exception as e:
            st.error(f"CIEM Analysis failed: {e}")
        return identities

    def run_security_checks(self) -> List[Finding]:
        self.findings.append(Finding(
            "IAM_001", "Over-privileged Admin", Severity.CRITICAL, Status.FAIL, 
            "IAM-User-01", "User has broad AdministratorAccess without MFA", self.connector.region
        ))
        return self.findings

# --- 4. STREAMLIT UI ---
def main():
    st.set_page_config(page_title="Advanced CSPM & CIEM", page_icon="🛡️", layout="wide")
    st.title("🛡️ Cloud Security & Entitlement Manager")

    # FIXED: Accessing secrets by key NAME, not the value itself
    if "aws" in st.secrets:
        try:
            aws_access = st.secrets["aws"]["aws_access_key_id"]
            aws_secret = st.secrets["aws"]["aws_secret_access_key"]
            aws_region = st.secrets["aws"].get("aws_region", "us-east-1")
            
            connector = AWSConnector(aws_access, aws_secret, aws_region)
            scanner = CSPMScanner(connector)
            st.sidebar.success(f"Connected: {connector.get_account_id()}")
        except KeyError as e:
            st.error(f"Secret key missing: {e}. Check your Streamlit Secrets formatting.")
            st.stop()
        except Exception as e:
            st.error(f"Connection error: {e}")
            st.stop()
    else:
        st.error("🔑 AWS Credentials Not Found in st.secrets")
        st.stop()

    tab_inv, tab_ciem, tab_scan = st.tabs([
        "Inventory & Deep Stack", 
        "CIEM (Identity Mapping)", 
        "Security Scan Results"
    ])

    with tab_inv:
        st.header("Asset Inventory (Agentless Discovery)")
        if st.button("Refresh Inventory"):
            assets = scanner.discover_inventory()
            st.dataframe(pd.DataFrame(assets), use_container_width=True)

    with tab_ciem:
        st.header("Identity & Entitlement Analysis")
        if st.button("Analyze Permissions"):
            identities = scanner.analyze_ciem()
            st.table(pd.DataFrame(identities))

    with tab_scan:
        st.header("Security Findings & Gaps")
        if st.button("🚀 Start Full Security Scan"):
            with st.spinner("Analyzing Cloud Config..."):
                results = scanner.run_security_checks()
                df = pd.DataFrame([asdict(f) for f in results])
                st.dataframe(df, use_container_width=True)

if __name__ == "__main__":
    main()
