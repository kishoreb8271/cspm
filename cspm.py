import boto3
import json
import yaml
import datetime
import streamlit as st
import pandas as pd
from dataclasses import dataclass, field, asdict
from typing import Optional, List
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
    """Handles authentication and session management using Streamlit Secrets."""
    def __init__(self, access_key, secret_key, region):
        self.region = region
        try:
            # Initialize session using keys provided from secrets
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

# --- 3. SCANNER LOGIC ---
class CSPMScanner:
    def __init__(self, connector: AWSConnector):
        self.connector = connector
        self.findings: List[Finding] = []

    def run(self) -> List[Finding]:
        # Placeholder for your specific check logic (IAM, S3, etc.)
        self.findings.append(Finding(
            "S3_001", "Public S3 Buckets", Severity.HIGH, Status.PASS, 
            "N/A", "Scanning logic active", self.connector.region
        ))
        return self.findings

# --- 4. STREAMLIT UI ---
def main():
    st.set_page_config(page_title="CSPM Dashboard", page_icon="☁️", layout="wide")
    st.title("☁️ Cloud Security Posture Management")
    st.markdown("---")

    # Attempt to load credentials from Streamlit Secrets manager
    if "aws" in st.secrets:
        aws_access = st.secrets["aws"]["aws_access_key_id"]
        aws_secret = st.secrets["aws"]["aws_secret_access_key"]
        aws_region = st.secrets["aws"].get("aws_region", "us-east-1")
    else:
        st.error("🔑 **AWS Credentials Not Found**")
        st.info("""
            Please add your credentials to the **Streamlit Secrets** manager:
            1. Go to your App Settings on the Streamlit Cloud Dashboard.
            2. Open the **Secrets** tab.
            3. Paste the following:
            ```toml
            [aws]
            aws_access_key_id = "YOUR_ACCESS_KEY"
            aws_secret_access_key = "YOUR_SECRET_KEY"
            aws_region = "us-east-1"
            ```
        """)
        st.stop()

    try:
        connector = AWSConnector(aws_access, aws_secret, aws_region)
        account_id = connector.get_account_id()
        
        st.sidebar.success(f"Connected to: {account_id}")
        st.sidebar.info(f"Region: {aws_region}")
        
    except Exception as e:
        st.error(f"Authentication Error: {e}")
        st.stop()

    if st.button("🚀 Run Security Scan"):
        with st.spinner("Scanning AWS environment..."):
            scanner = CSPMScanner(connector)
            results = scanner.run()
            
            df = pd.DataFrame([asdict(f) for f in results])
            
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Checks", len(df))
            col2.metric("Failures", len(df[df['status'] == 'FAIL']))
            col3.metric("Passed", len(df[df['status'] == 'PASS']))

            st.dataframe(df, use_container_width=True)

if __name__ == "__main__":
    main()
