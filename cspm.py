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
    """Handles authentication and session management."""
    def __init__(self, access_key=None, secret_key=None, region="us-east-1"):
        self.region = region
        try:
            if access_key and secret_key:
                # Prioritize explicit keys (from Streamlit Secrets)
                self.session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name=region
                )
            else:
                # Fallback to default environment/IAM role
                self.session = boto3.Session(region_name=region)
            
            self.sts = self.session.client("sts")
        except Exception as e:
            raise Exception(f"Session initialization failed: {e}")

    def get_account_id(self) -> str:
        return self.sts.get_caller_identity()["Account"]

# --- 3. SCANNER LOGIC (STUB) ---
# Note: Keep your existing CSPMScanner class logic here
class CSPMScanner:
    def __init__(self, connector: AWSConnector):
        self.connector = connector
        self.findings: List[Finding] = []

    def run(self) -> List[Finding]:
        # Place your specific check logic (IAM, S3, etc.) here
        # For demonstration, returning a dummy finding:
        self.findings.append(Finding(
            "S3_001", "Public S3 Buckets", Severity.HIGH, Status.PASS, "N/A", "Scanning logic placeholder", self.connector.region
        ))
        return self.findings

# --- 4. STREAMLIT UI ---
def main():
    st.set_page_config(page_title="CSPM Dashboard", page_icon="☁️", layout="wide")
    st.title("☁️ Cloud Security Posture Management")
    st.markdown("---")

    # 1. Setup Credentials from Secrets
    # In Streamlit Cloud, add these to the 'Secrets' dashboard
    aws_access = st.secrets.get("aws_access_key_id", "AKIAVTDJYPX7QJHHYO3S") # Fallback for your testing
    aws_secret = st.secrets.get("aws_secret_access_key", "2aTrBcpZrmTXEu8WTwB7EkUiV7a9oCi0HPzof5OP")
    aws_region = st.secrets.get("aws_region", "us-east-1")

    try:
        connector = AWSConnector(aws_access, aws_secret, aws_region)
        account_id = connector.get_account_id()
        
        st.sidebar.success(f"Connected to: {account_id}")
        st.sidebar.info(f"Region: {aws_region}")
        
    except Exception as e:
        st.error(f"Failed to authenticate: {e}")
        st.stop()

    if st.button("🚀 Run Security Scan"):
        with st.spinner("Scanning your AWS environment..."):
            scanner = CSPMScanner(connector)
            results = scanner.run()
            
            # Convert findings to DataFrame for display
            df = pd.DataFrame([asdict(f) for f in results])
            
            # Summary Metrics
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Checks", len(df))
            col2.metric("Failures", len(df[df['status'] == 'FAIL']))
            col3.metric("Passed", len(df[df['status'] == 'PASS']))

            st.dataframe(df, use_container_width=True)

if __name__ == "__main__":
    main()
