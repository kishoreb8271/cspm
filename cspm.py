import streamlit as st  # Added for secrets management
import boto3
import json
import yaml
import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ... (Severity, Status, and Finding classes remain unchanged) ...

# ──────────────────────────────────────────────
# 2. UPDATED BASE CONNECTOR
# ──────────────────────────────────────────────

class AWSConnector:
    """Thin wrapper around boto3 that caches clients."""

    def __init__(self, region: str = "us-east-1"):
        self.region = region
        
        # IMPROVED AUTHENTICATION LOGIC:
        # This will first look for Streamlit Secrets (for Cloud deployment).
        # If not found, it falls back to your local AWS credentials (~/.aws/credentials).
        
        try:
            if "AWS_ACCESS_KEY_ID" in st.secrets:
                self.session = boto3.Session(
                    aws_access_key_id=st.secrets["AKIAVTDJYPX7QJHHYO3S"],
                    aws_secret_access_key=st.secrets["P"],
                    region_name=self.region
                )
            else:
                # Fallback for local terminal execution
                self.session = boto3.Session(region_name=self.region)
        except Exception:
            # Final fallback to default credential chain
            self.session = boto3.Session(region_name=self.region)

        self._clients: dict = {}

    def client(self, service: str):
        if service not in self._clients:
            self._clients[service] = self.session.client(service)
        return self._clients[service]

    def get_account_id(self) -> str:
        return self.client("sts").get_caller_identity()["Account"]

# ... (BaseCheck, Security Checks, Scanner, and Reporter classes remain unchanged) ...

# ──────────────────────────────────────────────
# 7. ENTRY POINT
# ──────────────────────────────────────────────

def main():
    console.rule("[bold blue]☁  Cloud Security Posture Management (CSPM)")
    console.print()

    # UPDATED: No longer passing a profile name, uses the secrets logic above
    connector = AWSConnector(region="us-east-1")

    try:
        account_id = connector.get_account_id()
        console.print(f"[bold]Account ID :[/bold] {account_id}")
        console.print(f"[bold]Region     :[/bold] {connector.region}\n")
    except Exception as e:
        console.print(f"[red]Failed to authenticate: {e}[/red]")
        console.print("[yellow]Tip: Ensure your Access Keys are set in Streamlit Secrets or ~/.aws/credentials[/yellow]")
        return

    # ... (Rest of the main function remains the same) ...

if __name__ == "__main__":
    main()
