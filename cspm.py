import streamlit as st
import pandas as pd
import boto3
import io
import datetime
import time
import json
import re
from PIL import Image

# --- LOGO CONFIGURATION ---
LOGO_URL = "https://github.com/kishoreb8271/cspm/blob/main/VantageGuard.png?raw=true"

# Page Configuration
st.set_page_config(page_title="Cloud Security & Entitlement Manager", layout="wide")

# --- CUSTOM CSS ---
st.markdown(f"""
    <style>
    .stApp {{ background-color: #0b1026; }}
    div.stButton > button {{ width: 100%; height: 60px; border-radius: 5px; border: 1px solid #444; }}
    [data-testid="stMetric"] {{ background-color: #1e2129; padding: 15px; border-radius: 10px; border: 1px solid #333; }}
    .cnapp-card {{ background-color: #ff4b4b; color: white; padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 10px; box-shadow: 2px 2px 10px rgba(0,0,0,0.1); }}
    .cnapp-card h2 {{ margin: 0; font-size: 2rem; color: white; }}
    .cnapp-card p {{ margin: 0; font-size: 0.8rem; font-weight: bold; text-transform: uppercase; }}
    .insight-box {{ background-color: #1e2129; border-left: 5px solid #ff4b4b; padding: 12px; margin-bottom: 10px; font-size: 0.85rem; border-radius: 4px; }}
    .brand-logo {{ display: block; margin-left: auto; margin-right: auto; width: 300px; padding-bottom: 20px; }}
    </style>
    """, unsafe_allow_html=True)

# --- SESSION STATE INITIALIZATION ---
if 'authenticated' not in st.session_state: st.session_state['authenticated'] = False
if 'user_role' not in st.session_state: st.session_state['user_role'] = None
if 'user_db' not in st.session_state:
    st.session_state['user_db'] = pd.DataFrame([{"Username": "admin", "Password": "AdminPassword@123", "Role": "Admin"}])
if 'integrations' not in st.session_state: st.session_state['integrations'] = {} 
if 'cspm_results' not in st.session_state: st.session_state['cspm_results'] = pd.DataFrame()
if 'ciem_results' not in st.session_state: st.session_state['ciem_results'] = pd.DataFrame()
if 'dspm_results' not in st.session_state: st.session_state['dspm_results'] = pd.DataFrame()
if 'compliance_results' not in st.session_state: st.session_state['compliance_results'] = pd.DataFrame()
if 'last_scan_time' not in st.session_state: st.session_state['last_scan_time'] = "Never"
if 'schedule_enabled' not in st.session_state: st.session_state['schedule_enabled'] = False
if 'next_scan_time' not in st.session_state: st.session_state['next_scan_time'] = None

# --- HELPER FUNCTIONS ---
def validate_password(password):
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return re.match(pattern, password)

def get_aws_client(service, creds):
    return boto3.client(service, aws_access_key_id=creds['key'], aws_secret_access_key=creds['secret'], region_name=creds['region'])

def scan_content_for_pii(content):
    findings = []
    patterns = {
        "PII (Email/SSN)": r"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b|\b\d{3}-\d{2}-\d{4}\b)",
        "PCI (Credit Card)": r"\b(?:\d[ -]*?){13,16}\b",
        "HIPAA/PHI (Health ID)": r"\b[A-Z]{3}\d{7}\b",
        "Secret/API Key": r"(?:key|secret|password|token)[-|_| ]*[:|=][-|_| ]*([A-Za-z0-9/+=]{16
