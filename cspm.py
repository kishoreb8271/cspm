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
    /* Global Background */
    .stApp {{
        background-color: #0b1026; /* Dark Navy branding */
    }}
    /* Global Button Styling */
    div.stButton > button {{
        width: 100%;
        height: 60px;
        border-radius: 5px;
        border: 1px solid #444;
    }}
    /* Metric Card Styling */
    [data-testid="stMetric"] {{
        background-color: #1e2129;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #333;
    }}
    /* CNAPP Dashboard Styling */
    .cnapp-card {{
        background-color: #ff4b4b;
        color: white;
        padding: 20px;
        border-radius: 8px;
        text-align: center;
        margin-bottom: 10px;
        box-shadow: 2px 2px 10px rgba(0,0,0,0.1);
    }}
    .cnapp-card h2 {{ margin: 0; font-size: 2rem; color: white; }}
    .cnapp-card p {{ margin: 0; font-size: 0.8rem; font-weight: bold; text-transform: uppercase; }}
    
    .insight-box {{
        background-color: #1e2129;
        border-left: 5px solid #ff4b4b;
        padding: 12px;
        margin-bottom: 10px;
        font-size: 0.85rem;
        border-radius: 4px;
    }}

    /* Logo Styling */
    .brand-logo {{
        display: block;
        margin-left: auto;
        margin-right: auto;
        width: 300px;
        padding-bottom: 20px;
    }}
    </style>
    """, unsafe_allow_html=True)

# --- ACCESS MANAGEMENT & LOGIN MODULE ---
if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False
if 'user_role' not in st.session_state:
    st.session_state['user_role'] = None
if 'user_db' not in st.session_state:
    # Default Admin User
    st.session_state['user_db'] = pd.DataFrame([
        {"Username": "admin", "Password": "AdminPassword@123", "Role": "Admin"}
    ])

def validate_password(password):
    """Regex for complexity: Min 8 chars, 1 Upper, 1 Lower, 1 Number, 1 Special Char"""
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return re.match(pattern, password)

def login_page():
    # Adding Logo to Login Page
    st.image(LOGO_URL, width=400) 
    st.markdown("<h2 style='text-align: center; color: white;'>🔐 Console Login</h2>", unsafe_allow_html=True)
    with st.container():
        col1, col2, col3 = st.columns([1,2,1])
        with col2:
            user = st.text_input("Username")
            pw = st.text_input("Password", type="password")
            if st.button("Login"):
                db = st.session_state['user_db']
                match = db[(db['Username'] == user) & (db['Password'] == pw)]
                if not match.empty:
                    st.session_state['authenticated'] = True
                    st.session_state['user_role'] = match.iloc[0]['Role']
                    st.rerun()
                else:
                    st.error("Invalid credentials")

# --- START APP LOGIC ---
if not st.session_state['authenticated']:
    login_page()
else:
    # Sidebar Logout, Branding and User Info
    st.sidebar.image(LOGO_URL, use_container_width=True)
    st.sidebar.success(f"Logged in as: {st.session_state['user_role']}")
    if st.sidebar.button("Logout"):
        st.session_state['authenticated'] = False
        st.rerun()

    # Main Title with Branding
    st.markdown(f'<img src="{LOGO_URL}" class="brand-logo">', unsafe_allow_html=True)
    st.title("🛡️ VantageGuard Security Manager")

    # --- SESSION STATE INITIALIZATION ---
    if 'integrations' not in st.session_state:
        st.session_state['integrations'] = {} 
    if 'cspm_results' not in st.session_state:
        st.session_state['cspm_results'] = pd.DataFrame()
    if 'ciem_results' not in st.session_state:
        st.session_state['ciem_results'] = pd.DataFrame()
    if 'dspm_results' not in st.session_state:
        st.session_state['dspm_results'] = pd.DataFrame()
    if 'compliance_results' not in st.session_state:
        st.session_state['compliance_results'] = pd.DataFrame()
    if 'last_scan_time' not in st.session_state:
        st.session_state['last_scan_time'] = "Never"
    
    # NEW: Scheduler State
    if 'schedule_enabled' not in st.session_state:
        st.session_state['schedule_enabled'] = False
    if 'next_scan_time' not in st.session_state:
        st.session_state['next_scan_time'] = None

    # --- HELPER FUNCTIONS ---
    def get_aws_client(service, creds):
        return boto3.client(
            service,
            aws_access_key_id=creds['
