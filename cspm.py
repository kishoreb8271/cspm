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

# --- ACCESS MANAGEMENT & LOGIN MODULE ---
if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False
if 'user_role' not in st.session_state:
    st.session_state['user_role'] = None
if 'user_db' not in st.session_state:
    st.session_state['user_db'] = pd.DataFrame([{"Username": "admin", "Password": "AdminPassword@123", "Role": "Admin"}])

def validate_password(password):
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return re.match(pattern, password)

def login_page():
    st.image(LOGO_URL, width=400) 
    st.markdown("<h2 style='text-align: center; color: white;'>🔐 Console Login</h2>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        user = st.text_input("Username")
        pw = st.text_input("Password", type="password")
        if st.button("Login"):
            db = st.session_state['user_db']
            match = db[(db['Username'] == user) & (db['Password'] == pw)]
            if not match.empty:
                st.session_state['authenticated'] = True
                st.session_state['user_role'] = match.iloc[0]['
