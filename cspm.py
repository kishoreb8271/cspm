import streamlit as st
import pandas as pd
import boto3
import io
import datetime
import time
import json
import re

# 1. Page Configuration MUST come before any other st commands
st.set_page_config(page_title="Cloud Security & Entitlement Manager", layout="wide")

# --- CUSTOM CSS (Including the Bento Box Cards) ---
st.markdown("""
    <style>
    .stApp { background-color: #0e1117; }
    
    /* Global Button Styling */
    div.stButton > button {
        width: 100%;
        height: 60px;
        border-radius: 5px;
        border: 1px solid #444;
    }

    /* Modern Bento Risk Card */
    .risk-card {
        background: #16191f;
        border: 1px solid #2d3139;
        border-radius: 20px;
        padding: 30px;
        text-align: left;
        transition: transform 0.3s ease;
        margin-bottom: 20px;
    }
    .risk-card:hover { border-color: #444; transform: translateY(-5px); }
    
    .icon-box {
        width: 50px;
        height: 50px;
        border-radius: 12px;
        display: flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 20px;
        font-size: 24px;
    }

    /* Severity Colors & Gradients */
    .high-sev-icon { background: rgba(255, 75, 75, 0.15); color: #ff4b4b; }
    .high-sev-text { 
        background: linear-gradient(180deg, #fff 0%, #ff4b4b 100%);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        font-size: 3.5rem; font-weight: 800;
    }

    .med-risk-icon { background: rgba(255, 184, 0, 0.15); color: #ffb800; }
    .med-risk-text { 
        background: linear-gradient(180deg, #fff 0%, #ffb800 100%);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        font-size: 3.5rem; font-weight: 800;
    }

    .card-label { color: #808495; text-transform: uppercase; font-size: 0.8rem; font-weight: 700; }
    .trend-text { color: #616675; font-size: 0.85rem; margin-top: 10px; }

    /* Tab Styling */
    .stTabs [data-baseweb="tab-list"] { gap: 8px; background-color: #1e2129; padding: 10px; border-radius: 10px; }
    .stTabs [aria-selected="true"] { color: #ff4b4b !important; border-bottom: 3px solid #ff4b4b !important; }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Cloud Security & Entitlement Manager")

# --- SESSION STATE INITIALIZATION ---
for key in ['integrations', 'cspm_results', 'ciem_results', 'dspm_results', 'compliance_results']:
    if key not in st.session_state:
        st.session_state[key] = pd.DataFrame() if 'results' in key else {}

if 'last_scan_time' not in st.session_state: st.session_state['last_scan_time'] = "Never"
if 'aws_connected' not in st.session_state: st.session_state['aws_connected'] = False

# --- HELPER FUNCTIONS ---
def get_aws_client(service, creds):
    return boto3.client(
        service,
        aws_access_key_id=creds['key'],
        aws_secret_access_key=creds['secret'],
        region_name=creds['region']
    )

def run_real_time_scan(module_name="Full System"):
    with st.status(f"🚀 Running {module_name} Scan...", expanded=True) as status:
        # Mock Scan Logic (Replace with actual API calls as needed)
        time.sleep(1)
        st.session_state['cspm_results'] = pd.DataFrame([
            {"Resource": "s3-finance-bucket", "Issue": "Public Access", "Severity": "Critical"}
        ])
        st.session_state['ciem_results'] = pd.DataFrame([
            {"Identity": "admin-user-01", "Status": "Zombie (Unused)", "Severity": "High"}
        ])
        st.session_state['last_scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status.update(label="Scan Complete!", state="complete", expanded=False)

# --- MAIN TABS ---
tabs = st.tabs(["🤖 AI Dashboard", "📊 Executive", "🔌 Integration", "🔍 CSPM", "🔑 CIEM"])

# --- TAB 0: AI DASHBOARD (Bento Box Style) ---
with tabs[0]:
    st.header("🤖 AI-Powered Risk Insights")
    c1, c2 = st.columns(2)
    
    with c1:
        st.markdown(f"""
            <div class="risk-card">
                <div class="icon-box high-sev-icon">🔥</div>
                <div class="card-label">High Severity Findings</div>
                <div class="high-sev-text">{len(st.session_state['cspm_results'])}</div>
                <div class="trend-text">↑ Last 7 days</div>
            </div>
        """, unsafe_allow_html=True)

    with c2:
        st.markdown(f"""
            <div class="risk-card">
                <div class="icon-box med-risk-icon">⚠️</div>
                <div class="card-label">Identity Risks</div>
                <div class="med-risk-text">{len(st.session_state['ciem_results'])}</div>
                <div class="trend-text">— Stable</div>
            </div>
        """, unsafe_allow_html=True)

# --- TAB 2: CLOUD INTEGRATION ---
with tabs[2]:
    st.header("🔌 Connectivity")
    col_l, col_r = st.columns(2)
    with col_l:
        aws_key = st.text_input("AWS Access Key", type="password")
        aws_sec = st.text_input("AWS Secret Key", type="password")
        if st.button("Connect AWS"):
            st.session_state['aws_connected'] = True
            st.success("AWS Connected!")
