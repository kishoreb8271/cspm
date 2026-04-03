st.markdown("""
    <style>
    /* Global Dark Theme Overrides */
    .stApp {
        background-color: #0e1117;
    }

    /* Modern Risk Card Container */
    .risk-card {
        background: #16191f;
        border: 1px solid #2d3139;
        border-radius: 20px;
        padding: 30px;
        text-align: left;
        transition: transform 0.3s ease;
    }
    
    .risk-card:hover {
        border-color: #444;
        transform: translateY(-5px);
    }

    /* Icon Container */
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

    /* High Severity (Orange) */
    .high-sev-icon { background: rgba(255, 75, 75, 0.15); color: #ff4b4b; }
    .high-sev-text { 
        background: linear-gradient(180deg, #fff 0%, #ff4b4b 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 4rem;
        font-weight: 800;
    }

    /* Medium Risk (Yellow) */
    .med-risk-icon { background: rgba(255, 184, 0, 0.15); color: #ffb800; }
    .med-risk-text { 
        background: linear-gradient(180deg, #fff 0%, #ffb800 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 4rem;
        font-weight: 800;
    }

    .card-label {
        color: #808495;
        text-transform: uppercase;
        font-size: 0.8rem;
        letter-spacing: 1.5px;
        font-weight: 700;
        margin-bottom: 5px;
    }

    .trend-text {
        color: #616675;
        font-size: 0.85rem;
        margin-top: 10px;
    }
    </style>
    """, unsafe_allow_html=True)
