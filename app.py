import streamlit as st
import joblib
import preprocess
import re
import csv
import os
import matplotlib.pyplot as plt
from wordcloud import WordCloud
import whois
from fpdf import FPDF
import html
import requests
import time
from difflib import SequenceMatcher
import pandas as pd
from datetime import datetime

# --- CONFIGURATION ---
MODEL_VERSION = "1.0.4"
MODEL_DATE = "2025-12-25"
MODEL_TYPE = "MultinomialNB (Naive Bayes)"
ICON_ARROW = "https://cdn-icons-png.flaticon.com/512/54/54366.png"
ICON_CHECK = "https://cdn-icons-png.flaticon.com/512/4561/4561511.png"
MAIN_LOGO = "https://cdn-icons-png.flaticon.com/512/2092/2092663.png"

st.set_page_config(
    page_title="NeuralShield | Cyber Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- SESSION STATE INITIALIZATION ---
if 'history' not in st.session_state: st.session_state.history = []
if 'analyzed' not in st.session_state: st.session_state.analyzed = False
if 'total_scans' not in st.session_state: st.session_state.total_scans = 0
if 'phishing_count' not in st.session_state: st.session_state.phishing_count = 0
if 'safe_count' not in st.session_state: st.session_state.safe_count = 0

# --- CUSTOM CSS ---
st.markdown(f"""
    <style>
    /* Main Background */
    .stApp {{
        background-color: #2b2b2b;
        color: #ffffff;
        font-family: 'Arial', sans-serif;
    }}
    
    /* CENTER THE CONTENT ON DESKTOP */
    .block-container {{
        max_width: 1000px;
        margin: 0 auto;
        padding-top: 2rem;
        padding-bottom: 2rem;
    }}

    /* Sidebar Background */
    [data-testid="stSidebar"] {{
        background-color: #363636;
        padding-top: 20px;
    }}

    /* Input Fields */
    .stTextInput input, .stTextArea textarea {{
        background-color: #474747 !important;
        color: #ffffff !important;
        border: none;
        border-radius: 12px;
        padding: 15px;
    }}
    ::placeholder {{ color: #a0a0a0 !important; opacity: 1; }}

    /* Analyze Button */
    .stButton>button {{
        width: 100%;
        background-color: #e0a899;
        color: #000000;
        font-weight: bold;
        border: none;
        border-radius: 25px;
        padding: 15px 20px;
        font-size: 16px;
        display: flex;
        align-items: center;
        justify-content: center;
    }}
    .stButton>button::before {{ content: "⚡ "; font-size: 20px; margin-right: 10px; }}
    .stButton>button:hover {{ background-color: #d49788; }}

    /* Sidebar Dashboard Cards */
    .dash-card-large {{
        background-color: #474747;
        border-radius: 15px;
        padding: 20px;
        text-align: center;
        margin-bottom: 15px;
        height: 120px;
        display: flex;
        flex-direction: column;
        justify-content: center;
    }}
    .dash-card-small {{
        background-color: #474747;
        border-radius: 15px;
        padding: 15px;
        text-align: center;
        height: 100px;
        display: flex;
        flex-direction: column;
        justify-content: center;
        flex: 1;
    }}
    .dash-val {{ font-size: 32px; font-weight: bold; margin-bottom: 5px; }}
    .dash-label {{ font-size: 14px; color: #c0c0c0; }}

    /* System Status Card */
    .sys-card {{
        background-color: #474747;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 20px;
        font-size: 13px;
        line-height: 1.6;
        color: #d0d0d0;
    }}
    .sys-title {{ font-weight: bold; color: #ffffff; margin-bottom: 10px; display: block; }}
    .sys-online {{ color: #00ffa3; font-weight: bold; }}

    /* Sidebar Headers */
    .sidebar-header {{
        display: flex;
        align-items: center;
        font-size: 18px;
        font-weight: bold;
        margin-bottom: 15px;
        color: #ffffff;
    }}
    .sidebar-header img {{ margin-right: 10px; width: 20px; height: 20px; }}

    /* Checkbox */
    .custom-checkbox {{
        display: flex;
        align-items: center;
        font-size: 16px;
        color: #ffffff;
        cursor: pointer;
    }}
    .custom-checkbox img {{ margin-right: 10px; width: 24px; height: 24px; }}

    /* Main Title Styling */
    .main-title-container {{
        display: flex;
        align-items: center;
        margin-bottom: 10px;
    }}
    .main-logo {{ width: 60px; margin-right: 20px; }}
    .main-title-text h1 {{ margin: 0; font-size: 48px; font-weight: bold; }}
    .main-subtitle {{ font-size: 20px; color: #c0c0c0; margin-bottom: 40px; }}

    /* Hide Elements */
    #MainMenu {{visibility: hidden;}}
    footer {{visibility: hidden;}}
    .stDeployButton {{visibility: hidden;}}
    [data-testid="stHeader"] {{visibility: hidden;}}
    </style>
""", unsafe_allow_html=True)

# --- LOAD MODELS & HELPERS ---
try:
    tfidf = joblib.load('models/vectorizer.pkl')
    model = joblib.load('models/model.pkl')
except FileNotFoundError:
    st.error("⚠️ Model files not found. Please run 'train.py' first.")
    st.stop()

def sanitize_input(text): return html.escape(text)
def extract_urls(text): return re.findall(r'(https?://\S+|www\.\S+)', text)
def check_rate_limit():
    if 'last_request_time' not in st.session_state: st.session_state.last_request_time = 0
    if time.time() - st.session_state.last_request_time < 2: return False
    st.session_state.last_request_time = time.time()
    return True

# --- HELPER: FIX PDF ENCODING ---
def clean_text_for_pdf(text):
    """
    Removes characters that FPDF (latin-1) cannot handle, 
    like smart quotes, emojis, etc.
    """
    if not isinstance(text, str): return str(text)
    # Replace common "smart" quotes with standard ASCII ones
    replacements = {
        '\u2018': "'", '\u2019': "'", '\u201c': '"', '\u201d': '"',
        '\u2013': '-', '\u2014': '-'
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    
    # Force encode to latin-1, replacing unknown chars with '?'
    return text.encode('latin-1', 'replace').decode('latin-1')

def create_pdf_report(text, sender, prediction, confidence, urls, keywords, ips):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="NeuralShield Security Report", ln=True, align='C')
    pdf.ln(10)
    
    status = "PHISHING DETECTED" if prediction == 1 else "SAFE EMAIL"
    pdf.set_font("Arial", 'B', 14)
    pdf.set_text_color(255, 0, 0) if prediction == 1 else pdf.set_text_color(0, 128, 0)
    pdf.cell(200, 10, txt=f"Analysis Result: {status}", ln=True)
    
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Confidence Score: {round(confidence*100, 2)}%", ln=True)
    pdf.cell(200, 10, txt=f"Sender Identity: {clean_text_for_pdf(sender) if sender else 'Unknown'}", ln=True)
    pdf.cell(200, 10, txt=f"Model Version: {MODEL_VERSION}", ln=True)
    pdf.ln(10)
    
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Threat Intelligence Found:", ln=True)
    pdf.set_font("Arial", size=11)
    
    if urls:
        pdf.cell(200, 10, txt=f"- Suspicious Links: {len(urls)} found", ln=True)
        for url in urls:
            clean_url = clean_text_for_pdf(url)
            pdf.cell(200, 10, txt=f"  * {clean_url[:50]}...", ln=True)
    else:
        pdf.cell(200, 10, txt="- No suspicious links detected.", ln=True)
        
    if ips:
        pdf.cell(200, 10, txt=f"- Raw IP Addresses: {', '.join(ips)}", ln=True)
        
    if keywords:
        clean_kws = [clean_text_for_pdf(k) for k in keywords]
        pdf.cell(200, 10, txt=f"- Trigger Words: {', '.join(clean_kws)}", ln=True)
    else:
        pdf.cell(200, 10, txt="- No trigger words detected.", ln=True)
        
    pdf.ln(10)
    pdf.set_font("Arial", 'I', 10)
    
    # Clean the main text snippet too
    safe_snippet = clean_text_for_pdf(text[:300])
    pdf.multi_cell(0, 10, txt=f"Analyzed Content Snippet:\n{safe_snippet}...")
    
    return pdf.output(dest='S').encode('latin-1')

# --- OTHER HELPERS ---
def extract_ips(text):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return re.findall(ip_pattern, text)

def check_typosquatting(url):
    targets = ['google.com', 'amazon.com', 'facebook.com', 'apple.com', 'netflix.com', 'paypal.com', 'microsoft.com', 'instagram.com', 'whatsapp.com']
    try:
        domain = url.split("//")[-1].split("/")[0].replace("www.", "")
        for target in targets:
            similarity = SequenceMatcher(None, domain, target).ratio()
            if 0.80 < similarity < 1.0:
                return f"⚠️ **Typosquatting Alert:** This domain `{domain}` mimics `{target}` ({round(similarity*100)}% Match)"
    except:
        pass
    return None

def expand_url(short_url):
    try:
        response = requests.head(short_url, allow_redirects=True, timeout=5)
        return response.url
    except:
        return None

def get_domain_info(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        w = whois.whois(domain)
        return {"registrar": w.registrar, "creation_date": w.creation_date, "org": w.org}
    except:
        return None

def find_keywords(text):
    suspicious_words = ['urgent', 'verify', 'account', 'bank', 'suspended', 'click here', 'password', 'reward', 'lottery', 'update']
    return [word for word in suspicious_words if word in text.lower()]

def check_sender_mismatch(sender, body):
    trusted_domains = {
        'amazon': 'amazon.com', 'paypal': 'paypal.com', 'google': 'google.com',
        'apple': 'apple.com', 'netflix': 'netflix.com', 'bank of america': 'bankofamerica.com'
    }
    warnings = []
    sender_domain = sender.split('@')[-1].lower() if '@' in sender else ''
    for company, official_domain in trusted_domains.items():
        if company in body.lower():
            if official_domain not in sender_domain:
                warnings.append(f"⚠️ **Impersonation Risk:** Email mentions **{company.title()}**, but sender is `{sender_domain}` (expected `{official_domain}`).")
    return warnings

def save_feedback(text, label):
    file_exists = os.path.isfile('feedback.csv')
    with open('feedback.csv', mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(['text', 'user_suggested_label'])
        writer.writerow([text, label])

# --- SIDEBAR LAYOUT ---
with st.sidebar:
    st.markdown(f"""
        <div class="sidebar-header">
            <img src="{ICON_ARROW}"> Live Dashboard
        </div>
        <div class="dash-card-large">
            <div class="dash-val">{st.session_state.total_scans}</div>
            <div class="dash-label">Total Scans</div>
        </div>
        <div style="display: flex; gap: 15px;">
            <div class="dash-card-small">
                <div class="dash-val" style="color:#ff4b4b">{st.session_state.phishing_count}</div>
                <div class="dash-label">Threats</div>
            </div>
            <div class="dash-card-small">
                <div class="dash-val" style="color:#00ffa3">{st.session_state.safe_count}</div>
                <div class="dash-label">Safe</div>
            </div>
        </div>
        <br>
        <div class="sys-card">
            <span class="sys-title">SYSTEM STATUS</span>
            Version: {MODEL_VERSION}<br>
            Engine: {MODEL_TYPE}<br>
            <span class="sys-online">● System Online</span>
        </div>
    """, unsafe_allow_html=True)

    CLOCK_ICON = "https://cdn-icons-png.flaticon.com/512/2784/2784459.png"
    st.markdown(f'<div class="sidebar-header"><img src="{CLOCK_ICON}"> Recent Scans</div>', unsafe_allow_html=True)

    if not st.session_state.history:
        st.markdown('<div style="text-align:center; color:#c0c0c0; font-style:italic;">No scan history yet.</div>', unsafe_allow_html=True)
    else:
        for scan in st.session_state.history[:3]:
            color = "#ff4b4b" if scan['status'] == "PHISHING" else "#00ffa3"
            st.markdown(f"""
            <div style="background-color: #474747; padding: 10px; border-radius: 8px; margin-bottom: 8px; border-left: 4px solid {color}; font-size: 13px;">
                <b>{scan['status']}</b> <span style="color:#a0a0a0;">({scan['conf']})</span><br>
                <span style="color:#808080; font-size: 11px;">{scan['email'][:25]}...</span>
            </div>
            """, unsafe_allow_html=True)

    st.markdown(f"""
        <hr style="border-color: #474747; margin-top: 30px;">
        <div class="custom-checkbox">
            <img src="{ICON_CHECK}"> Debug Mode
        </div>
    """, unsafe_allow_html=True)

# --- MAIN CONTENT LAYOUT ---
st.markdown(f"""
    <div class="main-title-container">
        <img src="{MAIN_LOGO}" class="main-logo">
        <div class="main-title-text">
            <h1>NeuralShield</h1>
        </div>
    </div>
    <div class="main-subtitle">Advanced Phishing Email Analysis System</div>
""", unsafe_allow_html=True)

col1, col2 = st.columns([1, 2])
with col1:
    st.markdown('<p style="font-size: 16px; margin-bottom: 10px;">Sender Email Address (Optional):</p>', unsafe_allow_html=True)
    sender_email = st.text_input("Sender Email", placeholder="e.g. support@company.com", label_visibility="collapsed")

    st.markdown('<p style="font-size: 16px; margin-top: 20px; margin-bottom: 10px;">Paste Email Content:</p>', unsafe_allow_html=True)
    email_text = st.text_area("Email Content", height=250, placeholder="Paste suspicious email text here...", label_visibility="collapsed")
    
    st.markdown("<br>", unsafe_allow_html=True)

    if st.button("ANALYZE SECURITY RISK"):
        if not check_rate_limit():
            st.error("⏳ Please wait 2 seconds between scans.")
        elif email_text:
            st.session_state.total_scans += 1
            safe_text = sanitize_input(email_text)
            safe_sender = sanitize_input(sender_email)
            
            transformed_text = preprocess.transform_text(safe_text)
            vector_input = tfidf.transform([transformed_text])
            prediction = model.predict(vector_input)[0]
            proba = model.predict_proba(vector_input)[0]
            confidence = proba[prediction]

            if prediction == 1:
                st.session_state.phishing_count += 1
                status = "PHISHING"
            else:
                st.session_state.safe_count += 1
                status = "SAFE"
            
            st.session_state.history.insert(0, {"email": safe_sender or "Unknown", "status": status, "conf": f"{round(confidence*100)}%"})
            st.session_state.analyzed = True
            
            # Save variables for report generation
            st.session_state.text = safe_text
            st.session_state.sender = safe_sender
            st.session_state.prediction = prediction
            st.session_state.confidence = confidence
            st.session_state.urls = extract_urls(safe_text)
            st.session_state.ips = extract_ips(safe_text)
            st.session_state.keywords = find_keywords(safe_text)
            st.session_state.raw_proba = proba

            st.rerun()

# Results Section
if st.session_state.analyzed:
    with col1:
        st.markdown("---")
        last_scan = st.session_state.history[0]
        if last_scan['status'] == "PHISHING":
            st.error(f"🚨 **PHISHING DETECTED** (Confidence: {last_scan['conf']})")
        else:
            st.success(f"✅ **SAFE EMAIL** (Confidence: {last_scan['conf']})")
        
        # --- GENERATE PDF ---
        # We pass the cleaned text to avoid the latin-1 encoding error
        pdf_bytes = create_pdf_report(
            st.session_state.text, st.session_state.sender, st.session_state.prediction, st.session_state.confidence, 
            st.session_state.urls, st.session_state.keywords, st.session_state.ips
        )
        st.download_button("📥 Download PDF Report", pdf_bytes, "scan_report.pdf", "application/pdf")
        
        st.info("Check the sidebar for scan history.")
