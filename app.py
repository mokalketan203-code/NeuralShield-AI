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

# --- UI/UX: MODERN HACKER THEME CSS (From Request) ---
st.markdown("""
    <style>
    /* Global Styles */
    .stApp { background-color: #0e1117; color: #ffffff; }
    
    /* Input Fields */
    .stTextArea textarea, .stTextInput input { 
        background-color: #1f2937 !important; 
        color: #e5e7eb !important; 
        border: 1px solid #374151; 
        border-radius: 8px;
    }
    
    /* Buttons */
    .stButton>button { 
        width: 100%; 
        background: linear-gradient(90deg, #00ffa3 0%, #00d4ff 100%);
        color: black; 
        font-weight: bold; 
        border: none; 
        border-radius: 8px;
        padding: 12px;
        transition: transform 0.1s ease-in-out;
    }
    .stButton>button:hover { 
        transform: scale(1.02);
        box-shadow: 0px 0px 15px rgba(0, 255, 163, 0.5);
    }

    /* Sidebar Dashboard Box */
    .dash-card {
        background-color: #1f2937;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #374151;
        margin-bottom: 15px;
        text-align: center;
    }
    .dash-val { font-size: 24px; font-weight: bold; color: #00ffa3; }
    .dash-label { font-size: 12px; color: #9ca3af; }

    /* History Cards (Glassmorphism) */
    .history-card { 
        background: rgba(255, 255, 255, 0.05); 
        backdrop-filter: blur(10px);
        padding: 10px; 
        border-radius: 8px; 
        margin-bottom: 10px; 
        color: white; 
        border-left: 4px solid #4b5563;
        transition: border-left 0.3s;
    }
    
    /* System Info Box */
    .sys-info {
        background-color: #111827;
        padding: 10px;
        border-radius: 8px;
        border: 1px solid #374151;
        margin-bottom: 20px;
        font-size: 12px;
    }
    </style>
""", unsafe_allow_html=True)

# --- LOAD MODELS ---
try:
    tfidf = joblib.load('models/vectorizer.pkl')
    model = joblib.load('models/model.pkl')
except FileNotFoundError:
    st.error("⚠️ Model files not found. Please run 'train.py' first.")
    st.stop()

# --- HELPER FUNCTIONS ---
def check_rate_limit():
    if 'last_request_time' not in st.session_state:
        st.session_state.last_request_time = 0
    current_time = time.time()
    if current_time - st.session_state.last_request_time < 2:
        return False
    st.session_state.last_request_time = current_time
    return True

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

def sanitize_input(text):
    return html.escape(text)

def expand_url(short_url):
    try:
        response = requests.head(short_url, allow_redirects=True, timeout=5)
        return response.url
    except:
        return None

def extract_urls(text):
    return re.findall(r'(https?://\S+|www\.\S+)', text)

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

# --- CRITICAL PRODUCTION FUNCTION: PDF FIX ---
def clean_text_for_pdf(text):
    """
    Removes characters that FPDF (latin-1) cannot handle, 
    like smart quotes, emojis, etc.
    """
    if not isinstance(text, str): return str(text)
    replacements = {
        '\u2018': "'", '\u2019': "'", '\u201c': '"', '\u201d': '"',
        '\u2013': '-', '\u2014': '-'
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
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
    
    safe_snippet = clean_text_for_pdf(text[:300])
    pdf.multi_cell(0, 10, txt=f"Analyzed Content Snippet:\n{safe_snippet}...")
    
    return pdf.output(dest='S').encode('latin-1')

# --- SIDEBAR (UI/UX from Requirement) ---
with st.sidebar:
    st.markdown("### 📊 Live Dashboard")
    
    # Dashboard Metrics using "dash-card" style
    st.markdown(f"""
    <div class="dash-card">
        <div class="dash-val">{st.session_state.total_scans}</div>
        <div class="dash-label">Total Scans</div>
    </div>
    <div style="display: flex; gap: 10px;">
        <div class="dash-card" style="flex: 1; border-color: #ff4b4b;">
            <div class="dash-val" style="color: #ff4b4b;">{st.session_state.phishing_count}</div>
            <div class="dash-label">Threats</div>
        </div>
        <div class="dash-card" style="flex: 1; border-color: #00ffa3;">
            <div class="dash-val" style="color: #00ffa3;">{st.session_state.safe_count}</div>
            <div class="dash-label">Safe</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # System Info
    st.markdown(f"""
    <div class="sys-info">
        <b style="color:white;">SYSTEM STATUS</b><br>
        <span style="color:gray;">Version:</span> {MODEL_VERSION}<br>
        <span style="color:gray;">Engine:</span> {MODEL_TYPE}<br>
        <span style="color:#00ffa3;">● System Online</span>
    </div>
    """, unsafe_allow_html=True)
    
    # History Log
    st.markdown("### 🕒 Recent Scans")
    
    if st.session_state.history:
        for scan in st.session_state.history:
            border_color = "#ff4b4b" if scan['status'] == "PHISHING" else "#00ffa3"
            st.markdown(f"""
            <div class="history-card" style="border-left: 4px solid {border_color};">
                <div style="font-weight:bold; font-size:14px;">{scan['status']}</div>
                <div style="font-size:12px; color:#9ca3af;">{scan['email']}</div>
                <div style="font-size:11px; color:#6b7280; margin-top:4px;">Confidence: {scan['conf']}</div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No scan history yet.")
    
    st.markdown("---")
    show_debug = st.checkbox("🐞 Debug Mode")

# --- MAIN PAGE (UI/UX from Requirement) ---
# Header
col1, col2 = st.columns([0.1, 0.9])
with col1:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=100)
with col2:
    st.title("NeuralShield")

st.markdown("### Advanced Phishing Email Analysis System")

col_input, col_viz = st.columns([2, 1])

with col_input:
    # Inputs matching the requested UI (Standard inputs with labels)
    sender_email = st.text_input("Sender Email Address (Optional):", placeholder="e.g. support@company.com")
    email_text = st.text_area("Email Content:", height=250, placeholder="Paste the suspicious email text here...")

    if st.button("⚡ START SECURITY SCAN"):
        if not check_rate_limit():
            st.error("⏳ RATE LIMIT EXCEEDED: Please wait 2 seconds between scans.")
        elif email_text:
            st.session_state.total_scans += 1
            
            safe_text = sanitize_input(email_text)
            safe_sender = sanitize_input(sender_email)
            
            # --- PRODUCTION LOGIC START ---
            st.session_state.analyzed = True
            st.session_state.text = safe_text
            st.session_state.sender = safe_sender
            
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
            
            st.session_state.raw_proba = proba 
            st.session_state.prediction = prediction
            st.session_state.confidence = confidence
            st.session_state.urls = extract_urls(safe_text)
            st.session_state.ips = extract_ips(safe_text)
            st.session_state.keywords = find_keywords(safe_text)
            
            try:
                if len(transformed_text) > 0:
                    wc = WordCloud(width=600, height=300, background_color='#0e1117', colormap='Reds').generate(transformed_text)
                    st.session_state.wordcloud_fig = plt.figure(figsize=(6, 3), facecolor='#0e1117')
                    plt.imshow(wc, interpolation='bilinear')
                    plt.axis("off")
                else:
                    st.session_state.wordcloud_fig = None
            except ValueError:
                st.session_state.wordcloud_fig = None
            
            st.session_state.history.insert(0, {
                "email": safe_sender if safe_sender else "Unknown Sender",
                "status": status,
                "conf": f"{round(confidence*100, 1)}%"
            })
            
            st.rerun() # Keep rerun to refresh sidebar metrics immediately
            # --- PRODUCTION LOGIC END ---
        else:
            st.warning("⚠️ Please enter text to analyze.")

# RESULTS AREA
if st.session_state.analyzed:
    st.markdown("### 📊 Analysis Report")
    r1, r2 = st.columns([2, 1])
    
    with r1:
        prediction = st.session_state.prediction
        confidence = st.session_state.confidence
        
        if prediction == 1:
            st.error(f"🚨 **PHISHING DETECTED** (Confidence: {round(confidence*100, 2)}%)")
        else:
            st.success(f"✅ **SAFE EMAIL** (Confidence: {round(confidence*100, 2)}%)")
            
        # PRODUCTION: PDF Generation using the CLEAN function
        pdf_bytes = create_pdf_report(
            st.session_state.text, st.session_state.sender, prediction, confidence, 
            st.session_state.urls, st.session_state.keywords, st.session_state.ips
        )
        st.download_button("📥 Download PDF Report", pdf_bytes, "scan_report.pdf", "application/pdf")
        
        if st.session_state.sender:
            header_warnings = check_sender_mismatch(st.session_state.sender, st.session_state.text)
            if header_warnings:
                for w in header_warnings:
                    st.warning(w)
            else:
                st.info("✅ Sender domain matches email context.")

        if st.session_state.urls:
            st.markdown("#### 🔗 URL Analysis")
            target_url = st.session_state.urls[0]
            st.code(target_url, language="text")
            
            typo_warning = check_typosquatting(target_url)
            if typo_warning:
                st.error(typo_warning)

            c1, c2 = st.columns(2)
            with c1:
                with st.spinner("Checking WHOIS..."):
                    info = get_domain_info(target_url)
                    if info:
                        st.write(f"**Registrar:** {info['registrar']}")
                        st.write(f"**Created:** {info['creation_date']}")
            with c2:
                with st.spinner("Checking Redirects..."):
                    real_dest = expand_url(target_url)
                    if real_dest and real_dest != target_url:
                        st.error(f"⚠️ Redirects to: `{real_dest}`")
                    elif real_dest:
                        st.success("✅ Direct Link")

    with r2:
        st.markdown("#### ☁️ Threat Cloud")
        if st.session_state.wordcloud_fig:
            st.pyplot(st.session_state.wordcloud_fig)
        else:
            st.caption("No word cloud data available.")
        
        st.markdown("#### 🧠 AI Confidence")
        st.progress(st.session_state.confidence)
        
        if show_debug:
            st.caption("Raw Probabilities:")
            prob_df = pd.DataFrame({"Type": ["Safe", "Phishing"], "Prob": st.session_state.raw_proba})
            st.dataframe(prob_df, hide_index=True)

    st.markdown("---")
    with st.expander("📝 Flag Incorrect Result"):
        f1, f2 = st.columns(2)
        if f1.button("Mark as SAFE"):
            save_feedback(st.session_state.text, "Safe")
            st.toast("Feedback Saved: Safe")
        if f2.button("Mark as PHISHING"):
            save_feedback(st.session_state.text, "Phishing")
            st.toast("Feedback Saved: Phishing")
