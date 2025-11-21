#Importing Libraries
import streamlit as st
import re
import tldextract

#Domain check function 

def check_domain(domain):
    score = 0
    reasons = []

    # Character replacements (0→o, 1→l, 5→s)
    replacements = {"0": "o", "1": "l", "5": "s", "I": "l"}
    for char in replacements:
        if char in domain:
            score += 20
            reasons.append("Suspicious character replacement detected")

    # Suspicious keywords
    keywords = ["security", "alert", "verify", "update", "login", "notice", "support"]
    for w in keywords:
        if w in domain.lower():
            score += 20
            reasons.append(f"Suspicious keyword detected: {w}")

    # Suspicious domain endings
    bad_tlds = [".xyz", ".top", ".click", ".live", ".info", ".vip", ".rest"]
    for t in bad_tlds:
        if domain.endswith(t):
            score += 20
            reasons.append(f"Suspicious TLD detected: {t}")

    return score, reasons

#Adding URL Check
def check_url(url):
    score = 0
    reasons = []

    if not url.startswith("https://"):
        score += 20
        reasons.append("URL has HTTPS")

    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix

    domain_score, domain_reasons = check_domain(domain)
    score += domain_score
    reasons.extend(domain_reasons)

    return score, reasons

#Adding urgent word checking 
def check_urgency(text):
    score = 0
    reasons = []

    urgent_words = ["asap", "immediate", "24 hours", "last chance", "urgent"]
    for w in urgent_words:
        if w in text.lower():
            score += 10
            reasons.append(f"Urgent language detected: {w}")

    return score, reasons

#Adding senstive Info Check
def check_sensitive_info(text):
    score = 0
    reasons = []

    sensitive_words = ["password", "login", "reset", "refund", "deposit", "account lock"]
    for w in sensitive_words:
        if w in text.lower():
            score += 30
            reasons.append(f"Sensitive info request detected: {w}")

    return score, reasons

#Putting all the logics together the brain of the system 

def analyze_input(user_input,attachment):
    total_score = 0
    reasons = []   # This will store ALL warnings from all checks

    # 1. URL check (only runs if a URL exists)
    if "http" in user_input.lower():
        url_score, url_reasons = check_url(user_input)
        total_score += url_score
        reasons.extend(url_reasons)

    # 2. Urgent wording check
    urg_score, urg_reasons = check_urgency(user_input)
    total_score += urg_score
    reasons.extend(urg_reasons)

    # 3. Sensitive information check
    sens_score, sens_reasons = check_sensitive_info(user_input)
    total_score += sens_score
    reasons.extend(sens_reasons)

    #Attachment check (user indicated)
    if attachment:
        total_score += 20
        reasons.append("Email contains an attachment - high risk")

    # Return final risk score + list of reasons
    return total_score, reasons


# User Interface as per the requiremnt # 

st.title("PhishShield by PingFlyod ")

# User text input area (URL or email)
user_input = st.text_area("Enter a URL or Email Text Below:")

#Attachment Checkbox
attachment = st.checkbox("Does the email contain an attachment?")

#File upload
uploaded_file = st.file_uploader("Upload an email or attachment (txt, pdf, docx):", type=["txt", "pdf", "docx"])


# Button that triggers analysis
if st.button("Check for Phishing"):

    score, reasons = analyze_input(user_input,attachment)

    # Display result with color
    if score < 30:
        st.success(f"SAFE (Score: {score})")
    elif score < 70:
        st.warning(f"SUSPICIOUS (Score: {score})")
    else:
        st.error(f"HIGH RISK - LIKELY PHISHING (Score: {score})")

    # Display reasons below the result
    st.write("### Reasons Detected:")
    for r in reasons:
        st.write("- " + r)

