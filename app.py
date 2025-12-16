import streamlit as st
import tldextract
import pandas as pd
import re

try:
    import PyPDF2
except Exception:
    PyPDF2 = None

try:
    import docx
except Exception:
    docx = None

if "last_score" not in st.session_state:
    st.session_state["last_score"] = None
if "last_reasons" not in st.session_state:
    st.session_state["last_reasons"] = []
if "last_attachment" not in st.session_state:
    st.session_state["last_attachment"] = False
if "score_history" not in st.session_state:
    st.session_state["score_history"] = []
if "full_history" not in st.session_state:
    st.session_state["full_history"] = []

SUSPICIOUS_KEYWORDS = [
    "security", "alert", "verify", "update", "login", "notice", "support",
    "secure", "unlock", "validate", "confirm", "account", "billing",
    "recovery", "reset", "authentication", "invoice", "customer",
    "service", "official", "verification", "limitedtime", "payment"
]

BAD_TLDS = [
    ".xyz", ".top", ".click", ".live", ".info", ".vip", ".rest",
    ".cam", ".shop", ".online", ".monster", ".cyou",
    ".ml", ".tk", ".ga", ".gq"
]

URGENT_WORDS = [
    "asap", "immediately", "urgent", "urgent action",
    "urgent action required", "final notice", "last chance",
    "24 hours", "respond now", "act now", "time sensitive",
    "your account will be closed"
]

SENSITIVE_WORDS = [
    "password", "login", "reset", "refund", "deposit", "account lock",
    "bank", "routing number", "ssn", "social security", "credit card",
    "debit card", "pin", "otp", "one time password", "mfa", "2fa",
    "identity verification", "billing", "payment details", "gift card",
    "wire transfer", "credentials", "secure form", "kyc verification"
]

def get_risk_label(score):
    if score < 30:
        return "SAFE"
    elif score < 70:
        return "SUSPICIOUS"
    else:
        return "HIGH RISK"

def extract_urls(text):
    return re.findall(r"(https?://[^\s]+)", text, flags=re.IGNORECASE)

def clean_token(token):
    return token.strip(".,;:()[]{}<>\"'!?")

def check_domain(domain):
    domain = domain.lower()
    reasons = []
    replacements = {"0": "o", "1": "l", "5": "s", "i": "l"}

    for char in replacements:
        if char in domain:
            reasons.append(f"Suspicious character substitution detected: '{char}'")
            break

    for w in SUSPICIOUS_KEYWORDS:
        if w in domain:
            reasons.append(f"Suspicious keyword found in domain: '{w}'")
            break

    for t in BAD_TLDS:
        if domain.endswith(t):
            reasons.append(f"High-risk TLD detected: '{t}'")
            break

    return (len(reasons) > 0), reasons

def check_url(url):
    reasons = []
    non_https = not url.lower().startswith("https://")
    if non_https:
        reasons.append("URL is not using HTTPS (security risk)")

    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}".lower() if ext.domain and ext.suffix else ""

    domain_flag = False
    domain_reasons = []
    if domain:
        domain_flag, domain_reasons = check_domain(domain)
        reasons.extend(domain_reasons)

    url_flag = non_https or domain_flag
    return url_flag, non_https, domain, reasons

def check_urgency(text):
    text = text.lower()
    found = []
    for w in URGENT_WORDS:
        if w in text:
            found.append(f"Urgent or threatening language detected: '{w}'")
    return (len(found) > 0), found

def check_sensitive_info(text):
    text = text.lower()
    found = []
    for w in SENSITIVE_WORDS:
        if w in text:
            found.append(f"Sensitive information request detected: '{w}'")
    return (len(found) > 0), found

def read_uploaded_text(uploaded_file):
    if uploaded_file is None:
        return ""
    name = uploaded_file.name.lower()

    if name.endswith(".txt"):
        return uploaded_file.read().decode("utf-8", errors="ignore")

    if name.endswith(".pdf"):
        if PyPDF2 is None:
            return ""
        try:
            reader = PyPDF2.PdfReader(uploaded_file)
            text = ""
            for page in reader.pages:
                text += (page.extract_text() or "") + "\n"
            return text.strip()
        except Exception:
            return ""

    if name.endswith(".docx"):
        if docx is None:
            return ""
        try:
            d = docx.Document(uploaded_file)
            return "\n".join(p.text for p in d.paragraphs).strip()
        except Exception:
            return ""

    return ""

def analyze_input(user_input, attachment, irregular_time=False, uploaded_filename=None):
    total_score = 0
    reasons = []

    urls = extract_urls(user_input)

    url_flag_any = False
    domain_flag_any = False
    non_https_any = False

    for u in urls:
        url_flag, non_https, dom, url_reasons = check_url(u)
        if url_flag:
            url_flag_any = True
            reasons.append(f"Suspicious link detected: {u}")
        if non_https:
            non_https_any = True
        reasons.extend(url_reasons)

    tokens = user_input.lower().split()
    for token in tokens:
        token = clean_token(token)
        if "." in token and "@" not in token and "/" not in token:
            d_flag, d_reasons = check_domain(token)
            if d_flag:
                domain_flag_any = True
                reasons.extend(d_reasons)

    sens_flag, sens_reasons = check_sensitive_info(user_input)
    reasons.extend(sens_reasons)

    urg_flag, urg_reasons = check_urgency(user_input)
    reasons.extend(urg_reasons)

    exec_attachment_flag = False
    if uploaded_filename:
        risky_exts = (".exe", ".bat", ".cmd", ".js", ".vbs", ".scr", ".ps1")
        if uploaded_filename.lower().endswith(risky_exts):
            exec_attachment_flag = True
            reasons.append(f"High-risk attachment type detected: {uploaded_filename}")

    if domain_flag_any:
        total_score += 40
    if url_flag_any:
        total_score += 40
    if domain_flag_any and url_flag_any:
        total_score += 20

    if sens_flag:
        total_score += 20

    if urg_flag:
        total_score += 5
    if attachment:
        total_score += 5
        reasons.append("Attachment present")
    if exec_attachment_flag:
        total_score += 10
    if irregular_time:
        total_score += 5
        reasons.append("Unusual email sent time selected")

    if non_https_any:
        reasons.append("One or more links are not HTTPS")

    total_score = min(total_score, 100)
    reasons = list(dict.fromkeys(reasons))
    return total_score, reasons

st.title("PhishShield by PingFloyd (YorkU)")

st.markdown(
    """
    **Learn more about phishing:**  
    [Government Cybersecurity Guide](https://www.cyber.gc.ca/en)
    """
)

tab_check, tab_dashboard, tab_history = st.tabs(["Phishing Checker", "Dashboard", "History"])

with tab_check:
    st.subheader("Phishing Checker")
    user_input = st.text_area("Enter a URL or Email Text Below:")
    attachment = st.checkbox("Does the email contain an attachment?")
    irregular_time = st.checkbox("Was the email sent at an unusual time (e.g., 2–4 AM)?")

    uploaded_file = st.file_uploader(
        "Upload an email or attachment (txt, pdf, docx):",
        type=["txt", "pdf", "docx"]
    )

    if uploaded_file and not user_input.strip():
        extracted_text = read_uploaded_text(uploaded_file)
        if extracted_text:
            user_input = extracted_text
            st.info(f"Loaded text from uploaded file: {uploaded_file.name}")
        else:
            if uploaded_file.name.lower().endswith(".pdf") and PyPDF2 is None:
                st.warning("Install PDF support: pip install PyPDF2")
            if uploaded_file.name.lower().endswith(".docx") and docx is None:
                st.warning("Install DOCX support: pip install python-docx")

    if st.button("Check for Phishing"):
        if not user_input.strip():
            st.warning("Please enter text or upload a file.")
        else:
            uploaded_name = uploaded_file.name if uploaded_file else None
            score, reasons = analyze_input(
                user_input=user_input,
                attachment=attachment,
                irregular_time=irregular_time,
                uploaded_filename=uploaded_name
            )

            st.session_state["last_score"] = score
            st.session_state["last_reasons"] = reasons
            st.session_state["last_attachment"] = attachment
            st.session_state["score_history"].append(score)

            st.session_state["full_history"].append({
                "Score": score,
                "Attachment": attachment,
                "Irregular Time": irregular_time,
                "Uploaded File": uploaded_name if uploaded_name else "None",
                "Reasons": reasons,
                "Input": user_input
            })

            label = get_risk_label(score)
            if score < 30:
                st.success(f"{label} (Score: {score})")
            elif score < 70:
                st.warning(f"{label} (Score: {score})")
            else:
                st.error(f"{label} (Score: {score})")

            st.write("### Reasons Detected:")
            if reasons:
                for r in reasons:
                    st.write(f"- {r}")
            else:
                st.write("- No clear phishing indicators detected.")

with tab_dashboard:
    st.subheader("Session Dashboard")
    if st.session_state["last_score"] is None:
        st.info("No scans yet. Run a scan in the Phishing Checker tab.")
    else:
        score = st.session_state["last_score"]
        reasons = st.session_state["last_reasons"]
        st.write(f"**Last Scan Score:** {score}")
        st.write(f"**Risk Level:** {get_risk_label(score)}")
        st.write(f"**Attachment in last email:** {'Yes' if st.session_state['last_attachment'] else 'No'}")

        st.write("### Warnings from last scan:")
        if reasons:
            for r in reasons:
                st.write(f"- {r}")
        else:
            st.write("- No warnings.")

        if len(st.session_state["score_history"]) > 1:
            st.write("### Score Trend (Session)")
            st.line_chart(st.session_state["score_history"])
        else:
            st.info("Run more scans to see a trend chart.")

with tab_history:
    st.subheader("Full Scan History")
    if not st.session_state["full_history"]:
        st.info("No scan history available yet.")
    else:
        rows = []
        for i, entry in enumerate(st.session_state["full_history"], start=1):
            rows.append({
                "Scan No.": i,
                "Score": entry["Score"],
                "Risk Level": get_risk_label(entry["Score"]),
                "Attachment": "Yes" if entry["Attachment"] else "No",
                "Irregular Time": "Yes" if entry.get("Irregular Time") else "No",
                "Uploaded File": entry.get("Uploaded File", "None"),
                "Input": entry["Input"],
                "Reasons": "; ".join(entry["Reasons"]) if entry["Reasons"] else "None"
            })

        df_history = pd.DataFrame(rows)
        st.dataframe(df_history, use_container_width=True)

        st.download_button(
            "Download History as CSV",
            df_history.to_csv(index=False).encode("utf-8"),
            "phishshield_history.csv",
            "text/csv"
        )
