# ==============================================================
#  PhishShield by PingFloyd (YorkU)
#  Simple Streamlit app to detect possible phishing emails/URLs
# ==============================================================

import streamlit as st
import tldextract
import pandas as pd  # Used for history table


# =======================================================================
#                INITIALIZE SESSION STATE FOR DASHBOARD + HISTORY
# =======================================================================

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


# =======================================================================
#                       PHISHING SIGNAL DEFINITIONS
# =======================================================================

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


# =======================================================================
#                     RISK LEVEL LABEL (NO EMOJIS)
# =======================================================================

def get_risk_label(score):
    if score < 30:
        return "SAFE"
    elif score < 70:
        return "SUSPICIOUS"
    else:
        return "HIGH RISK"


# =======================================================================
#                           DOMAIN CHECK
# =======================================================================

def check_domain(domain):
    score = 0
    reasons = []

    replacements = {"0": "o", "1": "l", "5": "s", "I": "l"}

    for char in replacements:
        if char in domain:
            score += 20
            reasons.append(f"Suspicious character substitution detected: '{char}'")

    for w in SUSPICIOUS_KEYWORDS:
        if w in domain.lower():
            score += 20
            reasons.append(f"Suspicious keyword found in domain: '{w}'")

    for t in BAD_TLDS:
        if domain.endswith(t):
            score += 20
            reasons.append(f"High-risk TLD detected: '{t}'")

    return score, reasons


# =======================================================================
#                           URL CHECK
# =======================================================================

def check_url(url):
    score = 0
    reasons = []

    if not url.startswith("https://"):
        score += 20
        reasons.append("URL is not using HTTPS (security risk)")

    ext = tldextract.extract(url)
    domain = ext.domain + "." + ext.suffix

    domain_score, domain_reasons = check_domain(domain)
    score += domain_score
    reasons.extend(domain_reasons)

    return score, reasons


# =======================================================================
#                           URGENCY CHECK
# =======================================================================

def check_urgency(text):
    score = 0
    reasons = []

    for w in URGENT_WORDS:
        if w in text.lower():
            score += 10
            reasons.append(f"Urgent or threatening language detected: '{w}'")

    return score, reasons


# =======================================================================
#                     SENSITIVE INFORMATION CHECK
# =======================================================================

def check_sensitive_info(text):
    score = 0
    reasons = []

    for w in SENSITIVE_WORDS:
        if w in text.lower():
            score += 30
            reasons.append(f"Sensitive information request detected: '{w}'")

    return score, reasons


# =======================================================================
#                           MAIN ANALYZER
# =======================================================================

def analyze_input(user_input, attachment):
    total_score = 0
    reasons = []

    if "http" in user_input.lower():
        url_score, url_reasons = check_url(user_input)
        total_score += url_score
        reasons.extend(url_reasons)

    urg_score, urg_reasons = check_urgency(user_input)
    total_score += urg_score
    reasons.extend(urg_reasons)

    sens_score, sens_reasons = check_sensitive_info(user_input)
    total_score += sens_score
    reasons.extend(sens_reasons)

    if attachment:
        total_score += 20
        reasons.append("Email contains an attachment — higher phishing risk")

    return total_score, reasons


# =======================================================================
#                        STREAMLIT UI + DESCRIPTION
# =======================================================================

st.title("PhishShield by PingFloyd (YorkU)")

# Add a simple link instead of description box
st.markdown(
    """
    **Learn more about phishing:**  
    [Government Cybersecurity Guide](https://www.cyber.gc.ca/en)
    """
)

tab_check, tab_dashboard, tab_history = st.tabs([
    "Phishing Checker",
    "Dashboard",
    "History"
])


# =======================================================================
#                           TAB 1 – CHECKER
# =======================================================================

with tab_check:
    st.subheader("Phishing Checker")

    user_input = st.text_area("Enter a URL or Email Text Below:")

    attachment = st.checkbox("Does the email contain an attachment?")

    uploaded_file = st.file_uploader(
        "Upload an email or attachment (txt, pdf, docx):",
        type=["txt", "pdf", "docx"]
    )

    if uploaded_file is not None and uploaded_file.type == "text/plain":
        if not user_input.strip():
            file_text = uploaded_file.read().decode("utf-8")
            user_input = file_text
            st.info("Loaded text from uploaded .txt file into the input box.")

    if st.button("Check for Phishing"):
        if not user_input.strip():
            st.warning("Please enter a URL/email text or upload a .txt file before checking.")
        else:
            score, reasons = analyze_input(user_input, attachment)

            st.session_state["last_score"] = score
            st.session_state["last_reasons"] = reasons
            st.session_state["last_attachment"] = attachment
            st.session_state["score_history"].append(score)

            st.session_state["full_history"].append({
                "Score": score,
                "Attachment": attachment,
                "Reasons": reasons,
                "Input": user_input
            })

            risk_label = get_risk_label(score)

            if score < 30:
                st.success(f"{risk_label} (Score: {score})")
            elif score < 70:
                st.warning(f"{risk_label} (Score: {score})")
            else:
                st.error(f"{risk_label} (Score: {score})")

            st.write("### Reasons Detected:")
            for r in reasons:
                st.write(f"- {r}")


# =======================================================================
#                           TAB 2 – DASHBOARD
# =======================================================================

with tab_dashboard:
    st.subheader("Session Dashboard")

    if st.session_state["last_score"] is None:
        st.info("No scans yet. Run a scan in the Phishing Checker tab.")
    else:
        score = st.session_state["last_score"]
        reasons = st.session_state["last_reasons"]
        risk_label = get_risk_label(score)

        st.write(f"**Last Scan Score:** {score}")
        st.write(f"**Risk Level:** {risk_label}")

        if score < 30:
            st.success("Overall Risk Level: SAFE")
        elif score < 70:
            st.warning("Overall Risk Level: SUSPICIOUS")
        else:
            st.error("Overall Risk Level: HIGH RISK")

        st.write(f"**Attachment in last email:** {'Yes' if st.session_state['last_attachment'] else 'No'}")

        st.write("### Warnings from last scan:")
        for r in reasons:
            st.write(f"- {r}")

        if len(st.session_state["score_history"]) > 1:
            st.write("### Score Trend (Session)")
            st.line_chart(st.session_state["score_history"])
        else:
            st.info("Run more scans to see a trend chart.")


# =======================================================================
#                        TAB 3 – HISTORY (TABLE + DOWNLOAD)
# =======================================================================

with tab_history:
    st.subheader("Full Scan History")

    if not st.session_state["full_history"]:
        st.info("No scan history available yet.")
    else:
        rows = []
        for i, entry in enumerate(st.session_state["full_history"], start=1):
            score = entry["Score"]
            rows.append({
                "Scan No.": i,
                "Score": score,
                "Risk Level": get_risk_label(score),
                "Attachment": "Yes" if entry["Attachment"] else "No",
                "Input": entry["Input"],
                "Reasons": "; ".join(entry["Reasons"]) if entry["Reasons"] else "None"
            })

        df_history = pd.DataFrame(rows)
        st.dataframe(df_history, use_container_width=True)

        csv_data = df_history.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="Download History as CSV",
            data=csv_data,
            file_name="phishshield_history.csv",
            mime="text/csv"
        )
