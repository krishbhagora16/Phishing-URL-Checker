import streamlit as st
from urllib.parse import urlparse

def detect_phishing_with_reasons(url: str):
    keywords = ["login", "verify", "update", "bank", "secure", "account"]
    parsed = urlparse(url)

    checks = []

    # Check 1: HTTPS or not
    checks.append({
        "name": "Uses HTTPS",
        "passed": parsed.scheme == "https",
        "detail": f"Scheme is '{parsed.scheme or 'missing'}'"
    })

    # Check 2: Too many dots (subdomains)
    checks.append({
        "name": "Excessive subdomains",
        "passed": parsed.netloc.count('.') <= 3,
        "detail": f"Dots in host: {parsed.netloc.count('.')}"
    })

    # Check 3: Hyphen in domain
    checks.append({
        "name": "Hyphen in domain",
        "passed": "-" not in parsed.netloc,
        "detail": f"Host contains hyphen: {'-' in parsed.netloc}"
    })

    # Check 4: Suspicious keywords in URL
    has_keyword = any(word in url.lower() for word in keywords)
    checks.append({
        "name": "Suspicious keywords",
        "passed": not has_keyword,
        "detail": f"Keywords found: {has_keyword}"
    })

    # Check 5: '@' symbol used
    checks.append({
        "name": "@ symbol in URL",
        "passed": "@" not in url,
        "detail": f"Contains '@': {'@' in url}"
    })

    # Compute score
    score = sum(0 if c["passed"] else 1 for c in checks)
    if score >= 3:
        verdict = "⚠ Phishing suspected!"
        category = "phishing"
    elif score == 2:
        verdict = "❗ Suspicious URL"
        category = "suspicious"
    else:
        verdict = "✅ Looks safe"
        category = "safe"

    return verdict, category, checks


st.set_page_config(page_title="Smart Link Analyzer for Safer Browsing", page_icon="🛡", layout="centered")

st.title("🛡 Smart Link Analyzer")
st.write("Check URLs for phishing indicators.")

url_input = st.text_input("Enter URL", placeholder="https://example.com/login")
if st.button("Check URL"):
    if not url_input.strip():
        st.warning("Please enter a URL.")
    else:
        verdict, category, checks = detect_phishing_with_reasons(url_input.strip())
        if category == "phishing":
            st.error(verdict)
        elif category == "suspicious":
            st.warning(verdict)
        else:
            st.success(verdict)

        st.subheader("Check details")
        for c in checks:
            st.markdown(f"- {'✅' if c['passed'] else '⚠'} *{c['name']}* — {c['detail']}")
