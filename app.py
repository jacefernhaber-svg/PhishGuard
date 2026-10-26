
import re
import ipaddress
from urllib.parse import urlsplit

import streamlit as st


# ----------------------------------
# 1. WEBSITE CONFIGURATION
# ----------------------------------

st.set_page_config(
    page_title="PhishGuard 2.0",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""

<style>

/* Main website background */
.stApp {
    background-color: #0B1220;
    color: #FFFFFF;
}

/* Main headings */
h1, h2, h3 {
    color: #FFFFFF !important;
}

/* Normal paragraphs and list text */
.stMarkdown p,
.stMarkdown li {
    color: #F1F5F9;
}

/* Input labels */
[data-testid="stWidgetLabel"] {
    color: #F1F5F9 !important;
}

/* Tab labels */
button[data-baseweb="tab"] {
    color: #CBD5E1 !important;
}

/* Active tab */
button[data-baseweb="tab"][aria-selected="true"] {
    color: #5EEAD4 !important;
}

/* Metric cards */
[data-testid="stMetric"] {
    background: #18253B;
    padding: 18px;
    border-radius: 12px;
}

/* Metric values */
[data-testid="stMetricValue"] {
    color: #67E8F9;
}

/* Main action buttons */
.stButton > button[kind="primary"] {
    background-color: #0D9488;
    color: #FFFFFF;
    border-radius: 9px;
    border: none;
}

/* Secondary captions */
.stCaption {
    color: #CBD5E1;
}
.stTextArea textarea::placeholder {
    color: #666666 !important;
    -webkit-text-fill-color: #666666 !important;
}

.stTextInput input {
    color: #000000 !important;
    -webkit-text-fill-color: #000000 !important;
}
/* Fix secondary buttons so text is always visible */
.stButton > button[kind="secondary"] {
    background-color: #0D9488 !important;
    color: #FFFFFF !important;
    border: none !important;
    border-radius: 9px !important;
}

/* Keep button text white, including nested elements */
.stButton > button[kind="secondary"] * {
    color: #FFFFFF !important;
}

/* Slightly brighter teal when hovering */
.stButton > button[kind="secondary"]:hover {
    background-color: #0F766E !important;
    color: #FFFFFF !important;
}

/* Keep keyboard focus readable */
.stButton > button[kind="secondary"]:focus {
    color: #FFFFFF !important;
}
</style>
""", unsafe_allow_html=True)

# ----------------------------------
# 2. DETECTION ENGINE
# ----------------------------------

def inspect_url(url):
    """Inspect URL text without opening the website."""
    warnings = []
    points = 0

    cleaned = url.strip().rstrip(".,!?;)")
    if not re.match(r"^https?://", cleaned, re.I):
        cleaned = "https://" + cleaned

    try:
        parsed = urlsplit(cleaned)
        hostname = (parsed.hostname or "").lower()

        if not hostname or "." not in hostname:
            return 0, ["Could not identify a valid hostname."]

        shorteners = {
            "bit.ly", "tinyurl.com", "t.co",
            "is.gd", "cutt.ly", "tiny.cc"
        }

        if hostname in shorteners:
            warnings.append("URL shortening service detected.")
            points += 20

        if "xn--" in hostname:
            warnings.append(
                "Internationalized domain encoding detected. "
                "Verify the intended domain carefully."
            )
            points += 20

        if "@" in parsed.netloc:
            warnings.append(
                "URL contains @, which may obscure the destination."
            )
            points += 25

        try:
            ipaddress.ip_address(hostname)
            warnings.append(
                "Link uses an IP address instead of a domain name."
            )
            points += 20
        except ValueError:
            pass

        if hostname.count("-") >= 3:
            warnings.append(
                "Domain contains several hyphens."
            )
            points += 10

        if parsed.scheme == "http":
            warnings.append(
                "Link uses HTTP instead of HTTPS."
            )
            points += 10

    except ValueError:
        return 0, ["The URL could not be parsed."]

    return points, warnings


def analyze_message(message):
    text = message.lower()
    findings = []
    score = 0

    rules = [
        (
            "Urgency or pressure",
            [
                "urgent", "immediately", "act now",
                "final warning", "within 24 hours",
                "account suspended", "limited time"
            ],
            20,
            "Creates pressure to respond without verifying."
        ),
        (
            "Sensitive information request",
            [
                "verify your password",
                "send your password",
                "social security number",
                "bank details",
                "verification code",
                "confirm your password"
            ],
            30,
            "May be attempting to collect confidential data."
        ),
        (
            "Unexpected prize or reward",
            [
                "you won", "claim your prize",
                "free gift", "congratulations winner"
            ],
            15,
            "Unexpected rewards are a common phishing lure."
        ),
        (
            "Account or payment threat",
            [
                "account will be closed",
                "payment failed",
                "unusual login",
                "unauthorized activity",
                "avoid suspension"
            ],
            20,
            "Account warnings should be verified independently."
        ),
    ]

    for name, phrases, points, explanation in rules:
        if any(phrase in text for phrase in phrases):
            score += points
            findings.append((name, explanation))

    # Find URLs in the message
    urls = re.findall(
        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
        message,
        re.IGNORECASE
    )

    if urls:
        score += 5
        findings.append((
            "Message contains links",
            "Verify destinations using trusted official sources."
        ))

    for url in urls:
        url_points, url_warnings = inspect_url(url)
        score += url_points

        for warning in url_warnings:
            findings.append(("URL warning", warning))

    score = min(score, 100)

    if score >= 60:
        level = "High concern"
    elif score >= 25:
        level = "Moderate concern"
    else:
        level = "Few indicators detected"

    return score, level, findings, urls


# ----------------------------------
# 3. WEBSITE HEADER
# ----------------------------------
# Fix input box text and improve readability
st.markdown("""
<style>
/* Message scanner input */
[data-testid="stTextArea"] textarea {
    color: #000000 !important;
    -webkit-text-fill-color: #000000 !important;
    background-color: #F1F5F9 !important;
}

[data-testid="stTextArea"] textarea::placeholder {
    color: #666666 !important;
    -webkit-text-fill-color: #666666 !important;
}

/* URL Inspector input */
[data-testid="stTextInput"] input {
    color: #000000 !important;
    -webkit-text-fill-color: #000000 !important;
}

/* Improve tab visibility */
button[data-baseweb="tab"] {
    color: #E2E8F0 !important;
}

/* Improve safety notice visibility */
[data-testid="stAlert"] p {
    color: #FFFFFF !important;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ PhishGuard 2.0")
st.caption("Cybersecurity awareness and phishing detection")

st.info(
    "PhishGuard identifies potential warning signs, not confirmed "
    "phishing attacks. A low score does NOT prove a message is safe. "
    "Never paste passwords or confidential information."
)

scanner_tab, url_tab, quiz_tab, about_tab, evaluation_tab = st.tabs([
    "🔍 Message Scanner",
    "🔗 URL Inspector",
    "🎓 Learn & Quiz",
    "ℹ️ About",
    "📊 Evaluation"
])


# ----------------------------------
# 4. MESSAGE SCANNER
# ----------------------------------

with scanner_tab:
    st.header("Message Scanner")

    st.write(
        "Paste a suspicious message to identify common "
        "social-engineering and phishing indicators."
    )

    message = st.text_area(
        "Email or text message",
        height=190,
        placeholder="Paste a suspicious message here...",
        key="message"
    )

    if st.button("Analyze Message", type="primary"):

        if not message.strip():
            st.warning("Please enter a message.")

        elif len(message) > 10000:
            st.warning("Limit messages to 10,000 characters.")

        else:
            score, level, findings, urls = analyze_message(message)

            st.divider()
            st.subheader("Analysis Results")

            col1, col2, col3 = st.columns(3)

            col1.metric("Warning-Sign Score", f"{score}/100")
            col2.metric("Indicators Found", len(findings))
            col3.metric("Links Found", len(urls))

            st.progress(score / 100)

            if level == "High concern":
                st.error("🔴 HIGH CONCERN")
            elif level == "Moderate concern":
                st.warning("🟠 MODERATE CONCERN")
            else:
                st.info("🔵 FEW INDICATORS DETECTED")

            st.subheader("Detection Breakdown")

            if findings:
                for title, explanation in findings:
                    with st.expander("⚠️ " + title):
                        st.write(explanation)
            else:
                st.write(
                    "No rules triggered. This does not "
                    "mean the message is safe."
                )

            st.subheader("Recommended Actions")
            st.write(
                "• Do not open unexpected links or attachments.\n\n"
                "• Never share passwords or one-time codes.\n\n"
                "• Verify requests through official websites or apps.\n\n"
                "• Report suspicious messages to the relevant service."
            )

            st.caption(
                "The score is a heuristic based on triggered rules, "
                "not a statistical probability of phishing."
            )


# ----------------------------------
# 5. URL INSPECTOR
# ----------------------------------

with url_tab:
    st.header("URL Inspector")

    st.write(
        "Inspect the structure of a URL without visiting it."
    )

    url_input = st.text_input(
        "Enter a URL",
        placeholder="https://example.com",
        key="url"
    )

    if st.button("Inspect URL"):
        if not url_input.strip():
            st.warning("Enter a URL first.")
        elif len(url_input) > 2048:
            st.warning("URL is too long.")
        else:
            points, warnings = inspect_url(url_input)

            st.metric("URL Warning Score", f"{min(points, 100)}/100")

            if warnings:
                for warning in warnings:
                    st.warning(warning)
            else:
                st.info(
                    "No listed URL indicators detected. "
                    "This does not verify that the website is safe."
                )

            st.caption(
                "The inspector does not open links, check "
                "reputation databases, or scan website content."
            )


# ----------------------------------
# 6. PHISHING AWARENESS QUIZ
# ----------------------------------

with quiz_tab:
    st.header("Test Your Phishing Knowledge")

    examples = [
        {
            "message": (
                "URGENT! Your account is suspended. "
                "Verify your password immediately."
            ),
            "answer": "Suspicious",
            "explanation": (
                "Urgency combined with a password request "
                "is a strong warning sign."
            ),
        },
        {
            "message": (
                "Hi Sam, can you bring your notebook "
                "to class tomorrow?"
            ),
            "answer": "No obvious warning signs",
            "explanation": (
                "This example has no obvious phishing indicators, "
                "although context and sender identity still matter."
            ),
        },
        {
            "message": (
                "You won a free gift! Claim your prize now "
                "at https://bit.ly/example"
            ),
            "answer": "Suspicious",
            "explanation": (
                "An unexpected reward and a shortened URL "
                "are reasons to investigate."
            ),
        },
    ]

    choice = st.selectbox(
        "Select a practice scenario",
        range(len(examples)),
        format_func=lambda i: f"Scenario {i + 1}"
    )

    example = examples[choice]
    st.info(example["message"])

    answer = st.radio(
        "Does this message have phishing warning signs?",
        ["Suspicious", "No obvious warning signs"],
        key=f"quiz_answer_{choice}",
        index=None
    )

    if st.button("Check Answer"):
        if answer is None:
            st.warning("Choose an answer first.")
        elif answer == example["answer"]:
            st.success("Correct!")
            st.write(example["explanation"])
        else:
            st.error("Not quite.")
            st.write(example["explanation"])


# ----------------------------------
# 7. ABOUT PAGE
# ----------------------------------

with about_tab:
    st.header("About PhishGuard")

    st.write(
        "PhishGuard is an independent educational "
        "cybersecurity project built using Python "
        "and Streamlit."
    )

    st.subheader("Project Goals")
    st.write(
        "• Help people recognize phishing warning signs.\n\n"
        "• Explain how social engineering works.\n\n"
        "• Make cybersecurity education accessible.\n\n"
        "• Evaluate and improve detection algorithms."
    )

    st.subheader("Limitations")
    st.write(
        "PhishGuard is a rule-based educational detector. "
        "It can miss malicious messages and flag legitimate "
        "ones. Its scores are not validated probabilities."
    )

    st.subheader("Privacy")
    st.write(
        "This version does not intentionally write "
        "submitted messages to a database or file. "
        "Hosting providers may still process application "
        "traffic. Do not submit private information."
    )
# ----------------------------------
# 8. DETECTION EVALUATION DASHBOARD
# ----------------------------------

with evaluation_tab:
    st.header("📊 Detection Performance")

    st.write(
        "This experiment evaluates PhishGuard against "
        "a small collection of fictional labeled messages."
    )

    # 1 means phishing; 0 means legitimate
    test_messages = [
        ("URGENT! Verify your password immediately.", 1),
        ("Your payment failed. Act now to avoid suspension.", 1),
        ("You won a free gift! Claim your prize.", 1),
        ("Send your password to restore your account.", 1),
        ("Your account will be closed within 24 hours.", 1),
        ("Confirm your verification code immediately.", 1),

        ("Are we still meeting at the library?", 0),
        ("Can you bring your notebook tomorrow?", 0),
        ("Thanks for helping with the presentation!", 0),
        ("I'll see you at practice after school.", 0),
        ("Your order is ready for pickup.", 0),
        ("The meeting starts at 3 PM tomorrow.", 0),
    ]

    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    results = []

    for message, actual in test_messages:
        score, level, findings, urls = analyze_message(message)

        # 25 or higher is classified as phishing
        predicted = 1 if score >= 25 else 0

        if actual == 1 and predicted == 1:
            true_positive += 1
        elif actual == 0 and predicted == 0:
            true_negative += 1
        elif actual == 0 and predicted == 1:
            false_positive += 1
        else:
            false_negative += 1

        results.append({
            "Message": message,
            "Actual": "Phishing" if actual else "Legitimate",
            "Prediction": "Phishing" if predicted else "Legitimate",
            "Score": score,
            "Correct": actual == predicted
        })

    total = len(test_messages)

    accuracy = (true_positive + true_negative) / total

    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive > 0 else 0
    )

    recall = (
        true_positive / (true_positive + false_negative)
        if true_positive + false_negative > 0 else 0
    )

    st.subheader("Performance Metrics")

    col1, col2, col3 = st.columns(3)

    col1.metric("Accuracy", f"{accuracy:.1%}")
    col2.metric("Precision", f"{precision:.1%}")
    col3.metric("Recall", f"{recall:.1%}")

    st.subheader("Classification Results")

    col1, col2 = st.columns(2)

    col1.metric("True Positives", true_positive)
    col1.metric("False Positives", false_positive)

    col2.metric("True Negatives", true_negative)
    col2.metric("False Negatives", false_negative)

    st.subheader("Detailed Test Results")
    st.dataframe(results, use_container_width=True)

    st.info(
        "These results use a tiny, hand-written fictional dataset. "
        "They do not establish real-world phishing detection accuracy."
    )
st.divider()
st.caption(
    "PhishGuard 2.0 | Built with Python and Streamlit"
)
