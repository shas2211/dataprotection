from flask import Flask, render_template, request
import re

app = Flask(__name__)

# Regex patterns for PII
patterns = {
    "Email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "Phone": r"(?:\+91[-\s]?)?(?:[6-9]\d{9})",
    "Aadhaar": r"\b\d{4}\s\d{4}\s\d{4}\b",
    "PAN": r"[A-Z]{5}[0-9]{4}[A-Z]",
    "DOB": r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"
}

risk_weights = {
    "Email": 5,
    "Phone": 6,
    "Aadhaar": 10,
    "PAN": 9,
    "DOB": 3
}


def detect_pii(text: str):
    results = {}
    risk_score = 0

    for label, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            results[label] = matches
            risk_score += len(matches) * risk_weights[label]

    if risk_score > 50:
        risk_level = "🚨 High Risk"
    elif risk_score > 20:
        risk_level = "⚠️ Medium Risk"
    else:
        risk_level = "🟢 Low Risk"

    return results, risk_score, risk_level


# ---------- Masking helpers ----------
def mask_email(match):
    email = match.group()
    user, domain = email.split("@")
    masked_user = user[0] + "*" * (len(user) - 2) + user[-1]
    return masked_user + "@" + domain


def mask_phone(match):
    digits = re.sub(r"\D", "", match.group())
    return "******" + digits[-4:]


def mask_aadhaar(match):
    raw = match.group()
    parts = raw.split()
    return f"XXXX XXXX {parts[2]}"


def mask_pan(match):
    raw = match.group()
    return f"XXXXX{raw[5:9]}X"


def mask_dob(match):
    raw = match.group()
    parts = re.split(r"[/-]", raw)
    return f"XX/XX/{parts[-1]}"


def protect_text(text):
    protected = text
    order = ["Aadhaar", "PAN", "Phone", "Email", "DOB"]

    for label in order:
        pattern = re.compile(patterns[label])
        if label == "Email":
            protected = pattern.sub(mask_email, protected)
        elif label == "Phone":
            protected = pattern.sub(mask_phone, protected)
        elif label == "Aadhaar":
            protected = pattern.sub(mask_aadhaar, protected)
        elif label == "PAN":
            protected = pattern.sub(mask_pan, protected)
        elif label == "DOB":
            protected = pattern.sub(mask_dob, protected)

    return protected


@app.route("/", methods=["GET", "POST"])
def index():
    input_text = ""
    pii_found = {}
    risk_score = None
    risk_level = None
    protected_text = None

    if request.method == "POST":
        input_text = request.form.get("input_text", "").strip()
        pii_found, risk_score, risk_level = detect_pii(input_text)
        if pii_found:
            protected_text = protect_text(input_text)

    return render_template(
        "index.html",
        input_text=input_text,
        pii_found=pii_found,
        risk_score=risk_score,
        risk_level=risk_level,
        protected_text=protected_text
    )


@app.route("/report", methods=["POST"])
def report():
    input_text = request.form.get("input_text", "").strip()
    pii_found, risk_score, risk_level = detect_pii(input_text)
    protected_text = protect_text(input_text)

    return render_template(
        "report.html",
        input_text=input_text,
        pii_found=pii_found,
        risk_score=risk_score,
        risk_level=risk_level,
        protected_text=protected_text
    )


if __name__ == "__main__":
    app.run(debug=True)
