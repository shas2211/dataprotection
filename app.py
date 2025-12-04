from flask import Flask, render_template, request, redirect, url_for, session, send_file
import re
import sqlite3
import json
import io
from datetime import datetime

# ML (SpaCy) for additional PII like names/locations
try:
    import spacy
    nlp = spacy.load("en_core_web_sm")
    ML_ENABLED = True
except Exception:
    nlp = None
    ML_ENABLED = False

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key"  # change for real use

# Very simple login data – portfolio demo level
USERS = {
    "analyst": "flipkart123",   # Full access
    "viewer": "viewer123"       # Can only see masked data
}

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
    "DOB": 3,
    "Name": 4,
    "Location": 4,
    "Organization": 4
}

DB_PATH = "audit_logs.db"


# ---------- DB INIT & AUDIT LOGGING ----------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            pii_summary TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def log_audit(username, risk_score, risk_level, pii_found):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    timestamp = datetime.utcnow().isoformat()
    pii_summary = {label: len(items) for label, items in pii_found.items()}
    cur.execute(
        "INSERT INTO audits (timestamp, username, risk_score, risk_level, pii_summary) VALUES (?, ?, ?, ?, ?)",
        (timestamp, username, risk_score, risk_level, json.dumps(pii_summary))
    )
    conn.commit()
    conn.close()


# ---------- HELPER: ROLE CHECK ----------

def current_user():
    return session.get("username")


def is_analyst():
    return current_user() == "analyst"


# ---------- ML-BASED PII (SpaCy NER) ----------

def detect_pii_ml(text: str):
    """
    Uses SpaCy NER to detect Names, Locations, Organizations.
    """
    if not ML_ENABLED or not nlp or not text.strip():
        return {}

    doc = nlp(text)
    results = {}
    for ent in doc.ents:
        if ent.label_ == "PERSON":
            results.setdefault("Name", []).append(ent.text)
        elif ent.label_ in ("GPE", "LOC"):
            results.setdefault("Location", []).append(ent.text)
        elif ent.label_ == "ORG":
            results.setdefault("Organization", []).append(ent.text)
    return results


# ---------- REGEX PII + RISK ----------

def detect_pii(text: str):
    results = {}
    risk_score = 0

    # Regex-based
    for label, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            results[label] = matches
            risk_score += len(matches) * risk_weights[label]

    # ML-based (names, locations, orgs)
    ml_results = detect_pii_ml(text)
    for label, matches in ml_results.items():
        if matches:
            results.setdefault(label, [])
            # avoid duplicates
            for m in matches:
                if m not in results[label]:
                    results[label].append(m)
            risk_score += len(matches) * risk_weights.get(label, 2)

    # Risk level
    if risk_score > 50:
        risk_level = "🚨 High Risk"
    elif risk_score > 20:
        risk_level = "⚠️ Medium Risk"
    else:
        risk_level = "🟢 Low Risk"

    return results, risk_score, risk_level


# ---------- MASKING HELPERS ----------

def mask_email(match):
    email = match.group()
    if "@" not in email:
        return "***@***"
    user, domain = email.split("@", 1)
    if len(user) <= 2:
        masked_user = user[0] + "***"
    else:
        masked_user = user[0] + "*" * (len(user) - 2) + user[-1]
    return masked_user + "@" + domain


def mask_phone(match):
    digits = re.sub(r"\D", "", match.group())
    if len(digits) < 4:
        return "******"
    return "******" + digits[-4:]


def mask_aadhaar(match):
    raw = match.group()
    parts = raw.split()
    if len(parts) == 3:
        return f"XXXX XXXX {parts[2]}"
    return "XXXX XXXX XXXX"


def mask_pan(match):
    raw = match.group()
    if len(raw) != 10:
        return "XXXXX9999X"
    return f"XXXXX{raw[5:9]}X"


def mask_dob(match):
    raw = match.group()
    parts = re.split(r"[/-]", raw)
    if len(parts) == 3:
        return f"XX/XX/{parts[2]}"
    return "XX/XX/XXXX"


def protect_text(text: str) -> str:
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


# ---------- PDF GENERATION ----------

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

def generate_pdf(input_text, pii_found, risk_score, risk_level, protected_text):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    y = height - 50
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "PII Security Compliance Report")
    y -= 30

    c.setFont("Helvetica", 11)
    c.drawString(40, y, f"Risk Level: {risk_level}")
    y -= 20
    c.drawString(40, y, f"Risk Score: {risk_score}")
    y -= 30

    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "PII Summary:")
    y -= 20
    c.setFont("Helvetica", 10)
    for label, items in pii_found.items():
        line = f"- {label}: {len(items)} found"
        c.drawString(50, y, line)
        y -= 15
        if y < 100:
            c.showPage()
            y = height - 50

    y -= 10
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Protected Data (Masked):")
    y -= 20
    c.setFont("Helvetica", 9)

    for line in protected_text.splitlines():
        c.drawString(50, y, line[:100])  # simple line wrap
        y -= 14
        if y < 80:
            c.showPage()
            y = height - 50

    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer


# ---------- ROUTES ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if username in USERS and USERS[username] == password:
            session["username"] = username
            return redirect(url_for("index"))
        else:
            error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
def index():
    input_text = ""
    pii_found = {}
    risk_score = None
    risk_level = None
    protected_text = None

    if request.method == "POST":
        input_text = request.form.get("input_text", "").strip()
        if input_text:
            pii_found, risk_score, risk_level = detect_pii(input_text)
            protected_text = protect_text(input_text) if pii_found else input_text

            # Log audit if any PII found
            if pii_found:
                log_audit(current_user() or "guest", risk_score, risk_level, pii_found)

    return render_template(
        "index.html",
        input_text=input_text,
        pii_found=pii_found,
        risk_score=risk_score,
        risk_level=risk_level,
        protected_text=protected_text,
        is_analyst=is_analyst(),
        ml_enabled=ML_ENABLED,
    )


@app.route("/report", methods=["POST"])
def report():
    input_text = request.form.get("input_text", "").strip()
    pii_found, risk_score, risk_level = detect_pii(input_text)
    protected_text = protect_text(input_text)

    # Log audit for report generation as well
    if pii_found:
        log_audit(current_user() or "guest", risk_score, risk_level, pii_found)

    return render_template(
        "report.html",
        input_text=input_text,
        pii_found=pii_found,
        risk_score=risk_score,
        risk_level=risk_level,
        protected_text=protected_text,
        is_analyst=is_analyst()
    )


@app.route("/report/pdf", methods=["POST"])
def report_pdf():
    input_text = request.form.get("input_text", "").strip()
    pii_found, risk_score, risk_level = detect_pii(input_text)
    protected_text = protect_text(input_text)
    pdf_buffer = generate_pdf(input_text, pii_found, risk_score, risk_level, protected_text)

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name="pii_report.pdf",
        mimetype="application/pdf"
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
