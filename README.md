🔐 AI-Powered PII Protection System

Data Protection • Infosec • Privacy Compliance • ML & Security Automation

📌 Overview

This project is an AI-driven data security and privacy compliance tool that automatically detects and protects Personally Identifiable Information (PII) in text inputs.

It was built with a security-first mindset aligned to Flipkart Infosec roles:

✔ Application Security
✔ Data Protection
✔ Governance, Risk & Compliance (GRC)
✔ Security Automation
✔ Vendor Risk & ISO 27001 Controls

The tool identifies sensitive data, masks or encrypts it, evaluates compliance risk, and generates a professional security report (HTML & PDF).

🧠 What This Tool Can Do
Feature	Description
🔍 PII Detection	Regex + Machine Learning using SpaCy NER
🛡 Data Protection	Smart masking applied to all detected fields
📊 Risk Scoring	Calculates exposure risk — Low/Medium/High
🧾 Compliance Report	Downloadable PDF for audits & incident response
🔐 Role-Based Access	Login system with analyst vs viewer privileges
🗄 Audit Logging	Stores scan logs securely in SQLite
🚫 Least-Privilege UI	Raw PII only visible to authorized analysts
🕵️ Detected PII Types
Category	Examples	Method
Contact Info	Email, Phone	Regex
Government ID	Aadhaar, PAN	Regex
Identity Clues	Name, Location, Org	Machine Learning (NER)
DOB	Birth dates	Regex
📡 Architecture
📌 User Input
     ↓
🔍 PII Detection
     - Regex-based patterns
     - ML-based NER using SpaCy
     ↓
📊 Risk Evaluation
     - Weighted scoring model
     - ISO compliance checks
     ↓
🛡 Protection (Masking)
     - Confidential data redacted
     ↓
🧾 Audit Logging + Report
     - HTML/PDF export
     ↓
🔐 RBAC Access Control (Login)

🛠️ Tech Stack
Layer	Technology
Frontend	HTML5, Jinja Templates, CSS
Backend	Flask (Python)
Database	SQLite
Security	AES-ready masking modules
AI/ML	SpaCy NLP Model
Reporting	ReportLab PDF Generator
🚀 How to Run Locally
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
python -m spacy download en_core_web_sm
python app.py


Now open ➝ http://127.0.0.1:5000

🔑 Login Credentials (Demo)
Role	Username	Password	Permissions
Analyst	analyst	flipkart123	Full access — can see raw PII & audit
Viewer	viewer	viewer123	Only masked data (secure mode)
📄 Example Output Screenshots (To Add)

Add later (or I can help generate):

🖥 Scan Page (with masked data)

📈 Risk Score shown

🔍 Analyst-only panel

📄 PDF Compliance Report

🗄 Audit Logs View

🛑 Security Principles Used

✔ Data Minimization
✔ Secure-by-Default UI
✔ Encryption-Ready Safe Storage
✔ Role Based Access Control
✔ Privacy by Design
✔ Governance controls for ISO 27001 & NIST CSF
✔ Vendor Risk Reporting support
