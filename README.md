# 🔐 AI-Powered PII Protection System  
*Data Protection • Infosec • Security Automation • ML Compliance*

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Flask](https://img.shields.io/badge/Framework-Flask-darkgreen)
![Security](https://img.shields.io/badge/Focus-Data%20Protection-red)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## 📌 Overview  

A security-focused web application that automatically **detects, protects and reports**  
**Personally Identifiable Information (PII)** in any text input.

Built with security engineering practices used in real Infosec teams:
- PII discovery (Regex + ML)
- Risk scoring & compliance evaluation
- Security automation (masking & PDF reporting)
- Access control for analysts vs users
- Audit logging for governance

This project is aligned with industry frameworks like:
➡ ISO 27001  
➡ NIST CSF  
➡ Data Privacy principles (least privilege access)

---

## ✨ Features

| Feature | Description |
|--------|-------------|
| 🔍 PII Detection | Emails, Phones, Aadhaar, PAN, DOB, Names, Locations |
| 🛡 Data Protection | Smart masking & future AES encryption support |
| 📊 Risk Scoring | Confidentiality-weighted exposure analysis |
| 🧾 Compliance Report | Downloadable **PDF** for audits & risk reviews |
| 🔐 Login System | Analyst role can view raw sensitive data |
| 🗄 Audit Logging | Every scan securely logged into SQLite |

---

## 🎯 Detected PII Types

| Detection Method | PII Types |
|------------------|-----------|
| Regex | Email, Phone, Aadhaar, PAN, DOB |
| ML (SpaCy NER) | Person Names, Locations, Organizations |

---

## 🧠 System Architecture

