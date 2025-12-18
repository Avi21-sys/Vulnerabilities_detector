# 🔐 Automated SQLi and XSS Vulnerability Detector

An automated web security tool designed to detect **SQL Injection (SQLi)** and **Cross-Site Scripting (XSS)** vulnerabilities in web applications.  
The system uses a **Chrome browser extension** as the frontend and a **Python Flask backend** to perform dynamic vulnerability scanning.

This project was developed as a **Minor Project (B.Tech – Computer Science & Engineering)**.

---

## 📌 Project Overview

SQL Injection and Cross-Site Scripting remain among the most critical web application vulnerabilities.  
This tool automates the process of identifying such vulnerabilities by:
- Dynamically discovering HTML forms
- Injecting predefined attack payloads
- Analyzing server responses for insecure behavior

The scanner helps developers and testers identify security issues early in the development lifecycle.

---

## ✨ Features

- Automated detection of **SQL Injection (SQLi)**
- Automated detection of **Reflected XSS**
- Chrome extension to scan the **currently active website**
- Dynamic form and input field discovery
- Centralized payload management
- REST API–based backend using Flask
- Structured JSON output for scan results
- Timeout and error handling for reliable scans

---

## 🛠️ Tech Stack

**Frontend**
- HTML
- CSS
- JavaScript
- Chrome Extension APIs (Manifest V3)

**Backend**
- Python 3
- Flask
- Flask-CORS
- Requests
- BeautifulSoup
- Regular Expressions





