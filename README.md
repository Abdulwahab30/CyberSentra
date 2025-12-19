# 🛡️ CyberSentra

**Windows Security Monitoring & ML-Driven Anomaly Detection Dashboard**

CyberSentra is a desktop security monitoring application built with **C# and Avalonia UI**.  
It ingests **Windows Event Logs**, persists them into **SQLite**, applies **rule-based threat detection** and **machine-learning anomaly detection**, and visualizes everything in a **modern SOC-style dashboard**.

This project was built in **phases** to demonstrate log ingestion, detection logic, persistence, analytics, and **explainable ML** — making it suitable for **academic projects, demos, and security tooling prototypes**.

---

## ✨ Key Features

### 📊 Dashboard
- Dynamic **Security Index** (risk score)
- Event, anomaly, threat, and failed-login counters
- **Top anomalous users** (ML-driven)
- **Top MITRE ATT&CK techniques**
- Recent anomalies table
- Time-range filtering:
  - All
  - Last 24 hours
  - Last 1 hour

---

### 📜 Event Collection
- Windows Event Logs:
  - Application
  - System
  - Security (best-effort, permission-aware)
- **Sysmon** support (if installed)
- JSON fallback (`data/events.json`)
- All events persisted into **SQLite**

---

### 🔍 Threat Detection (Rule-Based)
- MITRE ATT&CK technique mapping
- Detection of:
  - Failed logons / credential abuse
  - Suspicious PowerShell or command execution
  - Remote access / RDP activity
  - High-severity generic events
- Threat history view backed by SQLite

---

### 🤖 ML Anomaly Detection (Phase 3)
- Per-user **hourly feature aggregation**
- Baseline vs target window comparison
- **Unsupervised PCA-based anomaly detection** (ML.NET)

**Features include:**
- Total events
- Failed logins
- Errors / failures
- Warnings
- Unique processes
- Unique sources

**Explainable output:**
- “Why flagged” reasons vs baseline
- Related logs per anomaly window

---

### 🧠 ML History & Trend Analysis
- Hourly ML runs persisted to SQLite
- Trend charts:
  - Anomaly count per run
  - Maximum anomaly score
- Run-to-run comparison:
  - New anomalies
  - Resolved anomalies
  - Repeated offenders

---

### 👥 AD Users View
- Users extracted directly from logs
- Per-user activity visibility
- Per-user anomaly indicators

---

## 🏗️ Architecture

```text
CyberSentra
├── UI (Avalonia)
│   ├── DashboardView
│   ├── EventsView
│   ├── ThreatsView
│   ├── ADUsersView
│   ├── MlAnomaliesView
│   └── MlAnomalyHistoryView
│
├── Event Pipeline
│   ├── EventSource (Windows Logs / JSON)
│   ├── EventContext (filters, time windows)
│   └── EventRepository (SQLite)
│
├── Detection
│   ├── ThreatDetector (rule-based, MITRE)
│   └── ThreatRepository
│
├── Machine Learning
│   ├── FeatureBuilder
│   ├── AnomalyModel (ML.NET PCA)
│   ├── UserFeatureRow
│   └── UserAnomaly
│
└── Database
    ├── DatabaseContext
    ├── MlAnomalyRepository
    └── ThreatRepository

## 🗄️ Database (SQLite)

Tables

Events

Threats

MlAnomalies

Schema Highlights

RunKey (hourly snapshot)

UserWindow

Score

IsAnomaly

Feature values (F0–F5)

Optimized with indexing for fast querying and trend analysis.

##📈 ML Design Philosophy

Unsupervised (no labeled data required)

Baseline vs recent window comparison

Hourly granularity to reduce noise

Z-score based anomaly decision

Deterministic & explainable (no black-box behavior)

Designed for SOC explainability rather than opaque AI models.

## 🖥️ Tech Stack

.NET 8

C#

Avalonia UI

SQLite

ML.NET

LiveChartsCore

Windows Event Log API

##🚀 Getting Started
Prerequisites

Windows (required for live Event Log ingestion)

.NET 8 SDK

Optional: Sysmon installed

##📌 Notes

Security log access is permission-aware and best-effort

JSON fallback enables demo/testing without admin privileges

Designed for extensibility (new rules, features, or models)
