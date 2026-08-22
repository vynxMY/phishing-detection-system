# Master Technical Specification

## Machine Learning-Based Phishing Email Detection System

| Field | Value |
|---|---|
| **Document Version** | 1.0.0 |
| **Status** | Approved for Implementation |
| **Project Type** | System Development (PSM) |
| **Official Title** | Machine Learning-Based Phishing Email Detection System |
| **Last Updated** | 2026-08-22 |

---

## Document Purpose

This document is the **single source of truth** for the Machine Learning-Based Phishing Email Detection System. It defines requirements, architecture, APIs, data models, ML pipelines, deployment, and development phasing.

Every feature in this specification is tagged with one of three scope labels:

| Tag | Meaning |
|---|---|
| **PSM Core** | Required for academic deliverables; aligns with the approved proposal |
| **PSM Extension** | Enhanced prototype features that extend the core without changing project identity |
| **Post-PSM Startup** | Future commercial/enterprise capabilities; documented for roadmap continuity |

---

## Table of Contents

1. [Final System Requirements](#1-final-system-requirements)
2. [Functional Requirements](#2-functional-requirements)
3. [Non-Functional Requirements](#3-non-functional-requirements)
4. [Complete Feature Specification](#4-complete-feature-specification)
5. [System Architecture](#5-system-architecture)
6. [ML Architecture](#6-ml-architecture)
7. [Detection Pipeline](#7-detection-pipeline)
8. [Explainability Architecture](#8-explainability-architecture)
9. [Email Parsing Architecture](#9-email-parsing-architecture)
10. [Attachment Analysis Architecture](#10-attachment-analysis-architecture)
11. [Gmail / Chrome / Edge Architecture](#11-gmail--chrome--edge-architecture)
12. [Database ERD](#12-database-erd)
13. [API Endpoint Specification](#13-api-endpoint-specification)
14. [Authentication Architecture](#14-authentication-architecture)
15. [Security Architecture](#15-security-architecture)
16. [Privacy Architecture](#16-privacy-architecture)
17. [Model Training Pipeline](#17-model-training-pipeline)
18. [Dataset Strategy](#18-dataset-strategy)
19. [Model Evaluation Methodology](#19-model-evaluation-methodology)
20. [Feedback / Retraining Pipeline](#20-feedback--retraining-pipeline)
21. [Web UI / Page Structure](#21-web-ui--page-structure)
22. [Browser Extension Structure](#22-browser-extension-structure)
23. [Docker / Deployment Architecture](#23-docker--deployment-architecture)
24. [GitHub Repository Structure](#24-github-repository-structure)
25. [PSM1 / PSM2 Development Mapping](#25-psm1--psm2-development-mapping)
26. [Sprint / Gantt Plan](#26-sprint--gantt-plan)
27. [Testing Strategy](#27-testing-strategy)
28. [Future Startup Architecture](#28-future-startup-architecture)

---

## 1. Final System Requirements

### 1.1 Project Identity

The system is a **web-based cybersecurity platform** that detects phishing emails using supervised machine learning, multi-signal email analysis, explainable risk scoring, and user-facing security guidance.

The approved PSM title remains unchanged:

> **Machine Learning-Based Phishing Email Detection System**

The approved proposal establishes this as a **system-development project** with supervised ML, multiple models, TF-IDF/N-grams, URL/sender analysis, Flask, MySQL, HTTPS, and an online client-server architecture. All PSM Core components preserve that foundation.

### 1.2 System Vision

The platform shall:

- Detect phishing emails and classify email legitimacy
- Analyse email content, URLs, sender information, headers, SPF/DKIM/DMARC, and attachments
- Detect brand impersonation
- Provide a 0–100 risk score with human-readable explanations
- Provide actionable security advice
- Learn from validated user feedback (not instant online retraining)
- Provide scan history and user awareness/education
- Provide an administrator dashboard
- Integrate with Gmail via browser extension **[PSM Extension]**
- Automatically analyse opened Gmail messages **[PSM Extension]**
- Operate online over HTTPS **[PSM Core]**
- Be architected for future commercial deployment **[Post-PSM Startup]**

### 1.3 Development Strategy

Build in layers. Do **not** attempt the startup version immediately.

```
                  FINAL PLATFORM
                       │
        ┌──────────────┴──────────────┐
        │                             │
   PSM CORE                    PRODUCTION EXTENSIONS
        │                             │
        ▼                             ▼
 ML Classification              Gmail Integration
 Email Analysis                 Browser Extension
 Web Application                Attachment Analysis
 Explainability                 Advanced XAI
 User Accounts                  Feedback Learning
 Admin Dashboard                Risk Engine
        │                             │
        └──────────────┬──────────────┘
                       ▼
             Future Startup Platform
```

### 1.4 PSM Baseline vs Extended Prototype

| Layer | Description |
|---|---|
| **PSM Baseline** | Users paste email text into the web interface; no direct live email server integration (as stated in the approved proposal scope) |
| **PSM Extension** | Gmail browser extension, automatic scanning, attachment analysis, advanced explainability, feedback pipeline |
| **Post-PSM Startup** | Multi-provider email, enterprise admin, external threat intelligence, sandboxing, paid API platform |

### 1.5 Development Philosophy

| Rule | Description |
|---|---|
| **Rule 1** | ML makes the prediction; explanations expose evidence behind the decision |
| **Rule 2** | LLM may assist explanation generation; it does **not** become the security authority |
| **Rule 3** | User privacy comes before data collection; raw emails are not permanently stored by default |
| **Rule 4** | Optimize for trust, not a misleading 99.99% accuracy headline; evaluate on unseen, realistic data |

### 1.6 Target Users

| Role | Description | Scope |
|---|---|---|
| **User** | Scans emails, views results, provides feedback, accesses learning content | PSM Core |
| **Administrator** | Monitors users, scans, models, system health, feedback review | PSM Core |
| **Organization Administrator** | Manages teams, org-wide policies | Post-PSM Startup |

### 1.7 Stakeholders

- PSM student (developer)
- Academic supervisor
- End users (students, office workers, general public)
- Security-aware / technical users (detailed/technical explanation modes)

---

## 2. Functional Requirements

### 2.1 Email Ingestion

| ID | Requirement | Scope |
|---|---|---|
| FR-001 | System shall accept raw email text via web interface | PSM Core |
| FR-002 | System shall accept `.eml` file upload | PSM Extension |
| FR-003 | System shall parse HTML and plain-text email bodies | PSM Core |
| FR-004 | System shall extract email headers (From, Reply-To, Return-Path, Received, Authentication-Results) | PSM Extension |
| FR-005 | System shall extract URLs from email body and HTML | PSM Core |
| FR-006 | System shall accept attachment uploads for static analysis | PSM Extension |
| FR-007 | Browser extension shall extract opened Gmail message data and send to API | PSM Extension |
| FR-008 | Gmail API integration via OAuth for programmatic access | PSM Extension |

### 2.2 Detection and Classification

| ID | Requirement | Scope |
|---|---|---|
| FR-010 | System shall classify emails as Safe, Low Risk, Suspicious, High Risk, or Phishing | PSM Core |
| FR-011 | System shall produce a risk score from 0 to 100 | PSM Core |
| FR-012 | System shall run Naive Bayes, Logistic Regression, and Random Forest classifiers | PSM Core |
| FR-013 | System shall support XGBoost as an additional structured classifier | PSM Extension |
| FR-014 | System shall support a specialized URL classifier | PSM Extension |
| FR-015 | System shall fuse ML predictions, rule-based signals, and feature scores into a final risk score | PSM Core |
| FR-016 | System shall maintain an interpretable detection layer alongside any advanced model | PSM Core |
| FR-017 | System shall record the model version used for each scan | PSM Core |

### 2.3 Analysis Modules

| ID | Requirement | Scope |
|---|---|---|
| FR-020 | Content analyser: subject urgency, threats, credential requests, social engineering phrases | PSM Core |
| FR-021 | URL analyser: domain, subdomain count, HTTPS, IP, punycode, shortening, anchor mismatch | PSM Core |
| FR-022 | Sender analyser: From/Reply-To/Return-Path comparison, display name vs domain | PSM Core |
| FR-023 | Header analyser: routing anomalies, suspicious header patterns | PSM Extension |
| FR-024 | Authentication analyser: SPF, DKIM, DMARC, ARC where available | PSM Extension |
| FR-025 | Attachment analyser: file type, extension mismatch, hashes, embedded URLs, macros | PSM Extension |
| FR-026 | Brand impersonation analyser: claimed brand vs sender domain similarity | PSM Extension |
| FR-027 | Threat pattern analyser: internal rule-based suspicious pattern detection | PSM Core |

### 2.4 Explainability

| ID | Requirement | Scope |
|---|---|---|
| FR-030 | System shall explain why an email is dangerous in plain language | PSM Core |
| FR-031 | System shall provide risk breakdown by category (content, URL, sender, auth, attachment, brand) | PSM Core |
| FR-032 | System shall highlight suspicious text in email body | PSM Core |
| FR-033 | System shall provide three explanation levels: Simple, Detailed, Technical | PSM Extension |
| FR-034 | System shall provide SHAP-based feature contributions | PSM Extension |
| FR-035 | System shall provide counterfactual explanations | PSM Extension |
| FR-036 | System shall provide context-specific security advice | PSM Core |

### 2.5 User Management

| ID | Requirement | Scope |
|---|---|---|
| FR-040 | Users shall register with email and password | PSM Core |
| FR-041 | Users shall log in and maintain authenticated sessions | PSM Core |
| FR-042 | Administrators shall have elevated access to admin dashboard | PSM Core |
| FR-043 | Users shall view scan history | PSM Core |
| FR-044 | Users shall configure privacy and scanning preferences | PSM Extension |
| FR-045 | Google OAuth login for Gmail users | PSM Extension |
| FR-046 | Microsoft OAuth login | Post-PSM Startup |

### 2.6 Feedback

| ID | Requirement | Scope |
|---|---|---|
| FR-050 | Users shall mark scan results as correct or incorrect | PSM Extension |
| FR-051 | Users shall specify the correct classification when marking incorrect | PSM Extension |
| FR-052 | Users shall optionally indicate which analysis category was wrong | PSM Extension |
| FR-053 | Administrators shall review feedback before it enters training data | PSM Extension |

### 2.7 Administration

| ID | Requirement | Scope |
|---|---|---|
| FR-060 | Admin shall view user list and activity summary | PSM Core |
| FR-061 | Admin shall view scan statistics (phishing, suspicious, legitimate counts) | PSM Core |
| FR-062 | Admin shall view model performance metrics | PSM Core |
| FR-063 | Admin shall view system health status | PSM Extension |
| FR-064 | Admin shall manage model versions | PSM Extension |
| FR-065 | Admin shall review and approve feedback for retraining | PSM Extension |

### 2.8 Browser Extension

| ID | Requirement | Scope |
|---|---|---|
| FR-070 | Chrome extension (Manifest V3) shall detect opened Gmail messages | PSM Extension |
| FR-071 | Extension shall display risk badge/warning on Gmail UI | PSM Extension |
| FR-072 | Extension shall support automatic scanning toggle | PSM Extension |
| FR-073 | Extension shall support manual rescan | PSM Extension |
| FR-074 | Extension shall be compatible with Microsoft Edge (Chromium) | PSM Extension |

### 2.9 Education

| ID | Requirement | Scope |
|---|---|---|
| FR-080 | System shall provide a learning centre with phishing awareness content | PSM Extension |
| FR-081 | System shall show user-specific risk patterns based on scan history | PSM Extension |

---

## 3. Non-Functional Requirements

### 3.1 Performance

| ID | Requirement | Target | Scope |
|---|---|---|---|
| NFR-001 | API scan response time (paste-text, no attachments) | ≤ 3 seconds (p95) | PSM Core |
| NFR-002 | API scan response time (with attachments ≤ 5 MB) | ≤ 10 seconds (p95) | PSM Extension |
| NFR-003 | Concurrent users supported (PSM deployment) | ≥ 50 | PSM Core |
| NFR-004 | Extension UI update after scan | ≤ 2 seconds after API response | PSM Extension |

### 3.2 Availability and Deployment

| ID | Requirement | Scope |
|---|---|---|
| NFR-010 | System shall be accessible online via HTTPS | PSM Core |
| NFR-011 | System shall not require localhost-only access for PSM demonstration | PSM Core |
| NFR-012 | System shall be deployable via Docker Compose | PSM Extension |
| NFR-013 | Target uptime for PSM demo deployment | ≥ 99% during evaluation period |

### 3.3 Security

| ID | Requirement | Scope |
|---|---|---|
| NFR-020 | All passwords shall be stored using bcrypt or Argon2 | PSM Core |
| NFR-021 | All API communication shall use HTTPS/TLS | PSM Core |
| NFR-022 | System shall implement CSRF protection on web forms | PSM Core |
| NFR-023 | System shall sanitize all user inputs | PSM Core |
| NFR-024 | System shall implement rate limiting on scan API | PSM Extension |
| NFR-025 | OAuth tokens shall be encrypted at rest | PSM Extension |
| NFR-026 | File uploads shall be validated and size-limited | PSM Extension |

### 3.4 Privacy

| ID | Requirement | Scope |
|---|---|---|
| NFR-030 | Raw email body shall not be permanently stored by default | PSM Core |
| NFR-031 | Attachments shall be deleted after analysis by default | PSM Extension |
| NFR-032 | Only derived features, scores, and explanations shall be persisted | PSM Core |
| NFR-033 | Users shall opt in to extended data retention | PSM Extension |

### 3.5 Maintainability

| ID | Requirement | Scope |
|---|---|---|
| NFR-040 | Codebase shall follow modular package structure per Section 24 | PSM Core |
| NFR-041 | All models shall be versioned and reproducible | PSM Core |
| NFR-042 | API shall be documented (OpenAPI/Swagger) | PSM Extension |

### 3.6 Usability

| ID | Requirement | Scope |
|---|---|---|
| NFR-050 | Scan results shall be understandable by non-technical users (Simple mode) | PSM Core |
| NFR-051 | Web interface shall be responsive (mobile-friendly) | PSM Core |
| NFR-052 | Colour-coded risk levels shall meet WCAG AA contrast requirements | PSM Core |

### 3.7 ML Quality

| ID | Requirement | Scope |
|---|---|---|
| NFR-060 | Models shall be evaluated on held-out test set never seen during training | PSM Core |
| NFR-061 | False negative rate shall be reported and minimized as a primary metric | PSM Core |
| NFR-062 | False positive rate shall be reported and monitored | PSM Core |
| NFR-063 | Model calibration shall be measured and reported | PSM Extension |

---

## 4. Complete Feature Specification

Features are tagged: `[Core]`, `[Ext]`, `[Startup]`.

### 4.1 Core Detection

| Feature | Tag | Status |
|---|---|---|
| Phishing classification | Core | Planned |
| Legitimate classification | Core | Planned |
| TF-IDF vectorization | Core | Planned |
| N-gram features (1–2 grams) | Core | Planned |
| Naive Bayes classifier | Core | Planned |
| Logistic Regression classifier | Core | Planned |
| Random Forest classifier | Core | Planned |
| XGBoost classifier | Ext | Planned |
| Specialized URL model | Ext | Planned |
| Advanced NLP / semantic model | Startup | Future |

### 4.2 Email Analysis

| Feature | Tag | Status |
|---|---|---|
| Subject analysis | Core | Planned |
| Body analysis | Core | Planned |
| URL analysis | Core | Planned |
| Sender analysis | Core | Planned |
| Reply-To analysis | Ext | Planned |
| Return-Path analysis | Ext | Planned |
| Email header analysis | Ext | Planned |
| SPF analysis | Ext | Planned |
| DKIM analysis | Ext | Planned |
| DMARC analysis | Ext | Planned |
| Brand impersonation detection | Ext | Planned |

### 4.3 Attachment Analysis

| Feature | Tag | Status |
|---|---|---|
| File type detection (magic bytes) | Ext | Planned |
| Extension mismatch detection | Ext | Planned |
| Hash analysis (SHA-256) | Ext | Planned |
| Embedded URL detection | Ext | Planned |
| Macro detection (OOXML) | Ext | Planned |
| JavaScript detection | Ext | Planned |
| Archive contents listing | Ext | Planned |
| Static attachment risk scoring | Ext | Planned |
| Dynamic sandbox analysis | Startup | Future |

### 4.4 Explainability

| Feature | Tag | Status |
|---|---|---|
| Feature importance | Core | Planned |
| Suspicious text highlighting | Core | Planned |
| URL explanation | Core | Planned |
| Sender explanation | Core | Planned |
| Authentication explanation | Ext | Planned |
| SHAP values | Ext | Planned |
| Counterfactual explanations | Ext | Planned |
| Natural-language explanation | Ext | Planned |
| Three explanation levels (Simple/Detailed/Technical) | Ext | Planned |

### 4.5 Advice Engine

| Feature | Tag | Status |
|---|---|---|
| Risk warning display | Core | Planned |
| General security recommendations | Core | Planned |
| Context-specific advice (by risk level) | Ext | Planned |
| Verification instructions | Ext | Planned |
| User education links | Ext | Planned |

### 4.6 Web Application

| Feature | Tag | Status |
|---|---|---|
| Landing page | Core | Planned |
| Registration | Core | Planned |
| Login | Core | Planned |
| Email scanner (paste/upload) | Core | Planned |
| Scan results page | Core | Planned |
| Scan history | Core | Planned |
| User profile | Core | Planned |
| Admin dashboard | Core | Planned |
| User security overview dashboard | Ext | Planned |
| Learning centre | Ext | Planned |
| Model monitoring panel | Ext | Planned |

### 4.7 Gmail Integration

| Feature | Tag | Status |
|---|---|---|
| Gmail connection via extension | Ext | Planned |
| Google OAuth | Ext | Planned |
| Automatic scanning on email open | Ext | Planned |
| Risk indicator in Gmail UI | Ext | Planned |
| Explanation panel in extension | Ext | Planned |
| Enable/disable automatic scanning | Ext | Planned |
| Manual rescan | Ext | Planned |
| Gmail Workspace Add-on | Startup | Future |

### 4.8 Browser Extension

| Feature | Tag | Status |
|---|---|---|
| Chrome extension (Manifest V3) | Ext | Planned |
| Edge compatibility | Ext | Planned |
| Gmail DOM integration | Ext | Planned |
| Warning UI overlay | Ext | Planned |
| Extension settings page | Ext | Planned |

### 4.9 Feedback and Learning

| Feature | Tag | Status |
|---|---|---|
| Correct/incorrect feedback | Ext | Planned |
| User-provided correct classification | Ext | Planned |
| Category-specific error reporting | Ext | Planned |
| Admin feedback review | Ext | Planned |
| Training dataset generation from approved feedback | Ext | Planned |
| Offline model retraining pipeline | Ext | Planned |
| Model versioning and deployment | Ext | Planned |

### 4.10 Security

| Feature | Tag | Status |
|---|---|---|
| HTTPS | Core | Planned |
| Password hashing | Core | Planned |
| Session/JWT security | Core | Planned |
| Input validation | Core | Planned |
| Rate limiting | Ext | Planned |
| Secure file uploads | Ext | Planned |
| OAuth security | Ext | Planned |
| Audit logging | Ext | Planned |
| Privacy controls | Ext | Planned |

### 4.11 Threat Intelligence

| Feature | Tag | Status |
|---|---|---|
| Local malicious URL database | Ext | Planned |
| Local suspicious domain database | Ext | Planned |
| Local file hash database | Ext | Planned |
| VirusTotal integration | Startup | Future |
| URLhaus integration | Startup | Future |
| Google Safe Browsing integration | Startup | Future |

---

## 5. System Architecture

### 5.1 High-Level Architecture

```
                         ┌───────────────────────┐
                         │       END USERS       │
                         ├───────────────────────┤
                         │ Web Application       │
                         │ Gmail                 │
                         │ Browser Extension     │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │       API SERVER       │
                         ├───────────────────────┤
                         │ Authentication        │
                         │ Email Scan API        │
                         │ User API              │
                         │ Feedback API          │
                         │ Admin API             │
                         └───────────┬───────────┘
                                     │
                                     ▼
                    ┌────────────────────────────────┐
                    │       EMAIL ANALYSIS ENGINE     │
                    ├────────────────────────────────┤
                    │ Email Content Analyzer         │
                    │ URL Analyzer                   │
                    │ Header Analyzer                │
                    │ Sender Analyzer                │
                    │ Authentication Analyzer        │
                    │ Attachment Analyzer            │
                    │ Brand Impersonation Analyzer   │
                    │ Threat Pattern Analyzer        │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                    ┌────────────────────────────────┐
                    │       ML DETECTION ENGINE       │
                    ├────────────────────────────────┤
                    │ Logistic Regression            │
                    │ Naive Bayes                    │
                    │ Random Forest                  │
                    │ XGBoost                        │
                    │ URL Model                      │
                    │ NLP Model                      │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                    ┌────────────────────────────────┐
                    │       RISK FUSION ENGINE        │
                    ├────────────────────────────────┤
                    │ Model predictions              │
                    │ Security rules                 │
                    │ Feature scores                 │
                    │ Authentication results         │
                    │ Attachment results             │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                         ┌───────────────────────┐
                         │    RISK SCORE 0–100   │
                         └───────────┬───────────┘
                                     │
                                     ▼
                    ┌────────────────────────────────┐
                    │      EXPLAINABILITY ENGINE      │
                    ├────────────────────────────────┤
                    │ SHAP                           │
                    │ Feature importance             │
                    │ Suspicious text highlighting   │
                    │ URL / Sender / Auth explanations│
                    │ Counterfactual explanations    │
                    │ Natural-language explanation   │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                    ┌────────────────────────────────┐
                    │       USER RECOMMENDATION       │
                    ├────────────────────────────────┤
                    │ Why dangerous?                 │
                    │ What should I do?              │
                    │ What should I avoid?           │
                    │ How can I verify it?           │
                    └────────────────────────────────┘
```

### 5.2 Component Responsibilities

| Component | Responsibility | Scope |
|---|---|---|
| **Web Application** | User-facing UI for scanning, history, education, admin | Core |
| **API Server** | REST API, authentication, request routing | Core |
| **Email Analysis Engine** | Feature extraction from parsed email objects | Core |
| **ML Detection Engine** | Model inference on extracted features | Core |
| **Risk Fusion Engine** | Weighted combination of all signals into 0–100 score | Core |
| **Explainability Engine** | Generate multi-level explanations and advice | Core |
| **Browser Extension** | Gmail integration, auto-scan, UI overlay | Ext |
| **Worker** | Async jobs: attachment analysis, batch retraining | Ext |

### 5.3 Technology Stack

#### PSM Core Stack (per approved proposal)

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| ML | Scikit-learn, Pandas, NumPy |
| NLP | NLTK / spaCy |
| Database | MySQL |
| Frontend | HTML, CSS, JavaScript |

#### PSM Extension Additions

| Layer | Technology |
|---|---|
| Frontend | React, TypeScript |
| ML | XGBoost, SHAP |
| ORM | SQLAlchemy |
| Cache/Queue | Redis |
| Reverse Proxy | Nginx |
| Containerization | Docker, Docker Compose |

#### Post-PSM Considerations

| Layer | Technology |
|---|---|
| Dedicated ML API | FastAPI (optional) |
| Threat Intel | VirusTotal, URLhaus, Google Safe Browsing |

**Migration note:** Do not migrate away from Flask until PSM Core is complete and stable.

### 5.4 Communication Patterns

| Pattern | Usage |
|---|---|
| Synchronous REST | Scan requests, auth, user CRUD |
| Async task queue (Redis) | Attachment analysis, batch feedback processing |
| WebSocket (optional) | Real-time scan progress for large attachments |

---

## 6. ML Architecture

### 6.1 Multi-Model Strategy

Detection is **not** a single model. The architecture uses specialized models fused by the Risk Fusion Engine.

```
                    EMAIL
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
       CONTENT       URL       METADATA
        MODEL        MODEL       MODEL
          │           │           │
          └───────────┼───────────┘
                      ▼
                 RISK FUSION
                      │
                      ▼
                 FINAL SCORE
```

### 6.2 Models

| Model | Algorithm | Purpose | Scope |
|---|---|---|---|
| **Model 1** | Naive Bayes | Baseline text classifier | Core |
| **Model 2** | Logistic Regression | Primary interpretable classifier | Core |
| **Model 3** | Random Forest | Structured feature comparison | Core |
| **Model 4** | XGBoost | Stronger structured classifier | Ext |
| **Model 5** | URL classifier | Specialized URL phishing detection | Ext |
| **Model 6** | NLP model | Semantic phishing detection | Startup |

**Critical rule:** The advanced model does not replace the explainable model. An interpretable detection layer is always maintained.

### 6.3 Feature Groups

#### Text Features (Core)

- TF-IDF vectors (subject + body combined)
- N-grams (1-gram, 2-gram)
- Linguistic features: urgency word count, threat word count, credential request indicators
- Email length, subject length, exclamation/question mark counts

#### URL Features (Core)

- URL count, max URL length, average URL length
- Domain length, subdomain count, path length
- HTTPS presence, IP address in URL, port number
- URL shortening service detection
- Suspicious TLD detection
- Punycode/homograph detection
- Anchor text vs href mismatch

#### Sender/Metadata Features (Core)

- From domain, Reply-To domain, Return-Path domain
- Reply-To domain mismatch (binary)
- Display name vs domain mismatch
- Domain age proxy (TLD-based heuristics for PSM)
- Free email provider detection

#### Authentication Features (Ext)

- SPF result (pass/fail/none/neutral)
- DKIM result (pass/fail/none)
- DMARC result (pass/fail/none)
- ARC chain presence

#### Attachment Features (Ext)

- Attachment count, total size
- Extension mismatch score
- Macro presence, embedded URL count
- Archive nesting depth
- Hash match against local blocklist

#### Brand Impersonation Features (Ext)

- Claimed brand detection (keyword/NLP)
- Sender domain similarity to known brand domains (Levenshtein)
- Logo/brand mention without matching domain

### 6.4 Model Training Configuration

| Parameter | Value |
|---|---|
| Train/Validation/Test split | 70% / 15% / 15% |
| Cross-validation | 5-fold stratified (during model selection) |
| Random seed | 42 (reproducibility) |
| TF-IDF max features | 10,000 |
| N-gram range | (1, 2) |
| Class balancing | SMOTE or class_weight='balanced' (evaluate both) |

### 6.5 Model Versioning

Every deployed model is recorded as:

```
Model v{major}.{minor}.{patch}
```

Stored metadata: dataset hash, feature list, algorithm, hyperparameters, training date, all evaluation metrics.

Each scan record references the exact model version(s) used.

---

## 7. Detection Pipeline

### 7.1 End-to-End Flow

```
Input (text / .eml / Gmail extension)
        │
        ▼
   Email Parser ──→ Normalized Email Object
        │
        ▼
   Feature Extraction (parallel analysers)
        │
        ├── Content features
        ├── URL features
        ├── Sender features
        ├── Header features
        ├── Auth features
        └── Attachment features
        │
        ▼
   ML Inference (multiple models)
        │
        ▼
   Rule Engine (hard signals)
        │
        ▼
   Risk Fusion Engine
        │
        ▼
   Risk Score (0–100) + Classification
        │
        ▼
   Explainability Engine
        │
        ▼
   Response (score, breakdown, explanations, advice)
        │
        ▼
   Persist (features + scores + explanations, NOT raw email)
```

### 7.2 Risk Score Classification

| Score Range | Classification |
|---|---|
| 0–19 | SAFE |
| 20–39 | LOW RISK |
| 40–59 | SUSPICIOUS |
| 60–79 | HIGH RISK |
| 80–100 | PHISHING |

Thresholds shall be calibrated against validation data. Initial thresholds above are starting points.

### 7.3 Risk Breakdown Categories

| Category | Description |
|---|---|
| Content | Text-based phishing signals |
| URL | Link-based threats |
| Sender | Identity and domain mismatch |
| Authentication | SPF/DKIM/DMARC results |
| Attachment | File-based threats |
| Brand Impersonation | Brand vs sender mismatch |

Example output:

```
PHISHING RISK: 91 / 100

Content                  +16
URL                      +27
Sender                   +13
Authentication           +14
Attachment               +11
Brand impersonation      +10
────────────────────────────
Final Risk                91
```

### 7.4 Risk Fusion Algorithm (Initial)

Weighted sum with caps:

```
risk_score = min(100, Σ (category_weight_i × category_score_i))
```

Initial weights (subject to validation tuning):

| Category | Weight |
|---|---|
| Content | 0.20 |
| URL | 0.25 |
| Sender | 0.15 |
| Authentication | 0.15 |
| Attachment | 0.15 |
| Brand | 0.10 |

Hard rules (override/boost):

- Extension mismatch in attachment (e.g., `.pdf.exe`): +30 boost, floor 80
- SPF fail + Reply-To mismatch + suspicious URL: floor 70
- Authentication pass alone: no automatic safe classification

### 7.5 Rule Engine

Authentication failure alone does **not** automatically mean phishing. Rules provide evidence, not absolute proof.

Hard rules generate explanation entries and may boost category scores; they do not bypass the fusion engine entirely except for known-dangerous attachment patterns.

---

## 8. Explainability Architecture

### 8.1 Design Principle

> ML makes the prediction. The explanation system exposes the evidence.

LLMs may assist natural-language generation (Option B) but never serve as the primary classification authority.

### 8.2 Explanation Components

| Component | Output | Scope |
|---|---|---|
| Feature Importance | Top contributing features with direction | Core |
| Category Breakdown | Per-category risk contribution | Core |
| Text Highlighter | Suspicious phrases marked in body | Core |
| URL Explainer | Displayed vs actual domain, mismatch reason | Core |
| Sender Explainer | From/Reply-To/Return-Path analysis | Core |
| Auth Explainer | SPF/DKIM/DMARC plain-language meaning | Ext |
| SHAP Explainer | Per-feature SHAP values for tree/linear models | Ext |
| Counterfactual Engine | "What would reduce risk?" scenarios | Ext |
| NL Generator | Plain-language summary paragraph | Ext |
| Advice Engine | Do/Don't actions by risk level | Core |

### 8.3 Three Explanation Modes

#### Simple (Core)

For general users. Single paragraph summary.

> This email is suspicious because it contains a fake login link and the sender does not match the organisation it claims to represent.

#### Detailed (Ext)

Structured by category with expandable sections: URL, Sender, Authentication, Content, Attachment, Brand.

#### Technical (Ext)

For security users:

```
Feature: reply_to_domain_mismatch
Value: 1
Model: Random Forest
Contribution: High (+0.23)
Model Version: v1.4.2
```

### 8.4 Counterfactual Explanations

```
Current risk: 86/100

What would make this email less suspicious?

Current:
  SPF = FAIL
  Reply-To mismatch = YES
  Suspicious URL = YES

If changed to:
  SPF = PASS
  Reply-To mismatch = NO
  Suspicious URL = NO

Estimated risk: 31/100
```

Implementation: perturb feature vector, re-run fusion engine, report delta. Mark as estimated, not guaranteed.

### 8.5 Advice Engine Templates

#### High Risk / Phishing

```
DO NOT:
  ❌ Click links
  ❌ Download attachments
  ❌ Reply to the sender
  ❌ Enter your password
  ❌ Provide financial information

DO:
  ✓ Verify the sender independently
  ✓ Open the organisation's official website directly
  ✓ Contact the organisation through official channels
  ✓ Report the email as phishing
```

Advice templates are selected by classification level and triggered explanation categories.

---

## 9. Email Parsing Architecture

### 9.1 Supported Input Formats

| Format | Scope |
|---|---|
| Raw pasted text | Core |
| Plain-text email | Core |
| HTML email | Core |
| `.eml` (RFC 822) | Ext |
| Gmail DOM extraction (extension) | Ext |

### 9.2 Normalized Email Object

All detection modules consume a single standardized structure:

```json
{
  "message_id": "uuid",
  "subject": "string",
  "sender": {
    "display_name": "string",
    "email": "string",
    "domain": "string"
  },
  "reply_to": {
    "display_name": "string",
    "email": "string",
    "domain": "string"
  },
  "return_path": "string",
  "recipients": ["string"],
  "date": "ISO8601",
  "body": {
    "plain": "string",
    "html": "string"
  },
  "urls": [
    {
      "href": "string",
      "anchor_text": "string",
      "displayed_text": "string"
    }
  ],
  "attachments": [
    {
      "filename": "string",
      "content_type": "string",
      "size_bytes": 0,
      "content_base64": "string (transient, not persisted)"
    }
  ],
  "headers": {
    "received": ["string"],
    "authentication_results": "string",
    "dkim_signature": "string",
    "spf": "string",
    "dmarc": "string"
  },
  "raw_headers": {}
}
```

### 9.3 Parser Pipeline

```
Input
  │
  ├─ Paste text ──→ Heuristic parser (regex for headers + body)
  ├─ .eml file ──→ Python email.parser (stdlib)
  └─ Gmail DOM ──→ Extension content script extractor
  │
  ▼
HTML sanitization (bleach)
  │
  ▼
URL extraction (BeautifulSoup + regex fallback)
  │
  ▼
Header normalization
  │
  ▼
Normalized Email Object
```

### 9.4 HTML Processing

- Strip scripts and active content
- Extract visible text for NLP
- Preserve link href vs anchor text pairs
- Decode HTML entities

---

## 10. Attachment Analysis Architecture

### 10.1 Scope

PSM Extension implements **static analysis only**. Sandboxing is Post-PSM Startup.

### 10.2 Supported File Types (Initial)

PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, ZIP, RAR, HTML, JS, LNK, EXE, ISO

### 10.3 Analysis Pipeline

```
                Attachment
                     │
                     ▼
              File Validation
              (size, type, name)
                     │
                     ▼
              Static Analysis
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
        Hash       Content      URLs
       Analysis    Analysis    Analysis
          │          │          │
          └──────────┼──────────┘
                     ▼
              Attachment Risk Score
```

### 10.4 Static Checks

| Check | Description |
|---|---|
| Extension vs magic bytes | Detect `invoice.pdf.exe` disguises |
| Double extension | Flag `file.pdf.exe`, `file.doc.js` |
| File size anomaly | Tiny executables, oversized archives |
| SHA-256 hash | Match against local hash blocklist |
| Embedded URLs | Extract URLs from PDF/HTML/Office docs |
| Macro detection | Check for VBA macros in OOXML |
| JavaScript | Detect JS in PDF/HTML attachments |
| Archive nesting | List contents of ZIP/RAR without extraction beyond 1 level |
| Dangerous types | Flag EXE, LNK, ISO, JS outright |

### 10.5 Security Constraints

- Maximum upload size: 10 MB (PSM), configurable
- Files processed in isolated temp directory
- Files deleted immediately after analysis (default)
- No execution of uploaded files

---

## 11. Gmail / Chrome / Edge Architecture

### 11.1 Integration Layers

Two integration paths, prioritized:

#### Layer 1: Browser Extension (Primary — PSM Extension)

```
Gmail UI
   ↓
Chrome/Edge Extension (Manifest V3)
   ↓
Content Script (Gmail DOM observer)
   ↓
Background Service Worker
   ↓
Backend Detection API
   ↓
Risk Score + Explanation
   ↓
Extension UI Overlay (badge + panel)
```

#### Layer 2: Gmail API (Secondary — PSM Extension / Startup)

```
Gmail
   ↓
Google OAuth 2.0
   ↓
Gmail API
   ↓
Backend
```

Layer 2 provides flexibility and reduces dependence on Gmail DOM structure.

### 11.2 Automatic Scan Flow

```
User opens Gmail email
        ↓
Extension detects email open (MutationObserver)
        ↓
Extract email data (subject, sender, body, links)
        ↓
Check user settings (auto-scan ON/OFF)
        ↓
Send normalized payload to POST /api/v1/scan
        ↓
Receive risk score + explanation
        ↓
Display warning badge / side panel
```

### 11.3 Extension Settings

| Setting | Default |
|---|---|
| Automatic scanning | ON |
| Scan attachments | ON |
| Show warnings | ON |
| Explanation detail level | Simple |

### 11.4 Chrome → Edge Strategy

Build for Chrome (Manifest V3) first. Test and package for Microsoft Edge. Both are Chromium-based; architecture is highly reusable.

### 11.5 Extension Permissions (Minimal)

- `activeTab` or host permission for `mail.google.com` only
- `storage` for settings
- No broad `<all_urls>` permission

---

## 12. Database ERD

### 12.1 Entity Relationship Diagram

```
┌─────────────┐       ┌─────────────────┐       ┌──────────────────┐
│    users    │       │   email_scans   │       │  email_features  │
├─────────────┤       ├─────────────────┤       ├──────────────────┤
│ id (PK)     │──┐    │ id (PK)         │──┐    │ id (PK)          │
│ email       │  └───→│ user_id (FK)    │  └───→│ scan_id (FK)     │
│ password_hash│      │ provider        │       │ content_score    │
│ role        │       │ message_hash    │       │ url_score        │
│ created_at  │       │ classification  │       │ sender_score     │
│ updated_at  │       │ risk_score      │       │ auth_score       │
└─────────────┘       │ model_version   │       │ attachment_score │
                      │ created_at      │       │ brand_score      │
                      └────────┬────────┘       └──────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
     ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
     │ explanations │  │   feedback   │  │ oauth_tokens │
     ├──────────────┤  ├──────────────┤  ├──────────────┤
     │ id (PK)      │  │ id (PK)      │  │ id (PK)      │
     │ scan_id (FK) │  │ scan_id (FK) │  │ user_id (FK) │
     │ type         │  │ user_id (FK) │  │ provider     │
     │ category     │  │ is_correct   │  │ access_token │
     │ feature      │  │ actual_label │  │ refresh_token│
     │ contribution │  │ error_categ. │  │ expires_at   │
     │ severity     │  │ reviewed     │  │ created_at   │
     │ explanation  │  │ created_at   │  └──────────────┘
     └──────────────┘  └──────────────┘

┌──────────────────┐       ┌──────────────────┐
│  model_versions  │       │  audit_logs      │
├──────────────────┤       ├──────────────────┤
│ id (PK)          │       │ id (PK)          │
│ version          │       │ user_id (FK)     │
│ algorithm        │       │ action           │
│ dataset_hash     │       │ resource         │
│ feature_list     │       │ ip_address       │
│ hyperparameters  │       │ created_at       │
│ precision        │       └──────────────────┘
│ recall           │
│ f1               │       ┌──────────────────┐
│ roc_auc          │       │ threat_intel_*   │
│ pr_auc           │       │ (url/domain/hash)│
│ fpr              │       └──────────────────┘
│ fnr              │
│ is_active        │
│ created_at       │
└──────────────────┘
```

### 12.2 Table Definitions

#### users

| Column | Type | Notes |
|---|---|---|
| id | INT PK AUTO_INCREMENT | |
| email | VARCHAR(255) UNIQUE NOT NULL | |
| password_hash | VARCHAR(255) NOT NULL | bcrypt |
| role | ENUM('user','admin') | Default 'user' |
| created_at | DATETIME | |
| updated_at | DATETIME | |

#### email_scans

| Column | Type | Notes |
|---|---|---|
| id | INT PK AUTO_INCREMENT | |
| user_id | INT FK → users.id | Nullable for anonymous scans |
| provider | ENUM('web','extension','gmail_api') | |
| message_hash | VARCHAR(64) | SHA-256 of subject+sender+date |
| classification | ENUM('safe','low_risk','suspicious','high_risk','phishing') | |
| risk_score | TINYINT | 0–100 |
| model_version | VARCHAR(20) | e.g., v1.2.0 |
| created_at | DATETIME | |

**Note:** Raw email body is NOT stored in this table.

#### email_features

| Column | Type | Notes |
|---|---|---|
| id | INT PK AUTO_INCREMENT | |
| scan_id | INT FK → email_scans.id | |
| content_score | TINYINT | 0–100 |
| url_score | TINYINT | 0–100 |
| sender_score | TINYINT | 0–100 |
| auth_score | TINYINT | 0–100 |
| attachment_score | TINYINT | 0–100 |
| brand_score | TINYINT | 0–100 |
| feature_vector | JSON | Serialized feature dict |

#### explanations

| Column | Type | Notes |
|---|---|---|
| id | INT PK AUTO_INCREMENT | |
| scan_id | INT FK → email_scans.id | |
| type | ENUM('simple','detailed','technical') | |
| category | VARCHAR(50) | content, url, sender, etc. |
| feature | VARCHAR(100) | Nullable |
| contribution | DECIMAL(5,2) | Nullable |
| severity | ENUM('info','warning','critical') | |
| explanation | TEXT | Human-readable text |

#### feedback

| Column | Type | Notes |
|---|---|---|
| id | INT PK AUTO_INCREMENT | |
| scan_id | INT FK → email_scans.id | |
| user_id | INT FK → users.id | |
| is_correct | BOOLEAN | |
| actual_label | ENUM('legitimate','phishing') | Nullable |
| error_categories | JSON | Array of category strings |
| reviewed | BOOLEAN DEFAULT FALSE | Admin approval flag |
| created_at | DATETIME | |

#### model_versions

| Column | Type | Notes |
|---|---|---|
| id | INT PK AUTO_INCREMENT | |
| version | VARCHAR(20) UNIQUE | |
| algorithm | VARCHAR(50) | |
| dataset_hash | VARCHAR(64) | |
| feature_list | JSON | |
| hyperparameters | JSON | |
| precision | DECIMAL(5,4) | |
| recall | DECIMAL(5,4) | |
| f1 | DECIMAL(5,4) | |
| roc_auc | DECIMAL(5,4) | |
| pr_auc | DECIMAL(5,4) | |
| fpr | DECIMAL(5,4) | |
| fnr | DECIMAL(5,4) | |
| is_active | BOOLEAN DEFAULT FALSE | |
| created_at | DATETIME | |

---

## 13. API Endpoint Specification

Base URL: `https://{domain}/api/v1`

All endpoints return JSON. Authenticated endpoints require `Authorization: Bearer {jwt}`.

### 13.1 Authentication

| Method | Endpoint | Description | Scope |
|---|---|---|---|
| POST | `/auth/register` | Register new user | Core |
| POST | `/auth/login` | Login, returns JWT | Core |
| POST | `/auth/logout` | Invalidate session/token | Core |
| GET | `/auth/me` | Current user profile | Core |
| GET | `/auth/google` | Initiate Google OAuth | Ext |
| GET | `/auth/google/callback` | OAuth callback | Ext |

#### POST /auth/register

Request:
```json
{
  "email": "user@example.com",
  "password": "securepassword"
}
```

Response (201):
```json
{
  "id": 1,
  "email": "user@example.com",
  "role": "user"
}
```

#### POST /auth/login

Response (200):
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### 13.2 Email Scanning

| Method | Endpoint | Description | Scope |
|---|---|---|---|
| POST | `/scan` | Scan email (text or structured) | Core |
| POST | `/scan/eml` | Scan uploaded .eml file | Ext |
| POST | `/scan/attachment` | Analyse single attachment | Ext |
| GET | `/scan/{scan_id}` | Get scan result | Core |
| GET | `/scan/history` | User's scan history (paginated) | Core |

#### POST /scan

Request:
```json
{
  "subject": "Urgent: Verify your account",
  "sender": "support@micr0soft-security.com",
  "reply_to": "attacker@evil.com",
  "body": "Click here to verify: http://fake-login.example.com",
  "headers": {
    "authentication-results": "spf=fail dkim=fail dmarc=fail"
  },
  "explanation_level": "simple"
}
```

Response (200):
```json
{
  "scan_id": 42,
  "risk_score": 91,
  "classification": "phishing",
  "breakdown": {
    "content": 16,
    "url": 27,
    "sender": 13,
    "authentication": 14,
    "attachment": 0,
    "brand": 10
  },
  "explanations": [
    {
      "category": "url",
      "severity": "critical",
      "text": "The email contains a link whose actual domain does not match the organisation mentioned."
    }
  ],
  "advice": {
    "do_not": ["Click links", "Download attachments"],
    "do": ["Verify the sender independently", "Report as phishing"]
  },
  "model_version": "v1.0.0",
  "created_at": "2026-08-22T12:00:00Z"
}
```

### 13.3 Feedback

| Method | Endpoint | Description | Scope |
|---|---|---|---|
| POST | `/feedback` | Submit scan feedback | Ext |
| GET | `/feedback` | Admin: list feedback (paginated) | Ext |
| PATCH | `/feedback/{id}/review` | Admin: approve/reject feedback | Ext |

#### POST /feedback

Request:
```json
{
  "scan_id": 42,
  "is_correct": false,
  "actual_label": "legitimate",
  "error_categories": ["sender", "url"]
}
```

### 13.4 User

| Method | Endpoint | Description | Scope |
|---|---|---|---|
| GET | `/user/stats` | User security overview stats | Ext |
| GET | `/user/settings` | Get user preferences | Ext |
| PUT | `/user/settings` | Update preferences | Ext |

### 13.5 Admin

| Method | Endpoint | Description | Scope |
|---|---|---|---|
| GET | `/admin/users` | List users | Core |
| GET | `/admin/scans` | Scan statistics | Core |
| GET | `/admin/models` | Model versions and metrics | Core |
| GET | `/admin/health` | System health | Ext |
| POST | `/admin/models/deploy` | Activate model version | Ext |

### 13.6 Extension

| Method | Endpoint | Description | Scope |
|---|---|---|---|
| POST | `/extension/scan` | Scan from extension (same as /scan with provider tag) | Ext |
| GET | `/extension/settings` | Extension-specific settings | Ext |

### 13.7 Error Response Format

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Email body is required",
    "details": []
  }
}
```

HTTP status codes: 400 (validation), 401 (unauthorized), 403 (forbidden), 404 (not found), 429 (rate limit), 500 (internal).

---

## 14. Authentication Architecture

### 14.1 PSM Core: Email + Password

- Registration with email validation
- Password minimum: 8 characters
- Hashing: bcrypt (cost factor 12)
- Session: JWT (HS256) with 1-hour expiry
- Refresh token: 7-day expiry, stored in HTTP-only cookie

### 14.2 PSM Extension: Google OAuth 2.0

- OAuth 2.0 authorization code flow
- Scopes: `openid`, `email`, `profile` (login); `gmail.readonly` (Gmail integration, separate consent)
- Tokens encrypted at rest (Fernet/AES)
- Token refresh handled by background job

### 14.3 Role-Based Access Control

| Role | Permissions |
|---|---|
| user | Scan, view own history, submit feedback, manage own settings |
| admin | All user permissions + admin dashboard, user management, model management, feedback review |

Route protection via Flask decorators / middleware checking JWT claims.

### 14.4 JWT Payload

```json
{
  "sub": "user_id",
  "email": "user@example.com",
  "role": "user",
  "exp": 1234567890,
  "iat": 1234564290
}
```

---

## 15. Security Architecture

### 15.1 Application Security

| Threat | Mitigation | Scope |
|---|---|---|
| SQL Injection | Parameterized queries (SQLAlchemy ORM) | Core |
| XSS | Output encoding, CSP headers, HTML sanitization | Core |
| CSRF | CSRF tokens on forms, SameSite cookies | Core |
| Authentication bypass | JWT validation middleware on all protected routes | Core |
| Broken access control | RBAC, scan ownership checks | Core |
| File upload attacks | Type validation, size limits, temp dir isolation | Ext |
| Malicious email parsing | Parser limits, timeout, memory caps | Core |
| SSRF (URL analyser) | Block internal IP resolution, no automatic URL fetching in PSM | Core |
| API abuse | Rate limiting (Redis-backed) | Ext |
| OAuth issues | State parameter, PKCE, token encryption | Ext |

### 15.2 Rate Limiting

| Endpoint | Limit |
|---|---|
| POST /scan | 30 requests/minute per user |
| POST /auth/login | 10 requests/minute per IP |
| POST /auth/register | 5 requests/minute per IP |

### 15.3 Security Headers

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; ...
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
```

### 15.4 Audit Logging

Log: login attempts, scan requests, admin actions, model deployments, feedback reviews. Store: user_id, action, resource, IP, timestamp.

---

## 16. Privacy Architecture

### 16.1 Default Data Flow

```
Email Input
    ↓
Temporary in-memory processing
    ↓
Feature extraction
    ↓
Risk score + explanation generation
    ↓
Persist: scan_id, message_hash, scores, features, explanations, model_version
    ↓
Delete: raw email body, attachment content
```

### 16.2 What Is Stored

| Data | Stored | Reason |
|---|---|---|
| Scan ID | Yes | Reference |
| Message hash (SHA-256) | Yes | Deduplication |
| Risk score + classification | Yes | History |
| Category feature scores | Yes | Breakdown display |
| Explanations | Yes | Result display |
| Model version | Yes | Auditability |
| User feedback | Yes | Training pipeline |
| Raw email body | **No** (default) | Privacy |
| Attachment content | **No** (default) | Privacy |
| Gmail OAuth tokens | Yes (encrypted) | Integration |

### 16.3 User Controls

- Opt-in extended retention (store email subject + sender for history display)
- Delete scan history
- Disconnect Gmail integration (revoke tokens)
- Export personal data

### 16.4 Extension Privacy

- Extension extracts only visible email data
- Auto-scan can be disabled
- No background scanning of emails not opened by user
- Clear privacy policy displayed during extension install

---

## 17. Model Training Pipeline

### 17.1 Pipeline Overview

```
Raw Dataset(s)
    ↓
Collection & Merge
    ↓
Cleaning (dedup, label validation, encoding normalization)
    ↓
Feature Engineering (TF-IDF, n-grams, metadata features)
    ↓
Train/Val/Test Split (stratified)
    ↓
Model Training (NB, LR, RF, XGBoost)
    ↓
Hyperparameter Tuning (GridSearchCV / RandomizedSearchCV)
    ↓
Evaluation (all metrics)
    ↓
Model Selection
    ↓
Version & Register (model_versions table)
    ↓
Deploy (copy to inference directory, update is_active flag)
```

### 17.2 Training Scripts Location

```
ml/
├── datasets/
├── preprocessing/
│   ├── clean.py
│   └── split.py
├── features/
│   ├── text_features.py
│   ├── url_features.py
│   └── metadata_features.py
├── models/
│   ├── naive_bayes.py
│   ├── logistic_regression.py
│   ├── random_forest.py
│   └── xgboost_model.py
├── training/
│   ├── train.py
│   └── tune.py
└── evaluation/
    ├── evaluate.py
    └── compare_models.py
```

### 17.3 Reproducibility

- Fixed random seed (42)
- Dataset version hash recorded
- All hyperparameters saved in model_versions
- Training scripts runnable via CLI: `python -m ml.training.train --model random_forest --version v1.0.0`

### 17.4 Inference

- Models loaded at application startup (Flask app factory)
- Inference via Scikit-learn `predict` / `predict_proba`
- Model files stored in `ml/models/artifacts/`
- Active model version read from config/DB

---

## 18. Dataset Strategy

### 18.1 Data Sources

| Dataset | Type | Scope |
|---|---|---|
| Enron Spam / Ling Spam | Legitimate + spam baseline | Core |
| Nazario Phishing Corpus | Known phishing emails | Core |
| PhishTank / OpenPhish feeds | Phishing URLs (for URL features) | Core |
| Custom collected samples | Localized/recent phishing | Ext |
| User feedback (admin-approved) | Real-world corrections | Ext |

### 18.2 Dataset Requirements

| Requirement | Detail |
|---|---|
| Minimum size | ≥ 5,000 emails (combined) |
| Label balance | Report imbalance; apply balancing techniques |
| Duplicate removal | Exact + near-duplicate (hash-based) |
| Label validation | Manual review of random 5% sample |
| Language | English primary; document limitations |

### 18.3 Feature Comparison Study (PSM Evaluation)

Train and evaluate:

1. **Text-only model** (TF-IDF + n-grams)
2. **Text + metadata model** (TF-IDF + URL + sender features)

Compare all metrics. This directly supports the PSM evaluation chapter.

### 18.4 Data Storage

- Raw datasets in `ml/datasets/raw/` (gitignored)
- Processed datasets in `ml/datasets/processed/`
- Dataset hashes recorded in model_versions

---

## 19. Model Evaluation Methodology

### 19.1 Metrics

| Metric | Purpose |
|---|---|
| Accuracy | Overall correctness |
| Precision | Minimize false alarms |
| Recall | Minimize missed phishing (critical) |
| F1-score | Balance precision and recall |
| ROC-AUC | Threshold-independent performance |
| PR-AUC | Performance on imbalanced data |
| False Positive Rate (FPR) | Legitimate emails flagged as phishing |
| False Negative Rate (FNR) | Phishing emails marked safe (most critical) |
| Confusion Matrix | Full error breakdown |
| Model Calibration | Predicted probabilities vs actual outcomes |

### 19.2 Evaluation Protocol

1. Train on training set (70%)
2. Tune hyperparameters on validation set (15%)
3. Final evaluation **once** on held-out test set (15%)
4. Report all metrics with confidence intervals where applicable
5. Compare text-only vs text+metadata models
6. Compare NB vs LR vs RF (and XGBoost if implemented)

### 19.3 Security-Focused Evaluation

Beyond standard test set:

| Test Category | Description | Scope |
|---|---|---|
| Known dataset | Standard held-out test | Core |
| Unseen dataset | Completely new phishing samples | Core |
| Adversarial emails | URL obfuscation, homographs | Ext |
| BEC samples | Business email compromise patterns | Ext |
| Brand impersonation | Fake Microsoft/PayPal/Apple | Ext |
| Attachment phishing | Malicious attachment scenarios | Ext |
| AI-generated phishing | LLM-generated phishing text | Ext |

### 19.4 User Evaluation (Explainability)

Give users a set of emails and measure:

- Detection accuracy (user vs system)
- User understanding (pre/post explanation quiz)
- Trust rating (Likert scale)
- Decision confidence
- Explanation usefulness rating

This provides evidence that explainability features add value.

---

## 20. Feedback / Retraining Pipeline

### 20.1 Critical Rule

> User clicks "wrong" → **does NOT** immediately retrain the production model.

Feedback must pass through validation to prevent model poisoning.

### 20.2 Pipeline

```
User Feedback (👍/👎)
    ↓
Feedback Database (reviewed = false)
    ↓
Admin Review (approve / reject)
    ↓
Approved Feedback → Labeled Training Data
    ↓
Merge with Existing Dataset
    ↓
Offline Retraining (new model version)
    ↓
Evaluation on Test Set
    ↓
Admin Approval for Deployment
    ↓
Deploy New Model Version
```

### 20.3 Feedback UI

After scan result:

```
Was this result correct?
    👍 Yes      👎 No

If No:
    What was the correct classification?
    ○ Legitimate    ○ Phishing

    What did we get wrong? (optional)
    □ Sender  □ URL  □ Content  □ Attachment  □ Authentication  □ Other
```

### 20.4 Retraining Triggers

- Manual admin trigger (primary for PSM)
- Automatic trigger when approved feedback count exceeds threshold (e.g., 500) — Ext
- Scheduled retraining (monthly) — Startup

---

## 21. Web UI / Page Structure

### 21.1 Page Map

```
/                           Landing page
/register                   Registration
/login                      Login
/dashboard                  User dashboard
/scan                       Email scanner
/scan/{id}                  Scan result detail
/history                    Scan history
/profile                    User profile
/settings                   User settings
/learn                      Learning centre [Ext]
/admin                      Admin dashboard
/admin/users                User management
/admin/scans                Scan statistics
/admin/models               Model management
/admin/feedback             Feedback review [Ext]
```

### 21.2 User Dashboard

```
Dashboard
├── Scan Email
├── Recent Scans
├── Risk Statistics
├── Learning Centre [Ext]
├── Feedback [Ext]
├── Settings
└── Gmail Integration [Ext]
```

Example security overview:

```
Your Security Overview

Emails scanned        1,248
Phishing detected       83
Suspicious             142
Safe                  1,023
```

### 21.3 Scan Result Page

```
┌─────────────────────────────────────────────┐
│  ⚠ HIGH RISK EMAIL                          │
│  Risk Score: 91/100                         │
│  Classification: PHISHING                   │
├─────────────────────────────────────────────┤
│  Risk Breakdown                             │
│  [Content 16] [URL 27] [Sender 13] ...      │
├─────────────────────────────────────────────┤
│  Why is this dangerous?                     │
│  🔴 Suspicious URL                          │
│  🔴 Sender mismatch                         │
│  🔴 Authentication failure                  │
│  🟠 Urgent language                         │
│  🟠 Brand impersonation                     │
├─────────────────────────────────────────────┤
│  What should I do?                          │
│  ❌ Do not click links                      │
│  ✓ Verify sender independently             │
├─────────────────────────────────────────────┤
│  Was this result correct?  👍  👎          │
└─────────────────────────────────────────────┘
```

### 21.4 Admin Dashboard

```
ADMIN DASHBOARD
├── Users
├── Scans (Phishing / Suspicious / Legitimate)
├── Feedback [Ext]
├── Model Performance
│   ├── Version: v1.2.0
│   ├── Precision: 96.1%
│   ├── Recall: 95.4%
│   ├── F1: 95.7%
│   ├── FPR: 2.4%
│   └── FNR: 1.8%
└── System Health [Ext]
```

### 21.5 UI Technology

| Phase | Frontend |
|---|---|
| PSM Core | Server-rendered HTML/CSS/JS (Flask templates) |
| PSM Extension | React + TypeScript SPA |

---

## 22. Browser Extension Structure

### 22.1 Directory Layout

```
extension/
├── manifest.json
├── background/
│   └── service-worker.js
├── content/
│   ├── gmail-detector.js
│   ├── email-extractor.js
│   └── ui-overlay.js
├── popup/
│   ├── popup.html
│   ├── popup.js
│   └── popup.css
├── settings/
│   ├── settings.html
│   └── settings.js
├── assets/
│   └── icons/
└── utils/
    ├── api-client.js
    └── storage.js
```

### 22.2 Manifest V3 Configuration

```json
{
  "manifest_version": 3,
  "name": "Phishing Email Detector",
  "version": "1.0.0",
  "permissions": ["storage"],
  "host_permissions": ["https://mail.google.com/*"],
  "background": {
    "service_worker": "background/service-worker.js"
  },
  "content_scripts": [
    {
      "matches": ["https://mail.google.com/*"],
      "js": ["content/gmail-detector.js", "content/email-extractor.js", "content/ui-overlay.js"],
      "css": ["content/overlay.css"]
    }
  ],
  "action": {
    "default_popup": "popup/popup.html"
  }
}
```

### 22.3 UI Components

| Component | Description |
|---|---|
| Risk Badge | Coloured indicator on email row / open email |
| Warning Banner | Top-of-email alert for high-risk |
| Side Panel | Detailed explanation and advice |
| Popup | Quick status, settings link, manual scan button |
| Settings Page | Auto-scan toggle, explanation level, API connection |

---

## 23. Docker / Deployment Architecture

### 23.1 Deployment Diagram

```
                 INTERNET
                     │
                     ▼
                Cloudflare (DNS + SSL + DDoS)
                     │
                     ▼
               Nginx (Reverse Proxy)
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
      Frontend (React/static)   Backend (Flask)
                                  │
                     ┌────────────┼───────────┐
                     ▼            ▼           ▼
                  ML Models     MySQL       Redis
                  (artifacts)  (database)   (cache/queue)
                                  │
                                  ▼
                               Worker
                          (async tasks)
```

### 23.2 Docker Compose Services

```yaml
services:
  frontend:    # React app or Nginx serving static files
  backend:     # Flask API + ML inference
  database:    # MySQL 8
  redis:       # Cache + task queue
  worker:      # Celery/RQ worker for async jobs
  nginx:       # Reverse proxy + SSL termination
```

### 23.3 Environment Configuration

Secrets via environment variables (`.env`, not committed):

```
DATABASE_URL=mysql://user:pass@database:3306/phishing_db
REDIS_URL=redis://redis:6379/0
JWT_SECRET=...
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
MODEL_VERSION=v1.0.0
```

### 23.4 PSM Deployment Target

The PSM prototype must be accessible at:

```
https://your-domain.com
```

Not `localhost:5000`. Use Cloudflare + VPS or cloud provider (e.g., DigitalOcean, AWS Lightsail).

---

## 24. GitHub Repository Structure

```
phishing-detection-system/
│
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── api/
│   │   │   ├── auth.py
│   │   │   ├── scan.py
│   │   │   ├── feedback.py
│   │   │   ├── admin.py
│   │   │   └── extension.py
│   │   ├── auth/
│   │   │   ├── jwt.py
│   │   │   └── oauth.py
│   │   ├── detection/
│   │   │   ├── pipeline.py
│   │   │   ├── risk_fusion.py
│   │   │   └── rule_engine.py
│   │   ├── email_parser/
│   │   │   ├── parser.py
│   │   │   ├── html_parser.py
│   │   │   └── eml_parser.py
│   │   ├── explainability/
│   │   │   ├── explainer.py
│   │   │   ├── shap_explainer.py
│   │   │   ├── counterfactual.py
│   │   │   └── advice.py
│   │   ├── attachments/
│   │   │   ├── validator.py
│   │   │   └── static_analyzer.py
│   │   ├── analyzers/
│   │   │   ├── content.py
│   │   │   ├── url.py
│   │   │   ├── sender.py
│   │   │   ├── header.py
│   │   │   ├── auth.py
│   │   │   └── brand.py
│   │   ├── users/
│   │   │   └── models.py
│   │   └── database/
│   │       ├── models.py
│   │       └── migrations/
│   ├── tests/
│   ├── requirements.txt
│   └── wsgi.py
│
├── ml/
│   ├── datasets/
│   ├── preprocessing/
│   ├── features/
│   ├── models/
│   │   └── artifacts/
│   ├── training/
│   └── evaluation/
│
├── frontend/
│   ├── public/
│   ├── src/
│   └── package.json
│
├── extension/
│   ├── manifest.json
│   ├── background/
│   ├── content/
│   ├── popup/
│   └── settings/
│
├── gmail/
│   └── oauth/
│
├── docker/
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   ├── Dockerfile.worker
│   └── nginx.conf
│
├── docs/
│   ├── MASTER_TECHNICAL_SPECIFICATION.md
│   ├── API.md
│   └── DEPLOYMENT.md
│
├── scripts/
│   ├── setup.sh
│   ├── train_models.sh
│   └── deploy.sh
│
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md
```

---

## 25. PSM1 / PSM2 Development Mapping

### 25.1 PSM1 (Proposal Phase — Completed)

| Deliverable | Status |
|---|---|
| Project title and classification | ✅ Submitted |
| Problem statement and objectives | ✅ Submitted |
| Literature review | ✅ Submitted |
| Methodology overview | ✅ Submitted |
| Technology stack selection | ✅ Submitted |
| Initial system design | ✅ Submitted |
| Timeline / Gantt chart | ✅ Submitted |

### 25.2 PSM2 (Implementation Phase)

| Chapter | Content | Maps To |
|---|---|---|
| Introduction | Problem, objectives, scope (Core vs Extension) | Sections 1, 4 |
| Literature Review | ML phishing detection, XAI, email security | Section 6 |
| Methodology | System design, ML pipeline, evaluation | Sections 5–7, 17–19 |
| System Design | Architecture, ERD, API, UI | Sections 5, 12, 13, 21 |
| Implementation | Sprint deliverables, screenshots, code | Sections 24, 26 |
| Evaluation | ML metrics, security testing, user study | Sections 19, 27 |
| Conclusion | Summary, limitations, future work | Section 28 |

### 25.3 Scope Framing for Supervisor

> "The core PSM implementation focuses on the approved machine-learning phishing detection system with web-based analysis, explainability, and online deployment. The Gmail integration, browser extension, and advanced components are extensions of the prototype architecture documented as PSM Extension features."

---

## 26. Sprint / Gantt Plan

### 26.1 Sprint Overview

| Sprint | Focus | Duration | Scope Tag | Key Deliverables |
|---|---|---|---|---|
| 1 | Requirements & Architecture | 1 week | Core | This document, ERD, API spec |
| 2 | Dataset & Preprocessing | 2 weeks | Core | Clean training dataset, feature extraction |
| 3 | Baseline ML | 2 weeks | Core | NB, LR, RF trained and evaluated |
| 4 | Enhanced Detection | 2 weeks | Core | URL/sender/header features, comparison study |
| 5 | Email Parser | 1 week | Core/Ext | Normalized email object, .eml support |
| 6 | Risk Engine | 1 week | Core | Fusion engine, 0–100 score, classification |
| 7 | Explainability | 2 weeks | Core/Ext | Explanations, advice, highlighting |
| 8 | Web Application | 3 weeks | Core | Full web app with auth, scan, history, admin |
| 9 | Attachment Analysis | 2 weeks | Ext | Static analysis pipeline |
| 10 | Feedback Learning | 1 week | Ext | Feedback UI, admin review, retraining pipeline |
| 11 | Browser Extension | 2 weeks | Ext | Chrome MV3 extension for Gmail |
| 12 | Gmail Integration | 2 weeks | Ext | OAuth, auto-scan, settings |
| 13 | Deployment | 1 week | Core | Docker, HTTPS, online deployment |
| 14 | Security Testing | 1 week | Core/Ext | OWASP testing, pen test checklist |
| 15 | ML Evaluation | 2 weeks | Core | Full evaluation report |
| 16 | User Evaluation | 1 week | Ext | Explainability user study |

**Total estimated duration:** ~26 weeks

### 26.2 Gantt Chart

```
Sprint:  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16
         ├──┤
         Req/Arch
            ├────┤
            Data/Preproc
                 ├────┤
                 Baseline ML
                      ├────┤
                      Enhanced Detect
                           ├─┤
                           Parser
                             ├─┤
                             Risk Engine
                               ├────┤
                               Explain
                                    ├──────┤
                                    Web App
                                           ├────┤
                                           Attach
                                                ├─┤
                                                Feedback
                                                  ├────┤
                                                  Extension
                                                       ├────┤
                                                       Gmail
                                                            ├─┤
                                                            Deploy
                                                              ├─┤
                                                              Security
                                                                 ├────┤
                                                                 ML Eval
                                                                      ├─┤
                                                                      User Eval
```

### 26.3 Milestone Checkpoints

| Milestone | Sprint | Criteria |
|---|---|---|
| M1: ML Baseline Working | 3 | 3 models trained, metrics reported |
| M2: Detection Pipeline Complete | 6 | End-to-end scan returns risk score |
| M3: Web App Demo | 8 | Online web app with scan + results |
| M4: PSM Core Complete | 8 + 13 | All Core features deployed online |
| M5: Extension Demo | 11 | Gmail extension shows risk badge |
| M6: Full Evaluation | 15 | ML + security + user evaluation done |

---

## 27. Testing Strategy

### 27.1 Testing Levels

| Level | Scope | Tools |
|---|---|---|
| Unit Tests | Individual functions, analysers, parsers | pytest |
| Integration Tests | API endpoints, DB operations, pipeline | pytest + Flask test client |
| ML Tests | Model reproducibility, metric thresholds | pytest + custom scripts |
| Security Tests | OWASP Top 10, auth bypass, injection | Manual + OWASP ZAP |
| E2E Tests | Full user flows (scan, login, history) | Selenium / Playwright |
| Extension Tests | Gmail extraction, API communication | Manual + Chrome dev tools |
| Performance Tests | API response time under load | locust / k6 |
| User Acceptance | Explainability usefulness | Survey + task completion |

### 27.2 Security Test Checklist

| Test | Description | Sprint |
|---|---|---|
| SQL Injection | Parameterized query validation | 14 |
| XSS | Script injection in email body, scan results display | 14 |
| CSRF | Form submission without token | 14 |
| Authentication Bypass | Access protected routes without JWT | 14 |
| Broken Access Control | User A accessing User B's scans | 14 |
| File Upload Attacks | Malicious file types, oversized uploads | 14 |
| Malicious Email Parsing | Billion-laughs XML, deeply nested MIME | 14 |
| SSRF | Internal URL in email body | 14 |
| API Abuse | Rate limit enforcement | 14 |
| OAuth Issues | State tampering, token leakage | 14 |
| Extension Permissions | Minimal permission verification | 14 |

### 27.3 ML Test Checklist

| Test | Description | Sprint |
|---|---|---|
| Known dataset | Standard metrics on held-out test | 15 |
| Unseen dataset | New phishing samples not in training | 15 |
| Adversarial emails | URL obfuscation, homographs, padding | 15 |
| BEC | Business email compromise patterns | 15 |
| Brand impersonation | Fake brand domains | 15 |
| URL obfuscation | Encoding, redirects, IP addresses | 15 |
| Attachment phishing | Disguised executables | 15 |
| AI-generated phishing | LLM-generated phishing text | 15 |

### 27.4 Test Coverage Target

- Backend unit test coverage: ≥ 80% for Core modules
- All API endpoints have integration tests
- All three Core ML models have reproducibility tests

---

## 28. Future Startup Architecture

### 28.1 Post-PSM Platform Vision

```
USER OPENS EMAIL (any provider)
       │
       ▼
EMAIL AUTOMATICALLY ANALYSED
       │
       ▼
RISK SCORE + EXPLANATION + ADVICE
       │
       ▼
USER FEEDBACK → VALIDATED RETRAINING
       │
       ▼
CONTINUOUS IMPROVEMENT
```

### 28.2 Startup Feature Roadmap

| Feature | Description |
|---|---|
| Multi-provider email | Outlook, Yahoo, ProtonMail integration |
| Organization accounts | Team management, org-wide policies |
| Enterprise administration | SSO, SAML, audit compliance |
| External threat intelligence | VirusTotal, URLhaus, Google Safe Browsing |
| SIEM/SOC integration | Splunk, Elastic, webhook alerts |
| Attachment sandboxing | Dynamic analysis in isolated environment |
| Advanced NLP | Transformer-based semantic phishing detection |
| API platform | Public REST API with API keys and billing |
| Paid plans | Free / Pro / Enterprise tiers |

### 28.3 Startup Architecture Extensions

```
                    ┌─────────────────────────┐
                    │    API Platform (B2B)    │
                    │    API Keys + Billing    │
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
              ┌─────┴─────┐           ┌───────┴───────┐
              │  Multi-   │           │  Threat Intel│
              │  Provider │           │  Gateway     │
              │  Connectors│           │  (VT, GSb)  │
              └───────────┘           └───────────────┘
                    │                         │
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │   Existing PSM Platform  │
                    │   (Detection + XAI)      │
                    └─────────────────────────┘
```

### 28.4 Monetization Model (Future)

| Tier | Features |
|---|---|
| Free | 50 scans/month, web only, simple explanations |
| Pro | Unlimited scans, extension, detailed explanations, history |
| Enterprise | API access, SSO, admin, threat intel, SLA |

### 28.5 Scalability Path

| Stage | Infrastructure |
|---|---|
| PSM | Single VPS, Docker Compose |
| Startup MVP | Managed DB, load balancer, 2–3 app instances |
| Growth | Kubernetes, dedicated ML inference service, CDN |
| Enterprise | Multi-region, dedicated threat intel pipeline |

---

## Appendix A: Risk Classification Reference

| Score | Label | Colour | User Action |
|---|---|---|---|
| 0–19 | SAFE | Green | No action needed |
| 20–39 | LOW RISK | Yellow-green | Exercise normal caution |
| 40–59 | SUSPICIOUS | Yellow | Verify before interacting |
| 60–79 | HIGH RISK | Orange | Do not click links or download attachments |
| 80–100 | PHISHING | Red | Do not interact; report as phishing |

## Appendix B: Glossary

| Term | Definition |
|---|---|
| BEC | Business Email Compromise |
| DMARC | Domain-based Message Authentication, Reporting and Conformance |
| DKIM | DomainKeys Identified Mail |
| SPF | Sender Policy Framework |
| TF-IDF | Term Frequency–Inverse Document Frequency |
| XAI | Explainable Artificial Intelligence |
| SHAP | SHapley Additive exPlanations |
| PSM | Project Study Module |

## Appendix C: Document Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0.0 | 2026-08-22 | Project Team | Initial Master Technical Specification |

---

*This document is the authoritative reference for all implementation decisions. Changes require version increment and revision history update.*
