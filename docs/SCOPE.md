# Project Scope — Corrected PSM Proposal (Authoritative)

**Official title**

> Explainable Web-Based Phishing Email Detection for User Awareness Using Logistic Regression

**Project type:** System Development (not Research)  
**Aligned to:** Corrected PSM proposal (authoritative from 2026-08-22)  
**Full spec:** [MASTER_TECHNICAL_SPECIFICATION.md](MASTER_TECHNICAL_SPECIFICATION.md)

---

## Identity

An explainable web-based phishing email detection system that uses **Logistic Regression** to classify phishing emails and provides understandable explanations of suspicious email characteristics to improve **user awareness**.

The current PSM scope **does not** include real-time email-server integration. Users paste or upload email content into a web application.

| Layer | What it is |
|---|---|
| **PSM Core** | Approved baseline vs improved Logistic Regression, explainability, Flask web app, MySQL, HTTPS |
| **PSM Extension** | Same engine, extra prototype features (headers, auth, attachments, Gmail, extension, feedback) |
| **Post-PSM Startup** | Multi-provider, enterprise, threat intel, additional ML algorithms |

---

## PSM-approved core

```text
Explainable Web-Based Phishing Email Detection
                    │
                    ▼
             Logistic Regression
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
   Baseline Model          Improved Model
   TF-IDF only             TF-IDF
                           + URL Features
                           + Metadata
                           + Explainability
                    │
                    ▼
              Web Application
                    │
                    ▼
             User Awareness
```

**Single main model:** Logistic Regression. Naive Bayes, Random Forest, XGBoost, and other algorithms are **not** PSM requirements.

**Baseline** = TF-IDF + Logistic Regression.  
**Improved** = TF-IDF + URL features + metadata + explainability.

**Stack:** Flask + HTML/CSS/JavaScript + MySQL. Public phishing/legitimate datasets. Agile SDLC.

---

## Three evaluation experiments (PSM)

### Experiment 1 — Baseline

Email → preprocess → TF-IDF → Logistic Regression → Accuracy, Precision, Recall, F1.

### Experiment 2 — Improved

Email → preprocess → TF-IDF + URL + metadata → Logistic Regression → same metrics.

**Core question:** Does adding URL and metadata features improve Logistic Regression-based phishing email detection?

### Experiment 3 — User awareness

Pre/post questionnaire: can participants identify phishing, confidence, correct decisions, explanation usefulness. Do **not** invent numeric results.

---

## Explainability is a main output

Not an optional add-on. After classification the system must explain:

- Suspicious URLs
- Sender / domain mismatches
- Urgent or threatening language
- Risky phrases
- Feature importance (interpretable LR coefficients)
- Natural-language explanation
- Security advice

```text
Email → Preprocess → Features (TF-IDF, URL, metadata)
      → Logistic Regression → Classification
      → Explainability → User awareness
```

---

## Shared detection engine

The browser extension (extension scope) must **not** contain the ML model. Web app and extension call the same Flask HTTPS API.

---

## What is in / out of PSM Core

**Must (Core):** paste/scan email, subject/body, TF-IDF, URL + metadata features, LR baseline + improved, phishing vs legitimate, explanations, advice, register/login, results, history, dashboards, HTTPS, input validation, password hashing, logging.

**If time (Extension):** `.eml`, headers, SPF/DKIM/DMARC, attachments, fused 0–100 risk bands, SHAP/counterfactuals, feedback/retraining, learning centre, Chrome/Edge Gmail extension, Google OAuth.

**After graduation (Startup):** Outlook and other providers, org accounts, threat intelligence, extra ML models, public API, SOC/SIEM, enterprise platform.
