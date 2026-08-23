# Changelog — PhishGuard / Phishing Detection System

Chronological record of **implemented** product and detection changes aligned to the corrected PSM:

> **Explainable Web-Based Phishing Email Detection for User Awareness Using Logistic Regression**

**Rules for this document**

- Single main model: **Logistic Regression** (no extra algorithms as Core requirements).
- Metrics below are **held-out lab / test-set** figures from training artifacts — **not** live traffic and **not** Experiment 3 user-study results.
- Gmail OAuth / browser extension / attachments / feedback export = **PSM Extension** unless noted as Core UX.

Canonical docs: [SCOPE.md](SCOPE.md) · [MASTER_TECHNICAL_SPECIFICATION.md](MASTER_TECHNICAL_SPECIFICATION.md)

---

## Summary timeline

| Date (approx.) | Commit | Theme |
|---|---|---|
| 2026-08-22 | `b587319` | Public Render + Docker deployment readiness |
| 2026-08-22 | `4a6b209` / PR #1 | Extension “Failed to fetch” hardening |
| 2026-08-22 | `b8a27b4` | Corrected PSM identity (LR-only story) |
| 2026-08-22 | `053d88a` … `3f0cda8` | Explainable security-analysis UI, theme, extension zip |
| 2026-08-23 | `fa527c2` | Phase 1 **production UX** |
| 2026-08-23 | `98ea6d4` | Detection Phases **1–3** (hybrid LR + rules + explainability) |

---

## 2026-08-23 — Detection Phases 1–3 (`98ea6d4`)

**Goal:** Improve real detection quality and explainability while keeping **one Logistic Regression** model, with hybrid security rules and offline reputation.

### Architecture (runtime)

```text
Email / URL paste
       │
       ▼
   Parse (NormalizedEmail)
       │
       ▼
   Analyzers
   • content (urgency, threat, credential, financial)
   • URL (structure, brand-in-subdomain, lookalikes)
   • sender / brand (display-name vs domain)
   • authentication (SPF/DKIM/DMARC when present)
   • attachment (static — Extension)
   • reputation (offline heuristics — no VirusTotal/WHOIS API)
       │
       ▼
   Logistic Regression (prefer v1.1.0-text_metadata)
       │
       ▼
   Risk fusion + hard rules (floors)
       │
       ▼
   Explainability → risk score, findings, advice, confidence
```

### Phase 1 — Features, data hygiene, evaluation story

| Change | Detail |
|---|---|
| Default model | Runtime prefers **`v1.1.0-text_metadata`** (TF-IDF + URL + metadata) over text-only / v1.0.0 |
| URL parsing | Extra runtime signals (entropy, `@`, hyphens, login path, etc.) while keeping **stable ML URL width** for pickled v1.1 extractors |
| Content / sender | Stronger urgency, credential, threat, financial patterns; Reply-To / display-name mismatch |
| Split hygiene | Deduplicate by content hash; remove cross-split leakage (`ml/preprocessing/split.py`) |
| Hygiene script | `scripts/dataset_hygiene.py` — reports duplicate rates and split overlap |
| Lab metrics UI | About / Admin lead with **F1 / Precision / Recall** (accuracy secondary) |
| Training summaries | `training_summary_v1.1.0-text_metadata.json` (+ text_only) written for Experiment 2 UI |

**Held-out test metrics** (from `ml/models/artifacts/training_summary_*.json` after retrain):

| Model | Precision | Recall | F1 | Accuracy | FNR | FPR |
|---|---:|---:|---:|---:|---:|---:|
| v1.0.0 (baseline TF-IDF) | 97.32% | 99.72% | 98.51% | 98.50% | 0.28% | 2.69% |
| v1.1.0-text_only | 98.41% | 99.53% | 98.97% | 98.97% | 0.47% | 1.57% |
| v1.1.0-text_metadata (improved / default runtime) | 97.59% | 99.62% | 98.60% | 98.60% | 0.38% | 2.41% |

Runtime still prefers **text_metadata** for the Experiment 2 product story (URL + metadata features), even when text_only F1 is competitive on this split.

> Story for FYP: report **Precision, Recall, F1, confusion matrix** — do not claim “95% accuracy = excellent” alone.

### Phase 2 — Brand, reputation, hybrid rules, explainability

| Change | Detail |
|---|---|
| Brand utils | Shared brand list + Levenshtein / lookalike helpers (`backend/app/detection/brand_utils.py`) |
| Brand-in-subdomain | e.g. `paypal.com.security-check.example.com` → registered domain `example.com` |
| Offline reputation | Suspicious TLDs, phishing-keyword hosts, “new-looking” domain proxy, trusted allowlist (`analyzers/reputation.py`) — **no live WHOIS / VT** |
| Hard rules | Brand impersonation + credential ask / suspicious URL → risk floor **≥ 85**; attachment / auth combo floors retained |
| Explanations | Human findings with contribution scores, “why dangerous”, confidence High/Medium/Low |
| Counterfactual | Summary of how risk might drop if key signals were removed (estimated, not SHAP) |

### Phase 3 — Extension surfaces (demo-complete, still Extension scope)

| Change | Detail |
|---|---|
| Attachments | `Path` crash fix; demo SHA-256 in blocklist; sample `docs/samples/demo_dangerous_attachment.eml` |
| Result / report UI | Attachment summary + counterfactual copy |
| Extension overlay | why-dangerous, confidence, top signals, Do / Do-not |
| Extension settings | Sync auto-scan, warnings, attachments, explanation level via API |
| Feedback export | Admin CSV download; explanation + findings text; **no raw bodies**; **no auto-retrain** |
| Experiment 3 kit | Facilitator checklist; survey template path fixed in `USER_EVALUATION.md` |

### Key files touched

- Detection: `backend/app/detection/pipeline.py`, `ml_inference.py`, `rule_engine.py`, `brand_utils.py`
- Analyzers: `url.py`, `content.py`, `sender.py`, `reputation.py`, `auth.py`
- Explain: `explainability/explainer.py`, `counterfactual.py`
- ML: `ml/features/url_utils.py`, `ml/preprocessing/split.py`, `ml/evaluation/compare_models.py`, artifacts under `ml/models/artifacts/`
- Extension: `extension/content/ui-overlay.js`, `extension/settings/*`
- Scripts: `scripts/dataset_hygiene.py`, `scripts/sync_training_summaries.py`, `scripts/export_feedback.py`

### Explicitly out of scope (unchanged)

- Multiple ML algorithms as Core
- Live VirusTotal / WHOIS / Safe Browsing
- Automatic retraining from feedback
- Invented Experiment 3 study percentages

---

## 2026-08-23 — Phase 1 production UX (`fa527c2`)

**Goal:** Product UX that matches an awareness assistant, not a raw ML classifier dashboard.

| Area | Change |
|---|---|
| Landing | “Check before you click” — Detect / Understand / Act |
| After login | **Dashboard** home (not scanner-first) |
| IA | Sidebar: Dashboard, Analyse email, History, Awareness, Reports, Gmail protection, Settings |
| Analyse | Email-first; URL as secondary tab |
| Result | Verdict → why → what to do → technical details collapsed |
| Theme | Light/dark; restrained palette; Inter |
| Tests | `backend/tests/test_web_ui.py` (+ security) |

---

## 2026-08-22 — Explainable UI productisation

Commits: `053d88a`, `f48021c`, `bce9d5c`, `3f0cda8`

| Change | Detail |
|---|---|
| Product framing | Check → explain → advise |
| Theme | Light / dark mode |
| Extension download | Zip served from Integrations / Gmail protection pages |
| Online deploy UI | Templates aligned for Render-hosted demo |

---

## 2026-08-22 — Corrected PSM identity (`b8a27b4`)

| Change | Detail |
|---|---|
| Title / docs | Aligned to Logistic Regression + user awareness |
| Model story | Baseline TF-IDF+LR vs improved TF-IDF+URL+metadata+explainability |
| Scope | No live mailbox as Core; Gmail/extension marked Extension |
| Docs | `docs/SCOPE.md`, master technical spec, Cursor rule `psm-scope` |

---

## 2026-08-22 — Extension fetch reliability (`4a6b209`, PR #1)

| Change | Detail |
|---|---|
| Host permissions | Extension can reach configured API origin |
| Retries | Soft retries on transient network / cold start |
| Settings | API base + token from Integrations |

---

## 2026-08-22 — Deployment readiness (`b587319`)

| Change | Detail |
|---|---|
| Docker / Compose | Backend + nginx path for production-like runs |
| Artifacts | Trained LR joblibs packaged for Render |
| Config | `MODEL_VERSION`, secrets via env |

---

## How to verify after pull

```bash
# Dataset hygiene (expect zero cross-split content_hash overlap)
PYTHONPATH=. python scripts/dataset_hygiene.py

# Unit tests (Docker example)
docker compose run --rm --no-deps --entrypoint pytest backend \
  backend/tests/test_pipeline.py backend/tests/test_attachments.py -q

# Lab metrics on About / Admin come from
#   ml/models/artifacts/training_summary_v1.1.0-text_metadata.json
#   (fallback: training_summary_v1.0.0.json)
```

### Demo attachment

Paste / upload: `docs/samples/demo_dangerous_attachment.eml`  
Expect double-extension and/or blocklist-hash findings (static analysis only).

### Feedback improvement loop (offline)

1. Users submit feedback on result page  
2. Admin approves on Feedback review  
3. Export CSV (UI or `python scripts/export_feedback.py`)  
4. Curate dataset → `python -m ml.training.train …` **manually** — never auto-retrain in Core

---

## Experiment mapping (for report writing)

| Experiment | What this changelog supports |
|---|---|
| **1 — Baseline** | v1.0.0 TF-IDF + LR; metrics in `training_summary_v1.0.0.json` |
| **2 — Improved** | v1.1.0-text_metadata + hybrid rules/explainability in product |
| **3 — User awareness** | Protocol + pack + facilitator checklist under `docs/user_eval/` — run study; **do not invent numbers** |

---

## Related documents

| Doc | Purpose |
|---|---|
| [SCOPE.md](SCOPE.md) | Core vs Extension vs Startup |
| [MASTER_TECHNICAL_SPECIFICATION.md](MASTER_TECHNICAL_SPECIFICATION.md) | Full technical design |
| [USER_EVALUATION.md](USER_EVALUATION.md) | Experiment 3 protocol |
| [user_eval/FACILITATOR_CHECKLIST.md](user_eval/FACILITATOR_CHECKLIST.md) | Session checklist |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Deploy / env |
| [API.md](API.md) | HTTP / extension API |

---

*Last updated: 2026-08-23 (documents commits through `98ea6d4`).*
