# User Evaluation Protocol — Experiment 3 (User Awareness)

**PSM Core.** The official title includes *user awareness*; ML metrics (Experiments 1–2) are not sufficient on their own.

## Goal

Measure whether the system's **explanations** help users identify phishing more accurately and confidently than unaided inspection.

Do **not** invent percentages. Report only what participants actually scored.

## Participants

- Target: 8–20 participants (students / office workers)
- Mix of technical and non-technical users if possible
- Informed consent required (see form below)

## Materials

1. Web app running (local or deployed URL)
2. Email pack: `docs/user_eval/email_pack.json`
3. Survey sheet: `docs/user_eval/survey.csv` (copy per participant)
4. Scoring script: `scripts/score_user_eval.py`

## Procedure (per participant, ~25–35 minutes)

### Phase A — Before the system (baseline awareness)

For each of 6 emails:

1. Show the email only
2. Ask: Is this phishing or legitimate?
3. Ask confidence (1–5)
4. Do **not** show the detector yet

### Phase B — With PhishGuard

For the same (or matched) emails:

1. Run / show the scan result page (score, why, advice)
2. Ask again: phishing or legitimate?
3. Ask confidence (1–5)
4. Rate explanation usefulness (1–5)
5. Rate trust in the system (1–5)

### Phase C — Short interview (optional)

- What helped most: score, breakdown, findings, or advice?
- Anything confusing or missing?

## Metrics

| Metric | Definition |
|---|---|
| Detection accuracy (human) | % correct labels in Phase A vs B |
| Decision confidence | Mean Likert before/after |
| Explanation usefulness | Mean Likert Phase B |
| Trust | Mean Likert Phase B |
| Agreement with system | % times user final label matches system |

## Consent text (short)

> I agree to participate in a usability study of a phishing detection prototype. I understand my responses will be used for academic evaluation only. No personal email accounts will be accessed. I may withdraw at any time.

## Privacy

- Use synthetic / public sample emails only
- Do not ask participants to paste personal inbox mail
- Store participant IDs as anonymous codes (P01, P02, …)
