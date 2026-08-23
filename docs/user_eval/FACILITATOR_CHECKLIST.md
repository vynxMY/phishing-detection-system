# Experiment 3 — Facilitator checklist

Print or keep open during each session. Do **not** invent scores — only record what participants answer.

## Before the session

- [ ] App is reachable (local or deployed)
- [ ] Logged in with a demo account
- [ ] Copy `docs/user_eval/survey_template.csv` → `survey_P0X.csv`
- [ ] Open `docs/user_eval/email_pack.json` (6 emails)
- [ ] Consent text read aloud (`docs/USER_EVALUATION.md`)
- [ ] Participant ID assigned (P01, P02, …)

## Phase A — Without PhishGuard (~10 min)

For each email in the pack:

1. Show **only** the email text (no score / no explanation)
2. Ask: phishing or legitimate?
3. Ask confidence 1–5
4. Record on the survey sheet

## Phase B — With PhishGuard (~15 min)

For the same emails:

1. Paste into **Analyse email** (or open a prepared result)
2. Show verdict → why → what to do
3. Ask again: phishing or legitimate?
4. Ask confidence 1–5
5. Ask explanation usefulness 1–5
6. Ask trust 1–5

## Phase C — Optional (~5 min)

- What helped most: score, findings, or advice?
- Anything confusing?

## After all participants

```bash
PYTHONPATH=. python scripts/score_user_eval.py \
  --pack docs/user_eval/email_pack.json \
  --survey path/to/merged_survey.csv
```

Report only the script output. Do not invent lift percentages.
