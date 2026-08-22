"""Advice engine — actionable Do / Don't recommendations (Sprint 7)."""

from __future__ import annotations

ADVICE_BY_LEVEL = {
    "safe": {
        "do_not": [],
        "do": [
            "Continue exercising normal email caution",
            "Verify unexpected requests through a separate channel if unsure",
        ],
    },
    "low_risk": {
        "do_not": [
            "Click unfamiliar links without checking the real destination",
        ],
        "do": [
            "Hover over links to inspect the actual URL",
            "Confirm the sender address carefully",
        ],
    },
    "suspicious": {
        "do_not": [
            "Click links until you verify the sender",
            "Download attachments from unknown senders",
            "Enter passwords from this email",
        ],
        "do": [
            "Verify the sender independently",
            "Open the organisation's official website by typing the address yourself",
            "Contact the organisation through official channels",
        ],
    },
    "high_risk": {
        "do_not": [
            "Click links",
            "Download attachments",
            "Reply to the sender",
            "Enter your password",
            "Provide financial information",
        ],
        "do": [
            "Verify the sender independently",
            "Open the organisation's official website directly",
            "Contact the organisation through official channels",
            "Report the email as phishing",
        ],
    },
    "phishing": {
        "do_not": [
            "Click links",
            "Download attachments",
            "Reply to the sender",
            "Enter your password",
            "Provide financial information",
        ],
        "do": [
            "Verify the sender independently",
            "Open the organisation's official website directly",
            "Contact the organisation through official channels",
            "Report the email as phishing",
            "Delete the email after reporting",
        ],
    },
}


def generate_advice(classification: str, triggered_categories: list[str] | None = None) -> dict:
    advice = dict(ADVICE_BY_LEVEL.get(classification, ADVICE_BY_LEVEL["suspicious"]))
    advice = {
        "do_not": list(advice["do_not"]),
        "do": list(advice["do"]),
    }

    cats = set(triggered_categories or [])
    if "url" in cats and "Hover over links to inspect the actual URL" not in advice["do"]:
        advice["do"].append("Hover over links to inspect the actual URL")
    if "attachment" in cats:
        if "Download attachments" not in advice["do_not"]:
            advice["do_not"].insert(0, "Download attachments")
    if "authentication" in cats:
        advice["do"].append("Treat authentication failures as a warning signal, not absolute proof")

    return advice
