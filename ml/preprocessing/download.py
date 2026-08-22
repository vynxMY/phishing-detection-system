"""Download public email datasets for phishing detection training."""

from __future__ import annotations

import io
import re
import tarfile
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urljoin

import requests
from tqdm import tqdm

from ml.config import (
    ENRON_CSV_URL,
    HF_DATASET_NAME,
    LINGSPAM_URL,
    NAZARIO_BASE_URL,
    RAW_DIR,
)

USER_AGENT = "PhishingDetectionSystem/1.0 (academic-research)"


def _session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def _download_bytes(url: str, timeout: int = 120, verify: bool = True) -> bytes:
    response = _session().get(url, timeout=timeout, verify=verify)
    response.raise_for_status()
    return response.content


def _read_text_file(path: Path) -> str:
    for encoding in ("utf-8", "latin-1", "cp1252"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    return path.read_text(encoding="utf-8", errors="replace")


def _extract_email_body(raw: str) -> str:
    """Extract visible text from raw email content."""
    raw = raw.strip()
    if not raw:
        return ""

    if raw.lower().startswith(("from:", "received:", "return-path:", "subject:")):
        try:
            message = BytesParser(policy=policy.default).parsebytes(raw.encode("utf-8", errors="replace"))
            plain_parts = []
            for part in message.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_content()
                    if isinstance(payload, str) and payload.strip():
                        plain_parts.append(payload.strip())
            if plain_parts:
                return "\n".join(plain_parts)
            subject = message.get("subject", "")
            if subject:
                return str(subject)
        except Exception:
            pass

    return raw


def download_lingspam(dest: Path | None = None) -> list[dict]:
    """
    Download and parse the Ling-Spam corpus.

    Returns records with keys: text, label, source, subject.
    label: 0 = legitimate (ham), 1 = spam
    """
    dest = dest or RAW_DIR / "lingspam"
    dest.mkdir(parents=True, exist_ok=True)

    archive_path = dest / "lingspam_public.tar.gz"
    if not archive_path.exists():
        print(f"Downloading Ling-Spam from {LINGSPAM_URL} ...")
        try:
            archive_path.write_bytes(_download_bytes(LINGSPAM_URL))
        except requests.RequestException:
            print("  Retrying Ling-Spam with SSL verification disabled ...")
            archive_path.write_bytes(_download_bytes(LINGSPAM_URL, verify=False))

    extract_dir = dest / "lingspam_public"
    if not extract_dir.exists():
        print("Extracting Ling-Spam archive ...")
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(path=dest)

    records: list[dict] = []
    # Ling-Spam layout: lingspam_public/bare/partN/*.txt
    # Spam files start with "spmsg", ham files start with a digit (e.g. "3-1msg1.txt")
    search_roots = [extract_dir / "bare"] if (extract_dir / "bare").exists() else [extract_dir]
    for root in search_roots:
        if not root.exists():
            continue
        for file_path in sorted(root.rglob("*.txt")):
            name = file_path.name.lower()
            if name.startswith("spmsg"):
                label = 1
            elif name[0].isdigit():
                label = 0
            else:
                continue
            text = _read_text_file(file_path).strip()
            if len(text) < 20:
                continue
            records.append(
                {
                    "text": text,
                    "label": label,
                    "source": "lingspam",
                    "subject": "",
                }
            )

    print(f"Ling-Spam: {len(records)} emails ({sum(r['label'] for r in records)} spam)")
    return records


def download_nazario(dest: Path | None = None, max_files: int = 5000) -> list[dict]:
    """
    Download the Nazario phishing corpus from monkey.org.

    Returns records labeled as phishing (1).
    """
    dest = dest or RAW_DIR / "nazario"
    dest.mkdir(parents=True, exist_ok=True)

    index_url = NAZARIO_BASE_URL
    print(f"Fetching Nazario index from {index_url} ...")
    index_html = _session().get(index_url, timeout=60).text

    # Links like email_1/email.txt or similar patterns on the index page
    links = re.findall(r'href="([^"]+\.txt)"', index_html, flags=re.IGNORECASE)
    if not links:
        links = re.findall(r'href="([^"]+/)"', index_html)

    records: list[dict] = []
    seen_urls: set[str] = set()

    for link in links:
        if len(records) >= max_files:
            break
        full_url = urljoin(index_url, link)
        if full_url in seen_urls:
            continue
        seen_urls.add(full_url)

        try:
            if link.endswith(".txt"):
                content = _session().get(full_url, timeout=30).text
                body = _extract_email_body(content)
                if len(body) < 30:
                    continue
                records.append(
                    {
                        "text": body,
                        "label": 1,
                        "source": "nazario",
                        "subject": "",
                    }
                )
            elif link.endswith("/"):
                # Directory listing — fetch individual email files
                dir_html = _session().get(full_url, timeout=30).text
                file_links = re.findall(r'href="([^"]+\.(?:txt|eml))"', dir_html, flags=re.IGNORECASE)
                for file_link in file_links:
                    if len(records) >= max_files:
                        break
                    file_url = urljoin(full_url, file_link)
                    if file_url in seen_urls:
                        continue
                    seen_urls.add(file_url)
                    try:
                        content = _session().get(file_url, timeout=30).text
                        body = _extract_email_body(content)
                        if len(body) < 30:
                            continue
                        records.append(
                            {
                                "text": body,
                                "label": 1,
                                "source": "nazario",
                                "subject": "",
                            }
                        )
                    except requests.RequestException:
                        continue
        except requests.RequestException:
            continue

    print(f"Nazario: {len(records)} phishing emails")
    return records


def download_enron_csv(dest: Path | None = None, max_rows: int | None = 15000) -> list[dict]:
    """
    Download the Enron-Spam dataset as a single CSV from GitHub.

    33,716 emails total (spam + ham). Well-suited for PSM baseline training.
    """
    import io
    import zipfile

    import pandas as pd

    dest = dest or RAW_DIR / "enron"
    dest.mkdir(parents=True, exist_ok=True)

    zip_path = dest / "enron_spam_data.zip"
    csv_path = dest / "enron_spam_data.csv"

    if not csv_path.exists():
        print(f"Downloading Enron-Spam CSV from GitHub ...")
        zip_path.write_bytes(_download_bytes(ENRON_CSV_URL, timeout=180))
        with zipfile.ZipFile(io.BytesIO(zip_path.read_bytes())) as zf:
            csv_names = [n for n in zf.namelist() if n.endswith(".csv")]
            if not csv_names:
                raise ValueError("No CSV found in Enron zip archive")
            csv_path.write_bytes(zf.read(csv_names[0]))

    df = pd.read_csv(csv_path)
    # Columns: Subject, Message, Spam/Ham, Date
    subject_col = "Subject" if "Subject" in df.columns else "subject"
    message_col = "Message" if "Message" in df.columns else "message"
    label_col = "Spam/Ham" if "Spam/Ham" in df.columns else "label"

    if max_rows and len(df) > max_rows:
        df = df.sample(n=max_rows, random_state=42)

    records: list[dict] = []
    for _, row in df.iterrows():
        subject = str(row.get(subject_col, "") or "")
        message = str(row.get(message_col, "") or "")
        text = f"{subject}\n\n{message}".strip() if subject else message.strip()
        if len(text) < 30:
            continue

        raw_label = str(row.get(label_col, "")).lower()
        label = 1 if raw_label in ("spam", "phishing", "1") else 0

        records.append(
            {
                "text": text,
                "label": label,
                "source": "enron",
                "subject": subject,
            }
        )

    print(f"Enron-Spam CSV: {len(records)} emails")
    return records


def download_huggingface(max_rows: int | None = 10000) -> list[dict]:
    """Load unified phishing email dataset from Hugging Face."""
    try:
        from datasets import load_dataset
    except ImportError:
        print("Hugging Face datasets library not installed — skipping.")
        return []

    print(f"Loading Hugging Face dataset: {HF_DATASET_NAME} ...")
    ds = load_dataset(HF_DATASET_NAME, split="train")

    if max_rows and len(ds) > max_rows:
        ds = ds.shuffle(seed=42).select(range(max_rows))

    records: list[dict] = []
    for row in ds:
        subject = str(row.get("subject") or "")
        body = str(row.get("body") or row.get("content") or row.get("text") or "")
        text = f"{subject}\n\n{body}".strip() if subject else body.strip()
        if len(text) < 30:
            continue

        label = int(row.get("label", 0))
        source = str(row.get("dataset_name") or "huggingface")

        records.append(
            {
                "text": text,
                "label": label,
                "source": source,
                "subject": subject,
            }
        )

    print(f"Hugging Face: {len(records)} emails")
    return records


def download_enron_spam(dest: Path | None = None) -> list[dict]:
    """Legacy alias — delegates to CSV download."""
    return download_enron_csv(dest)


def _generate_fallback_dataset(n_legitimate: int = 3000, n_phishing: int = 3000) -> list[dict]:
    """Generate a reproducible synthetic dataset when downloads are unavailable."""
    import random

    random.seed(42)
    records: list[dict] = []

    legitimate_templates = [
        "Hi {name},\n\nPlease find attached the meeting notes from yesterday's session.\n\nBest regards,\n{sender}",
        "Dear {name},\n\nYour order #{order} has been shipped and will arrive by {date}.\n\nThank you for shopping with us.",
        "Hello {name},\n\nThis is a reminder about the team standup at 10 AM tomorrow in Conference Room B.\n\nThanks,\n{sender}",
        "Hi {name},\n\nCould you review the document I shared and send your feedback by Friday?\n\nRegards,\n{sender}",
        "Dear {name},\n\nYour subscription renewal is scheduled for {date}. No action is required if your payment details are up to date.\n\nBest,\nSupport Team",
    ]

    phishing_templates = [
        "URGENT: Your {service} account will be suspended in 24 hours!\n\nVerify immediately: http://secure-{service}-login.verify-account.xyz/auth\n\nDo not ignore this message.",
        "Dear Customer,\n\nWe detected unusual activity on your {service} account. Confirm your identity now:\nhttp://{service}-security-update.com/login\n\nFailure to verify will result in account closure.",
        "Your payment of $1,247.00 is overdue.\n\nView invoice and pay here: http://billing-portal-secure.net/invoice?id={order}\n\nIf you did not authorize this, click the link immediately.",
        "Congratulations! You have won a $500 {service} gift card.\n\nClaim now: http://prize-claim-reward.com/win?ref={order}\n\nOffer expires in 2 hours.",
        "IT Department Notice:\n\nYour mailbox quota is full. Upgrade now to avoid email loss:\nhttp://mail-upgrade-service.net/upgrade\n\nUsername: {name}\nPassword: [confirm]",
    ]

    names = ["Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Jamie", "Quinn"]
    senders = ["HR Team", "Project Lead", "Admin", "Finance Dept", "Support"]
    services = ["PayPal", "Microsoft", "Amazon", "Netflix", "Bank"]

    for i in range(n_legitimate):
        template = random.choice(legitimate_templates)
        text = template.format(
            name=random.choice(names),
            sender=random.choice(senders),
            order=random.randint(10000, 99999) + i,
            date=f"2025-{random.randint(1,12):02d}-{random.randint(1,28):02d}",
        )
        text += f"\n\nRef: LEG-{i:06d}"
        records.append({"text": text, "label": 0, "source": "synthetic", "subject": ""})

    for i in range(n_phishing):
        template = random.choice(phishing_templates)
        text = template.format(
            name=random.choice(names),
            service=random.choice(services),
            order=random.randint(10000, 99999) + i,
        )
        text += f"\n\nCase ID: PH-{i:06d}"
        records.append({"text": text, "label": 1, "source": "synthetic", "subject": ""})

    print(f"Fallback synthetic dataset: {len(records)} emails")
    return records


def download_all(force_fallback: bool = False) -> list[dict]:
    """Download all datasets and merge into a single record list."""
    from ml.config import MIN_DATASET_SIZE

    RAW_DIR.mkdir(parents=True, exist_ok=True)

    if force_fallback:
        return _generate_fallback_dataset()

    all_records: list[dict] = []

    # Primary: fast, reliable CSV sources first
    primary_loaders = (download_enron_csv, download_lingspam)
    for loader in primary_loaders:
        try:
            records = loader()
            all_records.extend(records)
            print(f"  Running total: {len(all_records)}")
        except Exception as exc:
            print(f"Warning: {loader.__name__} failed: {exc}")

    # Supplement with Hugging Face only if still below minimum
    if len(all_records) < MIN_DATASET_SIZE:
        try:
            needed = MIN_DATASET_SIZE - len(all_records) + 500
            records = download_huggingface(max_rows=needed)
            all_records.extend(records)
        except Exception as exc:
            print(f"Warning: download_huggingface failed: {exc}")

    # Nazario for additional phishing samples
    if len(all_records) < MIN_DATASET_SIZE:
        try:
            records = download_nazario()
            all_records.extend(records)
        except Exception as exc:
            print(f"Warning: download_nazario failed: {exc}")

    if len(all_records) < 1000:
        print("Insufficient downloaded data — supplementing with synthetic samples.")
        all_records.extend(_generate_fallback_dataset(n_legitimate=3000, n_phishing=3000))

    print(f"Total raw records collected: {len(all_records)}")
    return all_records


if __name__ == "__main__":
    records = download_all()
    print(f"Downloaded {len(records)} records")
