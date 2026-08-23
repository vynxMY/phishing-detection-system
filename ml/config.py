"""Shared ML pipeline configuration."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure repo root is importable when running `python -m ml...`
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from paths import ML_ARTIFACTS, ML_DIR, ML_PROCESSED, ML_RAW, ML_REPORTS

RANDOM_SEED = 42

# Paths (canonical via paths.py)
ML_ROOT = ML_DIR
DATASETS_DIR = ML_ROOT / "datasets"
RAW_DIR = ML_RAW
PROCESSED_DIR = ML_PROCESSED
ARTIFACTS_DIR = ML_ARTIFACTS
REPORTS_DIR = ML_REPORTS

# Processed dataset files
MERGED_CSV = PROCESSED_DIR / "emails_merged.csv"
TRAIN_CSV = PROCESSED_DIR / "train.csv"
VAL_CSV = PROCESSED_DIR / "val.csv"
TEST_CSV = PROCESSED_DIR / "test.csv"
DATASET_MANIFEST = PROCESSED_DIR / "dataset_manifest.json"

# Split ratios (train / val / test)
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15

# Labels
LABEL_LEGITIMATE = 0
LABEL_PHISHING = 1
LABEL_NAMES = {LABEL_LEGITIMATE: "legitimate", LABEL_PHISHING: "phishing"}

# TF-IDF
TFIDF_MAX_FEATURES = 10_000
TFIDF_NGRAM_RANGE = (1, 2)
TFIDF_MIN_DF = 2
TFIDF_MAX_DF = 0.95

# Logistic Regression defaults
LR_DEFAULT_C = 1.0
LR_MAX_ITER = 1_000
LR_CLASS_WEIGHT = "balanced"
LR_SOLVER = "liblinear"  # fast and reliable for sparse text features

# Model versioning
DEFAULT_MODEL_VERSION = "v1.1.0"

# Dataset sources
LINGSPAM_URL = "http://www.aueb.gr/users/ion/data/lingspam_public.tar.gz"
NAZARIO_BASE_URL = "https://monkey.org/~jose/phishing/"
ENRON_CSV_URL = "https://github.com/MWiechmann/enron_spam_data/raw/master/enron_spam_data.zip"
HF_DATASET_NAME = "K2509118/seven-phishing-email-datasets_pub"

# Minimum combined dataset size (spec requirement)
MIN_DATASET_SIZE = 5_000
