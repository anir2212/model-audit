"""Load licensed UCI credit datasets and document each split's temporal limits."""
from __future__ import annotations

from io import BytesIO
from pathlib import Path
import hashlib
import zipfile

import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
TAIWAN_ZIP = ROOT / "data/raw/uci_taiwan_350.zip"
GERMAN_ZIP = ROOT / "data/raw/uci_german_144.zip"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_taiwan():
    if not TAIWAN_ZIP.exists():
        raise FileNotFoundError("Download UCI dataset 350 as described in data/SOURCES.md")
    with zipfile.ZipFile(TAIWAN_ZIP) as archive:
        with archive.open("default of credit card clients.xls") as file:
            frame = pd.read_excel(BytesIO(file.read()), header=1, engine="xlrd")
    frame = frame.rename(columns={frame.columns[-1]: "default"})
    frame.columns = [str(c).upper() if c != "default" else c for c in frame.columns]
    if len(frame) != 30000 or "ID" not in frame or "default" not in frame:
        raise ValueError("unexpected Taiwan UCI schema")
    frame = frame.sort_values("ID").reset_index(drop=True)
    features = frame.drop(columns=["ID", "default"])
    labels = frame["default"].astype(int)
    return features, labels, {"rows": len(frame), "sha256_zip": sha256(TAIWAN_ZIP),
                              "split_warning": "ID-order proxy cohorts; dataset has no true application timestamp"}


def load_german():
    if not GERMAN_ZIP.exists():
        raise FileNotFoundError("Download UCI dataset 144 as described in data/SOURCES.md")
    with zipfile.ZipFile(GERMAN_ZIP) as archive:
        with archive.open("german.data") as file:
            frame = pd.read_csv(file, sep=r"\s+", header=None,
                                names=[f"A{i:02d}" for i in range(1, 21)] + ["risk_class"])
    if len(frame) != 1000 or set(frame["risk_class"]) != {1, 2}:
        raise ValueError("unexpected German UCI schema")
    features = frame.drop(columns="risk_class")
    labels = (frame["risk_class"] == 2).astype(int)
    return features, labels, {"rows": len(frame), "sha256_zip": sha256(GERMAN_ZIP),
                              "split_warning": "stratified random split; no time field"}


def split_taiwan(features, labels):
    """Chronological-looking ID order is a proxy, not a true out-of-time split."""
    return {"train": (features.iloc[:18000].copy(), labels.iloc[:18000].copy()),
            "validation": (features.iloc[18000:24000].copy(), labels.iloc[18000:24000].copy()),
            "test": (features.iloc[24000:].copy(), labels.iloc[24000:].copy())}


def split_german(features, labels):
    train_index, test_index = train_test_split(features.index, test_size=0.25,
                                               stratify=labels, random_state=7)
    return {"train": (features.loc[train_index].copy(), labels.loc[train_index].copy()),
            "test": (features.loc[test_index].copy(), labels.loc[test_index].copy())}
