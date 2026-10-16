"""Fetch pinned CC BY 4.0 UCI source archives when absent; verify byte hashes."""
from __future__ import annotations

import hashlib
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "uci_taiwan_350.zip": ("https://archive.ics.uci.edu/static/public/350/default%2Bof%2Bcredit%2Bcard%2Bclients.zip",
                           "56c885f84457f6680f8438f02bfcdac9579323d8a94465ee5f26e32baa727602"),
    "uci_german_144.zip": ("https://archive.ics.uci.edu/static/public/144/statlog%2Bgerman%2Bcredit%2Bdata.zip",
                           "e12d9d5def6845c0622634a1cd2ab87fa470668c4298f1ec52a4e403376a435b"),
}


def fetch():
    directory = ROOT / "data/raw"
    directory.mkdir(parents=True, exist_ok=True)
    for name, (url, digest) in SOURCES.items():
        path = directory / name
        if not path.exists():
            with urlopen(url, timeout=60) as response:
                path.write_bytes(response.read())
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            raise ValueError(f"{name}: hash mismatch; expected {digest}, got {actual}")
        print(name, actual)


if __name__ == "__main__":
    fetch()
