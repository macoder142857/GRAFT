from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".cff",
    ".ini",
    ".json",
    ".jsonl",
    ".md",
    ".py",
    ".toml",
    ".txt",
    ".yml",
    ".yaml",
}


def test_repository_contains_no_private_markers_or_probable_keys() -> None:
    forbidden = [
        "men" + "shen",
        "\u95e8" + "\u795e",
        "fun" + "cloud",
        "vm_" + "share",
        "D:" + "\\",
    ]
    probable_key = re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")
    violations: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        lowered = text.lower()
        for marker in forbidden:
            if marker.lower() in lowered:
                violations.append(f"{path.relative_to(ROOT)}: forbidden marker")
        if probable_key.search(text):
            violations.append(f"{path.relative_to(ROOT)}: probable API key")
    assert not violations, "\n".join(violations)
