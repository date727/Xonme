#!/usr/bin/env python3
"""Pre-translate MITRE ATT&CK group profiles for Chinese UI display.

The English STIX data and English vector index remain authoritative for RAG.
This script writes a separate, incrementally resumable Chinese display map.
It intentionally does not run on import and never rebuilds the vector index.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.knowledge_base.stix_parser import STIXParser
from app.model_config import get_chat_completions_url, get_model_config


DEFAULT_STIX_DIR = BACKEND_ROOT.parent / "attack-stix-data"
DEFAULT_OUTPUT = BACKEND_ROOT / "data" / "knowledge_base_zh.json"
DOMAINS = (
    "enterprise-attack/enterprise-attack.json",
    "ics-attack/ics-attack.json",
    "mobile-attack/mobile-attack.json",
)

SYSTEM_PROMPT = """Translate MITRE ATT&CK threat-intelligence text into Simplified Chinese.
Keep ATT&CK IDs, organization names, aliases, malware/tool names, IP addresses,
domains, URLs, and code-like identifiers unchanged. Translate only; do not add,
remove, summarize, explain, or infer information. Return only the translation."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Pre-translate ATT&CK profiles for UI display.")
    parser.add_argument("--stix-dir", type=Path, default=DEFAULT_STIX_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--model-id", default=None, help="Allowed model id from app/model_config.py")
    parser.add_argument("--limit", type=int, default=0, help="Translate at most N missing texts (0 = all)")
    parser.add_argument("--dry-run", action="store_true", help="List work without calling the model")
    parser.add_argument("--retry-delay", type=float, default=2.0)
    return parser.parse_args()


def stix_files(stix_dir: Path) -> list[Path]:
    files = [stix_dir / relative for relative in DOMAINS if (stix_dir / relative).exists()]
    if not files:
        raise FileNotFoundError(f"No ATT&CK STIX files found below: {stix_dir}")
    return files


def source_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_output(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema_version": 1, "translations": {}, "groups": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot read translation map: {path}") from exc
    data.setdefault("schema_version", 1)
    data.setdefault("translations", {})
    data.setdefault("groups", {})
    return data


def save_output(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    temp_path.replace(path)


def translate(text: str, config: Any, *, retry_delay: float) -> str:
    payload = {
        "model": config.model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
        "temperature": 0,
        **config.request_options,
    }
    url = get_chat_completions_url(config)
    headers = {"Authorization": f"Bearer {config.api_key}", "Content-Type": "application/json"}
    last_error = ""
    for attempt in range(3):
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=90)
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"].strip()
            if content:
                return content
            last_error = "empty model response"
        except (requests.RequestException, KeyError, IndexError, TypeError, ValueError) as exc:
            last_error = str(exc)
        if attempt < 2:
            time.sleep(retry_delay * (attempt + 1))
    raise RuntimeError(f"Translation request failed after retries: {last_error}")


def text_entry(text: str, kind: str) -> tuple[str, dict[str, str]] | None:
    value = " ".join(str(text or "").split())
    if not value:
        return None
    digest = source_hash(value)
    return digest, {"source_hash": digest, "source_text": value, "kind": kind}


def main() -> int:
    args = parse_args()
    load_dotenv(BACKEND_ROOT / ".env")
    parser = STIXParser(stix_paths=stix_files(args.stix_dir))
    profiles = parser.build_group_profiles()
    output = load_output(args.output)
    config = None if args.dry_run else get_model_config(args.model_id)
    translated_count = 0
    skipped_count = 0

    for group_id, profile in profiles.items():
        group = {
            "name": profile["name"],
            "aliases": profile["aliases"],
            "mitre_url": profile["mitre_url"],
            "background": None,
            "c2_techniques": {},
        }
        entries: list[tuple[str, dict[str, str]]] = []
        background = text_entry(profile.get("description", ""), "group_background")
        if background:
            entries.append(background)
            group["background"] = background[0]
        for technique in profile["c2_techniques"]:
            technique_id = technique.get("technique_id") or technique.get("name") or "unknown"
            fields: dict[str, str] = {}
            for field, kind in (
                ("name", "technique_name"),
                ("description", "technique_description"),
                ("relationship_desc", "relationship_evidence"),
            ):
                entry = text_entry(technique.get(field, ""), kind)
                if entry:
                    entries.append(entry)
                    fields[field] = entry[0]
            group["c2_techniques"][technique_id] = {"name": technique.get("name", ""), "translations": fields}
        output["groups"][group_id] = group

        for digest, entry in entries:
            cached = output["translations"].get(digest)
            if cached and cached.get("source_text") == entry["source_text"] and cached.get("zh"):
                skipped_count += 1
                continue
            if args.limit and translated_count >= args.limit:
                continue
            if args.dry_run:
                print(f"WOULD_TRANSLATE {entry['kind']} {digest[:12]} {entry['source_text'][:90]}")
                translated_count += 1
                continue
            try:
                chinese = translate(entry["source_text"], config, retry_delay=args.retry_delay)
            except RuntimeError as exc:
                print(f"FAILED {entry['kind']} {digest[:12]}: {exc}", file=sys.stderr)
                save_output(args.output, output)
                return 1
            output["translations"][digest] = {**entry, "zh": chinese}
            translated_count += 1
            save_output(args.output, output)
            print(f"TRANSLATED {translated_count}: {entry['kind']} {digest[:12]}")

    if not args.dry_run:
        save_output(args.output, output)
    print(f"Complete. translated={translated_count}, cached={skipped_count}, groups={len(profiles)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
