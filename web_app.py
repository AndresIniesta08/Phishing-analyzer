"""Loopback-only web interface and local report history for email analysis."""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
from contextlib import contextmanager
from collections.abc import Iterator
from datetime import date, timedelta
from getpass import getpass
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import uuid
import zipfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request as UrlRequest, urlopen as http_urlopen
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from email_analysis import DANGEROUS_EXTENSIONS, analyze_message


WEB_DIR = Path(__file__).with_name("web")
MAX_EMAIL_BYTES = 10 * 1024 * 1024
MAX_WHATSAPP_ZIP_BYTES = 10 * 1024 * 1024
MAX_WHATSAPP_MESSAGE_BYTES = 100 * 1024
MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024
MAX_SCREENSHOT_PIXELS = 16_000_000
MAX_SCREENSHOT_TEXT_BYTES = 100 * 1024
SCREENSHOT_OCR_TIMEOUT_SECONDS = 20
MAX_SCREENSHOT_REQUEST_BYTES = (MAX_SCREENSHOT_BYTES + 2) // 3 * 4 + 16 * 1024
MAX_WHATSAPP_REQUEST_BYTES = (
    (MAX_WHATSAPP_ZIP_BYTES + 2) // 3 * 4
    + MAX_WHATSAPP_MESSAGE_BYTES * 6
    + 8192
)
MAX_WHATSAPP_ZIP_ENTRIES = 1000
MAX_WHATSAPP_ZIP_LISTING = 100
MAX_REQUEST_BYTES = 64 * 1024 * 1024
HISTORY_LIMIT = 100
SESSION_COOKIE = "phishing_session"
SESSION_TTL_HOURS = 8
PASSWORD_ITERATIONS = 310_000
VALID_ROLES = {"user", "analyst", "admin"}
VALID_INCIDENT_STATUSES = {"open", "investigating", "resolved", "false_positive"}
VALID_INCIDENT_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_FEEDBACK_CLASSIFICATIONS = {
    "confirmed_phishing", "suspicious", "legitimate", "false_positive",
}
MAX_REPUTATION_LOOKUPS = 5
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
WHATSAPP_DANGEROUS_EXTENSIONS = DANGEROUS_EXTENSIONS | {
    ".apk", ".apks", ".xapk",
}
NESTED_ARCHIVE_EXTENSIONS = {".7z", ".gz", ".rar", ".tar", ".zip"}
SCREENSHOT_FORMATS = {"PNG", "JPEG", "WEBP", "BMP"}


class OcrUnavailableError(RuntimeError):
    """Raised when the local Tesseract OCR engine is unavailable."""


class OcrTimeoutError(RuntimeError):
    """Raised when local OCR exceeds its time limit."""


def _default_data_dir() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "EmailPhishingRiskAnalyzer"
    return Path.home() / ".local" / "share" / "EmailPhishingRiskAnalyzer"


DATA_DIR = Path(os.environ.get("PHISHING_ANALYZER_DATA_DIR", _default_data_dir()))
DATABASE_PATH = DATA_DIR / "history.sqlite3"


@contextmanager
def _database() -> Iterator[sqlite3.Connection]:
    connection = _connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            analyzed_at TEXT NOT NULL,
            subject TEXT NOT NULL,
            sender TEXT NOT NULL,
            level TEXT NOT NULL,
            score INTEGER NOT NULL,
            url_count INTEGER NOT NULL,
            report_json TEXT NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS feedback (
            report_id TEXT PRIMARY KEY REFERENCES reports(id) ON DELETE CASCADE,
            classification TEXT NOT NULL CHECK(classification IN
                ('confirmed_phishing', 'suspicious', 'legitimate', 'false_positive')),
            note TEXT NOT NULL DEFAULT '',
            submitted_by TEXT NOT NULL DEFAULT '',
            submitted_at TEXT NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user', 'analyst', 'admin')),
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            csrf_token TEXT NOT NULL,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            report_id TEXT NOT NULL UNIQUE REFERENCES reports(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('open', 'investigating', 'resolved', 'false_positive')),
            severity TEXT NOT NULL DEFAULT 'medium' CHECK(severity IN ('low', 'medium', 'high', 'critical')),
            assigned_to TEXT REFERENCES users(id) ON DELETE SET NULL,
            note TEXT NOT NULL DEFAULT ''
        )"""
    )
    _migrate_feedback_schema(connection)
    _migrate_incident_schema(connection)
    connection.execute(
        """CREATE TABLE IF NOT EXISTS feedback_reviews (
            report_id TEXT PRIMARY KEY REFERENCES reports(id) ON DELETE CASCADE,
            decision TEXT NOT NULL CHECK(decision IN ('approved', 'rejected')),
            reviewed_by TEXT REFERENCES users(id) ON DELETE SET NULL,
            reviewed_at TEXT NOT NULL,
            indicator TEXT,
            points_delta INTEGER,
            note TEXT NOT NULL DEFAULT ''
        )"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS rule_adjustments (
            indicator TEXT PRIMARY KEY,
            points_delta INTEGER NOT NULL CHECK(points_delta BETWEEN -25 AND 25),
            updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
            updated_at TEXT NOT NULL,
            source_report_id TEXT NOT NULL DEFAULT ''
        )"""
    )
    adjustment_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(rule_adjustments)").fetchall()
    }
    if "source_report_id" not in adjustment_columns:
        connection.execute(
            "ALTER TABLE rule_adjustments ADD COLUMN source_report_id TEXT NOT NULL DEFAULT ''"
        )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            report_id TEXT NOT NULL UNIQUE REFERENCES reports(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            acknowledged_at TEXT,
            acknowledged_by TEXT REFERENCES users(id) ON DELETE SET NULL,
            message TEXT NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            details_json TEXT NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS app_settings (
            name TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )"""
    )
    connection.executemany(
        "INSERT OR IGNORE INTO app_settings(name, value) VALUES (?, ?)",
        (("alert_threshold", "55"), ("retention_days", "0")),
    )
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _migrate_feedback_schema(connection: sqlite3.Connection) -> None:
    schema = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'feedback'"
    ).fetchone()
    if schema is not None and "false_negative" in str(schema["sql"]):
        connection.execute("ALTER TABLE feedback RENAME TO feedback_legacy")
        connection.execute(
            """CREATE TABLE feedback (
                report_id TEXT PRIMARY KEY REFERENCES reports(id) ON DELETE CASCADE,
                classification TEXT NOT NULL CHECK(classification IN
                    ('confirmed_phishing', 'suspicious', 'legitimate', 'false_positive')),
                note TEXT NOT NULL DEFAULT '',
                submitted_by TEXT NOT NULL DEFAULT '',
                submitted_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            """INSERT INTO feedback(report_id, classification, note, submitted_by, submitted_at)
            SELECT report_id,
                CASE classification WHEN 'false_negative' THEN 'confirmed_phishing'
                ELSE 'legitimate' END,
                note, '', submitted_at FROM feedback_legacy"""
        )
        connection.execute("DROP TABLE feedback_legacy")
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(feedback)").fetchall()}
    if "submitted_by" not in columns:
        connection.execute("ALTER TABLE feedback ADD COLUMN submitted_by TEXT NOT NULL DEFAULT ''")


def _migrate_incident_schema(connection: sqlite3.Connection) -> None:
    schema = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'incidents'"
    ).fetchone()
    if schema is None:
        return
    columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(incidents)").fetchall()
    }
    if "severity" not in columns:
        connection.execute(
            """ALTER TABLE incidents ADD COLUMN severity TEXT NOT NULL DEFAULT 'medium'
            CHECK(severity IN ('low', 'medium', 'high', 'critical'))"""
        )
        connection.execute(
            """UPDATE incidents SET severity = CASE
                WHEN report_id IN (SELECT id FROM reports WHERE level = 'HIGH') THEN 'high'
                WHEN report_id IN (SELECT id FROM reports WHERE level = 'LOW') THEN 'low'
                ELSE 'medium' END"""
        )
    if "false_positive" in str(schema["sql"]):
        return
    connection.execute("ALTER TABLE incidents RENAME TO incidents_legacy")
    connection.execute(
        """CREATE TABLE incidents (
            id TEXT PRIMARY KEY,
            report_id TEXT NOT NULL UNIQUE REFERENCES reports(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('open', 'investigating', 'resolved', 'false_positive')),
            severity TEXT NOT NULL DEFAULT 'medium' CHECK(severity IN ('low', 'medium', 'high', 'critical')),
            assigned_to TEXT REFERENCES users(id) ON DELETE SET NULL,
            note TEXT NOT NULL DEFAULT ''
        )"""
    )
    connection.execute(
        """INSERT INTO incidents(id, report_id, created_at, updated_at, status, severity, assigned_to, note)
        SELECT id, report_id, created_at, updated_at, status, severity, assigned_to, note
        FROM incidents_legacy"""
    )
    connection.execute("DROP TABLE incidents_legacy")


def _load_rule_adjustments() -> dict[str, int]:
    with _database() as connection:
        rows = connection.execute(
            "SELECT indicator, points_delta FROM rule_adjustments"
        ).fetchall()
    return {row["indicator"]: row["points_delta"] for row in rows}


def _apply_rule_adjustments(report: dict[str, Any], adjustments: dict[str, int]) -> None:
    if not adjustments:
        return
    for finding in report["findings"]:
        delta = adjustments.get(str(finding.get("indicator", "")), 0)
        if delta:
            finding["points"] = max(0, int(finding["points"]) + delta)
            finding["admin_approved_points_adjustment"] = delta
    raw_score = sum(int(finding["points"]) for finding in report["findings"])
    score = min(raw_score, 100)
    report["score"] = score
    report["level"] = "LOW" if score < 25 else "SUSPICIOUS" if score < 55 else "HIGH"
    report["scoring"]["indicator_points_total"] = raw_score
    report["scoring"]["score_cap_applied"] = raw_score > 100
    report["scoring"]["method"] += " Admin-approved indicator adjustments are included."


def _inspect_whatsapp_zip(encoded: str, filename: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    safe_filename = "".join(
        character
        for character in filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
        if ord(character) >= 32 and ord(character) != 127
    )
    if not safe_filename or len(safe_filename) > 255 or not safe_filename.casefold().endswith(".zip"):
        raise ValueError("Choose a ZIP file with a valid .zip filename.")
    try:
        archive_bytes = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("The ZIP upload was not valid base64 data.") from exc
    if not archive_bytes:
        raise ValueError("The ZIP file is empty.")
    if len(archive_bytes) > MAX_WHATSAPP_ZIP_BYTES:
        raise ValueError("ZIP files must be 10 MB or smaller.")

    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            entries = archive.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError) as exc:
        raise ValueError("The selected file is not a readable ZIP archive. Nothing was extracted.") from exc
    if len(entries) > MAX_WHATSAPP_ZIP_ENTRIES:
        raise ValueError(f"ZIP archives with more than {MAX_WHATSAPP_ZIP_ENTRIES} entries are not accepted.")

    listed_entries: list[str] = []
    risky_entries: list[str] = []
    nested_archive_count = 0
    encrypted_count = 0
    unsafe_path_count = 0
    declared_uncompressed_bytes = 0
    high_compression_ratio_count = 0
    findings: list[dict[str, Any]] = []

    for entry in entries:
        normalized_name = entry.filename.replace("\\", "/")
        parts = normalized_name.split("/")
        path_is_unsafe = (
            normalized_name.startswith("/")
            or any(part == ".." for part in parts)
            or (len(normalized_name) >= 2 and normalized_name[1] == ":")
        )
        if path_is_unsafe:
            unsafe_path_count += 1

        display_name = "".join(
            character for character in normalized_name
            if ord(character) >= 32 and ord(character) != 127
        )[:255]
        suffixes = [suffix.casefold() for suffix in Path(normalized_name).suffixes]
        if any(suffix in WHATSAPP_DANGEROUS_EXTENSIONS for suffix in suffixes):
            risky_entries.append(display_name)
        if suffixes and suffixes[-1] in NESTED_ARCHIVE_EXTENSIONS:
            nested_archive_count += 1
        if entry.flag_bits & 1:
            encrypted_count += 1
        declared_uncompressed_bytes += max(0, entry.file_size)
        if (
            entry.file_size >= 1024 * 1024
            and entry.compress_size > 0
            and entry.file_size / entry.compress_size > 100
        ):
            high_compression_ratio_count += 1

        if len(listed_entries) < MAX_WHATSAPP_ZIP_LISTING:
            listed_entries.append(display_name)

    if risky_entries:
        findings.append({
            "category": "attachments",
            "points": min(25 + (len(risky_entries) - 1) * 5, 40),
            "indicator": "Potentially executable archive contents",
            "reason": "The ZIP directory lists file types that can run code or install apps; this is a warning, not proof of malware.",
            "evidence": ", ".join(risky_entries[:10]),
        })
    if unsafe_path_count:
        findings.append({
            "category": "attachments",
            "points": 25,
            "indicator": "Unsafe archive paths",
            "reason": "The ZIP directory contains absolute or parent-directory paths that can be dangerous when extracted.",
            "evidence": f"{unsafe_path_count} unsafe path(s) found in archive metadata.",
        })
    if encrypted_count:
        findings.append({
            "category": "attachments",
            "points": 8,
            "indicator": "Encrypted archive entries",
            "reason": "Some ZIP entries are encrypted, so their contents could not be inspected.",
            "evidence": f"{encrypted_count} encrypted entry/entries; content was not opened.",
        })
    if high_compression_ratio_count:
        findings.append({
            "category": "attachments",
            "points": 12,
            "indicator": "Unusually high ZIP compression ratio",
            "reason": "Some entries declare unusually high expansion ratios; the app did not decompress them.",
            "evidence": f"{high_compression_ratio_count} entry/entries exceed a 100:1 declared ratio.",
        })
    if nested_archive_count:
        findings.append({
            "category": "attachments",
            "points": 0,
            "indicator": "Nested archives present",
            "reason": "Nested archives are not opened or inspected by this check.",
            "evidence": f"{nested_archive_count} nested archive(s) listed.",
        })

    return {
        "filename": safe_filename,
        "size_bytes": len(archive_bytes),
        "sha256": hashlib.sha256(archive_bytes).hexdigest(),
        "scan_status": "ZIP directory metadata only; contents not extracted or antivirus-scanned",
        "entry_count": len(entries),
        "listed_entries": listed_entries,
        "listing_truncated": len(entries) > len(listed_entries),
        "risky_entries": risky_entries[:MAX_WHATSAPP_ZIP_LISTING],
        "nested_archive_count": nested_archive_count,
        "encrypted_entry_count": encrypted_count,
        "unsafe_path_count": unsafe_path_count,
        "declared_uncompressed_bytes": declared_uncompressed_bytes,
        "high_compression_ratio_count": high_compression_ratio_count,
    }, findings


def _analyze_whatsapp_message(
    message_text: str,
    zip_inspection: dict[str, Any] | None,
    archive_findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    report = analyze_message(f"Subject: WhatsApp scam review\n\n{message_text}")
    report["channel"] = "WhatsApp"
    report["subject"] = "WhatsApp scam review"
    report["sender"] = [{"name": "WhatsApp conversation", "address": ""}]
    if zip_inspection is not None:
        report["zip_inspection"] = zip_inspection
        report["attachments"] = [{
            "filename": zip_inspection["filename"],
            "content_type": "application/zip",
            "size_bytes": zip_inspection["size_bytes"],
            "sha256": zip_inspection["sha256"],
            "scan_status": zip_inspection["scan_status"],
            "suspicious": bool(zip_inspection["risky_entries"] or zip_inspection["unsafe_path_count"]),
            "zip_inspection": zip_inspection,
        }]
    else:
        report["zip_inspection"] = None

    report["findings"].extend(archive_findings or [])
    raw_score = sum(int(finding["points"]) for finding in report["findings"])
    score = min(raw_score, 100)
    report["score"] = score
    report["level"] = "LOW" if score < 25 else "SUSPICIOUS" if score < 55 else "HIGH"
    report["scoring"]["indicator_points_total"] = raw_score
    report["scoring"]["score_cap_applied"] = raw_score > 100
    report["scoring"]["method"] += " WhatsApp text checks and ZIP directory metadata are included; archive contents were not scanned."
    report["confidence_note"] = (
        "This is a heuristic review, not a malware verdict. ZIP metadata cannot reveal malicious behavior "
        "inside files; do not extract or run an unexpected archive."
    )
    return report


def _ocr_screenshot(image_bytes: bytes) -> dict[str, Any]:
    try:
        from PIL import Image, UnidentifiedImageError
        import pytesseract
        from pytesseract import Output
    except ImportError as exc:
        raise OcrUnavailableError(
            "Local OCR support is missing. Install the project requirements and restart the app."
        ) from exc

    if not image_bytes:
        raise ValueError("Choose a non-empty screenshot image.")
    if len(image_bytes) > MAX_SCREENSHOT_BYTES:
        raise ValueError("Screenshot images must be 5 MB or smaller.")

    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
            image_format = str(image.format or "").upper()
            if image_format not in SCREENSHOT_FORMATS:
                raise ValueError("Use a PNG, JPEG, WebP, or BMP screenshot.")
            width, height = image.size
            if width <= 0 or height <= 0 or width * height > MAX_SCREENSHOT_PIXELS:
                raise ValueError("Screenshot dimensions must not exceed 16 megapixels.")
            if getattr(image, "is_animated", False):
                raise ValueError("Animated images are not supported; choose a still screenshot.")
            image.load()
            rgb_image = image.convert("RGB")
    except UnidentifiedImageError as exc:
        raise ValueError("The uploaded file is not a supported image.") from exc
    except Image.DecompressionBombError as exc:
        raise ValueError("Screenshot dimensions exceed the safe processing limit.") from exc

    configured_executable = os.environ.get("TESSERACT_CMD", "").strip()
    executable = configured_executable or shutil.which("tesseract")
    if not executable:
        common_executable = Path("C:/Program Files/Tesseract-OCR/tesseract.exe")
        if common_executable.is_file():
            executable = str(common_executable)
    if executable:
        pytesseract.pytesseract.tesseract_cmd = executable

    try:
        ocr_data = pytesseract.image_to_data(
            rgb_image,
            lang="eng",
            config="--psm 6",
            output_type=Output.DICT,
            timeout=SCREENSHOT_OCR_TIMEOUT_SECONDS,
        )
    except pytesseract.TesseractNotFoundError as exc:
        raise OcrUnavailableError(
            "Tesseract is not installed or was not found. Install Tesseract OCR, then restart the app."
        ) from exc
    except RuntimeError as exc:
        if "timeout" in str(exc).casefold():
            raise OcrTimeoutError(
                "Local OCR took too long. Try a smaller or simpler screenshot."
            ) from exc
        raise ValueError("Local OCR could not process this screenshot.") from exc
    except pytesseract.TesseractError as exc:
        raise ValueError("Local OCR could not read this screenshot. Try a clearer image.") from exc

    lines: dict[tuple[str, str, str], list[str]] = {}
    confidences: list[float] = []
    for index, word in enumerate(ocr_data.get("text", [])):
        cleaned_word = str(word).strip()
        if not cleaned_word:
            continue
        key = tuple(str(ocr_data[field][index]) for field in ("block_num", "par_num", "line_num"))
        lines.setdefault(key, []).append(cleaned_word)
        try:
            confidence = float(ocr_data["conf"][index])
        except (KeyError, IndexError, TypeError, ValueError):
            continue
        if confidence >= 0:
            confidences.append(confidence)

    text = "\n".join(" ".join(words) for words in lines.values())
    if len(text.encode("utf-8")) > MAX_SCREENSHOT_TEXT_BYTES:
        raise ValueError("OCR found more than 100 KB of text. Crop the screenshot and try again.")
    return {
        "text": text,
        "filename": "",
        "format": image_format,
        "width": width,
        "height": height,
        "word_count": sum(len(words) for words in lines.values()),
        "confidence": round(sum(confidences) / len(confidences), 1) if confidences else None,
    }


def _analyze_screenshot_text(text: str, filename: str) -> dict[str, Any]:
    if not text.strip():
        raise ValueError("Review or enter the screenshot text before analyzing it.")
    if len(text.encode("utf-8")) > MAX_SCREENSHOT_TEXT_BYTES:
        raise ValueError("Screenshot text must be 100 KB or smaller.")
    safe_filename = re.split(r"[\\/]", filename.strip())[-1][:200] or "screenshot"
    report = analyze_message(f"Subject: Screenshot review - {safe_filename}\n\n{text}")
    report["channel"] = "Screenshot OCR"
    report["subject"] = f"Screenshot review - {safe_filename}"
    report["sender"] = [{"name": "Screenshot OCR", "address": ""}]
    report["screenshot_review"] = {
        "filename": safe_filename,
        "processing": "OCR performed locally; screenshot image not retained",
    }
    report["scoring"]["method"] += (
        " Text was extracted by local OCR and may contain recognition errors; "
        "visual layout, logos, QR codes, and actual link destinations were not verified."
    )
    return report


def _virustotal_json(path: str, api_key: str) -> tuple[int, dict[str, Any] | None]:
    request = UrlRequest(
        f"{VIRUSTOTAL_API_URL}{path}",
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    try:
        with http_urlopen(request, timeout=5) as response:
            payload = json.loads(response.read())
    except HTTPError as exc:
        if exc.code == 404:
            return 404, None
        if exc.code == 429:
            return 429, None
        return exc.code, None
    except (URLError, TimeoutError, OSError):
        return 0, None
    except json.JSONDecodeError:
        return 0, None
    if not isinstance(payload, dict):
        return 0, None
    return 200, payload


def _virustotal_result(status_code: int, payload: dict[str, Any] | None) -> dict[str, Any]:
    if status_code == 404:
        return {"status": "not_found", "reputation": "No VirusTotal report found"}
    if status_code == 429:
        return {"status": "rate_limited", "reputation": "VirusTotal rate limit reached"}
    if status_code != 200 or payload is None:
        return {"status": "unavailable", "reputation": "VirusTotal lookup unavailable"}
    data = payload.get("data")
    attributes = data.get("attributes") if isinstance(data, dict) else None
    if not isinstance(attributes, dict):
        return {"status": "unavailable", "reputation": "VirusTotal returned no report details"}
    raw_stats = attributes.get("last_analysis_stats")
    stats = {
        key: value
        for key, value in raw_stats.items()
        if key in {"malicious", "suspicious", "harmless", "undetected", "timeout"}
        and isinstance(value, int)
        and value >= 0
    } if isinstance(raw_stats, dict) else {}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    status = (
        "malicious" if malicious else
        "suspicious" if suspicious else
        "no_detections" if stats else
        "unknown"
    )
    redirects = attributes.get("redirection_chain")
    categories = attributes.get("categories")
    result: dict[str, Any] = {
        "status": "found",
        "reputation": status.replace("_", " "),
        "detection_count": malicious + suspicious,
        "analysis_stats": stats,
        "categories": {
            str(key): str(value) for key, value in list(categories.items())[:10]
        } if isinstance(categories, dict) else {},
    }
    for key in ("last_final_url", "last_http_response_code", "reputation", "last_analysis_date"):
        value = attributes.get(key)
        if isinstance(value, (str, int)):
            result[key] = value
    if isinstance(redirects, list):
        result["redirect_chain"] = [str(item) for item in redirects[:10] if isinstance(item, str)]
    return result


def _check_url_reputation(report: dict[str, Any], api_key: str) -> int:
    unique_urls: set[str] = set()
    unique_domains: set[str] = set()
    checked_urls: dict[str, dict[str, Any]] = {}
    checked_domains: dict[str, dict[str, Any]] = {}
    lookups = 0
    for item in report["urls"]:
        destination = str(item["destination"])
        host = str(item["host"]).casefold()
        if destination in unique_urls:
            item["virustotal"] = checked_urls[destination]
            item["reputation_status"] = f"VirusTotal: {checked_urls[destination]['reputation']}"
            continue
        unique_urls.add(destination)
        if len(unique_urls) > MAX_REPUTATION_LOOKUPS:
            item["reputation_status"] = f"not checked; limit is {MAX_REPUTATION_LOOKUPS} URLs per message"
            item["virustotal"] = {"status": "skipped", "reputation": "Per-message lookup limit reached"}
            continue
        url_id = base64.urlsafe_b64encode(destination.encode("utf-8")).decode("ascii").rstrip("=")
        url_code, url_payload = _virustotal_json(f"/urls/{quote(url_id, safe='')}", api_key)
        url_result = _virustotal_result(url_code, url_payload)
        checked_urls[destination] = url_result
        item["virustotal"] = url_result
        item["reputation_status"] = f"VirusTotal: {url_result['reputation']}"
        lookups += 1
        if host and host != "unparsed":
            if host not in unique_domains:
                unique_domains.add(host)
                domain_code, domain_payload = _virustotal_json(f"/domains/{quote(host, safe='.-')}", api_key)
                checked_domains[host] = _virustotal_result(domain_code, domain_payload)
                lookups += 1
            item["virustotal"]["domain_report"] = checked_domains[host]
    return lookups


def _password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)


def _valid_credentials(username: Any, password: Any) -> tuple[str, str] | None:
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    username = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
        return None
    if len(password) < 12 or len(password) > 1024:
        return None
    return username, password


def _create_initial_admin(username: Any, password: Any) -> dict[str, str]:
    credentials = _valid_credentials(username, password)
    if credentials is None:
        raise ValueError(
            "Use a 3–64 character username and a password of at least 12 characters."
        )
    username, password = credentials
    salt = secrets.token_bytes(16)
    user = {"id": uuid.uuid4().hex, "username": username, "role": "admin"}
    with _database() as connection:
        connection.commit()
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            raise ValueError("An account already exists; ask an administrator to manage users.")
        connection.execute(
            """INSERT INTO users(id, username, password_hash, salt, role, active, created_at)
            VALUES (?, ?, ?, ?, 'admin', 1, ?)""",
            (
                user["id"],
                username,
                _password_digest(password, salt).hex(),
                salt.hex(),
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
            ),
        )
    _audit(user, "auth.admin_created")
    return user


def _create_session(user_id: str) -> tuple[str, str, str]:
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(24)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)).isoformat(timespec="seconds")
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    with _database() as connection:
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (datetime.now(timezone.utc).isoformat(),))
        connection.execute(
            "INSERT INTO sessions(token_hash, csrf_token, user_id, expires_at) VALUES (?, ?, ?, ?)",
            (token_hash, csrf_token, user_id, expires_at),
        )
    return token, csrf_token, expires_at


def _audit(user: dict[str, str] | None, action: str, details: dict[str, Any] | None = None) -> None:
    with _database() as connection:
        connection.execute(
            "INSERT INTO audit_log(created_at, user_id, username, action, details_json) VALUES (?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                user["id"] if user else None,
                user["username"] if user else "system",
                action,
                json.dumps(details or {}, ensure_ascii=False),
            ),
        )


def _store_report(report: dict[str, Any], user: dict[str, str]) -> tuple[str, str]:
    report_id = uuid.uuid4().hex
    analyzed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    senders = report["sender"]
    sender = ", ".join(
        f"{item['name']} <{item['address']}>" if item["name"] and item["address"]
        else item["name"] or item["address"]
        for item in senders
    )
    stored_report = {key: value for key, value in report.items() if key != "body"}
    with _database() as connection:
        retention_days = int(connection.execute(
            "SELECT value FROM app_settings WHERE name = 'retention_days'"
        ).fetchone()[0])
        if retention_days:
            cutoff = (datetime.now(timezone.utc).date() - timedelta(days=retention_days)).isoformat()
            expired = connection.execute(
                "SELECT COUNT(*) FROM reports WHERE date(analyzed_at) < date(?)",
                (cutoff,),
            ).fetchone()[0]
            connection.execute("DELETE FROM reports WHERE date(analyzed_at) < date(?)", (cutoff,))
            if expired:
                connection.execute(
                    "INSERT INTO audit_log(created_at, user_id, username, action, details_json) VALUES (?, ?, ?, ?, ?)",
                    (
                        analyzed_at, user["id"], user["username"], "retention.applied",
                        json.dumps({"deleted_reports": expired, "retention_days": retention_days}),
                    ),
                )
        connection.execute(
            """INSERT INTO reports
            (id, analyzed_at, subject, sender, level, score, url_count, report_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                report_id,
                analyzed_at,
                report["subject"],
                sender,
                report["level"],
                report["score"],
                report["url_count"],
                json.dumps(stored_report, ensure_ascii=False),
            ),
        )
        threshold = int(connection.execute(
            "SELECT value FROM app_settings WHERE name = 'alert_threshold'"
        ).fetchone()[0])
        if report["score"] >= threshold:
            connection.execute(
                "INSERT INTO alerts(id, report_id, created_at, message) VALUES (?, ?, ?, ?)",
                (
                    uuid.uuid4().hex,
                    report_id,
                    analyzed_at,
                    f"High-risk message detected (score {report['score']}/100).",
                ),
            )
    return report_id, analyzed_at


def _report_summary(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "analyzed_at": row["analyzed_at"],
        "subject": row["subject"],
        "sender": row["sender"],
        "level": row["level"],
        "score": row["score"],
        "url_count": row["url_count"],
        "status": row["incident_status"] if "incident_status" in row.keys() and row["incident_status"] else "none",
    }


class AnalyzerRequestHandler(BaseHTTPRequestHandler):
    def _session(self) -> tuple[dict[str, str] | None, str | None]:
        from http.cookies import SimpleCookie

        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            token = cookie[SESSION_COOKIE].value
        except (KeyError, ValueError):
            return None, None
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = datetime.now(timezone.utc).isoformat()
        with _database() as connection:
            row = connection.execute(
                """SELECT users.id, users.username, users.role, sessions.csrf_token
                FROM sessions JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ? AND sessions.expires_at > ? AND users.active = 1""",
                (token_hash, now),
            ).fetchone()
        if row is None:
            return None, None
        return {"id": row["id"], "username": row["username"], "role": row["role"]}, row["csrf_token"]

    def _authorize(
        self, roles: set[str] | None = None, *, write: bool = False
    ) -> dict[str, str] | None:
        user, csrf_token = self._session()
        if user is None:
            self._send_json(401, {"error": "Sign in to use the local analyzer."})
            return None
        if roles and user["role"] not in roles:
            self._send_json(403, {"error": "Your account role is not allowed to perform this action."})
            return None
        if write and (
            not csrf_token
            or not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), csrf_token)
        ):
            self._send_json(403, {"error": "The request security token is missing or invalid."})
            return None
        return user

    def _set_session_cookie(self, token: str | None, expires: str | None = None) -> None:
        if token is None:
            self._response_cookie = f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
        else:
            from urllib.parse import quote
            from email.utils import format_datetime

            expiration = datetime.fromisoformat(expires or "").astimezone(timezone.utc)
            self._response_cookie = (
                f"{SESSION_COOKIE}={quote(token)}; Path=/; HttpOnly; SameSite=Strict; "
                f"Max-Age={SESSION_TTL_HOURS * 60 * 60}; Expires={format_datetime(expiration, usegmt=True)}"
            )

    def _login(self, payload: dict[str, Any]) -> None:
        username, password = _valid_credentials(payload.get("username"), payload.get("password")) or (None, None)
        if username is None or password is None:
            self._send_json(400, {"error": "Use a 3–64 character username and a password of at least 12 characters."})
            return
        with _database() as connection:
            row = connection.execute(
                "SELECT id, username, password_hash, salt, role FROM users WHERE username = ? COLLATE NOCASE AND active = 1",
                (username,),
            ).fetchone()
        if row is None or not hmac.compare_digest(
            _password_digest(password, bytes.fromhex(row["salt"])).hex(),
            row["password_hash"],
        ):
            _audit(None, "auth.login_failed", {"username": username})
            self._send_json(401, {"error": "Username or password is incorrect."})
            return
        user = {"id": row["id"], "username": row["username"], "role": row["role"]}
        token, csrf_token, expires = _create_session(user["id"])
        self._set_session_cookie(token, expires)
        _audit(user, "auth.login")
        self._send_json(200, {"user": user, "csrf_token": csrf_token})

    def _logout(self, user: dict[str, str]) -> None:
        token_hash = None
        from http.cookies import SimpleCookie

        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        if SESSION_COOKIE in cookie:
            token_hash = hashlib.sha256(cookie[SESSION_COOKIE].value.encode("utf-8")).hexdigest()
        if token_hash:
            with _database() as connection:
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        _audit(user, "auth.logout")
        self._set_session_cookie(None)
        self._send_json(200, {"logged_out": True})

    def _is_local_request(self) -> bool:
        host = urlsplit("//" + self.headers.get("Host", "")).hostname
        if host not in {"127.0.0.1", "localhost"}:
            return False
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).hostname not in {"127.0.0.1", "localhost"}:
            return False
        return True

    def do_GET(self) -> None:
        if not self._is_local_request():
            self._send_json(403, {"error": "Local browser access only."})
            return
        path = urlsplit(self.path).path
        if path in {"/", "/login"}:
            user, _ = self._session()
            if path == "/" and user is None:
                self.send_response(303)
                self.send_header("Location", "/login")
                self.send_header("Content-Length", "0")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return
            if path == "/login" and user is not None:
                self.send_response(303)
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return
        routes = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/login": ("login.html", "text/html; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/login.js": ("login.js", "text/javascript; charset=utf-8"),
            "/styles.css": ("styles.css", "text/css; charset=utf-8"),
        }
        if path == "/health":
            self._send_json(200, {"status": "ok"})
            return
        if path == "/api/session":
            user, csrf_token = self._session()
            self._send_json(200, {
                "user": user,
                "csrf_token": csrf_token,
            })
            return
        if path in routes:
            filename, content_type = routes[path]
            self._send_response(200, content_type, (WEB_DIR / filename).read_bytes())
            return
        user = self._authorize()
        if user is None:
            return
        if path == "/api/history":
            self._send_history()
            return
        if path == "/api/integrations":
            self._send_json(200, {
                "virustotal_configured": bool(os.environ.get("VIRUSTOTAL_API_KEY", "").strip()),
            })
            return
        if path == "/api/trends":
            self._send_trends()
            return
        if path == "/api/threats":
            self._send_threat_detections()
            return
        if path == "/api/export.csv":
            self._send_csv()
            return
        if path == "/api/incidents":
            if self._authorize({"analyst", "admin"}) is None:
                return
            self._send_incidents()
            return
        if path == "/api/alerts":
            self._send_alerts()
            return
        if path == "/api/team":
            if self._authorize({"analyst", "admin"}) is None:
                return
            self._send_team()
            return
        if path == "/api/admin/users":
            if self._authorize({"admin"}) is not None:
                self._send_users()
            return
        if path == "/api/admin/settings":
            if self._authorize({"admin"}) is not None:
                self._send_settings()
            return
        if path == "/api/admin/feedback":
            if self._authorize({"admin"}) is not None:
                self._send_feedback_reviews()
            return
        if path == "/api/admin/audit":
            if self._authorize({"admin"}) is not None:
                self._send_audit()
            return
        if path.startswith("/api/report/") and path.endswith("/pdf"):
            report_id = path.removeprefix("/api/report/").removesuffix("/pdf").strip("/")
            self._send_pdf(report_id)
            return
        if path.startswith("/api/report/"):
            report_id = path.removeprefix("/api/report/")
            self._send_report(report_id)
            return
        self._send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        if not self._is_local_request():
            self._send_json(403, {"error": "Local browser access only."})
            return
        path = urlsplit(self.path).path
        if path == "/api/setup":
            self._send_json(
                403,
                {"error": "Account creation is disabled here. Ask an administrator to provision an account."},
            )
            return
        if path == "/api/login":
            payload = self._read_payload(required_field=None)
            if payload is not None:
                self._login(payload)
            return
        if path == "/api/logout":
            user = self._authorize(write=True)
            if user is not None:
                self._logout(user)
            return
        user = self._authorize(write=True)
        if user is None:
            return
        feedback_request = path.startswith("/api/report/") and path.endswith("/feedback")
        if path not in {
            "/preview", "/analyze", "/api/whatsapp/analyze",
            "/api/screenshot/ocr", "/api/screenshot/analyze",
            "/api/incidents", "/api/alerts/ack",
            "/api/admin/users", "/api/admin/settings", "/api/admin/feedback/review",
        } and not (
            feedback_request or path.startswith("/api/incidents/")
            or path.startswith("/api/admin/users/")
        ):
            self._send_json(404, {"error": "Not found"})
            return
        if path.startswith("/api/incidents") and self._authorize({"analyst", "admin"}) is None:
            return
        if path.startswith("/api/admin/") and self._authorize({"admin"}) is None:
            return
        if feedback_request and self._authorize({"analyst", "admin"}) is None:
            return
        required_field = (
            "classification" if feedback_request else
            "message" if path == "/api/whatsapp/analyze" else
            "text" if path == "/api/screenshot/analyze" else
            "email" if path in {"/preview", "/analyze"} else
            None
        )
        payload = self._read_payload(
            required_field=required_field,
            max_payload_bytes=(
                MAX_SCREENSHOT_REQUEST_BYTES if path == "/api/screenshot/ocr" else
                MAX_SCREENSHOT_TEXT_BYTES + 16 * 1024 if path == "/api/screenshot/analyze" else
                MAX_WHATSAPP_REQUEST_BYTES if path == "/api/whatsapp/analyze" else None
            ),
        )
        if payload is None:
            return
        if path == "/api/screenshot/ocr":
            encoded_image = payload.get("image_base64")
            filename = payload.get("filename")
            if not isinstance(encoded_image, str) or not isinstance(filename, str):
                self._send_json(400, {"error": "Provide a screenshot filename and base64 image data."})
                return
            if not encoded_image or len(filename) > 200:
                self._send_json(400, {"error": "Choose a screenshot image with a filename no longer than 200 characters."})
                return
            try:
                image_bytes = base64.b64decode(encoded_image, validate=True)
            except (binascii.Error, ValueError):
                self._send_json(400, {"error": "Screenshot image data must be valid base64."})
                return
            if len(image_bytes) > MAX_SCREENSHOT_BYTES:
                self._send_json(413, {"error": "Screenshot images must be 5 MB or smaller."})
                return
            safe_filename = re.split(r"[\\/]", filename.strip())[-1] or "screenshot"
            try:
                ocr_result = _ocr_screenshot(image_bytes)
            except OcrUnavailableError as exc:
                self._send_json(503, {"error": str(exc)})
                return
            except OcrTimeoutError as exc:
                self._send_json(504, {"error": str(exc)})
                return
            except ValueError as exc:
                status = 413 if "100 KB" in str(exc) or "5 MB" in str(exc) else 400
                self._send_json(status, {"error": str(exc)})
                return
            ocr_result["filename"] = safe_filename
            _audit(user, "screenshot.ocr_completed", {
                "format": ocr_result["format"],
                "width": ocr_result["width"],
                "height": ocr_result["height"],
                "word_count": ocr_result["word_count"],
            })
            self._send_json(200, ocr_result)
            return
        if path == "/api/screenshot/analyze":
            text = payload["text"]
            filename = payload.get("filename", "")
            if not isinstance(filename, str) or len(filename) > 200:
                self._send_json(400, {"error": "Screenshot filename must be text no longer than 200 characters."})
                return
            try:
                report = _analyze_screenshot_text(text, filename)
            except ValueError as exc:
                status = 413 if "100 KB" in str(exc) else 400
                self._send_json(status, {"error": str(exc)})
                return
            _apply_rule_adjustments(report, _load_rule_adjustments())
            report["report_id"], report["analyzed_at"] = _store_report(report, user)
            _audit(user, "screenshot.text_analyzed", {
                "report_id": report["report_id"],
                "level": report["level"],
                "score": report["score"],
            })
            report.pop("body", None)
            self._send_json(200, report)
            return
        if path == "/api/incidents":
            self._create_incident(user, payload)
            return
        if path.startswith("/api/incidents/"):
            self._update_incident(user, path.removeprefix("/api/incidents/").strip("/"), payload)
            return
        if path == "/api/alerts/ack":
            self._acknowledge_alert(user, payload)
            return
        if path == "/api/admin/feedback/review":
            self._review_feedback(user, payload)
            return
        if path == "/api/admin/users" or path.startswith("/api/admin/users/") or path == "/api/admin/settings":
            if path == "/api/admin/users":
                self._create_user(user, payload)
            elif path.startswith("/api/admin/users/"):
                self._update_user(user, path.removeprefix("/api/admin/users/"), payload)
            else:
                self._update_settings(user, payload)
            return
        if feedback_request:
            report_id = path.removeprefix("/api/report/").removesuffix("/feedback").strip("/")
            self._save_feedback(report_id, payload, user)
            return
        if path == "/api/whatsapp/analyze":
            message_text = payload["message"]
            if not message_text.strip():
                self._send_json(400, {"error": "Paste the suspicious WhatsApp message before reviewing."})
                return
            if len(message_text.encode("utf-8")) > MAX_WHATSAPP_MESSAGE_BYTES:
                self._send_json(413, {"error": "WhatsApp message text must be 100 KB or smaller."})
                return
            zip_encoded = payload.get("zip_base64", "")
            zip_filename = payload.get("zip_filename", "")
            if not isinstance(zip_encoded, str) or not isinstance(zip_filename, str):
                self._send_json(400, {"error": "ZIP upload data and filename must be text."})
                return
            if bool(zip_encoded) != bool(zip_filename):
                self._send_json(400, {"error": "Provide both the ZIP file and its filename, or leave both empty."})
                return
            try:
                zip_inspection, archive_findings = (
                    _inspect_whatsapp_zip(zip_encoded, zip_filename)
                    if zip_encoded
                    else (None, [])
                )
                report = _analyze_whatsapp_message(message_text, zip_inspection, archive_findings)
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
                return
            _apply_rule_adjustments(report, _load_rule_adjustments())
            report["report_id"], report["analyzed_at"] = _store_report(report, user)
            _audit(user, "whatsapp.message_analyzed", {
                "report_id": report["report_id"],
                "level": report["level"],
                "score": report["score"],
                "zip_attached": zip_inspection is not None,
            })
            report.pop("body", None)
            self._send_json(200, report)
            return
        if path == "/preview":
            try:
                report = analyze_message(
                    payload["email"],
                    header_overrides=_email_header_overrides(payload),
                )
                _apply_rule_adjustments(report, _load_rule_adjustments())
                self._send_json(200, report)
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
            return
        check_reputation = payload.get("check_reputation", False)
        if not isinstance(check_reputation, bool):
            self._send_json(400, {"error": "check_reputation must be true or false."})
            return
        api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
        if check_reputation and not api_key:
            self._send_json(503, {"error": "VirusTotal is not configured. Set VIRUSTOTAL_API_KEY and restart the app."})
            return
        try:
            report = analyze_message(
                payload["email"],
                header_overrides=_email_header_overrides(payload),
            )
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        _apply_rule_adjustments(report, _load_rule_adjustments())
        if check_reputation:
            lookup_count = _check_url_reputation(report, api_key)
            report["integration_status"]["threat_intelligence"] = "VirusTotal checked by request"
        else:
            lookup_count = 0
        report["report_id"], report["analyzed_at"] = _store_report(report, user)
        _audit(user, "email.analyzed", {
            "report_id": report["report_id"],
            "level": report["level"],
            "score": report["score"],
            "external_indicator_lookups": lookup_count,
        })
        report.pop("body", None)
        self._send_json(200, report)

    def do_DELETE(self) -> None:
        if not self._is_local_request():
            self._send_json(403, {"error": "Local browser access only."})
            return
        user = self._authorize(write=True)
        if user is None:
            return
        path = urlsplit(self.path).path
        if path.startswith("/api/admin/users/"):
            self._delete_user(user, path.removeprefix("/api/admin/users/"))
            return
        if self._authorize({"admin"}) is None:
            return
        if not path.startswith("/api/report/"):
            self._send_json(404, {"error": "Not found"})
            return
        report_id = path.removeprefix("/api/report/")
        if not report_id or "/" in report_id:
            self._send_json(404, {"error": "Report not found"})
            return
        with _database() as connection:
            report = connection.execute("SELECT level, score FROM reports WHERE id = ?", (report_id,)).fetchone()
            connection.execute("DELETE FROM feedback WHERE report_id = ?", (report_id,))
            cursor = connection.execute("DELETE FROM reports WHERE id = ?", (report_id,))
        if cursor.rowcount == 0:
            self._send_json(404, {"error": "Report not found"})
            return
        _audit(user, "report.deleted", {"report_id": report_id, "level": report["level"], "score": report["score"]})
        self._send_json(200, {"deleted": True})

    def _read_payload(
        self,
        *,
        required_field: str | None = "email",
        max_payload_bytes: int | None = None,
    ) -> dict[str, Any] | None:
        content_length = self.headers.get("Content-Length")
        try:
            request_size = int(content_length) if content_length is not None else -1
        except ValueError:
            request_size = -1
        if request_size < 0:
            self._send_json(400, {"error": "A valid Content-Length is required."})
            return None
        payload_limit = max_payload_bytes or (
            MAX_REQUEST_BYTES if required_field == "email" else 16 * 1024
        )
        if request_size > min(payload_limit, MAX_REQUEST_BYTES):
            self._send_json(413, {"error": "Request body exceeds the upload limit."})
            return None
        if self.headers.get_content_type() != "application/json":
            self._send_json(415, {"error": "Send request data as application/json."})
            return None
        try:
            payload: Any = json.loads(self.rfile.read(request_size))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"error": "Request body must be valid JSON."})
            return None
        if not isinstance(payload, dict):
            self._send_json(400, {"error": "Request body must be a JSON object."})
            return None
        if required_field and not isinstance(payload.get(required_field), str):
            self._send_json(400, {"error": f"JSON body must contain a {required_field} string."})
            return None
        if required_field == "email" and len(payload["email"].encode("utf-8")) > MAX_EMAIL_BYTES:
            self._send_json(413, {"error": "Email text exceeds the 10 MB limit."})
            return None
        return payload

    def _send_history(self) -> None:
        query = urlsplit(self.path).query
        params = parse_qs(query)
        search = params.get("q", [""])[0].strip()[:200]
        risk = params.get("risk", [""])[0].upper()
        status = params.get("status", [""])[0].lower()
        start_date = params.get("from", [""])[0]
        end_date = params.get("to", [""])[0]
        if risk not in {"", "LOW", "SUSPICIOUS", "HIGH"}:
            self._send_json(400, {"error": "Risk filter must be LOW, SUSPICIOUS, or HIGH."})
            return
        if status not in {"", "none", "open", "investigating", "resolved", "false_positive"}:
            self._send_json(400, {"error": "Status filter must be none, open, investigating, resolved, or false_positive."})
            return
        if status:
            session_user, _ = self._session()
            if session_user is None or session_user["role"] not in {"analyst", "admin"}:
                self._send_json(403, {"error": "Incident status filtering is restricted to analysts and administrators."})
                return
        try:
            if start_date:
                date.fromisoformat(start_date)
            if end_date:
                date.fromisoformat(end_date)
        except ValueError:
            self._send_json(400, {"error": "Date filters must use YYYY-MM-DD."})
            return
        if start_date and end_date and start_date > end_date:
            self._send_json(400, {"error": "Start date cannot be after end date."})
            return
        clauses: list[str] = []
        values: list[str | int] = []
        if search:
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append(
                "(subject LIKE ? ESCAPE '\\' OR sender LIKE ? ESCAPE '\\' "
                "OR report_json LIKE ? ESCAPE '\\')"
            )
            values.extend((f"%{escaped}%", f"%{escaped}%", f"%{escaped}%"))
        if risk:
            clauses.append("level = ?")
            values.append(risk)
        if status == "none":
            clauses.append("NOT EXISTS (SELECT 1 FROM incidents i WHERE i.report_id = reports.id)")
        elif status:
            clauses.append("EXISTS (SELECT 1 FROM incidents i WHERE i.report_id = reports.id AND i.status = ?)")
            values.append(status)
        if start_date:
            clauses.append("date(analyzed_at) >= date(?)")
            values.append(start_date)
        if end_date:
            clauses.append("date(analyzed_at) <= date(?)")
            values.append(end_date)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with _database() as connection:
            rows = connection.execute(
                f"""SELECT reports.*,
                (SELECT status FROM incidents WHERE incidents.report_id = reports.id) AS incident_status
                FROM reports{where} ORDER BY analyzed_at DESC LIMIT ?""",
                (*values, HISTORY_LIMIT),
            ).fetchall()
            total_count = connection.execute(
                """SELECT COUNT(*) AS total,
                SUM(CASE WHEN level = 'HIGH' THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN level = 'SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious,
                SUM(CASE WHEN level = 'LOW' THEN 1 ELSE 0 END) AS low
                FROM reports"""
            ).fetchone()
            matched = connection.execute(f"SELECT COUNT(*) AS total FROM reports{where}", values).fetchone()
            counts = connection.execute(
                f"""SELECT
                SUM(CASE WHEN level = 'HIGH' THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN level = 'SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious,
                SUM(CASE WHEN level = 'LOW' THEN 1 ELSE 0 END) AS low
                FROM reports{where}""",
                values,
            ).fetchone()
            feedback_rows = connection.execute(
                "SELECT report_id, classification FROM feedback"
            ).fetchall()
        feedback_by_id = {row["report_id"]: row["classification"] for row in feedback_rows}
        reports = [_report_summary(row) for row in rows]
        for report in reports:
            report["feedback"] = feedback_by_id.get(report["id"])
        counts = {
            "total": total_count["total"] or 0,
            "high": total_count["high"] or 0,
            "suspicious": total_count["suspicious"] or 0,
            "low": total_count["low"] or 0,
        }
        self._send_json(200, {
            "counts": counts,
            "matched": matched["total"],
            "reports": reports,
            "query": search,
            "risk": risk,
            "from": start_date,
            "to": end_date,
        })

    def _send_trends(self) -> None:
        period = parse_qs(urlsplit(self.path).query).get("period", ["day"])[0]
        if period not in {"day", "month"}:
            self._send_json(400, {"error": "Trend period must be day or month."})
            return

        today = datetime.now(timezone.utc).date()
        if period == "day":
            keys = [(today - timedelta(days=offset)).isoformat() for offset in range(29, -1, -1)]
            start_date = keys[0]
            group_expression = "date(analyzed_at)"
        else:
            month_indices = [today.year * 12 + today.month - 1 - offset for offset in range(11, -1, -1)]
            keys = [f"{index // 12:04d}-{index % 12 + 1:02d}" for index in month_indices]
            start_date = f"{keys[0]}-01"
            group_expression = "strftime('%Y-%m', analyzed_at)"
        end_date = today.isoformat()
        points_by_key = {
            key: {
                "period": key,
                "total": 0,
                "high": 0,
                "suspicious": 0,
                "low": 0,
                "legitimate": 0,
                "urls": 0,
            }
            for key in keys
        }
        with _database() as connection:
            rows = connection.execute(
                f"""SELECT {group_expression} AS bucket, level, feedback.classification,
                COUNT(*) AS total, SUM(url_count) AS urls
                FROM reports LEFT JOIN feedback ON feedback.report_id = reports.id
                WHERE date(analyzed_at) >= date(?) AND date(analyzed_at) <= date(?)
                GROUP BY bucket, level, feedback.classification""",
                (start_date, end_date),
            ).fetchall()
            feedback_counts = connection.execute(
                "SELECT classification, COUNT(*) AS total FROM feedback GROUP BY classification"
            ).fetchall()
            reports_with_findings = connection.execute("SELECT report_json FROM reports").fetchall()
        for row in rows:
            point = points_by_key.get(row["bucket"])
            if point is None:
                continue
            count = row["total"]
            point["total"] += count
            point["urls"] += row["urls"] or 0
            level_key = row["level"].lower()
            if level_key in {"high", "suspicious", "low"}:
                point[level_key] += count
            if row["classification"] == "legitimate":
                point["legitimate"] += count
        classifications = {row["classification"]: row["total"] for row in feedback_counts}
        indicator_counts: dict[str, int] = {}
        for row in reports_with_findings:
            saved_report = json.loads(row["report_json"])
            for finding in saved_report.get("findings", []):
                indicator = str(finding.get("indicator", "")).strip()
                if indicator and int(finding.get("points", 0)) > 0:
                    indicator_counts[indicator] = indicator_counts.get(indicator, 0) + 1
        points = list(points_by_key.values())
        self._send_json(200, {
            "period": period,
            "start": start_date,
            "end": end_date,
            "totals": {
                "messages": sum(point["total"] for point in points),
                "high": sum(point["high"] for point in points),
                "suspicious": sum(point["suspicious"] for point in points),
                "low": sum(point["low"] for point in points),
                "legitimate": sum(point["legitimate"] for point in points),
                "urls": sum(point["urls"] for point in points),
            },
            "reviewed": {
                "confirmed_phishing": classifications.get("confirmed_phishing", 0),
                "suspicious": classifications.get("suspicious", 0),
                "legitimate": classifications.get("legitimate", 0),
                "false_positive": classifications.get("false_positive", 0),
            },
            "common_indicators": [
                {"indicator": indicator, "count": count}
                for indicator, count in sorted(
                    indicator_counts.items(), key=lambda item: (-item[1], item[0].casefold())
                )[:8]
            ],
            "points": points,
        })

    def _send_incidents(self) -> None:
        with _database() as connection:
            rows = connection.execute(
                """SELECT incidents.id, incidents.report_id, incidents.created_at,
                incidents.updated_at, incidents.status, incidents.severity, incidents.note,
                incidents.assigned_to, users.username AS assignee,
                reports.subject, reports.sender, reports.level, reports.score
                FROM incidents
                JOIN reports ON reports.id = incidents.report_id
                LEFT JOIN users ON users.id = incidents.assigned_to
                ORDER BY incidents.updated_at DESC LIMIT 200"""
            ).fetchall()
            audit_rows = connection.execute(
                """SELECT created_at, username, action, details_json FROM audit_log
                WHERE action IN ('incident.created', 'incident.updated')
                ORDER BY id DESC LIMIT 1000"""
            ).fetchall()
        timeline_by_incident: dict[str, list[dict[str, str]]] = {}
        for event in audit_rows:
            details = json.loads(event["details_json"])
            incident_id = details.get("incident_id")
            if not isinstance(incident_id, str):
                continue
            timeline_by_incident.setdefault(incident_id, []).append({
                "created_at": event["created_at"],
                "username": event["username"],
                "action": event["action"],
                "status": str(details.get("status", "")),
                "severity": str(details.get("severity", "")),
                "assigned_to": str(details.get("assigned_to") or ""),
                "status_updated": bool(details.get("status_updated", False)),
                "severity_updated": bool(details.get("severity_updated", False)),
                "assignment_updated": bool(details.get("assignment_updated", False)),
                "note_updated": bool(details.get("note_updated", False)),
            })
        incidents = []
        for row in rows:
            incident = dict(row)
            incident["timeline"] = list(reversed(timeline_by_incident.get(incident["id"], [])))
            incidents.append(incident)
        self._send_json(200, {"incidents": incidents})

    def _send_threat_detections(self) -> None:
        with _database() as connection:
            rows = connection.execute(
                """SELECT id, analyzed_at, subject, level, report_json
                FROM reports WHERE url_count > 0
                ORDER BY analyzed_at DESC LIMIT 100"""
            ).fetchall()
        detections: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for row in rows:
            report = json.loads(row["report_json"])
            url_findings = [
                finding for finding in report["findings"]
                if finding["category"] == "urls" and finding["points"] > 0
            ]
            if not url_findings:
                continue
            evidence = " ".join(str(finding.get("evidence", "")) for finding in url_findings).casefold()
            for url in report["urls"]:
                host = str(url["host"])
                if (
                    len(report["urls"]) > 1
                    and host.casefold() not in evidence
                    and str(url["destination"]).casefold() not in evidence
                ):
                    continue
                key = (host.casefold(), row["id"])
                if key in seen:
                    continue
                seen.add(key)
                detections.append({
                    "domain": host,
                    "reason": str(url_findings[0].get("indicator") or "URL pattern"),
                    "level": row["level"],
                    "virustotal": url.get("virustotal"),
                    "subject": row["subject"] or "(No subject)",
                    "analyzed_at": row["analyzed_at"],
                })
                if len(detections) >= 8:
                    break
            if len(detections) >= 8:
                break
        self._send_json(200, {"detections": detections})

    def _send_team(self) -> None:
        with _database() as connection:
            rows = connection.execute(
                "SELECT id, username, role FROM users WHERE active = 1 AND role IN ('analyst', 'admin') ORDER BY username COLLATE NOCASE"
            ).fetchall()
        self._send_json(200, {"users": [dict(row) for row in rows]})

    def _send_feedback_reviews(self) -> None:
        with _database() as connection:
            rows = connection.execute(
                """SELECT feedback.report_id, feedback.classification, feedback.note,
                feedback.submitted_by, feedback.submitted_at, reports.subject,
                reports.level, reports.score, reports.report_json,
                users.username AS submitted_username, feedback_reviews.decision,
                feedback_reviews.indicator, feedback_reviews.points_delta,
                feedback_reviews.note AS review_note, feedback_reviews.reviewed_at,
                reviewers.username AS reviewer
                FROM feedback JOIN reports ON reports.id = feedback.report_id
                LEFT JOIN users ON users.id = feedback.submitted_by
                LEFT JOIN feedback_reviews ON feedback_reviews.report_id = feedback.report_id
                LEFT JOIN users AS reviewers ON reviewers.id = feedback_reviews.reviewed_by
                ORDER BY CASE WHEN feedback_reviews.report_id IS NULL THEN 0 ELSE 1 END,
                    feedback.submitted_at DESC LIMIT 200"""
            ).fetchall()
            adjustments = connection.execute(
                "SELECT indicator, points_delta FROM rule_adjustments ORDER BY indicator"
            ).fetchall()
        feedback_items = []
        for row in rows:
            report = json.loads(row["report_json"])
            feedback_items.append({
                "report_id": row["report_id"],
                "classification": row["classification"],
                "note": row["note"],
                "submitted_by": row["submitted_username"] or "Former analyst",
                "submitted_at": row["submitted_at"],
                "subject": row["subject"] or "(No subject)",
                "level": row["level"],
                "score": row["score"],
                "indicators": [
                    {"indicator": str(finding["indicator"]), "points": int(finding["points"])}
                    for finding in report.get("findings", [])
                    if finding.get("indicator") and int(finding.get("points", 0)) > 0
                ],
                "decision": row["decision"],
                "adjusted_indicator": row["indicator"],
                "points_delta": row["points_delta"],
                "review_note": row["review_note"],
                "reviewed_at": row["reviewed_at"],
                "reviewer": row["reviewer"],
            })
        self._send_json(200, {
            "feedback": feedback_items,
            "rule_adjustments": [dict(row) for row in adjustments],
        })

    def _review_feedback(self, actor: dict[str, str], payload: dict[str, Any]) -> None:
        report_id = payload.get("report_id")
        decision = payload.get("decision")
        indicator = payload.get("indicator")
        points_delta = payload.get("points_delta")
        note = payload.get("note", "")
        if not isinstance(report_id, str) or not report_id:
            self._send_json(400, {"error": "A report_id is required."})
            return
        if decision not in {"approved", "rejected"}:
            self._send_json(400, {"error": "Review decision must be approved or rejected."})
            return
        if not isinstance(note, str) or len(note) > 1000:
            self._send_json(400, {"error": "Review notes must be 1000 characters or fewer."})
            return
        if decision == "approved" and (
            not isinstance(indicator, str)
            or not indicator
            or isinstance(points_delta, bool)
            or not isinstance(points_delta, int)
            or points_delta == 0
            or not -25 <= points_delta <= 25
        ):
            self._send_json(400, {"error": "Approval requires a matched indicator and a non-zero adjustment from -25 to 25."})
            return
        reviewed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with _database() as connection:
            row = connection.execute(
                "SELECT report_json FROM reports WHERE id = ?",
                (report_id,),
            ).fetchone()
            if row is None:
                self._send_json(404, {"error": "Report not found."})
                return
            feedback = connection.execute(
                "SELECT 1 FROM feedback WHERE report_id = ?",
                (report_id,),
            ).fetchone()
            if feedback is None:
                self._send_json(404, {"error": "Analyst feedback not found."})
                return
            existing_review = connection.execute(
                "SELECT 1 FROM feedback_reviews WHERE report_id = ?",
                (report_id,),
            ).fetchone()
            if existing_review is not None:
                self._send_json(409, {"error": "This feedback has already been reviewed."})
                return
            if decision == "approved":
                report = json.loads(row["report_json"])
                matched_indicators = {
                    str(finding.get("indicator"))
                    for finding in report.get("findings", [])
                    if finding.get("indicator") and int(finding.get("points", 0)) > 0
                }
                if indicator not in matched_indicators:
                    self._send_json(400, {"error": "Choose a positive indicator present in this report."})
                    return
            connection.execute(
                """INSERT INTO feedback_reviews(
                    report_id, decision, reviewed_by, reviewed_at, indicator, points_delta, note
                ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    report_id,
                    decision,
                    actor["id"],
                    reviewed_at,
                    indicator if decision == "approved" else None,
                    points_delta if decision == "approved" else None,
                    note.strip(),
                ),
            )
            if decision == "approved":
                connection.execute(
                    """INSERT INTO rule_adjustments(
                        indicator, points_delta, updated_by, updated_at, source_report_id
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(indicator) DO UPDATE SET
                        points_delta = excluded.points_delta,
                        updated_by = excluded.updated_by,
                        updated_at = excluded.updated_at,
                        source_report_id = excluded.source_report_id""",
                    (indicator, points_delta, actor["id"], reviewed_at, report_id),
                )
        _audit(actor, "feedback.reviewed", {
            "report_id": report_id,
            "decision": decision,
            "indicator": indicator if decision == "approved" else None,
            "points_delta": points_delta if decision == "approved" else None,
        })
        self._send_json(200, {
            "report_id": report_id,
            "decision": decision,
            "indicator": indicator if decision == "approved" else None,
            "points_delta": points_delta if decision == "approved" else None,
            "reviewed_at": reviewed_at,
        })

    def _create_incident(self, user: dict[str, str], payload: dict[str, Any]) -> None:
        report_id = payload.get("report_id")
        note = payload.get("note", "")
        severity = payload.get("severity")
        if not isinstance(report_id, str) or not report_id:
            self._send_json(400, {"error": "A report_id is required to create an incident."})
            return
        if not isinstance(note, str) or len(note) > 1000:
            self._send_json(400, {"error": "Incident notes must be 1000 characters or fewer."})
            return
        if severity is not None and (not isinstance(severity, str) or severity not in VALID_INCIDENT_SEVERITIES):
            self._send_json(400, {"error": "Incident severity must be low, medium, high, or critical."})
            return
        incident_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with _database() as connection:
            report = connection.execute("SELECT level FROM reports WHERE id = ?", (report_id,)).fetchone()
            if report is None:
                self._send_json(404, {"error": "Report not found."})
                return
            if connection.execute("SELECT 1 FROM incidents WHERE report_id = ?", (report_id,)).fetchone():
                self._send_json(409, {"error": "An incident already exists for this report."})
                return
            connection.execute(
                """INSERT INTO incidents(
                    id, report_id, created_at, updated_at, status, severity, assigned_to, note
                ) VALUES (?, ?, ?, ?, 'open', ?, ?, ?)""",
                (
                    incident_id, report_id, now, now,
                    severity or {"HIGH": "high", "SUSPICIOUS": "medium", "LOW": "low"}[report["level"]],
                    user["id"], note.strip(),
                ),
            )
        initial_severity = severity or {"HIGH": "high", "SUSPICIOUS": "medium", "LOW": "low"}[report["level"]]
        _audit(user, "incident.created", {
            "incident_id": incident_id, "report_id": report_id, "severity": initial_severity,
        })
        self._send_json(201, {
            "id": incident_id, "report_id": report_id, "status": "open",
            "severity": initial_severity,
        })

    def _update_incident(self, user: dict[str, str], incident_id: str, payload: dict[str, Any]) -> None:
        status = payload.get("status")
        severity = payload.get("severity")
        note = payload.get("note", "")
        assigned_to = payload.get("assigned_to", user["id"])
        if not isinstance(status, str) or status not in VALID_INCIDENT_STATUSES:
            self._send_json(400, {"error": "Incident status must be open, investigating, resolved, or false_positive."})
            return
        if severity is not None and (not isinstance(severity, str) or severity not in VALID_INCIDENT_SEVERITIES):
            self._send_json(400, {"error": "Incident severity must be low, medium, high, or critical."})
            return
        if not isinstance(note, str) or len(note) > 1000:
            self._send_json(400, {"error": "Incident notes must be 1000 characters or fewer."})
            return
        if assigned_to is not None and not isinstance(assigned_to, str):
            self._send_json(400, {"error": "assigned_to must be a user id or null."})
            return
        with _database() as connection:
            existing = connection.execute(
                "SELECT status, severity, assigned_to, note FROM incidents WHERE id = ?",
                (incident_id,),
            ).fetchone()
            if existing is None:
                self._send_json(404, {"error": "Incident not found."})
                return
            if assigned_to:
                assignee = connection.execute(
                    "SELECT id FROM users WHERE id = ? AND active = 1 AND role IN ('analyst', 'admin')",
                    (assigned_to,),
                ).fetchone()
                if assignee is None:
                    self._send_json(400, {"error": "Incident assignee must be an active analyst or administrator."})
                    return
            next_severity = severity or existing["severity"]
            connection.execute(
                """UPDATE incidents SET status = ?, severity = ?, assigned_to = ?, note = ?, updated_at = ?
                WHERE id = ?""",
                (
                    status, next_severity, assigned_to, note.strip(),
                    datetime.now(timezone.utc).isoformat(timespec="seconds"), incident_id,
                ),
            )
        _audit(user, "incident.updated", {
            "incident_id": incident_id,
            "status": status,
            "severity": next_severity,
            "assigned_to": assigned_to,
            "status_updated": existing["status"] != status,
            "severity_updated": existing["severity"] != next_severity,
            "assignment_updated": existing["assigned_to"] != assigned_to,
            "note_updated": existing["note"] != note.strip(),
        })
        self._send_json(200, {
            "id": incident_id, "status": status, "severity": next_severity,
            "assigned_to": assigned_to,
        })

    def _send_alerts(self) -> None:
        with _database() as connection:
            rows = connection.execute(
                """SELECT alerts.id, alerts.report_id, alerts.created_at, alerts.message,
                alerts.acknowledged_at, users.username AS acknowledged_by,
                reports.subject, reports.level, reports.score
                FROM alerts JOIN reports ON reports.id = alerts.report_id
                LEFT JOIN users ON users.id = alerts.acknowledged_by
                ORDER BY alerts.created_at DESC LIMIT 100"""
            ).fetchall()
        self._send_json(200, {"alerts": [dict(row) for row in rows]})

    def _acknowledge_alert(self, user: dict[str, str], payload: dict[str, Any]) -> None:
        alert_id = payload.get("alert_id")
        if not isinstance(alert_id, str) or not alert_id:
            self._send_json(400, {"error": "An alert_id is required."})
            return
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with _database() as connection:
            cursor = connection.execute(
                "UPDATE alerts SET acknowledged_at = ?, acknowledged_by = ? WHERE id = ? AND acknowledged_at IS NULL",
                (now, user["id"], alert_id),
            )
            if cursor.rowcount == 0:
                exists = connection.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone()
                if exists is None:
                    self._send_json(404, {"error": "Alert not found."})
                    return
        _audit(user, "alert.acknowledged", {"alert_id": alert_id})
        self._send_json(200, {"alert_id": alert_id, "acknowledged_at": now})

    def _send_users(self) -> None:
        with _database() as connection:
            rows = connection.execute(
                "SELECT id, username, role, active, created_at FROM users ORDER BY username COLLATE NOCASE"
            ).fetchall()
        self._send_json(200, {"users": [dict(row) for row in rows]})

    def _create_user(self, actor: dict[str, str], payload: dict[str, Any]) -> None:
        credentials = _valid_credentials(payload.get("username"), payload.get("password"))
        role = payload.get("role")
        if credentials is None or not isinstance(role, str) or role not in VALID_ROLES:
            self._send_json(400, {"error": "Provide a valid username, password of at least 12 characters, and role user, analyst, or admin."})
            return
        username, password = credentials
        user_id = uuid.uuid4().hex
        salt = secrets.token_bytes(16)
        try:
            with _database() as connection:
                connection.execute(
                    """INSERT INTO users(id, username, password_hash, salt, role, active, created_at)
                    VALUES (?, ?, ?, ?, ?, 1, ?)""",
                    (user_id, username, _password_digest(password, salt).hex(), salt.hex(), role,
                     datetime.now(timezone.utc).isoformat(timespec="seconds")),
                )
        except sqlite3.IntegrityError:
            self._send_json(409, {"error": "That username is already in use."})
            return
        _audit(actor, "user.created", {"user_id": user_id, "username": username, "role": role})
        self._send_json(201, {"id": user_id, "username": username, "role": role, "active": True})

    def _update_user(self, actor: dict[str, str], user_id: str, payload: dict[str, Any]) -> None:
        role = payload.get("role")
        active = payload.get("active")
        password = payload.get("password")
        if role is not None and (not isinstance(role, str) or role not in VALID_ROLES):
            self._send_json(400, {"error": "Role must be user, analyst, or admin."})
            return
        if active is not None and not isinstance(active, bool):
            self._send_json(400, {"error": "active must be true or false."})
            return
        if password is not None and (not isinstance(password, str) or not 12 <= len(password) <= 1024):
            self._send_json(400, {"error": "New passwords must be between 12 and 1024 characters."})
            return
        with _database() as connection:
            current = connection.execute("SELECT role, active FROM users WHERE id = ?", (user_id,)).fetchone()
            if current is None:
                self._send_json(404, {"error": "User not found."})
                return
            next_role = role or current["role"]
            next_active = int(active if active is not None else current["active"])
            if user_id == actor["id"] and (next_role != "admin" or not next_active):
                self._send_json(400, {"error": "You cannot remove administrator access from your own account."})
                return
            if current["role"] == "admin" and current["active"] and (next_role != "admin" or not next_active):
                remaining = connection.execute(
                    "SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1 AND id != ?",
                    (user_id,),
                ).fetchone()[0]
                if remaining == 0:
                    self._send_json(409, {"error": "At least one active administrator must remain."})
                    return
            assignments = ["role = ?", "active = ?"]
            values: list[Any] = [next_role, next_active]
            if password is not None:
                salt = secrets.token_bytes(16)
                assignments.extend(("password_hash = ?", "salt = ?"))
                values.extend((_password_digest(password, salt).hex(), salt.hex()))
                connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            values.append(user_id)
            connection.execute(f"UPDATE users SET {', '.join(assignments)} WHERE id = ?", values)
            if not next_active:
                connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        _audit(actor, "user.updated", {"user_id": user_id, "role": next_role, "active": bool(next_active), "password_reset": password is not None})
        self._send_json(200, {"id": user_id, "role": next_role, "active": bool(next_active)})

    def _delete_user(self, actor: dict[str, str], user_id: str) -> None:
        if self._authorize({"admin"}, write=True) is None:
            return
        if user_id == actor["id"]:
            self._send_json(400, {"error": "You cannot delete your own administrator account."})
            return
        with _database() as connection:
            current = connection.execute("SELECT username, role, active FROM users WHERE id = ?", (user_id,)).fetchone()
            if current is None:
                self._send_json(404, {"error": "User not found."})
                return
            if current["role"] == "admin" and current["active"]:
                remaining = connection.execute(
                    "SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1 AND id != ?",
                    (user_id,),
                ).fetchone()[0]
                if remaining == 0:
                    self._send_json(409, {"error": "At least one active administrator must remain."})
                    return
            connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
        _audit(actor, "user.deleted", {"user_id": user_id, "username": current["username"], "role": current["role"]})
        self._send_json(200, {"deleted": True})

    def _send_settings(self) -> None:
        with _database() as connection:
            settings = {row["name"]: int(row["value"]) for row in connection.execute(
                "SELECT name, value FROM app_settings"
            ).fetchall()}
        self._send_json(200, {"settings": settings})

    def _update_settings(self, actor: dict[str, str], payload: dict[str, Any]) -> None:
        threshold = payload.get("alert_threshold")
        retention = payload.get("retention_days")
        if type(threshold) is not int or not 0 <= threshold <= 100:
            self._send_json(400, {"error": "Alert threshold must be an integer from 0 to 100."})
            return
        if type(retention) is not int or not 0 <= retention <= 3650:
            self._send_json(400, {"error": "Retention must be an integer from 0 to 3650 days; use 0 to keep reports until manually deleted."})
            return
        with _database() as connection:
            connection.executemany(
                "INSERT INTO app_settings(name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                (("alert_threshold", str(threshold)), ("retention_days", str(retention))),
            )
        _audit(actor, "settings.updated", {"alert_threshold": threshold, "retention_days": retention})
        self._send_json(200, {"settings": {"alert_threshold": threshold, "retention_days": retention}})

    def _send_audit(self) -> None:
        with _database() as connection:
            rows = connection.execute(
                "SELECT id, created_at, username, action, details_json FROM audit_log ORDER BY id DESC LIMIT 200"
            ).fetchall()
        entries = [{
            "id": row["id"],
            "created_at": row["created_at"],
            "username": row["username"],
            "action": row["action"],
            "details": json.loads(row["details_json"]),
        } for row in rows]
        self._send_json(200, {"events": entries})

    def _send_report(self, report_id: str) -> None:
        with _database() as connection:
            row = connection.execute(
                "SELECT * FROM reports WHERE id = ?", (report_id,)
            ).fetchone()
        if row is None:
            self._send_json(404, {"error": "Report not found"})
            return
        report = json.loads(row["report_json"])
        report.update(_report_summary(row))
        with _database() as connection:
            feedback = connection.execute(
                """SELECT feedback.classification, feedback.note, feedback.submitted_at,
                users.username AS submitted_by
                FROM feedback LEFT JOIN users ON users.id = feedback.submitted_by
                WHERE feedback.report_id = ?""",
                (report_id,),
            ).fetchone()
            review = connection.execute(
                """SELECT feedback_reviews.decision, feedback_reviews.indicator,
                feedback_reviews.points_delta, feedback_reviews.reviewed_at,
                users.username AS reviewer
                FROM feedback_reviews LEFT JOIN users ON users.id = feedback_reviews.reviewed_by
                WHERE feedback_reviews.report_id = ?""",
                (report_id,),
            ).fetchone()
        report["feedback"] = dict(feedback) if feedback else None
        report["feedback_review"] = dict(review) if review else None
        user, _ = self._session()
        _audit(user, "report.viewed", {"report_id": report_id})
        self._send_json(200, report)

    def _save_feedback(self, report_id: str, payload: dict[str, Any], user: dict[str, str]) -> None:
        classification = payload.get("classification")
        note = payload.get("note", "")
        if classification not in VALID_FEEDBACK_CLASSIFICATIONS:
            self._send_json(400, {"error": "Choose confirmed_phishing, suspicious, legitimate, or false_positive."})
            return
        if not isinstance(note, str) or not note.strip() or len(note) > 1000:
            self._send_json(400, {"error": "A review reason of 1 to 1000 characters is required."})
            return
        note = note.strip()
        submitted_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with _database() as connection:
            exists = connection.execute("SELECT 1 FROM reports WHERE id = ?", (report_id,)).fetchone()
            if exists is None:
                self._send_json(404, {"error": "Report not found"})
                return
            connection.execute(
                """INSERT INTO feedback(report_id, classification, note, submitted_by, submitted_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(report_id) DO UPDATE SET
                    classification = excluded.classification,
                    note = excluded.note,
                    submitted_by = excluded.submitted_by,
                    submitted_at = excluded.submitted_at""",
                (report_id, classification, note, user["id"], submitted_at),
            )
            connection.execute(
                "DELETE FROM rule_adjustments WHERE source_report_id = ?",
                (report_id,),
            )
            connection.execute(
                "DELETE FROM feedback_reviews WHERE report_id = ?",
                (report_id,),
            )
        _audit(user, "feedback.submitted", {"report_id": report_id, "classification": classification})
        self._send_json(200, {
            "report_id": report_id,
            "classification": classification,
            "note": note,
            "submitted_at": submitted_at,
        })

    def _send_pdf(self, report_id: str) -> None:
        with _database() as connection:
            row = connection.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
            feedback = connection.execute(
                "SELECT classification, note, submitted_at FROM feedback WHERE report_id = ?",
                (report_id,),
            ).fetchone()
        if row is None:
            self._send_json(404, {"error": "Report not found"})
            return
        report = json.loads(row["report_json"])
        report.update(_report_summary(row))
        report["feedback"] = dict(feedback) if feedback else None
        content = _build_pdf(report)
        user, _ = self._session()
        _audit(user, "report.pdf_exported", {"report_id": report_id})
        self._send_response(200, "application/pdf", content)

    def _send_csv(self) -> None:
        with _database() as connection:
            rows = connection.execute(
                "SELECT * FROM reports ORDER BY analyzed_at DESC LIMIT ?",
                (HISTORY_LIMIT,),
            ).fetchall()
            feedback_rows = connection.execute(
                "SELECT report_id, classification FROM feedback"
            ).fetchall()
        feedback_by_id = {row["report_id"]: row["classification"] for row in feedback_rows}
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(("Report ID", "Analyzed at (UTC)", "Subject", "Sender", "Risk", "Score", "URL count", "Classification feedback", "Finding reasons"))
        for row in rows:
            report = json.loads(row["report_json"])
            writer.writerow((
                _spreadsheet_safe(row["id"]),
                _spreadsheet_safe(row["analyzed_at"]),
                _spreadsheet_safe(row["subject"]),
                _spreadsheet_safe(row["sender"]),
                row["level"],
                row["score"],
                row["url_count"],
                feedback_by_id.get(row["id"], ""),
                _spreadsheet_safe(" | ".join(finding["reason"] for finding in report["findings"])),
            ))
        content = ("\ufeff" + stream.getvalue()).encode("utf-8")
        user, _ = self._session()
        _audit(user, "reports.csv_exported", {"report_count": len(rows)})
        self._send_response(200, "text/csv; charset=utf-8", content)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        content = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_response(status, "application/json; charset=utf-8", content)

    def _send_response(self, status: int, content_type: str, content: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )
        response_cookie = getattr(self, "_response_cookie", None)
        if response_cookie:
            self.send_header("Set-Cookie", response_cookie)
        if content_type.startswith("text/csv"):
            self.send_header("Content-Disposition", 'attachment; filename="email-analysis-reports.csv"')
        if content_type == "application/pdf":
            self.send_header("Content-Disposition", 'attachment; filename="email-analysis-report.pdf"')
        self.end_headers()
        self.wfile.write(content)


def _spreadsheet_safe(value: str) -> str:
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value


def _email_header_overrides(payload: dict[str, Any]) -> dict[str, str]:
    fields = {
        "subject": "Subject",
        "from": "From",
        "to": "To",
        "reply_to": "Reply-To",
    }
    overrides: dict[str, str] = {}
    for field, header in fields.items():
        if field not in payload:
            continue
        value = payload[field]
        if not isinstance(value, str):
            raise ValueError(f"{header} must be text.")
        overrides[header] = value
    return overrides


def _pdf_escape(value: str) -> bytes:
    encoded = value.encode("cp1252", errors="replace")
    return encoded.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def _build_pdf(report: dict[str, Any]) -> bytes:
    import textwrap

    severity = str(report.get("level", "LOW")).upper()
    severity_color = {
        "HIGH": (0.67, 0.19, 0.17),
        "SUSPICIOUS": (0.55, 0.36, 0.04),
        "LOW": (0.09, 0.39, 0.29),
    }.get(severity, (0.25, 0.30, 0.28))
    recommendations = {
        "sender": "Verify the sender and request using a known, independent contact method.",
        "content": "Do not provide credentials or approve unusual requests; verify through a trusted channel.",
        "urls": "Do not open the link. Use approved security tools or report it to your security team.",
        "attachments": "Do not open or execute the attachment. Request an approved security scan.",
    }
    pages: list[list[bytes]] = []
    commands: list[bytes] = []
    y = 0

    def color_command(color: tuple[float, float, float]) -> bytes:
        return f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg".encode("ascii")

    def draw_text(
        x: int,
        baseline: int,
        text: str,
        *,
        font: str = "F1",
        size: int = 9,
        color: tuple[float, float, float] = (0.12, 0.20, 0.18),
    ) -> None:
        commands.extend((
            b"BT",
            f"/{font} {size} Tf".encode("ascii"),
            color_command(color),
            f"1 0 0 1 {x} {baseline} Tm".encode("ascii"),
            b"(" + _pdf_escape(text) + b") Tj",
            b"ET",
        ))

    def fill_rect(
        x: int,
        bottom: int,
        width: int,
        height: int,
        color: tuple[float, float, float],
    ) -> None:
        commands.extend((
            b"q",
            color_command(color),
            f"{x} {bottom} {width} {height} re f".encode("ascii"),
            b"Q",
        ))

    def start_page() -> None:
        nonlocal commands, y
        commands = []
        pages.append(commands)
        draw_text(50, 766, "EMAIL SECURITY  /  PHISHING RISK ANALYSIS", font="F2", size=8,
                  color=(0.09, 0.39, 0.29))
        draw_text(422, 766, "LOCAL ANALYSIS REPORT", font="F2", size=8,
                  color=(0.39, 0.46, 0.43))
        commands.extend((
            b"0.84 0.88 0.85 RG",
            b"0.7 w",
            b"50 754 m 562 754 l S",
        ))
        y = 735

    def ensure_space(height: int) -> None:
        if y - height < 55:
            start_page()

    def wrapped_lines(value: str, width: int = 92) -> list[str]:
        printable = value.encode("cp1252", errors="replace").decode("cp1252")
        return textwrap.wrap(
            printable,
            width=width,
            break_long_words=True,
            break_on_hyphens=False,
        ) or [""]

    def add_paragraph(
        value: str,
        *,
        indent: int = 0,
        font: str = "F1",
        size: int = 9,
        color: tuple[float, float, float] = (0.12, 0.20, 0.18),
        width: int = 92,
        gap: int = 0,
    ) -> None:
        nonlocal y
        lines = wrapped_lines(value, width)
        for line in lines:
            ensure_space(14)
            draw_text(50 + indent, y, line, font=font, size=size, color=color)
            y -= 13
        y -= gap

    def add_detail(label: str, value: str) -> None:
        nonlocal y
        lines = wrapped_lines(value or "Not present", 71)
        for index, line in enumerate(lines):
            ensure_space(14)
            if index == 0:
                draw_text(50, y, label, font="F2", size=8,
                          color=(0.39, 0.46, 0.43))
            draw_text(145, y, line, size=9)
            y -= 13

    def add_section(title: str) -> None:
        nonlocal y
        ensure_space(38)
        y -= 5
        draw_text(50, y, title.upper(), font="F2", size=10,
                  color=(0.09, 0.39, 0.29))
        y -= 7
        commands.extend((
            b"0.88 0.91 0.89 RG",
            b"0.6 w",
            f"50 {y} m 562 {y} l S".encode("ascii"),
        ))
        y -= 16

    start_page()
    channel = str(report.get("channel") or "Email")
    draw_text(50, y, "WhatsApp scam review" if channel == "WhatsApp" else "Phishing risk analysis",
              font="F2", size=22)
    y -= 18
    draw_text(50, y, f"{channel} review report  |  Evidence-led heuristic screening",
              size=10, color=(0.39, 0.46, 0.43))
    y -= 31

    fill_rect(50, y - 48, 512, 66, (0.95, 0.97, 0.95))
    fill_rect(50, y - 48, 138, 66, severity_color)
    draw_text(64, y, severity, font="F2", size=12, color=(1, 1, 1))
    draw_text(64, y - 25, f"{report.get('score', 0)}/100", font="F2", size=20,
              color=(1, 1, 1))
    draw_text(207, y + 1, "OVERALL ASSESSMENT", font="F2", size=8,
              color=(0.39, 0.46, 0.43))
    score = max(0, min(100, int(report.get("score", 0))))
    draw_text(207, y - 16, f"Risk score: {score} out of 100", font="F2", size=11)
    fill_rect(207, y - 34, 327, 7, (0.86, 0.89, 0.87))
    if score:
        fill_rect(207, y - 34, max(2, round(327 * score / 100)), 7, severity_color)
    draw_text(207, y - 46, {
        "HIGH": "Treat as high risk. Do not interact; report to your security team.",
        "SUSPICIOUS": "Verify independently before replying, clicking, or sharing information.",
        "LOW": "No configured indicators matched. This is not proof the message or file is safe.",
    }.get(severity, "Review the evidence and verify unexpected requests independently."),
              size=8)
    y -= 78

    scoring = report.get("scoring", {})
    language_analysis = report.get("language_analysis", {})
    add_section("Scoring and evidence reliability")
    add_paragraph(
        f"{scoring.get('method', 'Heuristic rule points; not a calibrated probability.')} "
        f"Indicator points before cap: {scoring.get('indicator_points_total', report.get('score', 0))}; "
        f"score cap applied: {'yes' if scoring.get('score_cap_applied') else 'no'}."
    )
    add_paragraph(
        f"{report.get('confidence_note', 'Evidence quality describes the available source, not certainty that the email is malicious.')}",
        size=8,
        color=(0.39, 0.46, 0.43),
    )
    if language_analysis:
        add_paragraph(
            f"Language rules: {', '.join(language_analysis.get('supported_languages', []))}. "
            f"Matched phrase rules: {', '.join(language_analysis.get('matched_languages', [])) or 'none'}. "
            f"{language_analysis.get('method', '')}",
            size=8,
        )
    y -= 4

    add_section("Message details")
    add_detail("SUBJECT", str(report.get("subject") or "Not present"))
    add_detail("SOURCE CHANNEL", str(report.get("channel") or "Email"))
    screenshot_review = report.get("screenshot_review")
    if screenshot_review:
        add_detail("SCREENSHOT OCR", str(screenshot_review.get("processing") or ""))
    add_detail("SENDER", str(report.get("sender") or "Not present"))
    add_detail("RECIPIENTS", _format_addresses(report.get("recipients", [])) or "Not present")
    add_detail("REPLY-TO", _format_addresses(report.get("reply_to", [])) or "Not present")
    add_detail("RETURN-PATH", str(report.get("return_path") or "Not present"))
    add_detail("ANALYZED (UTC)", str(report.get("analyzed_at") or "Not available"))
    add_detail("REPORT ID", str(report.get("id") or "Not available"))

    add_section("Detection findings and evidence")
    findings = report.get("findings", [])
    if not findings:
        add_paragraph("No configured indicators were recorded.")
    for index, finding in enumerate(findings, start=1):
        heading = (
            f"FINDING {index}  |  {str(finding.get('indicator', finding.get('category', 'content'))).upper()}  "
            f"|  +{finding.get('points', 0)} POINTS  "
            f"|  EVIDENCE {str(finding.get('evidence_reliability', {}).get('level', 'not rated')).upper()}"
        )
        add_paragraph(heading, font="F2", size=8, color=severity_color, width=105, gap=2)
        add_paragraph(str(finding.get("reason", "")), font="F2", width=92)
        add_paragraph(f"Evidence: {finding.get('evidence') or 'No specific evidence recorded.'}",
                      indent=10, size=8, color=(0.28, 0.35, 0.32), width=89)
        if finding.get("language"):
            add_paragraph(f"Matched language rule: {finding['language'].upper()}",
                          indent=10, size=8, width=89)
        reliability = finding.get("evidence_reliability", {})
        if reliability.get("explanation"):
            add_paragraph(f"Evidence quality: {reliability.get('level', 'not rated')} — "
                          f"{reliability['explanation']}", indent=10, size=8, width=89)
        action = recommendations.get(
            str(finding.get("category", "")),
            "Verify the request through a trusted, independent channel.",
        ) if int(finding.get("points", 0)) > 0 else (
            "No configured indicator matched; independently verify unexpected requests."
        )
        add_paragraph(f"Recommended response: {action}", indent=10, size=8,
                      color=(0.09, 0.39, 0.29), width=89, gap=5)

    add_section("Email authentication")
    add_paragraph(
        "Values below are reported from the supplied message headers; this application "
        "does not independently validate SPF, DKIM, or DMARC.",
        size=8,
        color=(0.39, 0.46, 0.43),
        gap=3,
    )
    authentication = report.get("authentication", [])
    for check in authentication:
        add_paragraph(
            f"{check.get('name', 'Check')}: {check.get('status', 'Not available')} "
            f"| Source: {check.get('source', 'supplied headers')}",
            width=92,
        )
    if not authentication:
        add_paragraph("No authentication results were present.")

    add_section("URLs and destinations")
    external_results = any(url.get("virustotal") for url in report.get("urls", []))
    add_paragraph(
        "Destinations are displayed for review only. Links were not opened. "
        + (
            "VirusTotal results are advisory; queried indicators may be added to its public dataset."
            if external_results else
            "No external threat-intelligence lookup was requested."
        ),
        size=8,
        color=(0.39, 0.46, 0.43),
        gap=3,
    )
    urls = report.get("urls", [])
    for url in urls:
        add_paragraph(
            f"{url.get('destination', 'Unknown destination')} "
            f"| Reputation: {url.get('reputation_status', 'not checked')}",
            indent=5,
            width=91,
        )
        vt_result = url.get("virustotal")
        if isinstance(vt_result, dict):
            add_paragraph(
                f"VirusTotal: {vt_result.get('reputation', 'Unknown')} "
                f"| detections: {vt_result.get('detection_count', 'not available')} "
                f"| domain: {vt_result.get('domain_report', {}).get('reputation', 'not available')}",
                indent=12,
                width=85,
            )
            for redirect in vt_result.get("redirect_chain", []):
                add_paragraph(f"Reported redirect: {redirect}", indent=12, width=85)
            if vt_result.get("last_final_url"):
                add_paragraph(
                    f"Reported final URL: {vt_result['last_final_url']}",
                    indent=12,
                    width=85,
                )
    if not urls:
        add_paragraph("No URLs were extracted.")

    add_section("Attachment details")
    add_paragraph(
        "Attachments were not opened or malware-scanned. Hashes are calculated locally "
        "and have not been checked against an external service.",
        size=8,
        color=(0.39, 0.46, 0.43),
        gap=3,
    )
    attachments = report.get("attachments", [])
    for attachment in attachments:
        add_paragraph(
            f"{attachment.get('filename', 'Unknown file')} "
            f"| {attachment.get('content_type', 'Unknown type')} "
            f"| {attachment.get('size_bytes', 0)} bytes",
            indent=5,
            width=91,
        )
        add_paragraph(f"SHA-256: {attachment.get('sha256', 'Not available')}",
                      indent=15, size=8, width=88, gap=2)
        archive = attachment.get("zip_inspection")
        if isinstance(archive, dict):
            add_paragraph(
                f"ZIP directory only: {archive.get('entry_count', 0)} entries; "
                f"{archive.get('declared_uncompressed_bytes', 0)} declared uncompressed bytes; "
                f"{archive.get('scan_status', 'not scanned')}.",
                indent=15,
                size=8,
                width=86,
            )
            for entry_name in archive.get("listed_entries", [])[:20]:
                add_paragraph(f"Listed entry: {entry_name}", indent=20, size=8, width=83)
            if archive.get("listing_truncated"):
                add_paragraph("ZIP entry listing truncated; remaining names not shown.", indent=20, size=8)
    if not attachments:
        add_paragraph("No attachment metadata was extracted.")

    feedback = report.get("feedback")
    if feedback:
        add_section("Classification feedback")
        add_paragraph(f"Classification: {feedback.get('classification', 'Not available')}")
        add_paragraph(f"Submitted (UTC): {feedback.get('submitted_at', 'Not available')}")
        add_paragraph(f"Note: {feedback.get('note') or 'No note provided.'}")

    add_section("Scope and recommended next steps")
    add_paragraph(
        "This report is based on local heuristic checks. It is not proof that a message "
        "is safe or malicious, and it does not replace a full security investigation."
    )
    add_paragraph(
        "Do not click suspicious links or open unexpected attachments. Verify sensitive "
        "requests with a known contact method and report concerns through your organization's "
        "security process."
    )
    add_paragraph(
        "Not configured for this local app: AI analysis, live URL/domain reputation, "
        "independent SPF/DKIM/DMARC validation, antivirus or sandbox scanning, and "
        "Microsoft 365/Defender checks.",
        size=8,
        color=(0.39, 0.46, 0.43),
    )

    for page_number, page_commands in enumerate(pages, start=1):
        page_commands.extend((
            b"0.84 0.88 0.85 RG",
            b"0.6 w",
            b"50 43 m 562 43 l S",
        ))
        commands = page_commands
        draw_text(50, 28, "LOCAL ANALYSIS  |  Handle this report according to your security policy",
                  size=7, color=(0.39, 0.46, 0.43))
        draw_text(499, 28, f"Page {page_number} of {len(pages)}",
                  font="F2", size=7, color=(0.39, 0.46, 0.43))

    objects: list[bytes] = []
    page_ids = [3 + index * 2 for index in range(len(pages))]
    font_id = 3 + len(pages) * 2
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode("ascii"))
    for index, page_lines in enumerate(pages):
        page_id = page_ids[index]
        content_id = page_id + 1
        stream = b"\n".join(page_lines)
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {font_id} 0 R /F2 {font_id + 1} 0 R >> >> "
            f"/Contents {content_id} 0 R >>".encode("ascii")
        )
        objects.append(
            b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n"
            + stream + b"\nendstream"
        )
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


def _format_addresses(addresses: list[dict[str, str]]) -> str:
    return ", ".join(
        f"{item['name']} <{item['address']}>" if item.get("name") else item["address"]
        for item in addresses
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the phishing analyzer web app.")
    parser.add_argument("--port", type=int, default=8765, help="Local web server port (default: 8765).")
    parser.add_argument(
        "--create-admin",
        action="store_true",
        help="Create the first administrator interactively, without starting the web server.",
    )
    args = parser.parse_args()
    if not 0 < args.port < 65536:
        parser.error("--port must be between 1 and 65535")

    if args.create_admin:
        username = input("Administrator username: ")
        password = getpass("Administrator password (12+ characters): ")
        confirmation = getpass("Confirm administrator password: ")
        if password != confirmation:
            parser.error("The passwords do not match.")
        try:
            user = _create_initial_admin(username, password)
        except ValueError as exc:
            parser.error(str(exc))
        print(
            f"Administrator '{user['username']}' created. "
            "Start the application normally and sign in."
        )
        return

    server = ThreadingHTTPServer(("127.0.0.1", args.port), AnalyzerRequestHandler)
    print(f"Phishing analyzer is available at http://127.0.0.1:{args.port}")
    print("Local access only. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping local web server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
