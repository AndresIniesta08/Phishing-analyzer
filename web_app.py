"""Loopback-only web interface and local report history for email analysis."""

from __future__ import annotations

import argparse
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
import sqlite3
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from email_analysis import analyze_message


WEB_DIR = Path(__file__).with_name("web")
MAX_EMAIL_BYTES = 10 * 1024 * 1024
MAX_REQUEST_BYTES = 64 * 1024 * 1024
HISTORY_LIMIT = 100
SESSION_COOKIE = "phishing_session"
SESSION_TTL_HOURS = 8
PASSWORD_ITERATIONS = 310_000
VALID_ROLES = {"user", "analyst", "admin"}
VALID_INCIDENT_STATUSES = {"open", "investigating", "resolved"}


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
            classification TEXT NOT NULL CHECK(classification IN ('false_positive', 'false_negative')),
            note TEXT NOT NULL DEFAULT '',
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
            status TEXT NOT NULL CHECK(status IN ('open', 'investigating', 'resolved')),
            assigned_to TEXT REFERENCES users(id) ON DELETE SET NULL,
            note TEXT NOT NULL DEFAULT ''
        )"""
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
        f"{item['name']} <{item['address']}>" if item["name"] else item["address"]
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
                    f"High-risk email detected (score {report['score']}/100).",
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
            "/preview", "/analyze", "/api/incidents", "/api/alerts/ack",
            "/api/admin/users", "/api/admin/settings",
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
        required_field = "classification" if feedback_request else "email" if path in {"/preview", "/analyze"} else None
        payload = self._read_payload(required_field=required_field)
        if payload is None:
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
        if path == "/preview":
            try:
                report = analyze_message(
                    payload["email"],
                    header_overrides=_email_header_overrides(payload),
                )
                self._send_json(200, report)
            except ValueError as exc:
                self._send_json(400, {"error": str(exc)})
            return
        try:
            report = analyze_message(
                payload["email"],
                header_overrides=_email_header_overrides(payload),
            )
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        report["report_id"], report["analyzed_at"] = _store_report(report, user)
        _audit(user, "email.analyzed", {
            "report_id": report["report_id"],
            "level": report["level"],
            "score": report["score"],
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

    def _read_payload(self, *, required_field: str | None = "email") -> dict[str, Any] | None:
        content_length = self.headers.get("Content-Length")
        try:
            request_size = int(content_length) if content_length is not None else -1
        except ValueError:
            request_size = -1
        if request_size < 0:
            self._send_json(400, {"error": "A valid Content-Length is required."})
            return None
        if request_size > MAX_REQUEST_BYTES:
            self._send_json(413, {"error": "Request body exceeds the upload limit."})
            return None
        if required_field != "email" and request_size > 16 * 1024:
            self._send_json(413, {"error": "Request body exceeds the 16 KB limit."})
            return None
        if self.headers.get_content_type() != "application/json":
            self._send_json(415, {"error": "Send email content as application/json."})
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
        if status not in {"", "none", "open", "investigating", "resolved"}:
            self._send_json(400, {"error": "Status filter must be none, open, investigating, or resolved."})
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
                "urls": 0,
            }
            for key in keys
        }
        with _database() as connection:
            rows = connection.execute(
                f"""SELECT {group_expression} AS bucket, level, COUNT(*) AS total,
                SUM(url_count) AS urls
                FROM reports
                WHERE date(analyzed_at) >= date(?) AND date(analyzed_at) <= date(?)
                GROUP BY bucket, level""",
                (start_date, end_date),
            ).fetchall()
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
        points = list(points_by_key.values())
        self._send_json(200, {
            "period": period,
            "start": start_date,
            "end": end_date,
            "totals": {
                "emails": sum(point["total"] for point in points),
                "high": sum(point["high"] for point in points),
                "suspicious": sum(point["suspicious"] for point in points),
                "low": sum(point["low"] for point in points),
                "urls": sum(point["urls"] for point in points),
            },
            "points": points,
        })

    def _send_incidents(self) -> None:
        with _database() as connection:
            rows = connection.execute(
                """SELECT incidents.id, incidents.report_id, incidents.created_at,
                incidents.updated_at, incidents.status, incidents.note,
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
                "assigned_to": str(details.get("assigned_to") or ""),
                "status_updated": bool(details.get("status_updated", False)),
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

    def _create_incident(self, user: dict[str, str], payload: dict[str, Any]) -> None:
        report_id = payload.get("report_id")
        note = payload.get("note", "")
        if not isinstance(report_id, str) or not report_id:
            self._send_json(400, {"error": "A report_id is required to create an incident."})
            return
        if not isinstance(note, str) or len(note) > 1000:
            self._send_json(400, {"error": "Incident notes must be 1000 characters or fewer."})
            return
        incident_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with _database() as connection:
            exists = connection.execute("SELECT 1 FROM reports WHERE id = ?", (report_id,)).fetchone()
            if exists is None:
                self._send_json(404, {"error": "Report not found."})
                return
            if connection.execute("SELECT 1 FROM incidents WHERE report_id = ?", (report_id,)).fetchone():
                self._send_json(409, {"error": "An incident already exists for this report."})
                return
            connection.execute(
                """INSERT INTO incidents(id, report_id, created_at, updated_at, status, assigned_to, note)
                VALUES (?, ?, ?, ?, 'open', ?, ?)""",
                (incident_id, report_id, now, now, user["id"], note.strip()),
            )
        _audit(user, "incident.created", {"incident_id": incident_id, "report_id": report_id})
        self._send_json(201, {"id": incident_id, "report_id": report_id, "status": "open"})

    def _update_incident(self, user: dict[str, str], incident_id: str, payload: dict[str, Any]) -> None:
        status = payload.get("status")
        note = payload.get("note", "")
        assigned_to = payload.get("assigned_to", user["id"])
        if not isinstance(status, str) or status not in VALID_INCIDENT_STATUSES:
            self._send_json(400, {"error": "Incident status must be open, investigating, or resolved."})
            return
        if not isinstance(note, str) or len(note) > 1000:
            self._send_json(400, {"error": "Incident notes must be 1000 characters or fewer."})
            return
        if assigned_to is not None and not isinstance(assigned_to, str):
            self._send_json(400, {"error": "assigned_to must be a user id or null."})
            return
        with _database() as connection:
            existing = connection.execute(
                "SELECT status, assigned_to, note FROM incidents WHERE id = ?",
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
            connection.execute(
                """UPDATE incidents SET status = ?, assigned_to = ?, note = ?, updated_at = ?
                WHERE id = ?""",
                (status, assigned_to, note.strip(), datetime.now(timezone.utc).isoformat(timespec="seconds"), incident_id),
            )
        _audit(user, "incident.updated", {
            "incident_id": incident_id,
            "status": status,
            "assigned_to": assigned_to,
            "status_updated": existing["status"] != status,
            "assignment_updated": existing["assigned_to"] != assigned_to,
            "note_updated": existing["note"] != note.strip(),
        })
        self._send_json(200, {"id": incident_id, "status": status, "assigned_to": assigned_to})

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
                "SELECT classification, note, submitted_at FROM feedback WHERE report_id = ?",
                (report_id,),
            ).fetchone()
        report["feedback"] = dict(feedback) if feedback else None
        user, _ = self._session()
        _audit(user, "report.viewed", {"report_id": report_id})
        self._send_json(200, report)

    def _save_feedback(self, report_id: str, payload: dict[str, str], user: dict[str, str]) -> None:
        classification = payload.get("classification")
        note = payload.get("note", "").strip()
        if classification not in {"false_positive", "false_negative"}:
            self._send_json(400, {"error": "Feedback must be false_positive or false_negative."})
            return
        if len(note) > 1000:
            self._send_json(400, {"error": "Feedback note must be 1000 characters or fewer."})
            return
        submitted_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with _database() as connection:
            exists = connection.execute("SELECT 1 FROM reports WHERE id = ?", (report_id,)).fetchone()
            if exists is None:
                self._send_json(404, {"error": "Report not found"})
                return
            connection.execute(
                """INSERT INTO feedback(report_id, classification, note, submitted_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(report_id) DO UPDATE SET
                    classification = excluded.classification,
                    note = excluded.note,
                    submitted_at = excluded.submitted_at""",
                (report_id, classification, note, submitted_at),
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
    draw_text(50, y, "Phishing risk analysis", font="F2", size=22)
    y -= 18
    draw_text(50, y, "Email review report  |  Evidence-led heuristic screening",
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
        "LOW": "No configured indicators matched. This is not proof the email is safe.",
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
    add_paragraph(
        "Destinations are displayed for review only. Links were not opened and no live "
        "threat-intelligence reputation check was performed.",
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
