import base64
import hashlib
import io
import os
import sqlite3
import tempfile
import json
import threading
import unittest
import zipfile
from contextlib import closing
from email.message import EmailMessage
from http.server import ThreadingHTTPServer
from PIL import Image
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from unittest import mock

_TEST_DATA_DIR = tempfile.TemporaryDirectory()
os.environ["PHISHING_ANALYZER_DATA_DIR"] = _TEST_DATA_DIR.name
from email_analysis import analyze_message
from web_app import (
    AnalyzerRequestHandler,
    DATABASE_PATH,
    MAX_EMAIL_BYTES,
    _build_pdf,
    _create_initial_admin,
    _inspect_whatsapp_zip,
    _analyze_whatsapp_message,
    _analyze_screenshot_text,
    _ocr_screenshot,
    _migrate_feedback_schema,
    _migrate_incident_schema,
    _server_address,
    _spreadsheet_safe,
)

_RAW_URLOPEN = urlopen


class WebAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        admin = _create_initial_admin("test-admin", "TestAdminPass!2026")
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), AnalyzerRequestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"
        login = Request(
            f"{cls.base_url}/api/login",
            data=json.dumps({"username": "test-admin", "password": "TestAdminPass!2026"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with _RAW_URLOPEN(login) as response:
            auth = json.loads(response.read())
            cls.session_cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        cls.csrf_token = auth["csrf_token"]
        cls.admin_id = admin["id"]

        def authenticated_urlopen(url, *args, **kwargs):
            if isinstance(url, Request):
                url.add_header("Cookie", cls.session_cookie)
                if url.get_method() in {"POST", "DELETE"}:
                    url.add_header("X-CSRF-Token", cls.csrf_token)
            else:
                url = Request(url, headers={"Cookie": cls.session_cookie})
            return _RAW_URLOPEN(url, *args, **kwargs)

        cls.original_urlopen = urlopen
        globals()["urlopen"] = authenticated_urlopen

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()
        globals()["urlopen"] = cls.original_urlopen

    def test_home_page_serves_web_app(self) -> None:
        with urlopen(self.base_url) as response:
            page = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers.get_content_type(), "text/html")
        self.assertIn("Phishing risk analyzer", page)
        self.assertIn('id="app-shell"', page)
        self.assertIn('id="email-subject"', page)
        self.assertIn('id="severity-title"', page)
        self.assertIn('id="severity-bar"', page)
        self.assertIn('aria-label="Main navigation"', page)
        self.assertIn('href="#threat-detections"', page)
        self.assertIn('id="email-drop-zone"', page)
        self.assertIn('id="history-status"', page)
        self.assertIn('id="whatsapp-pdf-link"', page)
        self.assertNotIn('id="auth-form"', page)

    def test_azure_server_uses_assigned_port_and_requires_allowlists(self) -> None:
        azure_environment = {
            "WEBSITE_INSTANCE_ID": "test-instance",
            "PORT": "8123",
            "WEBSITES_PORT": "9000",
            "PHISHING_ANALYZER_ALLOWED_HOSTS": "analyzer.azurewebsites.net",
            "PHISHING_ANALYZER_ALLOWED_ORIGINS": "https://analyzer.azurewebsites.net",
        }
        with mock.patch.dict(os.environ, azure_environment):
            self.assertEqual(_server_address(8765), ("0.0.0.0", 8123))

        with mock.patch.dict(os.environ, {"WEBSITE_INSTANCE_ID": "test-instance"}, clear=False):
            os.environ.pop("PHISHING_ANALYZER_ALLOWED_HOSTS", None)
            os.environ.pop("PHISHING_ANALYZER_ALLOWED_ORIGINS", None)
            with self.assertRaisesRegex(ValueError, "PHISHING_ANALYZER_ALLOWED_HOSTS"):
                _server_address(8765)

    def test_azure_requests_require_allowlisted_host_and_origin(self) -> None:
        azure_environment = {
            "WEBSITE_INSTANCE_ID": "test-instance",
            "PHISHING_ANALYZER_ALLOWED_HOSTS": "analyzer.azurewebsites.net",
            "PHISHING_ANALYZER_ALLOWED_ORIGINS": "https://analyzer.azurewebsites.net",
        }
        with mock.patch.dict(os.environ, azure_environment):
            request = Request(
                f"{self.base_url}/health",
                headers={
                    "Host": "analyzer.azurewebsites.net",
                    "Origin": "https://analyzer.azurewebsites.net",
                },
            )
            with _RAW_URLOPEN(request) as response:
                self.assertEqual(response.status, 200)

            request = Request(
                f"{self.base_url}/health",
                headers={
                    "Host": "analyzer.azurewebsites.net",
                    "Origin": "https://attacker.example",
                },
            )
            with self.assertRaises(HTTPError) as rejected:
                _RAW_URLOPEN(request)
            self.assertEqual(rejected.exception.code, 403)

            request = Request(
                f"{self.base_url}/health",
                headers={"Host": "localhost"},
            )
            with self.assertRaises(HTTPError) as rejected:
                _RAW_URLOPEN(request)
            self.assertEqual(rejected.exception.code, 403)

    def test_azure_session_cookie_is_secure(self) -> None:
        handler = object.__new__(AnalyzerRequestHandler)
        with mock.patch.dict(os.environ, {"WEBSITE_INSTANCE_ID": "test-instance"}):
            handler._set_session_cookie("session-token", "2026-11-09T12:00:00+00:00")
            self.assertIn("; Secure;", handler._response_cookie)
            handler._set_session_cookie(None)
            self.assertIn("; Secure", handler._response_cookie)

    def test_signed_out_visitors_are_redirected_to_standalone_login(self) -> None:
        with _RAW_URLOPEN(f"{self.base_url}/") as response:
            self.assertEqual(response.geturl(), f"{self.base_url}/login")
            login_page = response.read().decode("utf-8")
            self.assertIn('id="auth-form"', login_page)
            self.assertIn("Accounts are provisioned by an administrator", login_page)
            self.assertNotIn("Create the administrator account", login_page)
            self.assertNotIn('id="auth-confirm"', login_page)
            self.assertNotIn('id="app-shell"', login_page)

    def test_signed_in_visitors_are_redirected_away_from_login_page(self) -> None:
        request = Request(
            f"{self.base_url}/login",
            headers={"Cookie": self.session_cookie},
        )
        with _RAW_URLOPEN(request) as response:
            self.assertEqual(response.geturl(), self.base_url + "/")
            app_page = response.read().decode("utf-8")
        self.assertIn('id="app-shell"', app_page)
        self.assertNotIn('id="auth-form"', app_page)

    def test_api_requires_login_and_csrf_for_writes(self) -> None:
        with self.assertRaises(HTTPError) as unauthorized:
            _RAW_URLOPEN(f"{self.base_url}/api/history")
        self.assertEqual(unauthorized.exception.code, 401)

        request = Request(
            f"{self.base_url}/analyze",
            data=json.dumps({"email": "Subject: CSRF test\n\nBody."}).encode(),
            headers={
                "Content-Type": "application/json",
                "Cookie": self.session_cookie,
            },
            method="POST",
        )
        with self.assertRaises(HTTPError) as missing_csrf:
            _RAW_URLOPEN(request)
        self.assertEqual(missing_csrf.exception.code, 403)

    def test_public_account_setup_is_disabled_and_last_admin_guard_remains(self) -> None:
        setup_request = Request(
            f"{self.base_url}/api/setup",
            data=json.dumps({"username": "unauthorized", "password": "StrongPassphrase!2026"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as blocked:
            urlopen(setup_request)
        self.assertEqual(blocked.exception.code, 403)
        with self.assertRaises(ValueError):
            _create_initial_admin("weak-user", "short")
        with self.assertRaises(ValueError):
            _create_initial_admin("second-admin", "AnotherAdmin!Passphrase2026")

        disable_self = Request(
            f"{self.base_url}/api/admin/users/{self.admin_id}",
            data=json.dumps({"role": "user", "active": False}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as self_lockout:
            urlopen(disable_self)
        self.assertEqual(self_lockout.exception.code, 400)

    def test_admin_can_manage_accounts_alerts_and_incidents(self) -> None:
        create_user = Request(
            f"{self.base_url}/api/admin/users",
            data=json.dumps({
                "username": "test-analyst",
                "password": "AnalystPass!2026",
                "role": "analyst",
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(create_user) as response:
            analyst = json.loads(response.read())

        analyst_login = Request(
            f"{self.base_url}/api/login",
            data=json.dumps({"username": "test-analyst", "password": "AnalystPass!2026"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with _RAW_URLOPEN(analyst_login) as response:
            analyst_auth = json.loads(response.read())
            analyst_cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        forbidden = Request(
            f"{self.base_url}/api/admin/users",
            headers={"Cookie": analyst_cookie},
        )
        with self.assertRaises(HTTPError) as raised:
            _RAW_URLOPEN(forbidden)
        self.assertEqual(raised.exception.code, 403)
        analyst_incidents = Request(
            f"{self.base_url}/api/incidents",
            headers={"Cookie": analyst_cookie},
        )
        with _RAW_URLOPEN(analyst_incidents) as response:
            self.assertEqual(json.loads(response.read())["incidents"], [])
        analyst_logout = Request(
            f"{self.base_url}/api/logout",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "Cookie": analyst_cookie,
                "X-CSRF-Token": analyst_auth["csrf_token"],
            },
            method="POST",
        )
        with _RAW_URLOPEN(analyst_logout) as response:
            self.assertTrue(json.loads(response.read())["logged_out"])

        analyze = Request(
            f"{self.base_url}/analyze",
            data=json.dumps({
                "email": "Subject: Urgent security request\n\nImmediately verify your password and send OTP code; keep confidential. https://micros0ft.com.evil.net/login",
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(analyze) as response:
            report = json.loads(response.read())
        self.assertEqual(report["level"], "HIGH")
        report_id = report["report_id"]
        incident_id = None
        try:
            with urlopen(f"{self.base_url}/api/alerts") as response:
                alerts = json.loads(response.read())["alerts"]
            alert = next(item for item in alerts if item["report_id"] == report_id)
            ack = Request(
                f"{self.base_url}/api/alerts/ack",
                data=json.dumps({"alert_id": alert["id"]}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(ack) as response:
                self.assertTrue(json.loads(response.read())["acknowledged_at"])

            create_incident = Request(
                f"{self.base_url}/api/incidents",
                data=json.dumps({"report_id": report_id, "note": "Needs analyst review."}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(create_incident) as response:
                incident_id = json.loads(response.read())["id"]
            update_incident = Request(
                f"{self.base_url}/api/incidents/{incident_id}",
                data=json.dumps({
                    "status": "investigating",
                    "severity": "critical",
                    "assigned_to": analyst["id"],
                    "note": "Analyst assigned.",
                }).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(update_incident) as response:
                self.assertEqual(json.loads(response.read())["status"], "investigating")
            with urlopen(f"{self.base_url}/api/incidents") as response:
                cases = json.loads(response.read())["incidents"]
            case = next(item for item in cases if item["id"] == incident_id)
            self.assertEqual(case["assignee"], "test-analyst")
            self.assertEqual(case["note"], "Analyst assigned.")
            self.assertEqual(case["severity"], "critical")

            settings = Request(
                f"{self.base_url}/api/admin/settings",
                data=json.dumps({"alert_threshold": 65, "retention_days": 0}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(settings) as response:
                self.assertEqual(json.loads(response.read())["settings"]["alert_threshold"], 65)

            with urlopen(f"{self.base_url}/api/admin/audit") as response:
                actions = {entry["action"] for entry in json.loads(response.read())["events"]}
            self.assertIn("email.analyzed", actions)
            self.assertIn("incident.created", actions)
            self.assertIn("incident.updated", actions)
            self.assertIn("alert.acknowledged", actions)
        finally:
            if incident_id:
                delete_report = Request(f"{self.base_url}/api/report/{report_id}", method="DELETE")
                with urlopen(delete_report):
                    pass
            delete_user = Request(f"{self.base_url}/api/admin/users/{analyst['id']}", method="DELETE")
            with urlopen(delete_user):
                pass
            reset_settings = Request(
                f"{self.base_url}/api/admin/settings",
                data=json.dumps({"alert_threshold": 55, "retention_days": 0}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(reset_settings):
                pass

    def test_analyze_endpoint_returns_findings(self) -> None:
        request = Request(
            f"{self.base_url}/analyze",
            data=json.dumps({
                "email": "From: sender@example.com\n\nNormal update.",
                "subject": "Separate subject",
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            result = json.loads(response.read())
        self.assertEqual(result["level"], "LOW")
        self.assertEqual(result["score"], 0)
        self.assertTrue(result["findings"])
        self.assertTrue(result["report_id"])
        self.assertEqual(result["subject"], "Separate subject")

    def test_separate_subject_overrides_header_and_is_validated(self) -> None:
        preview = Request(
            f"{self.base_url}/preview",
            data=json.dumps({
                "email": "Subject: Header subject\n\nBody.",
                "subject": "Entered subject",
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(preview) as response:
            result = json.loads(response.read())
        self.assertEqual(result["subject"], "Entered subject")

        invalid = Request(
            f"{self.base_url}/preview",
            data=json.dumps({"email": "Body.", "subject": "Line one\nLine two"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as invalid_subject:
            urlopen(invalid)
        self.assertEqual(invalid_subject.exception.code, 400)

    def test_manual_from_to_and_reply_to_fields_reach_preview_and_analysis(self) -> None:
        payload = {
            "email": (
                "From: original@example.net\nTo: old-recipient@example.net\n"
                "Reply-To: old-reply@example.net\nSubject: Header subject\n\n"
                "A routine local test."
            ),
            "from": "Microsoft Support <help@attacker.example>",
            "to": "Analyst <analyst@example.org>",
            "reply_to": "reply@different.example",
            "subject": "Entered subject",
        }
        for endpoint in ("preview", "analyze"):
            with self.subTest(endpoint=endpoint):
                request = Request(
                    f"{self.base_url}/{endpoint}",
                    data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urlopen(request) as response:
                    result = json.loads(response.read())
                self.assertEqual(result["sender"][0]["address"], "help@attacker.example")
                self.assertEqual(result["recipients"][0]["address"], "analyst@example.org")
                self.assertEqual(result["reply_to"][0]["address"], "reply@different.example")
                self.assertEqual(result["subject"], "Entered subject")
                if endpoint == "analyze":
                    self.assertTrue(any(
                        finding.get("indicator") == "Trusted-brand display-name mismatch"
                        for finding in result["findings"]
                    ))

    def test_header_field_rejects_crlf_injection_and_non_text_values(self) -> None:
        for field_value in (
            {"reply_to": "reply@example.net\r\nBcc: victim@example.net"},
            {"from": ["sender@example.net"]},
        ):
            with self.subTest(field_value=field_value):
                request = Request(
                    f"{self.base_url}/preview",
                    data=json.dumps({"email": "Body.", **field_value}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(HTTPError) as invalid:
                    urlopen(request)
                self.assertEqual(invalid.exception.code, 400)

    def test_preview_extracts_email_without_creating_history(self) -> None:
        with urlopen(f"{self.base_url}/api/history") as response:
            before = json.loads(response.read())["counts"]["total"]
        request = Request(
            f"{self.base_url}/preview",
            data=json.dumps({"email": "From: sender@example.com\nSubject: Preview\n\nText."}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            result = json.loads(response.read())
        self.assertEqual(result["sender"][0]["address"], "sender@example.com")
        self.assertNotIn("report_id", result)
        with urlopen(f"{self.base_url}/api/history") as response:
            after = json.loads(response.read())["counts"]["total"]
        self.assertEqual(before, after)

    def test_history_report_export_and_delete(self) -> None:
        request = Request(
            f"{self.base_url}/analyze",
            data=json.dumps({"email": "From: sender@example.com\nSubject: History test\n\nText."}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            analyzed = json.loads(response.read())
        report_id = analyzed["report_id"]
        with urlopen(f"{self.base_url}/api/report/{report_id}") as response:
            report = json.loads(response.read())
        self.assertEqual(report["subject"], "History test")
        with urlopen(f"{self.base_url}/api/export.csv") as response:
            self.assertIn("text/csv", response.headers.get("Content-Type", ""))
            self.assertIn(b"History test", response.read())
        delete = Request(f"{self.base_url}/api/report/{report_id}", method="DELETE")
        with urlopen(delete) as response:
            self.assertEqual(json.loads(response.read())["deleted"], True)

    def test_history_can_filter_by_query_risk_and_date(self) -> None:
        request = Request(
            f"{self.base_url}/analyze",
            data=json.dumps({"email": "From: filtered@example.com\nSubject: Unique search term\n\nText."}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            analyzed = json.loads(response.read())
        params = urlencode({
            "q": "Unique search",
            "risk": "LOW",
            "from": analyzed["analyzed_at"][:10],
            "to": analyzed["analyzed_at"][:10],
        })
        with urlopen(f"{self.base_url}/api/history?{params}") as response:
            data = json.loads(response.read())
        self.assertEqual(data["matched"], 1)
        self.assertEqual(len(data["reports"]), 1)
        self.assertEqual(data["reports"][0]["id"], analyzed["report_id"])
        delete = Request(f"{self.base_url}/api/report/{analyzed['report_id']}", method="DELETE")
        with urlopen(delete):
            pass

    def test_history_search_includes_extracted_domains(self) -> None:
        request = Request(
            f"{self.base_url}/analyze",
            data=json.dumps({
                "email": "Subject: Domain lookup\n\nReview https://history-search-domain.example/login",
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            analyzed = json.loads(response.read())
        with urlopen(f"{self.base_url}/api/history?q=history-search-domain.example") as response:
            results = json.loads(response.read())
        self.assertTrue(any(item["id"] == analyzed["report_id"] for item in results["reports"]))
        with urlopen(Request(f"{self.base_url}/api/report/{analyzed['report_id']}", method="DELETE")):
            pass

    def test_threat_detections_list_domains_linked_to_url_findings(self) -> None:
        request = Request(
            f"{self.base_url}/analyze",
            data=json.dumps({
                "email": (
                    "Subject: Threat indicator test\n\n"
                    "Sign in at https://microsoft.com.evil.net/login"
                ),
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            analyzed = json.loads(response.read())
        with urlopen(f"{self.base_url}/api/threats") as response:
            detections = json.loads(response.read())["detections"]
        match = next(item for item in detections if item["domain"] == "microsoft.com.evil.net")
        self.assertEqual(match["subject"], "Threat indicator test")
        self.assertEqual(match["level"], analyzed["level"])
        with urlopen(Request(f"{self.base_url}/api/report/{analyzed['report_id']}", method="DELETE")):
            pass

    def test_history_can_filter_by_incident_status_and_incident_has_timeline(self) -> None:
        analysis = Request(
            f"{self.base_url}/analyze",
            data=json.dumps({"email": "Subject: Status filter test\n\nRoutine message."}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(analysis) as response:
            report = json.loads(response.read())
        create_incident = Request(
            f"{self.base_url}/api/incidents",
            data=json.dumps({"report_id": report["report_id"], "note": "Initial evidence reviewed."}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(create_incident) as response:
            incident_id = json.loads(response.read())["id"]
        with urlopen(f"{self.base_url}/api/history?status=open") as response:
            opened = json.loads(response.read())
        self.assertTrue(any(
            item["id"] == report["report_id"] and item["status"] == "open"
            for item in opened["reports"]
        ))
        with urlopen(f"{self.base_url}/api/history?status=none") as response:
            unassigned = json.loads(response.read())
        self.assertFalse(any(item["id"] == report["report_id"] for item in unassigned["reports"]))
        update_incident = Request(
            f"{self.base_url}/api/incidents/{incident_id}",
            data=json.dumps({
                "status": "investigating",
                "assigned_to": "",
                "note": "URLs and sender details reviewed.",
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(update_incident):
            pass
        with urlopen(f"{self.base_url}/api/incidents") as response:
            incidents = json.loads(response.read())["incidents"]
        incident = next(item for item in incidents if item["report_id"] == report["report_id"])
        self.assertEqual(incident["timeline"][0]["action"], "incident.created")
        self.assertEqual(incident["timeline"][-1]["action"], "incident.updated")
        self.assertEqual(incident["timeline"][-1]["status"], "investigating")
        self.assertTrue(incident["timeline"][-1]["note_updated"])

        false_positive_update = Request(
            f"{self.base_url}/api/incidents/{incident_id}",
            data=json.dumps({
                "status": "false_positive",
                "severity": "critical",
                "assigned_to": "",
                "note": "Reviewed as a false positive.",
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(false_positive_update) as response:
            updated_incident = json.loads(response.read())
        self.assertEqual(updated_incident["severity"], "critical")
        with urlopen(f"{self.base_url}/api/history?status=false_positive") as response:
            false_positive_history = json.loads(response.read())["reports"]
        self.assertTrue(any(item["id"] == report["report_id"] for item in false_positive_history))

        invalid = Request(
            f"{self.base_url}/api/history?status=closed",
            headers={"Cookie": self.session_cookie},
        )
        with self.assertRaises(HTTPError) as invalid_status:
            urlopen(invalid)
        self.assertEqual(invalid_status.exception.code, 400)
        with urlopen(Request(f"{self.base_url}/api/report/{report['report_id']}", method="DELETE")):
            pass

    def test_daily_and_monthly_trends_aggregate_risk_and_urls(self) -> None:
        with urlopen(f"{self.base_url}/api/trends?period=day") as response:
            daily_before = json.loads(response.read())
        with urlopen(f"{self.base_url}/api/trends?period=month") as response:
            monthly_before = json.loads(response.read())
        report_ids = []
        samples = (
            "Subject: Trend low\n\nA routine local test.",
            "Subject: Trend high\n\nImmediately verify your password and send OTP code; keep confidential, visit https://micros0ft.com.evil.net/login.",
        )
        analyzed = []
        for email in samples:
            request = Request(
                f"{self.base_url}/analyze",
                data=json.dumps({"email": email}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(request) as response:
                report = json.loads(response.read())
            report_ids.append(report["report_id"])
            analyzed.append(report)

        try:
            feedback_request = Request(
                f"{self.base_url}/api/report/{report_ids[0]}/feedback",
                data=json.dumps({
                    "classification": "legitimate",
                    "note": "Reviewed as a routine internal test message.",
                }).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(feedback_request):
                pass
            with urlopen(f"{self.base_url}/api/trends?period=day") as response:
                daily = json.loads(response.read())
            self.assertEqual(len(daily["points"]), 30)
            today = analyzed[0]["analyzed_at"][:10]
            today_point = next(point for point in daily["points"] if point["period"] == today)
            today_before = next(point for point in daily_before["points"] if point["period"] == today)
            self.assertEqual(today_point["total"], today_before["total"] + 2)
            self.assertEqual(today_point["low"], today_before["low"] + 1)
            self.assertEqual(today_point["high"], today_before["high"] + 1)
            self.assertEqual(today_point["urls"], today_before["urls"] + 1)
            self.assertEqual(today_point["legitimate"], today_before["legitimate"] + 1)
            self.assertEqual(daily["totals"]["messages"], daily_before["totals"]["messages"] + 2)
            self.assertEqual(daily["totals"]["urls"], daily_before["totals"]["urls"] + 1)
            self.assertEqual(daily["totals"]["legitimate"], daily_before["totals"]["legitimate"] + 1)
            self.assertEqual(
                daily["reviewed"]["legitimate"],
                daily_before["reviewed"]["legitimate"] + 1,
            )
            self.assertTrue(all(
                indicator["count"] > 0
                for indicator in daily["common_indicators"]
            ))

            with urlopen(f"{self.base_url}/api/trends?period=month") as response:
                monthly = json.loads(response.read())
            current_month = today[:7]
            month_point = next(point for point in monthly["points"] if point["period"] == current_month)
            month_before = next(point for point in monthly_before["points"] if point["period"] == current_month)
            self.assertEqual(month_point["total"], month_before["total"] + 2)
            self.assertEqual(month_point["high"], month_before["high"] + 1)
            self.assertEqual(month_point["legitimate"], month_before["legitimate"] + 1)
            self.assertEqual(monthly["totals"]["messages"], monthly_before["totals"]["messages"] + 2)
            self.assertEqual(
                monthly["reviewed"]["legitimate"],
                monthly_before["reviewed"]["legitimate"] + 1,
            )

            with self.assertRaises(HTTPError) as raised:
                urlopen(f"{self.base_url}/api/trends?period=year")
            self.assertEqual(raised.exception.code, 400)
        finally:
            for report_id in report_ids:
                delete = Request(f"{self.base_url}/api/report/{report_id}", method="DELETE")
                with urlopen(delete):
                    pass

    def test_feedback_can_be_saved_and_updated(self) -> None:
        request = Request(
            f"{self.base_url}/analyze",
            data=json.dumps({"email": "Subject: Feedback case\n\nText."}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            report_id = json.loads(response.read())["report_id"]
        for classification in ("legitimate", "suspicious", "false_positive", "confirmed_phishing"):
            feedback_request = Request(
                f"{self.base_url}/api/report/{report_id}/feedback",
                data=json.dumps({"classification": classification, "note": "Reviewed by local analyst."}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(feedback_request) as response:
                feedback = json.loads(response.read())
            self.assertEqual(feedback["classification"], classification)
        with urlopen(f"{self.base_url}/api/report/{report_id}") as response:
            report = json.loads(response.read())
        self.assertEqual(report["feedback"]["classification"], "confirmed_phishing")
        self.assertEqual(report["feedback"]["note"], "Reviewed by local analyst.")
        self.assertEqual(report["feedback"]["submitted_by"], "test-admin")
        delete = Request(f"{self.base_url}/api/report/{report_id}", method="DELETE")
        with urlopen(delete):
            pass

    def test_analyst_can_submit_feedback_but_cannot_review_it(self) -> None:
        create_user = Request(
            f"{self.base_url}/api/admin/users",
            data=json.dumps({
                "username": "feedback-analyst",
                "password": "FeedbackAnalyst!2026",
                "role": "analyst",
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(create_user) as response:
            analyst = json.loads(response.read())
        login = Request(
            f"{self.base_url}/api/login",
            data=json.dumps({
                "username": "feedback-analyst",
                "password": "FeedbackAnalyst!2026",
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with _RAW_URLOPEN(login) as response:
            analyst_auth = json.loads(response.read())
            analyst_cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        with urlopen(Request(
            f"{self.base_url}/analyze",
            data=json.dumps({"email": "Subject: Analyst review\n\nRoutine message."}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )) as response:
            report_id = json.loads(response.read())["report_id"]

        try:
            feedback_request = Request(
                f"{self.base_url}/api/report/{report_id}/feedback",
                data=json.dumps({
                    "classification": "suspicious",
                    "note": "Needs a second analyst review.",
                }).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Cookie": analyst_cookie,
                    "X-CSRF-Token": analyst_auth["csrf_token"],
                },
                method="POST",
            )
            with _RAW_URLOPEN(feedback_request) as response:
                self.assertEqual(json.loads(response.read())["classification"], "suspicious")

            review_request = Request(
                f"{self.base_url}/api/admin/feedback/review",
                data=json.dumps({
                    "report_id": report_id,
                    "decision": "rejected",
                    "note": "Analysts cannot administer rule changes.",
                }).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Cookie": analyst_cookie,
                    "X-CSRF-Token": analyst_auth["csrf_token"],
                },
                method="POST",
            )
            with self.assertRaises(HTTPError) as forbidden:
                _RAW_URLOPEN(review_request)
            self.assertEqual(forbidden.exception.code, 403)
        finally:
            with urlopen(Request(f"{self.base_url}/api/report/{report_id}", method="DELETE")):
                pass
            with urlopen(Request(
                f"{self.base_url}/api/admin/users/{analyst['id']}",
                method="DELETE",
            )):
                pass

    def test_feedback_approval_adjusts_future_analysis_and_resubmission_removes_it(self) -> None:
        email = (
            "Subject: Feedback rule review\n\n"
            "Immediately verify your password and send OTP code; keep confidential."
        )
        request = Request(
            f"{self.base_url}/analyze",
            data=json.dumps({"email": email}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            original = json.loads(response.read())
        report_id = original["report_id"]
        indicator = next(
            finding["indicator"]
            for finding in original["findings"]
            if finding.get("indicator") and finding.get("points", 0) > 0
        )
        try:
            feedback_request = Request(
                f"{self.base_url}/api/report/{report_id}/feedback",
                data=json.dumps({
                    "classification": "confirmed_phishing",
                    "note": "Verified as credential theft.",
                }).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(feedback_request):
                pass

            review_request = Request(
                f"{self.base_url}/api/admin/feedback/review",
                data=json.dumps({
                    "report_id": report_id,
                    "decision": "approved",
                    "indicator": indicator,
                    "points_delta": 5,
                    "note": "Increase this indicator's weight.",
                }).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(review_request) as response:
                self.assertEqual(json.loads(response.read())["decision"], "approved")

            with urlopen(Request(
                f"{self.base_url}/analyze",
                data=json.dumps({"email": email}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )) as response:
                adjusted = json.loads(response.read())
            adjusted_finding = next(
                finding for finding in adjusted["findings"]
                if finding.get("indicator") == indicator
            )
            original_finding = next(
                finding for finding in original["findings"]
                if finding.get("indicator") == indicator
            )
            self.assertEqual(
                adjusted_finding["points"],
                original_finding["points"] + 5,
            )
            self.assertEqual(adjusted_finding["admin_approved_points_adjustment"], 5)

            update_request = Request(
                f"{self.base_url}/api/report/{report_id}/feedback",
                data=json.dumps({
                    "classification": "suspicious",
                    "note": "Review updated after additional evidence.",
                }).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(update_request):
                pass
            with urlopen(f"{self.base_url}/api/admin/feedback") as response:
                review_queue = json.loads(response.read())
            self.assertFalse(any(
                adjustment["indicator"] == indicator
                for adjustment in review_queue["rule_adjustments"]
            ))
            self.assertIsNone(next(
                item for item in review_queue["feedback"]
                if item["report_id"] == report_id
            )["decision"])
            with urlopen(Request(
                f"{self.base_url}/api/report/{adjusted['report_id']}",
                method="DELETE",
            )):
                pass
        finally:
            with urlopen(Request(f"{self.base_url}/api/report/{report_id}", method="DELETE")):
                pass

    def test_virustotal_lookups_require_opt_in_and_are_limited(self) -> None:
        with mock.patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-api-key"}), \
                mock.patch("web_app._virustotal_json") as lookup:
            without_opt_in = Request(
                f"{self.base_url}/analyze",
                data=json.dumps({"email": "Subject: No lookup\n\nhttps://example.com/path"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(without_opt_in) as response:
                unqueried = json.loads(response.read())
            lookup.assert_not_called()

            lookup.side_effect = lambda path, _api_key: (
                200,
                {"data": {"attributes": {
                    "last_analysis_stats": {"malicious": 2, "suspicious": 1},
                    "last_final_url": "https://final.example/path",
                    "redirection_chain": ["https://start.example", "https://final.example"],
                    "categories": {"provider": "phishing"},
                }}},
            )
            email = "Subject: Lookup limit\n\n" + " ".join(
                f"https://example{i}.com/path" for i in range(6)
            )
            with urlopen(Request(
                f"{self.base_url}/analyze",
                data=json.dumps({"email": email, "check_reputation": True}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )) as response:
                checked = json.loads(response.read())

        self.assertNotIn("virustotal", unqueried["urls"][0])
        self.assertEqual(len(lookup.call_args_list), 10)
        self.assertEqual(len(checked["urls"]), 6)
        self.assertEqual(checked["urls"][0]["virustotal"]["detection_count"], 3)
        self.assertEqual(
            checked["urls"][0]["virustotal"]["domain_report"]["status"],
            "found",
        )
        self.assertEqual(checked["urls"][0]["virustotal"]["redirect_chain"][-1], "https://final.example")
        self.assertEqual(checked["urls"][5]["virustotal"]["status"], "skipped")
        self.assertEqual(checked["integration_status"]["threat_intelligence"], "VirusTotal checked by request")
        for report in (unqueried, checked):
            with urlopen(Request(f"{self.base_url}/api/report/{report['report_id']}", method="DELETE")):
                pass

    def test_legacy_feedback_and_incident_schemas_migrate(self) -> None:
        feedback_db = sqlite3.connect(":memory:")
        feedback_db.row_factory = sqlite3.Row
        feedback_db.execute("CREATE TABLE reports (id TEXT PRIMARY KEY)")
        feedback_db.executemany(
            "INSERT INTO reports(id) VALUES (?)",
            (("legacy-positive",), ("legacy-negative",)),
        )
        feedback_db.execute(
            """CREATE TABLE feedback (
                report_id TEXT PRIMARY KEY REFERENCES reports(id) ON DELETE CASCADE,
                classification TEXT NOT NULL CHECK(classification IN ('false_positive', 'false_negative')),
                note TEXT NOT NULL DEFAULT '',
                submitted_at TEXT NOT NULL
            )"""
        )
        feedback_db.executemany(
            "INSERT INTO feedback VALUES (?, ?, ?, ?)",
            (
                ("legacy-positive", "false_negative", "confirmed", "2026-01-01"),
                ("legacy-negative", "false_positive", "benign", "2026-01-02"),
            ),
        )
        _migrate_feedback_schema(feedback_db)
        feedback_rows = {
            row["report_id"]: row["classification"]
            for row in feedback_db.execute("SELECT report_id, classification FROM feedback")
        }
        self.assertEqual(feedback_rows, {
            "legacy-positive": "confirmed_phishing",
            "legacy-negative": "legitimate",
        })
        self.assertIn(
            "submitted_by",
            {row["name"] for row in feedback_db.execute("PRAGMA table_info(feedback)")},
        )
        feedback_db.close()

        incident_db = sqlite3.connect(":memory:")
        incident_db.row_factory = sqlite3.Row
        incident_db.execute("CREATE TABLE reports (id TEXT PRIMARY KEY, level TEXT NOT NULL)")
        incident_db.execute("INSERT INTO reports VALUES ('legacy-report', 'HIGH')")
        incident_db.execute("CREATE TABLE users (id TEXT PRIMARY KEY)")
        incident_db.execute(
            """CREATE TABLE incidents (
                id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL UNIQUE REFERENCES reports(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('open', 'investigating', 'resolved')),
                assigned_to TEXT REFERENCES users(id) ON DELETE SET NULL,
                note TEXT NOT NULL DEFAULT ''
            )"""
        )
        incident_db.execute(
            "INSERT INTO incidents VALUES ('legacy-case', 'legacy-report', 'created', 'updated', 'open', NULL, 'review')"
        )
        _migrate_incident_schema(incident_db)
        migrated_incident = incident_db.execute(
            "SELECT status, severity FROM incidents WHERE id = 'legacy-case'"
        ).fetchone()
        self.assertEqual(migrated_incident["status"], "open")
        self.assertEqual(migrated_incident["severity"], "high")
        self.assertIn(
            "false_positive",
            incident_db.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'incidents'"
            ).fetchone()["sql"],
        )
        incident_db.close()

    def test_whatsapp_zip_review_checks_metadata_without_extracting_or_storing_chat(self) -> None:
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("Read me.txt", "Harmless placeholder.")
            archive.writestr("Documents/invoice.pdf.exe", "not an executable")
            archive.writestr("../outside.ps1", "not a script")
            archive.writestr("nested.zip", "not inspected")
        zip_bytes = archive_buffer.getvalue()
        encoded_zip = base64.b64encode(zip_bytes).decode("ascii")
        inspection, archive_findings = _inspect_whatsapp_zip(encoded_zip, "received.zip")
        self.assertEqual(inspection["entry_count"], 4)
        self.assertEqual(inspection["unsafe_path_count"], 1)
        self.assertEqual(inspection["nested_archive_count"], 1)
        self.assertEqual(
            inspection["sha256"],
            hashlib.sha256(zip_bytes).hexdigest(),
        )
        self.assertEqual(len(archive_findings), 3)
        direct_report = _analyze_whatsapp_message(
            "Please verify your password immediately.",
            inspection,
            archive_findings,
        )
        self.assertEqual(direct_report["channel"], "WhatsApp")
        self.assertEqual(direct_report["zip_inspection"]["filename"], "received.zip")
        self.assertGreaterEqual(direct_report["score"], 55)

        unique_chat_text = "Do not share this exact sample phrase 738291."
        request = Request(
            f"{self.base_url}/api/whatsapp/analyze",
            data=json.dumps({
                "message": f"{unique_chat_text} Verify your password immediately.",
                "zip_filename": "received.zip",
                "zip_base64": encoded_zip,
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            report = json.loads(response.read())

        report_id = report["report_id"]
        try:
            self.assertEqual(report["channel"], "WhatsApp")
            self.assertNotIn("body", report)
            self.assertEqual(report["zip_inspection"]["entry_count"], 4)
            self.assertEqual(report["attachments"][0]["scan_status"].split(";")[0], "ZIP directory metadata only")
            with urlopen(f"{self.base_url}/api/report/{report_id}") as response:
                saved_report = json.loads(response.read())
            self.assertEqual(saved_report["subject"], "WhatsApp scam review")
            self.assertEqual(saved_report["sender"], "WhatsApp conversation")
            self.assertNotIn("body", saved_report)
            pdf = _build_pdf(saved_report)
            self.assertIn(b"WhatsApp scam review", pdf)
            self.assertIn(b"ZIP directory only", pdf)
            self.assertIn(b"Documents/invoice.pdf.exe", pdf)
            with closing(sqlite3.connect(DATABASE_PATH)) as connection:
                stored_json = connection.execute(
                    "SELECT report_json FROM reports WHERE id = ?",
                    (report_id,),
                ).fetchone()[0]
            self.assertNotIn(unique_chat_text, stored_json)
            self.assertNotIn(base64.b64decode(encoded_zip).decode("latin-1"), stored_json)
        finally:
            with urlopen(Request(f"{self.base_url}/api/report/{report_id}", method="DELETE")):
                pass

    def test_screenshot_ocr_extracts_lines_and_reports_confidence(self) -> None:
        image_buffer = io.BytesIO()
        Image.new("RGB", (40, 30), "white").save(image_buffer, format="PNG")
        with mock.patch("pytesseract.image_to_data", return_value={
            "text": ["Verify", "account", "now"],
            "conf": ["90", "80", "70"],
            "block_num": ["1", "1", "1"],
            "par_num": ["1", "1", "1"],
            "line_num": ["1", "1", "1"],
        }):
            result = _ocr_screenshot(image_buffer.getvalue())
        self.assertEqual(result["text"], "Verify account now")
        self.assertEqual(result["format"], "PNG")
        self.assertEqual((result["width"], result["height"]), (40, 30))
        self.assertEqual(result["word_count"], 3)
        self.assertEqual(result["confidence"], 80.0)

        direct_report = _analyze_screenshot_text("Visible message text.", r"C:\private\chat.png")
        self.assertEqual(direct_report["channel"], "Screenshot OCR")
        self.assertEqual(direct_report["screenshot_review"]["filename"], "chat.png")

        with self.assertRaisesRegex(ValueError, "not a supported image"):
            _ocr_screenshot(b"not an image")

        class OversizedImage:
            format = "PNG"
            size = (4097, 4000)
            is_animated = False

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

        with mock.patch("PIL.Image.open", return_value=OversizedImage()):
            with self.assertRaisesRegex(ValueError, "16 megapixels"):
                _ocr_screenshot(b"encoded image placeholder")
        with self.assertRaisesRegex(ValueError, "5 MB"):
            _ocr_screenshot(b"x" * (5 * 1024 * 1024 + 1))

    def test_screenshot_review_is_local_and_saved_report_excludes_image_and_full_text(self) -> None:
        image_bytes = b"not retained screenshot bytes"
        ocr_text = "This is a harmless screenshot reference 482731."
        ocr_result = {
            "text": ocr_text,
            "filename": "",
            "format": "PNG",
            "width": 400,
            "height": 300,
            "word_count": 8,
            "confidence": 91.2,
        }
        ocr_request = Request(
            f"{self.base_url}/api/screenshot/ocr",
            data=json.dumps({
                "filename": r"C:\private\chat.png",
                "image_base64": base64.b64encode(image_bytes).decode("ascii"),
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with mock.patch("web_app._ocr_screenshot", return_value=dict(ocr_result)) as ocr:
            with urlopen(ocr_request) as response:
                extracted = json.loads(response.read())
        ocr.assert_called_once_with(image_bytes)
        self.assertEqual(extracted["filename"], "chat.png")
        self.assertEqual(extracted["text"], ocr_text)

        with self.assertRaises(HTTPError) as invalid_image:
            invalid_request = Request(
                f"{self.base_url}/api/screenshot/ocr",
                data=json.dumps({"filename": "bad.png", "image_base64": "!not-base64!"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urlopen(invalid_request)
        self.assertEqual(invalid_image.exception.code, 400)

        report_request = Request(
            f"{self.base_url}/api/screenshot/analyze",
            data=json.dumps({"filename": extracted["filename"], "text": extracted["text"]}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(report_request) as response:
            report = json.loads(response.read())
        report_id = report["report_id"]
        try:
            self.assertEqual(report["channel"], "Screenshot OCR")
            self.assertNotIn("body", report)
            self.assertEqual(report["screenshot_review"]["filename"], "chat.png")
            with urlopen(f"{self.base_url}/api/report/{report_id}") as response:
                saved_report = json.loads(response.read())
            self.assertNotIn("body", saved_report)
            self.assertEqual(
                saved_report["screenshot_review"]["processing"],
                "OCR performed locally; screenshot image not retained",
            )
            with closing(sqlite3.connect(DATABASE_PATH)) as connection:
                stored_json = connection.execute(
                    "SELECT report_json FROM reports WHERE id = ?",
                    (report_id,),
                ).fetchone()[0]
            self.assertNotIn(ocr_text, stored_json)
            self.assertNotIn(base64.b64encode(image_bytes).decode("ascii"), stored_json)
            self.assertNotIn(image_bytes.decode("ascii"), stored_json)
        finally:
            with urlopen(Request(f"{self.base_url}/api/report/{report_id}", method="DELETE")):
                pass

    def test_whatsapp_zip_review_rejects_invalid_archive_and_empty_message(self) -> None:
        invalid_archive = Request(
            f"{self.base_url}/api/whatsapp/analyze",
            data=json.dumps({
                "message": "Suspicious file attached.",
                "zip_filename": "bad.zip",
                "zip_base64": base64.b64encode(b"not a zip").decode("ascii"),
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as invalid:
            urlopen(invalid_archive)
        self.assertEqual(invalid.exception.code, 400)

        empty_message = Request(
            f"{self.base_url}/api/whatsapp/analyze",
            data=json.dumps({"message": "  "}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as empty:
            urlopen(empty_message)
        self.assertEqual(empty.exception.code, 400)

        chat_only = Request(
            f"{self.base_url}/api/whatsapp/analyze",
            data=json.dumps({"message": "A message with no ZIP selected."}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(chat_only) as response:
            report = json.loads(response.read())
        self.assertIsNone(report["zip_inspection"])
        with urlopen(Request(f"{self.base_url}/api/report/{report['report_id']}", method="DELETE")):
            pass

    def test_whatsapp_zip_review_rejects_archives_over_entry_limit(self) -> None:
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w") as archive:
            for index in range(1001):
                archive.writestr(f"entry-{index}.txt", "x")
        request = Request(
            f"{self.base_url}/api/whatsapp/analyze",
            data=json.dumps({
                "message": "Please review this download.",
                "zip_filename": "too-many.zip",
                "zip_base64": base64.b64encode(archive_buffer.getvalue()).decode("ascii"),
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as raised:
            urlopen(request)
        self.assertEqual(raised.exception.code, 400)

    def test_pdf_download_returns_valid_pdf_structure(self) -> None:
        request = Request(
            f"{self.base_url}/analyze",
            data=json.dumps({
                "email": (
                    "From: finance@example.net\nSubject: Payroll verification\n\n"
                    "Urgent: immediately verify your password. Keep this confidential. "
                    "Send the OTP code now at https://micros0ft.com.example.net/login."
                ),
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            report_id = json.loads(response.read())["report_id"]
        with urlopen(f"{self.base_url}/api/report/{report_id}/pdf") as response:
            pdf = response.read()
            self.assertEqual(response.headers.get_content_type(), "application/pdf")
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertIn(b"xref", pdf)
        self.assertIn(b"%%EOF", pdf)
        for section in (
            b"Phishing risk analysis",
            b"OVERALL ASSESSMENT",
            b"SCORING AND EVIDENCE RELIABILITY",
            b"MESSAGE DETAILS",
            b"DETECTION FINDINGS AND EVIDENCE",
            b"Recommended response:",
            b"EMAIL AUTHENTICATION",
            b"URLS AND DESTINATIONS",
            b"ATTACHMENT DETAILS",
            b"SCOPE AND RECOMMENDED NEXT STEPS",
            b"Page 1 of",
            b"Page 2 of",
        ):
            self.assertIn(section, pdf)
        self.assertIn(b"Payroll verification", pdf)
        self.assertIn(b"finance@example.net", pdf)
        self.assertIn(b"micros0ft.com.example.net", pdf)
        delete = Request(f"{self.base_url}/api/report/{report_id}", method="DELETE")
        with urlopen(delete):
            pass

    def test_whatsapp_report_can_be_downloaded_as_pdf(self) -> None:
        request = Request(
            f"{self.base_url}/api/whatsapp/analyze",
            data=json.dumps({"message": "Please review this download."}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            report_id = json.loads(response.read())["report_id"]
        with urlopen(f"{self.base_url}/api/report/{report_id}/pdf") as response:
            pdf = response.read()
            self.assertEqual(response.headers.get_content_type(), "application/pdf")
            self.assertIn("attachment", response.headers.get("Content-Disposition", ""))
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertIn(b"WhatsApp scam review", pdf)
        self.assertIn(report_id.encode(), pdf)
        delete = Request(f"{self.base_url}/api/report/{report_id}", method="DELETE")
        with urlopen(delete):
            pass

    def test_pdf_keeps_spanish_accents_and_finding_quality(self) -> None:
        message = EmailMessage()
        message["From"] = "Soporte técnico <help@company.example>"
        message.set_content("Verifique su contraseña inmediatamente.")
        report = analyze_message(message.as_string())
        pdf = _build_pdf({
            **report,
            "id": "language-report",
            "analyzed_at": "2026-10-12T12:00:00+00:00",
        })
        self.assertIn("contraseña".encode("cp1252"), pdf)
        self.assertIn(b"EVIDENCE HIGH", pdf)
        self.assertIn(b"Matched language rule: ES", pdf)

    def test_retention_removes_expired_reports_and_linked_incidents(self) -> None:
        old_request = Request(
            f"{self.base_url}/analyze",
            data=json.dumps({"email": "Subject: Expired test report\n\nOld report."}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(old_request) as response:
            old_report_id = json.loads(response.read())["report_id"]
        incident_request = Request(
            f"{self.base_url}/api/incidents",
            data=json.dumps({"report_id": old_report_id}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(incident_request):
            pass
        with closing(sqlite3.connect(DATABASE_PATH)) as connection:
            connection.execute(
                "UPDATE reports SET analyzed_at = ? WHERE id = ?",
                ("2000-01-01T00:00:00+00:00", old_report_id),
            )
            connection.commit()
        settings = Request(
            f"{self.base_url}/api/admin/settings",
            data=json.dumps({"alert_threshold": 55, "retention_days": 1}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(settings):
            pass
        new_request = Request(
            f"{self.base_url}/analyze",
            data=json.dumps({"email": "Subject: Retention trigger\n\nCurrent report."}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(new_request) as response:
            new_report_id = json.loads(response.read())["report_id"]
        try:
            with self.assertRaises(HTTPError) as expired:
                urlopen(f"{self.base_url}/api/report/{old_report_id}")
            self.assertEqual(expired.exception.code, 404)
            with urlopen(f"{self.base_url}/api/incidents") as response:
                incidents = json.loads(response.read())["incidents"]
            self.assertNotIn(old_report_id, {incident["report_id"] for incident in incidents})
            with urlopen(f"{self.base_url}/api/admin/audit") as response:
                events = json.loads(response.read())["events"]
            self.assertIn("retention.applied", {entry["action"] for entry in events})
        finally:
            reset_settings = Request(
                f"{self.base_url}/api/admin/settings",
                data=json.dumps({"alert_threshold": 55, "retention_days": 0}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(reset_settings):
                pass
            delete = Request(f"{self.base_url}/api/report/{new_report_id}", method="DELETE")
            with urlopen(delete):
                pass

    def test_empty_email_returns_validation_error(self) -> None:
        request = Request(
            f"{self.base_url}/analyze",
            data=json.dumps({"email": "  "}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as raised:
            urlopen(request)
        self.assertEqual(raised.exception.code, 400)
        self.assertIn("empty", json.loads(raised.exception.read())["error"])

    def test_oversized_request_is_rejected(self) -> None:
        request = Request(
            f"{self.base_url}/analyze",
            data=json.dumps({"email": "x" * (MAX_EMAIL_BYTES + 1)}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as raised:
            urlopen(request)
        self.assertEqual(raised.exception.code, 413)

    def test_csv_cells_with_formula_prefixes_are_escaped(self) -> None:
        self.assertEqual(_spreadsheet_safe("=HYPERLINK(\"https://bad.example\")"), "'=HYPERLINK(\"https://bad.example\")")
        self.assertEqual(_spreadsheet_safe("normal subject"), "normal subject")


if __name__ == "__main__":
    unittest.main()
