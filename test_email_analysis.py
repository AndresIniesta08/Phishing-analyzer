import hashlib
import unittest
from email.message import EmailMessage

from email_analysis import analyze_message


def example_email() -> str:
    message = EmailMessage()
    message["From"] = "Microsoft Help <support@micros0ft.com>"
    message["To"] = "User <user@example.net>"
    message["Reply-To"] = "help@reply.example"
    message["Return-Path"] = "<bounce@example.net>"
    message["Subject"] = "Urgent action required"
    message["Authentication-Results"] = (
        "mx.example; spf=fail smtp.mailfrom=micros0ft.com; "
        "dkim=pass; dmarc=fail"
    )
    message.set_content(
        "Act now. Verify your password immediately at https://bit.ly/login."
    )
    message.add_alternative(
        '<p>Act now. <a href="https://evil.example/login">microsoft.com</a></p>',
        subtype="html",
    )
    message.add_attachment(
        b"harmless test bytes",
        maintype="application",
        subtype="octet-stream",
        filename="invoice.pdf.exe",
    )
    return message.as_string()


class AnalyzeMessageTests(unittest.TestCase):
    def test_manual_header_overrides_are_used_for_analysis(self) -> None:
        result = analyze_message(
            "From: original@example.net\n"
            "To: old-recipient@example.net\n"
            "Reply-To: old-reply@example.net\n"
            "Subject: Original subject\n\n"
            "A routine local test.",
            header_overrides={
                "From": "Microsoft Support <help@attacker.example>",
                "To": "Analyst <analyst@example.org>",
                "Reply-To": "reply@different.example",
                "Subject": "Entered subject",
            },
        )
        self.assertEqual(result["sender"][0]["name"], "Microsoft Support")
        self.assertEqual(result["sender"][0]["address"], "help@attacker.example")
        self.assertEqual(result["recipients"][0]["address"], "analyst@example.org")
        self.assertEqual(result["reply_to"][0]["address"], "reply@different.example")
        self.assertEqual(result["subject"], "Entered subject")
        self.assertTrue(any(
            finding.get("indicator") == "Trusted-brand display-name mismatch"
            for finding in result["findings"]
        ))

    def test_blank_header_overrides_keep_parsed_values(self) -> None:
        result = analyze_message(
            "From: original@example.net\nTo: recipient@example.net\n"
            "Reply-To: reply@example.net\nSubject: Original\n\nBody.",
            header_overrides={"From": "", "To": " ", "Reply-To": "", "Subject": ""},
        )
        self.assertEqual(result["sender"][0]["address"], "original@example.net")
        self.assertEqual(result["recipients"][0]["address"], "recipient@example.net")
        self.assertEqual(result["reply_to"][0]["address"], "reply@example.net")
        self.assertEqual(result["subject"], "Original")

    def test_header_overrides_reject_line_breaks_types_and_unknown_names(self) -> None:
        for overrides in (
            {"From": "attacker@example.net\r\nBcc: victim@example.net"},
            {"To": 123},
            {"X-Injected": "value"},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                analyze_message("Body.", header_overrides=overrides)

    def test_extracts_headers_urls_authentication_and_attachment_hash(self) -> None:
        result = analyze_message(example_email())
        self.assertEqual(result["subject"], "Urgent action required")
        self.assertEqual(result["sender"][0]["address"], "support@micros0ft.com")
        self.assertEqual(result["recipients"][0]["address"], "user@example.net")
        self.assertEqual(result["reply_to"][0]["address"], "help@reply.example")
        self.assertEqual(result["return_path"], "<bounce@example.net>")
        self.assertEqual(result["url_count"], 2)

        attachment = result["attachments"][0]
        self.assertEqual(attachment["filename"], "invoice.pdf.exe")
        self.assertTrue(attachment["suspicious"])
        self.assertEqual(attachment["sha256"], hashlib.sha256(b"harmless test bytes").hexdigest())
        self.assertIn("not scanned", attachment["scan_status"])

    def test_reports_evidence_and_separate_categories(self) -> None:
        result = analyze_message(example_email())
        self.assertEqual(result["level"], "HIGH")
        categories = {finding["category"] for finding in result["findings"]}
        self.assertTrue({"sender", "content", "urls", "attachments"}.issubset(categories))
        self.assertTrue(all(finding["evidence"] for finding in result["findings"]))

    def test_authentication_values_are_reported_but_not_independently_trusted(self) -> None:
        result = analyze_message(example_email())
        statuses = {check["name"]: check["status"] for check in result["authentication"]}
        self.assertEqual(statuses, {"SPF": "fail", "DKIM": "pass", "DMARC": "fail"})
        self.assertIn("not independently verified", result["authentication"][0]["source"])

    def test_detects_bec_secrecy_otp_request_and_lookalike_url(self) -> None:
        message = EmailMessage()
        message["From"] = "Executive <boss@example.net>"
        message["Subject"] = "Quick confidential request"
        message.set_content(
            "Keep this confidential. Please send me the OTP code using "
            "https://microsoft.com.evil.net/login."
        )
        result = analyze_message(message.as_string())
        reasons = [finding["reason"] for finding in result["findings"]]
        self.assertTrue(any("asks for secrecy" in reason for reason in reasons))
        self.assertTrue(any("one-time passcode" in reason for reason in reasons))
        self.assertTrue(any("embeds the known brand" in reason for reason in reasons))

    def test_known_brand_subdomain_is_not_flagged_as_a_lookalike(self) -> None:
        result = analyze_message(
            "From: Service <alerts@login.microsoft.com>\n\nYour scheduled report is ready."
        )
        self.assertFalse(any("brand domain" in finding["reason"] for finding in result["findings"]))

    def test_detects_sensitive_data_and_remote_access_requests_with_evidence(self) -> None:
        result = analyze_message(
            "Subject: IT support\n\n"
            "Please email your social security number to verify your profile. "
            "Download and install AnyDesk for remote support."
        )
        findings = {finding["reason"]: finding for finding in result["findings"]}
        sensitive = findings["Requests confidential or sensitive financial information."]
        remote = findings["Requests installation or use of remote-access software."]
        self.assertIn("social security number", sensitive["evidence"].lower())
        self.assertIn("anydesk", remote["evidence"].lower())

    def test_language_rules_match_spanish_french_and_german_phrases(self) -> None:
        samples = {
            "es": "Verifique su contraseña inmediatamente. Mantenga esto confidencial.",
            "fr": "Vérifiez votre mot de passe immédiatement. Gardez ceci confidentiel.",
            "de": "Bestätigen Sie Ihr Passwort sofort. Halten Sie dies vertraulich.",
        }
        for language, body in samples.items():
            with self.subTest(language=language):
                result = analyze_message(f"Subject: Account notice\n\n{body}")
                self.assertIn(language, result["language_analysis"]["matched_languages"])
                matching = [
                    finding for finding in result["findings"]
                    if finding.get("language") == language
                ]
                self.assertTrue(matching)
                self.assertTrue(all(finding["evidence_reliability"]["level"] == "high" for finding in matching))
                self.assertIn("not a calibrated probability", result["scoring"]["method"])

    def test_display_name_brand_mismatch_and_role_context_are_explained(self) -> None:
        brand = analyze_message(
            "From: Microsoft Support <help@attacker.example>\n\n"
            "Your regular monthly summary is available."
        )
        brand_findings = [
            finding for finding in brand["findings"]
            if finding.get("indicator") == "Trusted-brand display-name mismatch"
        ]
        self.assertEqual(len(brand_findings), 1)
        self.assertIn("Microsoft Support", brand_findings[0]["evidence"])
        self.assertIn("attacker.example", brand_findings[0]["evidence"])

        executive = analyze_message(
            "From: CFO <cfo@example.net>\n\nPlease make a wire transfer today."
        )
        self.assertTrue(any(
            finding.get("indicator") == "Executive-themed payment request"
            for finding in executive["findings"]
        ))

        message = EmailMessage()
        message["From"] = "Soporte técnico <help@company.example>"
        message.set_content("Verifique su contraseña para continuar.")
        support = analyze_message(message.as_string())
        self.assertTrue(any(
            finding.get("indicator") == "IT-support and credential/access request"
            for finding in support["findings"]
        ))
        self.assertIn("not a probability", support["confidence_note"])

    def test_empty_input_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            analyze_message(" \n")


if __name__ == "__main__":
    unittest.main()
