import unittest

from phishing_analyzer import analyze_email


class AnalyzeEmailTests(unittest.TestCase):
    def test_ordinary_message_is_low_risk(self) -> None:
        result = analyze_email(
            "From: coworker@example.com\nSubject: Meeting notes\n\n"
            "Here are the notes from our meeting. See you tomorrow."
        )
        self.assertEqual(result["level"], "LOW")
        self.assertEqual(result["score"], 0)

    def test_shortened_http_link_is_flagged(self) -> None:
        result = analyze_email(
            "Subject: Project update\n\nPlease see http://bit.ly/example for details."
        )
        self.assertEqual(result["score"], 19)
        self.assertTrue(any("shortening service" in f.reason for f in result["findings"]))
        self.assertTrue(any("does not use encrypted HTTPS" in f.reason for f in result["findings"]))

    def test_urgent_credential_request_is_suspicious_risk(self) -> None:
        result = analyze_email(
            "Subject: Urgent action\n\n"
            "Your account will be locked. Verify your password immediately at https://login.example.test."
        )
        self.assertEqual(result["level"], "SUSPICIOUS")
        self.assertEqual(result["score"], 42)
        self.assertTrue(any("password" in f.reason.lower() for f in result["findings"]))

    def test_reply_to_domain_mismatch_is_flagged(self) -> None:
        result = analyze_email(
            "From: Payroll <payroll@company.example>\n"
            "Reply-To: payroll@external.example\nSubject: Payslip\n\nAttached is your payslip."
        )
        self.assertTrue(any("Reply-To" in f.reason for f in result["findings"]))

    def test_empty_input_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            analyze_email("  \n")


if __name__ == "__main__":
    unittest.main()
