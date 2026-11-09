"""Explainable, offline phishing-risk checks for pasted or saved email messages."""

from __future__ import annotations

import re
from dataclasses import dataclass
from email import message_from_string
from email.message import Message
from email.policy import default
from html.parser import HTMLParser
from urllib.parse import urlparse


@dataclass(frozen=True)
class Finding:
    points: int
    reason: str


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href is not None:
            self.links.append((self._href, " ".join(self._text).strip()))
            self._href = None
            self._text = []


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _message_content(message: Message) -> tuple[str, list[str]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    if message.is_multipart():
        parts = message.walk()
    else:
        parts = [message]

    for part in parts:
        if part.get_content_maintype() == "multipart":
            continue
        content_type = part.get_content_type()
        if content_type == "text/plain":
            text_parts.append(_decode_part(part))
        elif content_type == "text/html":
            html_parts.append(_decode_part(part))

    return "\n".join(text_parts + html_parts), html_parts


def _hostname(value: str) -> str | None:
    candidate = value.strip().strip("<>.,;()[]{}\"'")
    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate
    parsed = urlparse(candidate)
    host = parsed.hostname
    return host.lower().rstrip(".") if host else None


def _extract_urls(text: str) -> list[str]:
    return re.findall(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+", text)


def analyze_email(raw_email: str) -> dict[str, object]:
    """Return a heuristic risk assessment without making network requests."""
    if not raw_email.strip():
        raise ValueError("Email content is empty. Paste a message or provide a non-empty file.")

    message = message_from_string(raw_email, policy=default)
    body, html_parts = _message_content(message)
    searchable_text = f"{message.get('Subject', '')}\n{body}".lower()
    findings: list[Finding] = []

    urgency_patterns = (
        r"\bact now\b", r"\bimmediately\b", r"\bwithin 24 hours\b",
        r"\brespond within \d+ hours?\b", r"\bverify (?:now|immediately)\b",
        r"\baccount (?:will be|has been) (?:locked|suspended|closed)\b",
        r"\burgent action\b", r"\baction required\b", r"\bfinal warning\b",
    )
    urgency_hits = sum(bool(re.search(pattern, searchable_text)) for pattern in urgency_patterns)
    if urgency_hits:
        findings.append(Finding(min(urgency_hits * 10, 20), "Uses urgent or threatening language to pressure a quick response."))

    credential_patterns = (
        r"\benter your password\b", r"\bverify your password\b",
        r"\bconfirm your login\b", r"\breset your password\b",
        r"\bverify your account\b", r"\b(?:send|share|provide)\s+(?:me\s+)?your password\b",
    )
    if any(re.search(pattern, searchable_text) for pattern in credential_patterns):
        findings.append(Finding(22, "Requests account, password, or login verification."))

    payment_patterns = (
        r"\bwire transfer\b", r"\bgift cards?\b", r"\bpayment is overdue\b",
        r"\bupdate (?:your )?billing\b", r"\bchange of bank details\b",
        r"\b(?:new|updated|changed) bank account\b",
        r"\bchange (?:the|your) bank (?:account|details)\b",
    )
    if any(re.search(pattern, searchable_text) for pattern in payment_patterns):
        findings.append(Finding(18, "Requests money, payment details, or an unusual payment action."))

    sensitive_patterns = (
        r"\b(?:send|share|provide|email)\b.{0,60}\b(?:social security number|tax identification number|credit card number|bank account number|confidential information)\b",
        r"\b(?:social security number|tax identification number|credit card number|bank account number|confidential information)\b.{0,60}\b(?:send|share|provide|email)\b",
    )
    if any(re.search(pattern, searchable_text) for pattern in sensitive_patterns):
        findings.append(Finding(22, "Requests confidential or sensitive financial information."))

    remote_access_patterns = (
        r"\b(?:download|install)\b.{0,50}\b(?:remote access|remote support|anydesk|teamviewer)\b",
        r"\b(?:anydesk|teamviewer)\b.{0,50}\b(?:download|install|connect)\b",
    )
    if any(re.search(pattern, searchable_text) for pattern in remote_access_patterns):
        findings.append(Finding(24, "Requests installation or use of remote-access software."))

    sender = message.get("From")
    reply_to = message.get("Reply-To")
    sender_addresses = re.findall(r"[\w.+-]+@([\w.-]+)", str(sender or "").lower())
    reply_addresses = re.findall(r"[\w.+-]+@([\w.-]+)", str(reply_to or "").lower())
    if sender_addresses and reply_addresses and sender_addresses[0].rstrip(".") != reply_addresses[0].rstrip("."):
        findings.append(Finding(24, "Reply-To uses a different domain from the sender address."))

    urls = _extract_urls(body)
    for html in html_parts:
        parser = _LinkParser()
        parser.feed(html)
        for href, label in parser.links:
            if href.lower().startswith(("http://", "https://", "www.")):
                urls.append(href)
                label_host = _hostname(label) if label else None
                target_host = _hostname(href)
                if label_host and target_host and label_host != target_host:
                    findings.append(Finding(25, f"A link displays {label_host} but points to {target_host}."))

    unique_urls = list(dict.fromkeys(urls))
    for url in unique_urls:
        host = _hostname(url)
        if not host:
            continue
        if host.startswith("xn--") or ".xn--" in host:
            findings.append(Finding(18, f"Link uses an internationalized/punycode domain: {host}."))
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            findings.append(Finding(18, f"Link uses a raw IP address instead of a domain: {host}."))
        if host in {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}:
            findings.append(Finding(14, f"Link uses a URL-shortening service ({host}), which hides its destination."))
        if url.lower().startswith("http://"):
            findings.append(Finding(5, f"Link to {host} does not use encrypted HTTPS."))

    score = min(sum(finding.points for finding in findings), 100)
    level = "LOW" if score < 25 else "SUSPICIOUS" if score < 55 else "HIGH"
    if not findings:
        findings.append(Finding(0, "No common phishing indicators were detected by these checks."))

    return {"score": score, "level": level, "findings": findings, "subject": str(message.get("Subject", "(no subject)")), "url_count": len(unique_urls)}


def main() -> None:
    """Launch the optional desktop app without adding GUI imports to the backend."""
    from desktop_app import main as desktop_main

    desktop_main()


if __name__ == "__main__":
    main()
