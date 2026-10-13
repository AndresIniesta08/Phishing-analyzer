"""Explainable, offline phishing-risk checks for pasted or saved email messages."""

from __future__ import annotations

import re
import tkinter as tk
from dataclasses import dataclass
from email import message_from_string
from email.message import Message
from email.policy import default
from html.parser import HTMLParser
from tkinter import filedialog, messagebox
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


class PhishingAnalyzerApp:
    BACKGROUND = "#eef1ed"
    INK = "#183a34"
    MUTED = "#64736d"
    WHITE = "#ffffff"

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("Email Phishing Risk Analyzer")
        root.geometry("900x760")
        root.minsize(700, 620)
        root.configure(bg=self.BACKGROUND)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        header = tk.Frame(root, bg=self.INK, padx=28, pady=20)
        header.grid(row=0, column=0, sticky="ew")
        tk.Label(
            header,
            text="EMAIL SECURITY / MESSAGE REVIEW",
            bg=self.INK,
            fg="#a8d5bb",
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w")
        tk.Label(
            header,
            text="Phishing risk analyzer",
            bg=self.INK,
            fg=self.WHITE,
            font=("Segoe UI", 22, "bold"),
        ).pack(anchor="w", pady=(5, 0))

        main = tk.Frame(root, bg=self.BACKGROUND, padx=28, pady=20)
        main.grid(row=1, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(1, weight=3)
        main.rowconfigure(4, weight=2)

        input_heading = tk.Frame(main, bg=self.BACKGROUND)
        input_heading.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        input_heading.columnconfigure(0, weight=1)
        tk.Label(
            input_heading,
            text="EMAIL MESSAGE",
            bg=self.BACKGROUND,
            fg=self.INK,
            font=("Segoe UI", 10, "bold"),
        ).grid(row=0, column=0, sticky="w")
        tk.Button(
            input_heading,
            text="Open email file",
            command=self.open_file,
            font=("Segoe UI", 9),
            bg=self.WHITE,
            fg=self.INK,
            relief="solid",
            bd=1,
            padx=12,
            pady=6,
            cursor="hand2",
        ).grid(row=0, column=1, sticky="e")

        input_panel = tk.Frame(main, bg=self.WHITE, highlightthickness=1, highlightbackground="#d6ded8")
        input_panel.grid(row=1, column=0, sticky="nsew")
        input_panel.rowconfigure(0, weight=1)
        input_panel.columnconfigure(0, weight=1)
        self.email_input = tk.Text(
            input_panel,
            wrap="word",
            undo=True,
            font=("Consolas", 10),
            bg=self.WHITE,
            fg="#25352f",
            insertbackground=self.INK,
            relief="flat",
            padx=14,
            pady=12,
        )
        self.email_input.grid(row=0, column=0, sticky="nsew")
        input_scroll = tk.Scrollbar(input_panel, command=self.email_input.yview)
        input_scroll.grid(row=0, column=1, sticky="ns")
        self.email_input.configure(yscrollcommand=input_scroll.set)
        self.email_input.insert("1.0", "Paste the full email message here, including headers when available.")

        actions = tk.Frame(main, bg=self.BACKGROUND)
        actions.grid(row=2, column=0, sticky="ew", pady=12)
        tk.Button(
            actions,
            text="Analyze message",
            command=self.analyze,
            font=("Segoe UI", 10, "bold"),
            bg="#16745b",
            fg=self.WHITE,
            activebackground="#125e4a",
            activeforeground=self.WHITE,
            relief="flat",
            padx=18,
            pady=10,
            cursor="hand2",
        ).pack(side="left")
        tk.Button(
            actions,
            text="Clear",
            command=self.clear,
            font=("Segoe UI", 9),
            bg=self.BACKGROUND,
            fg=self.MUTED,
            relief="flat",
            padx=14,
            pady=10,
            cursor="hand2",
        ).pack(side="left", padx=(6, 0))
        tk.Label(
            actions,
            text="Offline check · links are never opened",
            bg=self.BACKGROUND,
            fg=self.MUTED,
            font=("Segoe UI", 9),
        ).pack(side="right", pady=10)

        tk.Label(
            main,
            text="ASSESSMENT",
            bg=self.BACKGROUND,
            fg=self.INK,
            font=("Segoe UI", 10, "bold"),
        ).grid(row=3, column=0, sticky="w", pady=(4, 8))

        result_panel = tk.Frame(main, bg=self.WHITE, highlightthickness=1, highlightbackground="#d6ded8")
        result_panel.grid(row=4, column=0, sticky="nsew")
        result_panel.columnconfigure(0, weight=1)
        result_panel.rowconfigure(1, weight=1)

        self.risk_banner = tk.Frame(result_panel, bg="#edf2ee", padx=16, pady=12)
        self.risk_banner.grid(row=0, column=0, sticky="ew")
        self.risk_banner.columnconfigure(0, weight=1)
        self.risk_label = tk.Label(
            self.risk_banner,
            text="READY TO ANALYZE",
            bg="#edf2ee",
            fg=self.INK,
            font=("Segoe UI", 13, "bold"),
        )
        self.risk_label.grid(row=0, column=0, sticky="w")
        self.score_label = tk.Label(
            self.risk_banner,
            text="-- / 100",
            bg="#edf2ee",
            fg=self.INK,
            font=("Segoe UI", 11, "bold"),
        )
        self.score_label.grid(row=0, column=1, sticky="e")

        self.findings = tk.Text(
            result_panel,
            height=7,
            wrap="word",
            state="disabled",
            font=("Segoe UI", 10),
            bg=self.WHITE,
            fg="#25352f",
            relief="flat",
            padx=16,
            pady=12,
        )
        self.findings.grid(row=1, column=0, sticky="nsew")
        result_scroll = tk.Scrollbar(result_panel, command=self.findings.yview)
        result_scroll.grid(row=1, column=1, sticky="ns")
        self.findings.configure(yscrollcommand=result_scroll.set)
        self._set_findings("Your results and the reasons behind them will appear here.")

        tk.Label(
            main,
            text="Heuristic results are not a guarantee. Verify unexpected requests through a trusted channel.",
            bg=self.BACKGROUND,
            fg=self.MUTED,
            font=("Segoe UI", 9),
        ).grid(row=5, column=0, sticky="w", pady=(10, 0))

    def _set_findings(self, text: str) -> None:
        self.findings.configure(state="normal")
        self.findings.delete("1.0", "end")
        self.findings.insert("1.0", text)
        self.findings.configure(state="disabled")

    def open_file(self) -> None:
        filename = filedialog.askopenfilename(
            title="Open an email message",
            filetypes=(("Email and text files", "*.eml *.txt"), ("All files", "*.*")),
        )
        if not filename:
            return
        try:
            with open(filename, encoding="utf-8", errors="replace") as email_file:
                content = email_file.read()
        except OSError as exc:
            messagebox.showerror("Could not open file", str(exc), parent=self.root)
            return
        self.email_input.delete("1.0", "end")
        self.email_input.insert("1.0", content)

    def analyze(self) -> None:
        try:
            result = analyze_email(self.email_input.get("1.0", "end-1c"))
        except ValueError as exc:
            messagebox.showwarning("Email needed", str(exc), parent=self.root)
            return

        palette = {
            "LOW": ("#e5f3ea", "#176642"),
            "SUSPICIOUS": ("#fff1d6", "#8a5b00"),
            "HIGH": ("#fbe7e4", "#a32f24"),
        }
        background, foreground = palette[str(result["level"])]
        self.risk_banner.configure(bg=background)
        self.risk_label.configure(
            text=f"{result['level']} RISK  |  {result['subject']}",
            bg=background,
            fg=foreground,
        )
        self.score_label.configure(
            text=f"{result['score']} / 100  |  {result['url_count']} URL(s)",
            bg=background,
            fg=foreground,
        )
        findings_text = "\n\n".join(
            f"-  {finding.reason}" + (f"  (+{finding.points})" if finding.points else "")
            for finding in result["findings"]
        )
        self._set_findings(findings_text)

    def clear(self) -> None:
        self.email_input.delete("1.0", "end")
        self.risk_banner.configure(bg="#edf2ee")
        self.risk_label.configure(text="READY TO ANALYZE", bg="#edf2ee", fg=self.INK)
        self.score_label.configure(text="-- / 100", bg="#edf2ee", fg=self.INK)
        self._set_findings("Your results and the reasons behind them will appear here.")


def main() -> None:
    root = tk.Tk()
    PhishingAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
