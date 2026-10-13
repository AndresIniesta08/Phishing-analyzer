"""Structured local analysis of RFC email messages and attached file metadata."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from difflib import SequenceMatcher
from email.header import decode_header
from email import message_from_string
from email.message import Message
from email.policy import default
from email.utils import getaddresses
from html.parser import HTMLParser
from urllib.parse import urlparse

from phishing_analyzer import Finding, analyze_email


MAX_ATTACHMENT_HASH_BYTES = 10 * 1024 * 1024
DANGEROUS_EXTENSIONS = {
    ".ade", ".adp", ".app", ".bat", ".chm", ".cmd", ".com", ".cpl", ".dll",
    ".exe", ".hta", ".ins", ".isp", ".jar", ".js", ".jse", ".lnk", ".msi",
    ".msp", ".mst", ".pif", ".ps1", ".reg", ".scr", ".sct", ".shb", ".sys",
    ".vb", ".vbe", ".vbs", ".wsf", ".wsh",
}
MACRO_EXTENSIONS = {".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm", ".ppam"}
KNOWN_BRAND_DOMAINS = (
    "amazon.com", "apple.com", "bankofamerica.com", "chase.com", "docusign.com",
    "dropbox.com", "google.com", "microsoft.com", "office.com", "outlook.com",
    "paypal.com",
)
BRAND_DISPLAY_NAMES = {
    "amazon": ("amazon.com",),
    "apple": ("apple.com",),
    "bank of america": ("bankofamerica.com",),
    "chase": ("chase.com",),
    "docusign": ("docusign.com",),
    "dropbox": ("dropbox.com",),
    "google": ("google.com",),
    "microsoft": ("microsoft.com", "office.com", "outlook.com"),
    "paypal": ("paypal.com",),
}
LANGUAGE_PATTERNS = {
    "es": {
        "urgency": (
            "actúe ahora", "actua ahora", "acción urgente requerida", "accion urgente requerida",
            "inmediatamente", "último aviso", "ultimo aviso", "su cuenta será suspendida",
            "su cuenta ha sido suspendida", "responda en 24 horas",
        ),
        "credential": (
            "verifique su contraseña", "verifique su contrasena", "confirme su contraseña",
            "confirme su contrasena", "introduzca su contraseña", "introduzca su contrasena",
            "envíe su contraseña", "envie su contrasena", "comparta su contraseña",
            "comparta su contrasena",
        ),
        "otp": (
            "envíe el código de verificación", "envie el codigo de verificacion",
            "comparta el código de verificación", "comparta el codigo de verificacion",
            "código otp", "codigo otp", "código de autenticación multifactor",
            "codigo de autenticacion multifactor",
        ),
        "payment": (
            "realice una transferencia bancaria", "transfiera el dinero", "tarjetas de regalo",
            "cambie los datos bancarios", "nueva cuenta bancaria", "actualice los datos de pago",
        ),
        "secrecy": (
            "mantenga esto confidencial", "mantén esto confidencial", "no se lo diga a nadie",
            "no le diga a nadie", "mantenga esto en secreto",
        ),
    },
    "fr": {
        "urgency": (
            "agissez maintenant", "action urgente requise", "immédiatement", "immediatement",
            "dernier avertissement", "votre compte sera suspendu", "votre compte est suspendu",
            "répondez dans les 24 heures", "repondez dans les 24 heures",
        ),
        "credential": (
            "vérifiez votre mot de passe", "verifiez votre mot de passe",
            "confirmez votre mot de passe", "saisissez votre mot de passe",
            "envoyez votre mot de passe",
        ),
        "otp": (
            "envoyez le code de vérification", "envoyez le code de verification",
            "partagez le code de vérification", "partagez le code de verification",
            "code otp", "code d'authentification",
        ),
        "payment": (
            "virement bancaire", "cartes cadeaux", "modifier les coordonnées bancaires",
            "modifier les coordonnees bancaires", "nouveau compte bancaire",
            "mettre à jour les informations de paiement",
            "mettre a jour les informations de paiement",
        ),
        "secrecy": (
            "gardez ceci confidentiel", "ne le dites à personne", "ne le dites a personne",
            "gardez cela secret",
        ),
    },
    "de": {
        "urgency": (
            "jetzt handeln", "dringende aktion erforderlich", "sofort", "letzte warnung",
            "ihr konto wird gesperrt", "ihr konto wurde gesperrt",
            "antworten sie innerhalb von 24 stunden",
        ),
        "credential": (
            "bestätigen sie ihr passwort", "bestatigen sie ihr passwort",
            "überprüfen sie ihr passwort", "uberprufen sie ihr passwort",
            "geben sie ihr passwort ein", "senden sie ihr passwort",
        ),
        "otp": (
            "senden sie den bestätigungscode", "senden sie den bestatigungscode",
            "teilen sie den bestätigungscode", "teilen sie den bestatigungscode",
            "otp-code", "mfa-code",
        ),
        "payment": (
            "überweisen sie das geld", "uberweisen sie das geld", "banküberweisung",
            "bankuberweisung", "geschenkkarten", "bankverbindung ändern",
            "bankverbindung andern", "zahlungsdaten aktualisieren",
        ),
        "secrecy": (
            "halten sie dies vertraulich", "sagen sie es niemandem",
            "behalten sie dies für sich", "behalten sie dies fur sich",
        ),
    },
}
INDICATOR_DESCRIPTIONS = {
    "urgency": "Urgency or threat language",
    "credential": "Credential request",
    "otp": "One-time code request",
    "payment": "Payment or financial request",
    "secrecy": "Secrecy request",
    "display_name_brand": "Trusted-brand display-name mismatch",
    "executive_payment": "Executive-themed payment request",
    "role_context": "Sender-role and request mismatch",
}
URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")


class _HTMLDetailsParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.text: list[str] = []
        self.links: list[dict[str, str]] = []
        self._href: str | None = None
        self._label: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            self._href = dict(attrs).get("href")
            self._label = []

    def handle_data(self, data: str) -> None:
        self.text.append(data)
        if self._href is not None:
            self._label.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href is not None:
            href = self._href.strip()
            if href.lower().startswith(("http://", "https://", "www.")):
                self.links.append({"destination": href, "displayed_as": " ".join(self._label).strip()})
            self._href = None
            self._label = []


def _decoded_payload(part: Message) -> bytes:
    decoded = part.get_payload(decode=True)
    if decoded is not None:
        return decoded
    payload = part.get_payload()
    if isinstance(payload, str):
        try:
            return payload.encode(part.get_content_charset() or "utf-8", errors="replace")
        except LookupError:
            return payload.encode("utf-8", errors="replace")
    return b""


def _decode_text(payload: bytes, charset: str | None) -> str:
    try:
        return payload.decode(charset or "utf-8", errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _address_details(value: str | None) -> list[dict[str, str]]:
    decoded_parts = decode_header(value or "")
    decoded_value = "".join(
        part.decode(charset or "ascii", errors="replace") if isinstance(part, bytes) else part
        for part, charset in decoded_parts
    )
    return [
        {"name": name.strip(), "address": address.strip()}
        for name, address in getaddresses([decoded_value])
        if address.strip()
    ]


def _raw_header(message: Message, name: str) -> str:
    return next(
        (str(value) for key, value in message.raw_items() if key.casefold() == name.casefold()),
        "",
    )


def _domain(address: str) -> str | None:
    if "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower().rstrip(".")


def _normalized_words(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    without_marks = "".join(character for character in decomposed if not unicodedata.combining(character))
    return " ".join(re.findall(r"[a-z0-9]+", without_marks))


def _first_language_phrase(
    text: str,
    indicator: str,
) -> tuple[str, str] | None:
    folded = text.casefold()
    for language, patterns in LANGUAGE_PATTERNS.items():
        for phrase in patterns[indicator]:
            start = folded.find(phrase.casefold())
            if start >= 0:
                return text[start : start + len(phrase)], language
    return None


def _brand_for_display_name(display_name: str) -> tuple[str, tuple[str, ...]] | None:
    normalized = _normalized_words(display_name)
    for brand, domains in BRAND_DISPLAY_NAMES.items():
        if re.search(rf"\b{re.escape(brand)}\b", normalized):
            return brand, domains
    return None


def _display_name_role(display_name: str) -> str | None:
    normalized = _normalized_words(display_name)
    role_groups = {
        "executive": (
            "ceo", "chief executive", "chief financial", "cfo", "president",
            "managing director", "finance director", "director ejecutivo",
            "director financiero", "directeur général", "directeur financier",
            "geschäftsführer", "finanzvorstand", "vorstandsvorsitzender",
        ),
        "it_support": (
            "it support", "help desk", "helpdesk", "technical support",
            "security team", "information technology", "soporte técnico",
            "soporte tecnico", "equipo de seguridad", "assistance informatique",
            "support informatique", "équipe de sécurité", "equipe de securite",
            "it-support", "it-abteilung", "sicherheitsteam",
        ),
    }
    for role, markers in role_groups.items():
        if any(re.search(rf"\b{re.escape(_normalized_words(marker))}\b", normalized) for marker in markers):
            return role
    return None


def _url_host(value: str) -> str | None:
    candidate = value.strip().strip("<>.,;()[]{}\"'")
    if candidate.lower().startswith("www.") or (
        "://" not in candidate and re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", candidate)
    ):
        candidate = "http://" + candidate
    try:
        host = urlparse(candidate).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def _registrable_domain(host: str) -> str:
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) > 1 else host


def _lookalike_brand(domain: str) -> str | None:
    compact = domain.replace(".", "").replace("-", "")
    for official in KNOWN_BRAND_DOMAINS:
        if official + "." in domain:
            return official
        official_compact = official.replace(".", "")
        if domain == official:
            continue
        if SequenceMatcher(None, compact, official_compact).ratio() >= 0.84:
            return official
    return None


def _brand_impersonation_domain(host: str) -> str | None:
    if any(host == brand or host.endswith("." + brand) for brand in KNOWN_BRAND_DOMAINS):
        return None
    embedded_brand = next(
        (brand for brand in KNOWN_BRAND_DOMAINS if brand + "." in host),
        None,
    )
    if embedded_brand:
        return embedded_brand
    labels = host.split(".")
    for index in range(len(labels) - 1):
        candidate = ".".join(labels[index : index + 2])
        similar_brand = _lookalike_brand(candidate)
        if similar_brand:
            return similar_brand
    return _lookalike_brand(_registrable_domain(host))


def _authentication_checks(message: Message) -> list[dict[str, str]]:
    values = message.get_all("Authentication-Results", [])
    joined = " ".join(str(value) for value in values)
    checks = []
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(
            rf"\b{mechanism}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)",
            joined,
            flags=re.IGNORECASE,
        )
        checks.append({
            "name": mechanism.upper(),
            "status": match.group(1).lower() if match else "not reported",
            "source": "reported in supplied Authentication-Results header; not independently verified",
        })
    return checks


def _evidence_for(finding: Finding, raw_email: str, urls: list[dict[str, str]]) -> str:
    reason = finding.reason.lower()
    if "reply-to" in reason:
        return "From and Reply-To addresses parsed from the supplied headers."
    if "displays" in reason or "points to" in reason:
        for link in urls:
            if link["displayed_as"] and link["destination"] in finding.reason:
                return f"Displayed text: {link['displayed_as']}; destination: {link['destination']}"
        return finding.reason
    if "link" in reason or "domain" in reason or "shortening" in reason or "punycode" in reason:
        return next(
            (
                url["destination"]
                for url in urls
                if url["host"] != "unparsed" and url["host"] in finding.reason
            ),
            finding.reason,
        )
    patterns = {
        "urgent": (r"\bact now\b", r"\bimmediately\b", r"\bwithin 24 hours\b", r"\brespond within \d+ hours?\b", r"\bverify (?:now|immediately)\b", r"\baccount (?:will be|has been) (?:locked|suspended|closed)\b", r"\burgent action\b", r"\baction required\b", r"\bfinal warning\b"),
        "credential": (r"\benter your password\b", r"\bverify your password\b", r"\bconfirm your login\b", r"\breset your password\b", r"\bverify your account\b", r"\b(?:send|share|provide)\s+(?:me\s+)?your password\b"),
        "payment": (r"\bwire transfer\b", r"\bgift cards?\b", r"\bpayment is overdue\b", r"\bupdate (?:your )?billing\b", r"\bchange of bank details\b", r"\b(?:new|updated|changed) bank account\b", r"\bchange (?:the|your) bank (?:account|details)\b"),
        "sensitive": (r"\b(?:send|share|provide|email)\b.{0,60}\b(?:social security number|tax identification number|credit card number|bank account number|confidential information)\b", r"\b(?:social security number|tax identification number|credit card number|bank account number|confidential information)\b.{0,60}\b(?:send|share|provide|email)\b"),
        "remote access": (r"\b(?:download|install)\b.{0,50}\b(?:remote access|remote support|anydesk|teamviewer)\b", r"\b(?:anydesk|teamviewer)\b.{0,50}\b(?:download|install|connect)\b"),
    }
    key = (
        "urgent" if "urgent" in reason or "threatening" in reason or "pressure" in reason
        else "credential" if "password" in reason or "login" in reason
        else "payment" if "payment" in reason
        else "sensitive" if "confidential or sensitive" in reason
        else "remote access" if "remote-access" in reason
        else None
    )
    if key:
        match = next((re.search(pattern, raw_email, re.IGNORECASE) for pattern in patterns[key] if re.search(pattern, raw_email, re.IGNORECASE)), None)
        if match:
            return match.group(0)
    return finding.reason


def analyze_message(
    raw_email: str,
    *,
    header_overrides: dict[str, str] | None = None,
) -> dict[str, object]:
    """Parse, assess, and return structured findings without network activity."""
    if header_overrides:
        message = message_from_string(raw_email, policy=default)
        allowed_headers = {"subject", "from", "to", "reply-to"}
        for name, value in header_overrides.items():
            normalized_name = name.casefold().replace("_", "-")
            if normalized_name not in allowed_headers:
                raise ValueError(f"Unsupported email header override: {name}.")
            if not isinstance(value, str):
                raise ValueError(f"{name} must be text.")
            value = value.strip()
            if len(value) > 998 or any(character in value for character in "\r\n"):
                raise ValueError(f"{name} must be 998 characters or fewer and contain no line breaks.")
            if not value:
                continue
            if normalized_name in message:
                del message[normalized_name]
            message[normalized_name] = value
        raw_email = message.as_string()
    base = analyze_email(raw_email)
    message = message_from_string(raw_email, policy=default)
    sender = _address_details(_raw_header(message, "From"))
    recipients = _address_details(
        ", ".join(
            value
            for header in ("To", "Cc", "Bcc")
            for value in (
                str(raw_value)
                for key, raw_value in message.raw_items()
                if key.casefold() == header.casefold()
            )
        )
    )
    reply_to = _address_details(_raw_header(message, "Reply-To"))
    text_bodies: list[str] = []
    html_bodies: list[str] = []
    attachments: list[dict[str, object]] = []

    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        payload = _decoded_payload(part)
        if filename or disposition == "attachment":
            safe_name = filename or "(unnamed attachment)"
            suffix = "." + safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
            attachments.append({
                "filename": safe_name,
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "scan_status": "not scanned; no antivirus or sandbox integration configured",
                "suspicious": suffix in DANGEROUS_EXTENSIONS or suffix in MACRO_EXTENSIONS,
            })
            continue
        if part.get_content_type() == "text/plain":
            text_bodies.append(_decode_text(payload, part.get_content_charset()))
        elif part.get_content_type() == "text/html":
            html_bodies.append(_decode_text(payload, part.get_content_charset()))

    html_details: list[_HTMLDetailsParser] = []
    for html in html_bodies:
        parser = _HTMLDetailsParser()
        parser.feed(html)
        html_details.append(parser)

    body = "\n".join(text_bodies + [" ".join(parser.text) for parser in html_details]).strip()
    url_values = list(URL_PATTERN.findall(body))
    for parser in html_details:
        url_values.extend(link["destination"] for link in parser.links)
    urls: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    html_link_by_destination = {
        link["destination"]: link["displayed_as"]
        for parser in html_details
        for link in parser.links
    }
    for value in url_values:
        cleaned = value.rstrip(".,;:!?)]}")
        if cleaned in seen_urls:
            continue
        seen_urls.add(cleaned)
        host = _url_host(cleaned)
        urls.append({
            "destination": cleaned,
            "host": host or "unparsed",
            "displayed_as": html_link_by_destination.get(cleaned, cleaned),
            "reputation_status": "not checked; no threat-intelligence service configured",
        })

    findings: list[dict[str, object]] = []
    for finding in base["findings"]:
        reason = finding.reason
        category = "sender" if "reply-to" in reason.lower() else "urls" if any(term in reason.lower() for term in ("link", "domain", "shortening", "punycode")) else "content"
        evidence = _evidence_for(finding, raw_email, urls)
        if "reply-to" in reason.lower():
            from_values = _address_details(_raw_header(message, "From"))
            reply_values = _address_details(_raw_header(message, "Reply-To"))
            from_text = ", ".join(f"{item['name']} <{item['address']}>" if item["name"] else item["address"] for item in from_values)
            reply_text = ", ".join(f"{item['name']} <{item['address']}>" if item["name"] else item["address"] for item in reply_values)
            evidence = (
                f"From: {from_text or 'not present'}; Reply-To: {reply_text or 'not present'}"
            )
        findings.append({
            "category": category,
            "points": finding.points,
            "reason": reason,
            "evidence": evidence,
        })

    html_links = [link for parser in html_details for link in parser.links]
    for link in html_links:
        display_host = _url_host(link["displayed_as"])
        destination_host = _url_host(link["destination"])
        if display_host and destination_host and display_host != destination_host:
            reason = f"A link displays {display_host} but points to {destination_host}."
            if not any(finding.reason == reason for finding in base["findings"]):
                findings.append({
                    "category": "urls",
                    "points": 25,
                    "reason": reason,
                    "evidence": f"Displayed text: {link['displayed_as']}; destination: {link['destination']}",
                })

    for email_address in sender:
        sender_domain = _domain(email_address["address"])
        if not sender_domain:
            continue
        similar_to = _brand_impersonation_domain(sender_domain)
        if similar_to:
            findings.append({
                "category": "sender",
                "points": 25,
                "reason": f"Sender domain resembles the known brand domain {similar_to}.",
                "evidence": email_address["address"],
            })

    for url in urls:
        if url["host"] == "unparsed":
            continue
        similar_to = _brand_impersonation_domain(url["host"])
        if similar_to:
            findings.append({
                "category": "urls",
                "points": 25,
                "reason": f"URL domain resembles or embeds the known brand domain {similar_to}.",
                "evidence": url["destination"],
            })

    body_lower = body.lower()
    bec_patterns = (
        r"\bkeep (?:this|it) (?:confidential|between us|secret)\b",
        r"\bdon't tell anyone\b",
        r"\bdo not tell anyone\b",
        r"\bkeep this from (?:the team|everyone|your manager)\b",
    )
    if any(re.search(pattern, body_lower) for pattern in bec_patterns):
        matched_phrase = next(
            match.group(0)
            for pattern in bec_patterns
            if (match := re.search(pattern, body, re.IGNORECASE))
        )
        findings.append({
            "category": "content",
            "points": 18,
            "reason": "Message asks for secrecy, a possible business email compromise indicator.",
            "evidence": matched_phrase,
        })

    one_time_code_patterns = (
        r"\b(?:send|share|provide|enter|reply with|give me)\b.{0,50}\bone[- ]time (?:passcode|password|code)\b",
        r"\b(?:send|share|provide|enter|reply with|give me)\b.{0,50}\b(?:otp|mfa) code\b",
        r"\b(?:send|share|provide|enter|reply with|give me)\b.{0,50}\bverification code\b",
    )
    if any(re.search(pattern, body_lower) for pattern in one_time_code_patterns):
        matched_phrase = next(
            match.group(0)
            for pattern in one_time_code_patterns
            if (match := re.search(pattern, body, re.IGNORECASE))
        )
        findings.append({
            "category": "content",
            "points": 22,
            "reason": "Message asks the recipient to share or enter a one-time passcode or MFA code.",
            "evidence": matched_phrase,
        })

    auth_checks = _authentication_checks(message)
    for attachment in attachments:
        if attachment["suspicious"]:
            findings.append({
                "category": "attachments",
                "points": 25,
                "reason": f"Attachment type may contain executable code or active content: {attachment['filename']}.",
                "evidence": f"{attachment['content_type']}, {attachment['size_bytes']} bytes, SHA-256 {attachment['sha256']}",
            })

    searchable_text = f"{message.get('Subject', '')}\n{body}"
    matched_languages: set[str] = set()
    multilingual_points = {
        "urgency": 10,
        "credential": 22,
        "otp": 22,
        "payment": 18,
        "secrecy": 18,
    }
    for indicator, points in multilingual_points.items():
        match = _first_language_phrase(searchable_text, indicator)
        if match is None:
            continue
        evidence, language = match
        matched_languages.add(language)
        if any(
            finding["category"] == "content" and finding["evidence"].casefold() == evidence.casefold()
            for finding in findings
        ):
            continue
        findings.append({
            "category": "content",
            "indicator": INDICATOR_DESCRIPTIONS[indicator],
            "points": points,
            "reason": f"Message contains a {INDICATOR_DESCRIPTIONS[indicator].lower()} pattern matched by the {language.upper()} rules.",
            "evidence": evidence,
            "language": language,
        })

    payment_terms = (
        "wire transfer", "bank transfer", "gift card", "change bank details",
        "new bank account", "bank details", "transfer funds", "transferencia bancaria",
        "transfiera el dinero", "tarjetas de regalo", "cambie los datos bancarios",
        "nouveau compte bancaire", "virement bancaire", "cartes cadeaux",
        "modifier les coordonnées bancaires", "banküberweisung", "bankuberweisung",
        "überweisen sie das geld", "uberweisen sie das geld", "geschenkkarten",
        "bankverbindung ändern", "bankverbindung andern",
    )
    credential_terms = (
        "verify your password", "enter your password", "send your password",
        "share your password", "verification code", "otp code", "mfa code",
        "one-time passcode", "verifique su contraseña", "verifique su contrasena",
        "confirme su contraseña", "confirme su contrasena", "código de verificación",
        "codigo de verificacion", "vérifiez votre mot de passe",
        "verifiez votre mot de passe", "code de vérification", "code de verification",
        "bestätigen sie ihr passwort", "bestatigen sie ihr passwort",
        "überprüfen sie ihr passwort", "uberprufen sie ihr passwort",
        "bestätigungscode", "bestatigungscode",
    )
    remote_access_terms = ("anydesk", "teamviewer", "remote access", "remote support")
    folded_context = searchable_text.casefold()

    def first_context_phrase(terms: tuple[str, ...]) -> str | None:
        for term in terms:
            if term in folded_context:
                start = folded_context.index(term)
                return searchable_text[start : start + len(term)]
        return None

    payment_evidence = first_context_phrase(payment_terms)
    credential_evidence = first_context_phrase(credential_terms)
    remote_evidence = first_context_phrase(remote_access_terms)
    for sender_entry in sender:
        display_name = sender_entry["name"]
        sender_domain = _domain(sender_entry["address"])
        brand_match = _brand_for_display_name(display_name) if display_name else None
        if brand_match:
            brand, official_domains = brand_match
            domain_matches = bool(sender_domain) and any(
                sender_domain == domain or sender_domain.endswith("." + domain)
                for domain in official_domains
            )
            if not domain_matches:
                findings.append({
                    "category": "sender",
                    "indicator": "Trusted-brand display-name mismatch",
                    "points": 25,
                    "reason": f"Sender display name claims {brand.title()}, but the sender address is not from its known domain.",
                    "evidence": (
                        f"Display name: {display_name}; sender address: {sender_entry['address']}; "
                        f"expected domain: {' or '.join(official_domains)}"
                    ),
                })

        role = _display_name_role(display_name)
        if role == "executive" and payment_evidence:
            findings.append({
                "category": "content",
                "indicator": "Executive-themed payment request",
                "points": 25,
                "reason": "A sender using an executive title requests a payment or bank-detail action, a possible business email compromise pattern.",
                "evidence": f"Display name: {display_name}; request: {payment_evidence}",
            })
        elif role == "it_support" and (
            credential_evidence or remote_evidence
        ):
            request_evidence = credential_evidence or remote_evidence
            findings.append({
                "category": "content",
                "indicator": "IT-support and credential/access request",
                "points": 20,
                "reason": "A sender using an IT/support identity requests credentials or remote-access activity; verify through a separate trusted channel.",
                "evidence": f"Display name: {display_name}; request: {request_evidence}",
            })

    for finding in findings:
        indicator = finding.get("indicator")
        if not indicator:
            reason = str(finding["reason"])
            indicator = next(
                (label for label in INDICATOR_DESCRIPTIONS.values() if label.lower() in reason.lower()),
                str(finding["category"]).title() + " check",
            )
            finding["indicator"] = indicator
        if finding.get("points", 0) <= 0:
            quality_level = "limited"
            quality_reason = "No positive signal was found by the configured local rules."
        elif str(finding.get("evidence", "")) and finding["evidence"] != finding["reason"]:
            quality_level = "high"
            quality_reason = "The quoted phrase or parsed message artifact is directly present in the supplied email; this does not independently authenticate its origin."
        else:
            quality_level = "medium"
            quality_reason = "The rule matched message content, but the available evidence is indirect or lacks independent verification."
        finding["evidence_reliability"] = {
            "level": quality_level,
            "explanation": quality_reason,
        }

    raw_score = sum(int(finding["points"]) for finding in findings)
    score = min(raw_score, 100)
    level = "LOW" if score < 25 else "SUSPICIOUS" if score < 55 else "HIGH"
    if not any(int(finding["points"]) for finding in findings):
        findings = [{
            "category": "content",
            "points": 0,
            "indicator": "Baseline content check",
            "reason": "No common phishing indicators were detected by these checks.",
            "evidence": "No configured heuristic matched the supplied email text.",
            "evidence_reliability": {
                "level": "limited",
                "explanation": "No positive signal was found by the configured local rules; this is not evidence that the email is safe.",
            },
        }]

    return {
        "score": score,
        "level": level,
        "subject": str(message.get("Subject", "(no subject)")),
        "sender": sender,
        "recipients": recipients,
        "reply_to": reply_to,
        "return_path": str(message.get("Return-Path", "")),
        "body": body,
        "urls": urls,
        "url_count": len(urls),
        "attachments": attachments,
        "authentication": auth_checks,
        "findings": findings,
        "scoring": {
            "method": "Sum of configured rule points, capped at 100; risk score is not a calibrated probability.",
            "indicator_points_total": raw_score,
            "score_cap_applied": raw_score > 100,
            "thresholds": {"LOW": "0-24", "SUSPICIOUS": "25-54", "HIGH": "55-100"},
        },
        "language_analysis": {
            "method": "Curated phrase matching only; this is not general language identification or translation.",
            "supported_languages": ["English", "Spanish", "French", "German"],
            "matched_languages": sorted(matched_languages),
        },
        "confidence_note": "Evidence reliability describes how directly a quoted phrase or parsed artifact supports an indicator. It is not a probability that the message is malicious; sender authenticity and business expectations cannot be fully determined from message text alone.",
        "integration_status": {
            "ai": "not configured",
            "threat_intelligence": "not configured",
            "antivirus_sandbox": "not configured",
            "microsoft_365": "not configured",
        },
    }
