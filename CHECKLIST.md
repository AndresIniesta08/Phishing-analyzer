# Email phishing review checklist

Complete this checklist for each message. It combines manual review with the
local analyzer, which only checks text for a limited set of indicators. A LOW
score does not mean the email is safe, and a HIGH score alone does not prove it
is malicious.

## 1. Handle the message safely

- [ ] Do not click links, scan QR codes, open attachments, enable macros, reply,
  or call numbers supplied in the message while investigating.
- [ ] Keep the original email or screenshot available for comparison. Preserve
  the original message and full headers if your IT/security team asks for them.
- [ ] Use approved organizational tools and procedures for reporting, scanning,
  and reputation checks. Do not upload confidential email or attachments to
  unapproved services.
- [ ] If VirusTotal is enabled, treat URL/domain queries as disclosure to an
  external service; VirusTotal may add queried indicators to its public dataset.
  Never query confidential or personal indicators without authorization.

## 2. If the evidence is a screenshot

The app cannot open images, run OCR, inspect image pixels, or determine a
link's real destination from a screenshot. Review the screenshot yourself
before entering a transcription.

- [ ] Visually inspect and record only details that are actually shown:
  display name, sender address, recipient, subject, message, attachment names,
  and any visible security warnings.
- [ ] Check logos, layout, fonts, spacing, signature, and thread context for
  inconsistencies. These visual clues are not scored by the analyzer.
- [ ] Note visible link text without clicking it. If the actual URL is not
  visible, record the destination as **unknown**; displayed text alone does not
  prove where a link leads.
- [ ] Note QR codes, but do not scan them as part of this review.
- [ ] Transcribe visible text faithfully into the analyzer. Label any omitted
  or unclear detail **not visible** or **unreadable**; do not guess headers,
  destinations, or attachment behavior.

## 3. Review the sender and subject

- [ ] Read the sender's display name and verify the complete sender address,
  not just the name shown in the inbox.
- [ ] Look for misspelled, substituted, extra, or look-alike domain characters
  (for example, `micros0ft.com` instead of `microsoft.com`).
- [ ] Compare `Reply-To` with the sender address, if available; note any
  unexpected difference.
- [ ] Ask whether the sender is known, expected, and appropriate for the
  request. Familiar names and logos can be impersonated or spoofed.
- [ ] Check whether the subject matches the sender and the conversation.
- [ ] Look for urgency, account suspension/password-expiry warnings,
  unexpected invoices or refunds, unusual prizes/offers, threats of closure or
  legal action, or other unexpected claims.

## 4. Review the content and business context

- [ ] Look for requests for passwords, one-time passcodes (OTPs), MFA codes,
  confidential information, or financial information.
- [ ] Look for urgency, fear, secrecy, pressure to bypass review, or unusual
  grammar, spelling, greetings, or formatting.
- [ ] Check whether the request makes sense for the sender's role and fits the
  ongoing conversation and normal company procedures.
- [ ] Treat unexpected transfers, gift cards, payment instructions, and bank
  detail changes as suspicious. Confirm changes independently.
- [ ] Check whether the signature, logo, and contact details are consistent
  with a trusted source; do not rely on contact details in the message.
- [ ] Watch for unexpected MFA approvals/sign-in alerts, software or remote
  access requests, cloud document-sharing notices, or claims that antivirus
  or mailbox protection has expired.
- [ ] Note suspicious forms, cloud-storage links, QR codes, or fake/altered
  conversation threads.

## 5. Review links without opening them

- [ ] Never click a link during this review. In an actual email client, use its
  built-in link preview only if your organization's policy permits; this is
  not possible from a screenshot alone.
- [ ] Compare the displayed link with the actual destination only when the
  destination can be safely previewed. If it cannot, mark it **unknown**.
- [ ] Check for misspelled/look-alike domains, misleading subdomains (for
  example, `microsoft.com.example.net` is under `example.net`), unexpected
  shorteners, strange characters, or excessive redirects.
- [ ] Be cautious of unexpected login pages and credential requests. Do not
  visit a destination to test it.
- [ ] Use approved security tools if domain, URL, or sending IP reputation
  needs checking; do not submit sensitive URLs to unapproved services.

## 6. Review attachments without opening them

- [ ] Ask whether each attachment was expected and relevant to the conversation.
- [ ] Treat executable or script files (such as `.exe`, `.msi`, `.bat`, `.cmd`,
  and `.scr`) as suspicious unless verified through approved procedures.
- [ ] Be cautious of Office files asking to enable macros, editing, or active
  content; do not enable these to inspect a file.
- [ ] Treat unexpected `.zip`, `.rar`, `.iso`, password-protected archives, and
  HTML/HTM files as suspicious.
- [ ] Check for deceptive double extensions such as `invoice.pdf.exe`.
- [ ] If inspection is needed, use approved security scanning tools or contact
  IT/security. Do not open the attachment to test it.

## 7. Review headers and authentication when available

- [ ] Review SPF, DKIM, and DMARC results in the original message headers or
  your organization's approved mail-security interface.
- [ ] Compare `From`, `Return-Path`, and `Reply-To`; investigate unexpected
  discrepancies.
- [ ] Review `Received` headers and authentication failures only if you know
  how to interpret them or have help from IT/security.
- [ ] Treat a pass/fail result as one signal, not proof by itself that a
  message is safe or malicious.
- [ ] If checking sender domain or IP reputation, use approved tools and
  preserve the relevant headers for IT/security when requested.

## 8. Analyze available text in the local app

- [ ] Start the app with `python .\phishing_analyzer.py` or double-click
  `launch_app.pyw`.
- [ ] Paste the screenshot transcription, paste message text, or choose **Open
  email file** for a `.eml` or `.txt` file. Image files are not supported.
- [ ] Include complete headers when available. A screenshot transcription may
  lack headers, actual link targets, and attachment contents; do not invent
  missing information.
- [ ] Select **Analyze message** and record the risk level, score, URL count,
  and each finding.
- [ ] Compare the findings with the original evidence. The analyzer checks
  only the text it receives; it does not verify identity, authenticate
  headers, inspect image appearance or attachments, or browse links.
- [ ] If the input is empty, confirm the app shows an “Email needed” warning.
- [ ] Select **Clear** when finished if you want to remove the message from the
  app.

## 9. Verify, report, and respond

- [ ] Verify unusual requests through a known phone number, saved contact, or
  separate trusted communication channel—not details or links in the message.
- [ ] Report suspicious messages using your organization's phishing-reporting
  process. Preserve the original and headers if requested.
- [ ] If credentials were entered, notify IT/security immediately and change
  credentials through the legitimate site or organization-approved process.
- [ ] If an attachment was opened or executed, report it immediately for
  endpoint investigation.
- [ ] Do not use the analyzer score as the sole basis for a consequential
  decision.

## 10. Verify the current local MVP

Run these checks from the project directory. Automated checks validate
program behavior; they do not establish that any particular email is safe.

- [ ] Confirm Python 3.10 or later is installed.
- [ ] Run `python -m unittest -v`; all 27 automated tests should pass.
- [ ] Confirm ordinary-message test: LOW risk, score `0`.
- [ ] Confirm `http://bit.ly/...` produces both shortener and unencrypted-HTTP
  findings (19 points before any other findings).
- [ ] Confirm urgent password-request test: SUSPICIOUS risk, score `42`.
- [ ] Confirm rules flag a look-alike brand domain, secrecy/OTP request,
  sensitive-data request, remote-access software request, and dangerous
  attachment extension with supporting message evidence.
- [ ] Confirm findings include a category, evidence, and a recommended action.
- [ ] Confirm `.eml` parsing extracts sender, recipient, subject, body, links,
  Reply-To, Return-Path, and attachment metadata where present.
- [ ] Confirm attachment SHA-256 is calculated locally and the file is not
  opened or executed.
- [ ] Confirm SPF/DKIM/DMARC values are described as supplied-header reports,
  not independently verified authentication.
- [ ] Start the web app with `python .\web_app.py` and open
  `http://127.0.0.1:8765`.
- [ ] Preview an `.eml` file before analysis; verify extracted fields, URLs,
  attachment metadata, and authentication values are visible.
- [ ] Analyze the same sample; verify the categorized findings and score.
- [ ] Confirm the dashboard counters update, the report appears in local
  history, **View** reopens it, **Delete** removes it, and **Export CSV**
  downloads a report.
- [ ] Switch the trend dashboard between the last 30 days and last 12 months;
  verify LOW, SUSPICIOUS, and HIGH counts and URL totals match saved reports,
  including empty periods and updates after deleting a report.
- [ ] Verify dashboard analyst-reviewed legitimate counts and common positive
  detection indicators against saved feedback and report findings.
- [ ] On a fresh data directory, create the initial administrator with
  `python .\web_app.py --create-admin`; verify passwords shorter than 12
  characters are rejected and the first administrator cannot be created
  through the sign-in page or public API.
- [ ] Verify logout, login, eight-hour sessions, and rejection of write
  requests without the session CSRF token.
- [ ] As administrator, create user and analyst accounts; verify non-admin
  access to administration is denied and at least one active administrator
  must remain.
- [ ] Analyze a high-score message; confirm an in-app alert is created at the
  configured score threshold and can be acknowledged.
- [ ] As analyst/admin, create an incident from a report, assign it to an
  active analyst, change severity and status (including False Positive), add a
  note, and confirm the case timeline records each change and duplicate
  creation is rejected.
- [ ] Verify audit history records account, analysis, incident, alert,
  feedback, deletion, settings, and export events without email bodies.
- [ ] Configure retention and verify the policy removes expired reports and
  linked incidents/alerts on a subsequent analysis; verify audit entries stay.
- [ ] Search history by sender/subject, risk level, and date range; confirm
  results match filters and dashboard totals remain overall counts.
- [ ] Download a saved report as PDF and confirm it includes score, headers,
  findings/evidence, URLs, attachments, and check limitations.
- [ ] As analyst, classify a report as Confirmed Phishing, Suspicious,
  Legitimate, or False Positive and provide a reason; verify ordinary users
  cannot submit analyst feedback.
- [ ] As administrator, review feedback and reject one item; verify no rule
  changes. Approve a bounded adjustment for a matched indicator; verify new
  analyses use it while saved reports retain their original score. Verify
  feedback resubmission returns it to the review queue and rolls back its
  prior rule adjustment when that review was its source.
- [ ] With VirusTotal unconfigured, verify the opt-in control is unavailable
  and a forced API request fails clearly. With an authorized API key, verify
  URL/domain lookups require per-analysis consent, never open links, report
  detection counts/redirects where available, cap lookups at five unique URLs,
  and surface missing/rate-limited results without calling them safe.
- [ ] Confirm empty input and input larger than 10 MB show clear errors.
- [ ] Confirm analysis history stores no email body or attachment bytes.
- [ ] Confirm the server listens only on `127.0.0.1`, and stop it with Ctrl+C.

## 11. Provider-dependent integrations (partially configured)

The following external capabilities need provider selection, authorized access,
and privacy/security review. VirusTotal URL/domain lookups are implemented as
an optional opt-in integration; remaining items are not represented as working
features.

### Sender, header, and threat-intelligence integrations

- [ ] Independently validate SPF, DKIM, and DMARC using a trusted mail
  authentication source; do not trust unverified text in an uploaded header.
- [ ] Expand beyond the current limited look-alike-domain heuristic; assess
  sender-domain and sending-IP reputation using an approved provider.
- [x] Query VirusTotal URL/domain reports only after per-analysis opt-in; show
  available reputation counts, domain categories, redirect data, and lookup
  failures without treating unavailable results as safe.
- [ ] Add approved additional threat-intelligence providers and define
  retention, service-specific sharing, and lookup-time reporting.

### Attachment scanning and response

- [ ] Integrate authorized antivirus and malware-sandbox scanning; never
  execute submitted attachments on the analysis host.
- [ ] Detect macro/active content by safely inspecting supported file formats,
  not filename alone.
- [ ] Integrate quarantine/block/remediation only with explicit authorization
  and an approved email-security system.

### AI and external notifications

- [ ] Add AI classification only with explicit privacy controls and prompt
  injection safeguards; retain deterministic findings and evidence. Select
  an approved local model or provider and define what email data may be sent.
- [ ] Send alerts to an approved external notification destination only after
  provider selection and authorization. Current alerts are local/in-app only.

### Microsoft integrations and response

- [ ] Integrate Microsoft Graph/Outlook submission and Microsoft Defender only
  with approved tenant permissions and licensing.
- [ ] Integrate quarantine/remediation only with explicit authorization and an
  approved mail-security system; no destructive email action is available
  locally.

Public deployment is intentionally out of scope. The server remains bound to
loopback and is not hardened for network or multi-tenant use.

## Record results

- Date:
- Message reference (do not include sensitive content):
- Evidence type: pasted text / `.eml` / `.txt` / screenshot transcription
- Screenshot reviewed manually: yes / no / not applicable
- Details not visible, unreadable, or unknown:
- Sender/domain and subject concerns:
- Link and attachment concerns:
- Header/authentication observations:
- Analyzer risk / score / URL count:
- Analyzer findings:
- Independent verification and reporting action:
- Program verification: PASS / FAIL / NOT RUN
- Notes:
