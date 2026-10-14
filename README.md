# Email Phishing Risk Analyzer

A dependency-free Python desktop app and local-only localhost web app. The web
app parses pasted email or `.eml`/`.txt` files, previews extracted details,
performs explainable offline heuristics, and saves metadata-only reports to a
local SQLite history. It does not establish that a message is safe or malicious.
Scores are capped at `100`: `0–24` is LOW, `25–54` is SUSPICIOUS, and `55–100`
is HIGH. The thresholds are heuristic, not a calibrated probability.

Findings show the matched indicator, quoted/parsed evidence, rule-point
contribution, and evidence-source reliability. Reliability describes whether the
quoted signal is directly present in the supplied message; it is not a
probability of maliciousness or independent sender authentication. Curated
urgency, credential, OTP, payment, and secrecy phrase rules cover English,
Spanish, French, and German, but are not general language identification,
translation, or exhaustive detection. Display-name and business-context checks
use a limited set of known brands, role titles, and request phrases. The app
cannot know whether a sender/request was expected in your organization; verify
those cases through a trusted independent channel.

## Requirements

- Python 3.10 or later

## Run the web app on Windows

From PowerShell in the project directory:

```powershell
python .\web_app.py
```

On first use, create the initial administrator from the PowerShell console;
this cannot be done from the sign-in page:

```powershell
python .\web_app.py --create-admin
```

Enter a unique username and a strong password of at least 12 characters when
prompted. Then start the app normally with `python .\web_app.py` and sign in at
<http://127.0.0.1:8765>. Leave the PowerShell window open while using the app;
press **Ctrl+C** there to stop it. Use `python .\web_app.py --port 9000` to
select another port.

Only an administrator can provision subsequent accounts from **User
Management** in the application. The sign-in page does not offer registration,
and account-creation API requests outside the administrator console are
rejected.

The server binds exclusively to `127.0.0.1`. It is not hosted on the public
internet. Local accounts share this device's report history; the app does not
provide tenant isolation. Do not expose it to a network or deploy it publicly
as-is.

### Optional VirusTotal reputation lookup

Set `VIRUSTOTAL_API_KEY` in the server process environment before startup to
enable the integration. For example, in PowerShell:

```powershell
$env:VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
python .\web_app.py
```

The key is not stored in the application database or returned to the browser.
Analysts opt in separately for each analysis. The app queries up to five unique
URLs and their domains; it sends neither email bodies nor attachments and never
opens the links. VirusTotal states queried indicators may be added to its public
dataset. Do not query confidential or personal indicators. Available engine
counts, domain details, and reported redirects are shown; missing or
rate-limited lookups are not treated as safe.

## Analyze a message

1. Enter optional **From**, **To**, **Reply-To**, and **Subject** values in their
   separate fields, then paste the email body or full email, or choose a
   `.eml`/`.txt` file or drag it into the analysis workspace (maximum 10 MB).
   Entered values take precedence over the corresponding message headers;
   leave a field blank to use its header value.
2. Select **Preview extracted details**. Review sender/recipient headers,
   subject, body, links, attachment metadata and reported authentication
   results.
3. Select **Analyze and save report**. Findings are categorized as sender,
   content, URLs, or attachments, with evidence and recommended actions.
4. Review risk counts, analyst-reviewed legitimate classifications, common
   indicators, and daily/monthly analysis trends on the dashboard.
5. Analysts/admins can create cases from reports, set case severity and status,
   assign an analyst, add investigation notes, and review a timeline of status,
   severity, assignment, and note changes. High-risk score thresholds produce
   in-app alerts that users can acknowledge.
6. Admins can create accounts and assign user/analyst/admin roles, set the
   alert threshold, and configure report retention. Admins can review recent
   audit events and review analyst classifications. Analysts submit a
   classification with a required reason. Administrators can approve a bounded
   point adjustment for a matched indicator or reject the review; adjustments
   affect future analyses only, and saved reports are not recalculated. Users
   can search/filter history, review reports, filter cases by status, search
   extracted domains, or export CSV/PDF.

The sidebar links to the overview, analysis workspace, threat detections,
investigations, history, analytics, integrations, user management, and settings.
Administrator-only and analyst-only entries are role-gated. Domains shown under
threat detections are associated with URL indicators; they are not independently
verified unless an analyst opted in to a configured VirusTotal lookup.

Feedback is an analyst review annotation. Rule adjustments require an explicit
administrator approval and are never learned automatically. History search returns the latest 100 matching
reports, while dashboard counters summarize all stored reports. Trend charts
aggregate the local report history into UTC day/month buckets; they do not
estimate risk probability or use external data.

Individual PDF reports include a risk summary, message details, findings with
supporting evidence and recommended responses, reported authentication results,
extracted links, attachment hashes, and analysis limitations. They do not
include email body content.

Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes, not plaintext.
Sessions expire after eight hours and use HttpOnly, SameSite cookies plus a
CSRF token for write requests. The initial administrator is created through
the one-time `--create-admin` console command; further accounts are managed by
an authenticated administrator in the application.
Audit events include account, analysis, report, incident, alert, settings, and
export actions, but do not include email bodies. A nonzero retention setting
removes expired reports (and linked incidents/alerts) when the next message is
analyzed; audit records remain. Use `0` for manual report deletion only.

Attachment bytes are never opened or executed. The app calculates SHA-256
locally and flags risky filename extensions; it does not scan files. Supplied
SPF/DKIM/DMARC header values are displayed but not independently verified.
Links are extracted but never opened. VirusTotal checks require an API key and
per-analysis opt-in. Screenshot files are unsupported: inspect screenshots
manually and paste a faithful transcription of their visible text.

Saved history is under `%LOCALAPPDATA%\EmailPhishingRiskAnalyzer\history.sqlite3`
on Windows. It stores report metadata (including sender, subject, findings,
URLs, attachment names/hashes, and user feedback) but not the email body or
attachment bytes. Delete individual reports in the UI. VirusTotal is optional;
AI, antivirus/sandbox, Microsoft 365/Defender, external notifications, and
quarantine integrations are not configured. AI analysis requires an explicitly
approved model/provider and privacy review. Microsoft Graph/Defender and
authorized quarantine require tenant access and permissions; the app does not
simulate these integrations.

## Run the desktop app

Double-click `launch_app.pyw` or run:

```powershell
python .\phishing_analyzer.py
```

## Run tests

```powershell
python -m unittest -v
```

See [CHECKLIST.md](./CHECKLIST.md) for per-message review guidance, local
verification checks, and future integration acceptance criteria.
