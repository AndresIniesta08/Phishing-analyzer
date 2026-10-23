const emailInput = document.querySelector("#email-input");
const subjectInput = document.querySelector("#email-subject");
const fromInput = document.querySelector("#email-from");
const toInput = document.querySelector("#email-to");
const replyToInput = document.querySelector("#email-reply-to");
const fileInput = document.querySelector("#email-file");
const fileName = document.querySelector("#file-name");
const previewButton = document.querySelector("#preview-button");
const analyzeButton = document.querySelector("#analyze-button");
const errorMessage = document.querySelector("#error-message");
const previewCard = document.querySelector("#preview-card");
const resultCard = document.querySelector("#result-card");
const whatsappReviewForm = document.querySelector("#whatsapp-review-form");
const whatsappMessageInput = document.querySelector("#whatsapp-message");
const whatsappZipInput = document.querySelector("#whatsapp-zip");
const screenshotFileInput = document.querySelector("#screenshot-file");
const screenshotOcrText = document.querySelector("#screenshot-ocr-text");
let screenshotPreviewUrl = null;
let screenshotFilename = "";

let previewedInput = null;
let currentReportId = null;
let csrfToken = null;
let currentUser = null;
let incidentReportIds = new Set();
let virusTotalConfigured = false;

function getEmailInput() {
  return {
    email: emailInput.value,
    subject: subjectInput.value.trim(),
    from: fromInput.value.trim(),
    to: toInput.value.trim(),
    reply_to: replyToInput.value.trim(),
  };
}

for (const link of document.querySelectorAll(".nav-link")) {
  link.addEventListener("click", () => {
    for (const item of document.querySelectorAll(".nav-link")) {
      item.classList.toggle("is-active", item === link);
      if (item === link) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    }
  });
}

const recommendations = {
  sender: "Verify the sender and request using a known, independent contact method.",
  content: "Do not provide credentials or approve unusual requests; verify through a trusted channel.",
  urls: "Do not open the link. Use approved security tools or report it to your security team.",
  attachments: "Do not open or execute the attachment. Request an approved security scan.",
};

function showError(message) {
  errorMessage.textContent = message;
  errorMessage.hidden = false;
}

function clearError() {
  errorMessage.textContent = "";
  errorMessage.hidden = true;
}

function toBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

function renderWhatsappReview(report) {
  const result = document.querySelector("#whatsapp-review-result");
  result.hidden = false;
  const banner = document.querySelector("#whatsapp-risk-banner");
  banner.className = `risk-banner risk-${String(report.level).toLowerCase()}`;
  document.querySelector("#whatsapp-risk-level").textContent = `${report.level} risk indicators`;
  document.querySelector("#whatsapp-risk-score").textContent = report.score;
  document.querySelector("#whatsapp-report-id").textContent = `Report ${report.report_id}`;
  document.querySelector("#whatsapp-review-disclaimer").textContent =
    "A low score does not mean the message or ZIP is safe. This review does not scan file contents or replace antivirus tools.";

  const findings = document.querySelector("#whatsapp-findings");
  findings.replaceChildren();
  for (const finding of report.findings) {
    const item = document.createElement("li");
    const details = document.createElement("span");
    details.textContent = `${finding.indicator || finding.category}: ${finding.reason}`;
    const evidence = document.createElement("span");
    evidence.className = "finding-evidence";
    evidence.textContent = `Evidence: ${finding.evidence}`;
    const points = document.createElement("span");
    points.className = "finding-points";
    points.textContent = finding.points > 0 ? `+${finding.points} points` : "Informational";
    item.append(details, evidence, points);
    findings.append(item);
  }

  function resetScreenshotPreview() {
    if (screenshotPreviewUrl) {
      URL.revokeObjectURL(screenshotPreviewUrl);
      screenshotPreviewUrl = null;
    }
    document.querySelector("#screenshot-preview").removeAttribute("src");
    document.querySelector("#screenshot-preview").hidden = true;
  }

  const archive = report.zip_inspection;
  const archiveResult = document.querySelector("#whatsapp-archive-result");
  archiveResult.hidden = !archive;
  if (archive) {
    document.querySelector("#whatsapp-archive-summary").textContent =
      `${archive.filename} · ${archive.entry_count} entries · ${archive.size_bytes.toLocaleString()} bytes · ${archive.declared_uncompressed_bytes.toLocaleString()} declared uncompressed bytes · ${archive.encrypted_entry_count} encrypted · ${archive.nested_archive_count} nested archive(s) · ${archive.scan_status}`;
    document.querySelector("#whatsapp-archive-hash").textContent = `ZIP SHA-256: ${archive.sha256}`;
    const entries = document.querySelector("#whatsapp-archive-entries");
    entries.replaceChildren();
    const visibleEntries = archive.listed_entries.length
      ? archive.listed_entries
      : ["No entries listed in the ZIP directory."];
    for (const entryName of visibleEntries) {
      const item = document.createElement("li");
      item.textContent = entryName;
      entries.append(item);
    }
    if (archive.listing_truncated) {
      const item = document.createElement("li");
      item.textContent = "Listing truncated; not all names are shown.";
      entries.append(item);
    }
  }
}

function addField(container, label, value) {
  const term = document.createElement("dt");
  term.textContent = label;
  const description = document.createElement("dd");
  description.textContent = value || "Not present";
  container.append(term, description);
}

function formatAddresses(addresses) {
  return addresses.map((item) => item.name ? `${item.name} <${item.address}>` : item.address).join(", ");
}

function renderPreview(data) {
  const fields = document.querySelector("#email-fields");
  fields.replaceChildren();
  addField(fields, "From", formatAddresses(data.sender));
  addField(fields, "To", formatAddresses(data.recipients));
  addField(fields, "Reply-To", formatAddresses(data.reply_to));
  addField(fields, "Return-Path", data.return_path);
  addField(fields, "Subject", data.subject);

  const auth = document.querySelector("#auth-preview");
  auth.replaceChildren();
  for (const check of data.authentication) {
    const item = document.createElement("li");
    item.textContent = `${check.name}: ${check.status}`;
    const note = document.createElement("span");
    note.className = "subtle";
    note.textContent = check.source;
    item.append(note);
    auth.append(item);
  }

  const links = document.querySelector("#links-preview");
  links.replaceChildren();
  if (data.urls.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No links found in the extracted text.";
    links.append(item);
  }
  for (const link of data.urls) {
    const item = document.createElement("li");
    item.textContent = `Destination: ${link.destination}`;
    const label = document.createElement("span");
    label.className = "subtle";
    label.textContent = `Displayed as: ${link.displayed_as || "(not available)"} · ${link.reputation_status}`;
    item.append(label);
    links.append(item);
  }

  const attachments = document.querySelector("#attachments-preview");
  attachments.replaceChildren();
  if (data.attachments.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No attachments detected.";
    attachments.append(item);
  }
  for (const attachment of data.attachments) {
    const item = document.createElement("li");
    item.textContent = `${attachment.filename}${attachment.suspicious ? " · suspicious type" : ""}`;
    const note = document.createElement("span");
    note.className = "subtle";
    note.textContent = `${attachment.content_type} · ${attachment.size_bytes} bytes · SHA-256 ${attachment.sha256} · ${attachment.scan_status}`;
    item.append(note);
    attachments.append(item);
  }

  document.querySelector("#body-preview").textContent = data.body || "(No plain-text or HTML body extracted.)";
  previewCard.hidden = false;
  document.querySelector("#analysis-guidance").hidden = true;
  resultCard.hidden = true;
  analyzeButton.disabled = false;
}

function renderCategories(data) {
  const container = document.querySelector("#category-results");
  container.replaceChildren();
  const authStatus = (name) => data.authentication.find((item) => item.name === name).status;
  const sections = [
    {
      key: "sender",
      title: "Sender and authentication",
      checks: [
        `From: ${formatAddresses(data.sender) || "not present"}`,
        `Recipients: ${formatAddresses(data.recipients) || "not present"}`,
        `Reply-To: ${formatAddresses(data.reply_to) || "not present"}`,
        `Return-Path: ${data.return_path || "not present"}`,
        `SPF: ${authStatus("SPF")}`,
        `DKIM: ${authStatus("DKIM")}`,
        `DMARC: ${authStatus("DMARC")}`,
      ],
    },
    { key: "content", title: "Content indicators", checks: ["Urgency, credentials, payment, and business-context text heuristics"] },
    {
      key: "urls",
      title: "URLs",
      checks: [
        `${data.url_count} URL(s) extracted; reputation not checked`,
        ...data.urls.map((url) => `${url.destination} · ${url.reputation_status}`),
      ],
    },
    {
      key: "attachments",
      title: "Attachments",
      checks: data.attachments.length
        ? data.attachments.map((item) => `${item.filename} · ${item.content_type} · ${item.size_bytes} bytes · SHA-256 ${item.sha256} · ${item.scan_status}`)
        : ["No attachments detected."],
    },
  ];

  for (const section of sections) {
    const card = document.createElement("article");
    card.className = "category-card";
    const heading = document.createElement("h3");
    heading.textContent = section.title;
    card.append(heading);
    for (const check of section.checks) {
      const item = document.createElement("span");
      item.className = "check-pill";
      item.textContent = check;
      card.append(item);
    }
    const findings = data.findings.filter((finding) => finding.category === section.key);
    if (findings.length) {
      for (const finding of findings) {
        const item = document.createElement("span");
        item.className = finding.points > 0 ? "check-pill check-fail" : "check-pill";
        item.textContent = finding.reason;
        card.append(item);
      }
    }
    container.append(card);
  }
}

function renderResult(data) {
  currentReportId = data.report_id || data.id;
  const incidentButton = document.querySelector("#create-incident-button");
  incidentButton.hidden = !["analyst", "admin"].includes(currentUser?.role);
  incidentButton.disabled = incidentReportIds.has(currentReportId);
  incidentButton.textContent = incidentButton.disabled ? "Incident already created" : "Create incident";
  const level = String(data.level).toLowerCase();
  const banner = document.querySelector("#risk-banner");
  banner.className = `risk-banner risk-${level}`;
  document.querySelector("#risk-level").textContent = `${data.level} RISK`;
  document.querySelector("#risk-score").textContent = data.score;
  const scoring = data.scoring;
  document.querySelector("#scoring-explanation").textContent = scoring
    ? `${scoring.indicator_points_total} indicator points across ${data.findings.filter((finding) => finding.points > 0).length} positive finding(s); displayed score ${data.score}/100${scoring.score_cap_applied ? " (capped at 100)" : ""}. ${scoring.method}`
    : "The score combines configured rule points and is not a calibrated probability.";
  document.querySelector("#confidence-explanation").textContent = data.confidence_note
    || "Evidence quality describes how directly an indicator is supported; it is not a probability that the email is malicious.";
  const language = data.language_analysis;
  document.querySelector("#language-explanation").textContent = language
    ? `Language rules: ${language.supported_languages.join(", ")}. Matched: ${language.matched_languages.length ? language.matched_languages.join(", ") : "no non-English phrase rules"}. ${language.method}`
    : "Language detection is limited to the configured rule set.";
  const reportSource = data.channel ? `${data.channel} · ` : "";
  document.querySelector("#report-date").textContent =
    `${reportSource}Report ${data.report_id || data.id || ""} · ${data.analyzed_at || ""}`;
  const feedback = data.feedback;
  const feedbackStatus = document.querySelector("#feedback-status");
  const feedbackNote = document.querySelector("#feedback-note");
  document.querySelector("#feedback-classification").value = feedback?.classification || "confirmed_phishing";
  document.querySelector("#submit-feedback-button").disabled = !currentReportId;
  feedbackStatus.textContent = feedback
    ? `${feedback.classification.replaceAll("_", " ")} · reviewed by ${feedback.submitted_by || "analyst"} on ${feedback.submitted_at}${feedback.note ? ` — ${feedback.note}` : ""}${data.feedback_review ? ` · admin ${data.feedback_review.decision} the review` : " · awaiting administrator review"}`
    : "Analysts can record a classification and reason. Feedback waits for administrator review and does not automatically tune rules.";
  feedbackStatus.classList.toggle("feedback-confirmed", Boolean(feedback));
  feedbackNote.value = feedback?.note || "";
  const pdfLink = document.querySelector("#pdf-link");
  pdfLink.href = `/api/report/${encodeURIComponent(currentReportId)}/pdf`;
  pdfLink.hidden = false;

  const integrationNotice = document.querySelector("#integration-notice");
  const screenshotNotice = data.screenshot_review
    ? ` ${data.screenshot_review.processing}. OCR may be inaccurate; verify links and visual clues against the original screenshot.`
    : "";
  integrationNotice.textContent = `AI (${data.integration_status.ai}); VirusTotal (${data.integration_status.threat_intelligence}); antivirus/sandbox (${data.integration_status.antivirus_sandbox}); Microsoft 365 (${data.integration_status.microsoft_365}). Authentication values are reported from supplied headers only.${screenshotNotice}`;
  renderCategories(data);

  const reputationList = document.querySelector("#url-reputation-list");
  reputationList.replaceChildren();
  if (!data.urls.length) {
    const empty = document.createElement("li");
    empty.textContent = "No URLs were extracted.";
    reputationList.append(empty);
  }
  for (const url of data.urls) {
    const item = document.createElement("li");
    const result = url.virustotal;
    const domainReport = result?.domain_report;
    const detectionStats = result?.analysis_stats;
    const summary = [
      `Domain: ${url.host}`,
      `VirusTotal: ${result?.reputation || "not checked"}`,
      result ? `detections: ${result.detection_count ?? "not available"}` : "",
      detectionStats ? `engines: ${JSON.stringify(detectionStats)}` : "",
      domainReport ? `domain reputation: ${domainReport.reputation}` : "",
      result?.last_final_url ? `reported final URL: ${result.last_final_url}` : "",
      result?.redirect_chain?.length ? `reported redirects: ${result.redirect_chain.join(" → ")}` : "",
      result?.last_http_response_code ? `HTTP status: ${result.last_http_response_code}` : "",
      result?.categories && Object.keys(result.categories).length
        ? `categories: ${Object.entries(result.categories).map(([source, category]) => `${source}: ${category}`).join(", ")}`
        : "",
    ].filter(Boolean);
    item.textContent = `${url.destination} · ${summary.join(" · ")}`;
    reputationList.append(item);
  }

  const findingsList = document.querySelector("#findings-list");
  findingsList.replaceChildren();
  for (const finding of data.findings) {
    const row = document.createElement("li");
    const indicator = document.createElement("span");
    indicator.className = "finding-indicator";
    indicator.textContent = finding.indicator || finding.category;
    row.append(indicator);
    const title = document.createElement("span");
    title.textContent = finding.reason;
    row.append(title);
    const points = document.createElement("span");
    points.className = "finding-points";
    points.textContent = finding.points > 0 ? `+${finding.points} points` : finding.category;
    row.append(points);
    const evidence = document.createElement("span");
    evidence.className = "finding-evidence";
    evidence.textContent = `Evidence: ${finding.evidence}`;
    row.append(evidence);
    if (finding.language) {
      const language = document.createElement("span");
      language.className = "finding-quality";
      language.textContent = `Matched language rule: ${finding.language.toUpperCase()}`;
      row.append(language);
    }
    const reliability = finding.evidence_reliability;
    if (reliability) {
      const quality = document.createElement("span");
      quality.className = `finding-quality evidence-${reliability.level}`;
      quality.textContent = `Evidence reliability: ${reliability.level.toUpperCase()} — ${reliability.explanation}`;
      row.append(quality);
    }
    const action = document.createElement("span");
    action.className = "finding-action";
    action.textContent = finding.points > 0
      ? `Recommended action: ${recommendations[finding.category]}`
      : "No configured indicator matched. Independently verify unexpected requests.";
    row.append(action);
    findingsList.append(row);
  }

  resultCard.hidden = false;
  document.querySelector("#analysis-guidance").hidden = true;
  resultCard.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function requestJson(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (["POST", "PUT", "PATCH", "DELETE"].includes((options.method || "GET").toUpperCase()) && csrfToken) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  const response = await fetch(path, { ...options, headers });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "The analysis request failed.");
  return result;
}

async function activateAccount(user, csrf) {
  currentUser = user;
  csrfToken = csrf;
  document.querySelector("#app-shell").hidden = false;
  document.querySelector("#account-tools").hidden = false;
  document.querySelector("#account-label").textContent = `${user.username} · ${user.role}`;
  const canInvestigate = ["analyst", "admin"].includes(user.role);
  document.querySelector("#incident-card").hidden = !canInvestigate;
  document.querySelector("#overview-incidents-card").hidden = !canInvestigate;
  document.querySelector("#history-status-label").hidden = !canInvestigate;
  document.querySelector("#history-status-header").hidden = !canInvestigate;
  document.querySelectorAll(".analyst-nav").forEach((link) => { link.hidden = !canInvestigate; });
  document.querySelectorAll(".admin-nav").forEach((link) => { link.hidden = user.role !== "admin"; });
  document.querySelector("#admin-card").hidden = user.role !== "admin";
  document.querySelector("#feedback-panel").hidden = !canInvestigate;
  document.querySelector("#submit-feedback-button").hidden = !canInvestigate;
  document.querySelector("#create-incident-button").hidden = !canInvestigate;
  const integrations = await requestJson("/api/integrations");
  virusTotalConfigured = integrations.virustotal_configured;
  document.querySelector("#virustotal-opt-in").hidden = !virusTotalConfigured;
  document.querySelector("#virustotal-status").textContent = virusTotalConfigured
    ? "Configured · per-analysis opt-in"
    : "Not configured · set VIRUSTOTAL_API_KEY";
  await loadHistory();
  await loadAlerts();
  if (canInvestigate) await loadIncidents();
  if (user.role === "admin") await loadAdmin();
}

async function initializeApp() {
  try {
    const session = await requestJson("/api/session");
    if (session.user) {
      await activateAccount(session.user, session.csrf_token);
    } else {
      window.location.replace("/login");
    }
  } catch {
    window.location.replace("/login");
  }
}

function renderTrends(data) {
  const summary = data.totals;
  document.querySelector("#trend-summary").textContent =
    `${summary.messages} message${summary.messages === 1 ? "" : "s"} analyzed · ${summary.high} high risk · ${summary.suspicious} suspicious · ${summary.low} low risk · ${summary.legitimate} reviewed as legitimate · ${summary.urls} URL${summary.urls === 1 ? "" : "s"} found`;
  document.querySelector("#count-legitimate").textContent = data.reviewed.legitimate;
  const indicators = document.querySelector("#common-indicators");
  indicators.replaceChildren();
  if (!data.common_indicators.length) {
    const empty = document.createElement("li");
    empty.textContent = "No positive indicators recorded yet.";
    indicators.append(empty);
  }
  for (const entry of data.common_indicators) {
    const item = document.createElement("li");
    item.textContent = `${entry.indicator} · ${entry.count} match${entry.count === 1 ? "" : "es"}`;
    indicators.append(item);
  }
  const chart = document.querySelector("#trend-chart");
  chart.replaceChildren();
  const maximum = Math.max(1, ...data.points.map((point) => point.total));
  for (const point of data.points) {
    const column = document.createElement("div");
    column.className = "trend-column";
    column.setAttribute("role", "listitem");
    const date = point.period.length === 7 ? `${point.period}-01` : point.period;
    const labelDate = new Date(`${date}T00:00:00Z`).toLocaleDateString(undefined, {
      month: "short",
      day: data.period === "day" ? "numeric" : undefined,
      timeZone: "UTC",
    });
    column.setAttribute(
      "aria-label",
      `${point.period}: ${point.total} analyzed, ${point.high} high risk, ${point.suspicious} suspicious, ${point.low} low risk, ${point.legitimate} reviewed legitimate, ${point.urls} URLs`,
    );
    const count = document.createElement("span");
    count.className = "trend-count";
    count.textContent = point.total;
    const legitimateCount = document.createElement("span");
    legitimateCount.className = "trend-legitimate-count";
    legitimateCount.textContent = `${point.legitimate} legit`;
    const bar = document.createElement("div");
    bar.className = "trend-bar";
    for (const level of ["low", "suspicious", "high"]) {
      const segment = document.createElement("span");
      segment.className = `trend-segment trend-${level}`;
      segment.style.height = `${(point[level] / maximum) * 100}%`;
      segment.setAttribute("aria-hidden", "true");
      bar.append(segment);
    }
    const label = document.createElement("span");
    label.className = "trend-date";
    label.textContent = labelDate;
    label.title = point.period;
    column.append(count, bar, legitimateCount, label);
    chart.append(column);
  }
  const viewport = document.querySelector(".trend-chart-viewport");
  viewport.scrollLeft = viewport.scrollWidth;
}

async function loadTrends() {
  const period = document.querySelector("#trend-period").value;
  const data = await requestJson(`/api/trends?period=${encodeURIComponent(period)}`);
  renderTrends(data);
}

async function loadHistory() {
  try {
    const params = new URLSearchParams();
    const query = document.querySelector("#history-query").value.trim();
    const risk = document.querySelector("#history-risk").value;
    const status = document.querySelector("#history-status").value;
    const from = document.querySelector("#history-from").value;
    const to = document.querySelector("#history-to").value;
    if (query) params.set("q", query);
    if (risk) params.set("risk", risk);
    if (status) params.set("status", status);
    if (from) params.set("from", from);
    if (to) params.set("to", to);
    const queryString = params.toString();
    const suffix = queryString ? `?${queryString}` : "";
    const data = await requestJson(`/api/history${suffix}`);
    document.querySelector("#count-total").textContent = data.counts.total;
    document.querySelector("#count-high").textContent = data.counts.high;
    document.querySelector("#count-suspicious").textContent = data.counts.suspicious;
    document.querySelector("#count-low").textContent = data.counts.low;
    renderSeverityDistribution(data.counts);
    await loadTrends();
    await renderThreatDetections();
    document.querySelector("#history-match-count").textContent =
      `Showing ${data.reports.length} of ${data.matched} matching reports (latest 100); dashboard totals cover all reports.`;
    const rows = document.querySelector("#history-rows");
    rows.replaceChildren();
    if (data.reports.length === 0) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 8;
      cell.textContent = "No reports yet.";
      row.append(cell);
      rows.append(row);
      return;
    }
    for (const report of data.reports) {
      const row = document.createElement("tr");
      for (const value of [report.analyzed_at, report.subject, report.sender]) {
        const cell = document.createElement("td");
        cell.textContent = value;
        row.append(cell);
      }
      const levelCell = document.createElement("td");
      const levelBadge = document.createElement("span");
      levelBadge.className = `risk-badge risk-${report.level.toLowerCase()}`;
      levelBadge.textContent = report.level;
      levelCell.append(levelBadge);
      row.append(levelCell);
      const scoreCell = document.createElement("td");
      scoreCell.textContent = `${report.score}/100`;
      row.append(scoreCell);
      const statusCell = document.createElement("td");
      statusCell.textContent = report.status === "none" ? "—" : report.status;
      statusCell.hidden = !["analyst", "admin"].includes(currentUser?.role);
      row.append(statusCell);
      const feedbackCell = document.createElement("td");
      feedbackCell.textContent = report.feedback ? report.feedback.replace("_", " ") : "—";
      row.append(feedbackCell);
      const actions = document.createElement("td");
      const view = document.createElement("button");
      view.type = "button";
      view.className = "table-action";
      view.dataset.viewReport = report.id;
      view.textContent = "View";
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "table-action";
      remove.dataset.deleteReport = report.id;
      remove.textContent = "Delete";
      actions.append(view);
      if (currentUser?.role === "admin") {
        actions.append(document.createTextNode(" "), remove);
      }
      row.append(actions);
      rows.append(row);
    }
  } catch (error) {
    showError(error instanceof Error ? error.message : "Could not load analysis history.");
  }
}

async function renderThreatDetections() {
  const rows = document.querySelector("#threat-domain-rows");
  rows.replaceChildren();
  const { detections } = await requestJson("/api/threats");
  if (!detections.length) {
    const row = document.createElement("tr");
    const empty = document.createElement("td");
    empty.colSpan = 6;
    empty.textContent = "No suspicious domains detected yet.";
    row.append(empty);
    rows.append(row);
    return;
  }
  for (const detection of detections) {
    const row = document.createElement("tr");
    for (const value of [detection.domain, detection.reason]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    const riskCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `risk-badge risk-${detection.level.toLowerCase()}`;
    badge.textContent = detection.level;
    riskCell.append(badge);
    row.append(riskCell);
    const reputationCell = document.createElement("td");
    reputationCell.textContent = detection.virustotal
      ? `${detection.virustotal.reputation} · ${detection.virustotal.detection_count ?? "?"} detections`
      : "Not checked";
    row.append(reputationCell);
    for (const value of [detection.subject, detection.analyzed_at]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    rows.append(row);
  }
}

function renderSeverityDistribution(counts) {
  const total = counts.high + counts.suspicious + counts.low;
  const levels = [
    { key: "low", label: "Low", count: counts.low },
    { key: "suspicious", label: "Suspicious", count: counts.suspicious },
    { key: "high", label: "High", count: counts.high },
  ];
  const summary = document.querySelector("#severity-summary");
  const bar = document.querySelector("#severity-bar");
  summary.textContent = total === 0
    ? "No reports analyzed yet."
    : `${total} saved analysis report${total === 1 ? "" : "s"} · ${counts.high} high · ${counts.suspicious} suspicious · ${counts.low} low`;
  bar.setAttribute(
    "aria-label",
    total === 0
      ? "Severity distribution: no reports yet"
      : `Severity distribution: ${levels.map(({ label, count }) =>
        `${label} ${count} (${Math.round(count * 100 / total)}%)`).join(", ")}`,
  );

  for (const { key, count } of levels) {
    const percent = total === 0 ? 0 : Math.round(count * 100 / total);
    document.querySelector(`#severity-bar-${key}`).style.width = `${percent}%`;
    document.querySelector(`#severity-${key}-count`).textContent = count;
    document.querySelector(`#severity-${key}-percent`).textContent = `${percent}%`;
  }
}

async function loadAlerts() {
  const data = await requestJson("/api/alerts");
  const list = document.querySelector("#alerts-list");
  list.replaceChildren();
  const unacknowledged = data.alerts.filter((alert) => !alert.acknowledged_at).length;
  document.querySelector("#alert-count").textContent = `${unacknowledged} unacknowledged`;
  if (!data.alerts.length) {
    const empty = document.createElement("li");
    empty.className = "history-privacy";
    empty.textContent = "No high-risk alerts.";
    list.append(empty);
    return;
  }
  for (const alert of data.alerts) {
    const item = document.createElement("li");
    item.className = "workflow-item";
    const details = document.createElement("p");
    details.textContent = `${alert.message} ${alert.subject ? `Subject: ${alert.subject}. ` : ""}`;
    const status = document.createElement("span");
    status.className = "subtle";
    status.textContent = alert.acknowledged_at
      ? `Acknowledged ${alert.acknowledged_at} by ${alert.acknowledged_by || "another user"}`
      : `Created ${alert.created_at}`;
    details.append(status);
    item.append(details);
    if (!alert.acknowledged_at) {
      const acknowledge = document.createElement("button");
      acknowledge.type = "button";
      acknowledge.className = "table-action";
      acknowledge.dataset.ackAlert = alert.id;
      acknowledge.textContent = "Acknowledge";
      item.append(acknowledge);
    }
    list.append(item);
  }
}

async function loadIncidents() {
  const [incidentData, teamData] = await Promise.all([
    requestJson("/api/incidents"),
    requestJson("/api/team"),
  ]);
  const container = document.querySelector("#incidents-list");
  container.replaceChildren();
  incidentReportIds = new Set(incidentData.incidents.map((incident) => incident.report_id));
  const overview = document.querySelector("#overview-incidents");
  overview.replaceChildren();
  for (const incident of incidentData.incidents.slice(0, 4)) {
    const item = document.createElement("li");
    item.className = "workflow-item";
    const details = document.createElement("p");
    details.textContent = `${incident.subject || "(No subject)"} · ${incident.severity} severity · ${incident.status}`;
    const assignee = document.createElement("span");
    assignee.className = "subtle";
    assignee.textContent = `${incident.sender || "Unknown sender"} · ${incident.assignee || "Unassigned"} · Updated ${incident.updated_at}`;
    item.append(details, assignee);
    overview.append(item);
  }
  if (!incidentData.incidents.length) {
    const empty = document.createElement("li");
    empty.className = "history-privacy";
    empty.textContent = "No security incidents have been opened.";
    overview.append(empty);
  }
  if (!incidentData.incidents.length) {
    const empty = document.createElement("p");
    empty.className = "history-privacy";
    empty.textContent = "No incidents have been created.";
    container.append(empty);
    return;
  }
  for (const incident of incidentData.incidents) {
    const article = document.createElement("article");
    article.className = "incident-item";
    const heading = document.createElement("h3");
    heading.textContent = incident.subject || "(No subject)";
    const metadata = document.createElement("p");
    metadata.textContent = `${incident.severity} severity · report risk ${incident.level} (${incident.score}) · ${incident.sender || "Unknown sender"} · Report ${incident.report_id}`;
    const controls = document.createElement("div");
    controls.className = "incident-controls";
    const statusLabel = document.createElement("label");
    statusLabel.textContent = "Status";
    const statusSelect = document.createElement("select");
    statusSelect.dataset.incidentStatus = "";
    for (const [value, label] of [["open", "Open"], ["investigating", "Investigating"], ["resolved", "Resolved"], ["false_positive", "False Positive"]]) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = label;
      statusSelect.append(option);
    }
    statusSelect.value = incident.status;
    statusLabel.append(statusSelect);
    const severityLabel = document.createElement("label");
    severityLabel.textContent = "Case severity";
    const severitySelect = document.createElement("select");
    severitySelect.dataset.incidentSeverity = "";
    for (const [value, label] of [["low", "Low"], ["medium", "Medium"], ["high", "High"], ["critical", "Critical"]]) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = label;
      severitySelect.append(option);
    }
    severitySelect.value = incident.severity;
    severityLabel.append(severitySelect);
    const assigneeLabel = document.createElement("label");
    assigneeLabel.textContent = "Assigned analyst";
    const assigneeSelect = document.createElement("select");
    assigneeSelect.dataset.incidentAssignee = "";
    const unassigned = document.createElement("option");
    unassigned.value = "";
    unassigned.textContent = "Unassigned";
    assigneeSelect.append(unassigned);
    for (const person of teamData.users) {
      const option = document.createElement("option");
      option.value = person.id;
      option.textContent = `${person.username} (${person.role})`;
      assigneeSelect.append(option);
    }
    assigneeSelect.value = incident.assigned_to || "";
    assigneeLabel.append(assigneeSelect);
    const noteLabel = document.createElement("label");
    noteLabel.textContent = "Investigation note";
    const note = document.createElement("textarea");
    note.maxLength = 1000;
    note.value = incident.note;
    note.dataset.incidentNote = "";
    noteLabel.append(note);
    const save = document.createElement("button");
    save.type = "button";
    save.className = "secondary-button";
    save.dataset.saveIncident = incident.id;
    save.textContent = "Save incident";
    const timeline = document.createElement("ol");
    timeline.className = "incident-timeline";
    timeline.setAttribute("aria-label", "Incident evidence timeline");
    for (const event of incident.timeline || []) {
      const timelineEvent = document.createElement("li");
      const updateDetails = [
        event.status_updated ? `status: ${event.status}` : "",
        event.severity_updated ? `severity: ${event.severity}` : "",
        event.assignment_updated ? "assignee updated" : "",
        event.note_updated ? "investigation notes updated" : "",
      ].filter(Boolean).join(" · ");
      timelineEvent.textContent = `${event.created_at} · ${event.username} ${event.action === "incident.created" ? "created the incident" : `updated the incident${updateDetails ? ` · ${updateDetails}` : ""}`}`;
      timeline.append(timelineEvent);
    }
    if (!timeline.childElementCount) {
      const timelineEvent = document.createElement("li");
      timelineEvent.textContent = `Incident opened ${incident.created_at}`;
      timeline.append(timelineEvent);
    }
    controls.append(statusLabel, severityLabel, assigneeLabel, noteLabel, save);
    article.append(heading, metadata, timeline, controls);
    container.append(article);
  }
}

async function loadAdmin() {
  const [usersData, settingsData, auditData, feedbackData] = await Promise.all([
    requestJson("/api/admin/users"),
    requestJson("/api/admin/settings"),
    requestJson("/api/admin/audit"),
    requestJson("/api/admin/feedback"),
  ]);
  const usersRows = document.querySelector("#users-rows");
  usersRows.replaceChildren();
  for (const user of usersData.users) {
    const row = document.createElement("tr");
    row.dataset.userId = user.id;
    const username = document.createElement("td");
    username.textContent = user.username;
    const role = document.createElement("select");
    role.className = "user-role-select";
    role.dataset.userRole = "";
    for (const value of ["user", "analyst", "admin"]) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      role.append(option);
    }
    role.value = user.role;
    const roleCell = document.createElement("td");
    roleCell.append(role);
    const activeCell = document.createElement("td");
    const active = document.createElement("input");
    active.type = "checkbox";
    active.checked = Boolean(user.active);
    active.dataset.userActive = "";
    active.setAttribute("aria-label", `Active account for ${user.username}`);
    activeCell.append(active);
    const actionsCell = document.createElement("td");
    const password = document.createElement("input");
    password.type = "password";
    password.minLength = 12;
    password.maxLength = 1024;
    password.placeholder = "New password (optional)";
    password.dataset.userPassword = "";
    password.setAttribute("aria-label", `Reset password for ${user.username}`);
    const save = document.createElement("button");
    save.type = "button";
    save.className = "table-action";
    save.dataset.saveUser = user.id;
    save.textContent = "Save";
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "table-action";
    remove.dataset.deleteUser = user.id;
    remove.textContent = "Delete";
    actionsCell.append(password, document.createTextNode(" "), save, document.createTextNode(" "), remove);
    row.append(username, roleCell, activeCell, actionsCell);
    usersRows.append(row);
  }
  document.querySelector("#setting-alert-threshold").value = settingsData.settings.alert_threshold;
  document.querySelector("#setting-retention-days").value = settingsData.settings.retention_days;
  const auditRows = document.querySelector("#audit-rows");
  auditRows.replaceChildren();
  for (const entry of auditData.events) {
    const row = document.createElement("tr");
    for (const value of [entry.created_at, entry.username, entry.action, JSON.stringify(entry.details)]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    auditRows.append(row);
  }
  const reviewList = document.querySelector("#feedback-review-list");
  reviewList.replaceChildren();
  if (!feedbackData.feedback.length) {
    const empty = document.createElement("p");
    empty.className = "history-privacy";
    empty.textContent = "No analyst feedback is awaiting review.";
    reviewList.append(empty);
  }
  for (const item of feedbackData.feedback) {
    const card = document.createElement("article");
    card.className = "incident-item feedback-review-item";
    card.dataset.reportId = item.report_id;
    const heading = document.createElement("h4");
    heading.textContent = `${item.subject} · ${item.classification.replaceAll("_", " ")}`;
    const details = document.createElement("p");
    details.textContent = `Risk ${item.level} (${item.score}) · ${item.submitted_by} · ${item.submitted_at}`;
    const reason = document.createElement("p");
    reason.textContent = `Analyst reason: ${item.note}`;
    card.append(heading, details, reason);
    if (item.decision) {
      const decision = document.createElement("p");
      decision.textContent = `Reviewed ${item.decision} by ${item.reviewer || "administrator"} on ${item.reviewed_at}${item.adjusted_indicator ? ` · ${item.adjusted_indicator} ${item.points_delta > 0 ? "+" : ""}${item.points_delta}` : ""}${item.review_note ? ` · ${item.review_note}` : ""}`;
      card.append(decision);
    } else {
      const controls = document.createElement("div");
      controls.className = "incident-controls";
      const indicatorLabel = document.createElement("label");
      indicatorLabel.textContent = "Matched rule to adjust";
      const indicator = document.createElement("select");
      indicator.dataset.reviewIndicator = "";
      const placeholder = document.createElement("option");
      placeholder.value = "";
      placeholder.textContent = item.indicators.length ? "Select a matched indicator" : "No positive indicator available";
      indicator.append(placeholder);
      for (const match of item.indicators) {
        const option = document.createElement("option");
        option.value = match.indicator;
        option.textContent = `${match.indicator} (${match.points} points)`;
        indicator.append(option);
      }
      indicator.disabled = item.indicators.length === 0;
      indicatorLabel.append(indicator);
      const deltaLabel = document.createElement("label");
      deltaLabel.textContent = "Points adjustment for future analyses";
      const delta = document.createElement("select");
      delta.dataset.reviewDelta = "";
      const deltaPlaceholder = document.createElement("option");
      deltaPlaceholder.value = "";
      deltaPlaceholder.textContent = "Choose adjustment";
      delta.append(deltaPlaceholder);
      for (const value of [-25, -10, -5, 5, 10, 25]) {
        const option = document.createElement("option");
        option.value = String(value);
        option.textContent = `${value > 0 ? "+" : ""}${value}`;
        delta.append(option);
      }
      deltaLabel.append(delta);
      const noteLabel = document.createElement("label");
      noteLabel.textContent = "Administrator review note";
      const note = document.createElement("input");
      note.maxLength = 1000;
      note.dataset.reviewNote = "";
      noteLabel.append(note);
      const approve = document.createElement("button");
      approve.type = "button";
      approve.className = "secondary-button";
      approve.dataset.feedbackDecision = "approved";
      approve.disabled = item.indicators.length === 0;
      approve.textContent = "Approve adjustment";
      const reject = document.createElement("button");
      reject.type = "button";
      reject.className = "secondary-button";
      reject.dataset.feedbackDecision = "rejected";
      reject.textContent = "Review; do not adjust";
      controls.append(indicatorLabel, deltaLabel, noteLabel, approve, reject);
      card.append(controls);
    }
    reviewList.append(card);
  }
  const ruleList = document.querySelector("#rule-adjustments-list");
  ruleList.replaceChildren();
  if (!feedbackData.rule_adjustments.length) {
    const empty = document.createElement("li");
    empty.textContent = "No approved rule adjustments.";
    ruleList.append(empty);
  }
  for (const adjustment of feedbackData.rule_adjustments) {
    const entry = document.createElement("li");
    entry.textContent = `${adjustment.indicator}: ${adjustment.points_delta > 0 ? "+" : ""}${adjustment.points_delta} points`;
    ruleList.append(entry);
  }
}

document.querySelector("#logout-button").addEventListener("click", async () => {
  clearError();
  try {
    await requestJson("/api/logout", { method: "POST" });
    currentUser = null;
    csrfToken = null;
    window.location.replace("/login");
  } catch (error) {
    showError(error instanceof Error ? error.message : "Could not sign out.");
  }
});

document.querySelector("#user-create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = document.querySelector("#user-create-button");
  const status = document.querySelector("#user-create-status");
  status.hidden = true;
  status.setAttribute("role", "status");
  status.classList.remove("is-success");
  status.textContent = "";
  button.disabled = true;
  button.textContent = "Creating account…";
  try {
    await requestJson("/api/admin/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.querySelector("#new-username").value,
        password: document.querySelector("#new-password").value,
        role: document.querySelector("#new-role").value,
      }),
    });
    form.reset();
    status.textContent = "Account created successfully. It is now available in the user list.";
    status.classList.add("is-success");
    status.hidden = false;
    try {
      await loadAdmin();
      await loadIncidents();
    } catch (error) {
      status.textContent = `Account created, but the user list could not be refreshed. ${error instanceof Error ? error.message : ""}`.trim();
      status.classList.remove("is-success");
      status.setAttribute("role", "alert");
    }
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "Could not create user.";
    status.hidden = false;
    status.setAttribute("role", "alert");
  } finally {
    button.disabled = false;
    button.textContent = "Create account";
  }
});

document.querySelector("#settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError();
  try {
    await requestJson("/api/admin/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        alert_threshold: Number(document.querySelector("#setting-alert-threshold").value),
        retention_days: Number(document.querySelector("#setting-retention-days").value),
      }),
    });
    await loadAdmin();
  } catch (error) {
    showError(error instanceof Error ? error.message : "Could not save policies.");
  }
});

document.querySelector("#users-rows").addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLButtonElement)) return;
  const userId = target.closest("tr")?.dataset.userId;
  if (!userId) return;
  clearError();
  try {
    if (target.dataset.saveUser) {
      const row = target.closest("tr");
      const password = row.querySelector("[data-user-password]").value;
      const payload = {
        role: row.querySelector("[data-user-role]").value,
        active: row.querySelector("[data-user-active]").checked,
      };
      if (password) payload.password = password;
      await requestJson(`/api/admin/users/${encodeURIComponent(userId)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      await loadAdmin();
      await loadIncidents();
    } else if (target.dataset.deleteUser && window.confirm("Permanently delete this user?")) {
      await requestJson(`/api/admin/users/${encodeURIComponent(userId)}`, { method: "DELETE" });
      await loadAdmin();
      await loadIncidents();
    }
  } catch (error) {
    showError(error instanceof Error ? error.message : "Could not update the user.");
  }
});

document.querySelector("#feedback-review-list").addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLButtonElement) || !target.dataset.feedbackDecision) return;
  const card = target.closest(".feedback-review-item");
  const payload = {
    report_id: card.dataset.reportId,
    decision: target.dataset.feedbackDecision,
    note: card.querySelector("[data-review-note]").value,
  };
  if (payload.decision === "approved") {
    payload.indicator = card.querySelector("[data-review-indicator]").value;
    payload.points_delta = Number(card.querySelector("[data-review-delta]").value);
  }
  clearError();
  target.disabled = true;
  try {
    await requestJson("/api/admin/feedback/review", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    await loadAdmin();
  } catch (error) {
    target.disabled = false;
    showError(error instanceof Error ? error.message : "Could not review analyst feedback.");
  }
});

document.querySelector("#alerts-list").addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLButtonElement) || !target.dataset.ackAlert) return;
  clearError();
  try {
    await requestJson("/api/alerts/ack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert_id: target.dataset.ackAlert }),
    });
    await loadAlerts();
    if (currentUser?.role === "admin") await loadAdmin();
  } catch (error) {
    showError(error instanceof Error ? error.message : "Could not acknowledge this alert.");
  }
});

document.querySelector("#incidents-list").addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLButtonElement) || !target.dataset.saveIncident) return;
  const card = target.closest(".incident-item");
  clearError();
  try {
    await requestJson(`/api/incidents/${encodeURIComponent(target.dataset.saveIncident)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        status: card.querySelector("[data-incident-status]").value,
        severity: card.querySelector("[data-incident-severity]").value,
        assigned_to: card.querySelector("[data-incident-assignee]").value || null,
        note: card.querySelector("[data-incident-note]").value,
      }),
    });
    await loadIncidents();
    if (currentUser?.role === "admin") await loadAdmin();
  } catch (error) {
    showError(error instanceof Error ? error.message : "Could not update the incident.");
  }
});

document.querySelector("#create-incident-button").addEventListener("click", async () => {
  clearError();
  if (!currentReportId) {
    showError("Open a saved report before creating an incident.");
    return;
  }
  try {
    await requestJson("/api/incidents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ report_id: currentReportId }),
    });
    await loadIncidents();
    document.querySelector("#create-incident-button").disabled = true;
    document.querySelector("#create-incident-button").textContent = "Incident already created";
    if (currentUser?.role === "admin") await loadAdmin();
  } catch (error) {
    showError(error instanceof Error ? error.message : "Could not create an incident.");
  }
});

document.querySelector("#trend-period").addEventListener("change", async () => {
  clearError();
  try {
    await loadTrends();
  } catch (error) {
    showError(error instanceof Error ? error.message : "Could not load trend data.");
  }
});

previewButton.addEventListener("click", async () => {
  clearError();
  const input = getEmailInput();
  const { email } = input;
  if (!email.trim()) {
    showError("Email content is empty. Paste a message or choose a non-empty file.");
    return;
  }
  if (new TextEncoder().encode(email).length > 10 * 1024 * 1024) {
    showError("Email text exceeds the 10 MB limit.");
    return;
  }
  previewButton.disabled = true;
  previewButton.textContent = "Extracting…";
  try {
    const data = await requestJson("/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
    previewedInput = input;
    renderPreview(data);
  } catch (error) {
    showError(error instanceof Error ? error.message : "Could not extract email details.");
  } finally {
    previewButton.disabled = false;
    previewButton.textContent = "Preview extracted details";
  }
});

document.querySelector("#history-filter").addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError();
  await loadHistory();
});

document.querySelector("#reset-history-filter").addEventListener("click", async () => {
  document.querySelector("#history-filter").reset();
  clearError();
  await loadHistory();
});

document.querySelector("#submit-feedback-button").addEventListener("click", async () => {
  clearError();
  const note = document.querySelector("#feedback-note").value.trim();
  if (!currentReportId) {
    showError("Analyze or open a saved report before submitting analyst feedback.");
    return;
  }
  if (!note) {
    showError("Enter the evidence-based reason for this classification.");
    return;
  }
  const button = document.querySelector("#submit-feedback-button");
  button.disabled = true;
  try {
    const feedback = await requestJson(
      `/api/report/${encodeURIComponent(currentReportId)}/feedback`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          classification: document.querySelector("#feedback-classification").value,
          note,
        }),
      },
    );
    document.querySelector("#feedback-status").textContent =
      `Recorded ${feedback.classification.replaceAll("_", " ")} by analyst on ${feedback.submitted_at}. Awaiting administrator review.`;
    document.querySelector("#feedback-status").classList.add("feedback-confirmed");
    await loadHistory();
    if (currentUser?.role === "admin") await loadAdmin();
  } catch (error) {
    showError(error instanceof Error ? error.message : "Could not save analyst feedback.");
  } finally {
    button.disabled = false;
  }
});

analyzeButton.addEventListener("click", async () => {
  clearError();
  const input = getEmailInput();
  const email = input.email;
  if (JSON.stringify(previewedInput) !== JSON.stringify(input)) {
    analyzeButton.disabled = true;
    previewCard.hidden = true;
    showError("Preview the current email before analyzing it.");
    return;
  }
  analyzeButton.disabled = true;
  analyzeButton.textContent = "Analyzing…";
  try {
    const result = await requestJson("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...input,
        check_reputation: virusTotalConfigured && document.querySelector("#check-reputation").checked,
      }),
    });
    renderResult(result);
    await loadHistory();
    await loadAlerts();
    if (["analyst", "admin"].includes(currentUser?.role)) await loadIncidents();
    if (currentUser?.role === "admin") await loadAdmin();
  } catch (error) {
    showError(error instanceof Error ? error.message : "The analyzer could not be reached.");
  } finally {
    analyzeButton.disabled = false;
    analyzeButton.textContent = "Analyze and save report";
    document.querySelector("#check-reputation").checked = false;
  }
});

emailInput.addEventListener("input", () => {
  previewedInput = null;
  analyzeButton.disabled = true;
  previewCard.hidden = true;
  resultCard.hidden = true;
  document.querySelector("#analysis-guidance").hidden = false;
});

for (const input of [subjectInput, fromInput, toInput, replyToInput]) {
  input.addEventListener("input", () => {
    previewedInput = null;
    analyzeButton.disabled = true;
    previewCard.hidden = true;
    resultCard.hidden = true;
    document.querySelector("#analysis-guidance").hidden = false;
  });
}

async function loadEmailFile(file) {
  clearError();
  if (!file) return;
  if (!file.name.toLowerCase().endsWith(".eml") && !file.name.toLowerCase().endsWith(".txt")) {
    fileInput.value = "";
    showError("Choose a .eml or .txt file. Images and other formats are not supported.");
    return;
  }
  if (file.size > 10 * 1024 * 1024) {
    fileInput.value = "";
    showError("Please choose an email or text file no larger than 10 MB.");
    return;
  }
  try {
    emailInput.value = await file.text();
    fileName.textContent = `Loaded: ${file.name} (${file.size.toLocaleString()} bytes)`;
    previewedInput = null;
    analyzeButton.disabled = true;
    previewCard.hidden = true;
    resultCard.hidden = true;
    document.querySelector("#analysis-guidance").hidden = false;
  } catch {
    showError("Could not read that file. Choose a UTF-8 .eml or .txt file.");
  }
}

fileInput.addEventListener("change", () => {
  void loadEmailFile(fileInput.files?.[0]);
});

const inputCard = document.querySelector(".input-card");
for (const eventName of ["dragenter", "dragover"]) {
  inputCard.addEventListener(eventName, (event) => {
    event.preventDefault();
    inputCard.classList.add("is-dragging");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  inputCard.addEventListener(eventName, (event) => {
    event.preventDefault();
    inputCard.classList.remove("is-dragging");
  });
}
inputCard.addEventListener("drop", (event) => {
  const file = event.dataTransfer?.files?.[0];
  if (file) void loadEmailFile(file);
});

document.querySelector("#history-rows").addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLButtonElement)) return;
  try {
    if (target.dataset.viewReport) {
      const report = await requestJson(`/api/report/${encodeURIComponent(target.dataset.viewReport)}`);
      renderResult(report);
    } else if (target.dataset.deleteReport && window.confirm("Delete this saved report?")) {
      await requestJson(`/api/report/${encodeURIComponent(target.dataset.deleteReport)}`, { method: "DELETE" });
      await loadHistory();
      await loadAlerts();
      if (["analyst", "admin"].includes(currentUser?.role)) await loadIncidents();
      if (currentUser?.role === "admin") await loadAdmin();
      if (document.querySelector("#report-date").textContent.includes(target.dataset.deleteReport)) {
        resultCard.hidden = true;
        currentReportId = null;
      }
    }
  } catch (error) {
    showError(error instanceof Error ? error.message : "Could not update analysis history.");
  }
});

document.querySelector("#clear-button").addEventListener("click", () => {
  emailInput.value = "";
  subjectInput.value = "";
  fromInput.value = "";
  toInput.value = "";
  replyToInput.value = "";
  fileInput.value = "";
  fileName.textContent = "No file selected. Images are not supported.";
  previewedInput = null;
  analyzeButton.disabled = true;
  previewCard.hidden = true;
  resultCard.hidden = true;
  document.querySelector("#analysis-guidance").hidden = false;
  clearError();
});

whatsappZipInput.addEventListener("change", () => {
  const error = document.querySelector("#whatsapp-review-error");
  error.hidden = true;
  const file = whatsappZipInput.files?.[0];
  if (!file) {
    document.querySelector("#whatsapp-zip-name").textContent = "No ZIP selected.";
    return;
  }
  if (!file.name.toLowerCase().endsWith(".zip")) {
    whatsappZipInput.value = "";
    document.querySelector("#whatsapp-zip-name").textContent = "No ZIP selected.";
    error.textContent = "Choose a .zip archive.";
    error.hidden = false;
    return;
  }
  if (file.size > 10 * 1024 * 1024) {
    whatsappZipInput.value = "";
    document.querySelector("#whatsapp-zip-name").textContent = "No ZIP selected.";
    error.textContent = "ZIP files must be 10 MB or smaller.";
    error.hidden = false;
    return;
  }
  document.querySelector("#whatsapp-zip-name").textContent =
    `Selected: ${file.name} (${file.size.toLocaleString()} bytes)`;
});

whatsappReviewForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = document.querySelector("#whatsapp-review-error");
  error.hidden = true;
  const message = whatsappMessageInput.value;
  if (!message.trim()) {
    error.textContent = "Paste the suspicious WhatsApp message before reviewing.";
    error.hidden = false;
    return;
  }
  if (new TextEncoder().encode(message).length > 100 * 1024) {
    error.textContent = "WhatsApp message text must be 100 KB or smaller.";
    error.hidden = false;
    return;
  }

  const button = document.querySelector("#whatsapp-review-button");
  button.disabled = true;
  button.textContent = "Reviewing safely…";
  try {
    const zipFile = whatsappZipInput.files?.[0];
    const payload = { message, zip_filename: "", zip_base64: "" };
    if (zipFile) {
      payload.zip_filename = zipFile.name;
      payload.zip_base64 = toBase64(new Uint8Array(await zipFile.arrayBuffer()));
    }
    const report = await requestJson("/api/whatsapp/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    renderWhatsappReview(report);
    try {
      await loadHistory();
      await loadAlerts();
    } catch (refreshError) {
      error.textContent = `Review saved, but dashboard data could not refresh: ${refreshError instanceof Error ? refreshError.message : "unknown error"}`;
      error.hidden = false;
    }
  } catch (reviewError) {
    error.textContent = reviewError instanceof Error ? reviewError.message : "Could not review this WhatsApp message.";
    error.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = "Review message and ZIP";
  }
});

document.querySelector("#whatsapp-clear-button").addEventListener("click", () => {
  whatsappReviewForm.reset();
  document.querySelector("#whatsapp-zip-name").textContent = "No ZIP selected.";
  document.querySelector("#whatsapp-review-result").hidden = true;
  document.querySelector("#whatsapp-review-error").hidden = true;
});

screenshotFileInput.addEventListener("change", () => {
  const error = document.querySelector("#screenshot-ocr-error");
  error.hidden = true;
  document.querySelector("#screenshot-analyze-error").hidden = true;
  document.querySelector("#screenshot-text-review").hidden = true;
  document.querySelector("#screenshot-analyze-button").disabled = true;
  screenshotOcrText.value = "";
  screenshotFilename = "";
  resetScreenshotPreview();
  const file = screenshotFileInput.files?.[0];
  if (!file) {
    document.querySelector("#screenshot-file-name").textContent = "No screenshot selected.";
    document.querySelector("#screenshot-ocr-button").disabled = true;
    return;
  }
  const allowedTypes = new Set(["image/png", "image/jpeg", "image/webp", "image/bmp"]);
  const allowedExtensions = /\.(png|jpe?g|webp|bmp)$/i;
  if (!allowedExtensions.test(file.name) || (file.type && !allowedTypes.has(file.type))) {
    screenshotFileInput.value = "";
    document.querySelector("#screenshot-file-name").textContent = "No screenshot selected.";
    document.querySelector("#screenshot-ocr-button").disabled = true;
    error.textContent = "Choose a PNG, JPEG, WebP, or BMP screenshot.";
    error.hidden = false;
    return;
  }
  if (file.size > 5 * 1024 * 1024) {
    screenshotFileInput.value = "";
    document.querySelector("#screenshot-file-name").textContent = "No screenshot selected.";
    document.querySelector("#screenshot-ocr-button").disabled = true;
    error.textContent = "Screenshot images must be 5 MB or smaller.";
    error.hidden = false;
    return;
  }
  screenshotFilename = file.name;
  document.querySelector("#screenshot-file-name").textContent =
    `Selected: ${file.name} (${file.size.toLocaleString()} bytes)`;
  screenshotPreviewUrl = URL.createObjectURL(file);
  const preview = document.querySelector("#screenshot-preview");
  preview.src = screenshotPreviewUrl;
  preview.hidden = false;
  document.querySelector("#screenshot-ocr-button").disabled = false;
});

document.querySelector("#screenshot-ocr-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = document.querySelector("#screenshot-ocr-error");
  error.hidden = true;
  const file = screenshotFileInput.files?.[0];
  if (!file) {
    error.textContent = "Choose a screenshot before extracting text.";
    error.hidden = false;
    return;
  }
  const button = document.querySelector("#screenshot-ocr-button");
  button.disabled = true;
  button.textContent = "Extracting locally…";
  try {
    const imageBytes = new Uint8Array(await file.arrayBuffer());
    const ocr = await requestJson("/api/screenshot/ocr", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename: file.name, image_base64: toBase64(imageBytes) }),
    });
    screenshotFilename = ocr.filename;
    screenshotOcrText.value = ocr.text;
    document.querySelector("#screenshot-ocr-summary").textContent =
      `${ocr.format} · ${ocr.width} × ${ocr.height} pixels · ${ocr.word_count} words · average OCR confidence ${ocr.confidence === null ? "unavailable" : `${ocr.confidence}%`}. Confidence is approximate, not a safety score.`;
    document.querySelector("#screenshot-text-review").hidden = false;
    document.querySelector("#screenshot-analyze-button").disabled = !ocr.text.trim();
  } catch (ocrError) {
    error.textContent = ocrError instanceof Error ? ocrError.message : "Local OCR could not process this screenshot.";
    error.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = "Extract text locally";
  }
});

screenshotOcrText.addEventListener("input", () => {
  document.querySelector("#screenshot-analyze-button").disabled = !screenshotOcrText.value.trim();
  document.querySelector("#screenshot-analyze-error").hidden = true;
});

document.querySelector("#screenshot-analyze-button").addEventListener("click", async () => {
  const error = document.querySelector("#screenshot-analyze-error");
  error.hidden = true;
  const text = screenshotOcrText.value;
  if (!text.trim()) {
    error.textContent = "Review or enter the screenshot text before analyzing it.";
    error.hidden = false;
    return;
  }
  if (new TextEncoder().encode(text).length > 100 * 1024) {
    error.textContent = "Screenshot text must be 100 KB or smaller.";
    error.hidden = false;
    return;
  }
  const button = document.querySelector("#screenshot-analyze-button");
  button.disabled = true;
  button.textContent = "Analyzing reviewed text…";
  try {
    const report = await requestJson("/api/screenshot/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename: screenshotFilename, text }),
    });
    renderResult(report);
    await loadHistory();
    await loadAlerts();
    if (["analyst", "admin"].includes(currentUser?.role)) await loadIncidents();
    if (currentUser?.role === "admin") await loadAdmin();
  } catch (analysisError) {
    error.textContent = analysisError instanceof Error ? analysisError.message : "Could not analyze the reviewed screenshot text.";
    error.hidden = false;
  } finally {
    button.disabled = !screenshotOcrText.value.trim();
    button.textContent = "Analyze reviewed text";
  }
});

document.querySelector("#screenshot-clear-button").addEventListener("click", () => {
  screenshotFileInput.value = "";
  screenshotFilename = "";
  screenshotOcrText.value = "";
  document.querySelector("#screenshot-file-name").textContent = "No screenshot selected.";
  document.querySelector("#screenshot-ocr-button").disabled = true;
  document.querySelector("#screenshot-analyze-button").disabled = true;
  document.querySelector("#screenshot-text-review").hidden = true;
  document.querySelector("#screenshot-ocr-error").hidden = true;
  document.querySelector("#screenshot-analyze-error").hidden = true;
  resetScreenshotPreview();
});

initializeApp();
