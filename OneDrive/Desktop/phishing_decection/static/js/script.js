const els = {
    apiHealth: document.getElementById("api-health"),
    modelHealth: document.getElementById("model-health"),
    authName: document.getElementById("auth-name"),
    authEmail: document.getElementById("auth-email"),
    authPassword: document.getElementById("auth-password"),
    registerBtn: document.getElementById("register-btn"),
    loginBtn: document.getElementById("login-btn"),
    authStatus: document.getElementById("auth-status"),
    urlInput: document.getElementById("url-input"),
    checkBtn: document.getElementById("check-btn"),
    pasteBtn: document.getElementById("paste-btn"),
    sampleSafeBtn: document.getElementById("sample-safe-btn"),
    samplePhishBtn: document.getElementById("sample-phish-btn"),
    loading: document.getElementById("loading"),
    errorSection: document.getElementById("error-section"),
    errorMessage: document.getElementById("error-message"),
    liveStatus: document.getElementById("live-status"),
    verdictText: document.getElementById("verdict-text"),
    domainTitle: document.getElementById("domain-title"),
    recommendationValue: document.getElementById("recommendation-value"),
    confidenceValue: document.getElementById("confidence-value"),
    riskRing: document.getElementById("risk-ring"),
    riskBar: document.getElementById("risk-bar"),
    riskValue: document.getElementById("risk-value"),
    riskLevelValue: document.getElementById("risk-level-value"),
    favicon: document.getElementById("favicon"),
    faviconDomain: document.getElementById("favicon-domain"),
    sourceValue: document.getElementById("source-value"),
    registrarValue: document.getElementById("registrar-value"),
    countryValue: document.getElementById("country-value"),
    domainAgeValue: document.getElementById("domain-age-value"),
    sslValue: document.getElementById("ssl-value"),
    redirectValue: document.getElementById("redirect-value"),
    timestampValue: document.getElementById("timestamp-value"),
    analysisList: document.getElementById("analysis-list"),
    actionsList: document.getElementById("actions-list"),
    exportPdfBtn: document.getElementById("export-pdf-btn"),
    shareReportBtn: document.getElementById("share-report-btn"),
    featureLength: document.getElementById("feature-length"),
    featureSubdomains: document.getElementById("feature-subdomains"),
    mlProbabilityValue: document.getElementById("ml-probability-value"),
    mlConfidenceValue: document.getElementById("ml-confidence-value"),
    emailContent: document.getElementById("email-content"),
    emailAnalyzeBtn: document.getElementById("email-analyze-btn"),
    emailResult: document.getElementById("email-result"),
    bulkContent: document.getElementById("bulk-content"),
    bulkScanBtn: document.getElementById("bulk-scan-btn"),
    bulkResults: document.getElementById("bulk-results"),
    historySearch: document.getElementById("history-search"),
    refreshHistoryBtn: document.getElementById("refresh-history-btn"),
    historyList: document.getElementById("history-list"),
    totalScans: document.getElementById("total-scans"),
    safeScans: document.getElementById("safe-scans"),
    suspiciousScans: document.getElementById("suspicious-scans"),
    phishingScans: document.getElementById("phishing-scans"),
    liveThreatCounter: document.getElementById("live-threat-counter"),
    heroF1: document.getElementById("hero-f1"),
    metricAccuracy: document.getElementById("metric-accuracy"),
    metricPrecision: document.getElementById("metric-precision"),
    metricRecall: document.getElementById("metric-recall"),
    metricF1: document.getElementById("metric-f1"),
    metricAuc: document.getElementById("metric-auc"),
    metricVersion: document.getElementById("metric-version"),
    confusionMatrix: document.getElementById("confusion-matrix"),
};

const samples = {
    safe: "https://www.google.com",
    phishing: "https://google.com@secure-login-google.com/verify/account",
};

let token = localStorage.getItem("phishguard_token") || "";
let lastResult = null;
let debounceTimer = null;

document.addEventListener("DOMContentLoaded", () => {
    updateAuthStatus();
    checkHealth();
    loadModelPerformance();
    loadHistory();
});

els.registerBtn.addEventListener("click", () => authRequest("register"));
els.loginBtn.addEventListener("click", () => authRequest("login"));
els.checkBtn.addEventListener("click", () => scanUrl(true));
els.sampleSafeBtn.addEventListener("click", () => {
    els.urlInput.value = samples.safe;
    scanUrl(true);
});
els.samplePhishBtn.addEventListener("click", () => {
    els.urlInput.value = samples.phishing;
    scanUrl(true);
});
els.pasteBtn.addEventListener("click", pasteUrl);
els.urlInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") scanUrl(true);
});
els.urlInput.addEventListener("input", () => {
    clearTimeout(debounceTimer);
    hideError();
    if (els.urlInput.value.trim().length < 8) {
        setLiveStatus("Idle", false);
        return;
    }
    setLiveStatus("Watching", true);
    debounceTimer = setTimeout(() => scanUrl(false), 900);
});
els.exportPdfBtn.addEventListener("click", downloadPdf);
els.shareReportBtn.addEventListener("click", shareReport);
els.emailAnalyzeBtn.addEventListener("click", analyzeEmail);
els.bulkScanBtn.addEventListener("click", bulkScan);
els.refreshHistoryBtn.addEventListener("click", loadHistory);
els.historySearch.addEventListener("input", () => loadHistory(els.historySearch.value.trim()));

async function api(path, options = {}) {
    const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
    if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetch(path, { ...options, headers });
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
        const body = await response.json();
        if (!response.ok || body.success === false) throw new Error(body.error || body.message || "Request failed");
        return body;
    }
    if (!response.ok) throw new Error("Request failed");
    return response;
}

async function authRequest(mode) {
    try {
        const body = {
            name: els.authName.value.trim() || "PhishGuard User",
            email: els.authEmail.value.trim(),
            password: els.authPassword.value,
        };
        const result = await api(`/api/v1/auth/${mode}`, { method: "POST", body: JSON.stringify(body) });
        token = result.data.token;
        localStorage.setItem("phishguard_token", token);
        els.authStatus.textContent = `${result.data.user.email} (${result.data.user.role})`;
        await loadHistory();
    } catch (error) {
        showError(error.message);
    }
}

function updateAuthStatus() {
    els.authStatus.textContent = token ? "Authenticated session" : "Guest mode";
}

async function checkHealth() {
    try {
        const data = await fetch("/api/v1/health").then((res) => res.json());
        els.apiHealth.textContent = data.status === "healthy" ? "API Online" : "API Degraded";
        els.modelHealth.textContent = data.model_loaded ? "ML model loaded" : "Rule engine mode";
    } catch {
        els.apiHealth.textContent = "API Offline";
        els.modelHealth.textContent = "Unable to connect";
    }
}

async function loadModelPerformance() {
    try {
        const { data } = await api("/api/v1/model/performance");
        els.metricAccuracy.textContent = percent(data.accuracy);
        els.metricPrecision.textContent = percent(data.precision);
        els.metricRecall.textContent = percent(data.recall);
        els.metricF1.textContent = percent(data.f1_score);
        els.heroF1.textContent = data.f1_score.toFixed(2);
        els.metricAuc.textContent = percent(data.roc_auc);
        els.metricVersion.textContent = data.model_version;
        els.confusionMatrix.textContent = JSON.stringify(data.confusion_matrix, null, 2);
    } catch {
        els.confusionMatrix.textContent = "Model metrics unavailable.";
    }
}

async function scanUrl(immediate) {
    const url = els.urlInput.value.trim();
    if (!url) {
        showError("Enter a URL to scan.");
        return;
    }

    setLoading(true);
    setLiveStatus(immediate ? "Scanning" : "Live scan", true);
    try {
        const { data } = await api("/api/v1/scan", {
            method: "POST",
            body: JSON.stringify({ url }),
        });
        showResult(normalizeResult(data, url));
        await loadHistory();
        setLiveStatus("Complete", false);
    } catch (error) {
        showError(error.message);
        setLiveStatus("Failed", false);
    } finally {
        setLoading(false);
    }
}

function normalizeResult(data, originalUrl) {
    const detail = data.details || data;
    return {
        ...detail,
        url: originalUrl,
        verdict: data.verdict || data.status || detail.verdict,
        confidence: data.confidence || detail.confidence,
        risk_score: data.risk_score || detail.risk_score,
        riskScore: Number(data.risk_score || detail.risk_score || 0),
        riskLevel: data.risk_level || detail.risk_level || "LOW",
        domain: data.domain || detail.domain,
        analysis: data.reasons || detail.analysis || [],
        domainInfo: detail.domain_info || {},
        recommendedActions: data.recommendations || detail.recommended_actions || [],
        redirectAnalysis: detail.redirect_analysis || {},
        sslVerification: detail.ssl_verification || {},
        features: detail.features || {},
        timestampDisplay: detail.timestamp ? new Date(detail.timestamp).toLocaleString() : new Date().toLocaleString(),
    };
}

function showResult(result) {
    lastResult = result;
    const verdict = result.verdict || "safe";
    els.verdictText.textContent = verdict.toUpperCase();
    els.verdictText.className = `verdict-badge ${verdict}`;
    els.domainTitle.textContent = result.domain || "-";
    els.recommendationValue.textContent = result.recommendation || "Review before opening.";
    els.confidenceValue.textContent = `${Math.round(result.confidence || 0)}%`;
    els.riskValue.textContent = `${result.riskScore}/100`;
    els.riskLevelValue.textContent = result.riskLevel;
    els.sourceValue.textContent = result.source || "-";
    els.favicon.src = result.favicon || "";
    els.faviconDomain.textContent = result.domain || "-";
    els.registrarValue.textContent = result.domainInfo.registrar || "Not available";
    els.countryValue.textContent = result.domainInfo.country || "Not available";
    els.domainAgeValue.textContent = result.domainInfo.domain_age || "Not available";
    els.sslValue.textContent = formatSsl(result.sslVerification);
    els.redirectValue.textContent = formatRedirect(result.redirectAnalysis);
    els.timestampValue.textContent = result.timestampDisplay;
    els.featureLength.textContent = result.features.url_length ?? 0;
    els.featureSubdomains.textContent = result.features.subdomains ?? 0;
    els.mlProbabilityValue.textContent = `${result.ml_probability || 0}%`;
    els.mlConfidenceValue.textContent = `${result.ml_confidence || 0}%`;

    const riskColor = verdict === "phishing" ? "var(--red)" : verdict === "suspicious" ? "var(--yellow)" : "var(--green)";
    els.riskRing.style.setProperty("--risk", result.confidence || 0);
    els.riskRing.style.setProperty("--ring-color", riskColor);
    els.riskBar.style.width = `${result.riskScore}%`;
    els.riskBar.style.background = `linear-gradient(90deg, ${riskColor}, var(--cyan))`;
    renderList(els.analysisList, result.analysis?.length ? result.analysis : ["No suspicious indicators detected"]);
    renderList(els.actionsList, result.recommendedActions.length ? result.recommendedActions : ["Use normal caution."]);
}

async function analyzeEmail() {
    try {
        const { data } = await api("/api/v1/email/analyze", {
            method: "POST",
            body: JSON.stringify({ content: els.emailContent.value }),
        });
        els.emailResult.innerHTML = `<strong>${escapeHtml(data.verdict.toUpperCase())} - ${data.risk_score}/100</strong><br>${escapeHtml(data.findings.join(" | "))}`;
    } catch (error) {
        els.emailResult.textContent = error.message;
    }
}

async function bulkScan() {
    try {
        const urls = els.bulkContent.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
        const { data } = await api("/api/v1/bulk-scan", {
            method: "POST",
            body: JSON.stringify({ urls }),
        });
        els.bulkResults.innerHTML = data.results.map((item) => {
            if (!item.success) return `<div>${escapeHtml(item.url)} - Invalid</div>`;
            return `<div><strong>${escapeHtml(item.result.verdict.toUpperCase())}</strong> ${escapeHtml(item.url)} (${item.result.risk_score}/100)</div>`;
        }).join("");
    } catch (error) {
        els.bulkResults.textContent = error.message;
    }
}

async function loadHistory(query = "") {
    try {
        const { data } = await api(`/api/v1/history${query ? `?q=${encodeURIComponent(query)}` : ""}`);
        const analytics = await api("/api/v1/history/analytics");
        renderHistory(data);
        renderAnalytics(analytics.data);
    } catch {
        els.historyList.innerHTML = `<p class="empty-history">No history available yet.</p>`;
    }
}

function renderAnalytics(data) {
    els.totalScans.textContent = data.total_scans;
    els.safeScans.textContent = data.safe;
    els.suspiciousScans.textContent = data.suspicious;
    els.phishingScans.textContent = data.phishing;
    els.liveThreatCounter.textContent = data.suspicious + data.phishing;
}

function renderHistory(items) {
    if (!items.length) {
        els.historyList.innerHTML = `<p class="empty-history">No scans stored in the database yet.</p>`;
        return;
    }
    els.historyList.innerHTML = "";
    items.slice(0, 20).forEach((item) => {
        const row = document.createElement("div");
        row.className = "history-item";
        row.innerHTML = `
            <div>
                <strong>${escapeHtml(item.domain || "-")}</strong>
                <small>${escapeHtml(item.url)}</small>
                <small>${escapeHtml(item.created_at)}</small>
            </div>
            <span class="verdict-badge ${escapeHtml(item.verdict)}">${escapeHtml(item.verdict)}</span>
        `;
        row.addEventListener("click", () => showResult(normalizeResult(item.result, item.url)));
        els.historyList.appendChild(row);
    });
}

async function downloadPdf() {
    if (!lastResult) {
        showError("Scan a URL before downloading a report.");
        return;
    }
    try {
        const response = await api("/api/v1/reports/pdf", {
            method: "POST",
            body: JSON.stringify({ url: lastResult.url }),
        });
        const blob = await response.blob();
        const objectUrl = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = objectUrl;
        link.download = `phishguard-${(lastResult.domain || "report").replace(/[^a-z0-9.-]/gi, "-")}.pdf`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(objectUrl);
    } catch (error) {
        showError(error.message);
    }
}

async function shareReport() {
    if (!lastResult) {
        showError("Scan a URL before sharing.");
        return;
    }
    const text = `PhishGuard Report\n${lastResult.url}\nVerdict: ${lastResult.verdict}\nRisk: ${lastResult.risk_score}/100`;
    if (navigator.share) {
        await navigator.share({ title: "PhishGuard Report", text });
        return;
    }
    await navigator.clipboard.writeText(text);
    els.shareReportBtn.textContent = "Copied";
    setTimeout(() => {
        els.shareReportBtn.textContent = "Share Report";
    }, 1300);
}

async function pasteUrl() {
    try {
        els.urlInput.value = (await navigator.clipboard.readText()).trim();
        scanUrl(true);
    } catch {
        showError("Clipboard access is blocked. Paste manually with Ctrl+V.");
    }
}

function renderList(target, values) {
    target.innerHTML = "";
    values.forEach((value) => {
        const li = document.createElement("li");
        li.textContent = value;
        target.appendChild(li);
    });
}

function formatSsl(ssl) {
    if (!ssl || !ssl.checked) return "Not checked";
    return ssl.valid ? `Valid (${ssl.expires_at || "expiry unavailable"})` : "Invalid or unavailable";
}

function formatRedirect(redirect) {
    if (!redirect || !redirect.checked) return "Not checked";
    const count = Number(redirect.redirect_count || 0);
    return count ? `${count} redirect${count === 1 ? "" : "s"}` : "No redirects";
}

function setLoading(active) {
    els.loading.classList.toggle("active", active);
    els.checkBtn.disabled = active;
    els.checkBtn.querySelector("span").textContent = active ? "Scanning..." : "Scan URL";
}

function setLiveStatus(text, active) {
    els.liveStatus.textContent = text;
    els.liveStatus.classList.toggle("active", active);
}

function showError(message) {
    els.errorMessage.textContent = message;
    els.errorSection.classList.add("active");
}

function hideError() {
    els.errorMessage.textContent = "";
    els.errorSection.classList.remove("active");
}

function percent(value) {
    return `${Math.round(Number(value) * 100)}%`;
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}
