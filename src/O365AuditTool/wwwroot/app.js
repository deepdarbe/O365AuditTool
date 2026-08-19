"use strict";

const copyStatusNames = ["Planned", "Queued", "Running", "Completed", "Completed with errors", "Failed"];
const copyItemStatusNames = ["Planned", "Queued", "Copying", "Completed", "Skipped", "Failed"];
const jobStatusNames = ["Kuyrukta", "Çalışıyor", "Tamamlandı", "Hatalarla tamamlandı", "Başarısız"];
const deviceStatuses = {
  0: ["Başarılı", "ok"],
  1: ["Çevrimdışı", "offline"],
  2: ["Hata", "error"],
  3: ["Kısmi", "offline"],
  4: ["Zaman aşımı", "warning"]
};
let selectedCopyPlan = null;
let csrfTokenPromise = null;
let directoryOrganizationalUnits = [];
let activeScanJobId = null;
let activeScanTimer = null;
let activeScanPollFailures = 0;
const panelLastUpdated = new Map();

function byId(id) {
  return document.getElementById(id);
}

function setFeedback(id, message, kind = "muted") {
  const element = byId(id);
  element.textContent = message;
  element.className = `feedback ${kind}`;
  element.setAttribute("role", kind === "error" ? "alert" : "status");
  element.setAttribute("aria-live", kind === "error" ? "assertive" : "polite");
}

function setButtonBusy(button, busy, busyLabel) {
  if (!button.dataset.defaultLabel) {
    button.dataset.defaultLabel = button.textContent;
  }
  button.classList.toggle("busy", busy);
  button.disabled = busy;
  button.textContent = busy ? busyLabel : button.dataset.defaultLabel;
}

function setPanelState(panelId, stampId, state, message) {
  const panel = byId(panelId);
  const stamp = byId(stampId);
  panel.dataset.state = state;
  panel.setAttribute("aria-busy", state === "loading" ? "true" : "false");
  stamp.textContent = message;
  stamp.className = `panel-stamp ${state === "success" || state === "empty" ? "ok" : state === "loading" ? "" : state === "stale" || state === "warning" ? "warning" : "error"}`;
  if (state === "success" || state === "empty" || state === "warning") {
    panelLastUpdated.set(panelId, new Date());
  }
}

function getStaleMessage(panelId) {
  const lastUpdated = panelLastUpdated.get(panelId);
  return lastUpdated ? `Güncel değil · ${lastUpdated.toLocaleTimeString("tr-TR")}` : "Yüklenemedi";
}

function setReadiness(id, state, text) {
  const item = byId(id);
  item.dataset.state = state;
  item.textContent = text;
}

function updateReadinessSummary() {
  const states = ["readinessSession", "readinessDirectory", "readinessInventory"]
    .map(id => byId(id).dataset.state);
  if (states.includes("error")) {
    byId("readinessTitle").textContent = "Operatör müdahalesi gerekiyor";
    byId("readinessSummary").textContent = "Hatalı adımı düzeltin ve ilgili yenileme işlemini yeniden çalıştırın.";
  } else if (states.includes("warning")) {
    byId("readinessTitle").textContent = "Tarama erişimi sınırlı";
    byId("readinessSummary").textContent = "Çevrimdışı veya hatalı cihazlar tamamlanmadan migration envanteri güvenilir kabul edilmemelidir.";
  } else if (states.every(state => state === "ok")) {
    byId("readinessTitle").textContent = "Audit görünümü hazır";
    byId("readinessSummary").textContent = "AD kapsamı seçilebilir ve güncel envanter sonuçları raporlanabilir.";
  } else {
    byId("readinessTitle").textContent = "İlk tarama için hazırlanıyor";
    byId("readinessSummary").textContent = "Windows oturumu ve AD yapısı hazır olduğunda bir OU veya site seçin.";
  }
}

function getErrorMessage(error, fallback) {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return fallback;
}

async function fetchJson(url, options) {
  const requestOptions = options ? { ...options } : {};
  const timeoutMs = Number(requestOptions.timeoutMs || 60000);
  delete requestOptions.timeoutMs;
  const timeoutController = requestOptions.signal ? null : new AbortController();
  const timeoutHandle = timeoutController
    ? window.setTimeout(() => timeoutController.abort(), Math.max(1000, timeoutMs))
    : null;
  if (timeoutController) {
    requestOptions.signal = timeoutController.signal;
  }
  const method = String(requestOptions.method || "GET").toUpperCase();
  requestOptions.credentials = "same-origin";
  if (!["GET", "HEAD", "OPTIONS", "TRACE"].includes(method)) {
    const headers = new Headers(requestOptions.headers || {});
    headers.set("X-O365Audit-CSRF", await getCsrfToken());
    requestOptions.headers = headers;
  }

  let response;
  let responseText = "";
  try {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      response = await fetch(url, requestOptions);
      responseText = await response.text();
      const retryableServiceUnavailable = response.status === 503 && response.headers.has("Retry-After");
      if (!retryableServiceUnavailable || method !== "GET" || attempt === 2) {
        break;
      }
      await new Promise(resolve => window.setTimeout(resolve, 600 * (attempt + 1)));
    }
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new Error("Sunucu zamanında yanıt vermedi. İşlemi yeniden deneyin.");
    }
    throw error;
  } finally {
    if (timeoutHandle) {
      window.clearTimeout(timeoutHandle);
    }
  }
  if (!response.ok) {
    let details = "";
    try {
      const problem = responseText ? JSON.parse(responseText) : {};
      details = problem.detail || problem.title || problem.message || "";
    } catch {
      details = "";
    }
    throw new Error(details || `HTTP ${response.status}`);
  }

  if (!responseText) {
    return null;
  }
  return JSON.parse(responseText);
}

async function loadSession() {
  try {
    const session = await fetchJson("/api/security/session");
    const badge = byId("sessionBadge");
    const authenticationType = String(session.authenticationType || "Negotiate");
    const normalizedType = authenticationType.toLowerCase();
    const roles = Array.isArray(session.roles) && session.roles.length ? ` · ${session.roles.join(", ")}` : "";
    const version = session.appVersion ? ` · v${session.appVersion}` : "";
    badge.textContent = `${session.userName || "Windows kullanıcısı"} · ${authenticationType}${roles}${version}`;
    badge.className = "session-badge";
    if (normalizedType.includes("kerberos")) {
      badge.classList.add("kerberos");
      badge.title = "Kerberos ile doğrulandı.";
    } else if (normalizedType.includes("ntlm")) {
      badge.classList.add("ntlm");
      badge.title = "NTLM kullanılıyor; Kerberos SSO devrede değil.";
    } else {
      badge.title = "Windows Negotiate kimlik doğrulaması kullanılıyor.";
    }
    setReadiness("readinessSession", "ok", "Windows oturumu hazır");
  } catch (error) {
    const badge = byId("sessionBadge");
    badge.className = "session-badge auth-error";
    badge.textContent = `Windows oturumu okunamadı · ${getErrorMessage(error, "HTTP hata")}`;
    setReadiness("readinessSession", "error", "Oturum doğrulanamadı");
  } finally {
    updateReadinessSummary();
  }
}

function replaceScopeOptions(selectId, items, placeholder, getValue, getLabel) {
  const select = byId(selectId);
  const selectedValue = select.value;
  const fragment = document.createDocumentFragment();
  const emptyOption = document.createElement("option");
  emptyOption.value = "";
  emptyOption.textContent = placeholder;
  fragment.appendChild(emptyOption);

  items.forEach(item => {
    const option = document.createElement("option");
    option.value = getValue(item);
    option.textContent = getLabel(item);
    option.title = item.distinguishedName || option.value;
    fragment.appendChild(option);
  });
  select.replaceChildren(fragment);
  select.disabled = false;
  if ([...select.options].some(option => option.value === selectedValue)) {
    select.value = selectedValue;
  }
}

function replaceScopeWithError(selectId, message) {
  const select = byId(selectId);
  const option = document.createElement("option");
  option.value = "";
  option.textContent = message;
  select.replaceChildren(option);
  select.disabled = true;
}

function renderOuOptions(searchTerm = "") {
  const normalizedSearch = searchTerm.trim().toLocaleLowerCase("tr-TR");
  const selectedValue = byId("fOu").value;
  const matches = normalizedSearch
    ? directoryOrganizationalUnits.filter(item =>
      [item.displayName, item.name, item.distinguishedName]
        .filter(Boolean)
        .some(value => String(value).toLocaleLowerCase("tr-TR").includes(normalizedSearch)))
    : directoryOrganizationalUnits;
  const selectedItem = directoryOrganizationalUnits.find(item => item.distinguishedName === selectedValue);
  if (selectedItem && !matches.includes(selectedItem)) {
    matches.unshift(selectedItem);
  }
  replaceScopeOptions(
    "fOu",
    matches,
    normalizedSearch ? `Bir OU seçin · ${matches.length} eşleşme` : "Bir OU seçin",
    item => item.distinguishedName,
    item => `${"\u00a0\u00a0".repeat(Math.max(0, Number(item.depth || 1) - 1))}${item.displayName || item.name}`);

  // Searching only filters the list; the placeholder stays selected, so an operator who
  // typed a full DN could believe a scope was chosen while the scan button stayed disabled.
  // Select automatically when the search leaves no ambiguity.
  const select = byId("fOu");
  if (!select.value && normalizedSearch) {
    const exact = matches.find(item =>
      String(item.distinguishedName || "").toLocaleLowerCase("tr-TR") === normalizedSearch);
    const resolved = exact || (matches.length === 1 ? matches[0] : null);
    if (resolved) {
      select.value = resolved.distinguishedName;
    }
  }
  updateScanReadiness();
}

function updateScanReadiness() {
  const ouFilter = byId("fOu").value.trim();
  const siteFilter = byId("fSite").value.trim();
  const button = byId("startScanButton");
  const hasScope = Boolean(ouFilter || siteFilter);
  const isActive = Boolean(activeScanJobId);
  button.disabled = !hasScope || isActive;
  button.title = isActive
    ? `Tarama devam ediyor: ${activeScanJobId}`
    : hasScope
      ? "Seçili kapsam için yeni audit taraması başlatır."
      : "Önce bir OU veya AD site seçin.";
  byId("scanScopeSummary").textContent = isActive
    ? `Aktif tarama: ${activeScanJobId}`
    : hasScope
      ? `Seçili kapsam: ${ouFilter || "OU seçilmedi"}${ouFilter && siteFilter ? " · " : ""}${siteFilter || ""}${siteFilter ? " · Site filtresi yalnız AD site metadata'sı doğrulanabilen cihazları içerir; OU ile daraltma önerilir." : ""}`
      : "Tarama başlatmak için bir OU veya AD site seçin.";
}

async function loadDirectoryStructure() {
  const refreshButton = byId("refreshDirectoryButton");
  setButtonBusy(refreshButton, true, "AD yapısı yükleniyor");
  setFeedback("directoryFeedback", "Active Directory OU ve site yapısı yükleniyor...");
  try {
    const structure = await fetchJson("/api/directory/structure", { timeoutMs: 35000 });
    const organizationalUnits = Array.isArray(structure?.organizationalUnits) ? structure.organizationalUnits : [];
    const sites = Array.isArray(structure?.sites) ? structure.sites : [];
    directoryOrganizationalUnits = organizationalUnits;
    renderOuOptions(byId("fOuSearch").value);
    replaceScopeOptions("fSite", sites, "Bir AD site seçin", item => item.name, item => item.name);
    byId("fOuSearch").disabled = false;
    const warnings = Array.isArray(structure?.warnings) ? structure.warnings.filter(Boolean) : [];
    setFeedback(
      "directoryFeedback",
      `${organizationalUnits.length} OU ve ${sites.length} AD site yüklendi · ${structure.domainDistinguishedName || "domain"}${warnings.length ? ` · ${warnings.join(" ")}` : ""}`,
      warnings.length ? "warning" : "ok");
    setReadiness("readinessDirectory", "ok", `${organizationalUnits.length} OU · ${sites.length} site`);
  } catch (error) {
    directoryOrganizationalUnits = [];
    replaceScopeWithError("fOu", "OU listesi yüklenemedi");
    replaceScopeWithError("fSite", "AD site listesi yüklenemedi");
    byId("fOuSearch").disabled = true;
    byId("fOuSearch").value = "";
    setFeedback("directoryFeedback", `AD yapısı yüklenemedi: ${getErrorMessage(error, "Bilinmeyen hata")}`, "error");
    setReadiness("readinessDirectory", "error", "AD yapısı yüklenemedi");
  } finally {
    setButtonBusy(refreshButton, false);
    updateScanReadiness();
    updateReadinessSummary();
  }
}

async function getCsrfToken() {
  if (!csrfTokenPromise) {
    csrfTokenPromise = fetch("/api/security/antiforgery", { credentials: "same-origin" })
      .then(async response => {
        if (!response.ok) {
          throw new Error(`CSRF token alınamadı: HTTP ${response.status}`);
        }
        const payload = await response.json();
        if (!payload?.token) {
          throw new Error("CSRF token yanıtı geçersiz.");
        }
        return payload.token;
      })
      .catch(error => {
        csrfTokenPromise = null;
        throw error;
      });
  }
  return csrfTokenPromise;
}

function asArray(payload) {
  if (Array.isArray(payload)) {
    return payload;
  }
  if (Array.isArray(payload?.items)) {
    return payload.items;
  }
  if (Array.isArray(payload?.plans)) {
    return payload.plans;
  }
  return [];
}

function appendCell(row, value, className = "") {
  const cell = document.createElement("td");
  cell.textContent = value ?? "";
  if (className) {
    cell.className = className;
  }
  row.appendChild(cell);
  return cell;
}

function appendStatusCell(row, text, className, exitCode = null) {
  const cell = document.createElement("td");
  const status = document.createElement("span");
  status.textContent = text;
  status.className = className;
  cell.appendChild(status);
  if (exitCode !== null && exitCode !== undefined) {
    const badge = document.createElement("span");
    badge.className = "status-exit";
    badge.textContent = `PsExec exit ${exitCode}`;
    badge.title = "Toplayıcının döndürdüğü PsExec çıkış kodu";
    cell.append(document.createElement("br"), badge);
  }
  row.appendChild(cell);
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (!Number.isFinite(bytes) || bytes < 0) {
    return "-";
  }
  if (bytes === 0) {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / (1024 ** index)).toFixed(index > 2 ? 2 : 1)} ${units[index]}`;
}

function formatDate(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString("tr-TR");
}

function formatIpAddresses(value) {
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  if (typeof value !== "string") {
    return value || "-";
  }
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.join(", ") : value;
  } catch {
    return value;
  }
}

function splitFilterValues(value) {
  const values = value
    .split(",")
    .map(item => item.trim())
    .filter(Boolean);
  return values.length ? [...new Set(values)] : null;
}

function getDeviceFilterQuery() {
  const query = new URLSearchParams();
  const filters = {
    ou: byId("fOu").value.trim(),
    site: byId("fSite").value.trim(),
    device: byId("fDevice").value.trim(),
    user: byId("fUser").value.trim(),
    diskType: byId("fDiskType").value,
    officeVersion: byId("fOfficeVersion").value.trim(),
    status: byId("fStatus").value
  };
  Object.entries(filters).forEach(([key, value]) => {
    if (value) {
      query.set(key, value);
    }
  });
  const minGb = Number(byId("fPstMinGb").value);
  const maxGb = Number(byId("fPstMaxGb").value);
  if (Number.isFinite(minGb) && minGb >= 0 && byId("fPstMinGb").value !== "") {
    query.set("pstMinBytes", String(Math.round(minGb * (1024 ** 3))));
  }
  if (Number.isFinite(maxGb) && maxGb >= 0 && byId("fPstMaxGb").value !== "") {
    query.set("pstMaxBytes", String(Math.round(maxGb * (1024 ** 3))));
  }
  return query;
}

async function loadData() {
  const filterButton = byId("filterDevicesButton");
  const hadData = byId("deviceRows").childElementCount > 0;
  setButtonBusy(filterButton, true, "Filtreleniyor");
  setPanelState("inventory", "devicePanelStamp", "loading", "Yükleniyor");
  setFeedback("deviceFeedback", "Cihaz envanteri yükleniyor...");
  try {
    const query = getDeviceFilterQuery();
    const data = asArray(await fetchJson(`/api/inventory/devices?${query}`));
    const stats = renderStats(data);
    renderDeviceRows(data, query.size > 0);
    renderFailureSummary(data);
    const updatedTime = new Date().toLocaleTimeString("tr-TR");
    const stamp = `Güncel · ${updatedTime}`;
    const degraded = data.length > 0 && (stats.offline > 0 || stats.errors > 0);
    const inventoryState = stats.success === 0 && data.length > 0
      ? "error"
      : degraded
        ? "warning"
        : data.length
          ? "success"
          : "empty";
    setPanelState("inventory", "devicePanelStamp", inventoryState, degraded ? `Erişim sınırlı · ${updatedTime}` : stamp);
    setFeedback(
      "deviceFeedback",
      data.length
        ? `${data.length} cihaz gösteriliyor: ${stats.success} başarılı, ${stats.offline} çevrimdışı, ${stats.errors} hata/kısmi.`
        : "Henüz cihaz envanteri yok.",
      degraded ? "warning" : "ok");
    setReadiness(
      "readinessInventory",
      stats.success === 0 && data.length > 0 ? "error" : degraded ? "warning" : data.length ? "ok" : "pending",
      data.length ? `${stats.success}/${data.length} cihaz başarıyla toplandı` : "İlk tarama bekleniyor");
  } catch (error) {
    const state = hadData ? "stale" : "error";
    setPanelState("inventory", "devicePanelStamp", state, getStaleMessage("inventory"));
    setFeedback(
      "deviceFeedback",
      `${hadData ? "Önceki sonuçlar gösteriliyor; güncel veri alınamadı" : "Cihaz verisi yüklenemedi"}: ${getErrorMessage(error, "Bilinmeyen hata")}`,
      "error");
    setReadiness("readinessInventory", "error", hadData ? "Envanter güncel değil" : "Envanter yüklenemedi");
  } finally {
    setButtonBusy(filterButton, false);
    updateReadinessSummary();
  }
}

// Failure classification lives in dashboard-logic.js and is shared with the server rules in
// PsExecCollectorRunner.IsOfflineFailure. Keeping a second copy here is what let the dashboard
// drift and label the 2026-08 authorization incident (PsExec exit 6) as "Ağ / Offline".
const { categoryLabels, parsePsExecExit, classifyFailure } = globalThis.O365Dashboard;

const statusFilterNames = { 1: "Offline", 2: "Error", 3: "Partial", 4: "Timeout" };

function buildFailureRow(group) {
  const row = document.createElement("div");
  row.className = "failure-row";

  const count = document.createElement("span");
  count.className = "count";
  count.textContent = String(group.count);
  row.appendChild(count);

  const badge = document.createElement("span");
  badge.className = `failure-badge ${group.category}`;
  badge.textContent = categoryLabels[group.category] || categoryLabels.error;
  row.appendChild(badge);

  if (group.exit !== null && group.exit !== undefined) {
    const chip = document.createElement("span");
    chip.className = "exit-chip";
    chip.textContent = `exit ${group.exit}`;
    row.appendChild(chip);
  }

  const reason = document.createElement("div");
  reason.className = "failure-reason";
  const label = document.createElement("div");
  label.className = "r-label";
  label.textContent = group.label;
  const hint = document.createElement("div");
  hint.className = "r-hint";
  const sample = group.devices.slice(0, 3).join(", ");
  hint.textContent = group.devices.length > 3
    ? `${group.hint} · örn. ${sample} +${group.devices.length - 3}`
    : `${group.hint} · ${sample}`;
  reason.append(label, hint);
  row.appendChild(reason);

  const action = document.createElement("button");
  action.type = "button";
  action.className = "secondary";
  action.textContent = "Bu durumu filtrele";
  action.addEventListener("click", () => {
    byId("fStatus").value = statusFilterNames[group.statusNum] || "Error";
    loadData();
    byId("inventory").scrollIntoView({ behavior: "smooth" });
  });
  row.appendChild(action);

  return row;
}

function renderFailureSummary(data) {
  const panel = byId("failure-summary");
  const navLink = byId("failureNavLink");
  const container = byId("failureGroups");
  const failed = data.filter(device => [1, 2, 3, 4].includes(Number(device.status)));

  if (failed.length === 0) {
    panel.hidden = true;
    if (navLink) navLink.hidden = true;
    container.replaceChildren();
    return;
  }

  const groups = new Map();
  failed.forEach(device => {
    const info = classifyFailure(device);
    const key = `${info.category}|${info.exit ?? "-"}|${info.label}`;
    const existing = groups.get(key) || { ...info, count: 0, devices: [] };
    existing.count += 1;
    existing.devices.push(device.deviceName || "?");
    groups.set(key, existing);
  });

  const ordered = [...groups.values()].sort((a, b) => b.count - a.count);
  const fragment = document.createDocumentFragment();
  ordered.forEach(group => fragment.appendChild(buildFailureRow(group)));
  container.replaceChildren(fragment);

  // Show how old the underlying scan data is. The panel is rendered on page load, so a
  // load timestamp would wrongly suggest the rows are fresh.
  const collectedTimes = failed
    .map(device => new Date(device.collectedUtc).getTime())
    .filter(time => Number.isFinite(time));
  const newestCollected = collectedTimes.length ? new Date(Math.max(...collectedTimes)) : null;

  const stamp = byId("failurePanelStamp");
  stamp.textContent = newestCollected
    ? `${failed.length} başarısız · ${ordered.length} neden · veri: ${newestCollected.toLocaleString("tr-TR")}`
    : `${failed.length} başarısız · ${ordered.length} neden`;
  stamp.className = "panel-stamp warning";

  // Every failure recorded by v1.2.2+ carries an exit code. If none do, these rows predate
  // the running build and no scan has been run since the upgrade.
  const staleNotice = byId("failureStaleNotice");
  const anyExitCode = ordered.some(group => group.exit !== null && group.exit !== undefined);
  if (staleNotice) {
    staleNotice.hidden = anyExitCode;
  }

  panel.hidden = false;
  if (navLink) navLink.hidden = false;
}

function renderStats(data) {
  const success = data.filter(item => Number(item.status) === 0).length;
  const offline = data.filter(item => Number(item.status) === 1).length;
  const errors = data.filter(item => [2, 3, 4].includes(Number(item.status))).length;
  const pstBytes = data.reduce((total, item) => total + Number(item.pstTotalBytes || 0), 0);
  const fastStorage = data.filter(item =>
    (item.disks || []).some(disk =>
      String(disk.mediaType || "").toUpperCase() === "SSD" ||
      String(disk.busType || "").toUpperCase() === "NVME")
  ).length;

  byId("statDevices").textContent = String(data.length);
  byId("statOffline").textContent = String(offline);
  byId("statErrors").textContent = String(errors);
  byId("statPst").textContent = (pstBytes / (1024 ** 3)).toFixed(1);
  byId("statStorage").textContent = String(fastStorage);
  return { success, offline, errors };
}

function appendMobileDefinition(list, label, value) {
  const wrapper = document.createElement("div");
  const term = document.createElement("dt");
  const description = document.createElement("dd");
  term.textContent = label;
  description.textContent = value || "-";
  wrapper.append(term, description);
  list.appendChild(wrapper);
}

function appendMobileDeviceCard(fragment, device, status, details) {
  const card = document.createElement("details");
  card.className = "mobile-device-card";
  const summary = document.createElement("summary");
  const summaryMain = document.createElement("div");
  const name = document.createElement("span");
  name.className = "device-name";
  name.textContent = device.deviceName || "Bilinmeyen cihaz";
  const summaryLine = document.createElement("span");
  summaryLine.className = "device-summary";
  summaryLine.textContent = `${details.lastUser} · ${details.pstGb} GB PST`;
  summaryMain.append(name, document.createElement("br"), summaryLine);
  const statusElement = document.createElement("span");
  statusElement.className = status[1];
  statusElement.textContent = status[0];
  summary.append(summaryMain, statusElement);

  const body = document.createElement("dl");
  body.className = "mobile-device-body";
  appendMobileDefinition(body, "OU / Site", `${device.ou || "-"} · ${device.site || "-"}`);
  appendMobileDefinition(body, "IP adresleri", formatIpAddresses(device.ipAddresses));
  appendMobileDefinition(body, "Seri numarası", device.serialNumber || "-");
  appendMobileDefinition(body, "Profiller / hesaplar", details.accountText);
  appendMobileDefinition(body, "Disk / volume", `${details.diskText}\n${details.volumeText}`);
  appendMobileDefinition(body, "Office", details.officeText);
  appendMobileDefinition(body, "PST / Legacy", details.artifactText);
  appendMobileDefinition(body, "Tarama sonucu", `${device.errorMessage || "Hata yok"}\n${formatDate(device.collectedUtc)}`);
  card.append(summary, body);
  fragment.appendChild(card);
}

function renderDeviceRows(data, hasFilters = false) {
  const body = byId("deviceRows");
  const fragment = document.createDocumentFragment();
  const mobileFragment = document.createDocumentFragment();

  data.forEach(device => {
    const row = document.createElement("tr");
    appendCell(row, device.deviceName || "-");
    appendCell(row, device.ou || "-");
    appendCell(row, device.site || "-");
    const status = deviceStatuses[Number(device.status)] || [String(device.status ?? "Bilinmiyor"), "muted"];
    appendStatusCell(row, status[0], status[1], parsePsExecExit(device.errorMessage));
    appendCell(row, device.serialNumber || "-");
    appendCell(row, formatIpAddresses(device.ipAddresses));
    appendCell(
      row,
      device.currentLoggedOnUser
        ? `${device.currentLoggedOnUser} (aktif)${device.lastLoggedOnUser && device.lastLoggedOnUser !== device.currentLoggedOnUser ? ` | son: ${device.lastLoggedOnUser}` : ""}`
        : device.lastLoggedOnUser || "-");

    const profileLines = (device.profiles || []).map(profile =>
      `Profil | ${profile.userName || profile.sid || "Bilinmiyor"} | ${profile.profileName || "Windows profili"}${profile.loaded ? " | yüklü" : ""}${profile.isDefault ? " | varsayılan" : ""}`);
    const accountLines = (device.mailAccounts || []).map(account =>
      `Hesap | ${account.address || "Bilinmiyor"} | ${account.accountType || "Bilinmiyor"} | ${account.profileName || "Varsayılan"}${account.isActive ? " | aktif" : ""}`);
    const accountText = [...profileLines, ...accountLines].join("\n") || "-";
    const accountCell = appendCell(row, accountText);
    accountCell.style.whiteSpace = "pre-line";

    const diskText = (device.disks || [])
      .map(disk => `${disk.mediaType || "Bilinmiyor"} | ${disk.busType || disk.interfaceType || "Bilinmiyor"} | ${disk.model || ""}`.trim())
      .join("\n") || "-";
    const diskCell = appendCell(row, diskText);
    diskCell.style.whiteSpace = "pre-line";

    const volumeText = (device.volumes || [])
      .map(volume => `${volume.name || "?"} ${formatBytes(volume.freeBytes)} boş / ${formatBytes(volume.totalBytes)}`)
      .join("\n") || "-";
    const volumeCell = appendCell(row, volumeText);
    volumeCell.style.whiteSpace = "pre-line";

    const officeProducts = (device.officeProducts || [])
      .map(product => [
        product.name,
        product.version,
        product.architecture,
        product.productIds,
        product.updateChannel,
        product.updatesEnabled === false ? "güncellemeler kapalı" : null
      ].filter(Boolean).join(" | "))
      .filter(Boolean);
    const officeProcesses = (device.officeProcesses || [])
      .filter(process => process.isRunning)
      .map(process => `${process.processName || "Office"} PID ${process.pid || "?"} | ${process.owner || "sahip bilinmiyor"}`);
    const officeText = [
      ...officeProducts.map(product => `Kurulu | ${product}`),
      ...officeProcesses.map(process => `Çalışıyor | ${process}`)
    ].join("\n") || "-";
    const officeCell = appendCell(row, officeText);
    officeCell.style.whiteSpace = "pre-line";

    appendCell(row, (Number(device.pstTotalBytes || 0) / (1024 ** 3)).toFixed(1));

    const artifactText = [
      ...(device.pstFiles || []).map(file =>
        `PST | ${file.userPrincipalName || file.sid || "Bilinmiyor"} | ${file.profileName || "?"} | ${file.path} | ${formatBytes(file.sizeBytes)}`),
      ...(device.legacyFiles || []).map(file =>
        `${file.artifactType || "NK2"} | ${file.userPrincipalName || file.userName || file.sid || "Bilinmiyor"} | ${file.profileName || "?"} | ${file.path} | ${formatBytes(file.sizeBytes)}`)
    ].join("\n") || "-";
    const artifactCell = appendCell(row, artifactText);
    artifactCell.style.whiteSpace = "pre-line";
    artifactCell.style.minWidth = "360px";
    appendCell(row, device.errorMessage || "-");
    appendCell(row, formatDate(device.collectedUtc));
    fragment.appendChild(row);
    appendMobileDeviceCard(mobileFragment, device, status, {
      lastUser: device.currentLoggedOnUser || device.lastLoggedOnUser || "Kullanıcı yok",
      pstGb: (Number(device.pstTotalBytes || 0) / (1024 ** 3)).toFixed(1),
      accountText,
      diskText,
      volumeText,
      officeText,
      artifactText
    });
  });

  body.replaceChildren(fragment);
  byId("deviceCards").replaceChildren(mobileFragment);
  const empty = byId("deviceEmpty");
  empty.textContent = hasFilters
    ? "Seçili kapsam veya filtrelerle eşleşen cihaz yok. İlk tarama yapılmadıysa kapsamı seçip taramayı başlatın."
    : "Henüz envanter verisi yok. Bir OU veya AD site seçip ilk taramayı başlatın.";
  empty.classList.toggle("visible", data.length === 0);
}

async function loadLicenseRecommendations() {
  const refreshButton = byId("refreshLicensesButton");
  const hadData = byId("licenseRows").childElementCount > 0;
  setButtonBusy(refreshButton, true, "Yükleniyor");
  setPanelState("licenses", "licensePanelStamp", "loading", "Yükleniyor");
  setFeedback("licenseFeedback", "Lisans önerileri yükleniyor...");
  try {
    const recommendations = asArray(await fetchJson("/api/licenses/recommendations"));
    const body = byId("licenseRows");
    const fragment = document.createDocumentFragment();
    recommendations.forEach(recommendation => {
      const row = document.createElement("tr");
      appendCell(row, recommendation.userKey || recommendation.user || "-");
      appendCell(row, formatBytes(recommendation.totalPstBytes));
      appendCell(row, recommendation.recommendedLicense || "-");
      appendStatusCell(
        row,
        recommendation.confidence || "Low",
        String(recommendation.confidence).toLowerCase() === "high" ? "ok" : "warning");
      appendCell(row, recommendation.requiresTenantValidation ? "M365 tenant verisi gerekli" : "Doğrulandı");
      fragment.appendChild(row);
    });
    body.replaceChildren(fragment);
    byId("licenseEmpty").classList.toggle("visible", recommendations.length === 0);
    setPanelState(
      "licenses",
      "licensePanelStamp",
      recommendations.length ? "success" : "empty",
      `Güncel · ${new Date().toLocaleTimeString("tr-TR")}`);
    setFeedback("licenseFeedback", `${recommendations.length} kullanıcı için PST kapasite tahmini gösteriliyor; satın alma öncesi tenant doğrulaması zorunludur.`, "ok");
  } catch (error) {
    setPanelState("licenses", "licensePanelStamp", hadData ? "stale" : "error", getStaleMessage("licenses"));
    setFeedback(
      "licenseFeedback",
      `${hadData ? "Önceki kapasite tahminleri gösteriliyor; yenileme başarısız" : "Lisans önerileri yüklenemedi"}: ${getErrorMessage(error, "Bilinmeyen hata")}`,
      "error");
  } finally {
    setButtonBusy(refreshButton, false);
  }
}

function getLegacyFilterQuery() {
  const query = new URLSearchParams();
  const filters = {
    device: byId("legacyDevice").value.trim(),
    user: byId("legacyUser").value.trim(),
    profile: byId("legacyProfile").value.trim(),
    artifactType: byId("legacyType").value
  };
  Object.entries(filters).forEach(([key, value]) => {
    if (value) {
      query.set(key, value);
    }
  });
  return query;
}

async function loadLegacyFiles() {
  const filterButton = byId("filterLegacyButton");
  const hadData = byId("legacyRows").childElementCount > 0;
  setButtonBusy(filterButton, true, "Filtreleniyor");
  setPanelState("legacy", "legacyPanelStamp", "loading", "Yükleniyor");
  setFeedback("legacyFeedback", "NK2/N2K envanteri yükleniyor...");
  try {
    const files = asArray(await fetchJson(`/api/inventory/legacy-files?${getLegacyFilterQuery()}`));
    renderLegacyRows(files);
    byId("statLegacy").textContent = String(files.length);
    setPanelState(
      "legacy",
      "legacyPanelStamp",
      files.length ? "success" : "empty",
      `Güncel · ${new Date().toLocaleTimeString("tr-TR")}`);
    setFeedback("legacyFeedback", `${files.length} legacy artefact gösteriliyor.`, "ok");
  } catch (error) {
    if (!hadData) {
      byId("statLegacy").textContent = "-";
    }
    setPanelState("legacy", "legacyPanelStamp", hadData ? "stale" : "error", getStaleMessage("legacy"));
    setFeedback(
      "legacyFeedback",
      `${hadData ? "Önceki legacy kayıtları gösteriliyor; yenileme başarısız" : "Legacy dosyalar yüklenemedi"}: ${getErrorMessage(error, "Bilinmeyen hata")}`,
      "error");
  } finally {
    setButtonBusy(filterButton, false);
  }
}

function renderLegacyRows(files) {
  const body = byId("legacyRows");
  const fragment = document.createDocumentFragment();

  files.forEach(file => {
    const row = document.createElement("tr");
    appendCell(row, String(file.artifactType || "-").toUpperCase());
    appendCell(row, file.deviceName || "-");
    appendCell(row, file.userPrincipalName || file.userName || "-");
    appendCell(row, file.sid || "-");
    appendCell(row, file.profileName || "-");
    const pathCell = appendCell(row, file.path || "-", "path-cell");
    pathCell.title = file.path || "";
    appendCell(row, formatBytes(file.sizeBytes));
    appendCell(row, formatDate(file.lastWriteUtc));
    appendStatusCell(row, file.existsOnDisk === false ? "Erişilemiyor" : "Erişilebilir", file.existsOnDisk === false ? "error" : "ok");
    fragment.appendChild(row);
  });

  body.replaceChildren(fragment);
  byId("legacyEmpty").classList.toggle("visible", files.length === 0);
}

function normalizeJobStatus(value) {
  if (typeof value === "number" || /^\d+$/.test(String(value))) {
    return jobStatusNames[Number(value)] || String(value);
  }
  const names = {
    queued: "Kuyrukta",
    running: "Çalışıyor",
    completed: "Tamamlandı",
    completedwitherrors: "Hatalarla tamamlandı",
    failed: "Başarısız"
  };
  return names[String(value || "").toLowerCase()] || String(value || "Bilinmiyor");
}

function isTerminalJobStatus(value) {
  return [2, 3, 4].includes(Number(value)) || ["completed", "completedwitherrors", "failed"]
    .includes(String(value || "").toLowerCase());
}

function renderScanProgress(job) {
  const stats = job?.deviceStats || {};
  const total = Number(stats.total || 0);
  const completed = ["success", "offline", "error", "partial", "timeout"]
    .reduce((sum, key) => sum + Number(stats[key] || 0), 0);
  const status = normalizeJobStatus(job?.status);
  const progress = byId("scanProgressBar");
  byId("scanProgress").hidden = false;
  byId("scanProgressTitle").textContent = `Tarama ${status.toLocaleLowerCase("tr-TR")} · ${job.id || activeScanJobId}`;
  // A failed job never gets device stats, so without this it kept showing
  // "preparing the target list" and the actual reason (job notes) stayed hidden.
  const notes = String(job?.notes || "").trim();
  const failed = Number(job?.status) === 4 || String(job?.status || "").toLowerCase() === "failed";
  byId("scanProgressDetail").textContent = total
    ? `${completed}/${total} sonuç · ${stats.success || 0} başarılı · ${stats.offline || 0} çevrimdışı · ${(stats.error || 0) + (stats.partial || 0) + (stats.timeout || 0)} hata/kısmi`
    : failed
      ? (notes || "Tarama başarısız oldu; sunucu bir neden bildirmedi. Servis günlüklerine bakın.")
      : isTerminalJobStatus(job?.status)
        ? (notes || "Tarama tamamlandı fakat hiçbir cihaz sonucu kaydedilmedi.")
        : "Hedef cihaz listesi hazırlanıyor.";
  if (total > 0) {
    progress.max = total;
    progress.value = Math.min(completed, total);
  } else {
    progress.removeAttribute("value");
  }
}

async function pollScanJob(jobId) {
  if (activeScanJobId !== jobId) {
    return;
  }
  try {
    const job = await fetchJson(`/api/jobs/${encodeURIComponent(jobId)}`);
    activeScanPollFailures = 0;
    renderScanProgress(job);
    if (isTerminalJobStatus(job.status)) {
      activeScanJobId = null;
      activeScanTimer = null;
      setButtonBusy(byId("startScanButton"), false);
      updateScanReadiness();
      const status = normalizeJobStatus(job.status);
      setFeedback("deviceFeedback", `Tarama ${status.toLocaleLowerCase("tr-TR")}: ${jobId}. Envanter yenileniyor.`, Number(job.status) === 4 || String(job.status).toLowerCase() === "failed" ? "error" : "ok");
      await Promise.allSettled([loadData(), loadLegacyFiles(), loadLicenseRecommendations()]);
      return;
    }
    activeScanTimer = window.setTimeout(() => void pollScanJob(jobId), 2500);
  } catch (error) {
    activeScanPollFailures += 1;
    if (activeScanPollFailures < 5) {
      setFeedback("deviceFeedback", `Tarama sürüyor; durum geçici olarak okunamadı (${activeScanPollFailures}/5).`, "warning");
      activeScanTimer = window.setTimeout(() => void pollScanJob(jobId), 5000);
      return;
    }
    activeScanJobId = null;
    activeScanTimer = null;
    setButtonBusy(byId("startScanButton"), false);
    updateScanReadiness();
    setFeedback("deviceFeedback", `Tarama durum takibi kesildi: ${getErrorMessage(error, "Bilinmeyen hata")}. Job kimliği: ${jobId}`, "error");
  }
}

async function startScan() {
  const button = byId("startScanButton");
  if (activeScanJobId) {
    return;
  }
  setButtonBusy(button, true, "Tarama başlatılıyor");
  setFeedback("deviceFeedback", "Tarama kuyruğa alınıyor...");
  let queued = false;
  try {
    const ouFilter = byId("fOu").value.trim();
    const siteFilter = byId("fSite").value.trim();
    if (!ouFilter && !siteFilter) {
      throw new Error("Domain-geneli taramayı önlemek için OU veya AD site kapsamı girilmelidir.");
    }
    const result = await fetchJson("/api/jobs/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ouFilter: ouFilter || null, siteFilter: siteFilter || null, manual: true })
    });
    activeScanJobId = result.jobId || result.id;
    if (!activeScanJobId) {
      throw new Error("Tarama API yanıtında job kimliği bulunamadı.");
    }
    queued = true;
    activeScanPollFailures = 0;
    setFeedback("deviceFeedback", `Tarama kuyruğa alındı: ${activeScanJobId}`, "ok");
    updateScanReadiness();
    byId("scanProgress").hidden = false;
    byId("scanProgressTitle").textContent = "Tarama kuyrukta";
    byId("scanProgressDetail").textContent = `Job kimliği: ${activeScanJobId}`;
    byId("scanProgressBar").removeAttribute("value");
    void pollScanJob(activeScanJobId);
  } catch (error) {
    setFeedback("deviceFeedback", `Tarama başlatılamadı: ${getErrorMessage(error, "AuditAdmin yetkisini kontrol edin.")}`, "error");
  } finally {
    if (!queued) {
      setButtonBusy(button, false);
      updateScanReadiness();
    }
  }
}

function exportCsv() {
  window.open(`/api/export/csv?${getDeviceFilterQuery()}`, "_blank", "noopener");
}

function exportPdf() {
  window.open(`/api/export/executive-pdf?${getDeviceFilterQuery()}`, "_blank", "noopener");
}

async function createCopyPlan(event) {
  event.preventDefault();
  const artifactTypes = [...document.querySelectorAll('input[name="copyArtifactType"]:checked')]
    .map(input => input.value);
  if (artifactTypes.length === 0) {
    setFeedback("copyFeedback", "En az bir artefact tipi seçilmelidir.", "error");
    return;
  }

  const targetRoot = byId("copyTargetRoot").value.trim();
  const request = {
    targetRoot: targetRoot || null,
    devices: splitFilterValues(byId("copyDevices").value),
    users: splitFilterValues(byId("copyUsers").value),
    artifactTypes
  };

  const submitButton = byId("copyPlanForm").querySelector('button[type="submit"]');
  setButtonBusy(submitButton, true, "Plan oluşturuluyor");
  setFeedback("copyFeedback", "Copy planı oluşturuluyor...");
  try {
    const plan = await fetchJson("/api/copy/plans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request)
    });
    setFeedback("copyFeedback", `Plan oluşturuldu: ${plan?.id || plan?.jobId || "-"}. Dosyalar henüz kopyalanmadı.`, "ok");
    await loadCopyPlans();
  } catch (error) {
    setFeedback("copyFeedback", `Plan oluşturulamadı: ${getErrorMessage(error, "MigrationPlanner yetkisini ve Copy ayarlarını kontrol edin.")}`, "error");
  } finally {
    setButtonBusy(submitButton, false);
  }
}

function normalizeCopyStatus(value) {
  if (typeof value === "number" || /^\d+$/.test(String(value))) {
    return copyStatusNames[Number(value)] || String(value);
  }
  return String(value || "Unknown");
}

function translateCopyStatus(value) {
  const names = {
    planned: "Planlandı",
    queued: "Kuyrukta",
    running: "Çalışıyor",
    completed: "Tamamlandı",
    "completed with errors": "Hatalarla tamamlandı",
    completedwitherrors: "Hatalarla tamamlandı",
    failed: "Başarısız"
  };
  const normalized = normalizeCopyStatus(value);
  return names[normalized.toLowerCase()] || normalized;
}

function normalizeCopyItemStatus(value) {
  if (typeof value === "number" || /^\d+$/.test(String(value))) {
    return copyItemStatusNames[Number(value)] || String(value);
  }
  return String(value || "Unknown");
}

function copyStatusClass(status) {
  const normalized = normalizeCopyStatus(status).toLowerCase();
  if (normalized === "completed") {
    return "ok";
  }
  if (normalized.includes("error") || normalized === "failed") {
    return "error";
  }
  if (normalized === "running" || normalized === "queued") {
    return "warning";
  }
  return "muted";
}

function isPlanned(status) {
  return Number(status) === 0 || String(status).toLowerCase() === "planned";
}

async function loadCopyPlans() {
  const refreshButton = byId("refreshPlansButton");
  const hadData = byId("copyPlanRows").childElementCount > 0;
  setButtonBusy(refreshButton, true, "Yükleniyor");
  setPanelState("copy-plans", "copyPanelStamp", "loading", "Yükleniyor");
  setFeedback("copyFeedback", "Copy planları yükleniyor...");
  try {
    const plans = asArray(await fetchJson("/api/copy/plans"));
    renderCopyPlans(plans);
    setPanelState(
      "copy-plans",
      "copyPanelStamp",
      plans.length ? "success" : "empty",
      `Güncel · ${new Date().toLocaleTimeString("tr-TR")}`);
    setFeedback("copyFeedback", `${plans.length} copy planı gösteriliyor.`, "ok");
  } catch (error) {
    setPanelState("copy-plans", "copyPanelStamp", hadData ? "stale" : "error", getStaleMessage("copy-plans"));
    setFeedback(
      "copyFeedback",
      `${hadData ? "Önceki planlar gösteriliyor; yenileme başarısız" : "Copy planları yüklenemedi"}: ${getErrorMessage(error, "Bilinmeyen hata")}`,
      "error");
  } finally {
    setButtonBusy(refreshButton, false);
  }
}

function renderCopyPlans(plans) {
  const body = byId("copyPlanRows");
  const fragment = document.createDocumentFragment();

  plans.forEach(plan => {
    const items = Array.isArray(plan.items) ? plan.items : [];
    const totalItems = Number(plan.itemCount ?? plan.totalItems ?? items.length);
    const completed = Number(plan.completedItems ?? items.filter(item => ["completed", "skipped"].includes(normalizeCopyItemStatus(item.status).toLowerCase())).length);
    const failed = Number(plan.failedItems ?? items.filter(item => normalizeCopyItemStatus(item.status).toLowerCase() === "failed").length);
    const row = document.createElement("tr");
    const id = plan.id || plan.jobId || "";

    const idCell = appendCell(row, id || "-");
    idCell.className = "path-cell";
    appendStatusCell(row, translateCopyStatus(plan.status), copyStatusClass(plan.status));
    const targetCell = appendCell(row, plan.targetRoot || "-", "path-cell");
    targetCell.title = plan.targetRoot || "";
    appendCell(row, plan.requestedBy || "-");
    appendCell(row, String(totalItems));
    appendCell(row, `${completed} / ${failed}`);
    appendCell(row, formatDate(plan.createdUtc));

    const actionCell = document.createElement("td");
    const executeButton = document.createElement("button");
    executeButton.type = "button";
    executeButton.textContent = "İncele ve başlat";
    executeButton.className = "danger";
    executeButton.disabled = !isPlanned(plan.status) || !id || totalItems === 0;
    executeButton.addEventListener("click", () => void openExecuteDialog({ ...plan, id, totalItems }));
    actionCell.appendChild(executeButton);
    row.appendChild(actionCell);
    fragment.appendChild(row);
  });

  body.replaceChildren(fragment);
  byId("copyPlansEmpty").classList.toggle("visible", plans.length === 0);
}

async function openExecuteDialog(planSummary) {
  selectedCopyPlan = null;
  const acknowledgement = byId("executeAcknowledgement");
  const confirmButton = byId("confirmExecuteButton");
  acknowledgement.checked = false;
  acknowledgement.disabled = true;
  setButtonBusy(confirmButton, false);
  confirmButton.disabled = true;
  byId("executeSummary").textContent = `Plan ayrıntıları yükleniyor: ${planSummary.id}`;
  byId("executeSummary").style.whiteSpace = "pre-line";
  byId("executeDialog").showModal();
  try {
    const plan = await fetchJson(`/api/copy/plans/${encodeURIComponent(planSummary.id)}`);
    const items = Array.isArray(plan?.items) ? plan.items : [];
    const totalBytes = items.reduce((total, item) => total + Number(item.sourceSizeBytes || 0), 0);
    const snapshotDates = items
      .map(item => item.sourceLastWriteUtc)
      .filter(Boolean)
      .map(value => new Date(value))
      .filter(date => !Number.isNaN(date.getTime()))
      .sort((left, right) => left - right);
    if (!isPlanned(plan.status) || items.length === 0) {
      throw new Error("Plan artık yürütülebilir durumda değil veya kaynak öğe içermiyor.");
    }
    selectedCopyPlan = { ...plan, id: plan.id || planSummary.id, totalItems: items.length, totalBytes };
    acknowledgement.disabled = false;
    byId("executeSummary").textContent = [
      `Plan: ${selectedCopyPlan.id}`,
      `Hedef: ${plan.targetRoot || "-"}`,
      `İsteyen: ${plan.requestedBy || "-"}`,
      `Kaynak: ${items.length} dosya · ${formatBytes(totalBytes)}`,
      `Snapshot aralığı: ${snapshotDates.length ? `${formatDate(snapshotDates[0])} - ${formatDate(snapshotDates.at(-1))}` : "bilinmiyor"}`,
      "Çakışma politikası: overwrite yok; aynı hash atlanır, farklı içerik hata verir.",
      "Hedef boş alanı API tarafından raporlanmıyor; onaydan önce share kapasitesini doğrulayın."
    ].join("\n");
  } catch (error) {
    byId("executeSummary").textContent = `Plan doğrulanamadı: ${getErrorMessage(error, "Bilinmeyen hata")}`;
    setFeedback("copyFeedback", `Plan yürütme öncesi doğrulanamadı: ${getErrorMessage(error, "Bilinmeyen hata")}`, "error");
  }
}

function closeExecuteDialog() {
  selectedCopyPlan = null;
  byId("executeAcknowledgement").disabled = true;
  setButtonBusy(byId("confirmExecuteButton"), false);
  byId("confirmExecuteButton").disabled = true;
  if (byId("executeDialog").open) {
    byId("executeDialog").close();
  }
}

async function executeCopyPlan() {
  if (!selectedCopyPlan || !byId("executeAcknowledgement").checked) {
    return;
  }

  const planId = selectedCopyPlan.id;
  const button = byId("confirmExecuteButton");
  setButtonBusy(button, true, "Kuyruğa alınıyor");
  setFeedback("copyFeedback", `Plan execute kuyruğuna alınıyor: ${planId}`);
  try {
    await fetchJson(`/api/copy/plans/${encodeURIComponent(planId)}/execute`, { method: "POST" });
    closeExecuteDialog();
    setFeedback("copyFeedback", `Copy planı yürütme kuyruğuna alındı: ${planId}`, "ok");
    await loadCopyPlans();
  } catch (error) {
    setFeedback("copyFeedback", `Copy başlatılamadı: ${getErrorMessage(error, "AuditAdmin yetkisini ve sunucu Copy opt-in ayarını kontrol edin.")}`, "error");
    setButtonBusy(button, false);
  }
}

function resetDeviceReportFilters() {
  ["fDevice", "fUser", "fDiskType", "fOfficeVersion", "fStatus", "fPstMinGb", "fPstMaxGb"]
    .forEach(id => {
      byId(id).value = "";
    });
  void loadData();
}

function bindEvents() {
  byId("deviceFilterForm").addEventListener("submit", event => {
    event.preventDefault();
    void loadData();
  });
  byId("resetDeviceFiltersButton").addEventListener("click", resetDeviceReportFilters);
  byId("startScanButton").addEventListener("click", startScan);
  byId("refreshDirectoryButton").addEventListener("click", loadDirectoryStructure);
  byId("fOuSearch").addEventListener("input", event => {
    renderOuOptions(event.target.value);
    updateScanReadiness();
  });
  ["fOu", "fSite"].forEach(id => byId(id).addEventListener("change", updateScanReadiness));
  byId("exportCsvButton").addEventListener("click", exportCsv);
  byId("exportPdfButton").addEventListener("click", exportPdf);
  byId("legacyFilterForm").addEventListener("submit", event => {
    event.preventDefault();
    void loadLegacyFiles();
  });
  byId("refreshLicensesButton").addEventListener("click", loadLicenseRecommendations);
  byId("copyPlanForm").addEventListener("submit", createCopyPlan);
  byId("refreshPlansButton").addEventListener("click", loadCopyPlans);
  byId("cancelExecuteButton").addEventListener("click", closeExecuteDialog);
  byId("executeAcknowledgement").addEventListener("change", event => {
    byId("confirmExecuteButton").disabled = !event.target.checked || !selectedCopyPlan;
  });
  byId("confirmExecuteButton").addEventListener("click", executeCopyPlan);
  byId("executeDialog").addEventListener("close", () => {
    selectedCopyPlan = null;
  });
  byId("deviceFilterForm").addEventListener("keydown", event => {
    if (event.key !== "Escape") {
      return;
    }
    event.preventDefault();
    if (event.target === byId("fOuSearch")) {
      byId("fOuSearch").value = "";
      renderOuOptions();
      updateScanReadiness();
      return;
    }
    resetDeviceReportFilters();
  });
  window.addEventListener("beforeunload", () => {
    if (activeScanTimer) {
      window.clearTimeout(activeScanTimer);
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  void Promise.allSettled([
    loadSession(),
    loadDirectoryStructure(),
    loadData(),
    loadLegacyFiles(),
    loadLicenseRecommendations(),
    loadCopyPlans()
  ]);
});
