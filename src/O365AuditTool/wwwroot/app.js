"use strict";

const copyStatusNames = ["Planned", "Queued", "Running", "Completed", "Completed with errors", "Failed"];
const copyItemStatusNames = ["Planned", "Queued", "Copying", "Completed", "Skipped", "Failed"];
let selectedCopyPlan = null;

function byId(id) {
  return document.getElementById(id);
}

function setFeedback(id, message, kind = "muted") {
  const element = byId(id);
  element.textContent = message;
  element.className = `feedback ${kind}`;
}

function getErrorMessage(error, fallback) {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return fallback;
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const responseText = await response.text();
  if (!response.ok) {
    let details = "";
    try {
      const problem = responseText ? JSON.parse(responseText) : {};
      details = problem.detail || problem.title || problem.message || "";
    } catch {
      details = responseText;
    }
    throw new Error(details || `HTTP ${response.status}`);
  }

  if (!responseText) {
    return null;
  }
  return JSON.parse(responseText);
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

function appendStatusCell(row, text, className) {
  const cell = document.createElement("td");
  const status = document.createElement("span");
  status.textContent = text;
  status.className = className;
  cell.appendChild(status);
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
    device: byId("fDevice").value.trim(),
    user: byId("fUser").value.trim(),
    diskType: byId("fDiskType").value,
    officeVersion: byId("fOfficeVersion").value.trim()
  };
  Object.entries(filters).forEach(([key, value]) => {
    if (value) {
      query.set(key, value);
    }
  });
  return query;
}

async function loadData() {
  setFeedback("deviceFeedback", "Cihaz envanteri yükleniyor...");
  try {
    const data = asArray(await fetchJson(`/api/inventory/devices?${getDeviceFilterQuery()}`));
    renderStats(data);
    renderDeviceRows(data);
    setFeedback("deviceFeedback", `${data.length} cihaz gösteriliyor.`, "ok");
  } catch (error) {
    setFeedback("deviceFeedback", `Cihaz verisi yüklenemedi: ${getErrorMessage(error, "Bilinmeyen hata")}`, "error");
  }
}

function renderStats(data) {
  const offline = data.filter(item => Number(item.status) === 1).length;
  const errors = data.filter(item => Number(item.status) === 2).length;
  const pstBytes = data.reduce((total, item) => total + Number(item.pstTotalBytes || 0), 0);
  const fastStorage = data.filter(item =>
    (item.disks || []).some(disk => ["SSD", "NVME"].includes(String(disk.mediaType || "").toUpperCase()))
  ).length;

  byId("statDevices").textContent = String(data.length);
  byId("statOffline").textContent = String(offline);
  byId("statErrors").textContent = String(errors);
  byId("statPst").textContent = (pstBytes / (1024 ** 3)).toFixed(1);
  byId("statStorage").textContent = String(fastStorage);
}

function renderDeviceRows(data) {
  const body = byId("deviceRows");
  const fragment = document.createDocumentFragment();
  const deviceStatuses = {
    0: ["Success", "ok"],
    1: ["Offline", "offline"],
    2: ["Error", "error"]
  };

  data.forEach(device => {
    const row = document.createElement("tr");
    appendCell(row, device.deviceName || "-");
    const status = deviceStatuses[Number(device.status)] || [String(device.status ?? "Unknown"), "muted"];
    appendStatusCell(row, status[0], status[1]);
    appendCell(row, device.serialNumber || "-");
    appendCell(row, formatIpAddresses(device.ipAddresses));
    appendCell(row, device.lastLoggedOnUser || "-");

    const diskText = (device.disks || [])
      .map(disk => `${disk.mediaType || "-"} ${disk.model || ""}`.trim())
      .join("\n") || "-";
    const diskCell = appendCell(row, diskText);
    diskCell.style.whiteSpace = "pre-line";

    const freeBytes = (device.volumes || []).reduce((total, volume) => total + Number(volume.freeBytes || 0), 0);
    appendCell(row, (freeBytes / (1024 ** 3)).toFixed(1));

    const officeText = (device.officeProducts || [])
      .map(product => `${product.name || ""} ${product.version || ""}`.trim())
      .filter(Boolean)
      .join("\n") || "-";
    const officeCell = appendCell(row, officeText);
    officeCell.style.whiteSpace = "pre-line";

    appendCell(row, (Number(device.pstTotalBytes || 0) / (1024 ** 3)).toFixed(1));
    appendCell(row, formatDate(device.collectedUtc));
    fragment.appendChild(row);
  });

  body.replaceChildren(fragment);
  byId("deviceEmpty").classList.toggle("visible", data.length === 0);
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
  setFeedback("legacyFeedback", "NK2/N2K envanteri yükleniyor...");
  try {
    const files = asArray(await fetchJson(`/api/inventory/legacy-files?${getLegacyFilterQuery()}`));
    renderLegacyRows(files);
    byId("statLegacy").textContent = String(files.length);
    setFeedback("legacyFeedback", `${files.length} legacy artefact gösteriliyor.`, "ok");
  } catch (error) {
    byId("statLegacy").textContent = "-";
    setFeedback("legacyFeedback", `Legacy dosyalar yüklenemedi: ${getErrorMessage(error, "Bilinmeyen hata")}`, "error");
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
    appendStatusCell(row, file.existsOnDisk === false ? "Unavailable" : "Available", file.existsOnDisk === false ? "error" : "ok");
    fragment.appendChild(row);
  });

  body.replaceChildren(fragment);
  byId("legacyEmpty").classList.toggle("visible", files.length === 0);
}

async function startScan() {
  const button = byId("startScanButton");
  button.disabled = true;
  setFeedback("deviceFeedback", "Tarama kuyruğa alınıyor...");
  try {
    const result = await fetchJson("/api/jobs/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ouFilter: null, siteFilter: null, manual: true })
    });
    setFeedback("deviceFeedback", `Tarama kuyruğa alındı: ${result.jobId || result.id || "-"}`, "ok");
  } catch (error) {
    setFeedback("deviceFeedback", `Tarama başlatılamadı: ${getErrorMessage(error, "AuditAdmin yetkisini kontrol edin.")}`, "error");
  } finally {
    button.disabled = false;
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
  submitButton.disabled = true;
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
    submitButton.disabled = false;
  }
}

function normalizeCopyStatus(value) {
  if (typeof value === "number" || /^\d+$/.test(String(value))) {
    return copyStatusNames[Number(value)] || String(value);
  }
  return String(value || "Unknown");
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
  setFeedback("copyFeedback", "Copy planları yükleniyor...");
  try {
    const plans = asArray(await fetchJson("/api/copy/plans"));
    renderCopyPlans(plans);
    setFeedback("copyFeedback", `${plans.length} copy planı gösteriliyor.`, "ok");
  } catch (error) {
    setFeedback("copyFeedback", `Copy planları yüklenemedi: ${getErrorMessage(error, "Bilinmeyen hata")}`, "error");
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
    appendStatusCell(row, normalizeCopyStatus(plan.status), copyStatusClass(plan.status));
    const targetCell = appendCell(row, plan.targetRoot || "-", "path-cell");
    targetCell.title = plan.targetRoot || "";
    appendCell(row, plan.requestedBy || "-");
    appendCell(row, String(totalItems));
    appendCell(row, `${completed} / ${failed}`);
    appendCell(row, formatDate(plan.createdUtc));

    const actionCell = document.createElement("td");
    const executeButton = document.createElement("button");
    executeButton.type = "button";
    executeButton.textContent = "Execute";
    executeButton.className = "danger";
    executeButton.disabled = !isPlanned(plan.status) || !id || totalItems === 0;
    executeButton.addEventListener("click", () => openExecuteDialog({ ...plan, id, totalItems }));
    actionCell.appendChild(executeButton);
    row.appendChild(actionCell);
    fragment.appendChild(row);
  });

  body.replaceChildren(fragment);
  byId("copyPlansEmpty").classList.toggle("visible", plans.length === 0);
}

function openExecuteDialog(plan) {
  selectedCopyPlan = plan;
  byId("executeSummary").textContent =
    `Plan: ${plan.id}\nHedef: ${plan.targetRoot || "-"}\nÖğe sayısı: ${plan.totalItems}`;
  byId("executeSummary").style.whiteSpace = "pre-line";
  byId("executeAcknowledgement").checked = false;
  byId("confirmExecuteButton").disabled = true;
  byId("executeDialog").showModal();
}

function closeExecuteDialog() {
  selectedCopyPlan = null;
  byId("executeDialog").close();
}

async function executeCopyPlan() {
  if (!selectedCopyPlan || !byId("executeAcknowledgement").checked) {
    return;
  }

  const planId = selectedCopyPlan.id;
  const button = byId("confirmExecuteButton");
  button.disabled = true;
  setFeedback("copyFeedback", `Plan execute kuyruğuna alınıyor: ${planId}`);
  try {
    await fetchJson(`/api/copy/plans/${encodeURIComponent(planId)}/execute`, { method: "POST" });
    closeExecuteDialog();
    setFeedback("copyFeedback", `Copy planı yürütme kuyruğuna alındı: ${planId}`, "ok");
    await loadCopyPlans();
  } catch (error) {
    setFeedback("copyFeedback", `Copy başlatılamadı: ${getErrorMessage(error, "AuditAdmin yetkisini ve sunucu Copy opt-in ayarını kontrol edin.")}`, "error");
    button.disabled = false;
  }
}

function bindEvents() {
  byId("filterDevicesButton").addEventListener("click", loadData);
  byId("startScanButton").addEventListener("click", startScan);
  byId("exportCsvButton").addEventListener("click", exportCsv);
  byId("exportPdfButton").addEventListener("click", exportPdf);
  byId("filterLegacyButton").addEventListener("click", loadLegacyFiles);
  byId("copyPlanForm").addEventListener("submit", createCopyPlan);
  byId("refreshPlansButton").addEventListener("click", loadCopyPlans);
  byId("cancelExecuteButton").addEventListener("click", closeExecuteDialog);
  byId("executeAcknowledgement").addEventListener("change", event => {
    byId("confirmExecuteButton").disabled = !event.target.checked;
  });
  byId("confirmExecuteButton").addEventListener("click", executeCopyPlan);
}

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  void Promise.allSettled([loadData(), loadLegacyFiles(), loadCopyPlans()]);
});
