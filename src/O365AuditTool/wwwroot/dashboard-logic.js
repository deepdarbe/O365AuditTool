"use strict";

// Failure classification shared with the server. PsExecCollectorRunner.IsOfflineFailure makes
// the same decision on the collector side, so the two must stay in step; this file exists so
// node can exercise the rules without a DOM. The dashboard used to keep its own copy of the
// markers and it drifted: the generic "couldn't access" marker matched first, so the 2026-08
// incident ("PsExec exit 6: Couldn't access <host>: The handle is invalid." — the service
// identity could not write to the endpoint ADMIN$) reached the operator labelled "Ağ / Offline"
// and sent them hunting a firewall instead of the missing endpoint rights.
(function (root) {
  "use strict";

  // Also the CSS class names on .failure-badge, so these keys are part of the dashboard
  // contract and every marker below must use one of them.
  const categoryLabels = {
    network: "Ağ / Offline",
    auth: "Yetki",
    timeout: "Zaman aşımı",
    error: "Hata"
  };

  // Precedence step 1 — the exit code, taken from the stored column when the row has one (see
  // resolvePsExecExit). PsExec reports the Win32 code that stopped it, and the code survives the
  // OEM code page mangling that garbles localized endpoint text, so it is a stronger signal than
  // any string match. The network codes mirror the transient list in
  // PsExecCollectorRunner.IsOfflineFailure; the authorization codes stay above them because a
  // rights problem retried as "offline" only hides that the service identity is wrong.
  const exitCodeMarkers = [
    { codes: [5], category: "auth", label: "Erişim reddedildi", hint: "Servis kimliği endpoint local Administrator değil ya da ADMIN$/SCM erişimi kısıtlı." },
    { codes: [6], category: "auth", label: "Geçersiz tanıtıcı: ADMIN$ yazılamadı", hint: "PsExec servisi endpoint'e kopyalayamadı; ağ değil, yetki sorunu. Servis kimliğini endpoint local Administrator yapın." },
    { codes: [1326], category: "auth", label: "Oturum açma başarısız", hint: "Kimlik bilgisi endpoint tarafından reddedildi; parola veya güven ilişkisi bozuk olabilir." },
    { codes: [1311], category: "auth", label: "Oturum açma sunucusu bulunamadı", hint: "Endpoint bir domain controller'a ulaşamadı; kimlik doğrulanamıyor." },
    { codes: [1327, 1331], category: "auth", label: "Hesap kısıtlı veya devre dışı", hint: "Servis kimliği devre dışı, süresi dolmuş veya oturum açma saatleriyle kısıtlanmış." },
    { codes: [1385], category: "auth", label: "Oturum açma türüne izin yok", hint: "GPO endpoint'te bu hesaba ağ üzerinden oturum açma hakkı vermiyor." },
    { codes: [1789], category: "auth", label: "Güven ilişkisi bozuk", hint: "Endpoint'in domain güven ilişkisi bozulmuş; makineyi domain'e yeniden katın." },
    { codes: [53, 67], category: "network", label: "Ağ yolu bulunamadı", hint: "SMB/TCP 445 kapalı, ADMIN$ devre dışı veya cihaz gerçekten kapalı." },
    { codes: [64, 1231, 1232], category: "network", label: "Ağ konumuna ulaşılamıyor", hint: "Segmentasyon, firewall veya cihaz erişilemez." },
    { codes: [121, 1460], category: "network", label: "Ağ zaman aşımına uğradı", hint: "Bağlantı kuruldu ama yanıt gelmedi; yarı-açık bağlantı veya aşırı yüklü cihaz." },
    { codes: [1722, 1726], category: "network", label: "RPC sunucusu kullanılamıyor", hint: "Uzak Service Control Manager / RPC erişilemiyor." }
  ];

  // Precedence step 2 — authorization text. Mirrors the early return in
  // PsExecCollectorRunner.IsOfflineFailure: these win over every network marker, because
  // PsExec wraps them in a network-sounding "Couldn't access <host>: ..." sentence.
  const authorizationMarkers = [
    { re: /(access is denied|erişim engellendi|erişim reddedildi)/i, category: "auth", label: "Erişim reddedildi", hint: "Servis kimliği endpoint local Administrator değil ya da ADMIN$/SCM erişimi kısıtlı." },
    { re: /(handle is invalid|tanıtıcı geçersiz|geçersiz tanıtıcı)/i, category: "auth", label: "Geçersiz tanıtıcı: ADMIN$ yazılamadı", hint: "PsExec servisi endpoint'e kopyalayamadı; ağ değil, yetki sorunu. Servis kimliğini endpoint local Administrator yapın." },
    { re: /(logon failure|oturum açma)/i, category: "auth", label: "Oturum açma başarısız", hint: "Kimlik bilgisi endpoint tarafından reddedildi; parola veya güven ilişkisi bozuk olabilir." },
    { re: /(trust relationship|güven ilişkisi)/i, category: "auth", label: "Güven ilişkisi bozuk", hint: "Endpoint'in domain güven ilişkisi bozulmuş; makineyi domain'e yeniden katın." }
  ];

  // Precedence step 3 — remaining text markers, specific before generic. The catch-all PsExec
  // connect marker is last on purpose: it appears in authorization failures too.
  const failureMarkers = [
    { re: /(network path was not found|ağ yolu bulunamadı)/i, category: "network", label: "Ağ yolu bulunamadı", hint: "SMB/TCP 445 kapalı, ADMIN$ devre dışı veya cihaz gerçekten kapalı." },
    { re: /(rpc server is unavailable|rpc sunucusu kullanılamıyor)/i, category: "network", label: "RPC sunucusu kullanılamıyor", hint: "Uzak Service Control Manager / RPC erişilemiyor." },
    { re: /(no such host is known|ana bilgisayar bilinmiyor)/i, category: "network", label: "Ana bilgisayar bilinmiyor", hint: "DNS çözümlemesi başarısız veya kayıt bayat." },
    { re: /(host is unreachable|network location cannot be reached|network name is no longer available)/i, category: "network", label: "Ağ konumuna ulaşılamıyor", hint: "Segmentasyon, firewall veya cihaz erişilemez." },
    // The server measures reachability before spending a PsExec slot and reports the verdict with
    // this exact prefix (PsExecCollectorRunner.RunAsync). It must be read before the generic timeout
    // marker below, otherwise a measured-offline device is shown as a collector timeout.
    { re: /device is unreachable/i, category: "network", label: "Cihaza ulaşılamadı", hint: "SMB portu (445/139) yanıt vermedi; cihaz kapalı, ağda değil veya firewall engelliyor." },
    { re: /(integrity validation failed|sha256)/i, category: "error", label: "Bütünlük doğrulaması başarısız", hint: "Collector veya PsExec hash'i beklenen değerle uyuşmuyor." },
    { re: /(timed out|zaman aşımı|timeout)/i, category: "timeout", label: "Zaman aşımı", hint: "Toplayıcı süre içinde yanıt vermedi; yavaş cihaz veya yarı-açık bağlantı." },
    { re: /(could not start|couldn't access)/i, category: "network", label: "PsExec endpoint'e erişemedi", hint: "Servis kopyalanamadı/başlatılamadı; ADMIN$/SCM erişimini doğrulayın." }
  ];

  function parsePsExecExit(message) {
    const match = /PsExec exit (-?\d+)\s*:/i.exec(message || "");
    return match ? Number(match[1]) : null;
  }

  function normalizeExitCode(value) {
    if (typeof value === "number") {
      return Number.isFinite(value) ? value : null;
    }
    // JSON keeps the column as a number, but a string survives a hand-built row or a proxy that
    // re-serializes; accepting it costs one branch and avoids Number(null) === 0 further down.
    if (typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value))) {
      return Number(value);
    }
    return null;
  }

  // The API row carries the code the collector recorded (DeviceInventory.PsExecExitCode, sent as
  // "psExecExitCode"). Prefer it over the message: re-parsing prose is the indirection that let one
  // authorization failure read as a network outage across 117 devices, and the recorded code also
  // survives text the endpoint returns in its OEM code page. Rows stored before the column existed
  // carry no value, so the text parse has to stay as the fallback.
  function resolvePsExecExit(device, explicitExit) {
    const source = device || {};
    const reported = explicitExit === undefined ? source.psExecExitCode : explicitExit;
    const recorded = normalizeExitCode(reported);
    return recorded === null ? parsePsExecExit(source.errorMessage) : recorded;
  }

  function findExitCodeMarker(exit) {
    if (exit === null || !Number.isFinite(exit)) {
      return undefined;
    }
    return exitCodeMarkers.find(item => item.codes.includes(exit));
  }

  function classifyFailure(device, explicitExit) {
    const statusNum = Number(device.status);
    const message = String(device.errorMessage || "").trim();
    const exit = resolvePsExecExit(device, explicitExit);
    const core = message.replace(/^PsExec exit -?\d+\s*:\s*/i, "").trim();
    const marker = findExitCodeMarker(exit)
      || authorizationMarkers.find(item => item.re.test(message))
      || failureMarkers.find(item => item.re.test(message));
    if (marker) {
      return { category: marker.category, label: marker.label, hint: marker.hint, exit, statusNum };
    }
    const fallbackCategory = statusNum === 4 ? "timeout" : statusNum === 1 ? "network" : "error";
    const fallbackLabel = core ? core.slice(0, 90) : "Sınıflandırılmamış hata";
    return { category: fallbackCategory, label: fallbackLabel, hint: "Tam metin için cihaz satırındaki 'Tarama hatası' sütununa bakın.", exit, statusNum };
  }

  root.O365Dashboard = {
    categoryLabels,
    exitCodeMarkers,
    authorizationMarkers,
    failureMarkers,
    parsePsExecExit,
    resolvePsExecExit,
    classifyFailure
  };
})(globalThis);
