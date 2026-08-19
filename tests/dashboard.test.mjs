import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import path from "node:path";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(testDirectory, "..");
const wwwroot = path.join(projectRoot, "src", "O365AuditTool", "wwwroot");
const html = await readFile(path.join(wwwroot, "index.html"), "utf8");
const app = await readFile(path.join(wwwroot, "app.js"), "utf8");
const logic = await readFile(path.join(wwwroot, "dashboard-logic.js"), "utf8");

// dashboard-logic.js is a classic browser script, not an ES module, so it is evaluated in a
// bare vm context instead of imported: that loads it exactly the way the browser does and
// proves at the same time that the classification rules need no DOM.
const logicContext = vm.createContext({});
vm.runInContext(logic, logicContext, { filename: "dashboard-logic.js" });
const dashboard = logicContext.O365Dashboard;

function classify(errorMessage, status) {
  return dashboard.classifyFailure({ status, errorMessage });
}

function captures(source, pattern) {
  return [...source.matchAll(pattern)].map(match => match[1]);
}

test("dashboard DOM references are complete and IDs are unique", () => {
  const htmlIds = captures(html, /\bid="([^"]+)"/g);
  const uniqueIds = new Set(htmlIds);
  const javascriptIds = new Set(captures(app, /byId\("([^"]+)"\)/g));

  assert.equal(uniqueIds.size, htmlIds.length, "index.html contains duplicate IDs");
  assert.deepEqual(
    [...javascriptIds].filter(id => !uniqueIds.has(id)),
    [],
    "app.js references IDs that are missing from index.html");
});

test("dashboard forms and tables keep accessibility contracts", () => {
  assert.match(html, /<html lang="tr">/);
  assert.match(html, /class="skip-link"/);
  assert.match(html, /<main[^>]+id="mainContent"/);

  const tables = [...html.matchAll(/<table(?:\s[^>]*)?>/g)];
  const captions = [...html.matchAll(/<caption(?:\s[^>]*)?>/g)];
  assert.equal(captions.length, tables.length, "every table must have a caption");

  for (const heading of html.matchAll(/<th\b([^>]*)>/g)) {
    assert.match(heading[1], /scope="col"/, "every table heading must declare column scope");
  }

  for (const button of html.matchAll(/<button([^>]*)>/g)) {
    assert.match(button[1], /type="(?:button|submit)"/, "every button must declare its type");
  }
});

test("dashboard keeps safe API and mutation behavior", () => {
  assert.match(app, /credentials\s*=\s*"same-origin"/);
  assert.match(app, /X-O365Audit-CSRF/);
  assert.match(app, /\/api\/directory\/structure/);
  assert.match(app, /\/api\/jobs\/\$\{encodeURIComponent\(jobId\)\}/);
  assert.match(app, /Tarama erişimi sınırlı/);
  assert.match(app, /cihaz başarıyla toplandı/);
  assert.doesNotMatch(app, /details\s*=\s*responseText/, "raw server responses must not be shown to users");

  for (const [name, source] of Object.entries({ "app.js": app, "dashboard-logic.js": logic })) {
    assert.doesNotMatch(source, /\.(?:inner|outer)HTML\s*\+?=/, `${name}: API data must not be rendered through innerHTML/outerHTML`);
    assert.doesNotMatch(source, /insertAdjacentHTML/, `${name}: API data must not be rendered through insertAdjacentHTML`);
    assert.doesNotMatch(source, /document\.write/, `${name}: API data must not be rendered through document.write`);
  }
});

test("failure classification helpers are shared, not duplicated", () => {
  assert.equal(typeof dashboard.classifyFailure, "function");
  assert.equal(typeof dashboard.parsePsExecExit, "function");

  // Everything app.js pulls off the shared object at parse time must exist, or the whole
  // dashboard fails to load rather than degrading.
  const destructured = /const\s*\{([^}]+)\}\s*=\s*globalThis\.O365Dashboard/.exec(app);
  assert.ok(destructured, "app.js must consume the shared rules");
  for (const name of destructured[1].split(",").map(part => part.trim()).filter(Boolean)) {
    assert.ok(Object.hasOwn(dashboard, name), `dashboard-logic.js does not export ${name}`);
  }

  assert.doesNotMatch(app, /const failureMarkers\s*=/, "app.js must not keep a second copy of the markers");
  assert.doesNotMatch(app, /function classifyFailure\b/, "app.js must not keep a second classifier");
  assert.doesNotMatch(app, /function parsePsExecExit\b/, "app.js must not keep a second exit code parser");

  const scriptTags = [...html.matchAll(/<script\b([^>]*)>/g)].map(match => match[1]);
  const logicTag = html.indexOf("src=\"/dashboard-logic.js\"");
  const appTag = html.indexOf("src=\"/app.js\"");
  assert.ok(logicTag > -1, "index.html must load dashboard-logic.js");
  assert.ok(logicTag < appTag, "dashboard-logic.js must load before app.js");
  for (const attributes of scriptTags) {
    // defer/async would break the document order app.js depends on at parse time.
    assert.doesNotMatch(attributes, /\b(?:defer|async)\b/, "dashboard scripts must execute in document order");
  }

  assert.doesNotMatch(logic, /\bdocument\b/, "dashboard-logic.js must stay DOM-free");
  assert.doesNotMatch(logic, /\bwindow\b/, "dashboard-logic.js must stay DOM-free");
});

test("authorization failures outrank the generic PsExec network markers", () => {
  // Measured 2026-08: the server (PsExecCollectorRunner.IsOfflineFailure) treats this as an
  // authorization failure. The dashboard used to match "couldn't access" first and showed the
  // operator a network problem.
  const measured = classify("PsExec exit 6: Couldn't access CORELAPP:\nThe handle is invalid.", 2);
  assert.equal(measured.category, "auth");
  assert.notEqual(measured.category, "network");
  assert.equal(measured.exit, 6);

  const withoutExitCode = classify("Couldn't access CORELAPP:\nThe handle is invalid.", 2);
  assert.equal(withoutExitCode.category, "auth");
  assert.equal(withoutExitCode.exit, null);

  const denied = classify("PsExec exit 5: Couldn't access CORELAPP:\nAccess is denied.", 2);
  assert.equal(denied.category, "auth");
  assert.equal(denied.exit, 5);
});

test("network, timeout and unclassified failures keep their categories", () => {
  const network = classify("PsExec exit 53: Couldn't access NBRPC14:\nThe network path was not found.", 1);
  assert.equal(network.category, "network");
  assert.equal(network.exit, 53);

  const timeout = classify("Collector timed out after 300 seconds. stderr: <empty>", 4);
  assert.equal(timeout.category, "timeout");
  assert.equal(timeout.exit, null);

  const payload = classify("Collector output did not contain JSON payload. stdout: <empty>", 2);
  assert.equal(payload.category, "error");

  const rpc = classify("PsExec exit 1722: The RPC server is unavailable.", 1);
  assert.equal(rpc.category, "network");
});

// The server measures reachability before spending a PsExec slot and stores the verdict with
// IsOffline=true. The dashboard must agree: reading it as a collector timeout would send the
// operator looking for a slow endpoint instead of a device that never answered at all.
test("a measured unreachable device reads as network, not timeout", () => {
  const probed = classify(
    "Device is unreachable: no answer on TCP 445 within 5 seconds (no response).",
    1);
  assert.equal(probed.category, "network");
  assert.equal(probed.exit, null);

  const probedClosedPort = classify(
    "Device is unreachable: no answer on TCP 445 within 5 seconds (SocketException).",
    1);
  assert.equal(probedClosedPort.category, "network");
});

test("the exit code decides before the message text", () => {
  // A Turkish endpoint returns its message in the OEM code page; when it arrives mangled the
  // exit code is the only signal left, so it has to be read first.
  const mangled = classify("PsExec exit 6: Couldn't access CORELAPP:\nTan?t?c? ge?ersiz.", 2);
  assert.equal(mangled.category, "auth");

  const unreachable = classify("PsExec exit 1231: Couldn't access PC-014:\n???", 1);
  assert.equal(unreachable.category, "network");
});

test("unmatched failures fall back to the device status", () => {
  assert.equal(classify("Something nobody has seen before", 1).category, "network");
  assert.equal(classify("Something nobody has seen before", 4).category, "timeout");
  assert.equal(classify("Something nobody has seen before", 2).category, "error");
  assert.equal(classify("", 2).label, "Sınıflandırılmamış hata");
});

test("every rule and fallback maps to a badge label", () => {
  const categories = new Set([
    ...dashboard.exitCodeMarkers.map(marker => marker.category),
    ...dashboard.authorizationMarkers.map(marker => marker.category),
    ...dashboard.failureMarkers.map(marker => marker.category),
    classify("", 1).category,
    classify("", 2).category,
    classify("", 4).category
  ]);

  for (const category of categories) {
    assert.ok(
      Object.hasOwn(dashboard.categoryLabels, category),
      `category ${category} has no failure-badge label`);
    assert.ok(
      html.includes(`.failure-badge.${category} {`),
      `category ${category} has no failure-badge style`);
  }
});

test("marker order cannot silently regress", () => {
  // Arrays come from the vm realm, so compare counts rather than identities.
  assert.equal(
    dashboard.failureMarkers.filter(marker => marker.category === "auth").length,
    0,
    "authorization rules belong in authorizationMarkers, above the network markers");

  const lastTextMarker = dashboard.failureMarkers.at(-1);
  assert.ok(
    lastTextMarker.re.test("Couldn't access CORELAPP:"),
    "the catch-all PsExec connect marker must stay last so specific rules win");

  assert.ok(
    dashboard.authorizationMarkers.some(marker => marker.re.test("The handle is invalid.")),
    "handle-invalid must be an authorization marker, matching the server");
});

test("parsePsExecExit reads the exit code the server writes", () => {
  assert.equal(dashboard.parsePsExecExit("PsExec exit 53: The network path was not found."), 53);
  assert.equal(dashboard.parsePsExecExit("PsExec exit -1073741502: init failed"), -1073741502);
  assert.equal(dashboard.parsePsExecExit("Collector timed out after 300 seconds."), null);
  assert.equal(dashboard.parsePsExecExit(null), null);
});
