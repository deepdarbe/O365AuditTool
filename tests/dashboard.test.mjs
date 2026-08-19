import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(testDirectory, "..");
const html = await readFile(path.join(projectRoot, "src", "O365AuditTool", "wwwroot", "index.html"), "utf8");
const app = await readFile(path.join(projectRoot, "src", "O365AuditTool", "wwwroot", "app.js"), "utf8");

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
  assert.doesNotMatch(app, /\.innerHTML\s*=/, "API data must not be rendered through innerHTML");
  assert.doesNotMatch(app, /details\s*=\s*responseText/, "raw server responses must not be shown to users");
  assert.match(app, /\/api\/directory\/structure/);
  assert.match(app, /\/api\/jobs\/\$\{encodeURIComponent\(jobId\)\}/);
  assert.match(app, /Tarama erişimi sınırlı/);
  assert.match(app, /cihaz başarıyla toplandı/);
});
