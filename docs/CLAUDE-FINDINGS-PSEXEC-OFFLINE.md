# Claude Findings: Proving the PsExec "All Offline" Failure Reason

Continues `docs/CLAUDE-HANDOFF-OFFLINE-COLLECTOR.md`. Scope: prove, from the
code, exactly why every endpoint is reported `Offline`, and give the operator a
way to test endpoint `ADMIN$` access under the real service identity.

This analysis is code-grounded. No live customer environment was reachable from
the investigation host, and the project targets `net10.0-windows`, which cannot
be compiled or unit-tested on the Linux investigation host — CI on Windows is
the validation gate for the code change described below.

## What "Offline" actually means in this code

A device is stored as `Offline` **only** when
`PsExecCollectorRunner.IsOfflineFailure(exitCode, error)` returns `true`
(`ScanOrchestratorService.GetFailureStatus`). That happens when, and only when:

1. the error text does **not** contain an access-denied marker
   (`access is denied`, `erişim engellendi`, `erişim reddedildi`), **and**
2. either the PsExec exit code is one of the transient-network codes
   `{53, 64, 67, 121, 1231, 1232, 1460, 1722, 1726}`, **or** the error text
   matches a network/RPC marker (`network path was not found`,
   `rpc server is unavailable`, `no such host is known`, `timed out`,
   `couldn't access`, `ağ yolu bulunamadı`, …).

Access-denied is deliberately classified as `Error`, not `Offline`
(`PsExecCollectorRunnerTests.IsOfflineFailure_DoesNotRetryAuthorizationFailures`).

### Consequence for the "all 118 offline" symptom

If the root cause were simply *"the machine account `NBR\NBRADC$` is not an
endpoint local administrator"* (handoff hypothesis #1), PsExec would still reach
the endpoint's SMB layer and be **rejected with access-denied (exit 5)** — which
this code maps to **`Error`, not `Offline`**. A pure "not a local admin"
condition would therefore surface as a wall of `Error`, not `Offline`.

Every device landing on `Offline` instead means each one produced a
**network/RPC-class failure** — the collector could not even reach the SMB layer
to be told "access denied". A *uniform* all-offline result is the signature of an
**environment-wide reachability block from `NBRADC` to the endpoints**, most
plausibly (in order):

- **TCP 445 / SMB blocked** by endpoint firewall (Domain-profile GPO) or network
  segmentation → exit 53 / 1722 / timeout (handoff hypothesis #2).
- **`ADMIN$` administrative share disabled** by policy → network-name errors.
- **Name resolution returning stale/dead IPs** for decommissioned or re-IP'd
  hosts → `no such host is known` / unreachable.
- Genuinely powered-off hosts (but 118/118 being off, right after AD discovery
  returned them, is unlikely).

This is a meaningful refinement of the handoff's leading hypothesis: the
all-`Offline` symptom points at hypothesis **#2 (SMB/ADMIN$/firewall)** or DNS
more than at #1 (machine-account admin rights). The single decisive measurement
is the **exact exit code + error text of one known powered-on endpoint** — which
the current build does not preserve. That gap is the real blocker, and it is
what this change closes.

## Why the exact failure reason is currently unprovable

Three defects in `PsExecCollectorRunner.RunAsync` (pre-change) destroy the
evidence needed to answer handoff Review Question #1 ("top exact errorMessage
values and PsExec exit codes"):

1. **The exit code is discarded.** In the non-zero branch the code computed
   `IsOfflineFailure(process.ExitCode, error)` and then threw `process.ExitCode`
   away — `CollectResult` had no field for it and the persisted `ErrorMessage`
   never contained it. Review Question #1 was literally unanswerable from the
   dashboard.

2. **Only stderr was captured on failure.** `error = string.IsNullOrWhiteSpace(stderr) ? "PsExec command failed." : stderr.Trim();`
   If a PsExec build (or the remote PowerShell) writes the real reason to
   **stdout**, the persisted message collapses to the useless
   `"PsExec command failed."` and classification runs on empty text.

3. **Console output encoding is not pinned (still open).** `ProcessStartInfo`
   sets neither `StandardOutputEncoding` nor `StandardErrorEncoding`. On the
   Turkish-locale endpoints (`nbr.local`), PsExec/Windows emit **localized** error
   text using the console's OEM/ANSI code page (e.g. CP857/CP1254). Read with a
   mismatched code page, "Erişim reddedildi" / "Ağ yolu bulunamadı" arrive
   mangled, so the **Turkish markers in `IsOfflineFailure` cannot match** — they
   are effectively dead code in exactly this customer's locale. A mangled Turkish
   access-denied then fails the access-denied test *and* the network test →
   classified `Error` with unreadable text. This is handoff hypothesis #5.

## Change made in this branch

Surgical, single-file, no schema/API/signature change (low risk for a
Windows-only build validated only by CI):

- `CollectResult` gains an optional `ExitCode` field.
- On a non-zero PsExec exit, the persisted message is now
  `"PsExec exit {code}: {detail}"`, where `detail` is composed from **both**
  streams via the new pure helper `ComposeFailureDetail(stdout, stderr)`
  (stderr preferred, stdout appended/fallback, each bounded to 1500 chars).
- Classification (`IsOfflineFailure`) now runs on the combined `detail`, so a
  reason written to stdout is classified too — while the access-denied precedence
  is preserved.

Effect: the exact exit code and the real diagnostic text (from whichever stream
PsExec used) are now visible in `/api/inventory/devices` `errorMessage`, so the
operator can distinguish exit 53 (network) from exit 5 (access-denied) from the
dashboard alone. Tests added: `ComposeFailureDetail_*` cover stderr preference,
stdout fallback, empty-stream fallback, and stdout-carried access-denied still
classifying as non-offline.

### Deliberately NOT changed

- **No speculative marker expansion.** The handoff says to expand localized
  markers only from observed customer evidence. The field script below captures
  that evidence first.
- **No dedicated `PsExecExitCode` column yet.** The handoff prefers the exit code
  persisted *separately*. That is the right follow-up but needs a schema column
  + ingestion signature + API surfacing across several files, best landed and
  validated on a Windows build. The `CollectResult.ExitCode` field is in place to
  thread it through when that follow-up is done; for now the code is embedded in
  the human-readable message so no evidence is lost in the meantime.
- **The encoding fix (defect #3) is not applied here.** Pinning the streams to
  the OEM code page requires `System.Text.Encoding.CodePages` +
  `Encoding.RegisterProvider(...)`, whose restore/build cannot be verified off
  Windows. It is specified above and should be applied and validated on a Windows
  build as the immediate next step, because it is what makes the Turkish markers
  work in this environment.

## Field evidence: prove it on NBRADC

`scripts/Invoke-CollectorAccessDiagnostic.ps1` (new) runs on the management
server in an elevated console and, for one target endpoint:

1. reports the O365AuditTool service identity and its effective network identity
   (machine account vs gMSA);
2. tests DNS + TCP 445 (interactive context);
3. tests `ADMIN$` and SCM **through `psexec -s`**, so the network hop is made as
   the real service identity (`DOMAIN\SERVERNAME$` / gMSA) — not the interactive
   admin;
4. verifies the collector share is present and hash-matches the pinned value;
5. **reproduces the exact collector PsExec invocation** (same args as
   `RunAsync`, no `-u/-p`) and prints the **real exit code, stderr, and stdout**,
   then prints a verdict mapping the result to the classifier
   (SUCCESS / AUTHORIZATION / NETWORK-OFFLINE / UNCLASSIFIED).

```powershell
cd C:\temp\o365audit\app   # or wherever scripts\ was deployed
.\Invoke-CollectorAccessDiagnostic.ps1 -Target PC-TEST-01
```

Decision tree (also in `docs/DEPLOYMENT-DC.md`):

- TCP 445 Fail → network / DNS / firewall / offline.
- TCP 445 Pass + `ADMIN$` Fail as service identity → the service identity lacks
  endpoint admin rights, or `ADMIN$` is disabled (this classifies as `Error`).
- `ADMIN$` Pass + collector exit ≠ 0 → inspect SCM, EDR (`PSEXESVC` /
  `-EncodedCommand`), and the exact error text.
- **Powered-on device shown as `Offline`** → the collector hit a network/RPC exit
  code, i.e. it could not reach SMB — confirm firewall/445/ADMIN$ policy, not
  admin-group membership.

## Recommended next steps (in order)

1. Run the field script against one known powered-on endpoint; capture the exact
   exit code + text (sanitized). This resolves #1-vs-#2 definitively.
2. Apply and Windows-validate the OEM-encoding fix (defect #3).
3. Add the dedicated `PsExecExitCode` column + surface it in the devices API
   (thread `CollectResult.ExitCode` → `SaveFailureAsync`).
4. Only then, if the captured text shows an unhandled localized marker, expand
   the classifier from that real evidence.
5. Consider the privileged preflight endpoint from the handoff (DNS/445/ADMIN$/
   SCM/collector-share for one device) — the field script is its interim, manual
   equivalent.


## GUNCELLEME (v1.2.8): dogrulanan kok neden — PsExec konsol gerektiriyor

Musterinin sunucusunda SYSTEM olarak yapilan kontrollu deneyler (PsExec 2.43):

| Baslatma bicimi | Sonuc |
|---|---|
| CreateNoWindow (mevcut kod), stdin pipe | exit 6 — handle is invalid |
| stdin = NUL | exit 6 |
| `-h` bayragi olmadan | exit 6 |
| **Yeni konsol tahsis edilerek** (`cmd /c start "" /wait ...`) | **exit 0 — basarili** |

Yani stdin yonlendirmesi (onceki duzeltme) yeterli degildi; PsExec calisirken gercek
bir konsola ihtiyac duyuyor. Servis session 0'da `CREATE_NO_WINDOW` ile baslattigi
icin cocuk surec hic konsol almiyordu ve PsExec endpoint'e ulasamadan
"Couldn't access <host>: The handle is invalid." (exit 6) ile dusuyordu. Bu metin
"couldn't access" ag isaretcisine takildigi icin tum cihazlar Offline raporlaniyordu.

Duzeltme: `CreateNoWindow=false` — ebeveynin konsolu olmadigindan CreateProcess
cocuga gizli bir conhost tahsis eder; yonlendirilmis stdout/stderr cikti yakalamaya
devam eder. Regresyon testi `BuildStartInfo_AllocatesAConsoleForPsExec` bu bayragi
kilitler.
