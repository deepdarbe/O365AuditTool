# Claude Handoff: All Endpoints Reported Offline

## Objective

Find and fix why the O365AuditTool dashboard reports every Active Directory endpoint as offline and therefore collects no PST, Office, storage, profile, or legacy NK2/N2K inventory.

Do not treat `Offline` as an ICMP/ping result. In this application it means the PsExec collector failure matched a transient network/offline classifier.

## Current User-Visible Symptom

- Dashboard authentication and RBAC work.
- Active Directory discovery works and previously returned 58 OUs, one site, and 118 computer targets.
- The dashboard first showed 117 of 118 devices offline; the user now reports all devices offline.
- PST GB, SSD/NVMe, Office, and legacy counters remain zero because endpoint payloads are not being collected.
- The session badge shows `NBR\Administrator`, `NTLM`, and all three application roles.
- The dashboard host used by the customer is `nbradc.nbr.local`.
- The management server service was deployed as `LocalSystem` by `-AutoConfigure`.
- The known install root is `C:\temp\o365audit`.

The v1.2.1 UI correctly marks this as degraded inventory instead of saying the audit is ready. That UI fix does not solve endpoint access.

## Repository and Release State

- Private source repository: `deepdarbe/O365AuditTool`
- Public release repository: `deepdarbe/O365AuditTool-Releases`
- Current runtime tag: `v1.2.1`
- Runtime commit before this handoff document: `cb8295a04c8838ca60f8d9976f490195fdfc07a7`
- Public release: <https://github.com/deepdarbe/O365AuditTool-Releases/releases/tag/v1.2.1>
- Successful tag CI: <https://github.com/deepdarbe/O365AuditTool/actions/runs/32228661523>
- v1.2.1 bootstrap SHA256: `35D9F17C61B5392BA5EE975CDB2A1CC721334B8A142838F8221DCBFEF47BF04D`
- v1.2.1 bundle SHA256: `274C5417EA97B03A1F324075632C1B803C26FDC1EC2AF61D36C6CF4DFDDEBB35`
- Local tests at v1.2.1: .NET 118/118, dashboard 3/3.

Verify the customer actually upgraded to v1.2.1 before relying on the newer access-denied classification or degraded-readiness UI.

## Worktree Safety

The workspace contains unrelated, untracked Universal Data Protection work. Do not stage, delete, move, format, or modify it while working on O365AuditTool:

```text
.github/workflows/udp-platform-ci.yml
AI_READ_APP/
DEVELOPMENT_PLAN.md
artifacts/
docs/universal-data-protection/
pyproject.toml
scripts/Invoke-Udp*.ps1
scripts/New-Udp*.ps1
src/UniversalDataProtection/
src/app/
tests/ControlPlane.Api.Tests/
tests/test_controls_api.py
tests/test_repository.py
```

Stage O365AuditTool changes by explicit path only.

## Runtime Flow

1. The ASP.NET service runs on the management server.
2. AD target discovery returns computer names for an explicit OU or site scope.
3. `PsExecCollectorRunner` launches the protected PsExec binary against `\\TARGET`.
4. PsExec creates a temporary service on the endpoint and runs PowerShell as endpoint `SYSTEM`.
5. Endpoint PowerShell reads `\\NBRADC\o365audit\collector.ps1`, verifies its pinned SHA256, and executes it.
6. Collector JSON returns on stdout and is persisted to SQLite.

With the management service running as `LocalSystem`, outbound access to endpoints uses the management server computer account:

```text
NBR\NBRADC$
```

That computer account must be able to use endpoint `ADMIN$` and Service Control Manager. AutoConfigure does not and should not silently grant those domain-wide privileges.

## Highest-Probability Root Causes

### 1. LocalSystem machine account is not an endpoint administrator

This is the leading hypothesis. The original deployment printed this warning:

```text
LocalSystem ... remote device access uses the management server computer account; gMSA is recommended.
```

If `NBR\NBRADC$` is not in the endpoint local Administrators group, PsExec cannot create its remote service.

Preferred remediation is a dedicated gMSA plus a least-privilege AD group deployed to endpoint local Administrators through GPO. Do not use Domain Admins as the long-term service identity.

### 2. TCP 445, ADMIN$, or remote service control is blocked

PsExec requires at minimum endpoint name resolution, SMB/TCP 445, administrative shares, and remote Service Control Manager access. Endpoint firewall policy, disabled administrative shares, network segmentation, or EDR application control can block this.

### 3. AD contains stale or non-workstation targets

The default inactive threshold is 120 days. Confirm the selected OU does not mostly contain stale, disabled, decommissioned, server, or non-Windows computer objects.

### 4. Endpoint SYSTEM cannot read the collector share

The deployment grants the domain `Domain Computers` group read access to the collector SMB share and NTFS path. Verify the actual resolved group, share ACL, NTFS ACL, and endpoint access to:

```text
\\NBRADC\o365audit\collector.ps1
```

### 5. Failure classification hides a common authorization/localized message

`PsExecCollectorRunner.IsOfflineFailure` gives access-denied markers precedence over generic `couldn't access` markers in v1.2.0+. Confirm the exact persisted error messages. A localized or EDR-generated authorization message not covered by the classifier may still be labelled offline.

## First Evidence to Collect

Run these commands in an elevated PowerShell console on `NBRADC`.

### 1. Verify deployed version, service identity, and collector configuration

```powershell
$root = 'C:\temp\o365audit'
Get-CimInstance Win32_Service -Filter "Name='O365AuditTool'" |
    Select-Object Name, State, StartName, PathName

$settings = Get-Content "$root\app\appsettings.Production.json" -Raw | ConvertFrom-Json
$settings.Collector | Format-List PsExecPath, PsExecSha256, RemoteScriptPath, RemoteScriptSha256, DeviceTimeoutSeconds, MaxDeviceParallelism, ExcludeComputersInactiveDays, DefaultOuFilter, DefaultSiteFilter

Get-FileHash $settings.Collector.PsExecPath -Algorithm SHA256
Get-FileHash "$root\share\collector.ps1" -Algorithm SHA256
Invoke-RestMethod 'http://localhost:5081/health'
```

Expected:

- Service is `Running`.
- `StartName` is confirmed, likely `LocalSystem`.
- Both actual hashes equal the values in Production settings.
- Health is `healthy`.

### 2. Group the persisted endpoint failures by exact message

```powershell
$uri = 'https://nbradc.nbr.local:5080/api/inventory/devices'
$devices = Invoke-RestMethod -UseDefaultCredentials -Uri $uri
$devices |
    Group-Object errorMessage |
    Sort-Object Count -Descending |
    Select-Object Count, @{Name='ErrorMessage'; Expression={$_.Name}} |
    Format-Table -Wrap -AutoSize
```

If the customer certificate is not trusted by PowerShell, fix certificate trust rather than making insecure behavior part of the application. A temporary local diagnostic alternative is a Windows `curl.exe` build with SSPI support:

```powershell
curl.exe -k --negotiate -u : 'https://nbradc.nbr.local:5080/api/inventory/devices' |
    Set-Content -Encoding utf8 C:\temp\o365audit\devices-diagnostic.json
```

Sanitize domain usernames, hostnames, paths, and IP addresses before sharing output outside the customer environment.

### 3. Test a known powered-on endpoint

Replace `PC-TEST-01` with one workstation that is online and under the selected OU.

```powershell
$target = 'PC-TEST-01'
Resolve-DnsName $target
Test-NetConnection $target -Port 445
Test-Path "\\$target\ADMIN$"
```

The last command runs as the interactive administrator and is not sufficient to prove the service identity has access.

### 4. Test endpoint ADMIN$ as the actual LocalSystem network identity

The following starts a local process as `NBRADC` SYSTEM. Its network access is made as `NBR\NBRADC$`:

```powershell
$target = 'PC-TEST-01'
$psexec = 'C:\temp\o365audit\app\tools\psexec.exe'
& $psexec -accepteula -nobanner -s powershell.exe -NoProfile -Command "whoami; Test-Path '\\$target\ADMIN$'"
```

Interpretation:

- TCP 445 false: network, DNS, endpoint state, or firewall problem.
- TCP 445 true and LocalSystem `Test-Path` false: management server computer account lacks endpoint rights or ADMIN$ is disabled.
- Both true: continue with SCM, EDR, collector-share, and exact PsExec error analysis.

### 5. Verify collector share ACLs on the management server

```powershell
Get-SmbShare -Name o365audit
Get-SmbShareAccess -Name o365audit
Get-Acl 'C:\temp\o365audit\share' | Format-List Owner, AccessToString
Test-Path '\\NBRADC\o365audit\collector.ps1'
```

From a representative endpoint, also test the share as endpoint SYSTEM if local administrative access is available:

```powershell
Test-Path '\\NBRADC\o365audit\collector.ps1'
Get-FileHash '\\NBRADC\o365audit\collector.ps1' -Algorithm SHA256
```

## Code Map

- `src/O365AuditTool/Services/PsExecCollectorRunner.cs`
  - PsExec arguments, stdout/stderr handling, hash checks, timeout, hostname validation, and offline classification.
- `src/O365AuditTool/Services/ScanOrchestratorService.cs`
  - Target execution, failure status mapping, retry queue, and job summary.
- `src/O365AuditTool/Services/ActiveDirectoryTargetProvider.cs`
  - AD target filters, inactive threshold, OU/site matching.
- `src/O365AuditTool/Controllers/InventoryController.cs`
  - Returns `status` and persisted `errorMessage` for diagnosis.
- `src/O365AuditTool/Services/InventoryQueryService.cs`
  - Uses the latest device state while retaining the latest successful payload when one exists.
- `scripts/Deploy-ManagementServer.ps1`
  - Service identity selection, collector SMB ACLs, protected PsExec copy, and Production settings.
- `scripts/collector.ps1`
  - Endpoint-local inventory collection.
- `docs/DEPLOYMENT-DC.md`
  - gMSA, endpoint GPO, ADMIN$/SCM, firewall, and troubleshooting requirements.

## Important Review Questions

1. What are the top exact `errorMessage` values and PsExec exit codes?
2. Does the O365AuditTool service still run as LocalSystem after upgrade?
3. Can `NBR\NBRADC$` access `\\PC-TEST-01\ADMIN$`?
4. Is TCP 445 open from NBRADC to a known powered-on workstation?
5. Can endpoint SYSTEM read and hash `\\NBRADC\o365audit\collector.ps1`?
6. Are selected AD computer objects enabled, recent, Windows workstations, and DNS-resolvable?
7. Does EDR block `PSEXESVC`, remote service creation, or PowerShell `-EncodedCommand`?
8. Is the error text localized in a way that `IsOfflineFailure` misclassifies authorization errors?

## Likely Environment Remediation

The production model should be:

1. Create a dedicated gMSA for O365AuditTool.
2. Permit only NBRADC to retrieve the managed password.
3. Put the gMSA in a dedicated AD group such as `O365Audit-EndpointAdmins`.
4. Use a GPO scoped only to audited workstation OUs to add that group to local Administrators.
5. Enable required SMB/admin-share/SCM firewall rules only from NBRADC.
6. Redeploy with `-GmsaAccount 'NBR\account$'`; do not enable credential delegation.
7. Validate one endpoint and one small pilot OU before scanning the entire domain.

Do not grant the management server computer account or Domain Admins broad endpoint rights as the final architecture unless the customer explicitly accepts that risk.

## Potential Code Improvements After Root Cause Is Proven

- Persist PsExec exit code separately from the human-readable error.
- Add a privileged preflight endpoint that tests DNS, TCP 445, ADMIN$, SCM, and collector-share access for one selected device.
- Add an aggregated failure-reason panel so operators do not have to inspect 100+ rows.
- Expand localized authorization markers only from observed customer evidence.
- Bound and classify stdout as well as stderr because PsExec versions may write diagnostics to different streams.
- Add tests using representative real PsExec messages from this environment.

Do not weaken TLS, disable hash verification, enable unrestricted credential delegation, or change all failures to `Error` merely to make the dashboard counters look better.

## Acceptance Criteria

- A known powered-on pilot endpoint returns a successful collector payload when invoked by the actual service identity.
- A pilot OU scan reports correct success/offline/error counts.
- Successful devices populate serial number, IPs, volumes, disk type, Office products/processes, profiles/accounts, PST files, and NK2/N2K files where present.
- Access denied is reported as `Error`, not `Offline`.
- Truly unreachable devices remain `Offline` and enter the bounded retry queue.
- The dashboard no longer reports migration readiness when zero or only a small fraction of targets are successfully collected.

## Existing Follow-Up Issues

Private source issues already track broader hardening work:

- `#4` Bind discovered artifact ownership to the Windows profile.
- `#5` Resolve workstation site membership from subnet and DNS data.
- `#6` Make upgrade rollback fully transactional.
- `#7` Add pagination, bounded collector output, and SQLite write coordination.
- `#8` Automate public release mirror and signed provenance.
- `#9` Define Kerberos-only policy for privileged mutations.

The all-offline incident should be diagnosed before expanding artifact-copy usage. Artifact copy remains opt-in.
