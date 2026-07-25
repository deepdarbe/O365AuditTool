# O365 Migration Audit Tool

Active Directory uyesi Windows cihazlardan agent kurmadan O365 migration envanteri toplar:

- AD hedef cihaz kesfi ve PsExec ile uzaktan collector calistirma.
- Tum yerel Windows profillerinden Outlook profilleri, e-posta hesaplari ve PST metadata envanteri.
- Tum profillerde `.nk2` ve `.n2k` legacy Outlook autocomplete artefact kesfi.
- Office surumleri ve calisan Office process'leri.
- IP, seri numarasi, disk kapasitesi ve SATA/SSD/NVMe bilgileri.
- ASP.NET Core dashboard, API, SQLite, CSV ve PDF ciktilari.
- Kesif snapshot'indan guvenli iki asamali copy plan olusturma ve acik onayla yurutme.

## Proje Yapisi

- `src/O365AuditTool`: Web API, dashboard ve tarama orkestrasyonu.
- `scripts/collector.ps1`: Endpoint envanter collector'i.
- `scripts/Deploy-ManagementServer.ps1`: Guvenli domain deployment scripti.
- `scripts/Invoke-ManualScan.ps1`: Manuel tarama tetikleme scripti.
- `docs/DEPLOYMENT-DC.md`: Yetkiler, gMSA ve kurulum rehberi.
- `docs/O365-ARTIFACT-COPY-ARCHITECTURE.md`: NK2/N2K kesfi ve copy plan workflow mimarisi.

## Hizli Deployment

Uygulamayi Domain Controller yerine ayrik bir domain-member yonetim sunucusuna kurun. Varsayilan yerlesim:

```text
C:\temp\o365audit
|-- app
|-- data
|-- logs
`-- share
```

Onerilen gMSA kurulumu:

```powershell
cd C:\inetpub\CPT\scripts
.\Deploy-ManagementServer.ps1 `
  -GmsaAccount 'CONTOSO\svcO365Audit$' `
  -AuditAdminGroups 'CONTOSO\GG_O365_Audit_Admin' `
  -AuditReaderGroups 'CONTOSO\GG_O365_Audit_Read' `
  -MigrationPlannerGroups 'CONTOSO\GG_O365_Migration_Planner' `
  -PsExecPath 'C:\Tools\PsExec\PsExec64.exe'
```

Parolali domain servis hesabi:

```powershell
$auditCredential = Get-Credential 'CONTOSO\svc_o365audit'
.\Deploy-ManagementServer.ps1 `
  -ServiceCredential $auditCredential `
  -AuditAdminGroups 'CONTOSO\GG_O365_Audit_Admin' `
  -AuditReaderGroups 'CONTOSO\GG_O365_Audit_Read' `
  -MigrationPlannerGroups 'CONTOSO\GG_O365_Migration_Planner' `
  -PsExecPath 'C:\Tools\PsExec\PsExec64.exe'
```

Servis kimligi belirtilmeden deployment yapilmaz. LocalSystem varsayilan degildir ve ancak `-AllowLocalSystem` ile acik olarak secilebilir.

Script kendi konumundan `src\O365AuditTool` yolunu otomatik bulur, .NET 8 ve PsExec'i dogrular, uygulamayi `C:\temp\o365audit` altina kurar ve tekrar calistirildiginda mevcut servisi silmeden gunceller. Uc RBAC rolunun AD gruplari zorunludur; fallback cihaz listesi varsayilan olarak bostur ve sadece `-FallbackTargets` ile doldurulur.

## Self-contained Release ve IEX Bootstrap

Hedef sunucuda .NET SDK/runtime gerektirmeyen `win-x64` release bundle olusturmak icin:

```powershell
.\scripts\New-O365AuditRelease.ps1 `
  -Version '1.0.0' `
  -OutputDirectory '.\artifacts\o365audit-release'
```

Cikti:

```text
O365AuditTool-1.0.0-win-x64.zip
O365AuditTool-1.0.0-win-x64.zip.sha256
```

Release archive'i manifest ve SHA256 ile tekrar dogrulamak icin:

```powershell
.\scripts\Test-O365AuditRelease.ps1 `
  -ArchivePath '.\artifacts\o365audit-release\O365AuditTool-1.0.0-win-x64.zip'
```

Bootstrap, ZIP SHA256 dogrulanmadan dosya acmaz. Eksikse resmi Microsoft Sysinternals `PSTools.zip` paketinden `PsExec64.exe` indirir ve Authenticode imzasini dogrular. Onerilen IEX kullaniminda bootstrap kodu yalnizca indirilir; asil deployment dogrulanmis bundle icindeki fiziksel script ile yapilir:

```powershell
$bootstrap = Invoke-RestMethod 'https://audit.contoso.local/releases/Install-O365AuditTool.ps1'
& ([scriptblock]::Create($bootstrap)) `
  -BundleUri 'https://audit.contoso.local/releases/O365AuditTool-1.0.0-win-x64.zip' `
  -ExpectedSha256 '<RELEASE_SHA256>' `
  -GmsaAccount 'CONTOSO\svcO365Audit$' `
  -AuditAdminGroups 'CONTOSO\GG_O365_Audit_Admin' `
  -AuditReaderGroups 'CONTOSO\GG_O365_Audit_Read' `
  -MigrationPlannerGroups 'CONTOSO\GG_O365_Migration_Planner'
```

`-ChecksumUri` de desteklenir ancak ayni sunucudaki ZIP ve checksum birlikte degistirilebilecegi icin production'da SHA256 degerini ayri/guvenilir kanaldan `-ExpectedSha256` ile vermek daha guvenlidir.

Private GitHub deposunun raw/release adresleri anonim hedef sunucular tarafindan indirilemez. Release asset'lerini authenticated proxy, internal IIS veya kurum artifact repository'sine mirror edin. PAT/token'i script, komut satiri, log veya `appsettings` icine yazmayin.

Bundle deployment modu [Deploy-ManagementServer.ps1](scripts/Deploy-ManagementServer.ps1) icin `-PublishedAppPath` ve `-CollectorPath` kullanir. Bu mod `.csproj`, `$PSScriptRoot` ve hedefte .NET SDK gerektirmez.

## Artifact Copy Opt-in

Copy worker varsayilan olarak kapalidir. Yalnizca hedef share onceden hazirlandiktan ve servis hesabina gerekli izinler verildikten sonra acin:

```powershell
.\Deploy-ManagementServer.ps1 `
  -GmsaAccount 'CONTOSO\svcO365Audit$' `
  -AuditAdminGroups 'CONTOSO\GG_O365_Audit_Admin' `
  -AuditReaderGroups 'CONTOSO\GG_O365_Audit_Read' `
  -MigrationPlannerGroups 'CONTOSO\GG_O365_Migration_Planner' `
  -PsExecPath 'C:\Tools\PsExec\PsExec64.exe' `
  -EnableArtifactCopy `
  -CopyTargetRoot '\\filesrv01\O365Migration' `
  -AllowedCopyTargetRoots @('\\filesrv01\O365Migration') `
  -CopyVerifySha256
```

`-EnableArtifactCopy` kullanilirken hem `-CopyTargetRoot` hem de en az bir `-AllowedCopyTargetRoots` zorunludur. Varsayilan hedef izin verilen koklerden birinin altinda olmali ve deployment aninda erisilebilir olmalidir. Script bu degerleri `appsettings.Production.json` altindaki `Copy` bolumune yazar.

Servis kimligi:

- Kaynak cihazlarda yerel Administrator/`ADMIN$` read yetkisine sahip olmalidir.
- Hedef share ve NTFS tarafinda klasor/dosya olusturma ve yazma yetkisine sahip olmalidir.
- SHA-256 dogrulamasi kullanilacaksa ek I/O ve islem suresi planlanmalidir.

Plan olusturmak kopyalamayi baslatmaz. Dashboard'da plan hedefi ve oge sayisi incelendikten sonra `AuditAdmin` tarafindan ayri bir onayla execute edilir. Deployment tekrar calistirilirken `-EnableArtifactCopy` verilmezse copy yeniden kapatilir.

## Dashboard API

- `GET /api/inventory/legacy-files`: NK2/N2K artefact listesi ve cihaz/kullanici/profil/tip filtreleri.
- `POST /api/copy/plans`: Mevcut inventory snapshot'indan copy plani olusturur; dosya tasimaz.
- `GET /api/copy/plans`: Planlari ve durumlarini listeler.
- `POST /api/copy/plans/{id}/execute`: Daha once olusturulmus plani yurutme kuyruguna alir.

Endpoint local Administrator/ADMIN$/SCM yetkileri, SMB collector izinleri, gMSA hazirligi ve sorun giderme icin [domain deployment rehberine](docs/DEPLOYMENT-DC.md) bakin.

## Gelistirme

```powershell
dotnet restore .\src\O365AuditTool\O365AuditTool.csproj
dotnet build .\src\O365AuditTool\O365AuditTool.csproj -c Release
dotnet run --project .\src\O365AuditTool\O365AuditTool.csproj
```

Uygulama Windows bagimliliklarini acikca belirtmek icin `net8.0-windows` hedefler. AD hedef kesfi basarisizsa yalnizca Production ayarlarinda acikca tanimlanan fallback hedefleri kullanir; deployment scripti varsayilan olarak bos fallback listesi yazar.
