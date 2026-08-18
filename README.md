# O365 Migration Audit Tool

Active Directory uyesi Windows cihazlardan agent kurmadan O365 migration envanteri toplar:

- AD hedef cihaz kesfi ve PsExec ile uzaktan collector calistirma.
- Tum yerel Windows profillerinden Outlook profilleri, e-posta hesaplari ve PST metadata envanteri.
- Tum profillerde `.nk2` ve `.n2k` legacy Outlook autocomplete artefact kesfi.
- Office urunleri, Click-to-Run build/mimari/update channel bilgileri ve calisan Office process'leri.
- Aktif NIC IP'leri, seri numarasi, disk kapasitesi, bus tipi (SATA/NVMe) ve medya tipi (SSD/HDD).
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

Domain-member yonetim sunucusunda DNS, sertifika, servis hesabi, RBAC gruplari ve OU parametrelerini girmeden kontrollu ilk kurulum:

```powershell
.\Deploy-ManagementServer.ps1 -AutoConfigure
```

`-AutoConfigure` sunucu FQDN'ini ve domain DN'ini algilar, uygun TLS sertifikasini yeniden kullanir veya AD CS `Machine` enrollment dener. Kurumsal CA kullanilamiyorsa HTTPS icin self-signed sertifika uretir. Eksik servis kimligi LocalSystem, eksik roller domain SID RID 512 ile Domain Admins, eksik tarama kapsami domain koku olur. Self-signed fallback istemci bilgisayarlara otomatik guven dagitmaz; sertifika guvenini GPO/PKI ile dagitin. Artifact copy bu modda da kapali kalir.

Onerilen gMSA kurulumu:

```powershell
$repoRoot = 'C:\src\O365AuditTool'
Set-Location "$repoRoot\scripts"
.\Deploy-ManagementServer.ps1 `
  -GmsaAccount 'CONTOSO\svcO365Audit$' `
  -AuditAdminGroups 'CONTOSO\GG_O365_Audit_Admin' `
  -AuditReaderGroups 'CONTOSO\GG_O365_Audit_Read' `
  -MigrationPlannerGroups 'CONTOSO\GG_O365_Migration_Planner' `
  -PsExecPath 'C:\Tools\PsExec\PsExec64.exe' `
  -DashboardDnsName 'o365audit.contoso.local' `
  -TlsCertificateThumbprint '<LOCALMACHINE_MY_CERT_THUMBPRINT>' `
  -DefaultOuFilter 'OU=Workstations,DC=contoso,DC=local'
```

Parolali domain servis hesabi:

```powershell
$auditCredential = Get-Credential 'CONTOSO\svc_o365audit'
.\Deploy-ManagementServer.ps1 `
  -ServiceCredential $auditCredential `
  -AuditAdminGroups 'CONTOSO\GG_O365_Audit_Admin' `
  -AuditReaderGroups 'CONTOSO\GG_O365_Audit_Read' `
  -MigrationPlannerGroups 'CONTOSO\GG_O365_Migration_Planner' `
  -PsExecPath 'C:\Tools\PsExec\PsExec64.exe' `
  -DashboardDnsName 'o365audit.contoso.local' `
  -TlsCertificateThumbprint '<LOCALMACHINE_MY_CERT_THUMBPRINT>' `
  -DefaultOuFilter 'OU=Workstations,DC=contoso,DC=local'
```

Normal modda servis kimligi belirtilmeden deployment yapilmaz. LocalSystem yalnizca `-AllowLocalSystem` veya acik `-AutoConfigure` secimiyle kullanilir.

Script kendi konumundan `src\O365AuditTool` yolunu otomatik bulur, .NET 10 ve PsExec'i dogrular, uygulamayi `C:\temp\o365audit` altina staging/health-check/rollback ile kurar. TLS varsayilan olarak zorunludur; sertifika `LocalMachine\My` deposunda private key, Server Authentication EKU ve `DashboardDnsName` SAN kaydi ile bulunmalidir. Script HTTP SPN'lerini servis hesabina fail-closed olarak kaydeder/dogrular. Zamanlanmis tarama `DefaultOuFilter` veya `DefaultSiteFilter` olmadan fail-closed kalir.

## Self-contained Release ve Dogrulanmis Bootstrap

Hedef sunucuda .NET SDK/runtime gerektirmeyen `win-x64` release bundle olusturmak icin:

```powershell
.\scripts\New-O365AuditRelease.ps1 `
  -Version '1.0.0' `
  -OutputDirectory '.\artifacts\o365audit-release'
```

PATH uzerindeki `dotnet` .NET 10 degilse script `%USERPROFILE%\.dotnet\dotnet.exe` konumunu da dener; gerekirse `-DotNetPath 'C:\Users\user\.dotnet\dotnet.exe'` verin.

Cikti:

```text
O365AuditTool-1.0.0-win-x64.zip
O365AuditTool-1.0.0-win-x64.zip.sha256
Install-O365AuditTool-1.0.0.ps1
Install-O365AuditTool-1.0.0.ps1.sha256
```

Release archive'i manifest ve SHA256 ile tekrar dogrulamak icin:

```powershell
.\scripts\Test-O365AuditRelease.ps1 `
  -ArchivePath '.\artifacts\o365audit-release\O365AuditTool-1.0.0-win-x64.zip'
```

Bootstrap, ZIP SHA256 dogrulanmadan dosya acmaz. Eksikse resmi Microsoft Sysinternals `PSTools.zip` paketinden `PsExec64.exe` indirir ve Authenticode imzasini dogrular. Remote script'i dogrudan `IEX` etmeyin; bootstrap'in kendisini de ayri kanaldan alinan hash ile dogrulayin:

```powershell
$bootstrapPath = 'C:\temp\Install-O365AuditTool-1.0.0.ps1'
Invoke-WebRequest 'https://audit.contoso.local/releases/Install-O365AuditTool-1.0.0.ps1' -OutFile $bootstrapPath
if ((Get-FileHash $bootstrapPath -Algorithm SHA256).Hash -ne '<BOOTSTRAP_SHA256>') { throw 'Bootstrap hash mismatch' }
& $bootstrapPath `
  -BundleUri 'https://audit.contoso.local/releases/O365AuditTool-1.0.0-win-x64.zip' `
  -ExpectedSha256 '<RELEASE_SHA256>' `
  -DashboardDnsName 'o365audit.contoso.local' `
  -TlsCertificateThumbprint '<LOCALMACHINE_MY_CERT_THUMBPRINT>' `
  -DefaultOuFilter 'OU=Workstations,DC=contoso,DC=local' `
  -GmsaAccount 'CONTOSO\svcO365Audit$' `
  -AuditAdminGroups 'CONTOSO\GG_O365_Audit_Admin' `
  -AuditReaderGroups 'CONTOSO\GG_O365_Audit_Read' `
  -MigrationPlannerGroups 'CONTOSO\GG_O365_Migration_Planner'
```

`-ChecksumUri` de desteklenir ancak ayni sunucudaki ZIP ve checksum birlikte degistirilebilecegi icin production'da SHA256 degerini ayri/guvenilir kanaldan `-ExpectedSha256` ile vermek daha guvenlidir.

Private GitHub deposunun raw/release adresleri anonim hedef sunucular tarafindan indirilemez. GitHub API asset URL'sini `Authorization: Bearer` header'i ve yalnizca `Contents: Read` yetkili fine-grained PAT ile kullanin veya release'i kurum artifact repository'sine mirror edin. PAT/token'i URL, script, komut satiri, log veya `appsettings` icine yazmayin; interaktif credential prompt ile process memory'de tutun.

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
  -TlsCertificateThumbprint '<LOCALMACHINE_MY_CERT_THUMBPRINT>' `
  -DefaultOuFilter 'OU=Workstations,DC=contoso,DC=local' `
  -EnableArtifactCopy `
  -CopyTargetRoot '\\filesrv01\O365Migration' `
  -AllowedCopyTargetRoots @('\\filesrv01\O365Migration')
```

`-EnableArtifactCopy` kullanilirken hem `-CopyTargetRoot` hem de en az bir `-AllowedCopyTargetRoots` zorunludur. SHA-256 varsayilan olarak aciktir. Registry'de kesfedilen UNC kaynaklar varsayilan olarak reddedilir; gerekiyorsa guvenilen server/share koklerini `-AllowedCopySourceUncRoots` ile acikca tanimlayin. Aktif PST exclusive acilamiyorsa copy durur; Outlook'u kapatin veya VSS snapshot kullanin.

Servis kimligi:

- Kaynak cihazlarda yerel Administrator/`ADMIN$` read yetkisine sahip olmalidir.
- Hedef share ve NTFS tarafinda klasor/dosya olusturma ve yazma yetkisine sahip olmalidir.
- SHA-256 dogrulamasi kullanilacaksa ek I/O ve islem suresi planlanmalidir.

Plan olusturmak kopyalamayi baslatmaz. Dashboard'da plan hedefi ve oge sayisi incelendikten sonra `AuditAdmin` tarafindan ayri bir onayla execute edilir. Deployment tekrar calistirilirken `-EnableArtifactCopy` verilmezse copy yeniden kapatilir.

## Dashboard API

- `GET /api/inventory/legacy-files`: NK2/N2K artefact listesi ve cihaz/kullanici/profil/tip filtreleri.
- `GET /api/licenses/recommendations`: Tekillestirilmis PST toplamina gore kapasite adayi ve veri guveni. Sonuc lisans satin alma karari degildir; tenant mailbox/archive/SKU dogrulamasi zorunludur.
- `POST /api/copy/plans`: Mevcut inventory snapshot'indan copy plani olusturur; dosya tasimaz.
- `GET /api/copy/plans`: Planlari ve durumlarini listeler.
- `POST /api/copy/plans/{id}/execute`: Daha once olusturulmus plani yurutme kuyruguna alir.

Dashboard cihaz, OU, AD site, kullanici, disk tipi, Office surumu, durum ve PST boyut araligi filtrelerini CSV/PDF export'a aynen tasir. Profil loaded/default, aktif hesap, Office process owner/PID, volume free/total ve guncel scan hatasi ayrintilari merkezi tabloda gorunur.

Endpoint local Administrator/ADMIN$/SCM yetkileri, SMB collector izinleri, gMSA hazirligi ve sorun giderme icin [domain deployment rehberine](docs/DEPLOYMENT-DC.md) bakin.

## Gelistirme

```powershell
dotnet restore .\src\O365AuditTool\O365AuditTool.csproj
dotnet build .\src\O365AuditTool\O365AuditTool.csproj -c Release
dotnet run --project .\src\O365AuditTool\O365AuditTool.csproj
```

Uygulama Windows bagimliliklarini acikca belirtmek icin `net10.0-windows` hedefler. AD hedef kesfi basarisizsa yalnizca Production ayarlarinda acikca tanimlanan fallback hedefleri kullanir; sifir sonuc veren OU/site filtresi fallback'e genislemez.
