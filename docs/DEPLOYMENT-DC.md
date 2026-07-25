# O365 Audit Tool - Domain Deployment

Uygulamayi Domain Controller uzerine degil, domain uyesi ayrik bir yonetim sunucusuna kurun. Varsayilan kurulum kok dizini `C:\temp\o365audit` olarak kalir.

## Gereksinimler

- Windows Server 2019 veya ustu, domain member.
- Kaynaktan publish icin .NET 8 SDK; hazir publish ile kurulum icin ASP.NET Core Runtime 8.
- Microsoft Sysinternals PsExec. Script varsayilan olarak Authenticode imzasini dogrular.
- Deployment sirasinda yerel Administrator yetkili PowerShell.
- Onerilen servis kimligi: gMSA. Alternatif: ayri, parolasi yonetilen domain servis hesabi.
- `ActiveDirectory` PowerShell modulu gMSA testini otomatik yapabilmek icin onerilir.
- Artifact copy acilacaksa onceden olusturulmus bir hedef dizin/share ve servis kimligine verilmis yazma yetkisi.

Script su uc kimlik seceneginden tam olarak birini zorunlu tutar:

1. `-GmsaAccount 'DOMAIN\hesap$'` - onerilen.
2. `-ServiceCredential $credential` - `DOMAIN\kullanici` biciminde PSCredential.
3. `-AllowLocalSystem` - yalnizca acik risk kabuluyla; varsayilan degildir.

## Onerilen gMSA Hazirligi

Asagidaki AD islemleri ortaminizin OU ve grup standartlarina gore bir domain yoneticisi tarafindan yapilmalidir. gMSA'nin parolasini yalnizca yonetim sunucusu veya bu sunucuyu iceren sinirli bir guvenlik grubu alabilmelidir.

```powershell
# Ornek; AD tarafinda bir kez
New-ADServiceAccount `
  -Name 'svcO365Audit' `
  -DNSHostName 'svcO365Audit.contoso.local' `
  -PrincipalsAllowedToRetrieveManagedPassword 'CONTOSO\GG_O365Audit_Servers'

# Yonetim sunucusunda
Install-ADServiceAccount -Identity 'svcO365Audit'
Test-ADServiceAccount -Identity 'svcO365Audit'
```

Beklenen sonuc `True` olmalidir. gMSA adi deployment komutunda sondaki `$` ile verilir.

## Endpoint Yetkileri

PsExec hedef cihazda gecici servis olusturur. Servis kimligine hedef istemcilerde asagidaki yetkileri merkezi GPO ile verin:

- Hedef cihazlarin yerel `Administrators` grubunda uyelik. Bunu yalnizca audit kapsamindaki cihaz OU'larina uygulayin.
- `ADMIN$` ve Service Control Manager uzaktan erisimi.
- Windows Firewall'da domain profili icin `File and Printer Sharing` ve `Remote Service Management`.
- `Server` servisinin ve varsayilan idari paylasimlarin etkin olmasi.
- Yonetim sunucusundan hedeflere TCP 445 erisimi.

Collector CIM/WMI sorgularini hedefte yerel olarak calistirir; ayrica uzaktan WMI oturumu acmaz. LocalSystem secilirse uzak erisim yonetim sunucusunun `DOMAIN\SERVERNAME$` bilgisayar hesabi ile yapilir. Bu hesabi endpoint Administrator grubuna eklemek genis ve zor izlenen bir yetki verdigi icin gMSA tercih edilmelidir.

Collector, cihazdaki yalnizca aktif kullaniciyi degil mevcut tum yerel profil dizinlerini dikkate alir. Outlook registry profilleri, PST metadata ve `.nk2`/`.n2k` legacy autocomplete dosyalari SID, kullanici/UPN, Outlook profil adi ve kaynak path ile raporlanir. Offline veya erisilemeyen profiller hata kaydiyla birlikte merkezi inventory'de gorunur.

## SMB Collector Erisimi

Deployment scripti `C:\temp\o365audit\share` yolunu `\\SERVER\o365audit` olarak paylasir ve su izinleri uygular:

- Yerel Administrators: Full Control.
- Domain Computers (domain SID + RID 515 ile cozulur): Read.
- Secilen domain servis kimligi: Read.
- NTFS tarafinda SYSTEM ve yerel Administrators: Full Control; servis kimligi ve Domain Computers: Read and Execute.
- `Everyone` ve yerel `Guests` share ACE'leri kaldirilir.

Bu izinler, endpointte baslayan collector isleminin UNC yolunu okuyabilmesi icindir. Farkli bir domain grubu kullanilacaksa `-DomainComputersGroup 'DOMAIN\GG_O365Audit_Endpoints'` verin; bu daha dar kapsamli secenektir.

## Deployment

Administrator PowerShell acin. Script kendi konumundan repo kokunu ve `src\O365AuditTool` yolunu otomatik bulur:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process -Force
cd C:\inetpub\CPT\scripts

.\Deploy-ManagementServer.ps1 `
  -GmsaAccount 'CONTOSO\svcO365Audit$' `
  -AuditAdminGroups 'CONTOSO\GG_O365_Audit_Admin' `
  -AuditReaderGroups 'CONTOSO\GG_O365_Audit_Read' `
  -MigrationPlannerGroups 'CONTOSO\GG_O365_Migration_Planner' `
  -PsExecPath 'C:\Tools\PsExec\PsExec64.exe'
```

Repo standart disi bir konumdaysa `-ProjectPath` belirtin:

```powershell
.\Deploy-ManagementServer.ps1 `
  -ProjectPath 'C:\inetpub\CPT\src\O365AuditTool' `
  -GmsaAccount 'CONTOSO\svcO365Audit$' `
  -AuditAdminGroups 'CONTOSO\GG_O365_Audit_Admin' `
  -AuditReaderGroups 'CONTOSO\GG_O365_Audit_Read' `
  -MigrationPlannerGroups 'CONTOSO\GG_O365_Migration_Planner' `
  -InstallRoot 'C:\temp\o365audit' `
  -PsExecPath 'C:\Tools\PsExec\PsExec64.exe'
```

Parolali domain servis hesabi alternatifi:

```powershell
$auditCredential = Get-Credential 'CONTOSO\svc_o365audit'
.\Deploy-ManagementServer.ps1 `
  -ServiceCredential $auditCredential `
  -AuditAdminGroups 'CONTOSO\GG_O365_Audit_Admin' `
  -AuditReaderGroups 'CONTOSO\GG_O365_Audit_Read' `
  -MigrationPlannerGroups 'CONTOSO\GG_O365_Migration_Planner' `
  -PsExecPath 'C:\Tools\PsExec\PsExec64.exe'
```

PSCredential parolasi `sc.exe` komut satirina yazilmaz. Yeni serviste `New-Service -Credential`, mevcut serviste yerel `Win32_Service.Change` CIM metodu kullanilir.

LocalSystem sadece kontrollu test ortami icin:

```powershell
.\Deploy-ManagementServer.ps1 `
  -AllowLocalSystem `
  -AuditAdminGroups 'CONTOSO\GG_O365_Audit_Admin' `
  -AuditReaderGroups 'CONTOSO\GG_O365_Audit_Read' `
  -MigrationPlannerGroups 'CONTOSO\GG_O365_Migration_Planner' `
  -PsExecPath 'C:\Tools\PsExec\PsExec64.exe'
```

`-AllowUnsignedPsExec` imza kontrolunu atlar ve yalnizca kurum tarafindan yeniden imzalanmis, hash'i ayri kanaldan dogrulanmis binary icin kullanilmalidir.

## Artifact Copy Opt-in

Copy ozelligi deployment'ta fail-closed ve varsayilan olarak kapalidir. Sadece inventory toplamak icin hicbir copy parametresi vermeyin. Ozelligi acmak icin hedef share'i once olusturun:

```powershell
.\Deploy-ManagementServer.ps1 `
  -GmsaAccount 'CONTOSO\svcO365Audit$' `
  -AuditAdminGroups 'CONTOSO\GG_O365_Audit_Admin' `
  -AuditReaderGroups 'CONTOSO\GG_O365_Audit_Read' `
  -MigrationPlannerGroups 'CONTOSO\GG_O365_Migration_Planner' `
  -PsExecPath 'C:\Tools\PsExec\PsExec64.exe' `
  -EnableArtifactCopy `
  -CopyTargetRoot '\\filesrv01\O365Migration' `
  -AllowedCopyTargetRoots @(
    '\\filesrv01\O365Migration',
    '\\filesrv02\O365Migration-DR'
  ) `
  -CopyVerifySha256
```

Parametre davranisi:

- `-EnableArtifactCopy`: Worker'in plan execute etmesine izin verir. Switch yoksa plan execution sunucu tarafinda reddedilir.
- `-CopyTargetRoot`: Dashboard formunda hedef bos birakildiginda kullanilan varsayilan koktur.
- `-AllowedCopyTargetRoots`: Kullanici girdisinin cikamayacagi guvenli kok listesidir. Varsayilan hedef bu koklerden birine esit veya onun altinda olmalidir.
- `-CopyVerifySha256`: Kopya sonrasinda SHA-256 butunluk dogrulamasi acar. Buyuk PST'lerde sureyi ve storage I/O'yu artirir.

`-EnableArtifactCopy` ile hedef veya allowed root bos birakilirsa deployment durur. Path tam yerel/UNC path olmali, yerel surucu koku olmamali, normalize edildikten sonra izin verilen kok sinirini asmamali ve deployment aninda mevcut/erisilebilir olmalidir.

Script hedef ACL'lerini otomatik olarak genisletmez. Copy acildiginda su yetkileri ayri olarak vermek zorunludur:

- Servis kimligi kaynak cihazlarda local Administrator olmalidir; boylece `C:\...` kaynaklari `\\CIHAZ\C$\...` uzerinden okuyabilir.
- Kaynak endpointlerde TCP 445, `ADMIN$` ve gerekli SMB ilkeleri acik olmalidir.
- Servis kimligi hedef SMB share'de en az `Change`, NTFS'te hedef agacta `Modify` yetkisine sahip olmalidir.
- LocalSystem secilmisse uzak erisim `DOMAIN\MANAGEMENTSERVER$` bilgisayar hesabiyla yapilir. Bu genis yetki modeli yerine gMSA kullanin.

Deployment, hedef path'i deployment'i calistiran hesapla test eder; gMSA'nin etkin erisimini impersonation ile dogrulayamaz. Uretime gecmeden once servis kimligi baglaminda kaynak okuma ve hedef yazma smoke testi yapin. Gece toplu kopyalamadan once tek cihaz/tek kullanici planiyla baslayin.

Uretilen Production ayari:

```json
{
  "Copy": {
    "Enabled": true,
    "DefaultTargetRoot": "\\\\filesrv01\\O365Migration",
    "AllowedTargetRoots": [ "\\\\filesrv01\\O365Migration" ],
    "MaxParallelism": 2,
    "BufferSizeMb": 4,
    "VerifySha256": true,
    "MaxAttempts": 2,
    "PollingSeconds": 5
  }
}
```

Guvenlik nedeniyle yeniden deployment'ta `-EnableArtifactCopy` verilmezse `Copy:Enabled` tekrar `false` yazilir. Onceki opt-in sessizce korunmaz.

## IEX ve Self-contained Bundle Deployment

`Deploy-ManagementServer.ps1` dosyasini dogrudan `IEX` ile pipe etmeyin. Kaynak modunda script `.csproj`, collector dosyasi ve fiziksel `$PSScriptRoot` bekler. Bunun yerine release bundle ve bootstrap kullanin:

```powershell
# Build/release sunucusunda
.\scripts\New-O365AuditRelease.ps1 `
  -Version '1.0.0' `
  -OutputDirectory 'C:\release\O365AuditTool'
```

Olusan ZIP self-contained `win-x64` uygulama, collector, deployment scripti ve dosya hash manifestini icerir. Hedef sunucuda:

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

Bootstrap kontrolleri:

- Administrator oturumu.
- Bundle URI icin HTTPS; HTTP ancak acik `-AllowInsecureHttp` istisnasi.
- `ExpectedSha256` veya `ChecksumUri` zorunlulugu.
- ZIP SHA256 ve bundle icindeki dosyalar icin manifest SHA256.
- Eksik PsExec icin yalnizca resmi `https://download.sysinternals.com/files/PSTools.zip` kaynagi.
- `PsExec64.exe` icin gecerli Microsoft Corporation Authenticode imzasi.
- GUID tabanli `C:\temp\o365audit-bootstrap` staging ve kontrollu cleanup.

Private GitHub release asset'leri anonim indirilemez. Asset'leri internal IIS/artifact repository'ye mirror edin veya kurumsal authenticated proxy kullanin. GitHub PAT degerlerini PowerShell history, URL, log veya config dosyalarina koymayin.

`-ChecksumUri` operasyonu kolaylastirir fakat ZIP ile checksum ayni trust boundary icindeyse tek basina supply-chain korumasi saglamaz. Production'da release SHA256 degerini ayri onayli kanal uzerinden alip `-ExpectedSha256` kullanin.

## RBAC ve Fallback Hedefleri

Deployment fail-closed calisir; `AuditAdmin`, `AuditReader` ve `MigrationPlanner` icin en az birer AD grubu verilmeden devam etmez. Gruplar SID'e cozulur, ActiveDirectory modulu varsa nesnelerin gercekten AD grubu oldugu da dogrulanir. Bir role birden fazla grup atanabilir:

```powershell
-AuditReaderGroups @(
  'CONTOSO\GG_O365_Audit_Read',
  'CONTOSO\GG_Security_Operations'
)
```

Script bu eslemeleri `C:\temp\o365audit\app\appsettings.Production.json` icindeki `Auth:RoleMappings` bolumune yazar. Kaynak ayarlardaki ornek `DOMAIN\...` degerlerinin configuration merge ile geri gelmemesi icin publish dizinindeki base `appsettings.json` ornekleri temizlenir.

Fallback hedefleri varsayilan olarak bostur; `PC-001` ve `PC-002` uretilmez. AD kesfi basarisiz oldugunda gercek hedeflerin kullanilmasi isteniyorsa acikca belirtin:

```powershell
-FallbackTargets @('PC-FIN-001', 'PC-HR-002.contoso.local')
```

## Yeniden Deployment

Ayni komut tekrar calistirilabilir:

- Mevcut servis silinmez; durdurulup binary path, kimlik ve recovery ayarlari guncellenir.
- Mevcut SMB share ayni fiziksel yolu kullaniyorsa izinler tekrar uygulanir.
- Ayni isimli share farkli bir path'e gidiyorsa script guvenlik nedeniyle durur.
- Uygulama yeniden publish edilir, collector ve Production ayarlari guncellenir.
- RBAC gruplari ve istege bagli fallback hedefleri Production override'a yeniden yazilir.
- Copy opt-in, hedef kokler ve SHA-256 tercihi Production override'a yeniden yazilir.
- Domain profilli firewall kurali olusturulur veya mevcut kural guncellenir.
- Servis baslatildiktan sonra `http://127.0.0.1:<port>/health` endpoint'i otomatik dogrulanir.
- Deployment hata verirse daha once calisan servis yeniden baslatilmaya calisilir.

Hazir publish cikisi `C:\temp\o365audit\app` altina ayri olarak kopyalandiysa `-SkipPublish` kullanilabilir. Bu durumda script DLL'i ve ASP.NET Core Runtime 8'i yine dogrular.

## Dogrulama

```powershell
Get-Service O365AuditTool
sc.exe qc O365AuditTool
sc.exe qfailure O365AuditTool
Get-SmbShareAccess o365audit
Get-Acl C:\temp\o365audit\share | Format-List
Test-NetConnection $env:COMPUTERNAME -Port 5080
Invoke-RestMethod http://127.0.0.1:5080/health
```

Copy ayarlarini ve hedef erisimini dogrulayin:

```powershell
$settings = Get-Content C:\temp\o365audit\app\appsettings.Production.json -Raw |
  ConvertFrom-Json
$settings.Copy | Format-List
Test-Path -LiteralPath $settings.Copy.DefaultTargetRoot -PathType Container
```

Servisin hangi hesapla calistigini kontrol edin:

```powershell
Get-CimInstance Win32_Service -Filter "Name='O365AuditTool'" |
  Select-Object Name, StartName, State, PathName
```

Ilk manuel tarama:

```powershell
cd C:\inetpub\CPT
.\scripts\Invoke-ManualScan.ps1 -BaseUrl 'http://localhost:5080'
```

## Sorun Giderme

- `dotnet bulunamadi`: .NET 8 SDK veya ASP.NET Core Runtime 8 kurulu degildir ya da standart path disindadir.
- `PsExec imzasi gecerli degil`: Resmi Sysinternals binary'sini yeniden indirin; dosya ozelliklerinden dijital imzayi kontrol edin.
- `Test-ADServiceAccount False`: Yonetim sunucusu gMSA parolasini alma yetkisine sahip degildir veya gMSA yerel olarak kurulmamisti.
- Servis `1069` ile acilmiyor: Domain servis hesabi parolasi/lock durumu veya `Log on as a service` GPO'su kontrol edilmelidir. Deny logon ilkeleri izinleri ezer.
- PsExec `Access is denied`: Servis kimligi endpoint local Administrator degildir, TCP 445/firewall kapali veya ADMIN$/SCM erisimi engellidir.
- Collector UNC path'ini okuyamiyor: Share ve NTFS izinlerinde endpoint bilgisayar hesabi veya belirtilen endpoint grubu bulunmuyordur.
- AD hedef kesfi basarisiz: Servis kimliginin AD bilgisayar nesnelerini okuma yetkisini ve LDAP/DC erisimini kontrol edin.
- `Artifact copy etkinlestirilemez`: `CopyTargetRoot`/`AllowedCopyTargetRoots` bos, hedef allowed root disinda veya hedef path deployment hesabindan erisilemiyordur.
- Plan olusuyor ancak execute reddediliyor: `Copy:Enabled` degerini ve kullanicinin `AuditAdmin` rolunu kontrol edin.
- Copy item `Access denied`: Servis kimliginin kaynak cihaz `ADMIN$` read ve hedef share/NTFS write izinlerini ayri ayri test edin.
- Copy item boyut/hash hatasi: Kaynak PST halen degisiyor olabilir. Outlook kapatildiktan sonra yeni snapshot/plan olusturun; SHA-256 aciksa storage I/O ve timeout degerlerini kontrol edin.

Dashboard varsayilan olarak HTTP uzerinden `5080` portunda dinler ve firewall yalnizca Domain profiline acilir. Uretimde TLS sonlandirma icin IIS/reverse proxy kullanin ve uygulama portunu yalnizca proxy veya yonetim subnetlerinden erisilebilir hale getirin.
