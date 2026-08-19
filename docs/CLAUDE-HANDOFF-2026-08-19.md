# Devir Notu — 19 Agustos 2026

Bu dosya, "tum cihazlar cevrimdisi" vakasinin kapanisini ve yerelde devam edecek
oturum icin acik isleri ozetler. Onceki devir notu:
[`CLAUDE-HANDOFF-OFFLINE-COLLECTOR.md`](CLAUDE-HANDOFF-OFFLINE-COLLECTOR.md).
Teknik analiz ve olcum tablolari:
[`CLAUDE-FINDINGS-PSEXEC-OFFLINE.md`](CLAUDE-FINDINGS-PSEXEC-OFFLINE.md).

## 1. Kok neden (kapandi)

**Servis kimliginin endpoint yetkisi yoktu.** Yonetim sunucusu LocalSystem ile
kosuyordu, yani uzak erisim `NBR\NBRADC$` bilgisayar hesabiyla yapiliyordu ve bu
hesap endpoint `ADMIN$` paylasimina **yazamiyor**. PsExec PSEXESVC'yi kopyalayip
servis olusturamadigi icin dusuyordu.

Musteri ortaminda olculen tablo:

| Kimlik | PsExec | WinRM | ADMIN$ yazma |
|---|---|---|---|
| `NBR\Administrator` (interaktif) | exit 0 | calisiyor | - |
| `NBRADC$` (servis kimligi) | exit 6 | Access denied | **Access denied** |

PsExec bu durumu `Couldn't access <host>: The handle is invalid.` (exit 6) diye
raporluyor. Metin genel ag isaretcisi `couldn't access` ile eslestigi icin
siniflandirici cihazlari **Offline** yaziyor, sonsuza kadar retry ediyor ve
gercek sebep hicbir yerde gorunmuyordu.

**Yanlis giden aramalar (tekrarlanmasin):** konsol yoklugu, `CreateNoWindow`,
stdin yonlendirmesi, `-h` bayragi, session 0 kisitlari. Hepsi kontrollu olarak
olculdu ve elendi; ayrintili tablolar findings dosyasinda.

**Beni yanilan olcum:** `Test-Path \\HOST\ADMIN$` yetkisiz kimlik icin de basarili
donuyor. `ADMIN$` yetkisi **yazma** ile test edilmeli. Teshis scripti duzeltildi.

## 2. Simdiki durum

- Servis kimligi **gecici olarak** `NBR\Administrator` (CIM ile degistirildi,
  deploy calistirilmadi; SPN'e dokunulmadi).
- Bu degisiklikten sonra: **117 cevrimdisi → 15 basarisiz**, cihazlarin buyuk
  cogunlugu basariyla toplaniyor.
- Yayinlanan son surum: **v1.2.9**.

### Kalan 15 hata

| Adet | Hata | Yorum |
|---|---|---|
| 10 | `Collector output did not contain JSON payload` | En guclu aday: double-hop (asagi bkz.) |
| 3 | exit 6 — CORELWEB, NASCLUSTER, NBRSYNOLOGY | NAS/DMZ; Windows degil, kapsam disi birakilmali |
| 1 | exit 6 — GECOPDKS (PSEXESVC kopyalanirken) | Muhtemelen EDR/AV engeli |
| 1 | `Expected depth to be zero...` — HYPERV | Bozuk/kirpik JSON; v1.2.9 ayiklamayi sertlestirdi |

v1.2.9 artik JSON alinamadiginda **collector'in ham ciktisini** hata mesajinda
sakliyor. Yeni bir tarama, o 10 cihazin gercek sebebini ilk kez gosterecek.

## 3. Eski PowerShell projesinden alinacaklar

`C:\AI\CLOUDA\O365-Migration-Audit` (git deposu degil, ~Mart 2026) bu projenin
atasidir ve `Deploy-PsExec.ps1` bugunku iki zaafi zaten cozmus:

```
\\$comp -accepteula -s -h -n 30 powershell.exe -ExecutionPolicy Bypass -NoProfile
  -File C:\Windows\Temp\Collect-MailData.ps1 -OutputPath $SharePath
```

1. **Collector endpoint'in YEREL diskinden calisiyor** (`C:\Windows\Temp\...`),
   once oraya kopyalaniyor. Bizim surum UNC'den calistiriyor
   (`& \\NBRADC\o365audit\collector.ps1`), yani endpoint share'i **kendi makine
   hesabiyla** okumak zorunda — double-hop. 10 cihazdaki "JSON yok" hatasinin en
   guclu adayi bu. `ADMIN$` yazma yetkisi artik calistigi icin kopyalama
   uygulanabilir.
2. **Sonuc stdout yerine share'e yaziliyor** (`-OutputPath`). Bizim surum
   payload'i stdout'tan okuyor; CLIXML, ilerleme kayitlari ve artci metin
   yuzunden kirilgan (HYPERV vakasi).
3. **`-n 30` baglanti zaman asimi** bizde yok. Erisilemeyen cihaz
   `DeviceTimeoutSeconds` (300 sn) boyunca slot isgal ediyor.

Ayrica eski projede olup yenide olmayanlar: 32-bit PsExec fallback
(`PsExec.exe` hem 32 hem 64-bit'te calisir), `Retry-Deploy.ps1`,
`Merge-AuditReports.ps1`, `dashboard/` klasoru (icerigi henuz incelenmedi).

## 4. Acik isler

- [ ] v1.2.9 ile yeni tarama; 10 cihazin gercek hata metnini topla.
- [ ] `-n <saniye>` baglanti zaman asimi ekle (tek satir, dusuk risk).
- [ ] Collector'i endpoint yerel temp'ine kopyalayip oradan calistir (double-hop
      biter).
- [ ] Payload'i share'e yazdir, stdout'u yalniz teshis icin kullan.
- [ ] NAS/DMZ cihazlarini kapsam disi birakacak bir dislama listesi.
- [ ] **gMSA gecisi**: servis kalici olarak Domain Admin ile kosmamali.
      `Deploy-ManagementServer.ps1 -GmsaAccount 'NBR\svcO365Audit$'` + GPO ile
      endpoint local admin.
- [ ] `burcu.local` (BURCUDC) kurulumunda `Start-Service` hatasi — uygulamayi
      konsoldan calistirip gercek acilis hatasini gormek gerekiyor:
      `cd C:\temp\o365audit\app; $env:ASPNETCORE_ENVIRONMENT='Production'; .\O365AuditTool.exe`
- [ ] Acik issue'lar: #11 (ayri PsExecExitCode kolonu), #12 (encoding/erisim
      dogrulama), #13 (epik).

## 5. Bu oturumda yapilan kod degisiklikleri

Dal: `claude/psexec-admin-access-investigation-6ddawk`, PR #10.

- Hata mesajinda **PsExec exit kodu** + her iki cikti akisi saklaniyor.
- `handle is invalid` artik **yetki hatasi** (Error, retry yok).
- Turkce hata metni icin **OEM code page** cozumleme.
- JSON alinamadiginda/bozuldugunda **ham cikti korunuyor**; ayiklama parantez
  derinligine gore yapiliyor.
- Sifir hedef hatasi hangi OU/site ile arandigini ve site filtresinin neden
  hedefleri eledigini soyluyor.
- Kimlik degisince **HTTP SPN otomatik tasiniyor** (yalniz kendi bilgisayar
  hesabimizdaki kayit icin).
- Dashboard: **surum rozeti**, arıza ozeti paneli (neden + exit koduna gore
  gruplama), verinin gercek yasi, eski taramadan kalan kayitlar icin uyari,
  tarama basarisiz olunca gercek sebep, OU seciminde tam DN yazilinca otomatik
  secim.
- CI: `workflow_dispatch` ile surum girdisi vererek **tag + release** olusturma
  (tag push izni gerekmiyor).
- Teshis scriptleri: `Invoke-CollectorAccessDiagnostic.ps1` (ADMIN$ **yazma**
  testi dahil), `Test-PsExecLaunchModes.ps1`.

## 6. Build ve release

Yerelde (.NET 10 SDK gerekir):

```powershell
dotnet build .\src\O365AuditTool\O365AuditTool.csproj -c Release
.\scripts\New-O365AuditRelease.ps1 -Version '1.3.0' -OutputDirectory .\artifacts
```

GitHub uzerinden (sunucuda git gerekmez): Actions → O365 Audit CI →
**Run workflow** → `release_version` alanina surum yaz. Tag ve release otomatik
olusur, bundle asset olarak eklenir.

Sunucuya kurulum (tek satir, token gerekmez):

```powershell
$u='https://github.com/deepdarbe/O365AuditTool/releases/download/v<SURUM>'
$s="$env:TEMP\i.ps1"; irm "$u/Install-O365AuditTool-<SURUM>.ps1" -OutFile $s
& $s -BundleUri "$u/O365AuditTool-<SURUM>-win-x64.zip" -ExpectedSha256 '<HASH>' -AutoConfigure
```

`-AutoConfigure` mevcut kimlik, TLS, RBAC ve tarama kapsamini korur.
