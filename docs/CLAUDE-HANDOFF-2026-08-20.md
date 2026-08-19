# Devir Notu — 20 Agustos 2026

Onceki devir notu: [`CLAUDE-HANDOFF-2026-08-19.md`](CLAUDE-HANDOFF-2026-08-19.md).
Tam duzeltme plani: [`FIX-PLAN-2026-08-20.md`](FIX-PLAN-2026-08-20.md).

Bu oturumda 2026-03 tarihli calisan atadan (`O365-Migration-Audit`, PowerShell +
Node) bu projeye cok-ajanli bir karsilastirma yapildi (34 bulgu dogrulandi,
6 curutuldu), ardindan P0/P1 duzeltmeleri uygulandi.

## 1. Canlida olculen yeni gercekler

Bunlar 19 Agustos notunda **yoktu** ve varsayimla degil, uzaktan olcumle bulundu.

| Olcum | Sonuc |
|---|---|
| NBRADC'de kosan surum | **v1.2.8** — 19 Agustos notunun "v1.2.9 yayinlandi" ifadesi kurulumu kapsamiyor |
| v1.2.8 binary'sinde `handle is invalid` metni | **yok** → yetki hatalari hala `Offline` sayilip sonsuz retry ediliyor |
| BURCUDC servis durumu | **Stopped**, uygulama dizini `.failed-db1f8b2e...`'e geri alinmis |
| BURCUDC TLS sertifikasi | self-signed, private key var, 2028'e kadar gecerli |
| Ayni sertifikanin deposu | `LocalMachine\CA` (ara CA) — **`Root`'ta degil** |
| `X509Chain.Build()` | **False**, `UntrustedRoot` |

**BURCUDC kok nedeni kapandi:** `Program.cs` sertifikayi
`X509Store.Find(..., validOnly: true)` ile ariyordu; bu bayrak guvenilir zincir
de talep eder. Sertifika `Root` yerine `CA` deposuna alindigi icin zincir
kurulamiyor, arama bos donuyor, servis aciliyorken istisna atiyordu.

**nbr.local AD yapisi (olculdu):** is istasyonlari `OU=PC,OU=NBR,DC=nbr,DC=local`
altinda (~159 nesne). Sorunlu 5 cihazin **hepsi** `OU=SERVER` altinda:
CORELWEB (DMZ), HYPERV, GECOPDKS, ve OS niteligi **bos** olan NASCLUSTER /
NBRSYNOLOGY / NBR_DS1825PLUS (Synology appliance). Dagitilmis
`DefaultOuFilter` domain koku (`DC=nbr,DC=local`) oldugu icin hepsi her gece
taraniyordu.

## 2. Bu oturumda uygulananlar

### Toplama zinciri
- **PsExec `-n` connect timeout** (`PsExecConnectTimeoutSeconds`, varsayilan 30).
  Yalnizca CONNECT fazini sinirlar, toplayici calisma suresini degil.
- **Olculen erisilebilirlik**: PsExec slotu harcanmadan once TCP 445 (basarisizsa
  139) probe'u. Artik `Offline` bir *cikarim* degil, **olcum**. Baglanti reddi
  "erisilebilir" sayilir — host cevap vermistir, sorun sonraki asamadadir.
- **Siniflandirma artik exit-kod-oncelikli** (`IsOfflineFailure`). Onceden metin
  once bakiliyordu; bu yuzden mesaji genel `couldn't access` iceren her yetki
  hatasi `Offline` yazilip sonsuz retry ediliyordu — 117-offline olayinin sinifi.
  Yetki kodlari: 5, 6, 1311, 1326, 1327, 1331, 1385, 1789.
- **Timeout dalinda cikti korunuyor**: process oldurulduk ten sonra stdout/stderr
  3 sn'lik siniri asmadan okunur, hangi fazda takildigi kaybolmaz.
- **`PsExecExitCode` ayri kolon** (issue #11). Hata metnini ayristirarak gruplamak,
  tek bir yetki hatasinin 117 cihazda "ag sorunu" gibi gorunmesine yol acmisti.

### Kapsam
- AD kesfinde **OS / DC / isim / OU dislama** (`ExcludeDeviceNames` joker destekli
  ve iki uctan capali, `ExcludeOus` DN-siniri eslesmesi, `primaryGroupID` 516/521,
  `*Server*` OS, bos OS). Her taramada **tek satir ozet**: sebep bazli sayim,
  ornek adlar ve **hicbir seye eslesmeyen desenler** (bir yazim hatasi sessizce
  sunuculari tekrar taratmasin).
- `ExcludeUnknownOperatingSystem` **varsayilan KAPALI**. Bos `operatingSystem` bir
  ipucudur, kanit degil: yeni katilmis ama hic acilmamis gercek bir is istasyonu
  ayni gorunur. nbr.local'de `-ExcludeUnknownOperatingSystem` ile acikca acilir.
- Deploy artik **her yolda** (yalniz `-AutoConfigure` degil) bos/domain-koku
  kapsami reddediyor. Bos `DefaultOuFilter` servise "ayarlanmamis" degil "tum
  domain" demektir.

### Baslangic ve teshis
- Sertifika aramasi `validOnly:false` + **acik kontroller** (private key, tarih
  araligi, ServerAuth EKU veya EKU yoklugu); birden fazla eslesmede en gec
  bitenden secilir. Zincir dogrulanamazsa **kabul edilir ama uyarilir**.
- Baslangic istisnalari `startup-failure-<utc>.log` + Event Log'a yazilip
  yeniden firlatiliyor; arka plan servisleri icin `service-<yyyyMMdd>.log`
  rolling dosya sink'i eklendi.
- `Get-O365AuditDiagnostics.ps1` artik `.failed-*` dizinlerini buluyor, Event Log
  kuyrugunu ve sertifika zincir durumunu raporluyor.
- Deploy self-signed sertifikanin **public** bolumunu `Root`'a aliyor ve zinciri
  yeniden dogruluyor. **CA=true sertifika asla otomatik guvenilir yapilmaz**
  (makine genelinde sinirsiz guven delegasyonu olurdu).

### Dashboard
- Siniflandirma kurallari `wwwroot/dashboard-logic.js`'e tasindi ve sunucuyla
  ayni siraya getirildi (exit kodu → yetki metni → genel metin). `exit 6 /
  handle is invalid` artik "Ag / Offline" degil yetki hatasi olarak gosteriliyor.

## 3. Hakemlenen tartismalar (tekrar acilmasin)

- **"Zincir dogrulanamazsa deploy hata firlatsin"** — uygulanmadi. `validOnly:false`
  geldikten sonra guvenilmeyen zincir servisi artik engellemiyor; firlatmak
  calisacak bir kurulumu bloke ederdi. Uyari dogru davranis.
- **"`ExcludeUnknownOperatingSystem` varsayilan `true` olsun"** — reddedildi.
  Alt-ajanin karsi ornegi OU kapsami uygulanmadan olculmustu; `OU=PC,OU=NBR`
  kapsamiyla appliance'lar zaten disarida kaliyor. Sessiz daraltma riski daha agir.
- Curutulen eski hipotezler: 32-bit PsExec fallback eksikligi, orphan collector
  sureci, retry kuyrugu acligi, "-n yoklugu 300 sn slot isgal ediyor" (gercek OS
  SMB timeout'u ~20-45 sn).

## 4. Acik isler

- [ ] **Olcum kapisi**: yeni surum kuruldiktan sonra tarama calistirilip 10
      "JSON yok" cihazinin **ham ciktisi** okunacak. P0-D/E (payload'i share'e
      yazma, collector'i endpoint yerel diskine kopyalama) bu kanita gore
      tasarlanacak — kor uygulanmayacak.
- [ ] BURCUDC kurulumu yeni surumle tekrar denenecek (P0-A/B dogrudan bunu hedefler).
- [ ] gMSA gecisi (P1-A/B): servis kalici olarak `NBR\Administrator` ile kosmamali;
      `-AutoConfigure` bos kimlikle SPN'i built-in Administrator'a tasiyip onu
      Kerberoastable yapiyor.
- [ ] Dashboard `PsExecExitCode` kolonunu API'den okuyup metin ayristirmayi biraksin.
- [ ] Issue #12, #13.

## 5. Kurulum (nbr.local)

Kapsam artik acikca verilmek zorunda:

```powershell
$u='https://github.com/deepdarbe/O365AuditTool/releases/download/v<SURUM>'
$s="$env:TEMP\i.ps1"; irm "$u/Install-O365AuditTool-<SURUM>.ps1" -OutFile $s
& $s -BundleUri "$u/O365AuditTool-<SURUM>-win-x64.zip" -ExpectedSha256 '<HASH>' -AutoConfigure `
     -DefaultOuFilter 'OU=PC,OU=NBR,DC=nbr,DC=local' `
     -ExcludeOus 'OU=SERVER,DC=nbr,DC=local' `
     -ExcludeDeviceNames 'NAS*','*SYNOLOGY*','NBR_DS*' `
     -ExcludeUnknownOperatingSystem
```
