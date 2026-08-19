# O365 Migration Audit Runtime ve Copy Mimarisi

> Collector calisma akisi, offline/error siniflandirma karar agaci ve teshis
> icin ayrica bkz. [COLLECTOR-RUNTIME-AND-DIAGNOSTICS.md](COLLECTOR-RUNTIME-AND-DIAGNOSTICS.md).

## Amac

Sistem Windows oturumuyla kimlik dogrulanan merkezi dashboard'dan AD hedef kesfi, agentless PsExec collector calistirma, tum kullanici profillerinde envanter toplama, raporlama ve kontrollu migration copy akislarini yonetir. Kesfedilen PST/NK2/N2K dosyalari dogrudan kopyalanmaz; once degismez bir inventory snapshot'ina bagli copy plani olusturulur, ardindan yetkili kullanici hedefi ve oge sayisini gorerek plani acikca execute eder.

## Runtime Bilesenleri

```mermaid
flowchart TB
    subgraph Client["Yonetici istemcisi"]
        Browser["Tarayici\nmevcut Windows oturumu"]
    end

    subgraph Management["Yonetim sunucusu"]
        Edge["HTTPS dashboard + API\nNegotiate / RBAC / CSRF"]
        Directory["AD discovery\nRootDSE + OU/site + DN fallback"]
        Orchestrator["Scan orchestrator\nmanual + zamanlanmis + retry"]
        Ingest["JSON ingest + validation"]
        Database[("SQLite WAL\ninventory + jobs + copy plans")]
        Reports["Dashboard + CSV + PDF\nreadiness + lisans tahmini"]
        Copy["Copy worker\nallowlist + hash + atomic move"]
        Logs["JSONL diagnostics\nhealth + trace code"]
        Share["SMB collector share"]
    end

    subgraph Domain["Active Directory ve endpointler"]
        AD[("AD DS\nOU + sites + computers")]
        Endpoint["Windows endpoint\ntum yerel profiller"]
        Source["PST / NK2 / N2K\nkaynak dosyalari"]
    end

    subgraph Destination["Migration hedefi"]
        Target["SMB target root\nUser / Device / Profile / Type"]
    end

    Browser -->|"Kerberos veya NTLM"| Edge
    Edge --> Directory
    Directory --> AD
    Edge --> Orchestrator
    Orchestrator -->|"AD computer scope"| AD
    Orchestrator -->|"PsExec + ADMIN$"| Endpoint
    Share --> Endpoint
    Endpoint -->|"metadata JSON"| Ingest
    Endpoint --> Source
    Ingest --> Database
    Database --> Reports
    Reports --> Edge
    Database --> Copy
    Copy -->|"acik operator onayi sonrasi"| Source
    Copy --> Target
    Edge --> Logs
    Orchestrator --> Logs
    Copy --> Logs
```

## Tarama ve Retry Akisi

```mermaid
sequenceDiagram
    actor Operator as Audit operatoru
    participant UI as Dashboard
    participant API as ASP.NET Core API
    participant AD as Active Directory
    participant Queue as Scan queue
    participant PC as Endpoint collector
    participant DB as SQLite

    Operator->>UI: OU veya site secer
    UI->>API: POST /api/jobs/scan + CSRF
    API->>AD: Kapsamdaki bilgisayarlari sorgular
    AD-->>API: Computer listesi ve DN bilgisi
    API->>Queue: Job ve cihaz denemelerini yazar
    loop Her hedef cihaz
        Queue->>PC: PsExec ile collector.ps1
        alt Cihaz erisilebilir
            PC-->>Queue: Donanim + Office + profil + artefact JSON
            Queue->>DB: Validate ve inventory snapshot yaz
        else Offline veya timeout
            Queue->>DB: Durum + hata + sonraki retry zamani
        end
    end
    DB-->>UI: Filtreli inventory ve job durumu
```

AD OU/site endpoint'i LDAP gecici hatalarinda sinirli retry uygular. RootDSE sonucu alinamazsa yapilandirilmis scan base, sonrasinda bilinen bilgisayar distinguished name kayitlari kullanilir. Bu fallback yalnizca secim agacini ayakta tutar; tarama API'si yine acik OU veya site kapsami olmadan domain-geneli manuel tarama baslatmaz.

## Kimlik, Guven Sinirlari ve Gozlemlenebilirlik

- Dashboard mevcut Windows oturumunu `Negotiate` ile kullanir; parola uygulamaya girilmez veya saklanmaz.
- `AuditReader`, `MigrationPlanner` ve `AuditAdmin` rolleri AD grup eslemeleriyle sunucu tarafinda uygulanir.
- Mutasyon endpoint'leri antiforgery token ister; UI onayi tek basina yetki siniri degildir.
- Public HTTPS portu dashboard icindir. Loopback health portu yalnizca yerel servis kontrolu icin kullanilir.
- API hatalari hassas exception ayrintisi yerine trace code dondurur; ayrintili JSONL kayitlar sunucuda kalir.
- Collector sonucu guvenilmeyen endpoint girdisi kabul edilir ve kalici envantere yazilmadan once boyut/alan sinirlariyla validate edilir.

## Discovery Modeli

Collector aktif oturumla sinirli degildir. Cihazda mevcut tum Windows profil dizinleri SID bazinda ele alinir:

- Outlook profil ve hesap kayitlari yuklu/yuklu olmayan kullanici hive'larindan okunur.
- PST path, boyut, son degisim ve erisilebilirlik metadata olarak kaydedilir.
- Profil altindaki bilinen Outlook konumlari `.nk2` ve `.n2k` uzantilari icin taranir.
- Her legacy kayit cihaz, SID, kullanici adi, UPN, Outlook profil adi, artefact tipi, kaynak path, boyut ve son degisim zamaniyla raporlanir.
- Ayni SID/path birden fazla kaynaktan bulunursa merkezi raporda tekillestirilir.

`N2K`, standart Outlook `NK2` uzantisinin ters yazilmis varyanti olarak ayri artefact tipiyle korunur. Boylece sahadaki gercek dosya uzantisi raporda kaybolmaz.

## API ve RBAC

| Endpoint | Islem | Beklenen rol |
|---|---|---|
| `GET /api/inventory/legacy-files` | Legacy artefact raporu ve filtreler | `AuditReader` |
| `POST /api/copy/plans` | Inventory snapshot'indan plan olusturma | `MigrationPlanner` |
| `GET /api/copy/plans` | Plan/durum goruntuleme | `AuditReader` |
| `POST /api/copy/plans/{id}/execute` | Plan worker kuyruguna alma | `AuditAdmin` |

Plan olusturma body ornegi:

```json
{
  "targetRoot": "\\\\filesrv01\\O365Migration",
  "devices": [ "PC-FIN-001" ],
  "users": [ "user@contoso.local" ],
  "artifactTypes": [ "PST", "NK2", "N2K" ]
}
```

Bos `devices` veya `users` filtresi tum mevcut snapshot kapsamini ifade eder. `targetRoot` bos birakilirsa yalnizca sunucuda yapilandirilmis `Copy:DefaultTargetRoot` kullanilir. Hedef her durumda `Copy:AllowedTargetRoots` altinda kalmalidir.

## Hedef Dizin Taksonomisi

Dosyalar hesap ve cihaz ayrimini kaybetmeyecek deterministik bir agacta saklanir:

```text
<CopyTargetRoot>\
`-- <UserKey>\
    `-- <DeviceName>\
        `-- <ProfileName>\
            |-- PST\
            |   `-- archive_<source-hash>.pst
            |-- NK2\
            |   `-- Outlook.nk2
            `-- N2K\
                `-- legacy.n2k
```

- `UserKey` icin oncelik UPN/e-posta, domain kullanici adi, son olarak SID'dir.
- Path icin gecersiz karakterler guvenli bir bicimde normalize edilir.
- Ayni hedef ada dusen farkli kaynaklar deterministik bir suffix/hash ile ayrilir; sessiz overwrite yapilmaz.
- Ayni fiziksel artefact iki farkli kullanici/profil sahibine cozulurse plan otomatik sahip secmez; user-filtered plan ve operator dogrulamasi isteyerek fail-closed durur.
- Kaynak yerel path ise worker bunu cihaz admin share path'ine donusturur: `C:\Data\a.pst` → `\\PC-001\C$\Data\a.pst`.
- UNC kaynak path yalnizca `Copy:AllowedSourceUncRoots` allowlist'inde acikca izin verilen server/share altindaysa kullanilir; varsayilan fail-closed'dur.

## Iki Asamali Guvenlik Modeli

1. **Plan:** Kesif snapshot'indaki source path, source boyutu/mtime ve hesap-cihaz-profil baglami kalici plan ogelerine yazilir. Bu asama dosya I/O baslatmaz.
2. **Execute:** Dashboard plan kimligini, hedefi ve oge sayisini gosterir. Kullanici acik onay kutusunu secmeden execute butonu aktif olmaz.
3. **Server gate:** UI onayi tek basina guven siniri degildir. API `AuditAdmin`, `Copy:Enabled` ve allowed-root kontrolunu yeniden uygular.
4. **Worker:** Dosya once ayni hedef dizinde gecici `.partial-*` ada kopyalanir. Varsayilan SHA-256 ve boyut dogrulamasindan sonra final ada atomik olarak tasinir.
5. **Degisim korumasi:** Kaynak exclusive acilamiyorsa copy durur ve Outlook'un kapatilmasi veya VSS snapshot kullanilmasi istenir. Hedef dizin zincirinde reparse point/junction bulunursa islem fail-closed olur.
6. **Idempotency:** Mevcut hedef SHA-256 ile ayniysa oge `Skipped`; farkli icerik varsa overwrite edilmeden hata uretilir.

## Yetki Sinirlari

Onerilen servis kimligi sinirli bir gMSA'dir:

- Audit kapsamindaki endpointlerde local Administrator ve `ADMIN$` read.
- Collector share icin read.
- Migration hedef share'de `Change`, NTFS agacinda `Modify`.
- AD'de yalnizca bilgisayar nesnesi okuma.

Uygulama hedef ACL'sini otomatik olarak degistirmez. Deployment yalnizca girilen hedefin mevcut hesaptan erisilebilir oldugunu kontrol eder; gMSA effective access testi ayrica yapilmalidir. LocalSystem kullanimi uzak kaynak ve hedefte yonetim sunucusu bilgisayar hesabina genis yetki verilmesini gerektirdigi icin onerilmez.

## Operasyon ve Gozlemlenebilirlik

- Once tek cihaz/tek kullanici ve kucuk bir NK2 planiyla smoke test yapin.
- Sonra tek PST ile boyut ve SHA-256 davranisini dogrulayin.
- Plan durumlari: `Planned`, `Queued`, `Running`, `Completed`, `CompletedWithErrors`, `Failed`.
- Oge durumlari: `Planned`, `Queued`, `Copying`, `Completed`, `Skipped`, `Failed`.
- Hata kaydinda kaynak, hedef, deneme sayisi ve hata mesaji korunmalidir.
- Buyuk PST batch'lerinde hedef kapasitesi, SMB throughput, antivirus etkisi ve `Copy:MaxParallelism` birlikte izlenmelidir.

Deployment ve servis hesabi smoke testleri icin [DEPLOYMENT-DC.md](DEPLOYMENT-DC.md) runbook'unu izleyin.
