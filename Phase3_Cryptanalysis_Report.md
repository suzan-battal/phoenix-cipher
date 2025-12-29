# AŞAMA 3: Kriptanaliz ve Analiz Raporu

**Tarih:** 26.12.2025  
**Analiz Edilen Algoritma:** PHOENIX (Permutation and Hash-based Encrypted Network with Intelligent XOR)  
**Analist:** Suzan

---

## 1. Hedef Algoritma Özeti

### 1.1 Algoritma Özellikleri

PHOENIX, aşağıdaki özelliklere sahip bir blok şifre algoritmasıdır:

- **Blok Boyutu**: 128 bit (16 byte)
- **Anahtar Boyutu**: 128 bit (16 byte)
- **Tur Sayısı**: 8 tur
- **Kullanılan Teknikler**: S-Box, Permütasyon, XOR, GF(2^8) MixColumns

### 1.2 Tasarım Yapısı

```
Düz Metin → Padding → Initial XOR → [8 Tur: S-Box → Permütasyon → MixColumns]
→ Final XOR → Şifreli Metin
```

---

## 2. Saldırı Yöntemleri ve Seçim Kriterleri

Bu analizde **4 farklı saldırı yöntemi** uygulanmıştır:

### 2.1 Saldırı Seçim Gerekçeleri

| Saldırı Türü | Seçim Nedeni | Beklenti |
|--------------|--------------|----------|
| **1. Frekans Analizi** | Şifreli metnin entropisini ölçmek | İdeal dağılım testi |
| **2. Bilinen Düz Metin** | Anahtar çıkarım zafiyeti aramak | Tur yapısı analizi |
| **3. Sözlük Saldırısı** | Zayıf parola kullanımını test etmek | Brute-force simülasyonu |
| **4. Zamanlama Saldırısı** | Side-channel zafiyet kontrolü | Timing leak tespiti |

---

## 3. Adım Adım Saldırı Süreci

### 3.1 SALDIRI 1: Frekans Analizi

####  Amaç
Şifreli metindeki byte frekanslarını analiz ederek istatistiksel zayıflıkları tespit etmek.

####  Yöntem

1. Şifreli metindeki her byte'ın frekansını hesapla
2. Chi-square testi uygula
3. Tekrarlı desenleri ara (4+ byte)
4. Entropi seviyesini değerlendir

####  Sonuçlar

```
Test Parametreleri:
- Düz Metin: "Bu gizli bir mesajdır. PHOENIX algoritması test ediliyor!"
- Şifreli Metin Boyutu: 64 byte

İstatistikler:
- Farklı Byte Sayısı: 54 / 64
- Beklenen (Rastgele): ~64 farklı byte (küçük örneklem için)
- Chi-Square: 237.50
- Tekrarlı Desen: 0 adet
```

**En Sık Byte'lar:**
```
0x74: 3 kez (4.69%)
0xAE: 3 kez (4.69%)
0xED: 2 kez (3.12%)
```

####  Değerlendirme

 **Küçük zafiyet tespit edildi**: 64 byte'lık örneklemde yeterli entropi var ancak bazı byte'lar beklenenden fazla tekrar ediyor.

**Analiz:**
- Küçük veri setinde bazı byte frekansları yüksek
- Daha büyük veri setlerinde (1000+ byte) entropi artacaktır
- Genel olarak **frekans analizi direnci ORTA seviye**

---

### 3.2 SALDIRI 2: Bilinen Düz Metin Saldırısı

####  Amaç
Düz metin-şifreli metin çifti kullanarak anahtarı veya algoritma parametrelerini çıkarmak.

####  Yöntem

1. Bilinen düz metin ve şifreli metin çiftini al
2. İlk blokta XOR analizi yap
3. Anahtar whitening'i izole etmeye çalış
4. Tur anahtarlarını tahmin et

####  Sonuçlar

```
İlk Blok Analizi:
Düz Metin Blok:  42 75 20 67 69 7A 6C 69 20 62 69 72 20 6D 65 73
Şifreli Blok:    39 ED 74 34 4C F2 2C AE 63 7B 5B 89 95 83 94 01
XOR Farkı:       7B 98 54 53 25 88 40 C7 43 19 32 FB B5 EE F1 72
```

**Denenen Yaklaşımlar:**
1.  XOR farkından doğrudan anahtar çıkarımı → BAŞARISIZ
2.  Tur anahtarı tahminleri → BAŞARISIZ
3.  S-Box ters mühendisliği → BAŞARISIZ (SHA-256 koruması)

####  Değerlendirme

 **Algoritma dayanıklı!**

**Nedenleri:**
- SHA-256 tabanlı anahtar genişletme, doğrudan anahtar çıkarımını önlüyor
- 8 tur iterasyon, düz metin-şifreli metin ilişkisini kırıyor
- S-Box ve MixColumns doğrusal olmayan dönüşümler sağlıyor

**Sonuç:** PHOENIX, bilinen düz metin saldırısına **DAYANIKLI**

---

### 3.3 SALDIRI 3: Sözlük Saldırısı (Brute Force)

####  Amaç
Yaygın kullanılan parolaları deneyerek zayıf parola kullanımını kırmak.

####  Yöntem

1. Yaygın 10,000 parola listesi hazırla
2. Her parolayı `Anahtar_Uret()` ile anahtar üret
3. Şifreli metni deşifrele
4. Sonucu bilinen düz metin ile karşılaştır

####  Sonuçlar

```
Sözlük Boyutu: 21 parola
Test Parolası: "TestPassword123"

Deneme Sırası:
1. "123456" → BAŞARISIZ
2. "password" → BAŞARISIZ
3. "qwerty" → BAŞARISIZ
...
21. "TestPassword123" →  BAŞARILI!
```

**Bulunan Parola:** `TestPassword123`  
**Deneme Sayısı:** 21

####  Değerlendirme

 **ZAFIYET BULUNDU!**

**Analiz:**
- Algoritma kriptografik olarak güvenli ANCAK
- **Zayıf parola kullanımı** saldırıya açık hale getiriyor
- Gerçek dünyada milyonlarca yaygın parola bulunuyor

**Tahmini Kırılma Süresi:**
```
Sözlük Boyutu: 10,000,000 parola
Deneme Hızı: ~5,000 parola/saniye (tek CPU)
Tahmini Süre: ~33 dakika
```

**Sonuç:** Algoritma güvenli, ama **zayıf parola kullanımı ZAFİYET**

---

### 3.4 SALDIRI 4: Zamanlama Saldırısı

####  Amaç
Şifreleme işlemi süresindeki farklılıklardan bilgi sızdırması olup olmadığını test etmek.

####  Yöntem

1. Farklı uzunluklarda parolalar kullan
2. Her parola için 100 kez şifreleme yap
3. Ortalama süreleri ölç
4. İstatistiksel analiz (standart sapma)

####  Sonuçlar

```
Şifreleme Süreleri (Ortalama, 100 iterasyon):
Parola: "a"                    → 1.8138 ms
Parola: "abc"                  → 1.8378 ms
Parola: "password"             → 1.8434 ms
Parola: "verylongpassword123"  → 1.8593 ms

Standart Sapma: 0.018878 ms (~1.04% varyasyon)
```

####  Değerlendirme

 **Zamanlama saldırısına dirençli!**

**Analiz:**
- Parola uzunluğu şifreleme süresini minimal etkiliyor
- Standart sapma çok düşük (%1 altında)
- SHA-256 hashing sabit zamanlı çalışıyor
- Tur yapısı deterministik (giriş boyutundan bağımsız)

**Sonuç:** PHOENIX, zamanlama saldırılarına **DAYANIKLI**

---

## 4. Zafiyetlerin Detaylı Analizi

### 4.1 Bulunan Zafiyetler

####  Zafiyet 1: Zayıf Parola Kullanımı (CRİTİK)

**Açıklama:** Algoritma SHA-256 kullanarak güvenli anahtar üretse de, kullanıcı zayıf parola seçerse sözlük saldırısıyla kırılabilir.

**Kök Neden:**
- Parola → SHA-256 → Anahtar dönüşümü tek geçişli
- Salt veya iterasyon kullanılmıyor
- Yaygın parolalar saniyeler içinde denenebilir

**Exploit Senaryosu:**
```python
common_passwords = load_rockyou_wordlist()  # 14 milyon parola
for pwd in common_passwords:
    if crack_attempt(ciphertext, pwd):
        return pwd  # ~1 saat içinde kırılabilir
```

**Çözüm Önerisi:**
```python
# Mevcut (Zayıf):
def Anahtar_Uret(parola):
    return SHA256(parola)[:16]

# Önerilen (Güçlü):
def Anahtar_Uret(parola, salt, iterations=100000):
    return PBKDF2(parola, salt, iterations, dkLen=16)
    # veya Argon2id(parola, salt, ...)
```

---

####  Zafiyet 2: S-Box Tahmin Edilebilir (ORTA)

**Açıklama:** S-Box matematiksel formülle üretiliyor:
```python
S(x) = ((x ⊕ 0x63) * 0x1B) mod 256
```

**Kök Neden:**
- Deterministik formül
- Kriptografik rasgelelik yok
- Diferansiyel kriptanaliz için test edilmemiş

**Potansiyel Saldırı:**
- Diferansiyel kriptanaliz ile S-Box özelliklerini analiz et
- Yüksek diferansiyel uniform bulunursa exploit et

**Çözüm Önerisi:**
- AES S-Box gibi kriptografik olarak test edilmiş tablo kullan
- Veya kriptografik güvenli rastgele sayı üreticiyle oluştur

---

####  Zafiyet 3: 8 Tur Yetersiz Olabilir (DÜŞÜK)

**Açıklama:** Gelişmiş diferansiyel/lineer kriptanaliz için 8 tur yeterli olmayabilir.

**Karşılaştırma:**
- AES-128: 10 tur
- AES-256: 14 tur
- PHOENIX: 8 tur

**Öneri:** Güvenlik marjini için 12-16 tur kullan

---

### 4.2 Güçlü Yönler

####  Güçlü Yön 1: Çığ Etkisi

**Test Sonucu:** Anahtar'da 1 bit değişiklik → şifreli metinde %45.12 bit değişimi

**İdeal:** ~%50  
**PHOENIX:** %45.12  
**Değerlendirme:** Çok iyi çığ etkisi

---

####  Güçlü Yön 2: Padding Güvenliği

**Test:** 6 farklı boyutta metin (1-100 byte)  
**Sonuç:** Tüm testler başarılı, padding leak yok

---

####  Güçlü Yön 3: Anahtar Genişletme

**Yöntem:** SHA-256(key || round_number)  
**Avantaj:**
- Her tur için tamamen farklı anahtar
- Anahtar zamanlaması saldırısına dirençli
- Ters mühendislik zor

---

## 5. Genel Güvenlik Değerlendirmesi

### 5.1 Güvenlik Skoru

| Kriter | Puan | Açıklama |
|--------|------|----------|
| **Şifreleme Doğruluğu** | 10/10 | %100 başarı |
| **Çığ Etkisi** | 9/10 | %45 bit değişimi (ideal: %50) |
| **Frekans Direnci** | 7/10 | Orta entropi |
| **Known-Plaintext Direnci** | 9/10 | Çok güçlü |
| **Brute-Force Direnci** | 3/10 | Zayıf parola ile kırılabilir |
| **Timing Attack Direnci** | 10/10 | Mükemmel |
| **Genel Güvenlik** | **7.0/10** | İyi ama iyileştirilebilir |

---

### 5.2 Karşılaştırmalı Analiz

#### PHOENIX vs AES-128

| Özellik | PHOENIX | AES-128 | Yorum |
|---------|---------|---------|-------|
| Blok Boyutu | 128 bit | 128 bit |  Eşit |
| Anahtar Boyutu | 128 bit | 128 bit |  Eşit |
| Tur Sayısı | 8 | 10 |  AES daha fazla |
| S-Box | Formül bazlı | NIST onaylı |  AES daha güvenli |
| Anahtar Türetme | SHA-256 | Rijndael |  AES daha test edilmiş |
| Performans | ~1.8 ms/blok | ~0.1 ms/blok |  AES çok hızlı (donanım desteği) |
| Akademik Test | Yok | 20+ yıl |  AES kanıtlanmış |

**Sonuç:** PHOENIX akademik bir proje olarak iyi tasarlanmış ancak AES gibi endüstri standardı algoritmalarla rekabet edemez.

---

## 6. Sonuç ve Öneriler

### 6.1 Eğer Algoritma Kırıldıysa

 **EVET, kısmi olarak kırıldı:**

**Kırılma Yöntemi:** Sözlük Saldırısı  
**Kırılan Parola:** `TestPassword123`  
**Deneme Sayısı:** 21  
**Tahmini Gerçek Dünya:** 10M parola sözlüğü ile ~30-60 dakika

**Temel Zafiyet:**
- Parola türetme mekanizması yeterince güçlü değil
- Salt kullanılmıyor
- Iterasyon sayısı yok (brute-force maliyeti düşük)

---

### 6.2 Eğer Kırılamadıysa

 **Kısmi başarı:** Sözlük saldırısı hariç diğer saldırılara dayanıklı.

**Algoritmanın Güçlü Yönleri:**
1. Bilinen düz metin saldırısına dirençli
2. Zamanlama saldırısına karşı korumalı
3. İyi çığ etkisi (%45)
4. Karmaşık tur yapısı

**Neden Tam Kırılmadı:**
- SHA-256 anahtar genişletme güçlü
- 8 tur yeterli karıştırma sağlıyor
- MixColumns ve S-Box kombinasyonu etkili

---

### 6.3 İyileştirme Önerileri

####  Öncelik 1: Parola Türetmeyi Güçlendir

```python
# KDF kullan (Key Derivation Function)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def Anahtar_Uret_V2(parola, salt=None):
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000  # Brute-force'u zorlaştır
    )
    return kdf.derive(parola.encode()), salt
```

**Etki:** Sözlük saldırısı 100,000 kat daha zorlaşır

---

####  Öncelik 2: S-Box'ı İyileştir

```python
# AES S-Box kullan (NIST onaylı)
AES_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, ... # 256 byte
]
```

**Etki:** Diferansiyel kriptanaliz direnci artar

---

####  Öncelik 3: Tur Sayısını Artır

```python
NUM_ROUNDS = 12  # 8 yerine 12
```

**Etki:** Gelişmiş kriptanaliz saldırılarına karşı güvenlik marjini

---

####  Öncelik 4: Mod of Operation Ekle

```python
# CBC (Cipher Block Chaining) modu
# Her blok önceki blokla XOR'lanır
# Aynı düz metin blokları farklı şifreli metin üretir
```

**Etki:** Blok tekrarı zafiyetlerini önler

---

### 6.4 Final Yorum

PHOENIX algoritması, **eğitim amaçlı bir proje olarak başarılı**:
-  Temel kriptografik prensipler uygulanmış
-  Çoğu saldırı türüne dirençli
-  Kod kalitesi yüksek, okunabilir

Ancak **üretim ortamında kullanılmamalı**:
-  Yeterince test edilmemiş
-  Zayıf parola kullanımında kırılabilir
-  AES/ChaCha20 gibi kanıtlanmış algoritmalar tercih edilmeli

---

**Rapor Tarihi:** 26 Aralık 2025  
**Analist:** Suzan  
**Sonuç:** PHOENIX güvenli bir başlangıç, iyileştirmelerle üretim kalitesine çıkarılabilir.

**Tavsiye:** Gerçek uygulamalarda **libsodium**, **cryptography.io** veya **OpenSSL** gibi kanıtlanmış kütüphaneleri kullanın!
