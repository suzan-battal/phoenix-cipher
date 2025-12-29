#  PHOENIX Kriptografik Algoritma Projesi

**PHOENIX** - Permutation and Hash-based Encrypted Network with Intelligent XOR

Üç aşamalı akademik kriptografi projesi: Tasarım, Uygulama ve Kriptanaliz

---

##  Proje İçeriği

### Aşama 1: Tasarım Dokümantasyonu
- **[Phase1_Design_Report.md](Phase1_Design_Report.md)** - Algoritma tasarım şartnamesi
  - Matematiksel fonksiyonlar
  - Akış diyagramları
  - Güvenlik hedefleri

### Aşama 2: Python Implementasyonu
- **[phoenix_cipher.py](phoenix_cipher.py)** - Ana şifreleme modülü (500+ satır)
  - `Anahtar_Uret()` - Parola → Anahtar
  - `Sifrele()` - Şifreleme fonksiyonu
  - `Desifrele()` - Deşifreleme fonksiyonu

- **[test_phoenix.py](test_phoenix.py)** - Test süitleri
  - Şifreleme/deşifreleme doğrulama (%100 başarı)
  - Çığ etkisi testi (%45.12 bit değişimi)
  - Padding testleri

### Aşama 3: Kriptanaliz
- **[cryptanalysis.py](cryptanalysis.py)** - Güvenlik analiz araçları
  - Frekans analizi
  - Bilinen düz metin saldırısı
  - Sözlük saldırısı
  - Zamanlama saldırısı

- **[Phase3_Cryptanalysis_Report.md](Phase3_Cryptanalysis_Report.md)** - Analiz raporu
  - Bulunan zafiyetler
  - Güvenlik değerlendirmesi
  - İyileştirme önerileri

---

### Temel Kullanım

```python
from phoenix_cipher import PhoenixCipher

# Cipher oluştur
cipher = PhoenixCipher()

# Anahtar üret
anahtar = cipher.Anahtar_Uret("MySecretPassword")

# Şifrele
sifreli = cipher.Sifrele("Gizli mesaj!", anahtar)

# Deşifrele
duz = cipher.Desifrele(sifreli, anahtar)
print(duz)  # Output: "Gizli mesaj!"
```



##  Algoritma Özellikleri

| Özellik | Değer |
|---------|-------|
| **Algoritma Tipi** | Blok Şifre |
| **Blok Boyutu** | 128 bit (16 byte) |
| **Anahtar Boyutu** | 128 bit (16 byte) |
| **Tur Sayısı** | 8 tur |
| **Anahtar Türetme** | SHA-256 |
| **Padding** | PKCS#7 |

### Kullanılan Teknikler
-  S-Box (Substitution) - Byte ikamesi
-  Permütasyon - Byte karıştırma
-  XOR Whitening - Anahtar katmanları
-  MixColumns - GF(2^8) çarpımı

---

##  Test Sonuçları

```
 Test 1 (Şifreleme/Deşifreleme): BAŞARILI (%100)
 Test 2 (Çığ Etkisi): BAŞARILI (%45.12 bit değişimi)
 Test 3 (Padding): BAŞARILI (6/6 test)
```

### Çığ Etkisi Örneği

```
Orijinal Anahtar:     c878f4ada7a8cb5441eb0ce8e4da88e6
Değiştirilmiş:        c978f4ada7a8cb5441eb0ce8e4da88e6
                      ^ (1 bit fark)

Sonuç: 231/512 bit değişti (% 45.12)
```

---

##  Güvenlik Analizi Sonuçları

### Güvenlik Skoru: **7.0/10**

| Saldırı Türü | Sonuç | Durum |
|--------------|-------|-------|
| Frekans Analizi | Orta entropi |  Kabul edilebilir |
| Bilinen Düz Metin | Başarısız |  Dayanıklı |
| Sözlük Saldırısı | **Başarılı** |  Zafiyet |
| Zamanlama Saldırısı | Başarısız |  Dayanıklı |

### Bulunan Zafiyetler

####  Kritik: Zayıf Parola Kullanımı
- **Sorun:** Salt ve iterasyon yok
- **Etki:** Sözlük saldırısı ile ~30-60 dakikada kırılabilir
- **Çözüm:** PBKDF2/Argon2 kullan

####  Orta: Tahmin Edilebilir S-Box
- **Sorun:** Matematiksel formül ile üretiliyor
- **Çözüm:** AES S-Box kullan

####  Düşük: 8 Tur Yetersiz Olabilir
- **Sorun:** Gelişmiş kriptanaliz için marjin düşük
- **Çözüm:** 12-16 tur kullan

---

##  Öğrenilen Dersler

### Başarılar 
- Teoriden pratiğe başarılı geçiş
- Kapsamlı test coverage
- Gerçekçi güvenlik analizi

### Keşifler 
- En güçlü algoritma bile zayıf parola ile kırılabilir
- Çığ etkisi çok önemli (PHOENIX: %45 )
- KDF (Key Derivation Function) şart

---



##  Dokümantasyon

- [Tasarım Raporu](Phase1_Design_Report.md) - Matematiksel detaylar
- [Kriptanaliz Raporu](Phase3_Cryptanalysis_Report.md) - Güvenlik analizi
- API Dokümantasyonu - Kod içi docstring'ler

---

##  Proje Bilgileri

**Proje Türü:** Akademik - Kriptografi Eğitimi  
**Süre:** 3 hafta (12.12.2025 - 26.12.2025)  
**Dil:** Python 3.6+  
**Lisans:** Eğitim Amaçlı

---

##  İstatistikler

```
 Kod Satırı: ~1,200 satır
 Dokümantasyon: 25+ sayfa
 Test: 15+ senaryo
 Başarı Oranı: %100 (şifreleme/deşifreleme)
 Çığ Etkisi: %45.12
 Zafiyet: 3 adet bulundu
```

---

##  Katkıda Bulunma

Bu eğitim projesidir. İyileştirme önerileri:

1. PBKDF2/Argon2 entegrasyonu
2. CBC/CTR mod desteği
3. Diferansiyel kriptanaliz testleri
4. AES S-Box implementasyonu

---

## İletişim

**Geliştirici:** Suzan  
**Tarih:** 29 Aralık 2025


