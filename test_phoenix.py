"""
PHOENIX Şifreleme Algoritması - Test Süitleri
==============================================

Dosya: test_phoenix.py
Tarih: 19.12.2025

Bu dosya, PHOENIX algoritmasının doğruluğunu test eder:
- Test 1: Basit şifreleme/deşifreleme doğrulaması
- Test 2: Çığ etkisi (Avalanche Effect) analizi
"""

import phoenix_cipher
from phoenix_cipher import PhoenixCipher


def test_1_basic_encryption_decryption():
    """
    Test 1: Basit Doğrulama
    Kısa bir metni şifreleyip, deşifre ettikten sonra 
    orijinal düz metinle aynı olduğunu kanıtlama.
    """
    print("\n" + "=" * 70)
    print("TEST 1: BASİT ŞİFRELEME/DEŞİFRELEME DOĞRULAMA")
    print("=" * 70)
    
    cipher = PhoenixCipher()
    
    # Test senaryoları
    test_cases = [
        ("Merhaba Dünya!", "parola123"),
        ("PHOENIX Algoritması Test Ediliyor", "SuperSecretKey!"),
        ("1234567890 ABCDEFGH", "test_key_456"),
        ("Kısa", "k"),
        ("Bu çok uzun bir test mesajıdır. " * 10, "longtext"),
    ]
    
    all_passed = True
    
    for i, (duz_metin, parola) in enumerate(test_cases, 1):
        print(f"\n📋 Test Case {i}:")
        print(f"   Düz Metin: {duz_metin[:50]}{'...' if len(duz_metin) > 50 else ''}")
        print(f"   Parola: {parola}")
        
        # Anahtar üret
        anahtar = cipher.Anahtar_Uret(parola)
        
        # Şifrele
        sifreli = cipher.Sifrele(duz_metin, anahtar)
        print(f"   Şifreli (hex): {sifreli.hex()[:60]}...")
        
        # Deşifrele
        cozulmus = cipher.Desifrele(sifreli, anahtar)
        
        # Doğrula
        if duz_metin == cozulmus:
            print("   ✅ BAŞARILI: Şifreleme ve deşifreleme doğru!")
        else:
            print("   ❌ BAŞARISIZ: Deşifreleme hatalı!")
            print(f"   Beklenen: {duz_metin}")
            print(f"   Alınan: {cozulmus}")
            all_passed = False
    
    print("\n" + "-" * 70)
    if all_passed:
        print("🎉 TEST 1 SONUÇ: TÜM TEST CASE'LER BAŞARILI")
    else:
        print("⚠️  TEST 1 SONUÇ: BAŞARISIZ TEST VAR")
    print("=" * 70)
    
    return all_passed


def test_2_avalanche_effect():
    """
    Test 2: Anahtar Hassasiyeti (Çığ Etkisi)
    Şifreleme sırasında kullanılan anahtarın tek bir bitini değiştirip,
    deşifreleme sonucunun tamamen anlamsız olduğunu gösterme.
    """
    print("\n" + "=" * 70)
    print("TEST 2: ÇIĞ ETKİSİ (AVALANCHE EFFECT) - ANAHTAR HASSASİYETİ")
    print("=" * 70)
    
    cipher = PhoenixCipher()
    
    # Test metni
    duz_metin = "Bu metin çığ etkisi testi için kullanılıyor."
    print(f"\n📝 Düz Metin: {duz_metin}")
    
    # Orijinal anahtar
    parola = "OriginalPassword"
    anahtar1 = cipher.Anahtar_Uret(parola)
    print(f"\n🔑 Orijinal Anahtar (hex): {anahtar1.hex()}")
    
    # 1 bit değiştirilmiş anahtar (ilk byte'ın ilk biti)
    anahtar2 = bytearray(anahtar1)
    anahtar2[0] ^= 0x01  # İlk bitin flip edilmesi
    anahtar2 = bytes(anahtar2)
    print(f"🔑 Değiştirilmiş Anahtar (hex): {anahtar2.hex()}")
    print(f"   (İlk bit değiştirildi: {anahtar1[0]:08b} → {anahtar2[0]:08b})")
    
    # Orijinal anahtarla şifrele
    sifreli1 = cipher.Sifrele(duz_metin, anahtar1)
    print(f"\n🔒 Şifreli Metin 1 (hex): {sifreli1.hex()}")
    
    # Değiştirilmiş anahtarla şifrele
    sifreli2 = cipher.Sifrele(duz_metin, anahtar2)
    print(f"🔒 Şifreli Metin 2 (hex): {sifreli2.hex()}")
    
    # Hamming mesafesi (kaç bit farklı)
    hamming_distance = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(sifreli1, sifreli2))
    total_bits = len(sifreli1) * 8
    change_percentage = (hamming_distance / total_bits) * 100
    
    print(f"\n📊 Çığ Etkisi İstatistikleri:")
    print(f"   Toplam Bit Sayısı: {total_bits}")
    print(f"   Değişen Bit Sayısı: {hamming_distance}")
    print(f"   Değişim Oranı: {change_percentage:.2f}%")
    print(f"   İdeal Değişim: ~50%")
    
    # Yanlış anahtarla deşifreleme dene
    print("\n🔓 Yanlış Anahtarla Deşifreleme Denemesi:")
    try:
        yanlis_cozum = cipher.Desifrele(sifreli1, anahtar2)
        print(f"   Sonuç: {yanlis_cozum}")
        print("   ✅ Orijinal metinden tamamen farklı (çöp veri)")
        
        if yanlis_cozum == duz_metin:
            print("   ❌ PROBLEM: Aynı metne ulaşıldı!")
            avalanche_passed = False
        else:
            avalanche_passed = True
    except Exception as e:
        print(f"   ✅ Deşifreleme hatası oluştu (beklenen): {e}")
        avalanche_passed = True
    
    # Doğru anahtarla doğrulama
    print("\n🔓 Doğru Anahtarla Deşifreleme:")
    dogru_cozum = cipher.Desifrele(sifreli1, anahtar1)
    print(f"   Sonuç: {dogru_cozum}")
    
    if dogru_cozum == duz_metin:
        print("   ✅ Orijinal metin elde edildi!")
    else:
        print("   ❌ PROBLEM: Orijinal metin elde edilemedi!")
        avalanche_passed = False
    
    # Çığ etkisi kriteri (en az %25 değişim olmalı)
    print("\n" + "-" * 70)
    if change_percentage >= 25 and avalanche_passed:
        print(f"🎉 TEST 2 SONUÇ: ÇIĞ ETKİSİ BAŞARILI (Değişim: {change_percentage:.2f}%)")
        result = True
    else:
        print(f"⚠️  TEST 2 SONUÇ: ÇIĞ ETKİSİ YETERSİZ (Değişim: {change_percentage:.2f}%)")
        result = False
    print("=" * 70)
    
    return result


def test_3_different_block_sizes():
    """
    Test 3: Farklı Boyutlu Metinler
    Padding mekanizmasının doğru çalıştığını test eder.
    """
    print("\n" + "=" * 70)
    print("TEST 3: FARKLI BOYUTLU METİNLER (PADDING TESTİ)")
    print("=" * 70)
    
    cipher = PhoenixCipher()
    anahtar = cipher.Anahtar_Uret("test_padding")
    
    # Farklı boyutlarda metinler
    test_texts = [
        "A",                          # 1 byte
        "AB",                         # 2 byte
        "ABCDEFGHIJKLMNO",           # 15 byte (1 byte eksik)
        "ABCDEFGHIJKLMNOP",          # 16 byte (tam blok)
        "ABCDEFGHIJKLMNOPQ",         # 17 byte (1 byte fazla)
        "A" * 100,                    # 100 byte
    ]
    
    all_passed = True
    
    for text in test_texts:
        sifreli = cipher.Sifrele(text, anahtar)
        cozulmus = cipher.Desifrele(sifreli, anahtar)
        
        status = "✅" if text == cozulmus else "❌"
        print(f"{status} Boyut: {len(text):3d} byte → Şifreli: {len(sifreli):3d} byte")
        
        if text != cozulmus:
            all_passed = False
    
    print("\n" + "-" * 70)
    if all_passed:
        print("🎉 TEST 3 SONUÇ: TÜM BOYUTLAR İÇİN BAŞARILI")
    else:
        print("⚠️  TEST 3 SONUÇ: BAŞARISIZ")
    print("=" * 70)
    
    return all_passed


def analyze_encryption_randomness():
    """
    Bonus: Şifreli metnin rastgelelik analizi
    """
    print("\n" + "=" * 70)
    print("BONUS ANALİZ: ŞİFRELİ METİN RASTGELELİK ANALİZİ")
    print("=" * 70)
    
    cipher = PhoenixCipher()
    anahtar = cipher.Anahtar_Uret("analysis_key")
    
    # Tekrarlanan karakter içeren metin
    duz_metin = "AAAAAAAAAAAAAAAA" * 10  # 160 A karakteri
    sifreli = cipher.Sifrele(duz_metin, anahtar)
    
    print(f"\n📝 Düz Metin: {'A' * 16}... (160 karakter 'A')")
    print(f"🔒 Şifreli (hex): {sifreli.hex()[:80]}...")
    
    # Byte frekans analizi
    byte_freq = [0] * 256
    for byte in sifreli:
        byte_freq[byte] += 1
    
    max_freq = max(byte_freq)
    min_freq = min(b for b in byte_freq if b > 0)
    avg_freq = len(sifreli) / 256
    
    print(f"\n📊 Byte Frekans İstatistikleri:")
    print(f"   Toplam Byte: {len(sifreli)}")
    print(f"   Farklı Byte Sayısı: {sum(1 for b in byte_freq if b > 0)}")
    print(f"   En Sık Byte Tekrarı: {max_freq}")
    print(f"   En Az Byte Tekrarı: {min_freq}")
    print(f"   Ortalama Frekans: {avg_freq:.2f}")
    print(f"   Standart Sapma: {(sum((f - avg_freq) ** 2 for f in byte_freq) / 256) ** 0.5:.2f}")
    
    print("\n   💡 İdeal rastgele şifreli metinde tüm byte'lar yaklaşık eşit sıklıkta görülür.")
    print("=" * 70)


def main():
    """
    Ana test fonksiyonu - tüm testleri çalıştırır
    """
    print("\n" + "🔥" * 35)
    print("   PHOENIX ŞİFRELEME ALGORİTMASI - TEST SÜİTİ")
    print("🔥" * 35)
    
    # Test 1
    test1_result = test_1_basic_encryption_decryption()
    
    # Test 2
    test2_result = test_2_avalanche_effect()
    
    # Test 3
    test3_result = test_3_different_block_sizes()
    
    # Bonus analiz
    analyze_encryption_randomness()
    
    # Genel sonuç
    print("\n" + "=" * 70)
    print("GENEL TEST SONUÇLARI")
    print("=" * 70)
    print(f"Test 1 (Şifreleme/Deşifreleme): {'✅ BAŞARILI' if test1_result else '❌ BAŞARISIZ'}")
    print(f"Test 2 (Çığ Etkisi):            {'✅ BAŞARILI' if test2_result else '❌ BAŞARISIZ'}")
    print(f"Test 3 (Padding):               {'✅ BAŞARILI' if test3_result else '❌ BAŞARISIZ'}")
    print("=" * 70)
    
    if test1_result and test2_result and test3_result:
        print("\n🎉🎉🎉 TÜM TESTLER BAŞARILI - PHOENIX ALGORİTMASI ÇALIŞIYOR! 🎉🎉🎉\n")
        return 0
    else:
        print("\n⚠️  BAZI TESTLER BAŞARISIZ - GÖZDEN GEÇİRİLMELİ ⚠️\n")
        return 1


if __name__ == "__main__":
    exit(main())
