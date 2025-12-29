"""
PHOENIX Şifreleme Algoritması
==============================
Permutation and Hash-based Encrypted Network with Intelligent XOR

Dosya: phoenix_cipher.py
Tarih: 19.12.2025
Yazar: Suzan

Bu modül, PHOENIX blok şifre algoritmasının tam implementasyonunu içerir.
"""

import hashlib
import os
from typing import List, Tuple


class PhoenixCipher:
    """
    PHOENIX Blok Şifre Algoritması
    
    Özellikler:
    - Blok boyutu: 128 bit (16 byte)
    - Anahtar boyutu: 128 bit (16 byte)
    - Tur sayısı: 8
    """
    
    # Sabitler
    BLOCK_SIZE = 16  # 128 bit = 16 byte
    KEY_SIZE = 16    # 128 bit = 16 byte
    NUM_ROUNDS = 8
    
    # Permütasyon tablosu (involutory - kendi tersi)
    PERM_TABLE = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    
    # MixColumns matrisi katsayıları
    MIX_MATRIX = [
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2]
    ]
    
    # Ters MixColumns matrisi
    INV_MIX_MATRIX = [
        [14, 11, 13, 9],
        [9, 14, 11, 13],
        [13, 9, 14, 11],
        [11, 13, 9, 14]
    ]
    
    def __init__(self):
        """PHOENIX şifreleyici başlatıcı"""
        self.sbox = self._generate_sbox()
        self.inv_sbox = self._generate_inv_sbox()
    
    def _generate_sbox(self) -> List[int]:
        """
        S-Box üretimi
        Formül: S(x) = ((x XOR 0x63) * 0x1B) mod 256
        
        Returns:
            256 elemanlı S-Box listesi
        """
        sbox = []
        for x in range(256):
            val = ((x ^ 0x63) * 0x1B) % 256
            sbox.append(val)
        return sbox
    
    def _generate_inv_sbox(self) -> List[int]:
        """
        Ters S-Box üretimi
        
        Returns:
            256 elemanlı ters S-Box listesi
        """
        inv_sbox = [0] * 256
        for x in range(256):
            inv_sbox[self.sbox[x]] = x
        return inv_sbox
    
    def _galois_mult(self, a: int, b: int) -> int:
        """
        Galois Field GF(2^8) üzerinde çarpım
        Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)
        
        Args:
            a: İlk sayı
            b: İkinci sayı
            
        Returns:
            Galois Field çarpımı
        """
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1B  # x^8 + x^4 + x^3 + x + 1
            b >>= 1
        return p % 256
    
    def Anahtar_Uret(self, parola: str) -> bytes:
        """
        Anahtar Üretme Fonksiyonu
        Kullanıcı parolasından 128-bit anahtar üretir.
        
        Args:
            parola: Kullanıcı parolası (string)
            
        Returns:
            16 byte (128-bit) anahtar
        """
        # SHA-256 ile hash, ilk 128 bit al
        hash_obj = hashlib.sha256(parola.encode('utf-8'))
        key = hash_obj.digest()[:self.KEY_SIZE]
        return key
    
    def _expand_key(self, key: bytes, round_num: int) -> bytes:
        """
        Tur anahtarı genişletme
        Her tur için farklı 128-bit alt anahtar üretir.
        
        Args:
            key: Ana anahtar (16 byte)
            round_num: Tur numarası (0-7)
            
        Returns:
            Alt anahtar (16 byte)
        """
        seed = key + bytes([round_num])
        hash_obj = hashlib.sha256(seed)
        subkey = hash_obj.digest()[:self.KEY_SIZE]
        return subkey
    
    def _add_padding(self, data: bytes) -> bytes:
        """
        PKCS#7 padding ekle
        
        Args:
            data: Ham veri
            
        Returns:
            Padding eklenmiş veri
        """
        pad_len = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        padding = bytes([pad_len] * pad_len)
        return data + padding
    
    def _remove_padding(self, data: bytes) -> bytes:
        """
        PKCS#7 padding kaldır
        
        Args:
            data: Padding'li veri
            
        Returns:
            Padding kaldırılmış veri
        """
        if not data:
            return data
        pad_len = data[-1]
        return data[:-pad_len]
    
    def _sub_bytes(self, block: bytearray) -> bytearray:
        """
        S-Box substitution (ikame)
        
        Args:
            block: 16 byte blok
            
        Returns:
            S-Box uygulanmış blok
        """
        return bytearray([self.sbox[b] for b in block])
    
    def _inv_sub_bytes(self, block: bytearray) -> bytearray:
        """
        Ters S-Box substitution
        
        Args:
            block: 16 byte blok
            
        Returns:
            Ters S-Box uygulanmış blok
        """
        return bytearray([self.inv_sbox[b] for b in block])
    
    def _permute(self, block: bytearray) -> bytearray:
        """
        Byte permütasyonu
        
        Args:
            block: 16 byte blok
            
        Returns:
            Permüte edilmiş blok
        """
        result = bytearray(self.BLOCK_SIZE)
        for i in range(self.BLOCK_SIZE):
            result[self.PERM_TABLE[i]] = block[i]
        return result
    
    def _inv_permute(self, block: bytearray) -> bytearray:
        """
        Ters permütasyon (PERM_TABLE kendi tersi)
        
        Args:
            block: 16 byte blok
            
        Returns:
            Ters permüte edilmiş blok
        """
        return self._permute(block)  # Involutory
    
    def _mix_columns(self, block: bytearray) -> bytearray:
        """
        MixColumns işlemi - GF(2^8) matris çarpımı
        
        Args:
            block: 16 byte blok (4x4 matris gibi)
            
        Returns:
            Karıştırılmış blok
        """
        result = bytearray(self.BLOCK_SIZE)
        
        for col in range(4):
            # Her sütun için 4 byte
            c0, c1, c2, c3 = block[col * 4:(col + 1) * 4]
            
            result[col * 4] = (
                self._galois_mult(2, c0) ^
                self._galois_mult(3, c1) ^
                c2 ^ c3
            )
            result[col * 4 + 1] = (
                c0 ^
                self._galois_mult(2, c1) ^
                self._galois_mult(3, c2) ^
                c3
            )
            result[col * 4 + 2] = (
                c0 ^ c1 ^
                self._galois_mult(2, c2) ^
                self._galois_mult(3, c3)
            )
            result[col * 4 + 3] = (
                self._galois_mult(3, c0) ^
                c1 ^ c2 ^
                self._galois_mult(2, c3)
            )
        
        return result
    
    def _inv_mix_columns(self, block: bytearray) -> bytearray:
        """
        Ters MixColumns işlemi
        
        Args:
            block: 16 byte blok
            
        Returns:
            Ters karıştırılmış blok
        """
        result = bytearray(self.BLOCK_SIZE)
        
        for col in range(4):
            c0, c1, c2, c3 = block[col * 4:(col + 1) * 4]
            
            for row in range(4):
                result[col * 4 + row] = (
                    self._galois_mult(self.INV_MIX_MATRIX[row][0], c0) ^
                    self._galois_mult(self.INV_MIX_MATRIX[row][1], c1) ^
                    self._galois_mult(self.INV_MIX_MATRIX[row][2], c2) ^
                    self._galois_mult(self.INV_MIX_MATRIX[row][3], c3)
                )
        
        return result
    
    def _round_function(self, block: bytearray, subkey: bytes) -> bytearray:
        """
        Tur fonksiyonu F
        
        Args:
            block: 16 byte blok
            subkey: Tur anahtarı
            
        Returns:
            İşlenmiş blok
        """
        # 1. XOR ile alt anahtar
        block = bytearray([b ^ k for b, k in zip(block, subkey)])
        
        # 2. S-Box substitution
        block = self._sub_bytes(block)
        
        # 3. Permütasyon
        block = self._permute(block)
        
        # 4. MixColumns
        block = self._mix_columns(block)
        
        return block
    
    def _inv_round_function(self, block: bytearray, subkey: bytes) -> bytearray:
        """
        Ters tur fonksiyonu F^(-1)
        
        Args:
            block: 16 byte blok
            subkey: Tur anahtarı
            
        Returns:
            İşlenmiş blok
        """
        # Ters sırada uygula
        # 1. Ters MixColumns
        block = self._inv_mix_columns(block)
        
        # 2. Ters permütasyon
        block = self._inv_permute(block)
        
        # 3. Ters S-Box
        block = self._inv_sub_bytes(block)
        
        # 4. XOR (kendi tersi)
        block = bytearray([b ^ k for b, k in zip(block, subkey)])
        
        return block
    
    def Sifrele(self, duz_metin: str, anahtar: bytes) -> bytes:
        """
        Şifreleme Fonksiyonu
        
        Args:
            duz_metin: Düz metin (string)
            anahtar: 16 byte şifreleme anahtarı
            
        Returns:
            Şifreli metin (bytes)
        """
        # Veriyi bytes'a çevir
        plaintext = duz_metin.encode('utf-8')
        
        # Padding ekle
        plaintext = self._add_padding(plaintext)
        
        # Alt anahtarları üret
        subkeys = [self._expand_key(anahtar, i) for i in range(self.NUM_ROUNDS)]
        
        ciphertext = bytearray()
        
        # Her blok için
        for i in range(0, len(plaintext), self.BLOCK_SIZE):
            block = bytearray(plaintext[i:i + self.BLOCK_SIZE])
            
            # Initial whitening
            block = bytearray([b ^ k for b, k in zip(block, anahtar)])
            
            # 8 tur
            for round_num in range(self.NUM_ROUNDS):
                block = self._round_function(block, subkeys[round_num])
            
            # Final whitening
            block = bytearray([b ^ k for b, k in zip(block, anahtar)])
            
            ciphertext.extend(block)
        
        return bytes(ciphertext)
    
    def Desifrele(self, sifreli_metin: bytes, anahtar: bytes) -> str:
        """
        Deşifreleme Fonksiyonu
        
        Args:
            sifreli_metin: Şifreli metin (bytes)
            anahtar: 16 byte şifreleme anahtarı
            
        Returns:
            Düz metin (string)
        """
        # Alt anahtarları üret (aynı sıra)
        subkeys = [self._expand_key(anahtar, i) for i in range(self.NUM_ROUNDS)]
        
        plaintext = bytearray()
        
        # Her blok için
        for i in range(0, len(sifreli_metin), self.BLOCK_SIZE):
            block = bytearray(sifreli_metin[i:i + self.BLOCK_SIZE])
            
            # Final whitening (ters)
            block = bytearray([b ^ k for b, k in zip(block, anahtar)])
            
            # 8 tur (TERS SIRADA)
            for round_num in range(self.NUM_ROUNDS - 1, -1, -1):
                block = self._inv_round_function(block, subkeys[round_num])
            
            # Initial whitening (ters)
            block = bytearray([b ^ k for b, k in zip(block, anahtar)])
            
            plaintext.extend(block)
        
        # Padding kaldır
        plaintext = self._remove_padding(bytes(plaintext))
        
        # String'e çevir
        return plaintext.decode('utf-8')


def main():
    """
    Ana fonksiyon - Örnek kullanım
    """
    print("=" * 60)
    print("PHOENIX Şifreleme Algoritması - Demo")
    print("=" * 60)
    
    # Cipher nesnesi oluştur
    cipher = PhoenixCipher()
    
    # Kullanıcı parolasından anahtar üret
    parola = "MySecretPassword123!"
    anahtar = cipher.Anahtar_Uret(parola)
    
    print(f"\n📌 Parola: {parola}")
    print(f"🔑 Üretilen Anahtar (hex): {anahtar.hex()}")
    
    # Örnek metin
    duz_metin = "Merhaba Dünya! Bu bir test mesajıdır."
    print(f"\n📝 Düz Metin: {duz_metin}")
    
    # Şifreleme
    sifreli_metin = cipher.Sifrele(duz_metin, anahtar)
    print(f"\n🔒 Şifreli Metin (hex): {sifreli_metin.hex()}")
    print(f"   Uzunluk: {len(sifreli_metin)} byte")
    
    # Deşifreleme
    cozulmus_metin = cipher.Desifrele(sifreli_metin, anahtar)
    print(f"\n🔓 Deşifre Edilmiş: {cozulmus_metin}")
    
    # Doğrulama
    if duz_metin == cozulmus_metin:
        print("\n✅ BAŞARILI: Şifreleme ve deşifreleme doğru çalışıyor!")
    else:
        print("\n❌ HATA: Deşifreleme başarısız!")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
