## Güvenli Giriş Sistemi

Python ve Tkinter ile geliştirilen bu masaüstü uygulaması, modern kriptografik yöntemler kullanarak kullanıcı kimlik doğrulamasını güvenli biçimde gerçekleştirir. Hassas verilere erişim gerektiren uygulamalar için şifreli, brute-force korumalı ve kullanıcı dostu bir giriş katmanı sunar.

## Özellikler

### Güvenlik Özellikleri

- **PBKDF2 Anahtar Türetme**: Şifreler PBKDF2-HMAC-SHA256 algoritması ile 100.000 iterasyon kullanılarak güvenli anahtarlara dönüştürülür
- **Salt Mekanizması**: Her kurulum için benzersiz rastgele salt değeri üretilir ve güvenli şekilde saklanır
- **Hash Tabanlı Doğrulama**: Şifreler hiçbir zaman düz metin olarak saklanmaz, yalnızca hash değerleri kullanılır
- **Brute-Force Koruması**: Başarısız giriş denemeleri sınırlandırılır ve sistem otomatik olarak kilitlenir
- **Kalıcı Güvenlik**: Deneme sayacı ve kilitleme durumu JSON dosyasında saklanarak program yeniden başlatılsa bile korunur

### Kullanıcı Arayüzü

- İlk kullanımda güvenli şifre belirleme ekranı
- Şifre görünürlüğünü kontrol etme seçeneği
- Kalan deneme hakkı göstergesi
- Sistem kilitlendiğinde kalan süre bilgisi
- Modern ve minimal tasarım (Tkinter + ttk)
- Enter tuşu ile hızlı giriş desteği

## Kullanılan Teknolojiler

### Kriptografi
- **cryptography**: Fernet simetrik şifreleme için
- **hashlib**: PBKDF2-HMAC-SHA256 anahtar türetme ve hash işlemleri
- **os.urandom**: Kriptografik güvenli rastgele sayı üretimi
- **base64**: Binary verilerin metin formatına dönüştürülmesi

### Arayüz
- **tkinter**: Masaüstü uygulama arayüzü
- **ttk**: Modern tema ve widget'lar

### Veri Yönetimi
- **json**: Konfigürasyon ve kullanıcı verilerinin saklanması
- **datetime**: Zaman bazlı kilitleme mekanizması

## Teknik Detaylar

### Şifre Hashleme Süreci

```
Kullanıcı Şifresi + Salt (16 byte rastgele)
            |
            v
    PBKDF2-HMAC-SHA256
    (100.000 iterasyon)
            |
            v
     32 byte hash değeri
```

### Güvenlik Parametreleri

- **Maksimum Deneme Hakkı**: 3 başarısız deneme
- **Kilitleme Süresi**: 300 saniye (5 dakika)
- **Minimum Şifre Uzunluğu**: 6 karakter
- **PBKDF2 İterasyon Sayısı**: 100.000
- **Salt Boyutu**: 16 byte (128 bit)

### Dosya Yapısı

```
login_config.json
{
    "salt": "base64_encoded_salt",
    "sifre_hash": "hex_encoded_password_hash",
    "deneme_sayisi": 0,
    "kurulum_tarihi": "ISO_format_datetime",
    "kilit_zamani": "ISO_format_datetime" (opsiyonel)
}
```

## Kurulum

### Gereksinimler

```bash
pip install cryptography
```

Python 3.6 veya üzeri gereklidir. Tkinter, Python ile birlikte gelir.

### Çalıştırma

```bash
python secure_login.py
```

İlk çalıştırmada şifre belirleme ekranı açılacaktır. Belirlediğiniz şifreyi güvenli bir yerde saklayın.

## Kullanım

1. **İlk Kurulum**: Program ilk kez çalıştırıldığında şifre belirleme ekranı görünür
2. **Şifre Belirleme**: Güvenli bir şifre seçin ve onaylayın
3. **Giriş**: Belirlediğiniz şifreyle sisteme giriş yapın
4. **Güvenlik**: 3 yanlış denemeden sonra sistem 5 dakika kilitlenir

## Güvenlik Notları

- Şifre hash'leri SHA-256 algoritması kullanılarak oluşturulur
- Salt değerleri kriptografik güvenli rastgele sayı üreteci ile oluşturulur
- Tüm hassas veriler JSON dosyasında base64 veya hex formatında saklanır
- Brute-force saldırılarına karşı zaman bazlı kilitleme mekanizması aktiftir

## Özelleştirme

Güvenlik parametrelerini kod içinden değiştirebilirsiniz:

```python
MAX_DENEME = 3              # Deneme hakkı
KILITLEME_SURESI = 300      # Kilitleme süresi (saniye)
CONFIG_FILE = "login_config.json"  # Konfigürasyon dosyası
```

PBKDF2 iterasyon sayısını artırarak güvenliği artırabilirsiniz (performans azalır):

```python
hashlib.pbkdf2_hmac('sha256', sifre.encode('utf-8'), salt, 500_000)
```
