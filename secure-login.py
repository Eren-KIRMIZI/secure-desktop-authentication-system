import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet
import hashlib
import os
import json
import base64
from datetime import datetime, timedelta

# ===============================
# AYARLAR
# ===============================
MAX_DENEME = 3
KILITLEME_SURESI = 300  # saniye (5 dakika)
CONFIG_FILE = "login_config.json"

# ===============================
# YAPILAN HELPER FONKSİYONLARI
# ===============================
def anahtar_uret(sifre, salt):
    """Şifreden güvenli anahtar üretir (PBKDF2)"""
    kdf = hashlib.pbkdf2_hmac(
        'sha256',
        sifre.encode('utf-8'),
        salt,
        100_000
    )
    return base64.urlsafe_b64encode(kdf[:32])

def sifre_hash_olustur(sifre, salt):
    """Şifrenin hash'ini oluşturur"""
    return hashlib.pbkdf2_hmac(
        'sha256',
        sifre.encode('utf-8'),
        salt,
        100_000
    ).hex()

def config_yukle():
    """Konfigürasyon dosyasını yükler"""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return None

def config_kaydet(data):
    """Konfigürasyon dosyasını kaydeder"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def sistem_kilitli_mi():
    """Sistemin kilitli olup olmadığını kontrol eder"""
    config = config_yukle()
    if config and 'kilit_zamani' in config:
        kilit_zamani = datetime.fromisoformat(config['kilit_zamani'])
        if datetime.now() < kilit_zamani:
            kalan = (kilit_zamani - datetime.now()).seconds
            return True, kalan
    return False, 0

def sistemi_kilitle():
    """Sistemi belirli süre için kilitler"""
    config = config_yukle()
    kilit_zamani = datetime.now() + timedelta(seconds=KILITLEME_SURESI)
    config['kilit_zamani'] = kilit_zamani.isoformat()
    config['deneme_sayisi'] = 0
    config_kaydet(config)

def deneme_sayisini_arttir():
    """Başarısız deneme sayısını artırır"""
    config = config_yukle()
    config['deneme_sayisi'] = config.get('deneme_sayisi', 0) + 1
    config_kaydet(config)
    return config['deneme_sayisi']

def deneme_sayisini_sifirla():
    """Başarılı girişte deneme sayısını sıfırlar"""
    config = config_yukle()
    config['deneme_sayisi'] = 0
    if 'kilit_zamani' in config:
        del config['kilit_zamani']
    config_kaydet(config)

# ===============================
# ŞİFRE KURULUM EKRANI
# ===============================
class SifreKurulumEkrani:
    def __init__(self, root):
        self.root = root
        self.root.title("İlk Kurulum - Şifre Belirleme")
        self.root.geometry("450x350")
        self.root.resizable(False, False)
        
        self.setup_ui()
    
    def setup_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        
        frame = ttk.Frame(self.root, padding=30)
        frame.pack(expand=True, fill='both')
        
        ttk.Label(frame, text="İlk Kurulum", 
                 font=("Segoe UI", 16, "bold")).pack(pady=10)
        
        ttk.Label(frame, text="Lütfen güvenli bir ana şifre belirleyin",
                 font=("Segoe UI", 10)).pack(pady=5)
        
        # Şifre girişi
        ttk.Label(frame, text="Yeni Şifre:", font=("Segoe UI", 10)).pack(anchor="w", pady=(15,5))
        self.sifre_entry = ttk.Entry(frame, show="*", width=35, font=("Segoe UI", 10))
        self.sifre_entry.pack(pady=5)
        
        # Şifre tekrar
        ttk.Label(frame, text="Şifre Tekrar:", font=("Segoe UI", 10)).pack(anchor="w", pady=(10,5))
        self.sifre_tekrar_entry = ttk.Entry(frame, show="*", width=35, font=("Segoe UI", 10))
        self.sifre_tekrar_entry.pack(pady=5)
        
        # Şifre göster checkbox
        self.goster_var = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Şifreyi göster", 
                       variable=self.goster_var,
                       command=self.sifre_goster).pack(pady=10)
        
        # Bilgi metni
        info_text = "Şifrenizi güvende tutun!\nEn az 8 karakter kullanmanız önerilir."
        ttk.Label(frame, text=info_text, font=("Segoe UI", 9),
                 foreground="gray").pack(pady=10)
        
        # Kaydet butonu
        ttk.Button(frame, text="Şifreyi Kaydet ve Devam Et", 
                  command=self.sifre_kaydet).pack(pady=10)
        
        self.sifre_entry.focus()
        self.root.bind('<Return>', lambda e: self.sifre_kaydet())
    
    def sifre_goster(self):
        show_char = "" if self.goster_var.get() else "*"
        self.sifre_entry.config(show=show_char)
        self.sifre_tekrar_entry.config(show=show_char)
    
    def sifre_kaydet(self):
        sifre1 = self.sifre_entry.get()
        sifre2 = self.sifre_tekrar_entry.get()
        
        if not sifre1 or not sifre2:
            messagebox.showerror("Hata", "Lütfen tüm alanları doldurun!")
            return
        
        if sifre1 != sifre2:
            messagebox.showerror("Hata", "Şifreler eşleşmiyor!")
            return
        
        if len(sifre1) < 6:
            messagebox.showwarning("Uyarı", "Şifre en az 6 karakter olmalıdır!")
            return
        
        # Salt ve hash oluştur
        salt = os.urandom(16)
        sifre_hash = sifre_hash_olustur(sifre1, salt)
        
        # Konfigürasyonu kaydet
        config = {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'sifre_hash': sifre_hash,
            'deneme_sayisi': 0,
            'kurulum_tarihi': datetime.now().isoformat()
        }
        config_kaydet(config)
        
        messagebox.showinfo("Başarılı", "Şifreniz başarıyla kaydedildi! ✓\n\nGiriş ekranına yönlendiriliyorsunuz.")
        self.root.destroy()

# ===============================
# GİRİŞ EKRANI
# ===============================
class GirisEkrani:
    def __init__(self, root):
        self.root = root
        self.root.title("Güvenli Giriş Sistemi")
        self.root.geometry("400x280")
        self.root.resizable(False, False)
        
        # Sistem kilitli mi kontrol et
        kilitli, kalan = sistem_kilitli_mi()
        if kilitli:
            self.kilitleme_ekrani_goster(kalan)
        else:
            self.setup_ui()
    
    def kilitleme_ekrani_goster(self, kalan_saniye):
        frame = ttk.Frame(self.root, padding=30)
        frame.pack(expand=True)
        
        ttk.Label(frame, text="Sistem Kilitli", 
                 font=("Segoe UI", 16, "bold"),
                 foreground="red").pack(pady=20)
        
        dakika = kalan_saniye // 60
        saniye = kalan_saniye % 60
        
        mesaj = f"Çok fazla başarısız deneme!\n\nSistem {dakika} dakika {saniye} saniye\niçin kilitlendi."
        ttk.Label(frame, text=mesaj, font=("Segoe UI", 11),
                 justify="center").pack(pady=20)
        
        ttk.Button(frame, text="Kapat", 
                  command=self.root.destroy).pack(pady=10)
    
    def setup_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        
        frame = ttk.Frame(self.root, padding=30)
        frame.pack(expand=True)
        
        ttk.Label(frame, text="Güvenli Giriş", 
                 font=("Segoe UI", 16, "bold")).pack(pady=15)
        
        config = config_yukle()
        deneme = config.get('deneme_sayisi', 0)
        kalan = MAX_DENEME - deneme
        
        ttk.Label(frame, text=f"Kalan deneme hakkı: {kalan}", 
                 font=("Segoe UI", 9),
                 foreground="gray").pack(pady=5)
        
        ttk.Label(frame, text="Şifre:", font=("Segoe UI", 10)).pack(anchor="w", pady=(10,5))
        self.sifre_entry = ttk.Entry(frame, show="*", width=35, font=("Segoe UI", 11))
        self.sifre_entry.pack(pady=5)
        
        # Şifre göster checkbox
        self.goster_var = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Şifreyi göster", 
                       variable=self.goster_var,
                       command=self.sifre_goster).pack(pady=8)
        
        ttk.Button(frame, text="Giriş Yap", 
                  command=self.giris_yap).pack(pady=15)
        
        self.sifre_entry.focus()
        self.root.bind('<Return>', lambda e: self.giris_yap())
    
    def sifre_goster(self):
        show_char = "" if self.goster_var.get() else "*"
        self.sifre_entry.config(show=show_char)
    
    def giris_yap(self):
        sifre = self.sifre_entry.get()
        
        if not sifre:
            messagebox.showerror("Hata", "Lütfen şifrenizi girin!")
            return
        
        config = config_yukle()
        salt = base64.b64decode(config['salt'])
        kayitli_hash = config['sifre_hash']
        
        # Girilen şifrenin hash'ini hesapla
        girilen_hash = sifre_hash_olustur(sifre, salt)
        
        if girilen_hash == kayitli_hash:
            # Başarılı giriş
            deneme_sayisini_sifirla()
            messagebox.showinfo("Başarılı", "Giriş başarılı!\n\nSisteme hoş geldiniz.")
            self.root.destroy()
        else:
            # Başarısız giriş
            deneme = deneme_sayisini_arttir()
            kalan = MAX_DENEME - deneme
            
            if kalan <= 0:
                sistemi_kilitle()
                messagebox.showerror("Kilitlendi", 
                    f"Çok fazla başarısız deneme!\n\n"
                    f"Sistem {KILITLEME_SURESI//60} dakika süreyle kilitlendi.")
                self.root.destroy()
            else:
                messagebox.showerror("Hata", 
                    f"Şifre yanlış!\n\nKalan deneme hakkı: {kalan}")
                self.sifre_entry.delete(0, tk.END)
                self.sifre_entry.focus()

# ===============================
# ANA PROGRAM
# ===============================
def main():
    root = tk.Tk()
    
    # İlk kurulum kontrolü
    config = config_yukle()
    
    if config is None:
        # İlk kurulum - şifre belirleme
        SifreKurulumEkrani(root)
    else:
        # Normal giriş
        GirisEkrani(root)
    
    root.mainloop()

if __name__ == "__main__":
    main()