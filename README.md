# 🔐 Password Strength Visualizer

Bir şifrenin gücünü entropi hesabı, yaygın zayıflık desenleri ve tahmini
kaba kuvvet (brute-force) kırılma süresiyle analiz eden, **tamamen yerel
ve çevrimdışı** çalışan bir terminal aracı.

> ⚠️ **Gizlilik notu:** Bu araç hiçbir şifreyi hiçbir yere göndermez veya
> diske kaydetmez. Tüm hesaplama yerel olarak yapılır. Yine de gerçek
> şifrelerinizi `--check` ile komut satırı argümanı olarak girmek yerine
> argümansız çalıştırıp interaktif (gizli) giriş modunu kullanmanız
> önerilir — komut satırı argümanları kabuk (shell) geçmişinde kalabilir.

## Özellikler

- 📊 Shannon entropisi tabanlı güç skoru
- ⏱️ Farklı saldırı senaryoları için tahmini kırılma süresi (çevrimiçi,
  çevrimdışı, GPU çiftliği)
- 🚩 Yaygın zayıflık tespiti: sözlük şifreleri, ardışık karakterler,
  klavye desenleri, tarih/yıl içeren şifreler
- 🎨 Renkli terminal güç çubuğu
- 📁 Toplu analiz modu (bir dosyadaki şifre listesi için)
- 🔒 Gizli giriş modu (`getpass`) — şifre ekranda görünmez

## Kurulum

Sadece Python standart kütüphanesi kullanılır, kurulum gerekmez.

## Kullanım

```bash
# İnteraktif mod (önerilen) — şifre gizli girilir
python3 password_strength.py

# Doğrudan kontrol (DİKKAT: kabuk geçmişinde kalabilir)
python3 password_strength.py --check "ornekSifre123"

# Bir dosyadaki şifre listesini toplu analiz et
python3 password_strength.py --batch sifreler.txt
```

## Örnek çıktı

```
Şifre Analizi
Uzunluk: 16 karakter
Tahmini entropi: 104.9 bit

Güç: ÇOK GÜÇLÜ
████████████████████████████████████████

✓ Bilinen yaygın zayıflık deseni bulunamadı

Tahmini kaba kuvvet kırılma süresi:
  Çevrimiçi (oran sınırlı)               5.89e+20 yüzyıl
  Çevrimdışı (hızlı hash, örn. MD5/SHA1) 5.89e+11 yüzyıl
  GPU çiftliği (kurumsal saldırgan)      5.89e+10 yüzyıl
```

## Nasıl çalışır?

Entropi, şifrenin karakter setine (küçük/büyük harf, sayı, sembol) ve
uzunluğuna göre `uzunluk × log2(karakter_seti_boyutu)` formülüyle
hesaplanır. Bilinen zayıflıklar tespit edildiğinde entropi skoruna ceza
puanı uygulanır, çünkü gerçek dünyada saldırganlar rastgele deneme yerine
önce yaygın şifreleri ve desenleri dener (sözlük saldırısı).

## Lisans

MIT


---

> Made in [discord.gg/codeshare](https://discord.gg/codeshare) · [astra-dev.com.tr](https://astra-dev.com.tr)
