"""
Password Strength Visualizer
==============================
Bir şifrenin gücünü analiz eder ve görsel/sayısal olarak gösterir:
- Entropi (bit cinsinden)
- Tahmini kaba kuvvet (brute-force) kırılma süresi
- Yaygın zayıflık desenleri (sözlük kelimeleri, ardışık karakterler, tekrarlar)
- Terminal'de renkli güç çubuğu

Bu araç ŞİFRELERİ HİÇBİR YERE GÖNDERMEZ veya KAYDETMEZ; tamamen yerel
ve çevrimdışı çalışır. Gerçek şifrelerinizi test etmek güvenlidir.

Kullanım:
    python password_strength.py                  # İnteraktif mod (gizli giriş)
    python password_strength.py --check "test123" # Doğrudan kontrol (terminal geçmişine kaydedilebilir, dikkat!)
    python password_strength.py --batch dosya.txt # Bir dosyadaki şifre listesini toplu analiz et
"""

import argparse
import getpass
import math
import re
import sys

# En sık kullanılan / en kolay tahmin edilen şifrelerden kısa bir örnek liste
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "abc123", "football", "monkey", "letmein", "696969", "shadow",
    "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890",
    "michael", "654321", "superman", "1qaz2wsx", "7777777", "121212",
    "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan",
    "jennifer", "hunter", "buster", "soccer", "harley", "batman",
    "andrew", "tigger", "sunshine", "iloveyou", "fuckme", "2000",
    "charlie", "robert", "thomas", "hockey", "ranger", "daniel",
    "starwars", "klaster", "112233", "george", "asshole", "computer",
    "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom", "777777", "pass", "fuckyou",
    "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua",
    "cheese", "amanda", "summer", "love", "ashley", "6969", "nicole",
    "chelsea", "biteme", "matthew", "access", "yankees", "987654321",
    "dallas", "austin", "thunder", "taylor", "matrix", "william",
    "corvette", "hello", "martin", "heather", "secret", "fucker",
    "merlin", "diamond", "1234qwer", "gfhjkm", "hammer", "silver",
    "222222", "88888888", "anthony", "justin", "test", "bailey",
    "q1w2e3r4t5", "patrick", "internet", "scooter", "orange", "11111",
    "golfer", "cookie", "richard", "samantha", "bigdog", "guitar",
    "jackson", "whatever", "mickey", "chicken", "sparky", "snoopy",
    "password1", "password123", "admin", "welcome", "login", "passw0rd",
    "qwerty123", "1q2w3e4r", "iloveyou1", "monkey123",
}

CHAR_SETS = [
    ("lowercase", r"[a-z]", 26),
    ("uppercase", r"[A-Z]", 26),
    ("digits", r"[0-9]", 10),
    ("symbols", r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", 32),
    ("unicode", r"[^\x00-\x7F]", 50),  # Yaklaşık tahmin
]

GUESSES_PER_SECOND = {
    "Çevrimiçi (oran sınırlı)": 10,
    "Çevrimiçi (sınırsız)": 1_000,
    "Çevrimdışı (yavaş hash, örn. bcrypt)": 10_000,
    "Çevrimdışı (hızlı hash, örn. MD5/SHA1)": 10_000_000_000,
    "GPU çiftliği (kurumsal saldırgan)": 100_000_000_000,
}

BAR_LENGTH = 40
COLORS = {
    "red": "\033[91m",
    "orange": "\033[38;5;208m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "bright_green": "\033[38;5;46m",
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}


def calculate_charset_size(password: str) -> int:
    size = 0
    for _, pattern, set_size in CHAR_SETS:
        if re.search(pattern, password):
            size += set_size
    return max(size, 1)


def calculate_entropy(password: str) -> float:
    """Shannon entropisine yakın basit bir tahmin: log2(charset_size^length)"""
    if not password:
        return 0.0
    charset_size = calculate_charset_size(password)
    return len(password) * math.log2(charset_size)


def detect_weaknesses(password: str) -> list:
    """Yaygın zayıflık desenlerini tespit eder."""
    issues = []
    lower = password.lower()

    if lower in COMMON_PASSWORDS:
        issues.append("Bu, en sık kullanılan şifrelerden biri")
    if len(password) < 8:
        issues.append("Çok kısa (8 karakterden az)")
    if re.search(r"(.)\1{2,}", password):
        issues.append("Tekrarlanan karakterler var (örn. 'aaa')")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|7890)", password):
        issues.append("Ardışık sayılar içeriyor")
    if re.search(r"(abcd|bcde|cdef|qwer|wert|erty|asdf|zxcv)", lower):
        issues.append("Klavyede ardışık tuşlar veya alfabetik sıra içeriyor")
    if re.fullmatch(r"[a-zA-Z]+", password):
        issues.append("Sadece harf içeriyor, sayı veya sembol yok")
    if re.fullmatch(r"[0-9]+", password):
        issues.append("Sadece sayı içeriyor")
    if re.search(r"19\d{2}|20[0-2]\d", password):
        issues.append("Bir yıl/tarih içeriyor gibi görünüyor (tahmin edilebilir)")

    return issues


def format_time(seconds: float) -> str:
    """Saniyeyi okunabilir bir süreye çevirir."""
    if seconds < 1:
        return "anında"
    units = [
        ("yüzyıl", 100 * 365.25 * 24 * 3600),
        ("yıl", 365.25 * 24 * 3600),
        ("ay", 30 * 24 * 3600),
        ("gün", 24 * 3600),
        ("saat", 3600),
        ("dakika", 60),
        ("saniye", 1),
    ]
    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            if value > 1_000_000:
                return f"{value:.2e} {name}"
            return f"{value:.1f} {name}"
    return "anında"


def strength_label(entropy: float, weaknesses: list) -> tuple:
    """(etiket, renk, 0-1 arası skor) döndürür."""
    penalty = len(weaknesses) * 8
    effective = max(entropy - penalty, 0)

    if effective < 28:
        return "ÇOK ZAYIF", "red", 0.1
    elif effective < 40:
        return "ZAYIF", "orange", 0.3
    elif effective < 60:
        return "ORTA", "yellow", 0.55
    elif effective < 80:
        return "GÜÇLÜ", "green", 0.8
    else:
        return "ÇOK GÜÇLÜ", "bright_green", 1.0


def render_bar(score: float, color: str) -> str:
    filled = int(BAR_LENGTH * score)
    bar = "█" * filled + "░" * (BAR_LENGTH - filled)
    return f"{COLORS[color]}{bar}{COLORS['reset']}"


def analyze_password(password: str, verbose: bool = True) -> dict:
    entropy = calculate_entropy(password)
    weaknesses = detect_weaknesses(password)
    label, color, score = strength_label(entropy, weaknesses)

    result = {
        "length": len(password),
        "entropy_bits": round(entropy, 1),
        "weaknesses": weaknesses,
        "strength": label,
        "score": score,
    }

    if verbose:
        print(f"\n{COLORS['bold']}Şifre Analizi{COLORS['reset']}")
        print(f"Uzunluk: {len(password)} karakter")
        print(f"Tahmini entropi: {entropy:.1f} bit")
        print(f"\nGüç: {COLORS[color]}{COLORS['bold']}{label}{COLORS['reset']}")
        print(render_bar(score, color))

        if weaknesses:
            print(f"\n{COLORS['bold']}Tespit edilen zayıflıklar:{COLORS['reset']}")
            for w in weaknesses:
                print(f"  {COLORS['red']}✗{COLORS['reset']} {w}")
        else:
            print(f"\n{COLORS['green']}✓ Bilinen yaygın zayıflık deseni bulunamadı{COLORS['reset']}")

        print(f"\n{COLORS['bold']}Tahmini kaba kuvvet kırılma süresi:{COLORS['reset']}")
        guesses_needed = 2 ** entropy / 2  # Ortalama olarak arama uzayının yarısı
        for scenario, rate in GUESSES_PER_SECOND.items():
            seconds = guesses_needed / rate
            print(f"  {scenario:<38} {format_time(seconds)}")

    return result


def main():
    parser = argparse.ArgumentParser(description="Şifre gücü analiz aracı (tamamen yerel, çevrimdışı)")
    parser.add_argument("--check", type=str, help="Doğrudan analiz edilecek şifre (DİKKAT: terminal geçmişinde kalabilir)")
    parser.add_argument("--batch", type=str, help="Her satırda bir şifre olan dosyayı toplu analiz et")
    args = parser.parse_args()

    if args.batch:
        with open(args.batch, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]
        print(f"{len(passwords)} şifre analiz ediliyor...\n")
        print(f"{'Şifre':<25} {'Uzunluk':<10} {'Entropi':<10} {'Güç'}")
        print("-" * 65)
        for pwd in passwords:
            masked = pwd[:2] + "*" * max(len(pwd) - 2, 0)
            result = analyze_password(pwd, verbose=False)
            print(f"{masked:<25} {result['length']:<10} {result['entropy_bits']:<10} {result['strength']}")
        return

    if args.check:
        analyze_password(args.check)
        return

    # İnteraktif mod: şifre ekranda görünmeden girilir
    print("Şifre gücü analizörü (yerel, çevrimdışı çalışır — hiçbir veri gönderilmez)")
    try:
        password = getpass.getpass("Analiz edilecek şifreyi girin (görünmez): ")
    except (KeyboardInterrupt, EOFError):
        print("\nİptal edildi.")
        sys.exit(0)

    if not password:
        print("Boş şifre girildi.")
        sys.exit(0)

    analyze_password(password)


if __name__ == "__main__":
    main()
