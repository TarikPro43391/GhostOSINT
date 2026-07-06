"""
================================================================
 GHOST OSINT FRAMEWORK v0.1.1 (Alpha) - GUI EDITION
 by TarikPro43391
================================================================
Modüller:
  - Discord ID Lookup   (snowflake decode + opsiyonel Bot Token ile public profil)
  - IP Lookup           (geolocation / ISP / ASN)
  - Domain / DNS / WHOIS
  - Username Search     (çoklu platform)
  - Email Analyzer      (format + domain + MX)
  - Hash Identifier     (MD5/SHA1/SHA256/SHA512/bcrypt tahmini)
  - Phone Number Info   (ülke/operatör - phonenumbers kütüphanesi varsa)
  - URL Analyzer        (redirect zinciri, kısaltıcı tespiti, punycode/homograph uyarısı)
  - QR Kod Decode       (resimden QR kod okuma - opencv gerekir)
  - EXIF / Metadata     (resimden kamera/GPS/tarih metadata çıkarma - Pillow gerekir)
  - MAC Vendor Lookup   (OUI'den üretici tespiti)
  - User-Agent Parser   (tarayıcı/OS/cihaz/bot tespiti)

Not: Bu araç yalnızca PUBLIC/OSINT amaçlı bilgi toplar. Discord Bot Token
özelliği sadece kendi botunuzun tokenı ile, Discord'un resmi public
/users/{id} endpointini kullanır (username, avatar, badge gibi herkese
açık bilgiler). Başkasının hesabına yetkisiz erişim, mesaj/DM okuma,
token çalma gibi işlevler İÇERMEZ ve eklenmeyecektir.
================================================================
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import ssl
import socket
import re
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import webbrowser
import base64

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import phonenumbers
    from phonenumbers import geocoder as pn_geocoder, carrier as pn_carrier
    PHONENUMBERS_OK = True
except ImportError:
    PHONENUMBERS_OK = False

try:
    import dns.resolver
    DNSPYTHON_OK = True
except ImportError:
    DNSPYTHON_OK = False

try:
    from PIL import Image, ExifTags
    PIL_OK = True
except ImportError:
    PIL_OK = False

try:
    import cv2
    CV2_OK = True
except ImportError:
    CV2_OK = False

# ================= VERSION =================
CURRENT_VERSION = "v0.1.1"
# Gerçek bir repo URL'si ile değiştirin. version.json dosyası {"latest_version": "vX.Y.Z", "release_url": "..."} formatında olmalı.
VERSION_CHECK_URL = "https://raw.githubusercontent.com/TarikPro43391/GHOST-OSINT-FRAMEWORK/main/version.json"


# ================= THEMES =================
THEMES = {
    "Ghost Dark": {
        "BG": "#0c0c0e",
        "PANEL": "#151517",
        "PANEL2": "#1c1c1f",
        "FG": "#e8e8ea",
        "FG_DIM": "#9a9aa0",
        "RED": "#ff3b30",
        "BLUE": "#3b82f6",
        "BORDER": "#2a2a2e",
    },
    "Ghost Light": {
        "BG": "#f0f0f0",
        "PANEL": "#ffffff",
        "PANEL2": "#e9e9e9",
        "FG": "#1c1c1e",
        "FG_DIM": "#6a6a70",
        "RED": "#d70015",
        "BLUE": "#007aff",
        "BORDER": "#d1d1d6",
    },
    "Matrix": {
        "BG": "#000000",
        "PANEL": "#020f02",
        "PANEL2": "#051f05",
        "FG": "#00ff41",
        "FG_DIM": "#008f25",
        "RED": "#ff0000",
        "BLUE": "#33c3ff",
        "BORDER": "#005215",
    }
}
FONT        = ("Segoe UI", 9)
FONT_B      = ("Segoe UI", 9, "bold")
FONT_TITLE  = ("Segoe UI", 16, "bold")
FONT_MONO   = ("Consolas", 9)

DISCORD_EPOCH = 1420070400000  # ms

DISCORD_BADGES = {
    1 << 0:  "Discord Staff",
    1 << 1:  "Partnered Server Owner",
    1 << 2:  "HypeSquad Events",
    1 << 3:  "Bug Hunter Level 1",
    1 << 6:  "HypeSquad Bravery",
    1 << 7:  "HypeSquad Brilliance",
    1 << 8:  "HypeSquad Balance",
    1 << 9:  "Early Supporter",
    1 << 14: "Bug Hunter Level 2",
    1 << 16: "Verified Bot",
    1 << 17: "Early Verified Bot Developer",
    1 << 18: "Discord Certified Moderator",
    1 << 22: "Active Developer",
}

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) GhostOSINT/3.0"}


# ================= YARDIMCI FONKSİYONLAR =================

def check_for_updates():
    """GitHub'da yeni bir sürüm olup olmadığını kontrol eder."""
    if not REQUESTS_OK:
        return None
    try:
        r = requests.get(VERSION_CHECK_URL, headers=UA, timeout=5)
        if r.status_code != 200:
            return None
        data = r.json()
        latest_version = data.get("latest_version")
        # Basit string karşılaştırması "vX.Y.Z" formatı için çalışır
        if latest_version and latest_version > CURRENT_VERSION:
            return {
                "new_version": latest_version,
                "release_url": data.get("release_url")
            }
    except Exception:
        # Herhangi bir hatada sessizce başarısız ol (internet yok, geçersiz json vb.)
        return None
    return None

def decode_snowflake(raw_id: str) -> dict:
    sid = int(raw_id.strip())
    timestamp_ms = (sid >> 22) + DISCORD_EPOCH
    dt = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
    worker_id = (sid & 0x3E0000) >> 17
    process_id = (sid & 0x1F000) >> 12
    increment = sid & 0xFFF
    default_avatar_index = (sid >> 22) % 6
    age_days = (datetime.now(timezone.utc) - dt).days
    years = age_days // 365
    months = (age_days % 365) // 30
    return {
        "id": sid,
        "created_utc": dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "timestamp_ms": timestamp_ms,
        "worker_id": worker_id,
        "process_id": process_id,
        "increment": increment,
        "age": f"{years} yıl {months} ay ({age_days} gün)",
        "default_avatar_url": f"https://cdn.discordapp.com/embed/avatars/{default_avatar_index}.png",
    }


def fetch_discord_public_profile(user_id: str, token: str) -> dict:
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil (pip install requests)")

    clean_token = token.strip().strip('"').strip("'")
    for prefix in ("Bot ", "bot ", "Bearer ", "bearer "):
        if clean_token.startswith(prefix):
            clean_token = clean_token[len(prefix):].strip()
            break

    headers = {"Authorization": f"Bot {clean_token}", "User-Agent": UA["User-Agent"]}
    try:
        r = requests.get(f"https://discord.com/api/v10/users/{user_id.strip()}",
                          headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Bağlantı hatası: {e}")

    if r.status_code == 401:
        raise RuntimeError(
            "Token geçersiz veya yetkisiz (401). Kontrol et: token'ı 'Bot ' öneki OLMADAN "
            "yapıştır (kod zaten kendisi ekliyor), token'ın önünde/sonunda boşluk/yeni satır "
            "olmamalı, ve token Discord Developer Portal'dan resetlenmemiş olmalı."
        )
    if r.status_code == 404:
        raise RuntimeError("Kullanıcı bulunamadı (404). ID'yi kontrol et.")
    if r.status_code == 429:
        raise RuntimeError("Rate limit'e çarptın (429). Birkaç saniye bekleyip tekrar dene.")
    if r.status_code != 200:
        raise RuntimeError(f"Beklenmeyen yanıt: HTTP {r.status_code} — {r.text[:200]}")

    data = r.json()

    flags = data.get("public_flags", 0)
    badges = [name for bit, name in DISCORD_BADGES.items() if flags & bit]

    avatar_hash = data.get("avatar")
    if avatar_hash:
        ext = "gif" if avatar_hash.startswith("a_") else "png"
        avatar_url = f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.{ext}?size=512"
    else:
        avatar_url = None

    banner_hash = data.get("banner")
    banner_url = (f"https://cdn.discordapp.com/banners/{user_id}/{banner_hash}.png?size=512"
                  if banner_hash else None)

    return {
        "username": data.get("username"),
        "global_name": data.get("global_name"),
        "discriminator": data.get("discriminator"),
        "bot": data.get("bot", False),
        "avatar_url": avatar_url,
        "banner_url": banner_url,
        "badges": badges or ["-"],
        "accent_color": data.get("accent_color"),
    }


def fetch_discord_invite(invite_code: str) -> dict:
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil")
    code = invite_code.strip()
    for prefix in ("https://discord.gg/", "http://discord.gg/", "discord.gg/",
                   "https://discord.com/invite/", "discord.com/invite/"):
        if code.startswith(prefix):
            code = code[len(prefix):]
            break
    code = code.strip("/")

    r = requests.get(
        f"https://discord.com/api/v10/invites/{code}",
        params={"with_counts": "true", "with_expiration": "true"},
        headers=UA, timeout=8,
    )
    if r.status_code == 404:
        raise RuntimeError("Davet linki geçersiz veya süresi dolmuş (404).")
    r.raise_for_status()
    data = r.json()

    guild = data.get("guild", {}) or {}
    channel = data.get("channel", {}) or {}
    inviter = data.get("inviter") or {}

    icon_url = None
    if guild.get("icon"):
        icon_url = f"https://cdn.discordapp.com/icons/{guild.get('id')}/{guild.get('icon')}.png?size=256"

    return {
        "guild_name": guild.get("name"),
        "guild_id": guild.get("id"),
        "guild_description": guild.get("description"),
        "icon_url": icon_url,
        "verification_level": guild.get("verification_level"),
        "member_count": data.get("approximate_member_count"),
        "online_count": data.get("approximate_presence_count"),
        "channel_name": channel.get("name"),
        "inviter_username": inviter.get("username") if inviter else None,
        "expires_at": data.get("expires_at"),
    }


def ip_lookup(ip: str) -> dict:
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil")
    fields = "status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse"
    r = requests.get(f"http://ip-api.com/json/{ip.strip()}?fields={fields}", timeout=8)
    data = r.json()
    if data.get("status") != "success":
        raise RuntimeError(data.get("message", "IP bulunamadı"))
    return data


def dns_lookup(domain: str) -> dict:
    domain = domain.strip()
    result = {"A": [], "MX": [], "raw_error": None}
    try:
        result["A"] = list({ip for ip in socket.gethostbyname_ex(domain)[2]})
    except socket.gaierror as e:
        result["raw_error"] = str(e)

    if DNSPYTHON_OK:
        try:
            answers = dns.resolver.resolve(domain, "MX")
            result["MX"] = sorted(str(r.exchange).rstrip(".") for r in answers)
        except Exception:
            pass
    return result


def check_ssl_certificate(domain: str, port: int = 443) -> dict:
    domain = domain.strip()
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()
    except socket.gaierror as e:
        raise RuntimeError(f"Host çözülemedi: {e}")
    except ssl.SSLCertVerificationError as e:
        raise RuntimeError(f"Sertifika doğrulanamadı (geçersiz/kendinden imzalı olabilir): {e}")
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        raise RuntimeError(f"Bağlantı kurulamadı: {e}")

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    san_list = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

    def parse_cert_date(s):
        return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

    not_before = parse_cert_date(cert["notBefore"])
    not_after = parse_cert_date(cert["notAfter"])
    days_left = (not_after - datetime.now(timezone.utc)).days

    return {
        "domain": domain,
        "common_name": subject.get("commonName", "-"),
        "organization": subject.get("organizationName", "-"),
        "issuer_cn": issuer.get("commonName", "-"),
        "issuer_org": issuer.get("organizationName", "-"),
        "valid_from": not_before.strftime("%Y-%m-%d"),
        "valid_until": not_after.strftime("%Y-%m-%d"),
        "days_left": days_left,
        "expired": days_left < 0,
        "san_list": san_list,
        "tls_version": tls_version,
        "cipher": cipher[0] if cipher else "-",
    }


def whois_lookup(domain: str) -> str:
    domain = domain.strip().lower()
    tld = domain.split(".")[-1]

    def query(server, q, port=43):
        with socket.create_connection((server, port), timeout=10) as s:
            s.send((q + "\r\n").encode())
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
        return resp.decode(errors="ignore")

    def find_refer(text):
        for line in text.splitlines():
            low = line.lower()
            if low.startswith("refer:") or low.startswith("whois server:") or low.startswith("whois:"):
                return line.split(":", 1)[1].strip()
        return None

    try:
        iana_resp = query("whois.iana.org", domain)
    except Exception as e:
        return f"IANA whois sunucusuna bağlanılamadı: {e}\n(Ağ/firewall port 43'ü (WHOIS) engelliyor olabilir.)"

    refer_server = find_refer(iana_resp)
    if not refer_server:
        return f"'.{tld}' için authoritative WHOIS sunucusu bulunamadı.\n\n--- IANA yanıtı ---\n{iana_resp}"

    try:
        second_resp = query(refer_server, domain)
    except Exception as e:
        return f"'{refer_server}' sunucusuna bağlanılamadı: {e}\n\n--- IANA yanıtı ---\n{iana_resp}"

    # Bazı ccTLD'ler (örn. .co.uk gibi) ikinci bir sunucuya yönlendirme yapar
    second_refer = find_refer(second_resp)
    if second_refer and second_refer.lower() != refer_server.lower():
        try:
            third_resp = query(second_refer, domain)
            if third_resp.strip():
                return third_resp
        except Exception:
            pass

    return second_resp


USERNAME_PLATFORMS = [
    ("GitHub",    "https://github.com/{u}",              "not-found-page"),
    ("Reddit",    "https://www.reddit.com/user/{u}/about.json", "reddit-json"),
    ("Steam",     "https://steamcommunity.com/id/{u}",    "steam-text"),
    ("Twitch",    "https://www.twitch.tv/{u}",            "generic"),
    ("TikTok",    "https://www.tiktok.com/@{u}",          "generic"),
    ("YouTube",   "https://www.youtube.com/@{u}",         "generic"),
    ("Telegram",  "https://t.me/{u}",                     "telegram-text"),
    ("Pinterest", "https://www.pinterest.com/{u}/",       "generic"),
    ("Instagram", "https://www.instagram.com/{u}/",       "generic"),
]


def check_username_on_platform(name: str, url_tmpl: str, mode: str, username: str):
    url = url_tmpl.format(u=username)
    if not REQUESTS_OK:
        return name, "HATA (requests yok)", url
    try:
        r = requests.get(url, headers=UA, timeout=10, allow_redirects=True)
        text = r.text.lower() if r.text else ""
        if mode == "reddit-json":
            try:
                j = r.json()
                found = not (isinstance(j, dict) and j.get("error"))
            except Exception:
                found = r.status_code == 200
        elif mode == "steam-text":
            found = r.status_code == 200 and "the specified profile could not be found" not in text
        elif mode == "telegram-text":
            found = r.status_code == 200 and "if you have telegram" in text
        elif mode == "not-found-page":
            found = r.status_code == 200
        else:  # generic
            found = r.status_code == 200
        status = "BULUNDU" if found else "YOK"
        return name, status, url
    except requests.exceptions.Timeout:
        return name, "ZAMAN AŞIMI", url
    except requests.exceptions.SSLError:
        return name, "SSL HATASI", url
    except requests.exceptions.ConnectionError:
        return name, "BAĞLANTI HATASI", url
    except Exception as e:
        return name, f"HATA ({type(e).__name__})", url


def analyze_email(email: str) -> dict:
    email = email.strip()
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    valid_format = re.match(pattern, email) is not None
    domain = email.split("@")[-1] if "@" in email else None
    result = {"valid_format": valid_format, "domain": domain, "mx": [], "a_record": []}
    if domain:
        try:
            result["a_record"] = list({ip for ip in socket.gethostbyname_ex(domain)[2]})
        except Exception:
            pass
        if DNSPYTHON_OK:
            try:
                answers = dns.resolver.resolve(domain, "MX")
                result["mx"] = sorted(str(r.exchange).rstrip(".") for r in answers)
            except Exception:
                pass
    return result


def identify_hash(h: str) -> list:
    h = h.strip()
    guesses = []
    if re.fullmatch(r"[a-fA-F0-9]{32}", h):
        guesses += ["MD5", "NTLM", "MD4"]
    if re.fullmatch(r"[a-fA-F0-9]{40}", h):
        guesses += ["SHA-1", "MySQL5"]
    if re.fullmatch(r"[a-fA-F0-9]{56}", h):
        guesses += ["SHA-224"]
    if re.fullmatch(r"[a-fA-F0-9]{64}", h):
        guesses += ["SHA-256"]
    if re.fullmatch(r"[a-fA-F0-9]{96}", h):
        guesses += ["SHA-384"]
    if re.fullmatch(r"[a-fA-F0-9]{128}", h):
        guesses += ["SHA-512"]
    if re.match(r"^\$2[aby]?\$", h):
        guesses += ["bcrypt"]
    if re.match(r"^\$1\$", h):
        guesses += ["MD5 crypt (Unix)"]
    if re.match(r"^\$6\$", h):
        guesses += ["SHA-512 crypt (Unix)"]
    if re.fullmatch(r"[a-fA-F0-9]{32}:[a-fA-F0-9]+", h):
        guesses += ["Salted hash (format hash:salt)"]
    return guesses or ["Tanınamadı"]


URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
                   "ow.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc"]


def analyze_url(url: str) -> dict:
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil")
    parsed_initial = urllib.parse.urlparse(url)
    domain_initial = parsed_initial.netloc.lower()
    is_shortener = any(s in domain_initial for s in URL_SHORTENERS)

    result = {
        "original": url,
        "is_shortener": is_shortener,
        "https": url.lower().startswith("https"),
        "final_url": None,
        "redirect_chain": [],
        "ip": None,
        "punycode": False,
        "error": None,
    }
    try:
        r = requests.get(url, headers=UA, timeout=8, allow_redirects=True)
        result["final_url"] = r.url
        result["redirect_chain"] = [h.url for h in r.history]
        final_domain = urllib.parse.urlparse(r.url).netloc.split(":")[0]
        result["punycode"] = final_domain.startswith("xn--") or ".xn--" in final_domain
        try:
            result["ip"] = socket.gethostbyname(final_domain)
        except Exception:
            pass
    except Exception as e:
        result["error"] = str(e)
    return result


def decode_qr(path: str) -> str:
    if not CV2_OK:
        raise RuntimeError("opencv-python kurulu değil (pip install opencv-python)")
    img = cv2.imread(path)
    if img is None:
        raise RuntimeError("Görsel okunamadı, dosya yolu/format hatalı olabilir.")
    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(img)
    if not data:
        raise RuntimeError("QR kod bulunamadı veya okunamadı.")
    return data


def _gps_to_decimal(coord, ref):
    degrees, minutes, seconds = coord
    dec = float(degrees) + float(minutes) / 60 + float(seconds) / 3600
    if ref in ("S", "W"):
        dec = -dec
    return dec


def extract_exif(path: str) -> dict:
    if not PIL_OK:
        raise RuntimeError("Pillow kurulu değil (pip install Pillow)")
    img = Image.open(path)
    raw = img.getexif()
    result = {"tags": {}, "gps": None, "has_exif": False}
    if not raw:
        return result
    result["has_exif"] = True
    gps_raw = None
    for tag_id, value in raw.items():
        tag = ExifTags.TAGS.get(tag_id, str(tag_id))
        if tag == "GPSInfo":
            gps_raw = value
        else:
            result["tags"][tag] = value

    if gps_raw:
        gps_named = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_raw.items()}
        try:
            lat = _gps_to_decimal(gps_named["GPSLatitude"], gps_named.get("GPSLatitudeRef", "N"))
            lon = _gps_to_decimal(gps_named["GPSLongitude"], gps_named.get("GPSLongitudeRef", "E"))
            result["gps"] = {"lat": lat, "lon": lon}
        except Exception:
            pass
    return result


def mac_vendor_lookup(mac: str) -> str:
    mac_clean = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(mac_clean) < 6:
        raise ValueError("Geçersiz MAC adresi formatı.")
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil")
    r = requests.get(f"https://api.macvendors.com/{mac.strip()}", timeout=8)
    if r.status_code == 200 and r.text.strip():
        return r.text.strip()
    if r.status_code == 404:
        raise RuntimeError("Üretici bulunamadı (bilinmeyen OUI).")
    raise RuntimeError(f"Sorgu başarısız (HTTP {r.status_code}), API rate limit olabilir.")


def parse_user_agent(ua: str) -> dict:
    ua_l = ua.lower()

    os_name = "Bilinmiyor"
    if "windows nt 10" in ua_l:
        os_name = "Windows 10/11"
    elif "windows nt 6.3" in ua_l:
        os_name = "Windows 8.1"
    elif "windows nt 6.1" in ua_l:
        os_name = "Windows 7"
    elif "mac os x" in ua_l:
        os_name = "macOS"
    elif "android" in ua_l:
        os_name = "Android"
    elif "iphone" in ua_l or "ipad" in ua_l:
        os_name = "iOS"
    elif "linux" in ua_l:
        os_name = "Linux"

    browser, version = "Bilinmiyor", "-"
    order = [("edg/", "Edge"), ("opr/", "Opera"), ("chrome/", "Chrome"),
             ("firefox/", "Firefox"), ("safari/", "Safari")]
    for token, name in order:
        if token in ua_l:
            if name == "Safari" and "chrome/" in ua_l:
                continue
            m = re.search(re.escape(token) + r"([\d.]+)", ua_l)
            browser = name
            version = m.group(1) if m else "-"
            break

    is_bot = any(k in ua_l for k in ["bot", "spider", "crawl", "curl", "wget",
                                      "python-requests", "scrapy", "httpclient"])
    is_mobile = any(k in ua_l for k in ["mobile", "android", "iphone"])

    return {
        "os": os_name,
        "browser": browser,
        "version": version,
        "is_bot": is_bot,
        "is_mobile": is_mobile,
        "device": "Mobil" if is_mobile else "Masaüstü",
    }


def find_subdomains(domain: str) -> list:
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil")
    domain = domain.strip().lower()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                          headers=UA, timeout=35)
    except requests.exceptions.Timeout:
        raise RuntimeError("crt.sh zaman aşımına uğradı (sunucu çok yoğun, birkaç dakika sonra tekrar dene).")
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(f"crt.sh'a bağlanılamadı: {e}")
    if r.status_code != 200:
        raise RuntimeError(f"crt.sh sorgusu başarısız (HTTP {r.status_code})")
    if not r.text.strip():
        return []
    try:
        data = r.json()
    except Exception:
        raise RuntimeError("crt.sh yanıtı parse edilemedi (sunucu yoğun olabilir, tekrar dene).")
    subs = set()
    for entry in data:
        for line in entry.get("name_value", "").split("\n"):
            line = line.strip().lower().lstrip("*.")
            if line.endswith(domain):
                subs.add(line)
    return sorted(subs)


def wayback_history(domain: str) -> dict:
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil")
    domain = domain.strip()
    url = (f"http://web.archive.org/cdx/search/cdx?url={domain}&matchType=domain"
           f"&output=json&fl=timestamp&collapse=timestamp:8&limit=5000")
    r = requests.get(url, timeout=20)
    rows = r.json() if r.text.strip() else []
    timestamps = [row[0] for row in rows[1:]] if len(rows) > 1 else []
    result = {"count": len(timestamps), "first": None, "last": None}
    if timestamps:
        timestamps.sort()
        result["first"] = datetime.strptime(timestamps[0][:8], "%Y%m%d").strftime("%Y-%m-%d")
        result["last"] = datetime.strptime(timestamps[-1][:8], "%Y%m%d").strftime("%Y-%m-%d")
        result["latest_snapshot_url"] = f"https://web.archive.org/web/{timestamps[-1]}/{domain}"
    return result


def breach_check(email: str) -> dict:
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil")
    email = email.strip()
    r = requests.get(f"https://api.xposedornot.com/v1/check-email/{email}", timeout=15)
    if r.status_code == 404:
        return {"exposed": False, "breaches": []}
    try:
        data = r.json()
    except Exception:
        raise RuntimeError("Servis yanıtı parse edilemedi (rate limit olabilir, sonra tekrar dene).")
    breaches = data.get("breaches", [])
    flat = []
    if breaches:
        for group in breaches:
            if isinstance(group, list):
                flat.extend(group)
            else:
                flat.append(group)
    return {"exposed": bool(flat), "breaches": flat}


def generate_leak_dorks(term: str) -> dict:
    term = term.strip()
    q = urllib.parse.quote(term)
    paste_sites = ["pastebin.com", "ghostbin.com", "controlc.com", "gist.github.com", "rentry.co"]
    site_filter = " OR ".join(f"site:{s}" for s in paste_sites)
    return {
        "google": f"https://www.google.com/search?q=%22{q}%22+({urllib.parse.quote(site_filter)})",
        "duckduckgo": f"https://duckduckgo.com/?q=%22{q}%22+({urllib.parse.quote(site_filter)})",
        "google_generic": f"https://www.google.com/search?q=%22{q}%22+leak+OR+breach+OR+dump",
        "github_code": f"https://github.com/search?q=%22{q}%22&type=code",
        "psbdmp": f"https://psbdmp.ws/api/search/{q}",
    }

def pastebin_scraper(keyword: str, progress_callback=None) -> list:
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil")

    def report(msg):
        if progress_callback:
            progress_callback(msg)

    keyword = keyword.strip()
    if not keyword:
        raise ValueError("Arama terimi boş olamaz.")

    report(f"'{keyword}' için psbdmp.ws API'si sorgulanıyor...")
    try:
        # psbdmp.ws is a public archive of pastebin pastes
        r = requests.get(f"https://psbdmp.ws/api/search/{keyword}", headers=UA, timeout=15)
        r.raise_for_status()
        data = r.json()
    except requests.exceptions.Timeout:
        raise RuntimeError("psbdmp.ws zaman aşımına uğradı, daha sonra tekrar deneyin.")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"psbdmp.ws API sorgusu başarısız: {e}")
    except json.JSONDecodeError:
        raise RuntimeError("psbdmp.ws API'den geçersiz yanıt alındı.")

    if not data or not data.get("data"):
        report("psbdmp.ws üzerinde sonuç bulunamadı.")
        return []

    paste_ids = [p["id"] for p in data["data"]][:10] # Limit to first 10 results
    report(f"{len(paste_ids)} potansiyel paste bulundu. İçerikler çekiliyor...")

    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(lambda p: requests.get(f"https://pastebin.com/raw/{p}", headers=UA, timeout=10), pid): pid for pid in paste_ids}
        for future in futures:
            pid = futures[future]
            try:
                r_paste = future.result()
                if r_paste.status_code == 200:
                    results.append({"id": pid, "url": f"https://pastebin.com/{pid}", "content": r_paste.text})
            except Exception:
                report(f"-> Hata: {pid} çekilemedi.")
    return results

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    25565: "Minecraft (Java)", 19132: "Minecraft (Bedrock/UDP)", 27015: "Source Engine",
}


def scan_common_ports(host: str, timeout=1.2) -> dict:
    host = host.strip()
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        raise RuntimeError(f"Host çözülemedi: {e}")

    def check(port_name):
        port, name = port_name
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return (port, name)
        except Exception:
            return None

    open_ports = []
    with ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as executor:
        for result in executor.map(check, COMMON_PORTS.items()):
            if result:
                open_ports.append(result)

    return {"ip": ip, "open_ports": sorted(open_ports)}


SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"unclosed quotation mark",
    r"warning: mysql_fetch_array\(\)",
    r"supplied argument is not a valid mysql result resource",
    r"pg_query\(\): query failed",
    r"syntax error at or near",
    r"microsoft ole db provider for odbc drivers",
    r"ora-[0-9][0-9][0-9][0-9]",
    r"sqlite exception",
    r"\[sql server\]",
]

SQL_PAYLOADS = ["'", "\"", "'\"", "--", "'--", "\"--", "' OR 1=1--", "\" OR 1=1--", "' OR '1'='1"]

def sql_injection_test(url: str, progress_callback=None) -> dict:
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil")

    def report(msg):
        if progress_callback:
            progress_callback(msg)

    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url

    parsed_url = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed_url.query)

    if not params:
        msg = "URL'de test edilecek parametre bulunamadı."
        report(msg)
        return {"vulnerable": False, "details": [], "message": msg}

    vulnerabilities = []
    report(f"URL'de {len(params)} parametre bulundu: {', '.join(params.keys())}")
    for param_name, param_values in params.items():
        original_value = param_values[0] if param_values else ""
        for payload in SQL_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = original_value + payload
            test_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse(
                (parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, test_query, parsed_url.fragment)
            )
            report(f"-> Test ediliyor: {param_name} parametresi, payload: {payload}")
            try:
                r = requests.get(test_url, headers=UA, timeout=10)
                for pattern in SQL_ERROR_PATTERNS:
                    match = re.search(pattern, r.text, re.IGNORECASE)
                    if match:
                        report(f"  [!] ZAFİYET BULUNDU! Hata mesajı: \"{match.group(0)}\"")
                        vulnerabilities.append({"param": param_name, "payload": payload, "url": test_url, "error_snippet": match.group(0)})
                        break 
            except requests.exceptions.RequestException as e:
                report(f"  [!] Bağlantı hatası: {type(e).__name__}")
                pass 
            if any(v['param'] == param_name for v in vulnerabilities):
                break
    return {"vulnerable": bool(vulnerabilities), "details": vulnerabilities, "message": None}


XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    '"<script>alert("XSS")</script>',
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "' onmouseover=alert(1) '",
    '"><img src=x onerror=alert(1)>',
]

def xss_test(url: str, progress_callback=None) -> dict:
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil")

    def report(msg):
        if progress_callback:
            progress_callback(msg)

    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url

    parsed_url = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed_url.query)

    if not params:
        msg = "URL'de test edilecek parametre bulunamadı."
        report(msg)
        return {"vulnerable": False, "details": [], "message": msg}

    vulnerabilities = []
    report(f"URL'de {len(params)} parametre bulundu: {', '.join(params.keys())}")
    for param_name, param_values in params.items():
        original_value = param_values[0] if param_values else ""
        for payload in XSS_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = original_value + payload
            test_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse(
                (parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, test_query, parsed_url.fragment)
            )
            report(f"-> Test ediliyor: {param_name} parametresi, payload: {payload}")
            try:
                r = requests.get(test_url, headers=UA, timeout=10)
                if payload in r.text:
                    report(f"  [!] ZAFİYET BULUNDU! Payload sayfada yansıtıldı.")
                    vulnerabilities.append({"param": param_name, "payload": payload, "url": test_url})
                    break
            except requests.exceptions.RequestException as e:
                report(f"  [!] Bağlantı hatası: {type(e).__name__}")
                pass 
    return {"vulnerable": bool(vulnerabilities), "details": vulnerabilities, "message": None}

TR_AREA_CODES = {
    "212": "İstanbul (Avrupa)", "216": "İstanbul (Anadolu)", "222": "Eskişehir",
    "224": "Bursa", "226": "Yalova", "228": "Bilecik", "232": "İzmir",
    "236": "Manisa", "242": "Antalya", "246": "Isparta", "248": "Burdur",
    "252": "Muğla", "256": "Aydın", "258": "Denizli", "262": "Kocaeli",
    "264": "Sakarya", "266": "Balıkesir", "272": "Afyonkarahisar", "274": "Kütahya",
    "276": "Uşak", "282": "Tekirdağ", "284": "Edirne", "286": "Çanakkale",
    "288": "Kırklareli", "312": "Ankara", "318": "Kırıkkale", "322": "Adana",
    "324": "Mersin", "326": "Hatay", "328": "Osmaniye", "332": "Konya",
    "338": "Karaman", "342": "Gaziantep", "344": "Kahramanmaraş", "346": "Sivas",
    "348": "Kilis", "352": "Kayseri", "354": "Yozgat", "356": "Tokat",
    "358": "Amasya", "362": "Samsun", "364": "Çorum", "366": "Kastamonu",
    "368": "Sinop", "370": "Karabük", "372": "Zonguldak", "374": "Bolu",
    "376": "Çankırı", "378": "Bartın", "380": "Düzce", "382": "Aksaray",
    "384": "Nevşehir", "386": "Kırşehir", "388": "Niğde", "412": "Diyarbakır",
    "414": "Şanlıurfa", "416": "Adıyaman", "422": "Malatya", "424": "Elazığ",
    "426": "Bingöl", "428": "Tunceli", "432": "Van", "434": "Bitlis",
    "436": "Muş", "438": "Hakkari", "442": "Erzurum", "446": "Erzincan",
    "452": "Ordu", "454": "Giresun", "456": "Gümüşhane", "458": "Bayburt",
    "462": "Trabzon", "464": "Rize", "466": "Artvin", "472": "Ağrı",
    "474": "Kars", "476": "Iğdır", "478": "Ardahan", "482": "Mardin",
    "484": "Siirt", "486": "Şırnak", "488": "Batman",
    "444": "Ulusal Numara (Konumdan Bağımsız)",
    "850": "Konumdan Bağımsız Numara (VoIP)",
}


def guess_area_from_number(national_number: str, country_code: int) -> str:
    """Sadece Türkiye (+90) için: alan koduna göre şehir tahmini (public numaralandırma planı)."""
    if country_code != 90:
        return "-"
    s = str(national_number)
    if s.startswith("850"):
        return "Konumdan Bağımsız Numara (VoIP)"
    elif s.startswith("5"):
        return "Mobil hat (GSM operatörü - şehir bazlı değil)"
    for length in (3,):
        prefix = s[:length]
        if prefix in TR_AREA_CODES:
            return TR_AREA_CODES[prefix]
    return "Alan kodu tanınamadı"


def phone_info(number: str) -> dict:
    if not PHONENUMBERS_OK:
        raise RuntimeError("phonenumbers kütüphanesi kurulu değil (pip install phonenumbers)")
    parsed = phonenumbers.parse(number.strip(), None)
    geocoder_region = pn_geocoder.description_for_number(parsed, "tr") or "-"
    tr_area_guess = guess_area_from_number(parsed.national_number, parsed.country_code)
    return {
        "valid": phonenumbers.is_valid_number(parsed),
        "country_code": parsed.country_code,
        "national_number": parsed.national_number,
        "region": geocoder_region,
        "area_guess": tr_area_guess,
        "carrier": pn_carrier.name_for_number(parsed, "tr") or "-",
        "type": str(phonenumbers.number_type(parsed)),
        "line_type": "Mobil (GSM)" if str(parsed.national_number).startswith("5") and parsed.country_code == 90
                     else ("Sabit Hat" if parsed.country_code == 90 else "-"),
    }

TR_BANK_CODES = {
    "00010": "T.C. Ziraat Bankası A.Ş.",
    "00012": "Türkiye Halk Bankası A.Ş.",
    "00015": "Türkiye Vakıflar Bankası T.A.O.",
    "00032": "Türk Ekonomi Bankası A.Ş. (TEB)",
    "00034": "Aktif Yatırım Bankası A.Ş.",
    "00046": "Akbank T.A.Ş.",
    "00059": "Şekerbank T.A.Ş.",
    "00062": "Türkiye Garanti Bankası A.Ş.",
    "00064": "Türkiye İş Bankası A.Ş.",
    "00067": "Yapı ve Kredi Bankası A.Ş.",
    "00096": "Anadolubank A.Ş.",
    "00099": "ING Bank A.Ş.",
    "00100": "Adabank A.Ş.",
    "00103": "Fibabanka A.Ş.",
    "00109": "Burgan Bank A.Ş.",
    "00111": "QNB Finansbank A.Ş.",
    "00123": "HSBC Bank A.Ş.",
    "00124": "Alternatifbank A.Ş.",
    "00125": "Denizbank A.Ş.",
    "00134": "ICBC Turkey Bank A.Ş.",
    "00135": "Odeabank A.Ş.",
    "00203": "Albaraka Türk Katılım Bankası A.Ş.",
    "00205": "Kuveyt Türk Katılım Bankası A.Ş.",
    "00206": "Türkiye Finans Katılım Bankası A.Ş.",
    "00208": "Vakıf Katılım Bankası A.Ş.",
    "00209": "Ziraat Katılım Bankası A.Ş.",
    "00210": "Emlak Katılım Bankası A.Ş.",
    "10001": "Paycell (Turkcell Ödeme ve E-Para Hizmetleri A.Ş.)",
    "10002": "Papara Elektronik Para A.Ş.",
    "10003": "İninal Ödeme ve Elektronik Para Hizmetleri A.Ş.",
    "10010": "Pep Para Elektronik Para ve Ödeme Hizmetleri A.Ş.",
    "10011": "Ozan Elektronik Para A.Ş.",
    "10013": "Sipay Elektronik Para ve Ödeme Hizmetleri A.Ş.",
    "10016": "Tosla (Akbank)",
    "10017": "PayFix",
    "10020": "Param",
}

def analyze_iban(iban: str) -> dict:
    iban = iban.strip().replace(" ", "").upper()
    result = {
        "iban": iban, "is_valid": False, "country_code": None, "bank_code": None,
        "bank_name": "Bilinmiyor", "branch_code": None, "account_number": None, "error": None
    }

    if not re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}", iban):
        result["error"] = "Geçersiz IBAN formatı (örn: TR00...)."
        return result

    # MOD-97 Checksum validation
    rearranged_iban = iban[4:] + iban[:4]
    numeric_iban = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged_iban)

    try:
        is_valid = int(numeric_iban) % 97 == 1
    except ValueError:
        is_valid = False

    result["is_valid"] = is_valid
    if not is_valid:
        result["error"] = "IBAN checksum (MOD-97) doğrulaması başarısız."
        return result

    result["country_code"] = iban[:2]

    if result["country_code"] == "TR" and len(iban) == 26:
        result["bank_code"] = iban[4:9]
        result["branch_code"] = iban[10:14]
        result["account_number"] = iban[10:]
        result["bank_name"] = TR_BANK_CODES.get(result["bank_code"], "Banka kodu tanınamadı")
    else:
        result["bank_name"] = "Sadece Türkiye IBAN'ları için banka bilgisi gösterilir."

    return result

# ================= GUI =================

class GhostOSINT(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"GHOST OSINT FRAMEWORK {CURRENT_VERSION} (Alpha) — by TarikPro43391")

        self.current_theme_name = "Ghost Dark"
        self.theme = THEMES[self.current_theme_name]
        self.tracked_widgets = []
        self.nb = None
        self.report_is_dirty = False

        try:
            icon_data = base64.b64decode(ICON_BASE64)
            self.icon = tk.PhotoImage(data=icon_data)
            self.iconphoto(True, self.icon)
        except Exception:
            pass # İkon yüklenemezse sorun değil, varsayılan ikon kullanılır.

        self.geometry("1020x720")
        self.configure(bg=self.theme["BG"])
        self.minsize(920, 600)

        self._build_menu()
        self.output_widgets = {}

        self._build_style()
        self._build_header()
        self._build_tabs()
        self._build_statusbar()
        self._check_for_updates()
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    # ---------- MENU ----------
    def _build_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ayarlar", menu=settings_menu)

        theme_menu = tk.Menu(settings_menu, tearoff=0)
        settings_menu.add_cascade(label="Tema", menu=theme_menu)

        for theme_name in THEMES:
            theme_menu.add_command(
                label=theme_name,
                command=lambda t=theme_name: self._apply_theme(t)
            )
        
        settings_menu.add_separator()
        settings_menu.add_command(label="Hakkında", command=self._show_about_window)
        settings_menu.add_command(label="GitHub'da Görüntüle", command=lambda: webbrowser.open("https://github.com/TarikPro43391/GHOST-OSINT-FRAMEWORK"))

    # ---------- STYLE ----------
    def _build_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background=self.theme["BG"], borderwidth=0)
        style.configure("TNotebook.Tab", background=self.theme["PANEL"], foreground=self.theme["FG_DIM"],
                        padding=(10, 5), font=FONT, borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", self.theme["PANEL2"])],
                  foreground=[("selected", self.theme["RED"])],
                  font=[("selected", FONT_B)])
        style.configure("TFrame", background=self.theme["BG"])
        style.configure("TLabel", background=self.theme["BG"], foreground=self.theme["FG"], font=FONT)
        style.configure("TButton", background=self.theme["RED"], foreground="#ffffff",
                        font=FONT_B, borderwidth=0, padding=8)
        style.map("TButton", background=[("active", "#ff5c52")])
        style.configure("Blue.TButton", background=self.theme["BLUE"], foreground="#ffffff",
                        font=FONT_B, borderwidth=0, padding=8)
        style.map("Blue.TButton", background=[("active", "#5b9bff")])
        style.configure("TEntry", fieldbackground=self.theme["PANEL2"], foreground=self.theme["FG"],
                        insertcolor=self.theme["FG"], borderwidth=1, relief="flat", bordercolor=self.theme["BORDER"])
        style.map("TEntry", bordercolor=[("focus", self.theme["BLUE"])])

        style.configure("Clear.TButton", background=self.theme["PANEL2"], foreground=self.theme["FG_DIM"],
                        font=("Segoe UI", 8), borderwidth=1, relief="flat", padding=(5, 2), bordercolor=self.theme["BORDER"])
        style.map("Clear.TButton",
                  background=[("active", self.theme["BORDER"])],
                  foreground=[("active", self.theme["FG"])])

    # ---------- HEADER ----------
    def _build_header(self):
        header = tk.Frame(self, bg=self.theme["BG"])
        header.pack(fill="x", padx=20, pady=(16, 8))
        self.tracked_widgets.append((header, {"bg": "BG"}))
        l1 = tk.Label(header, text="GHOST", font=FONT_TITLE, bg=self.theme["BG"], fg=self.theme["RED"]); l1.pack(side="left"); self.tracked_widgets.append((l1, {"bg": "BG", "fg": "RED"}))
        l2 = tk.Label(header, text=" OSINT FRAMEWORK", font=FONT_TITLE, bg=self.theme["BG"], fg=self.theme["FG"]); l2.pack(side="left"); self.tracked_widgets.append((l2, {"bg": "BG", "fg": "FG"}))
        l3 = tk.Label(header, text=f"  {CURRENT_VERSION} (Alpha)", font=("Segoe UI", 10), bg=self.theme["BG"], fg=self.theme["FG_DIM"]); l3.pack(side="left", padx=(6, 0)); self.tracked_widgets.append((l3, {"bg": "BG", "fg": "FG_DIM"}))
        l4 = tk.Label(header, text="by TarikPro43391", font=FONT_B, bg=self.theme["BG"], fg=self.theme["BLUE"]); l4.pack(side="right"); self.tracked_widgets.append((l4, {"bg": "BG", "fg": "BLUE"}))

    # ---------- STATUSBAR ----------
    def _build_statusbar(self):
        bar = tk.Frame(self, bg=self.theme["PANEL"], height=28)
        bar.pack(fill="x", side="bottom")
        self.tracked_widgets.append((bar, {"bg": "PANEL"}))
        self.status_var = tk.StringVar(value="Hazır.")
        status_label = tk.Label(bar, textvariable=self.status_var, bg=self.theme["PANEL"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9), anchor="w")
        status_label.pack(side="left", padx=12, pady=4)
        self.tracked_widgets.append((status_label, {"bg": "PANEL", "fg": "FG_DIM"}))

        right_frame = tk.Frame(bar, bg=self.theme["PANEL"])
        right_frame.pack(side="right", padx=10, pady=2)
        self.tracked_widgets.append((right_frame, {"bg": "PANEL"}))

        ttk.Button(right_frame, text="Raporu Kaydet", command=self._export_report).pack(side="right")

        ttk.Button(right_frame, text="Tümünü Temizle", command=self._clear_all_outputs, style="Blue.TButton").pack(side="right", padx=(0, 6))

        sep_label = tk.Label(right_frame, text="|", bg=self.theme["PANEL"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9))
        sep_label.pack(side="right", padx=8)
        self.tracked_widgets.append((sep_label, {"bg": "PANEL", "fg": "FG_DIM"}))

        deps = []
        deps.append("requests OK" if REQUESTS_OK else "requests EKSİK")
        deps.append("dnspython OK" if DNSPYTHON_OK else "dnspython EKSİK")
        deps.append("phonenumbers OK" if PHONENUMBERS_OK else "phonenumbers EKSİK")
        deps_label = tk.Label(right_frame, text=" | ".join(deps), bg=self.theme["PANEL"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9), anchor="e")
        deps_label.pack(side="right")
        self.tracked_widgets.append((deps_label, {"bg": "PANEL", "fg": "FG_DIM"}))

    def set_status(self, text):
        self.status_var.set(text)

    # ---------- TABS ----------
    def _build_tabs(self):
        nb = ttk.Notebook(self)
        self.nb = nb
        nb.pack(fill="both", expand=True, padx=16, pady=8)

        tab_defs = [
            ("discord", "DISCORD ID"), ("ip", "IP LOOKUP"), ("domain", "DOMAIN/DNS"),
            ("username", "USERNAME"), ("email", "EMAIL"), ("hash", "HASH"),
            ("phone", "PHONE"), ("url", "URL/QR"), ("exif", "EXIF"),
            ("mac", "MAC VENDOR"), ("ua", "USER-AGENT"), ("subdomain", "SUBDOMAIN"),
            ("wayback", "WAYBACK"), ("breach", "BREACH"), ("portscan", "PORT SCAN"),
            ("leak", "LEAK SEARCH"), ("pastebin", "PASTEBIN"),
            ("invite", "INVITE"), ("ssl", "SSL"),
            ("iban", "IBAN"), ("xss", "XSS"), ("sql", "SQLi")
        ]

        for name, text in tab_defs:
            tab_frame = tk.Frame(nb, bg=self.theme["BG"])
            self.tracked_widgets.append((tab_frame, {"bg": "BG"}))
            setattr(self, f"tab_{name}", tab_frame)
            nb.add(tab_frame, text=text)

        self._build_discord_tab()
        self._build_ip_tab()
        self._build_domain_tab()
        self._build_username_tab()
        self._build_email_tab()
        self._build_hash_tab()
        self._build_phone_tab()
        self._build_url_tab()
        self._build_exif_tab()
        self._build_mac_tab()
        self._build_ua_tab()
        self._build_subdomain_tab()
        self._build_wayback_tab()
        self._build_breach_tab()
        self._build_portscan_tab()
        self._build_leak_tab()
        self._build_pastebin_tab()
        self._build_invite_tab()
        self._build_ssl_tab()
        self._build_iban_tab()
        self._build_xss_tab()
        self._build_sql_tab()

    # ---------- ORTAK YARDIMCI WIDGET ----------
    def _labeled_entry(self, parent, label, width=40, show=None):
        row = tk.Frame(parent, bg=self.theme["BG"])
        row.pack(fill="x", pady=4)
        self.tracked_widgets.append((row, {"bg": "BG"}))
        l = tk.Label(row, text=label, bg=self.theme["BG"], fg=self.theme["FG"], font=FONT, width=16, anchor="w")
        l.pack(side="left")
        self.tracked_widgets.append((l, {"bg": "BG", "fg": "FG"}))
        entry = ttk.Entry(row, width=width, font=FONT_MONO, show=show)

        def clear_entry():
            entry.delete(0, "end")

        clear_button = ttk.Button(row, text="Temizle", command=clear_entry, style="Clear.TButton")
        clear_button.pack(side="right", padx=(0, 6))
        entry.pack(side="left", padx=6, fill="x", expand=True)
        return entry

    def _output_box(self, parent, height=18, tab_name=""):
        wrapper = tk.Frame(parent, bg=self.theme["BG"])
        wrapper.pack(fill="both", expand=True, pady=(10, 0))
        self.tracked_widgets.append((wrapper, {"bg": "BG"}))

        bar = tk.Frame(wrapper, bg=self.theme["BG"])
        bar.pack(fill="x")
        self.tracked_widgets.append((bar, {"bg": "BG"}))
        l = tk.Label(bar, text="SONUÇ", bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9, "bold")); l.pack(side="left"); self.tracked_widgets.append((l, {"bg": "BG", "fg": "FG_DIM"}))

        frame = tk.Frame(wrapper, bg=self.theme["BORDER"])
        frame.pack(fill="both", expand=True, pady=(4, 0))
        self.tracked_widgets.append((frame, {"bg": "BORDER"}))
        text = tk.Text(frame, height=height, bg=self.theme["PANEL"], fg=self.theme["FG"], insertbackground=self.theme["FG"],
                        font=FONT_MONO, relief="flat", wrap="word", padx=10, pady=10)
        text.pack(fill="both", expand=True, padx=1, pady=1)
        text.configure(state="disabled")

        if tab_name:
            self.output_widgets[tab_name] = text

        def copy_output():
            content = text.get("1.0", "end-1c")
            if not content.strip():
                return
            self.clipboard_clear()
            self.clipboard_append(content)
            self.set_status("Sonuç panoya kopyalandı.")

        ttk.Button(bar, text="KOPYALA", style="Blue.TButton", command=copy_output).pack(side="right")
        return text

    def _write(self, box, content):
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("end", content)
        box.configure(state="disabled")
        if content.strip():
            self.report_is_dirty = True

    def _append_to_output(self, box, content):
        box.configure(state="normal")
        box.insert("end", content + "\n")
        box.see("end")
        box.configure(state="disabled")
        if content.strip():
            self.report_is_dirty = True

    def _run_async(self, fn, on_done):
        def worker():
            try:
                result = fn()
                self.after(0, lambda: on_done(result, None))
            except Exception as e:
                self.after(0, lambda: on_done(None, e))
        threading.Thread(target=worker, daemon=True).start()

    def _check_for_updates(self):
        """Güncelleme kontrolünü arka planda çalıştırır."""
        def on_done(result, err):
            if err or not result:
                return  # Sessizce başarısız ol

            new_version = result.get("new_version")
            release_url = result.get("release_url")

            if not new_version or not release_url:
                return

            message = (
                f"Yeni bir sürüm mevcut: {new_version}\n"
                f"Mevcut sürümünüz: {CURRENT_VERSION}\n\n"
                "Güncelleme notlarını görmek ve indirmek için sürüm sayfasına gitmek ister misiniz?"
            )
            if messagebox.askyesno("Güncelleme Mevcut", message):
                try:
                    webbrowser.open(release_url)
                except Exception as e:
                    messagebox.showwarning("Hata", f"Tarayıcı açılamadı: {e}")

        self._run_async(check_for_updates, on_done)

    def _apply_theme(self, theme_name):
        if theme_name not in THEMES or theme_name == self.current_theme_name:
            return

        self.current_theme_name = theme_name
        self.theme = THEMES[theme_name]

        # 1. Update main window
        self.configure(bg=self.theme["BG"])

        # 2. Update all ttk styles
        self._build_style()

        # 3. Update all tracked tk widgets
        for widget, color_map in self.tracked_widgets:
            try:
                if not widget.winfo_exists():
                    continue
                config_opts = {}
                for prop, color_key in color_map.items():
                    config_opts[prop] = self.theme[color_key]
                widget.configure(**config_opts)
            except tk.TclError:
                # Widget might have been destroyed
                pass

        self.set_status(f"Tema '{theme_name}' olarak değiştirildi.")

    def _export_report(self):
        report_lines = []
        report_lines.append("================================================")
        report_lines.append(" GHOST OSINT FRAMEWORK - Toplu Rapor")
        report_lines.append(f" Rapor Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("================================================\n")

        has_content = False
        # Raporun daha düzenli olması için sekmelerin sırasına göre çıktıları al
        tab_order = [
            "DISCORD ID", "IP LOOKUP", "DOMAIN / DNS", "USERNAME", "EMAIL", "HASH", "PHONE",
            "URL / QR", "EXIF", "MAC VENDOR", "USER-AGENT", "SUBDOMAIN", "WAYBACK",
            "BREACH CHECK", "PORT SCAN", "LEAK SEARCH", "PASTEBIN SCRAPER", "DISCORD INVITE", "SSL SERTİFİKA",
            "IBAN ANALYZER", "XSS TEST", "SQLi TEST"
        ]
        for tab_name in tab_order:
            if tab_name in self.output_widgets:
                widget = self.output_widgets[tab_name]
                content = widget.get("1.0", "end-1c").strip()
                if content:
                    has_content = True
                    report_lines.append(f"########## {tab_name.upper()} ##########\n")
                    report_lines.append(content)
                    report_lines.append("\n\n")

        if not has_content:
            messagebox.showinfo("Bilgi", "Rapor oluşturulacak herhangi bir çıktı bulunamadı.")
            return

        report_content = "".join(report_lines)

        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Raporu Kaydet",
                initialfile=f"ghost_osint_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            if not file_path:
                return
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(report_content)
            self.set_status(f"Rapor başarıyla kaydedildi.")
            messagebox.showinfo("Başarılı", f"Rapor başarıyla kaydedildi:\n{file_path}")
            self.report_is_dirty = False
        except Exception as e:
            messagebox.showerror("Hata", f"Rapor kaydedilirken bir hata oluştu:\n{e}")

    def _clear_all_outputs(self):
        if not self.report_is_dirty:
            self.set_status("Temizlenecek bir çıktı yok.")
            return

        if messagebox.askyesno("Tüm Çıktıları Temizle", "Tüm sekmelerdeki sonuçlar kalıcı olarak silinecek. Bu işlem geri alınamaz.\n\nDevam etmek istiyor musunuz?"):
            for box in self.output_widgets.values():
                box.configure(state="normal")
                box.delete("1.0", "end")
                box.configure(state="disabled")
            self.report_is_dirty = False
            self.set_status("Tüm çıktılar başarıyla temizlendi.")

    def _on_closing(self):
        if self.report_is_dirty:
            if messagebox.askyesno("Çıkışı Onayla", "Kaydedilmemiş rapor içeriği var. Yine de çıkmak istediğinize emin misiniz?"):
                self.destroy()
        else:
            self.destroy()

    def _show_about_window(self):
        about_win = tk.Toplevel(self)
        about_win.title("Hakkında")
        about_win.configure(bg=self.theme["BG"], padx=30, pady=20)
        about_win.resizable(False, False)

        # Center window
        self.update_idletasks()
        main_x = self.winfo_x()
        main_y = self.winfo_y()
        main_w = self.winfo_width()
        main_h = self.winfo_height()
        about_win.update_idletasks()
        about_w = about_win.winfo_width()
        about_h = about_win.winfo_height()
        x = main_x + (main_w // 2) - (about_w // 2)
        y = main_y + (main_h // 2) - (about_h // 2)
        about_win.geometry(f"+{x}+{y}")

        tk.Label(about_win, text="GHOST OSINT FRAMEWORK", font=FONT_TITLE, bg=self.theme["BG"], fg=self.theme["RED"]).pack(pady=(0, 5))
        tk.Label(about_win, text=f"Sürüm {CURRENT_VERSION} (Alpha)", font=FONT, bg=self.theme["BG"], fg=self.theme["FG_DIM"]).pack()
        tk.Label(about_win, text="TarikPro43391 tarafından geliştirilmiştir.", font=FONT_B, bg=self.theme["BG"], fg=self.theme["FG"]).pack(pady=(10, 20))

        desc = "Bu araç, public kaynakları kullanarak OSINT (Açık Kaynak İstihbaratı)\naraştırmaları yapmak için tasarlanmıştır."
        tk.Label(about_win, text=desc, font=FONT, bg=self.theme["BG"], fg=self.theme["FG"], justify="center").pack(pady=(0, 15))

        ttk.Button(about_win, text="Kapat", command=about_win.destroy, style="Blue.TButton").pack(pady=(20, 0))

        about_win.transient(self)
        about_win.grab_set()
        self.wait_window(about_win)

    # ================= DISCORD TAB =================
    def _build_discord_tab(self):
        t = self.tab_discord
        self.discord_id_entry = self._labeled_entry(t, "Discord ID:")
        btn_row = tk.Frame(t, bg=self.theme["BG"])
        btn_row.pack(fill="x", pady=6)
        self.tracked_widgets.append((btn_row, {"bg": "BG"}))
        ttk.Button(btn_row, text="SNOWFLAKE DECODE", command=self._on_discord_decode).pack(side="left")

        l = tk.Label(t, text="─── Opsiyonel: Kendi Bot Token'ın ile public profil bilgisi çek ───", bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9)); l.pack(fill="x", pady=(14, 2)); self.tracked_widgets.append((l, {"bg": "BG", "fg": "FG_DIM"}))
        self.discord_token_entry = self._labeled_entry(t, "Bot Token:", show="*")
        ttk.Button(btn_row, text="PUBLIC PROFİL ÇEK (API)", style="Blue.TButton",
                   command=self._on_discord_api).pack(side="left", padx=8)

        self.discord_output = self._output_box(t, tab_name="DISCORD ID")

    def _on_discord_decode(self):
        raw = self.discord_id_entry.get().strip()
        if not raw.isdigit():
            messagebox.showerror("Hata", "Geçerli bir Discord ID (sayısal) girin.")
            return
        try:
            info = decode_snowflake(raw)
            out = (
                f"[SNOWFLAKE DECODE]\n"
                f"ID              : {info['id']}\n"
                f"Oluşturulma     : {info['created_utc']}\n"
                f"Hesap Yaşı      : {info['age']}\n"
                f"Worker ID       : {info['worker_id']}\n"
                f"Process ID      : {info['process_id']}\n"
                f"Increment       : {info['increment']}\n"
                f"Varsayılan Avatar: {info['default_avatar_url']}\n"
            )
            self._write(self.discord_output, out)
            self.set_status("Snowflake decode tamamlandı.")
        except Exception as e:
            messagebox.showerror("Hata", str(e))

    def _on_discord_api(self):
        raw_id = self.discord_id_entry.get().strip()
        token = self.discord_token_entry.get().strip()
        if not raw_id.isdigit():
            messagebox.showerror("Hata", "Geçerli bir Discord ID girin.")
            return
        if not token:
            messagebox.showerror("Hata", "Bot token girmelisin (opsiyonel özellik).")
            return
        self.set_status("Discord API'den public profil çekiliyor...")

        def task():
            return fetch_discord_public_profile(raw_id, token)

        def done(result, err):
            if err:
                messagebox.showerror("Hata", str(err))
                self.set_status("Hata oluştu.")
                return
            out = (
                f"[DISCORD PUBLIC PROFİL]\n"
                f"Username        : {result['username']}\n"
                f"Global Name     : {result['global_name']}\n"
                f"Discriminator   : {result['discriminator']}\n"
                f"Bot Hesabı mı?  : {'Evet' if result['bot'] else 'Hayır'}\n"
                f"Avatar URL      : {result['avatar_url']}\n"
                f"Banner URL      : {result['banner_url']}\n"
                f"Accent Color    : {result['accent_color']}\n"
                f"Rozetler        : {', '.join(result['badges'])}\n"
            )
            self._write(self.discord_output, out)
            self.set_status("Discord public profil alındı.")

        self._run_async(task, done)

    # ================= IP TAB =================
    def _build_ip_tab(self):
        t = self.tab_ip
        self.ip_entry = self._labeled_entry(t, "IP Adresi:")
        ttk.Button(t, text="IP SORGULA", command=self._on_ip_lookup).pack(anchor="w", pady=6)
        self.ip_output = self._output_box(t, tab_name="IP LOOKUP")

    def _on_ip_lookup(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Hata", "IP adresi girin.")
            return
        self.set_status("IP sorgulanıyor...")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", str(err))
                self.set_status("Hata oluştu.")
                return
            out = (
                f"[IP LOOKUP: {result.get('query')}]\n"
                f"Ülke        : {result.get('country')}\n"
                f"Bölge       : {result.get('regionName')}\n"
                f"Şehir       : {result.get('city')}\n"
                f"Posta Kodu  : {result.get('zip')}\n"
                f"Koordinat   : {result.get('lat')}, {result.get('lon')}\n"
                f"Zaman Dilimi: {result.get('timezone')}\n"
                f"ISP         : {result.get('isp')}\n"
                f"Org         : {result.get('org')}\n"
                f"ASN         : {result.get('as')}\n"
                f"Reverse DNS : {result.get('reverse')}\n"
                f"\nHarita: https://www.google.com/maps?q={result.get('lat')},{result.get('lon')}\n"
            )
            self._write(self.ip_output, out)
            self.set_status("IP lookup tamamlandı.")

        self._run_async(lambda: ip_lookup(ip), done)

    # ================= DOMAIN TAB =================
    def _build_domain_tab(self):
        t = self.tab_domain
        self.domain_entry = self._labeled_entry(t, "Domain:")
        row = tk.Frame(t, bg=self.theme["BG"])
        row.pack(fill="x", pady=6)
        self.tracked_widgets.append((row, {"bg": "BG"}))
        ttk.Button(row, text="DNS SORGULA", command=self._on_dns).pack(side="left")
        ttk.Button(row, text="WHOIS SORGULA", style="Blue.TButton", command=self._on_whois).pack(side="left", padx=8)
        self.domain_output = self._output_box(t, tab_name="DOMAIN / DNS")

    def _on_dns(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Hata", "Domain girin.")
            return
        self.set_status("DNS sorgulanıyor...")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", str(err))
                return
            a = "\n  ".join(result["A"]) or "Bulunamadı"
            mx = "\n  ".join(result["MX"]) or ("Bulunamadı" if DNSPYTHON_OK else "(dnspython kurulu değil)")
            out = f"[DNS: {domain}]\nA Kayıtları:\n  {a}\n\nMX Kayıtları:\n  {mx}\n"
            if result["raw_error"]:
                out += f"\nHata: {result['raw_error']}\n"
            self._write(self.domain_output, out)
            self.set_status("DNS sorgu tamamlandı.")

        self._run_async(lambda: dns_lookup(domain), done)

    def _on_whois(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Hata", "Domain girin.")
            return
        self.set_status("WHOIS sorgulanıyor (birkaç saniye sürebilir)...")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", str(err))
                return
            self._write(self.domain_output, result)
            self.set_status("WHOIS sorgu tamamlandı.")

        self._run_async(lambda: whois_lookup(domain), done)

    # ================= USERNAME TAB =================
    def _build_username_tab(self):
        t = self.tab_username
        self.username_entry = self._labeled_entry(t, "Kullanıcı Adı:")
        ttk.Button(t, text="PLATFORMLARDA ARA", command=self._on_username_search).pack(anchor="w", pady=6)
        l = tk.Label(t, text="Not: JS ile render edilen bazı sitelerde sonuç tahminidir (kesin değildir).", bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9)); l.pack(anchor="w"); self.tracked_widgets.append((l, {"bg": "BG", "fg": "FG_DIM"}))
        self.username_output = self._output_box(t, tab_name="USERNAME")

    def _on_username_search(self):
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Hata", "Kullanıcı adı girin.")
            return
        if not REQUESTS_OK:
            messagebox.showerror("Hata", "requests kütüphanesi kurulu değil.")
            return
        self.set_status(f"'{username}' {len(USERNAME_PLATFORMS)} platformda aranıyor...")
        self._write(self.username_output, "Aranıyor, lütfen bekleyin (paralel taranıyor)...\n")

        def task():
            with ThreadPoolExecutor(max_workers=len(USERNAME_PLATFORMS)) as executor:
                futures = [executor.submit(check_username_on_platform, name, tmpl, mode, username)
                           for name, tmpl, mode in USERNAME_PLATFORMS]
                results = [f.result() for f in futures]
            # Orijinal platform sırasına göre sırala
            order = {name: i for i, (name, _, _) in enumerate(USERNAME_PLATFORMS)}
            results.sort(key=lambda r: order.get(r[0], 999))
            return results

        def done(results, err):
            if err:
                messagebox.showerror("Hata", str(err))
                return
            lines = [f"[USERNAME SEARCH: {username}]\n"]
            for name, status, url in results:
                mark = "✓" if status == "BULUNDU" else ("✗" if status == "YOK" else "?")
                lines.append(f"[{mark}] {name:<12} {status:<10} {url}")
            self._write(self.username_output, "\n".join(lines))
            self.set_status("Username arama tamamlandı.")

        self._run_async(task, done)

    # ================= EMAIL TAB =================
    def _build_email_tab(self):
        t = self.tab_email
        self.email_entry = self._labeled_entry(t, "Email Adresi:")
        ttk.Button(t, text="ANALİZ ET", command=self._on_email_analyze).pack(anchor="w", pady=6)
        self.email_output = self._output_box(t, tab_name="EMAIL")

    def _on_email_analyze(self):
        email = self.email_entry.get().strip()
        if not email:
            messagebox.showerror("Hata", "Email girin.")
            return
        self.set_status("Email analiz ediliyor...")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", str(err))
                return
            mx = "\n  ".join(result["mx"]) or ("Bulunamadı" if DNSPYTHON_OK else "(dnspython kurulu değil)")
            a = "\n  ".join(result["a_record"]) or "Bulunamadı"
            out = (
                f"[EMAIL: {email}]\n"
                f"Format Geçerli mi?: {'Evet' if result['valid_format'] else 'Hayır'}\n"
                f"Domain            : {result['domain']}\n"
                f"Domain A Kaydı    :\n  {a}\n\n"
                f"MX Kayıtları      :\n  {mx}\n"
            )
            self._write(self.email_output, out)
            self.set_status("Email analiz tamamlandı.")

        self._run_async(lambda: analyze_email(email), done)

    # ================= HASH TAB =================
    def _build_hash_tab(self):
        t = self.tab_hash
        self.hash_entry = self._labeled_entry(t, "Hash Değeri:", width=60)
        ttk.Button(t, text="HASH TÜRÜNÜ TAHMİN ET", command=self._on_hash_identify).pack(anchor="w", pady=6)
        self.hash_output = self._output_box(t, tab_name="HASH")

    def _on_hash_identify(self):
        h = self.hash_entry.get().strip()
        if not h:
            messagebox.showerror("Hata", "Hash değeri girin.")
            return
        guesses = identify_hash(h)
        out = f"[HASH IDENTIFY]\nUzunluk: {len(h)} karakter\nOlası Tür(ler):\n  " + "\n  ".join(guesses)
        self._write(self.hash_output, out)
        self.set_status("Hash analiz tamamlandı.")

    # ================= PHONE TAB =================
    def _build_phone_tab(self):
        t = self.tab_phone
        self.phone_entry = self._labeled_entry(t, "Telefon (+90...):")
        ttk.Button(t, text="SORGULA", command=self._on_phone_lookup).pack(anchor="w", pady=6)
        if not PHONENUMBERS_OK:
            l = tk.Label(t, text="'phonenumbers' kütüphanesi kurulu değil -> pip install phonenumbers", bg=self.theme["BG"], fg=self.theme["RED"], font=("Segoe UI", 9)); l.pack(anchor="w"); self.tracked_widgets.append((l, {"bg": "BG", "fg": "RED"}))
        self.phone_output = self._output_box(t, tab_name="PHONE")

    def _on_phone_lookup(self):
        number = self.phone_entry.get().strip()
        if not number:
            messagebox.showerror("Hata", "Telefon numarası girin (örn: +905551234567).")
            return
        try:
            result = phone_info(number)
            out = (
                f"[PHONE: {number}]\n"
                f"Geçerli mi?         : {'Evet' if result['valid'] else 'Hayır'}\n"
                f"Ülke Kodu           : +{result['country_code']}\n"
                f"Ulusal Numara       : {result['national_number']}\n"
                f"Ülke/Genel Bölge    : {result['region']}\n"
                f"Hat Tipi            : {result['line_type']}\n"
                f"Alan Kodu Tahmini   : {result['area_guess']}\n"
                f"Operatör            : {result['carrier']}\n"
                f"Numara Tipi (libphonenumber): {result['type']}\n"
                f"\nNot: Alan kodu tahmini sadece Türkiye sabit hatları için TİK/BTK\n"
                f"numaralandırma planına dayanır (statik/public veri). Mobil (05xx)\n"
                f"numaralar şehre bağlı değildir, operatör bilgisi verilir; gerçek\n"
                f"konum/kişi bilgisi vermez.\n"
            )
            self._write(self.phone_output, out)
            self.set_status("Telefon sorgusu tamamlandı.")
        except Exception as e:
            messagebox.showerror("Hata", str(e))


    # ================= URL / QR TAB =================
    def _build_url_tab(self):
        t = self.tab_url
        self.url_entry = self._labeled_entry(t, "URL:", width=60)
        ttk.Button(t, text="URL ANALİZ ET", command=self._on_url_analyze).pack(anchor="w", pady=6)

        l = tk.Label(t, text="─── QR Kod Decode (resimden) ───", bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9)); l.pack(anchor="w", pady=(10, 4)); self.tracked_widgets.append((l, {"bg": "BG", "fg": "FG_DIM"}))
        ttk.Button(t, text="RESİM SEÇ VE QR OKU", style="Blue.TButton",
                   command=self._on_qr_decode).pack(anchor="w")

        self.url_output = self._output_box(t, tab_name="URL / QR")

    def _on_url_analyze(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Hata", "URL girin.")
            return
        if not url.lower().startswith(("http://", "https://")):
            url = "http://" + url
        self.set_status("URL analiz ediliyor...")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", str(err))
                return
            chain = "\n  ".join(result["redirect_chain"]) or "Yönlendirme yok"
            out = (
                f"[URL ANALYZER]\n"
                f"Orijinal URL   : {result['original']}\n"
                f"HTTPS mi?      : {'Evet' if result['https'] else 'Hayır'}\n"
                f"Kısaltıcı mı?  : {'Evet (dikkat!)' if result['is_shortener'] else 'Hayır'}\n"
                f"Yönlendirmeler :\n  {chain}\n"
                f"Final URL      : {result['final_url']}\n"
                f"Final IP       : {result['ip']}\n"
                f"Punycode/Homograph Şüphesi: {'EVET - DİKKAT!' if result['punycode'] else 'Yok'}\n"
            )
            if result.get("error"):
                out += f"\nHata: {result['error']}\n"
            self._write(self.url_output, out)
            self.set_status("URL analiz tamamlandı.")

        self._run_async(lambda: analyze_url(url), done)

    def _on_qr_decode(self):
        if not CV2_OK:
            messagebox.showerror("Hata", "opencv-python kurulu değil (pip install opencv-python)")
            return
        path = filedialog.askopenfilename(
            title="QR kod içeren resmi seç",
            filetypes=[("Görsel", "*.png *.jpg *.jpeg *.bmp *.webp"), ("Tüm dosyalar", "*.*")]
        )
        if not path:
            return
        self.set_status("QR kod okunuyor...")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", str(err))
                self.set_status("QR okuma başarısız.")
                return
            self._write(self.url_output, f"[QR KOD SONUCU]\nDosya: {path}\n\nİçerik:\n{result}\n")
            self.set_status("QR kod okundu.")

        self._run_async(lambda: decode_qr(path), done)

    # ================= EXIF TAB =================
    def _build_exif_tab(self):
        t = self.tab_exif
        ttk.Button(t, text="RESİM SEÇ VE METADATA ÇIKAR", command=self._on_exif_extract).pack(anchor="w", pady=6)
        if not PIL_OK:
            l = tk.Label(t, text="'Pillow' kurulu değil -> pip install Pillow", bg=self.theme["BG"], fg=self.theme["RED"], font=("Segoe UI", 9)); l.pack(anchor="w"); self.tracked_widgets.append((l, {"bg": "BG", "fg": "RED"}))
        self.exif_output = self._output_box(t, tab_name="EXIF")

    def _on_exif_extract(self):
        if not PIL_OK:
            messagebox.showerror("Hata", "Pillow kurulu değil (pip install Pillow)")
            return
        path = filedialog.askopenfilename(
            title="Metadata çıkarılacak resmi seç",
            filetypes=[("Görsel", "*.jpg *.jpeg *.tiff *.png"), ("Tüm dosyalar", "*.*")]
        )
        if not path:
            return
        self.set_status("EXIF/metadata çıkarılıyor...")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", str(err))
                self.set_status("Metadata çıkarma başarısız.")
                return
            if not result["has_exif"]:
                self._write(self.exif_output, f"[EXIF]\nDosya: {path}\n\nBu dosyada EXIF metadata bulunamadı.\n")
                self.set_status("EXIF bulunamadı.")
                return
            lines = [f"[EXIF METADATA]\nDosya: {path}\n"]
            interesting = ["Make", "Model", "DateTime", "DateTimeOriginal", "Software",
                           "ImageWidth", "ImageLength", "Orientation"]
            for key in interesting:
                if key in result["tags"]:
                    lines.append(f"{key:<18}: {result['tags'][key]}")
            if result["gps"]:
                lat, lon = result["gps"]["lat"], result["gps"]["lon"]
                lines.append(f"\nGPS Koordinat     : {lat:.6f}, {lon:.6f}")
                lines.append(f"Harita            : https://www.google.com/maps?q={lat},{lon}")
            else:
                lines.append("\nGPS verisi bulunamadı.")
            self._write(self.exif_output, "\n".join(lines))
            self.set_status("EXIF/metadata çıkarıldı.")

        self._run_async(lambda: extract_exif(path), done)

    # ================= MAC VENDOR TAB =================
    def _build_mac_tab(self):
        t = self.tab_mac
        self.mac_entry = self._labeled_entry(t, "MAC Adresi:")
        ttk.Button(t, text="ÜRETİCİ SORGULA", command=self._on_mac_lookup).pack(anchor="w", pady=6)
        self.mac_output = self._output_box(t, tab_name="MAC VENDOR")

    def _on_mac_lookup(self):
        mac = self.mac_entry.get().strip()
        if not mac:
            messagebox.showerror("Hata", "MAC adresi girin (örn: AA:BB:CC:00:11:22).")
            return
        self.set_status("MAC üretici sorgulanıyor...")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", str(err))
                self.set_status("Sorgu başarısız.")
                return
            self._write(self.mac_output, f"[MAC VENDOR LOOKUP]\nMAC     : {mac}\nÜretici : {result}\n")
            self.set_status("MAC vendor sorgusu tamamlandı.")

        self._run_async(lambda: mac_vendor_lookup(mac), done)

    # ================= USER-AGENT TAB =================
    def _build_ua_tab(self):
        t = self.tab_ua
        self.ua_entry = self._labeled_entry(t, "User-Agent:", width=70)
        ttk.Button(t, text="PARSE ET", command=self._on_ua_parse).pack(anchor="w", pady=6)
        self.ua_output = self._output_box(t, tab_name="USER-AGENT")

    def _on_ua_parse(self):
        ua = self.ua_entry.get().strip()
        if not ua:
            messagebox.showerror("Hata", "User-Agent string girin.")
            return
        result = parse_user_agent(ua)
        out = (
            f"[USER-AGENT PARSER]\n"
            f"İşletim Sistemi : {result['os']}\n"
            f"Tarayıcı        : {result['browser']} {result['version']}\n"
            f"Cihaz Tipi      : {result['device']}\n"
            f"Bot mu?         : {'EVET - dikkat' if result['is_bot'] else 'Hayır'}\n"
        )
        self._write(self.ua_output, out)
        self.set_status("User-Agent parse edildi.")


    # ================= SUBDOMAIN TAB =================
    def _build_subdomain_tab(self):
        t = self.tab_subdomain
        self.subdomain_entry = self._labeled_entry(t, "Domain:")
        ttk.Button(t, text="SUBDOMAIN ARA (crt.sh)", command=self._on_subdomain_search).pack(anchor="w", pady=6)
        l = tk.Label(t, text="Sertifika şeffaflığı (Certificate Transparency) loglarından public subdomain listesi çeker.", bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9)); l.pack(anchor="w"); self.tracked_widgets.append((l, {"bg": "BG", "fg": "FG_DIM"}))
        self.subdomain_output = self._output_box(t, tab_name="SUBDOMAIN")

    def _on_subdomain_search(self):
        domain = self.subdomain_entry.get().strip()
        if not domain:
            messagebox.showerror("Hata", "Domain girin (örn: example.com).")
            return
        self.set_status("Subdomain aranıyor (crt.sh)...")
        self._write(self.subdomain_output, "Aranıyor, lütfen bekleyin...\n")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", str(err))
                self.set_status("Subdomain arama başarısız.")
                return
            if not result:
                self._write(self.subdomain_output, f"[SUBDOMAIN: {domain}]\n\nSonuç bulunamadı.")
            else:
                out = f"[SUBDOMAIN: {domain}] — {len(result)} sonuç\n\n" + "\n".join(result)
                self._write(self.subdomain_output, out)
            self.set_status("Subdomain arama tamamlandı.")

        self._run_async(lambda: find_subdomains(domain), done)

    # ================= WAYBACK TAB =================
    def _build_wayback_tab(self):
        t = self.tab_wayback
        self.wayback_entry = self._labeled_entry(t, "Domain/URL:")
        ttk.Button(t, text="WAYBACK GEÇMİŞİ SORGULA", command=self._on_wayback_search).pack(anchor="w", pady=6)
        self.wayback_output = self._output_box(t, tab_name="WAYBACK")

    def _on_wayback_search(self):
        domain = self.wayback_entry.get().strip()
        if not domain:
            messagebox.showerror("Hata", "Domain veya URL girin.")
            return
        self.set_status("Wayback Machine sorgulanıyor...")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", str(err))
                self.set_status("Wayback sorgusu başarısız.")
                return
            out = (
                f"[WAYBACK MACHINE: {domain}]\n"
                f"Toplam Arşiv Sayısı : {result['count']}\n"
                f"İlk Arşiv Tarihi    : {result['first'] or 'Bulunamadı'}\n"
                f"Son Arşiv Tarihi    : {result['last'] or 'Bulunamadı'}\n"
            )
            if result.get("latest_snapshot_url"):
                out += f"Son Snapshot Linki  : {result['latest_snapshot_url']}\n"
            self._write(self.wayback_output, out)
            self.set_status("Wayback sorgusu tamamlandı.")

        self._run_async(lambda: wayback_history(domain), done)

    # ================= BREACH CHECK TAB =================
    def _build_breach_tab(self):
        t = self.tab_breach
        self.breach_entry = self._labeled_entry(t, "Email Adresi:")
        ttk.Button(t, text="İHLAL KONTROLÜ YAP", command=self._on_breach_check).pack(anchor="w", pady=6)
        l = tk.Label(t, text="Sadece kendi email adresini kontrol et. Public breach veritabanı (XposedOrNot) kullanılır.", bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9)); l.pack(anchor="w"); self.tracked_widgets.append((l, {"bg": "BG", "fg": "FG_DIM"}))
        self.breach_output = self._output_box(t, tab_name="BREACH CHECK")

    def _on_breach_check(self):
        email = self.breach_entry.get().strip()
        if not email:
            messagebox.showerror("Hata", "Email girin.")
            return
        self.set_status("Veri ihlali veritabanı kontrol ediliyor...")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", str(err))
                self.set_status("Kontrol başarısız.")
                return
            if not result["exposed"]:
                out = f"[BREACH CHECK: {email}]\n\nBilinen bir veri ihlalinde bulunamadı. ✓"
            else:
                breaches = "\n  - ".join(str(b) for b in result["breaches"])
                out = (f"[BREACH CHECK: {email}]\n\n"
                       f"DİKKAT: Bu email {len(result['breaches'])} bilinen veri ihlalinde bulundu!\n\n"
                       f"İhlaller:\n  - {breaches}\n\n"
                       f"Önerilen: Bu email ile kullandığın şifreleri değiştir ve 2FA aktif et.")
            self._write(self.breach_output, out)
            self.set_status("Breach check tamamlandı.")

        self._run_async(lambda: breach_check(email), done)

    # ================= PORT SCAN TAB =================
    def _build_portscan_tab(self):
        t = self.tab_portscan
        self.portscan_entry = self._labeled_entry(t, "Host/IP:")
        ttk.Button(t, text="PORT TARAMASI YAP", command=self._on_port_scan).pack(anchor="w", pady=6)
        l = tk.Label(t, text="⚠ SADECE kendi sunucunu veya taramak için izinli olduğun sistemleri tara.\n"
                         "Başkasının sistemini izinsiz taramak yasal sorumluluk doğurabilir.", bg=self.theme["BG"], fg=self.theme["RED"], font=("Segoe UI", 9), justify="left"); l.pack(anchor="w", pady=(2, 0)); self.tracked_widgets.append((l, {"bg": "BG", "fg": "RED"}))
        self.portscan_output = self._output_box(t, tab_name="PORT SCAN")

    def _on_port_scan(self):
        host = self.portscan_entry.get().strip()
        if not host:
            messagebox.showerror("Hata", "Host veya IP girin.")
            return
        self.set_status(f"'{host}' üzerinde {len(COMMON_PORTS)} port taranıyor...")
        self._write(self.portscan_output, "Taranıyor, lütfen bekleyin...\n")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", str(err))
                self.set_status("Port tarama başarısız.")
                return
            if not result["open_ports"]:
                out = f"[PORT SCAN: {host} -> {result['ip']}]\n\nAçık port bulunamadı (taranan {len(COMMON_PORTS)} port)."
            else:
                lines = [f"[PORT SCAN: {host} -> {result['ip']}]\n"]
                for port, name in result["open_ports"]:
                    lines.append(f"  {port:<6} AÇIK   ({name})")
                out = "\n".join(lines)
            self._write(self.portscan_output, out)
            self.set_status("Port tarama tamamlandı.")

        self._run_async(lambda: scan_common_ports(host), done)


    # ================= LEAK SEARCH TAB =================
    def _build_leak_tab(self):
        t = self.tab_leak
        self.leak_entry = self._labeled_entry(t, "Email/Username:")
        ttk.Button(t, text="ARAMA LİNKİ OLUŞTUR", command=self._on_leak_search).pack(anchor="w", pady=6)
        l = tk.Label(t,
                 text="Bu modül otomatik veri çekmez/göstermez — sadece paste sitelerinde ve\n"
                      "arama motorlarında hazır sorgu linkleri üretir. Sonuçları kendi tarayıcında\n"
                      "incelersin. Sadece kendi email/username'ini araştırmak için kullan.", bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9), justify="left"); l.pack(anchor="w", pady=(2, 0)); self.tracked_widgets.append((l, {"bg": "BG", "fg": "FG_DIM"}))
        self.leak_output = self._output_box(t, tab_name="LEAK SEARCH")

    def _on_leak_search(self):
        term = self.leak_entry.get().strip()
        if not term:
            messagebox.showerror("Hata", "Email veya username girin.")
            return
        links = generate_leak_dorks(term)
        out = (
            f"[LEAK SEARCH LİNKLERİ: {term}]\n"
            f"(Aşağıdaki linkleri tarayıcında aç, sonuçları orada incele)\n\n"
            f"Google (paste siteleri) : {links['google']}\n\n"
            f"DuckDuckGo (paste site.) : {links['duckduckgo']}\n\n"
            f"Google (genel leak/dump) : {links['google_generic']}\n\n"
            f"GitHub Code Search       : {links['github_code']}\n\n"
            f"psbdmp.ws (paste arşivi) : {links['psbdmp']}\n\n"
            f"─────────────────────────────────────────\n"
            f"İpucu: Email için ayrıca BREACH CHECK sekmesini de kullan,\n"
            f"o sekme bilinen ihlal veritabanını otomatik kontrol eder."
        )
        self._write(self.leak_output, out)
        self.set_status("Leak search linkleri oluşturuldu.")


    # ================= PASTEBIN SCRAPER TAB =================
    def _build_pastebin_tab(self):
        t = self.tab_pastebin
        self.pastebin_entry = self._labeled_entry(t, "Aranacak Terim:")
        ttk.Button(t, text="PASTEBIN'DE TARA", command=self._on_pastebin_scrape).pack(anchor="w", pady=6)
        l1 = tk.Label(t,
                 text="⚠ Bu modül public paste sitelerinden veri çeker. Çıkan sonuçlar hassas bilgiler\n"
                      "içerebilir. Sadece yasal ve etik amaçlarla kullanın.", bg=self.theme["BG"], fg=self.theme["RED"], font=("Segoe UI", 9), justify="left"); l1.pack(anchor="w", pady=(2, 0)); self.tracked_widgets.append((l1, {"bg": "BG", "fg": "RED"}))
        l2 = tk.Label(t, text="psbdmp.ws API'si ile Pastebin arşivi taranır ve bulunan ilk 10 sonucun içeriği çekilir.",
                 bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9), justify="left"); l2.pack(anchor="w", pady=(2, 0)); self.tracked_widgets.append((l2, {"bg": "BG", "fg": "FG_DIM"}))
        self.pastebin_output = self._output_box(t, tab_name="PASTEBIN SCRAPER")

    def _on_pastebin_scrape(self):
        keyword = self.pastebin_entry.get().strip()
        if not keyword:
            messagebox.showerror("Hata", "Aranacak bir terim girin (örn: email, domain, username).")
            return
        self.set_status(f"'{keyword}' için Pastebin taranıyor...")
        self._write(self.pastebin_output, f"Pastebin Taraması Başlatıldı: {keyword}\n" + "="*50 + "\n")

        def progress_callback(message):
            self.after(0, self._append_to_output, self.pastebin_output, message)

        def worker():
            try:
                results = pastebin_scraper(keyword, progress_callback=progress_callback)

                def final_update():
                    progress_callback("\n" + "="*50 + "\nTarama Tamamlandı.")
                    if not results:
                        progress_callback(f"Sonuç: '{keyword}' ile ilgili bir paste bulunamadı.")
                    else:
                        progress_callback(f"Toplam {len(results)} eşleşen paste bulundu ve içeriği çekildi:\n")
                        for paste in results:
                            lines = [f"--- Paste ID: {paste['id']} ---", f"URL: {paste['url']}", "--- İÇERİK (ilk 20 satır) ---", *paste['content'].splitlines()[:20], "----------------------------------\n"]
                            progress_callback("\n".join(lines))
                    self.set_status("Pastebin taraması tamamlandı.")
                self.after(0, final_update)
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Hata", str(e)))
                self.after(0, self.set_status, "Pastebin taraması başarısız.")

        threading.Thread(target=worker, daemon=True).start()

    # ================= DISCORD INVITE TAB =================
    def _build_invite_tab(self):
        t = self.tab_invite
        self.invite_entry = self._labeled_entry(t, "Invite Linki/Kod:", width=50)
        ttk.Button(t, text="DAVET BİLGİSİ ÇEK", command=self._on_invite_lookup).pack(anchor="w", pady=6)
        l = tk.Label(t, text="Token gerekmez — Discord'un public /invites/{code} endpointini kullanır.\n"
                          "Sadece geçerli, süresi dolmamış davet linkleri için çalışır.", bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9), justify="left"); l.pack(anchor="w"); self.tracked_widgets.append((l, {"bg": "BG", "fg": "FG_DIM"}))
        self.invite_output = self._output_box(t, tab_name="DISCORD INVITE")

    def _on_invite_lookup(self):
        code = self.invite_entry.get().strip()
        if not code:
            messagebox.showerror("Hata", "Davet linki veya kodu girin (örn: discord.gg/abc123).")
            return
        self.set_status("Discord invite bilgisi çekiliyor...")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", str(err))
                self.set_status("Invite sorgusu başarısız.")
                return
            out = (
                f"[DISCORD INVITE BİLGİSİ]\n"
                f"Sunucu Adı        : {result['guild_name']}\n"
                f"Sunucu ID         : {result['guild_id']}\n"
                f"Açıklama          : {result['guild_description'] or '-'}\n"
                f"Doğrulama Seviyesi: {result['verification_level']}\n"
                f"Üye Sayısı (~)    : {result['member_count']}\n"
                f"Çevrimiçi (~)     : {result['online_count']}\n"
                f"Kanal             : {result['channel_name']}\n"
                f"Davet Eden        : {result['inviter_username'] or '-'}\n"
                f"Son Kullanma      : {result['expires_at'] or 'Süresiz'}\n"
                f"Sunucu İkonu      : {result['icon_url'] or '-'}\n"
            )
            self._write(self.invite_output, out)
            self.set_status("Invite bilgisi alındı.")

        self._run_async(lambda: fetch_discord_invite(code), done)


    # ================= SSL SERTİFİKA TAB =================
    def _build_ssl_tab(self):
        t = self.tab_ssl
        self.ssl_entry = self._labeled_entry(t, "Domain:")
        ttk.Button(t, text="SERTİFİKA ANALİZİ YAP", command=self._on_ssl_check).pack(anchor="w", pady=6)
        l = tk.Label(t, text="Tarayıcının adres çubuğundaki kilit simgesiyle aynı public sertifika bilgisini gösterir.", bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9)); l.pack(anchor="w"); self.tracked_widgets.append((l, {"bg": "BG", "fg": "FG_DIM"}))
        self.ssl_output = self._output_box(t, tab_name="SSL SERTİFİKA")

    def _on_ssl_check(self):
        domain = self.ssl_entry.get().strip()
        if not domain:
            messagebox.showerror("Hata", "Domain girin (örn: google.com).")
            return
        self.set_status("SSL sertifikası kontrol ediliyor...")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", str(err))
                self.set_status("SSL kontrolü başarısız.")
                return
            san = ", ".join(result["san_list"][:15]) or "-"
            durum = "SÜRESİ DOLMUŞ ✗" if result["expired"] else f"Geçerli ✓ ({result['days_left']} gün kaldı)"
            out = (
                f"[SSL SERTİFİKA: {result['domain']}]\n"
                f"Ortak Ad (CN)     : {result['common_name']}\n"
                f"Organizasyon      : {result['organization']}\n"
                f"Veren CA          : {result['issuer_cn']} ({result['issuer_org']})\n"
                f"Geçerlilik Başl.  : {result['valid_from']}\n"
                f"Geçerlilik Sonu   : {result['valid_until']}\n"
                f"Durum             : {durum}\n"
                f"TLS Versiyonu     : {result['tls_version']}\n"
                f"Şifreleme (Cipher): {result['cipher']}\n"
                f"Alternatif Adlar  : {san}\n"
            )
            if result["days_left"] < 15 and not result["expired"]:
                out += "\n⚠ UYARI: Sertifikanın süresi 15 günden az bir zamanda dolacak!\n"
            self._write(self.ssl_output, out)
            self.set_status("SSL sertifika analizi tamamlandı.")

        self._run_async(lambda: check_ssl_certificate(domain), done)

    # ================= IBAN ANALYZER TAB =================
    def _build_iban_tab(self):
        t = self.tab_iban
        self.iban_entry = self._labeled_entry(t, "IBAN:", width=50)
        ttk.Button(t, text="IBAN ANALİZİ YAP", command=self._on_iban_analyze).pack(anchor="w", pady=6)
        l = tk.Label(t, text="Girilen IBAN'ın geçerliliğini kontrol eder ve Türkiye IBAN'ları için\nbanka/şube bilgilerini tahmin eder.", bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9), justify="left"); l.pack(anchor="w"); self.tracked_widgets.append((l, {"bg": "BG", "fg": "FG_DIM"}))
        self.iban_output = self._output_box(t, tab_name="IBAN ANALYZER")

    def _on_iban_analyze(self):
        iban = self.iban_entry.get().strip()
        if not iban:
            messagebox.showerror("Hata", "IBAN girin.")
            return
        self.set_status("IBAN analiz ediliyor...")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", str(err))
                self.set_status("IBAN analizi başarısız.")
                return

            if result.get("error") and not result["is_valid"]:
                 out = (
                    f"[IBAN ANALİZİ: {result['iban']}]\n\n"
                    f"Durum: GEÇERSİZ ✗\n"
                    f"Sebep: {result['error']}"
                 )
            else:
                out = (
                    f"[IBAN ANALİZİ: {result['iban']}]\n\n"
                    f"Geçerlilik        : {'Evet ✓' if result['is_valid'] else 'Hayır ✗'}\n"
                    f"Ülke Kodu         : {result['country_code']}\n"
                    f"Banka Kodu        : {result.get('bank_code') or '-'}\n"
                    f"Banka Adı         : {result.get('bank_name') or '-'}\n"
                    f"Şube Kodu (Tahmin): {result.get('branch_code') or '-'}\n"
                    f"Hesap Numarası    : {result.get('account_number') or '-'}\n"
                )
            self._write(self.iban_output, out)
            self.set_status("IBAN analizi tamamlandı.")

        self._run_async(lambda: analyze_iban(iban), done)

    # ================= XSS TEST TAB =================
    def _build_xss_tab(self):
        t = self.tab_xss
        self.xss_entry = self._labeled_entry(t, "URL (parametrelerle):", width=70)
        ttk.Button(t, text="XSS TESTİ YAP", command=self._on_xss_test).pack(anchor="w", pady=6)
        l1 = tk.Label(t, text="⚠ SADECE kendi siteni veya test iznin olan sistemleri tara.\n"
                         "İzinsiz test yapmak yasa dışıdır ve ciddi sonuçları olabilir.", bg=self.theme["BG"], fg=self.theme["RED"], font=("Segoe UI", 9), justify="left"); l1.pack(anchor="w", pady=(2, 0)); self.tracked_widgets.append((l1, {"bg": "BG", "fg": "RED"}))
        l2 = tk.Label(t, text="Bu modül, URL parametrelerine payload ekleyerek sayfada yansıyıp yansımadığını kontrol eder (reflected XSS).",
                 bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9), justify="left"); l2.pack(anchor="w", pady=(2, 0)); self.tracked_widgets.append((l2, {"bg": "BG", "fg": "FG_DIM"}))
        self.xss_output = self._output_box(t, tab_name="XSS TEST")

    def _on_xss_test(self):
        url = self.xss_entry.get().strip()
        if not url:
            messagebox.showerror("Hata", "URL girin (örn: http://test.com/page.php?q=test).")
            return
        self.set_status(f"'{url}' için temel XSS testi yapılıyor...")
        self._write(self.xss_output, f"XSS Testi Başlatıldı: {url}\n" + "="*50 + "\n")

        def progress_callback(message):
            self.after(0, self._append_to_output, self.xss_output, message)

        def worker():
            try:
                result = xss_test(url, progress_callback=progress_callback)

                def final_update():
                    progress_callback("\n" + "="*50 + "\nTest Tamamlandı.")
                    if result.get("message"):
                        progress_callback(result['message'])
                    elif not result["vulnerable"]:
                        progress_callback("Sonuç: Potansiyel bir Reflected XSS zafiyeti bulunamadı.")
                    else:
                        lines = [f"DİKKAT: {len(result['details'])} potansiyel Reflected XSS zafiyeti bulundu!\n"]
                        for vuln in result["details"]:
                            lines.append(f"  Parametre : {vuln['param']}\n  Payload   : {vuln['payload']}\n  URL       : {vuln['url']}\n" + "-"*20)
                        lines.append("\nNot: Bu test, payload'un sayfada değiştirilmeden yansıdığını kontrol eder. False-positive olabilir.")
                        progress_callback("\n".join(lines))
                    self.set_status("XSS testi tamamlandı.")
                self.after(0, final_update)
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Hata", str(e)))
                self.after(0, self.set_status, "XSS testi başarısız.")

        threading.Thread(target=worker, daemon=True).start()

    # ================= SQL INJECTION TEST TAB =================
    def _build_sql_tab(self):
        t = self.tab_sql
        self.sql_entry = self._labeled_entry(t, "URL (parametrelerle):", width=70)
        ttk.Button(t, text="SQLi TESTİ YAP", command=self._on_sql_test).pack(anchor="w", pady=6)
        l1 = tk.Label(t, text="⚠ SADECE kendi siteni veya test iznin olan sistemleri tara.\n"
                         "İzinsiz test yapmak yasa dışıdır ve ciddi sonuçları olabilir.", bg=self.theme["BG"], fg=self.theme["RED"], font=("Segoe UI", 9), justify="left"); l1.pack(anchor="w", pady=(2, 0)); self.tracked_widgets.append((l1, {"bg": "BG", "fg": "RED"}))
        l2 = tk.Label(t, text="Bu modül, URL parametrelerine payload ekleyerek hata mesajı arar (error-based).",
                 bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9), justify="left"); l2.pack(anchor="w", pady=(2, 0)); self.tracked_widgets.append((l2, {"bg": "BG", "fg": "FG_DIM"}))
        self.sql_output = self._output_box(t, tab_name="SQLi TEST")

    def _on_sql_test(self):
        url = self.sql_entry.get().strip()
        if not url:
            messagebox.showerror("Hata", "URL girin (örn: http://test.com/page.php?id=1).")
            return
        self.set_status(f"'{url}' için temel SQLi testi yapılıyor...")
        self._write(self.sql_output, f"SQLi Testi Başlatıldı: {url}\n" + "="*50 + "\n")

        def progress_callback(message):
            self.after(0, self._append_to_output, self.sql_output, message)

        def worker():
            try:
                result = sql_injection_test(url, progress_callback=progress_callback)

                def final_update():
                    progress_callback("\n" + "="*50 + "\nTest Tamamlandı.")
                    if result.get("message"):
                        progress_callback(result['message'])
                    elif not result["vulnerable"]:
                        progress_callback("Sonuç: Potansiyel bir SQL Injection zafiyeti bulunamadı (error-based).")
                    else:
                        lines = [f"DİKKAT: {len(result['details'])} potansiyel SQL Injection zafiyeti bulundu!\n"]
                        for vuln in result["details"]:
                            lines.append(f"  Parametre : {vuln['param']}\n  Payload   : {vuln['payload']}\n  Hata      : {vuln['error_snippet']}\n  URL       : {vuln['url']}\n" + "-"*20)
                        progress_callback("\n".join(lines))
                    self.set_status("SQLi testi tamamlandı.")
                self.after(0, final_update)
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Hata", str(e)))
                self.after(0, self.set_status, "SQLi testi başarısız.")

        threading.Thread(target=worker, daemon=True).start()

if __name__ == "__main__":
    app = GhostOSINT()
    app.mainloop()
