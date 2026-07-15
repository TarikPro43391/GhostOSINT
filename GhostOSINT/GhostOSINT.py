"""
================================================================
 GHOST OSINT FRAMEWORK v0.1.5 (Alpha) - GUI EDITION
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import webbrowser
import os
import base64
import csv

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

try:
    from xhtml2pdf import pisa
    XHTML2PDF_OK = True
except ImportError:
    XHTML2PDF_OK = False

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_OK = True
except ImportError:
    PLAYWRIGHT_OK = False

# ================= CONFIG & TABS =================
CONFIG_FILE = "ghost_osint_config.json"

ALL_TAB_DEFS = [
    ("discord", "DISCORD ID"), ("ip", "IP LOOKUP"), ("domain", "DOMAIN/DNS"), ("reputation", "İTİBAR KONTROLÜ"),
    ("username", "USERNAME"), ("email", "EMAIL"), ("hash", "HASH"),
    ("phone", "PHONE"), ("url", "URL/QR"), ("exif", "EXIF"),
    ("mac", "MAC VENDOR"), ("ua", "USER-AGENT"), ("subdomain", "SUBDOMAIN"),
    ("wayback", "WAYBACK"), ("breach", "BREACH"), ("portscan", "PORT SCAN"),
    ("leak", "LEAK SEARCH"), ("leakpeek", "LEAK PEEK"),
    ("invite", "INVITE"), ("ssl", "SSL"), ("iban", "IBAN"), ("bin", "BIN LOOKUP")
]

# Pentest ve diğer araçlar
ALL_TAB_DEFS.extend([("xss", "XSS SCAN"), ("sql", "SQLi SCAN"), ("base64", "BASE64"), ("btc", "BITCOIN")])

def get_default_config():
    """Returns the default application configuration."""
    return {
        "visible_tabs": [name for name, text in ALL_TAB_DEFS],
        "abuseipdb_api_key": "",
        "virustotal_api_key": "",
    }

def load_config():
    """Loads configuration from the JSON file, or returns default if not found/invalid."""
    if not os.path.exists(CONFIG_FILE):
        return get_default_config()
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
        if not isinstance(config, dict) or "visible_tabs" not in config or not isinstance(config["visible_tabs"], list):
             return get_default_config()
        return config
    except (json.JSONDecodeError, IOError):
        return get_default_config()

def save_config(config):
    """Saves the configuration dictionary to the JSON file."""
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
    except IOError as e:
        messagebox.showerror("Hata", f"Ayarlar kaydedilemedi: {e}")

# ================= VERSION =================
CURRENT_VERSION = "v0.1.5"
# Gerçek bir repo URL'si ile değiştirin. version.json dosyası {"latest_version": "vX.Y.Z", "release_url": "..."} formatında olmalı.
VERSION_CHECK_URL = "https://raw.githubusercontent.com/TarikPro43391/GhostOSINT/main/version.json"


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
            "Token geçersiz veya yetkisiz (401). Kontrol edin: Token'ın doğru olduğundan, "
            "önünde/sonunda boşluk olmadığından ve Discord Developer Portal'dan "
            "resetlenmediğinden emin olun. ('Bot ' önekini ekleseniz de olur, kod bunu yönetir.)"
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
        result["raw_error"] = f"Host ('{domain}') çözülemedi. Domain adını kontrol edin veya ağ bağlantınızı test edin."

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
        error_message = (
            f"Host ('{domain}') çözülemedi.\n\n"
            "Bu hata genellikle şu nedenlerden kaynaklanır:\n"
            " - Domain adı yanlış yazılmış.\n"
            " - Domain adı mevcut değil veya süresi dolmuş.\n"
            " - İnternet bağlantınızda veya DNS ayarlarınızda bir sorun var."
        )
        raise RuntimeError(error_message) from e
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


TLD_WHOIS_SERVERS = {
    # Generic TLDs
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
    "org": "whois.pir.org", "info": "whois.afilias.info", "biz": "whois.biz",
    "xyz": "whois.nic.xyz", "online": "whois.nic.online", "site": "whois.nic.site",
    "club": "whois.nic.club", "app": "whois.nic.google", "dev": "whois.nic.google",
    "io": "whois.nic.io", "co": "whois.nic.co", "ai": "whois.nic.ai",
    "gg": "whois.gg", "me": "whois.nic.me", "tv": "whois.nic.tv",
    "cc": "whois.nic.cc", "ws": "whois.nic.ws",
    # Country-code TLDs
    "de": "whois.denic.de", "uk": "whois.nic.uk", "ca": "whois.cira.ca",
    "jp": "whois.jprs.jp", "au": "whois.auda.org.au", "ru": "whois.tcinet.ru",
    "tr": "whois.nic.tr", "fr": "whois.nic.fr", "nl": "whois.domain-registry.nl",
    "eu": "whois.eu", "cn": "whois.cnnic.cn", "in": "whois.registry.in",
    "br": "whois.registro.br", "ch": "whois.nic.ch", "it": "whois.nic.it",
    "es": "whois.nic.es", "se": "whois.iis.se", "pl": "whois.dns.pl",
    "us": "whois.nic.us",
}


def whois_lookup(domain: str) -> str:
    domain = domain.strip().lower()
    # Handle URLs by extracting the domain
    if "://" in domain:
        domain = urllib.parse.urlparse(domain).netloc

    parts = domain.split('.')
    if len(parts) < 2:
        return f"Geçersiz domain: {domain}"

    tld = parts[-1]

    def query(server, q, port=43):
        with socket.create_connection((server, port), timeout=10) as s:
            s.send((q + "\r\n").encode())
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                resp += chunk
        return resp.decode(errors="ignore")

    def find_refer(text):
        for line in text.splitlines():
            low = line.lower()
            if low.strip().startswith("whois server:") or low.strip().startswith("refer:"):
                server = line.split(":", 1)[1].strip()
                if server and '.' in server: # Basic validation
                    return server
        return None

    # 1. Check our local list first for speed
    whois_server = TLD_WHOIS_SERVERS.get(tld)

    # 2. If not in our list, fall back to IANA
    if not whois_server:
        try:
            iana_resp = query("whois.iana.org", tld)
            whois_server = find_refer(iana_resp)
            if not whois_server:
                return f"'.{tld}' için authoritative WHOIS sunucusu bulunamadı.\n\n--- IANA yanıtı ---\n{iana_resp}"
        except socket.gaierror:
            return "IANA WHOIS sunucusu ('whois.iana.org') çözümlenemedi. İnternet bağlantınızı kontrol edin."
        except Exception as e:
            return f"IANA whois sunucusuna bağlanılamadı: {e}\n(Ağ/firewall port 43'ü (WHOIS) engelliyor olabilir.)"

    # 3. Query the authoritative server
    try:
        main_resp = query(whois_server, domain)
    except socket.gaierror:
        return f"WHOIS sunucusu ('{whois_server}') çözümlenemedi. İnternet bağlantınızı kontrol edin."
    except Exception as e:
        return f"'{whois_server}' sunucusuna bağlanılamadı: {e}"

    # 4. Handle second-level referrals (e.g., for .uk domains)
    second_refer = find_refer(main_resp)
    if second_refer and second_refer.lower() != whois_server.lower():
        try:
            third_resp = query(second_refer, domain)
            if len(third_resp) > len(main_resp):
                return third_resp
        except socket.gaierror:
            # Referral sunucusu çözümlenemezse, görmezden gel ve önceki yanıtı döndür.
            pass
        except Exception:
            pass # If the third query fails, we still have the main response

    return main_resp

def abuseipdb_check(ip: str, api_key: str) -> dict:
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil")
    if not api_key:
        raise ValueError("AbuseIPDB API anahtarı gerekli.")

    ip = ip.strip()
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90',
        'verbose': True
    }
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=15)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"AbuseIPDB API'ye bağlanılamadı: {e}")

    if r.status_code == 401:
        raise RuntimeError("Geçersiz AbuseIPDB API anahtarı (401).")
    if r.status_code == 429:
        raise RuntimeError("AbuseIPDB API rate limit aşıldı (429).")
    if r.status_code == 422:
        try:
            error_detail = r.json()['errors'][0]['detail']
            raise RuntimeError(f"Geçersiz istek: {error_detail} (422).")
        except (json.JSONDecodeError, KeyError, IndexError):
             raise RuntimeError("AbuseIPDB'den geçersiz istek yanıtı (422).")

    r.raise_for_status()

    try:
        data = r.json().get('data', {})
    except json.JSONDecodeError:
        raise RuntimeError("AbuseIPDB API'den geçersiz JSON yanıtı alındı.")

    return data

def virustotal_domain_report(domain: str, api_key: str) -> dict:
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil")
    if not api_key:
        raise ValueError("VirusTotal API anahtarı gerekli.")

    domain = domain.strip()
    if "://" in domain:
        domain = urllib.parse.urlparse(domain).netloc

    headers = {"x-apikey": api_key}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=15)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"VirusTotal API'ye bağlanılamadı: {e}")

    if r.status_code == 401:
        raise RuntimeError("Geçersiz VirusTotal API anahtarı (401).")
    if r.status_code == 404:
        return {"domain": domain, "found": False}
    if r.status_code == 429:
        raise RuntimeError("VirusTotal API rate limit aşıldı (429).")

    r.raise_for_status()

    try:
        data = r.json().get('data', {}).get('attributes', {})
        data['found'] = True
        data['domain'] = domain
    except (json.JSONDecodeError, KeyError):
        raise RuntimeError("VirusTotal API'den geçersiz JSON yanıtı alındı.")
    return data

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
def hibp_lookup(email: str) -> dict:
    """Checks an email against the Have I Been Pwned API."""
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil")
    email = email.strip()

    headers = UA.copy()
    # HIBP requires a specific user agent if one is sent.
    headers["User-Agent"] = "GhostOSINT-Framework"

    try:
        # The public API without a key has a rate limit.
        # Repeated fast queries will get a 429 error.
        r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}", headers=headers, timeout=15)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"HIBP API'ye bağlanılamadı: {e}")

    if r.status_code == 404:
        return {"pwned": False, "breaches": [], "count": 0}
    if r.status_code == 429:
        raise RuntimeError("HIBP API rate limit aşıldı (429). Birkaç saniye bekleyip tekrar deneyin.")

    r.raise_for_status() # For other errors

    try:
        data = r.json()
        breach_names = sorted([b.get("Name") for b in data])
        return {"pwned": True, "breaches": breach_names, "count": len(breach_names)}
    except json.JSONDecodeError:
        raise RuntimeError("HIBP API'den geçersiz JSON yanıtı alındı.")


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
        except socket.gaierror:
            result["ip"] = "Çözülemedi"
        except Exception:
            pass
    except Exception as e:
        result["error"] = str(e)
    return result

def take_url_screenshot(url: str, save_path: str):
    """Takes a full-page screenshot of a URL using Playwright."""
    if not PLAYWRIGHT_OK:
        raise RuntimeError("Bu özellik için 'playwright' kütüphanesi gereklidir.\n\nLütfen `GhostOSINT-Installer.bat` dosyasını çalıştırarak kurulumu tamamlayın.")

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as e:
            raise RuntimeError(f"Playwright tarayıcısı başlatılamadı. Kurulumun tamamlandığından emin olun.\n\nDetay: {e}")
        
        page = browser.new_page(
            user_agent=UA["User-Agent"],
            viewport={'width': 1280, 'height': 1080} # A reasonable default viewport
        )
        try:
            # Go to URL, wait for content to load
            page.goto(url, wait_until="domcontentloaded", timeout=25000)
            # Wait a bit more for JS-heavy pages to render.
            page.wait_for_timeout(3000)
            page.screenshot(path=save_path, full_page=True)
        except Exception as e:
            browser.close()
            raise RuntimeError(f"Sayfa yüklenemedi veya ekran görüntüsü alınamadı.\n\nDetay: {e}")
        finally:
            if browser.is_connected():
                browser.close()
    return save_path


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
    """Converts GPS coordinate from EXIF (DMS) to decimal degrees."""
    if not isinstance(coord, (list, tuple)) or len(coord) != 3:
        return None

    def to_float(r):
        """Converts an EXIF value (which can be an IFDRational) to float."""
        if hasattr(r, 'numerator') and hasattr(r, 'denominator'):
            if r.denominator == 0:
                return 0.0
            return r.numerator / r.denominator
        return float(r)

    try:
        degrees = to_float(coord[0])
        minutes = to_float(coord[1])
        seconds = to_float(coord[2])
    except (ValueError, TypeError, IndexError):
        return None

    dec = degrees + (minutes / 60.0) + (seconds / 3600.0)
    if ref in ('S', 'W'):
        dec = -dec
    return dec


def extract_exif(path: str) -> dict:
    if not PIL_OK:
        raise RuntimeError("Pillow kurulu değil (pip install Pillow)")
    try:
        img = Image.open(path)

        result = {"tags": {}, "gps": None, "has_exif": False}
        
        # --- Get all available metadata ---
        all_tags = {}
        # 1. From PNG-style info
        if hasattr(img, 'info') and isinstance(img.info, dict):
            all_tags.update(img.info)
        
        # 2. From EXIF
        exif_data = img.getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                if tag_name == "GPSInfo": continue # Will be handled separately
                
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8', errors='replace').strip('\x00')
                    except Exception:
                        value = repr(value)
                all_tags[tag_name] = value

        if not all_tags and not exif_data:
            return result
            
        result["has_exif"] = True
        result["tags"] = all_tags

        # --- GPS Specific, more robust parsing using the dedicated IFD method ---
        if exif_data:
            gps_ifd = exif_data.get_ifd(ExifTags.IFD.GPSInfo)
            if gps_ifd:
                gps_named = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}

                lat_coord = gps_named.get("GPSLatitude")
                lon_coord = gps_named.get("GPSLongitude")

                # The coordinates themselves are required.
                if lat_coord and lon_coord:
                    # The Ref tags might be omitted by some cameras, default to N/E.
                    lat_ref_raw = gps_named.get("GPSLatitudeRef", "N")
                    lon_ref_raw = gps_named.get("GPSLongitudeRef", "E")

                    # Safely decode reference tags if they are bytes
                    lat_ref = lat_ref_raw
                    if isinstance(lat_ref, bytes):
                        lat_ref = lat_ref.decode('ascii', errors='ignore').strip('\x00')

                    lon_ref = lon_ref_raw
                    if isinstance(lon_ref, bytes):
                        lon_ref = lon_ref.decode('ascii', errors='ignore').strip('\x00')

                    lat = _gps_to_decimal(lat_coord, lat_ref)
                    lon = _gps_to_decimal(lon_coord, lon_ref)

                    if lat is not None and lon is not None:
                        result["gps"] = {"lat": lat, "lon": lon}

        return result
    except Exception as e:
        raise RuntimeError(f"Görsel dosyası işlenemedi veya desteklenmiyor.\n\nDetay: {e}")


def mac_vendor_lookup(mac: str) -> str:
    mac_clean = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(mac_clean) < 6:
        raise ValueError("Geçersiz MAC adresi formatı.")
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil")
    # Using the simple, free, and key-less plain-text API from macvendors.com
    try:
        # The API expects the MAC address directly in the URL.
        r = requests.get(f"https://api.macvendors.com/{urllib.parse.quote(mac.strip())}", headers=UA, timeout=8)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"MAC vendor API'ye bağlanılamadı: {e}")

    if r.status_code == 404:
        raise RuntimeError("Üretici bulunamadı (bilinmeyen OUI).")
    if r.status_code == 400:
        raise RuntimeError("Geçersiz MAC adresi formatı (API'ye göre).")

    r.raise_for_status()

    # The API returns the vendor name as plain text.
    vendor = r.text.strip()
    if not vendor or "errors" in vendor.lower():
        raise RuntimeError(f"Üretici bulunamadı veya API hatası: {vendor}")

    return vendor


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

def check_subdomain_liveness(subdomain: str):
    """Checks a single subdomain for HTTP/HTTPS liveness. Returns a tuple."""
    if not REQUESTS_OK:
        return (subdomain, "HATA", "(requests yok)")

    # Try HTTPS first
    try:
        # Use GET with stream=True, it's more reliable than HEAD and still fast.
        r = requests.get(f"https://{subdomain}", headers=UA, timeout=4, allow_redirects=True, stream=True)
        return (subdomain, r.status_code, r.url)
    except requests.exceptions.RequestException:
        # If anything goes wrong with HTTPS, fall back to HTTP
        try:
            r = requests.get(f"http://{subdomain}", headers=UA, timeout=4, allow_redirects=True, stream=True)
            return (subdomain, r.status_code, r.url)
        except requests.exceptions.RequestException:
            # If HTTP also fails
            return (subdomain, "ULAŞILAMADI", subdomain)

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

    # Handle cases where API returns 200 OK but with an error message in JSON
    if "Error" in data:
        return {"exposed": False, "breaches": []}

    breaches_list = data.get("breaches", [])
    # Extract just the names for cleaner output in the GUI
    breach_names = sorted([b.get("name", "Bilinmeyen Kaynak") for b in breaches_list]) if breaches_list else []

    return {"exposed": bool(breach_names), "breaches": breach_names}


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
        "paste_archive": f"https://ps.s.osint.sh/s/{q}",
    }

def censor_password(password: str) -> str:
    """Censors a password, showing only the first 2 and last 2 characters."""
    if len(password) <= 4:
        return "****"
    return password[:2] + "*" * (len(password) - 4) + password[-2:]


def leakpeek_lookup(keyword: str) -> dict:
    """LeakCheck Public API'sini kullanarak sızıntı kaynaklarını sorgular.

    Not: LeakPeek.com artık ücretli üyelik gerektirdiği ve eski (reverse-engineer
    edilmiş) /api/ endpoint'i kaldırıldığı için, bu modül LeakCheck'in resmi,
    ücretsiz ve anahtarsız Public API'sine geçirildi (https://leakcheck.io).
    Public API sadece hangi kaynaklarda / hangi veri kategorilerinde sızıntı
    bulunduğunu döner; şifre gibi hassas alanları döndürmez (bunun için
    ücretli Pro API v2 + API key gerekir).
    """
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil")

    keyword = keyword.strip()
    if not keyword:
        raise ValueError("Arama terimi boş olamaz.")

    api_url = "https://leakcheck.io/api/public"
    params = {"check": keyword}

    try:
        r = requests.get(api_url, params=params, headers=UA, timeout=25)
    except requests.exceptions.Timeout:
        raise RuntimeError("LeakCheck API zaman aşımına uğradı, daha sonra tekrar deneyin.")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"LeakCheck API sorgusu başarısız: {e}")

    if r.status_code == 429:
        raise RuntimeError("LeakCheck API rate limit aşıldı (429). Lütfen bir süre sonra tekrar deneyin.")
    if r.status_code == 404:
        raise RuntimeError("LeakCheck API sorgusu geçersiz (404). Girdiğiniz terim email/username formatında olmalı.")
    r.raise_for_status()

    try:
        data = r.json()
    except json.JSONDecodeError:
        raise RuntimeError("LeakCheck API'den geçersiz JSON yanıtı alındı.")

    if not data.get("success"):
        msg = data.get("error", data.get("message", "Bilinmeyen bir hata oluştu."))
        raise RuntimeError(f"LeakCheck API hatası: {msg}")

    found_count = data.get("found", 0)
    if not found_count:
        return {"found": False, "results": [], "count": 0, "fields": []}

    sources = data.get("sources", [])
    results = []
    for src in sources:
        name = src.get("name", "Bilinmeyen Kaynak")
        date = src.get("date", "Tarih bilinmiyor")
        results.append({"line": f"{name}  (Tarih: {date})", "sources": name})

    return {
        "found": True,
        "results": results,
        "count": found_count,
        "fields": data.get("fields", []),
    }



# Not: Bu tarayıcı sadece TCP portlarını tarar. UDP taraması (örn. Minecraft Bedrock) şu anki haliyle desteklenmemektedir.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS (TCP)", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    25565: "Minecraft (Java)",
    27015: "Source Engine (RCON)", # Genellikle UDP, ama RCON için TCP kullanabilir
}


def scan_common_ports(host: str, timeout=2.0) -> dict:
    host = host.strip()
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        error_message = (
            f"Host ('{host}') çözülemedi.\n\n"
            "Lütfen geçerli bir domain adı veya IP adresi girdiğinizden emin olun."
        )
        raise RuntimeError(error_message) from e

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
        report(f"[!] {msg} (Örn: https://site.com/index.php?id=1)")
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
        report(f"[!] {msg} (Örn: https://site.com/index.php?q=test)")
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

# Banka kodlarına göre bazı yaygın örnek BIN'ler. Bu liste tam değildir ve sadece görsel bir örnektir.
TR_BANK_EXAMPLE_BINS = {
    "00010": ["499884", "554961", "589004"], # Ziraat Bankası (Visa, Mastercard, Troy)
    "00012": ["403059", "552879", "979208"], # Halkbank (Visa, Mastercard, Troy)
    "00015": ["435528", "552098", "979203"], # Vakıfbank (Visa, Mastercard, Troy)
    "00032": ["402458", "540061"],          # TEB (Visa, Mastercard)
    "00046": ["450803", "557036", "979215"], # Akbank (Visa, Mastercard, Troy)
    "00062": ["426308", "554901"],          # Garanti BBVA (Visa, Mastercard)
    "00064": ["454360", "552609", "979201"], # İş Bankası (Visa, Mastercard, Troy)
    "00067": ["450680", "552401", "979205"], # Yapı Kredi (Visa, Mastercard, Troy)
    "00099": ["415463", "549800"],          # ING Bank (Visa, Mastercard)
    "00111": ["434070", "552641"],          # QNB Finansbank (Visa, Mastercard)
    "00125": ["520418", "479240"],          # Denizbank (Mastercard, Visa)
    "00205": ["421880", "552083"],          # Kuveyt Türk (Visa, Mastercard)
    "00206": ["409549", "552986"],          # Türkiye Finans (Visa, Mastercard)
}

def analyze_iban(iban: str) -> dict:
    iban = iban.strip().replace(" ", "").upper()
    result = {
        "iban": iban, "is_valid": False, "country_code": None, "bank_code": None,
        "bank_name": "Bilinmiyor", "branch_code": None, "account_number": None, "error": None,
        "example_bins": []
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
        if result["bank_code"] in TR_BANK_EXAMPLE_BINS:
            result["example_bins"] = TR_BANK_EXAMPLE_BINS[result["bank_code"]]
    else:
        result["bank_name"] = "Sadece Türkiye IBAN'ları için banka bilgisi gösterilir."

    return result

def bin_lookup(bin_number: str) -> dict:
    if not REQUESTS_OK:
        raise RuntimeError("requests kütüphanesi kurulu değil")

    # Clean and validate BIN
    bin_clean = re.sub(r"[^0-9]", "", bin_number.strip())
    if not (6 <= len(bin_clean) <= 8):
        raise ValueError("Geçersiz BIN. Lütfen kartın ilk 6-8 hanesini girin.")

    try:
        r = requests.get(f"https://lookup.binlist.net/{bin_clean}", headers=UA, timeout=10)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"API bağlantı hatası: {e}")

    if r.status_code == 404:
        raise RuntimeError("BIN bulunamadı veya geçersiz.")
    if r.status_code == 429:
        raise RuntimeError("API rate limit'e ulaşıldı. Lütfen bir süre sonra tekrar deneyin.")

    r.raise_for_status()

    try:
        data = r.json()
    except json.JSONDecodeError:
        raise RuntimeError("API'den geçersiz yanıt alındı (JSON parse edilemedi).")

    country = data.get("country", {}) or {}
    bank = data.get("bank", {}) or {}

    return {
        "bin": bin_clean,
        "scheme": data.get("scheme", "-").capitalize(),
        "type": data.get("type", "-").capitalize(),
        "brand": data.get("brand", "-"),
        "country_name": f"{country.get('name', '-')} ({country.get('alpha2', '-')})",
        "bank_name": bank.get("name", "-"),
        "bank_url": bank.get("url", "-"),
        "bank_phone": bank.get("phone", "-"),
        "prepaid": data.get("prepaid", False),
    }

# ================= GUI =================

class SplashScreen(tk.Toplevel):
    """
    Açılış ekranı. Ana pencere yüklenirken gösterilir.
    """
    # Not: Bu sınıfın içinde ICON_BASE64'ün global olarak tanımlı olduğu varsayılır.
    # Ana uygulama bu değişkeni betiğin sonunda tanımlar.
    # Eğer bu dosya tek başına çalıştırılırsa veya ikon datası eksikse,
    # try-except bloğu hatayı yakalayıp ikonsuz devam edecektir.
    # Bu, modülerlik ve potansiyel yeniden kullanılabilirlik için bir tasarım notudur.

    def __init__(self, parent):
        tk.Toplevel.__init__(self, parent)
        self.overrideredirect(True)

        theme = parent.theme

        main_frame = tk.Frame(self, bg=theme["BORDER"])
        main_frame.pack(padx=1, pady=1)

        content_frame = tk.Frame(main_frame, bg=theme["PANEL"], padx=60, pady=40)
        content_frame.pack()

        # Try to load and display the icon
        try:
            # Assuming ICON_BASE64 is defined globally, which the main app does
            icon_data = base64.b64decode(ICON_BASE64)
            self.icon = tk.PhotoImage(data=icon_data)
            tk.Label(content_frame, image=self.icon, bg=theme["PANEL"]).pack(pady=(0, 20))
        except (NameError, tk.TclError, Exception):
            # If ICON_BASE64 is not defined or image fails to load, just skip it
            pass

        header = tk.Frame(content_frame, bg=theme["PANEL"])
        header.pack()
        tk.Label(header, text="GHOST", font=FONT_TITLE, bg=theme["PANEL"], fg=theme["RED"]).pack(side="left")
        tk.Label(header, text=" OSINT FRAMEWORK", font=FONT_TITLE, bg=theme["PANEL"], fg=theme["FG"]).pack(side="left")

        tk.Label(content_frame, text="Yükleniyor...", font=FONT, bg=theme["PANEL"], fg=theme["FG_DIM"]).pack(pady=(25, 0))

        self.update_idletasks()
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        splash_w = self.winfo_width()
        splash_h = self.winfo_height()
        x = (screen_w // 2) - (splash_w // 2)
        y = (screen_h // 2) - (splash_h // 2)
        self.geometry(f"{splash_w}x{splash_h}+{x}+{y}")

        self.lift()
        self.update()

class GhostOSINT(tk.Tk):
    def __init__(self):
        # --- Ön Kontrol ---
        # Temel bağımlılıklar olmadan GUI'yi başlatmanın anlamı yok.
        if not REQUESTS_OK:
            # Tkinter'ı başlatmadan önce bir hata mesajı göster
            root = tk.Tk()
            root.withdraw() # Ana pencereyi gizle
            messagebox.showerror("Kritik Hata: Bağımlılık Eksik", "'requests' kütüphanesi bulunamadı.\n\nLütfen `GhostOSINT-Installer.bat` dosyasını çalıştırarak gerekli kurulumları yapın.")
            root.destroy()
            return

        super().__init__()
        self.withdraw() # Ana pencereyi başlangıçta gizle

        # Splash screen'in teması için temel ayarları önden yükle
        self.app_config = load_config()
        self.current_theme_name = "Ghost Dark"
        self.theme = THEMES[self.current_theme_name].copy()

        # Açılış ekranını göster
        splash = SplashScreen(self)

        # --- Tam Başlatma ---
        self.title(f"GHOST OSINT FRAMEWORK {CURRENT_VERSION} (Alpha) — by TarikPro43391")

        self.tracked_widgets = []
        self.nb = None
        self.report_is_dirty = False
        self.tab_results = {}
        self.tab_defs = []
        self.found_subdomains = []

        try:
            # ICON_BASE64 global olarak tanımlı olmalı
            icon_data = base64.b64decode(ICON_BASE64) 
            self.icon = tk.PhotoImage(data=icon_data)
            self.iconphoto(True, self.icon)
        except Exception:
            pass # İkon yüklenemezse sorun değil, varsayılan ikon kullanılır.

        self.geometry("1020x720")
        self.minsize(920, 600)

        self._build_menu()
        self.output_widgets = {}

        self.configure(bg=self.theme["BG"])
        self._build_style()
        self._build_header()
        self._build_tabs()
        self._build_statusbar()
        self._check_for_updates()
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Başlatma tamamlandı, splash'i kapat ve ana pencereyi göster
        self.update_idletasks()
        splash.destroy()
        self._start_fade_in()

    # ---------- MENU ----------
    def _build_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ayarlar", menu=settings_menu)

        self.theme_menu = tk.Menu(settings_menu, tearoff=0)
        settings_menu.add_cascade(label="Tema", menu=self.theme_menu)

        for theme_name in THEMES:
            self.theme_menu.add_command(
                label=theme_name,
                command=lambda t=theme_name: self._apply_theme(t)
            )
        
        settings_menu.add_separator()
        settings_menu.add_command(label="Tema Editörü...", command=self._show_theme_editor_window)
        settings_menu.add_command(label="Sekme Yöneticisi...", command=self._show_tab_manager_window)
        settings_menu.add_separator()
        settings_menu.add_command(label="Hakkında", command=self._show_about_window)
        settings_menu.add_command(label="GitHub'da Görüntüle", command=lambda: webbrowser.open("https://github.com/TarikPro43391/GhostOSINT"))

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

        style.configure("TCheckbutton",
                        background=self.theme["PANEL"],
                        foreground=self.theme["FG"],
                        indicatorcolor=self.theme["BORDER"],
                        font=FONT)
        style.map("TCheckbutton", background=[("active", self.theme["PANEL2"])])

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
        # Daha kapsamlı bir bağımlılık özeti
        dep_map = { "requests": REQUESTS_OK, "dnspython": DNSPYTHON_OK, "phonenumbers": PHONENUMBERS_OK,
                    "Pillow": PIL_OK, "OpenCV": CV2_OK, "Playwright": PLAYWRIGHT_OK, "PDF": XHTML2PDF_OK }
        
        for name, status in dep_map.items():
            if not status:
                deps.append(f"{name} EKSİK")
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

        # Filter tab definitions based on config
        visible_tab_names = self.app_config.get("visible_tabs", [name for name, _ in ALL_TAB_DEFS])
        self.tab_defs = [t for t in ALL_TAB_DEFS if t[0] in visible_tab_names]

        for name, text in self.tab_defs:
            tab_frame = tk.Frame(nb, bg=self.theme["BG"])
            self.tracked_widgets.append((tab_frame, {"bg": "BG"}))
            setattr(self, f"tab_{name}", tab_frame)
            nb.add(tab_frame, text=text)

        # Call build methods only for visible tabs
        for name, _ in self.tab_defs:
            build_method = getattr(self, f"_build_{name}_tab", None)
            if build_method:
                build_method()

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
                self.after(0, lambda e=e: on_done(None, e))
        threading.Thread(target=worker, daemon=True).start()

    def _format_error_message(self, err: Exception) -> str:
        """Formats common exceptions into user-friendly messages."""
        err_str = str(err)
        
        # 1. Handle requests' ConnectionError for DNS issues
        if (isinstance(err, requests.exceptions.ConnectionError) and 
            ('getaddrinfo failed' in err_str.lower() or "name or service not known" in err_str.lower())):
            match = re.search(r"host='([^']*)'", err_str)
            host = match.group(1) if match else "belirtilen host"
            return (
                f"Host ('{host}') çözülemedi veya ulaşılamadı.\n\n"
                "Bu hata genellikle şu nedenlerden kaynaklanır:\n"
                " - Domain/IP adresi yanlış yazılmış.\n"
                " - Domain adı mevcut değil veya süresi dolmuş.\n"
                " - İnternet bağlantınızda veya DNS ayarlarınızda bir sorun var."
            )

        # 2. Handle our custom RuntimeErrors for socket issues (already user-friendly)
        if isinstance(err, RuntimeError) and "Host" in err_str and "çözülemedi" in err_str:
            return err_str

        # 3. Handle generic Timeout
        if isinstance(err, (requests.exceptions.Timeout, socket.timeout)):
            return "İstek zaman aşımına uğradı. Sunucu yavaş, ulaşılamıyor veya bir firewall tarafından engelleniyor olabilir."

        # 4. Handle other common request errors
        if isinstance(err, requests.exceptions.RequestException):
            return f"Bir ağ/bağlantı hatası oluştu.\n\nDetay: {err}"

        # 5. Default fallback for other exceptions
        return str(err)

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

    def _start_fade_in(self):
        """Starts the main window fade-in animation."""
        self.attributes('-alpha', 0.0)
        self.deiconify()
        self.alpha = 0.0
        self._fade_in_step()

    def _fade_in_step(self):
        self.alpha += 0.05
        if self.alpha >= 1.0:
            self.attributes('-alpha', 1.0)
            return
        self.attributes('-alpha', self.alpha)
        self.after(25, self._fade_in_step)

    def _update_ui_from_theme(self):
        """Applies the colors from the current self.theme dict to all tracked widgets."""
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

    def _apply_theme(self, theme_name):
        if theme_name not in THEMES or theme_name == self.current_theme_name:
            return
        self.current_theme_name = theme_name
        self.theme = THEMES[theme_name].copy()
        self._update_ui_from_theme()
        self.set_status(f"Tema '{theme_name}' olarak değiştirildi.")

    def _export_report(self):
        if not self.report_is_dirty:
            messagebox.showinfo("Bilgi", "Rapor oluşturulacak herhangi bir çıktı bulunamadı.")
            return

        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[
                    ("Metin Dosyası", "*.txt"),
                    ("JSON Dosyası", "*.json"),
                    ("CSV Dosyası", "*.csv"),
                    ("HTML Dosyası", "*.html"),
                    ("PDF Dosyası", "*.pdf"),
                    ("Tüm Dosyalar", "*.*")
                ],
                title="Raporu Kaydet",
                initialfile=f"ghost_osint_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            if not file_path:
                return

            _, extension = os.path.splitext(file_path)
            if extension.lower() == ".json":
                self._export_as_json(file_path)
            elif extension.lower() == ".csv":
                self._export_as_csv(file_path)
            elif extension.lower() == ".html":
                self._export_as_html(file_path)
            elif extension.lower() == ".pdf":
                self._export_as_pdf(file_path)
            else: # Default to TXT
                self._export_as_txt(file_path)

            self.set_status(f"Rapor başarıyla kaydedildi.")
            messagebox.showinfo("Başarılı", f"Rapor başarıyla kaydedildi:\n{file_path}")
            self.report_is_dirty = False
        except Exception as e:
            messagebox.showerror("Hata", f"Rapor kaydedilirken bir hata oluştu:\n{e}")
            self.set_status("Rapor kaydetme başarısız.")

    def _export_as_txt(self, file_path):
        report_lines = []
        report_lines.append("================================================")
        report_lines.append(" GHOST OSINT FRAMEWORK - Toplu Rapor")
        report_lines.append(f" Rapor Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("================================================\n")

        tab_order = [text for name, text in self.tab_defs]
        for tab_name in tab_order:
            if tab_name in self.output_widgets:
                widget = self.output_widgets[tab_name]
                content = widget.get("1.0", "end-1c").strip()
                if content:
                    report_lines.append(f"########## {tab_name.upper()} ##########\n")
                    report_lines.append(content)
                    report_lines.append("\n\n")

        report_content = "".join(report_lines)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(report_content)

    def _export_as_json(self, file_path):
        report_data = {
            "report_metadata": {
                "tool": f"GHOST OSINT FRAMEWORK {CURRENT_VERSION}",
                "generated_at_utc": datetime.now(timezone.utc).isoformat()
            },
            "results": self.tab_results
        }
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)

    def _export_as_csv(self, file_path):
        rows = []
        header = ['Modül', 'Girdi', 'Kategori', 'Anahtar', 'Değer']
        rows.append(header)

        for module_name, data in sorted(self.tab_results.items()):
            input_val = str(data.get("input", ""))
            
            for category, result_data in data.items():
                if category == "input":
                    continue

                # Case 1: Result is a dictionary (e.g., IP Lookup, SSL Cert)
                if isinstance(result_data, dict):
                    for key, value in result_data.items():
                        if not isinstance(value, (list, dict)):
                            rows.append([module_name, input_val, category, key, str(value)])

                # Case 2: Result is a list
                elif isinstance(result_data, list):
                    for item in result_data:
                        if isinstance(item, dict):
                            sub_category_key = item.get("platform") or item.get("id") or category
                            for key, value in item.items():
                                rows.append([module_name, input_val, sub_category_key, key, str(value)])
                        else:
                            rows.append([module_name, input_val, category, "item", str(item)])
                
                # Case 3: Result is a simple value (e.g., WHOIS result)
                else:
                    rows.append([module_name, input_val, category, "result", str(result_data)])
        
        try:
            with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerows(rows)
        except Exception as e:
            raise IOError(f"CSV dosyası yazılırken hata oluştu: {e}")

    def _export_as_html(self, file_path):
        html_content = self._generate_html_report_content()
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)

    def _export_as_pdf(self, file_path):
        if not XHTML2PDF_OK:
            raise RuntimeError("PDF oluşturmak için 'xhtml2pdf' kütüphanesi gereklidir.\n\nLütfen kurun: pip install xhtml2pdf")

        self.set_status("HTML rapor içeriği oluşturuluyor...")
        html_content = self._generate_html_report_content()
        self.set_status("PDF dosyası oluşturuluyor (bu işlem biraz sürebilir)...")

        with open(file_path, "w+b") as f:
            pisa_status = pisa.CreatePDF(
                html_content,
                dest=f,
                encoding='utf-8'
            )

        if pisa_status.err:
            raise RuntimeError(f"PDF oluşturma hatası. Kod: {pisa_status.err}. Rapor çok büyük veya karmaşık olabilir.")

    def _generate_html_report_content(self):
        import html as html_escaper
        theme = self.theme

        def linkify(text):
            text = html_escaper.escape(str(text))
            url_pattern = re.compile(r'(https?://[^\s"\'<>]+)')
            return url_pattern.sub(r'<a href="\1" target="_blank">\1</a>', text)

        def build_kv_table(data_dict):
            if not isinstance(data_dict, dict):
                return f"<pre>{linkify(data_dict)}</pre>"
            table_html = "<table class='kv-table'>"
            for key, value in data_dict.items():
                if isinstance(value, (list, dict)):
                    value_str = json.dumps(value, indent=2, ensure_ascii=False)
                    value_str = f"<pre>{linkify(value_str)}</pre>"
                else:
                    value_str = linkify(value)
                table_html += f"<tr><th>{html_escaper.escape(str(key).replace('_', ' ').title())}</th><td>{value_str}</td></tr>"
            table_html += "</table>"
            return table_html

        def build_list_table(data_list):
            if not data_list:
                return "<p>Sonuç bulunamadı.</p>"
            if not isinstance(data_list[0], dict):
                items = "".join(f"<li>{linkify(item)}</li>" for item in data_list)
                return f"<ul>{items}</ul>"

            headers = list(data_list[0].keys())
            table_html = "<table><thead><tr>"
            for header in headers:
                table_html += f"<th>{html_escaper.escape(str(header).replace('_', ' ').title())}</th>"
            table_html += "</tr></thead><tbody>"
            for row_dict in data_list:
                table_html += "<tr>"
                for header in headers:
                    value = row_dict.get(header, "-")
                    table_html += f"<td>{linkify(value)}</td>"
                table_html += "</tr>"
            table_html += "</tbody></table>"
            return table_html

        html_content = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>GHOST OSINT Raporu</title>
    <style>
        body {{ font-family: "Segoe UI", sans-serif; background-color: {theme['BG']}; color: {theme['FG']}; line-height: 1.6; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; background-color: {theme['PANEL']}; border: 1px solid {theme['BORDER']}; border-radius: 8px; }}
        h1, h2 {{ color: {theme['RED']}; border-bottom: 2px solid {theme['BORDER']}; padding-bottom: 10px; }}
        h1 {{ font-size: 2em; }}
        h2 {{ font-size: 1.5em; margin-top: 40px; }}
        h3 {{ font-size: 1.2em; color: {theme['FG_DIM']}; margin-top: 25px; border-bottom: 1px solid {theme['BORDER']}; padding-bottom: 5px;}}
        .module-section {{ padding: 20px; margin-bottom: 20px; background-color: {theme['PANEL2']}; border-radius: 5px; overflow-x: auto; }}
        .input-val {{ font-family: "Consolas", monospace; color: {theme['FG_DIM']}; background-color: {theme['BG']}; padding: 2px 6px; border-radius: 3px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px 15px; border: 1px solid {theme['BORDER']}; text-align: left; word-break: break-word; }}
        th {{ background-color: {theme['BG']}; font-weight: bold; }}
        table.kv-table th {{ font-weight: bold; color: {theme['FG_DIM']}; width: 25%; }}
        pre {{ background-color: {theme['BG']}; color: {theme['FG']}; padding: 15px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; }}
        a {{ color: {theme['BLUE']}; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .meta {{ font-size: 0.9em; color: {theme['FG_DIM']}; margin-bottom: 30px; }}
    </style>
</head>
<body><div class="container">
<h1>GHOST OSINT FRAMEWORK Raporu</h1>
<p class="meta">Oluşturulma Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
"""
        for module_name, data in sorted(self.tab_results.items()):
            input_val = data.get("input", "")
            html_content += f"<h2>{html_escaper.escape(module_name)}</h2><div class='module-section'>"
            if input_val:
                html_content += f"<p><strong>Girdi:</strong> <span class='input-val'>{html_escaper.escape(str(input_val))}</span></p>"
            for category, result_data in data.items():
                if category == "input": continue
                html_content += f"<h3>{html_escaper.escape(category.replace('_', ' ').title())}</h3>"
                if isinstance(result_data, dict): html_content += build_kv_table(result_data)
                elif isinstance(result_data, list): html_content += build_list_table(result_data)
                else: html_content += f"<pre>{linkify(result_data)}</pre>"
            html_content += "</div>"
        html_content += "</div></body></html>"
        return html_content

    def _clear_all_outputs(self):
        if not self.report_is_dirty:
            self.set_status("Temizlenecek bir çıktı yok.")
            return

        if messagebox.askyesno("Tüm Çıktıları Temizle", "Tüm sekmelerdeki sonuçlar kalıcı olarak silinecek. Bu işlem geri alınamaz.\n\nDevam etmek istiyor musunuz?"):
            for box in self.output_widgets.values():
                box.configure(state="normal")
                box.delete("1.0", "end")
                box.configure(state="disabled")
            self.tab_results.clear()
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

    # ================= THEME EDITOR =================
    def _save_custom_theme(self):
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON Theme Files", "*.json"), ("All files", "*.*")],
                title="Özel Temayı Kaydet",
                initialfile=f"{self.current_theme_name.replace(' ', '_')}_custom.json"
            )
            if not file_path:
                return

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(self.theme, f, indent=4)

            self.set_status(f"Tema başarıyla '{os.path.basename(file_path)}' dosyasına kaydedildi.")
            messagebox.showinfo("Başarılı", "Tema başarıyla kaydedildi.")
        except Exception as e:
            messagebox.showerror("Hata", f"Tema kaydedilirken bir hata oluştu:\n{e}")

    def _load_custom_theme(self, parent_window=None):
        try:
            file_path = filedialog.askopenfilename(
                defaultextension=".json",
                filetypes=[("JSON Theme Files", "*.json"), ("All files", "*.*")],
                title="Özel Tema Yükle"
            )
            if not file_path:
                return

            with open(file_path, "r", encoding="utf-8") as f:
                loaded_theme = json.load(f)

            # Validation
            if not isinstance(loaded_theme, dict):
                raise ValueError("Tema dosyası geçerli bir JSON nesnesi (sözlük) içermiyor.")
            required_keys = set(THEMES["Ghost Dark"].keys())
            if not required_keys.issubset(loaded_theme.keys()):
                missing_keys = required_keys - set(loaded_theme.keys())
                raise ValueError(f"Tema dosyasında eksik anahtarlar var: {', '.join(missing_keys)}")

            # Add and Apply Theme
            theme_name = os.path.splitext(os.path.basename(file_path))[0]
            theme_name = theme_name.replace("_", " ").replace("-", " ").title()

            if theme_name not in THEMES:
                THEMES[theme_name] = loaded_theme
                self.theme_menu.add_command(
                    label=theme_name,
                    command=lambda t=theme_name: self._apply_theme(t)
                )
            else: # Update existing theme if name matches
                THEMES[theme_name] = loaded_theme

            self._apply_theme(theme_name)
            self.set_status(f"Özel tema '{theme_name}' yüklendi ve uygulandı.")

            if parent_window and parent_window.winfo_exists():
                parent_window.destroy()
                self._show_theme_editor_window()

        except json.JSONDecodeError:
            messagebox.showerror("Hata", "Tema dosyası geçerli bir JSON formatında değil.")
        except Exception as e:
            messagebox.showerror("Hata", f"Tema yüklenirken bir hata oluştu:\n{e}")

    def _get_contrasting_fg(self, hex_color):
        """Calculates a contrasting foreground color (black or white) for a given background hex color."""
        try:
            if not hex_color.startswith('#') or len(hex_color) != 7:
                return "#000000"
            r = int(hex_color[1:3], 16)
            g = int(hex_color[3:5], 16)
            b = int(hex_color[5:7], 16)
            # Formula for luminance (per W3C)
            luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255
            return "#000000" if luminance > 0.5 else "#FFFFFF"
        except (ValueError, TypeError):
            return "#000000"

    def _show_theme_editor_window(self):
        from tkinter import colorchooser

        editor_win = tk.Toplevel(self)
        editor_win.title("Tema Editörü")
        editor_win.configure(bg=self.theme["PANEL"], padx=20, pady=15)
        editor_win.resizable(False, False)

        # Center window
        self.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - (editor_win.winfo_reqwidth() // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (editor_win.winfo_reqheight() // 2)
        editor_win.geometry(f"+{x}+{y}")

        tk.Label(editor_win, text=f"Mevcut Tema: {self.current_theme_name}", font=FONT_B, bg=self.theme["PANEL"], fg=self.theme["FG"]).pack(pady=(0, 15))

        color_labels = {}

        def change_color(key):
            current_color = self.theme[key]
            new_color = colorchooser.askcolor(color=current_color, title=f"'{key}' için renk seç")

            if new_color and new_color[1]:
                hex_color = new_color[1]
                self.theme[key] = hex_color
                color_labels[key].config(text=hex_color, bg=hex_color, fg=self._get_contrasting_fg(hex_color))
                self._update_ui_from_theme()
                self.set_status(f"Tema rengi '{key}' güncellendi.")

        grid_frame = tk.Frame(editor_win, bg=self.theme["PANEL"])
        grid_frame.pack()

        sorted_keys = sorted(self.theme.keys())
        for i, key in enumerate(sorted_keys):
            color = self.theme[key]
            tk.Label(grid_frame, text=f"{key}:", font=FONT, bg=self.theme["PANEL"], fg=self.theme["FG_DIM"]).grid(row=i, column=0, sticky="w", padx=5, pady=3)
            lbl = tk.Label(grid_frame, text=color, font=FONT_MONO, bg=color, fg=self._get_contrasting_fg(color), width=10, relief="groove", borderwidth=2)
            lbl.grid(row=i, column=1, padx=5, pady=3)
            color_labels[key] = lbl
            btn = ttk.Button(grid_frame, text="Değiştir", command=lambda k=key: change_color(k), style="Blue.TButton")
            btn.grid(row=i, column=2, padx=5, pady=3)

        def reset_theme():
            self.theme = THEMES[self.current_theme_name].copy()
            self._update_ui_from_theme()
            editor_win.destroy()
            self._show_theme_editor_window()
            self.set_status(f"Tema '{self.current_theme_name}' orijinal haline sıfırlandı.")

        button_frame = tk.Frame(editor_win, bg=self.theme["PANEL"])
        button_frame.pack(pady=(20, 0), fill="x")

        ttk.Button(button_frame, text="Temayı Kaydet...", command=self._save_custom_theme).pack(side="left", expand=True, padx=2)
        ttk.Button(button_frame, text="Tema Yükle...", command=lambda: self._load_custom_theme(editor_win), style="Blue.TButton").pack(side="left", expand=True, padx=2)
        ttk.Button(button_frame, text="Temayı Sıfırla", command=reset_theme).pack(side="left", expand=True, padx=2)

        editor_win.transient(self)
        editor_win.grab_set()
        self.wait_window(editor_win)

    def _show_tab_manager_window(self):
        manager_win = tk.Toplevel(self)
        manager_win.title("Sekme Yöneticisi")
        manager_win.configure(bg=self.theme["PANEL"], padx=20, pady=15)
        manager_win.resizable(False, False)

        # Center window
        self.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - (manager_win.winfo_reqwidth() // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (manager_win.winfo_reqheight() // 2)
        manager_win.geometry(f"+{x}+{y}")

        tk.Label(manager_win, text="Görünecek Sekmeleri Seçin", font=FONT_B, bg=self.theme["PANEL"], fg=self.theme["FG"]).pack(pady=(0, 15))

        tab_vars = {}
        frame = tk.Frame(manager_win, bg=self.theme["PANEL"])
        frame.pack()

        # Create two columns of checkboxes
        num_tabs = len(ALL_TAB_DEFS)
        mid_point = (num_tabs + 1) // 2
        
        col1 = tk.Frame(frame, bg=self.theme["PANEL"])
        col1.pack(side="left", padx=10, anchor="n")
        col2 = tk.Frame(frame, bg=self.theme["PANEL"])
        col2.pack(side="left", padx=10, anchor="n")

        for i, (name, text) in enumerate(ALL_TAB_DEFS):
            parent_col = col1 if i < mid_point else col2
            var = tk.BooleanVar(value=(name in self.app_config["visible_tabs"]))
            tab_vars[name] = var
            chk = ttk.Checkbutton(parent_col, text=text, variable=var, style="TCheckbutton")
            chk.pack(anchor="w", pady=2)

        def save_and_close():
            self.app_config["visible_tabs"] = [name for name, var in tab_vars.items() if var.get()]
            save_config(self.app_config)
            messagebox.showinfo(
                "Kaydedildi", 
                "Ayarlar kaydedildi.\n\nDeğişikliklerin etkili olması için lütfen uygulamayı yeniden başlatın.", 
                parent=manager_win
            )
            manager_win.destroy()

        button_frame = tk.Frame(manager_win, bg=self.theme["PANEL"])
        button_frame.pack(pady=(20, 0), fill="x")
        ttk.Button(button_frame, text="Kaydet ve Kapat", command=save_and_close, style="Blue.TButton").pack()

        manager_win.transient(self)
        manager_win.grab_set()
        self.wait_window(manager_win)

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
            self.tab_results.setdefault("DISCORD ID", {"input": raw})["snowflake"] = info
            self.set_status("Snowflake decode tamamlandı.")
        except Exception as e:
            messagebox.showerror("Hata", self._format_error_message(e))

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
                messagebox.showerror("Hata", self._format_error_message(err))
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
            self.tab_results.setdefault("DISCORD ID", {"input": raw_id})["profile"] = result
            self.set_status("Discord public profil alındı.")

        self._run_async(task, done)

    # ================= IP TAB =================
    def _build_ip_tab(self):
        t = self.tab_ip
        self.ip_entry = self._labeled_entry(t, "IP Adresi:")
        ttk.Button(t, text="IP SORGULA (ip-api.com)", command=self._on_ip_lookup).pack(anchor="w", pady=6)
        
        # Separator

        self.ip_output = self._output_box(t, tab_name="IP LOOKUP")

    def _on_ip_lookup(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Hata", "IP adresi girin.")
            return
        self.set_status("IP sorgulanıyor...")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", self._format_error_message(err))
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
            self.tab_results.setdefault("IP LOOKUP", {"input": ip})["ip-api"] = result
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
                messagebox.showerror("Hata", self._format_error_message(err))
                return
            a = "\n  ".join(result["A"]) or "Bulunamadı"
            mx = "\n  ".join(result["MX"]) or ("Bulunamadı" if DNSPYTHON_OK else "(dnspython kurulu değil)")
            out = f"[DNS: {domain}]\nA Kayıtları:\n  {a}\n\nMX Kayıtları:\n  {mx}\n"
            if result["raw_error"]:
                out += f"\nHata: {result['raw_error']}\n"
            self._write(self.domain_output, out)
            self.tab_results.setdefault("DOMAIN / DNS", {"input": domain})["dns"] = result
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
                messagebox.showerror("Hata", self._format_error_message(err))
                return
            self._write(self.domain_output, result)
            self.tab_results.setdefault("DOMAIN / DNS", {"input": domain})["whois"] = result
            self.set_status("WHOIS sorgu tamamlandı.")

        self._run_async(lambda: whois_lookup(domain), done)

    # ================= REPUTATION TAB =================
    def _save_abuseipdb_key(self):
        key = self.abuseipdb_key_entry.get().strip()
        self.app_config["abuseipdb_api_key"] = key
        save_config(self.app_config)
        self.set_status("AbuseIPDB API anahtarı kaydedildi.")

    def _save_virustotal_key(self):
        key = self.virustotal_key_entry.get().strip()
        self.app_config["virustotal_api_key"] = key
        save_config(self.app_config)
        self.set_status("VirusTotal API anahtarı kaydedildi.")

    def _build_reputation_tab(self):
        t = self.tab_reputation
        self.reputation_entry = self._labeled_entry(t, "IP / Domain:")
        ttk.Button(t, text="İTİBAR SORGULA", command=self._on_reputation_lookup).pack(anchor="w", pady=6)

        l_sep = tk.Label(t, text="─── API Anahtarları ───", bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9))
        l_sep.pack(fill="x", pady=(14, 2))
        self.tracked_widgets.append((l_sep, {"bg": "BG", "fg": "FG_DIM"}))

        # AbuseIPDB API Key
        key_row1 = tk.Frame(t, bg=self.theme["BG"])
        key_row1.pack(fill="x", pady=4)
        self.tracked_widgets.append((key_row1, {"bg": "BG"}))
        l1 = tk.Label(key_row1, text="AbuseIPDB API Key:", bg=self.theme["BG"], fg=self.theme["FG"], font=FONT, width=18, anchor="w")
        l1.pack(side="left")
        self.tracked_widgets.append((l1, {"bg": "BG", "fg": "FG"}))
        self.abuseipdb_key_entry = ttk.Entry(key_row1, width=40, font=FONT_MONO, show="*")
        self.abuseipdb_key_entry.pack(side="left", padx=6, fill="x", expand=True)
        self.abuseipdb_key_entry.insert(0, self.app_config.get("abuseipdb_api_key", ""))
        ttk.Button(key_row1, text="Kaydet", command=self._save_abuseipdb_key, style="Clear.TButton").pack(side="right", padx=(0, 6))

        # VirusTotal API Key
        key_row2 = tk.Frame(t, bg=self.theme["BG"])
        key_row2.pack(fill="x", pady=4)
        self.tracked_widgets.append((key_row2, {"bg": "BG"}))
        l2 = tk.Label(key_row2, text="VirusTotal API Key:", bg=self.theme["BG"], fg=self.theme["FG"], font=FONT, width=18, anchor="w")
        l2.pack(side="left")
        self.tracked_widgets.append((l2, {"bg": "BG", "fg": "FG"}))
        self.virustotal_key_entry = ttk.Entry(key_row2, width=40, font=FONT_MONO, show="*")
        self.virustotal_key_entry.pack(side="left", padx=6, fill="x", expand=True)
        self.virustotal_key_entry.insert(0, self.app_config.get("virustotal_api_key", ""))
        ttk.Button(key_row2, text="Kaydet", command=self._save_virustotal_key, style="Clear.TButton").pack(side="right", padx=(0, 6))

        self.reputation_output = self._output_box(t, tab_name="İTİBAR KONTROLÜ")

    def _on_reputation_lookup(self):
        target = self.reputation_entry.get().strip()
        if not target:
            messagebox.showerror("Hata", "IP adresi veya domain girin.")
            return

        is_ip = re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", target) or ':' in target

        if is_ip:
            api_key = self.abuseipdb_key_entry.get().strip()
            if not api_key:
                messagebox.showerror("Hata", "IP itibarı için AbuseIPDB API anahtarı gereklidir.")
                return
            self.set_status(f"AbuseIPDB'de '{target}' sorgulanıyor...")
            self._write(self.reputation_output, f"AbuseIPDB'de '{target}' sorgulanıyor, lütfen bekleyin...\n")

            def done(result, err):
                if err:
                    messagebox.showerror("Hata", self._format_error_message(err))
                    self.set_status("AbuseIPDB sorgusu başarısız.")
                    return
                
                score = result.get('abuseConfidenceScore', 0)
                score_color = "KÖTÜ ✗" if score > 50 else ("ŞÜPHELİ ⚠" if score > 0 else "TEMİZ ✓")
                out = (
                    f"[ABUSEIPDB RAPORU: {result.get('ipAddress')}]\n"
                    f"İtibar Skoru      : {score}% ({score_color})\n"
                    f"IP Versiyonu      : IPv{result.get('ipVersion')}\n"
                    f"Kullanım Tipi     : {result.get('usageType') or '-'}\n"
                    f"Domain            : {result.get('domain') or '-'}\n"
                    f"ISP               : {result.get('isp') or '-'}\n"
                    f"Ülke              : {result.get('countryName')} ({result.get('countryCode')})\n"
                    f"Whitelist'te mi?  : {'Evet' if result.get('isWhitelisted') else 'Hayır'}\n"
                    f"Toplam Rapor Sayısı: {result.get('totalReports', 0)}\n"
                    f"Farklı Raporlayan : {result.get('numDistinctUsers', 0)}\n"
                    f"Son Rapor Tarihi  : {result.get('lastReportedAt') or '-'}\n\n"
                    f"Detaylı bilgi için: https://www.abuseipdb.com/check/{result.get('ipAddress')}\n"
                )
                self._write(self.reputation_output, out)
                self.tab_results.setdefault("İTİBAR KONTROLÜ", {"input": target})["abuseipdb"] = result
                self.set_status("AbuseIPDB sorgusu tamamlandı.")

            self._run_async(lambda: abuseipdb_check(target, api_key), done)
        else:
            api_key = self.virustotal_key_entry.get().strip()
            if not api_key:
                messagebox.showerror("Hata", "Domain itibarı için VirusTotal API anahtarı gereklidir.")
                return
            self.set_status(f"VirusTotal'de '{target}' sorgulanıyor...")
            self._write(self.reputation_output, f"VirusTotal'de '{target}' sorgulanıyor, lütfen bekleyin...\n")

            def done(result, err):
                if err:
                    messagebox.showerror("Hata", self._format_error_message(err))
                    self.set_status("VirusTotal sorgusu başarısız.")
                    return

                if not result.get('found'):
                    out = f"[VIRUSTOTAL RAPORU: {target}]\n\nVirusTotal veritabanında bu domain için bir kayıt bulunamadı."
                    self._write(self.reputation_output, out)
                    self.set_status("VirusTotal sorgusu tamamlandı (kayıt yok).")
                    return

                stats = result.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total_vendors = sum(stats.values())
                
                status = "TEMİZ ✓"
                if malicious > 0:
                    status = "ZARARLI ✗"
                elif suspicious > 0:
                    status = "ŞÜPHELİ ⚠"

                last_analysis_date_str = (datetime.fromtimestamp(result.get('last_analysis_date', 0)).strftime('%Y-%m-%d %H:%M:%S')
                                          if result.get('last_analysis_date') else '-')

                out = (
                    f"[VIRUSTOTAL RAPORU: {result.get('domain')}]\n"
                    f"Genel Durum       : {status}\n"
                    f"Tespit Oranı      : {malicious + suspicious} / {total_vendors}\n"
                    f"  - Zararlı       : {malicious}\n"
                    f"  - Şüpheli       : {suspicious}\n"
                    f"  - Zararsız      : {stats.get('harmless', 0)}\n"
                    f"  - Tespit Edilemedi: {stats.get('undetected', 0)}\n"
                    f"Son Analiz Tarihi : {last_analysis_date_str}\n"
                    f"Popülerlik Sırası : {result.get('popularity_ranks', {}).get('Alexa', {}).get('rank', '-') or '-' } (Alexa)\n\n"
                    f"Detaylı bilgi için: https://www.virustotal.com/gui/domain/{result.get('domain')}\n"
                )
                self._write(self.reputation_output, out)
                self.tab_results.setdefault("İTİBAR KONTROLÜ", {"input": target})["virustotal"] = result
                self.set_status("VirusTotal sorgusu tamamlandı.")

            self._run_async(lambda: virustotal_domain_report(target, api_key), done)

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
                messagebox.showerror("Hata", self._format_error_message(err))
                return
            lines = [f"[USERNAME SEARCH: {username}]\n"]
            for name, status, url in results:
                mark = "✓" if status == "BULUNDU" else ("✗" if status == "YOK" else "?")
                lines.append(f"[{mark}] {name:<12} {status:<10} {url}")
            self._write(self.username_output, "\n".join(lines))
            results_as_dict = [{"platform": name, "status": status, "url": url} for name, status, url in results]
            self.tab_results["USERNAME"] = {"input": username, "output": results_as_dict}
            self.set_status("Username arama tamamlandı.")

        self._run_async(task, done)

    # ================= EMAIL TAB =================
    def _build_email_tab(self):
        t = self.tab_email
        self.email_entry = self._labeled_entry(t, "Email Adresi:")
        
        btn_row = tk.Frame(t, bg=self.theme["BG"])
        btn_row.pack(fill="x", pady=6)
        self.tracked_widgets.append((btn_row, {"bg": "BG"}))
        
        ttk.Button(btn_row, text="FORMAT/MX ANALİZ ET", command=self._on_email_analyze).pack(side="left")

        # HIBP Lookup Button
        ttk.Button(btn_row, text="HAVE I BEEN PWNED? SORGULA", style="Blue.TButton", command=self._on_hibp_lookup).pack(side="left", padx=8)

        self.email_output = self._output_box(t, tab_name="EMAIL")

    def _on_hibp_lookup(self):
        email = self.email_entry.get().strip()
        if not email:
            messagebox.showerror("Hata", "Email adresi girin.")
            return
        
        self.set_status(f"Have I Been Pwned'de '{email}' sorgulanıyor...")
        self._write(self.email_output, f"HIBP'de '{email}' sorgulanıyor, lütfen bekleyin...\n")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", self._format_error_message(err))
                self.set_status("HIBP sorgusu başarısız.")
                return
            
            if not result["pwned"]:
                out = (f"[HAVE I BEEN PWNED?: {email}]\n\n"
                       f"SONUÇ: Bu email adresi bilinen veri sızıntılarında bulunamadı. ✓")
            else:
                breaches = "\n  - ".join(result.get("breaches", []))
                out = (
                    f"[HAVE I BEEN PWNED?: {email}]\n\n"
                    f"DİKKAT: Bu email adresi {result['count']} veri sızıntısında bulundu!\n\n"
                    f"Sızıntıların Listesi:\n  - {breaches}\n\n"
                    f"Detaylı bilgi için: https://haveibeenpwned.com/account/{urllib.parse.quote(email)}"
                )
            
            self._write(self.email_output, out)
            self.tab_results.setdefault("EMAIL", {"input": email})["hibp"] = result
            self.set_status("Have I Been Pwned sorgusu tamamlandı.")

        self._run_async(lambda: hibp_lookup(email), done)

    def _on_email_analyze(self):
        email = self.email_entry.get().strip()
        if not email:
            messagebox.showerror("Hata", "Email girin.")
            return
        self.set_status("Email analiz ediliyor...")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", self._format_error_message(err))
                return
            mx = "\n  ".join(result["mx"]) or ("Bulunamadı" if DNSPYTHON_OK else "(dnspython kurulu değil)")
            a = "\n  ".join(result["a_record"]) or "Bulunamadı"
            out = (
                f"[EMAIL FORMAT/MX ANALİZİ: {email}]\n"
                f"Format Geçerli mi?: {'Evet' if result['valid_format'] else 'Hayır'}\n"
                f"Domain            : {result['domain']}\n"
                f"Domain A Kaydı    :\n  {a}\n\n"
                f"MX Kayıtları      :\n  {mx}\n"
            )
            self._write(self.email_output, out)
            self.tab_results.setdefault("EMAIL", {"input": email})["analysis"] = result
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
        self.tab_results["HASH"] = {"input": h, "output": guesses}
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
            self.tab_results["PHONE"] = {"input": number, "output": result}
            self.set_status("Telefon sorgusu tamamlandı.")
        except Exception as e:
            messagebox.showerror("Hata", self._format_error_message(e))


    # ================= URL / QR TAB =================
    def _build_url_tab(self):
        t = self.tab_url
        self.url_entry = self._labeled_entry(t, "URL:", width=60)

        btn_row = tk.Frame(t, bg=self.theme["BG"])
        btn_row.pack(fill="x", pady=6)
        self.tracked_widgets.append((btn_row, {"bg": "BG"}))

        ttk.Button(btn_row, text="URL ANALİZ ET", command=self._on_url_analyze).pack(side="left")
        ttk.Button(btn_row, text="EKRAN GÖRÜNTÜSÜ AL", style="Blue.TButton", command=self._on_url_screenshot).pack(side="left", padx=8)

        l = tk.Label(t, text="─── QR Kod Decode (resimden) ───", bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9)); l.pack(anchor="w", pady=(10, 4)); self.tracked_widgets.append((l, {"bg": "BG", "fg": "FG_DIM"}))
        ttk.Button(t, text="RESİM SEÇ VE QR OKU", style="Clear.TButton",
                   command=self._on_qr_decode).pack(anchor="w")

        self.url_output = self._output_box(t, tab_name="URL / QR")

    def _on_url_screenshot(self):
        if not PLAYWRIGHT_OK:
            messagebox.showerror("Hata", "Bu özellik için 'playwright' kütüphanesi gereklidir.\n\nLütfen `GhostOSINT-Installer.bat` dosyasını çalıştırarak kurulumu tamamlayın.")
            return

        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Hata", "URL girin.")
            return
        if not url.lower().startswith(("http://", "https://")):
            url = "http://" + url

        domain = urllib.parse.urlparse(url).netloc or "url"
        initial_filename = f"screenshot_{domain.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.png"
        save_path = filedialog.asksaveasfilename(
            title="Ekran Görüntüsünü Kaydet", initialfile=initial_filename, defaultextension=".png",
            filetypes=[("PNG Image", "*.png"), ("All files", "*.*")]
        )
        if not save_path: return

        self.set_status(f"'{url}' için ekran görüntüsü alınıyor...")
        self._write(self.url_output, f"Ekran görüntüsü alınıyor, lütfen bekleyin...\nBu işlem 30 saniyeye kadar sürebilir.\n\nURL: {url}\n")

        def done(result_path, err):
            if err:
                messagebox.showerror("Hata", f"Ekran görüntüsü alınamadı:\n{self._format_error_message(err)}", parent=self)
                self.set_status("Ekran görüntüsü alma başarısız.")
                return
            
            out = f"\nEkran görüntüsü başarıyla alındı ve kaydedildi.\n\nDosya Yolu: {result_path}"
            self._append_to_output(self.url_output, out)
            self.tab_results.setdefault("URL / QR", {})["screenshot"] = {"input": url, "output": result_path}
            self.set_status("Ekran görüntüsü alındı.")
            
            if messagebox.askyesno("Başarılı", "Ekran görüntüsü kaydedildi.\n\nDosyayı şimdi açmak ister misiniz?", parent=self):
                try:
                    os.startfile(os.path.normpath(result_path))
                except Exception as e:
                    messagebox.showwarning("Hata", f"Dosya açılamadı: {e}", parent=self)

        self._run_async(lambda: take_url_screenshot(url, save_path), done)

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
                messagebox.showerror("Hata", self._format_error_message(err))
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
            self.tab_results.setdefault("URL / QR", {})["url_analysis"] = {"input": url, "output": result}
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
                messagebox.showerror("Hata", self._format_error_message(err))
                self.set_status("QR okuma başarısız.")
                return
            self._write(self.url_output, f"[QR KOD SONUCU]\nDosya: {path}\n\nİçerik:\n{result}\n")
            self.tab_results.setdefault("URL / QR", {})["qr_decode"] = {"input": path, "output": result}
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
            if err or result is None:
                error_msg = self._format_error_message(err) if err else "Görsel işlenirken bilinmeyen bir hata oluştu (sonuç alınamadı)."
                messagebox.showerror("Hata", error_msg)
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
            self.tab_results["EXIF"] = {"input": path, "output": result}
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
                messagebox.showerror("Hata", self._format_error_message(err))
                self.set_status("Sorgu başarısız.")
                return
            self._write(self.mac_output, f"[MAC VENDOR LOOKUP]\nMAC     : {mac}\nÜretici : {result}\n")
            self.tab_results["MAC VENDOR"] = {"input": mac, "output": result}
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
        self.tab_results["USER-AGENT"] = {"input": ua, "output": result}
        self.set_status("User-Agent parse edildi.")


    # ================= SUBDOMAIN TAB =================
    def _build_subdomain_tab(self):
        t = self.tab_subdomain
        self.subdomain_entry = self._labeled_entry(t, "Domain:")

        btn_row = tk.Frame(t, bg=self.theme["BG"])
        btn_row.pack(fill="x", pady=6)
        self.tracked_widgets.append((btn_row, {"bg": "BG"}))

        ttk.Button(btn_row, text="SUBDOMAIN ARA (crt.sh)", command=self._on_subdomain_search).pack(side="left")

        self.subdomain_check_button = ttk.Button(btn_row, text="BULUNANLARI KONTROL ET", style="Blue.TButton", command=self._on_subdomain_check)
        self.subdomain_check_button.pack(side="left", padx=8)
        self.subdomain_check_button.config(state="disabled")

        l = tk.Label(t, text="Sertifika şeffaflığı (Certificate Transparency) loglarından public subdomain listesi çeker.", bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9)); l.pack(anchor="w"); self.tracked_widgets.append((l, {"bg": "BG", "fg": "FG_DIM"}))
        self.subdomain_output = self._output_box(t, tab_name="SUBDOMAIN")

    def _on_subdomain_check(self):
        if not self.found_subdomains:
            messagebox.showinfo("Bilgi", "Önce 'SUBDOMAIN ARA' butonu ile bir arama yapmalısınız.")
            return

        total = len(self.found_subdomains)
        self.set_status(f"Toplam {total} subdomain kontrol ediliyor...")
        self.subdomain_check_button.config(state="disabled")
        self._write(self.subdomain_output, f"Kontrol ediliyor, lütfen bekleyin ({total} adet, paralel taranıyor)...\n\n")

        def task():
            results = []
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(check_subdomain_liveness, sub): sub for sub in self.found_subdomains}
                for future in as_completed(futures):
                    results.append(future.result())
            return results

        def done(results, err):
            if err:
                messagebox.showerror("Hata", self._format_error_message(err))
                self.set_status("Subdomain kontrolü başarısız.")
                self.subdomain_check_button.config(state="normal")
                return

            domain = self.subdomain_entry.get().strip()
            lines = [f"[SUBDOMAIN CANLILIK KONTROLÜ: {domain}]\n"]
            # Sort by status type (int vs str), then by status value
            for sub, status, url in sorted(results, key=lambda x: (isinstance(x[1], str), x[1])):
                lines.append(f"[{str(status):<11}] {sub}")

            self._write(self.subdomain_output, "\n".join(lines))
            self.tab_results.setdefault("SUBDOMAIN", {"input": domain})["liveness_check"] = results
            self.set_status("Subdomain kontrolü tamamlandı.")
            self.subdomain_check_button.config(state="normal")

        self._run_async(task, done)

    def _on_subdomain_search(self):
        domain = self.subdomain_entry.get().strip()
        if not domain:
            messagebox.showerror("Hata", "Domain girin (örn: example.com).")
            return
        self.set_status("Subdomain aranıyor (crt.sh)...")
        self._write(self.subdomain_output, "Aranıyor, lütfen bekleyin...\n")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", self._format_error_message(err))
                self.set_status("Subdomain arama başarısız.")
                self.subdomain_check_button.config(state="disabled")
                return

            self.found_subdomains = result

            if not result:
                self._write(self.subdomain_output, f"[SUBDOMAIN: {domain}]\n\nSonuç bulunamadı.")
                self.subdomain_check_button.config(state="disabled")
            else:
                out = f"[SUBDOMAIN: {domain}] — {len(result)} sonuç\n\n" + "\n".join(result)
                self._write(self.subdomain_output, out)
                self.subdomain_check_button.config(state="normal")
            self.set_status("Subdomain arama tamamlandı.")
            self.tab_results.setdefault("SUBDOMAIN", {"input": domain})["found_subdomains"] = result

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
                messagebox.showerror("Hata", self._format_error_message(err))
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
            self.tab_results["WAYBACK"] = {"input": domain, "output": result}
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
                messagebox.showerror("Hata", self._format_error_message(err))
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
            
            out += "\n\n----------------------------------------------------------------\n"
            out += "İpucu: 'PASTEBIN' sekmesini kullanarak bu email adresi için internete sızdırılmış ham metin (şifre vb.) olup olmadığını da kontrol edebilirsiniz."

            self._write(self.breach_output, out)
            self.tab_results["BREACH CHECK"] = {"input": email, "output": result}
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
                messagebox.showerror("Hata", self._format_error_message(err))
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
            self.tab_results["PORT SCAN"] = {"input": host, "output": result}
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
            f"Paste Arşivi (ps.s.osint.sh) : {links['paste_archive']}\n\n"
            f"─────────────────────────────────────────\n"
            f"İpucu: Email için ayrıca BREACH CHECK sekmesini de kullan,\n"
            f"o sekme bilinen ihlal veritabanını otomatik kontrol eder."
        )
        self._write(self.leak_output, out)
        self.tab_results["LEAK SEARCH"] = {"input": term, "output": links}
        self.set_status("Leak search linkleri oluşturuldu.")


    # ================= LEAK PEEK TAB =================
    def _build_leakpeek_tab(self):
        t = self.tab_leakpeek
        self.leakpeek_entry = self._labeled_entry(t, "Email/Username:")
        ttk.Button(t, text="LEAK PEEK'TE ARA", command=self._on_leakpeek_lookup).pack(anchor="w", pady=6)
        l1 = tk.Label(t,
                 text="⚠ Bu modül public veri sızıntılarını tarar. Çıkan sonuçlar hassas bilgiler\n"
                      "içerebilir. Sadece yasal ve etik amaçlarla kullanın.", bg=self.theme["BG"], fg=self.theme["RED"], font=("Segoe UI", 9), justify="left"); l1.pack(anchor="w", pady=(2, 0)); self.tracked_widgets.append((l1, {"bg": "BG", "fg": "RED"}))
        l2 = tk.Label(t, text="LeakCheck.io Public API'si kullanılarak, girilen email/username'in hangi\n"
                              "sızıntılarda (kaynak + tarih) geçtiği ücretsiz olarak taranır. (Powered by LeakCheck)",
                 bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9), justify="left"); l2.pack(anchor="w", pady=(2, 0)); self.tracked_widgets.append((l2, {"bg": "BG", "fg": "FG_DIM"}))
        self.leakpeek_output = self._output_box(t, tab_name="LEAK PEEK")

    def _on_leakpeek_lookup(self):
        keyword = self.leakpeek_entry.get().strip()
        if not keyword:
            messagebox.showerror("Hata", "Aranacak bir terim girin (örn: email, username).")
            return
        self.set_status(f"'{keyword}' için LeakCheck'te arama yapılıyor...")
        self._write(self.leakpeek_output, f"LeakCheck Taraması Başlatıldı: {keyword}\n" + "="*50 + "\n")

        def done(result, err):
            if err:
                error_message = self._format_error_message(err)
                messagebox.showerror("Hata", error_message)
                self.set_status("LeakCheck taraması başarısız.")
                self._append_to_output(self.leakpeek_output, f"\nHATA: {error_message}")
                return

            # Başarılı yol: 'result' geçerli bir sözlük (dictionary).
            self._append_to_output(self.leakpeek_output, "Tarama Tamamlandı.\n" + "="*50)

            if not result["found"]:
                self._append_to_output(self.leakpeek_output, f"\nSonuç: '{keyword}' için bilinen sızıntılarda bir kayıt bulunamadı.")
            else:
                fields = ", ".join(result.get("fields", [])) or "belirtilmemiş"
                self._append_to_output(self.leakpeek_output, f"\nDİKKAT: '{keyword}' için {result['count']} sızıntı kaynağı bulundu!\nAçığa çıkan veri kategorileri: {fields}\n")
                for leak in result["results"]:
                    self._append_to_output(self.leakpeek_output, f"Kaynak: {leak['line']}\n" + "-"*30)

                self._append_to_output(self.leakpeek_output, "\n" + "="*50)
                self._append_to_output(self.leakpeek_output, "UYARI: Bu terim, listelenen sızıntı veritabanlarında bulundu. İlişkili şifrelerinizi\nDERHAL değiştirmeniz önerilir. (Detaylı veri için LeakCheck Pro API + key gerekir.)\n\nPowered by LeakCheck (leakcheck.io)")

            self.tab_results["LEAK PEEK"] = {"input": keyword, "output": result}
            self.set_status("LeakCheck taraması tamamlandı.")

        self._run_async(lambda: leakpeek_lookup(keyword), done)

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
                messagebox.showerror("Hata", self._format_error_message(err))
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
            self.tab_results["DISCORD INVITE"] = {"input": code, "output": result}
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
                messagebox.showerror("Hata", self._format_error_message(err))
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
            self.tab_results["SSL SERTİFİKA"] = {"input": domain, "output": result}
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
                messagebox.showerror("Hata", self._format_error_message(err))
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
                if result.get("example_bins"):
                    bins_str = ", ".join(result["example_bins"])
                    out += (
                        f"\nBu Bankaya Ait Örnek Kart BIN'leri:\n"
                        f"  {bins_str}\n"
                        f"(Bu BIN'leri 'BIN LOOKUP' sekmesinde sorgulatabilirsiniz.)\n"
                    )
            self._write(self.iban_output, out)
            self.tab_results["IBAN ANALYZER"] = {"input": iban, "output": result}
            self.set_status("IBAN analizi tamamlandı.")

        self._run_async(lambda: analyze_iban(iban), done)

    # ================= BIN LOOKUP TAB =================
    def _build_bin_tab(self):
        t = self.tab_bin
        self.bin_entry = self._labeled_entry(t, "BIN Numarası (ilk 6-8 hane):")
        ttk.Button(t, text="BIN SORGULA", command=self._on_bin_lookup).pack(anchor="w", pady=6)
        l = tk.Label(t, text="Kredi/Banka kartının ilk 6-8 hanesini girerek kart şeması, banka ve ülke bilgilerini sorgular.",
                     bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9), justify="left")
        l.pack(anchor="w")
        self.tracked_widgets.append((l, {"bg": "BG", "fg": "FG_DIM"}))
        self.bin_output = self._output_box(t, tab_name="BIN LOOKUP")

    def _on_bin_lookup(self):
        bin_num = self.bin_entry.get().strip()
        if not bin_num:
            messagebox.showerror("Hata", "Lütfen bir BIN numarası girin.")
            return
        self.set_status("BIN bilgisi sorgulanıyor...")

        def done(result, err):
            if err:
                messagebox.showerror("Hata", self._format_error_message(err))
                self.set_status("BIN sorgusu başarısız.")
                return

            out = (
                f"[BIN LOOKUP: {result['bin']}]\n"
                f"Şema (Scheme) : {result['scheme']}\n"
                f"Marka (Brand) : {result['brand']}\n"
                f"Tip           : {result['type']}\n"
                f"Ön Ödemeli mi?: {'Evet' if result['prepaid'] else 'Hayır'}\n"
                f"Ülke          : {result['country_name']}\n"
                f"Banka Adı     : {result['bank_name']}\n"
                f"Banka URL     : {result['bank_url']}\n"
                f"Banka Telefon : {result['bank_phone']}\n"
            )
            self._write(self.bin_output, out)
            self.tab_results["BIN LOOKUP"] = {"input": bin_num, "output": result}
            self.set_status("BIN sorgusu tamamlandı.")

        self._run_async(lambda: bin_lookup(bin_num), done)

    # ================= XSS TEST TAB =================
    def _build_xss_tab(self):
        t = self.tab_xss
        self.xss_entry = self._labeled_entry(t, "URL (parametrelerle):", width=70)
        ttk.Button(t, text="REFLECTED XSS TESTİ YAP", command=self._on_xss_test).pack(anchor="w", pady=6)
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
                    self.tab_results["XSS TEST"] = {"input": url, "output": result}
                    self.set_status("XSS testi tamamlandı.")
                self.after(0, final_update)
            except Exception as e: # Capture exception for lambda
                self.after(0, lambda e=e: messagebox.showerror("Hata", self._format_error_message(e)))
                self.after(0, self.set_status, "XSS testi başarısız.")

        threading.Thread(target=worker, daemon=True).start()

    # ================= SQL INJECTION TEST TAB =================
    def _build_sql_tab(self):
        t = self.tab_sql
        self.sql_entry = self._labeled_entry(t, "URL (parametrelerle):", width=70)
        ttk.Button(t, text="ERROR-BASED SQLi TESTİ YAP", command=self._on_sql_test).pack(anchor="w", pady=6)
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
                    self.tab_results["SQLi TEST"] = {"input": url, "output": result}
                    self.set_status("SQLi testi tamamlandı.")
                self.after(0, final_update)
            except Exception as e: # Capture exception for lambda
                self.after(0, lambda e=e: messagebox.showerror("Hata", self._format_error_message(e)))
                self.after(0, self.set_status, "SQLi testi başarısız.")

        threading.Thread(target=worker, daemon=True).start()

    # ================= BASE64 TAB =================
    def _build_base64_tab(self):
        t = self.tab_base64
        
        input_frame = tk.Frame(t, bg=self.theme["BG"])
        input_frame.pack(fill="both", expand=True, pady=(0, 5))
        self.tracked_widgets.append((input_frame, {"bg": "BG"}))

        tk.Label(input_frame, text="Metin (Plain Text)", bg=self.theme["BG"], fg=self.theme["FG_DIM"]).pack(anchor="w")
        self.base64_input_text = tk.Text(input_frame, height=8, bg=self.theme["PANEL2"], fg=self.theme["FG"], insertbackground=self.theme["FG"], font=FONT_MONO, relief="flat", wrap="word", padx=10, pady=10, borderwidth=1, highlightthickness=1, highlightbackground=self.theme["BORDER"], highlightcolor=self.theme["BLUE"])
        self.base64_input_text.pack(fill="both", expand=True, pady=(2,0))

        button_frame = tk.Frame(t, bg=self.theme["BG"])
        button_frame.pack(fill="x", pady=5)
        self.tracked_widgets.append((button_frame, {"bg": "BG"}))

        ttk.Button(button_frame, text="▼ ENCODE ▼", command=self._on_base64_encode).pack(side="left", expand=True, padx=5)
        ttk.Button(button_frame, text="▲ DECODE ▲", command=self._on_base64_decode, style="Blue.TButton").pack(side="right", expand=True, padx=5)

        output_frame = tk.Frame(t, bg=self.theme["BG"])
        output_frame.pack(fill="both", expand=True, pady=(5, 0))
        self.tracked_widgets.append((output_frame, {"bg": "BG"}))

        tk.Label(output_frame, text="Base64", bg=self.theme["BG"], fg=self.theme["FG_DIM"]).pack(anchor="w")
        self.base64_output_text = tk.Text(output_frame, height=8, bg=self.theme["PANEL2"], fg=self.theme["FG"], insertbackground=self.theme["FG"], font=FONT_MONO, relief="flat", wrap="word", padx=10, pady=10, borderwidth=1, highlightthickness=1, highlightbackground=self.theme["BORDER"], highlightcolor=self.theme["BLUE"])
        self.base64_output_text.pack(fill="both", expand=True, pady=(2,0))

    def _on_base64_encode(self):
        try:
            plain_text = self.base64_input_text.get("1.0", "end-1c")
            if not plain_text:
                self.set_status("Kodlanacak metin girilmedi.")
                return
            encoded = base64.b64encode(plain_text.encode("utf-8")).decode("utf-8")
            self.base64_output_text.delete("1.0", "end")
            self.base64_output_text.insert("1.0", encoded)
            self.set_status("Metin başarıyla Base64'e kodlandı.")
        except Exception as e:
            messagebox.showerror("Hata", f"Kodlama sırasında hata: {e}")

    def _on_base64_decode(self):
        try:
            base64_text = self.base64_output_text.get("1.0", "end-1c").strip()
            if not base64_text:
                self.set_status("Çözülecek Base64 verisi girilmedi.")
                return
            missing_padding = len(base64_text) % 4
            if missing_padding:
                base64_text += '=' * (4 - missing_padding)
            decoded = base64.b64decode(base64_text).decode("utf-8", errors="replace")
            self.base64_input_text.delete("1.0", "end")
            self.base64_input_text.insert("1.0", decoded)
            self.set_status("Base64 başarıyla metne çözüldü.")
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            messagebox.showerror("Hata", f"Geçersiz Base64 verisi veya formatı.\n\nDetay: {e}")
        except Exception as e:
            messagebox.showerror("Hata", f"Çözme sırasında hata: {e}")

    # ================= BITCOIN TAB =================
    def _build_btc_tab(self):
        t = self.tab_btc
        self.btc_entry = self._labeled_entry(t, "Bitcoin Adresi:", width=50)
        ttk.Button(t, text="ADRESİ KONTROL ET", command=self._on_btc_lookup).pack(anchor="w", pady=6)
        l = tk.Label(t, text="Girilen adres için public block explorer linki oluşturur.", bg=self.theme["BG"], fg=self.theme["FG_DIM"], font=("Segoe UI", 9)); l.pack(anchor="w"); self.tracked_widgets.append((l, {"bg": "BG", "fg": "FG_DIM"}))
        self.btc_output = self._output_box(t, tab_name="BITCOIN")

    def _on_btc_lookup(self):
        address = self.btc_entry.get().strip()
        if not address:
            messagebox.showerror("Hata", "Bitcoin adresi girin.")
            return
        if not re.match(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$", address):
             if not messagebox.askyesno("Uyarı", "Girilen metin geçerli bir Bitcoin adresine benzemiyor. Yine de devam edilsin mi?"):
                 return
        explorer_url = f"https://www.blockchain.com/btc/address/{address}"
        out = (f"[BITCOIN ADRES KONTROLÜ]\n"
               f"Adres: {address}\n\n"
               f"Aşağıdaki linke tıklayarak bu adresin işlem geçmişini, bakiyesini ve\n"
               f"diğer public bilgilerini bir block explorer üzerinde görebilirsiniz:\n\n"
               f"{explorer_url}\n")
        self._write(self.btc_output, out)
        self.tab_results["BITCOIN"] = {"input": address, "output": {"explorer_url": explorer_url}}
        self.set_status("Bitcoin block explorer linki oluşturuldu.")

if __name__ == "__main__":
    # Ana uygulama nesnesini oluşturmadan önce temel kontroller yapılabilir.
    # __init__ içine taşıdım, böylece nesne hiç oluşmaz.
    app = GhostOSINT()
    # Eğer __init__ içinde bir erken çıkış (return) olduysa, app.title gibi bir attribute
    # mevcut olmayabilir. Bu yüzden app'in bir 'title' attribute'u olup olmadığını kontrol et.
    if hasattr(app, "title"):
        app.mainloop()
