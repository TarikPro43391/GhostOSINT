# GhostOSINT
Ghost OSINT Framework, Python ve Tkinter ile geliştirilmiş açık kaynak bir OSINT (Open Source Intelligence) masaüstü uygulamasıdır. 18 farklı modül içerir: IP geolocation, domain/DNS/WHOIS sorgulama, kullanıcı adı arama, Discord ID çözümleme, email analiz, hash tanımlama, telefon numarası bilgisi, URL analiz, QR kod okuma, EXIF/metadata çıkarma, MAC vendor lookup, User-Agent parser, port tarama ve breach kontrolü.

Not: Araç yalnızca herkese açık (public) bilgi toplama amaçlıdır, yetkisiz erişim veya izinsiz veri toplama içermez.

v0.1.5 Yenilikleri:

- **LEAK PEEK modülü LeakCheck Public API'ye geçirildi** — artık ücretsiz, dokümante ve login gerektirmeyen resmi bir API kullanılıyor (eski LeakPeek.com API'si paywall'a geçtiği için kaldırıldı)
- **Kritik async hata yakalama bug'ı düzeltildi** — `_run_async` içindeki değişken kapsam hatası nedeniyle uygulamadaki ~20 modülde (LEAK PEEK dahil) hata mesajları düzgün gösterilmiyor, aramalar sessizce takılı kalıyordu; artık tüm modüllerde hatalar doğru gösteriliyor
- **SUBDOMAIN → Bulunanları Kontrol Et özelliği düzeltildi** — eksik `concurrent.futures` importu nedeniyle her tıklamada çöküyordu
- LEAK PEEK sonuç ekranı yeni API'ye göre güncellendi: artık kaynak + tarih + açığa çıkan veri kategorileri (username, phone, address vb.) gösteriliyor, "Powered by LeakCheck" ibaresi eklendi
