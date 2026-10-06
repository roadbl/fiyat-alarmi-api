# Fiyat Alarmı API

GitHub Pages üzerindeki `roadbl/fiyat-alarmi` arayüzünün backend servisidir.

## Render kurulumu

Render'da **New → Blueprint** seçip bu repoyu bağlayabilirsin. `render.yaml`
ayarları otomatik yükler.

Gerekli gizli değişken:

- `NVIDIA_API_KEY`

API anahtarını GitHub dosyalarına yazma.

## Kontrol

Deploy tamamlandıktan sonra:

`https://SERVIS-ADRESIN.onrender.com/health`

yanıtı:

```json
{"ok": true}
```

olmalıdır.

## Önemli

Ücretsiz web servisleri uykuya geçebildiği için arka plan kontrolü 7/24 garanti değildir.
Bu sürüm çalışan MVP içindir. Kalıcı veritabanı ve güvenilir zamanlanmış kontroller
sonraki aşamada eklenebilir.
