# Licencje FFmpeg wbudowanego w serwer referencyjny

Serwer korzysta z **własnego buildu FFmpeg** zbudowanego z tego katalogu (`build.sh` + `ffmpeg-config.sh`). Wynikowe pliki
`ffmpeg` / `ffprobe` są częścią serwera i trafiają do jego paczek (instalator `.exe` dla Windows, `.run` dla Linuxa).

| Składnik | Licencja | Uwagi |
|---|---|---|
| FFmpeg (gałąź `release/7.1`) | **GPL v2+** (bo włączono `--enable-gpl`) | wynik jako całość jest objęty GPL |
| x264 | GPL v2+ | kodowanie H.264 (CPU) |
| x265 | GPL v2+ | kodowanie H.265 (CPU) |
| libopus, libwebp, libjxl, libaom, zlib | BSD / zlib | |
| nv-codec-headers (NVENC), AMF (AMD), libvpl (Intel QSV) | MIT | tylko nagłówki / dispatcher; sterowniki ładuje system |

## Co to oznacza w praktyce
- Rozpowszechniając binarki `ffmpeg`/`ffprobe` (np. w instalatorze) **musisz udostępnić ich kod źródłowy** na warunkach GPL.
  Ten katalog jest właśnie tym kodem: dokładne wersje zależności są przypięte w `build.sh` (tagi i pełne skróty commitów),
  a flagi w `ffmpeg-config.sh`. Dołączaj do wydania odnośnik do tego repozytorium.
- Reszta serwera (kod JavaScript) uruchamia `ffmpeg` jako **osobny proces** (`convert.js`), nie linkuje go — dlatego
  licencja GPL dotyczy plików binarnych FFmpeg, a nie kodu serwera.
- To nie jest porada prawna. Jeśli rozważasz dystrybucję komercyjną, skonsultuj licencje (GPL + patenty kodeków H.264/H.265).

## Akceleracja sprzętowa
NVENC (NVIDIA), AMF (AMD), QSV (Intel) i VAAPI (Intel/AMD na Linuxie) wymagają sterowników producenta zainstalowanych
w systemie — nie są częścią pliku. Gdy ich brak, `convert.js` automatycznie wraca do x264/x265.
