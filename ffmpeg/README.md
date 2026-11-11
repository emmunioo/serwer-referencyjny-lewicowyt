# ffmpeg-serwer

Minimalny, dedykowany build **FFmpeg** dla serwera lewicowYT — świadomie wąski, żeby
binarka była mała, szybka do audytu i bez niepotrzebnych kodeków. Wszystko linkowane
**statycznie**, wynik to jeden przenośny plik `ffmpeg` (+ `ffprobe`).

## Co zawiera (i czego NIE)

| Kategoria | Wspierane | Świadomie pominięte |
| --- | --- | --- |
| **Wideo** | — (nic) | wszystkie kodeki wideo (h264/hevc/av1-wideo/vpx…) |
| **Audio** | **Opus** (`libopus`, kontenery `.opus`/`.ogg`/`.mka`) | mp3, aac, vorbis, flac, … |
| **Obrazy** | **PNG** (natywny+zlib), **JPEG** (natywny `mjpeg` w FFmpeg **oraz** prawdziwy **MozJPEG** `cjpeg` obok), **WEBP** (`libwebp`), **JXL** (`libjxl`), **AVIF** (dekod: natywny `av1`; kod: `libaom`) | tiff, gif, bmp, heic… |
| **Filtry** | skalowanie i podstawowe przekształcenia: `scale`, `crop`, `pad`, `transpose`, `hflip`/`vflip`, `rotate`, `fps`, `overlay`, `zscale`, `thumbnail`, `format`, audio: `aresample` | reszta (setki filtrów) |
| **Protokoły** | tylko lokalne: `file`, `pipe`, `fd` | sieć wyłączona (`--disable-network`) |

Pełna, jedyna lista flag: [`ffmpeg-config.sh`](ffmpeg-config.sh).

### O „mozjpeg” — ważne
FFmpeg **nie linkuje libjpeg/libjpeg-turbo** — jego kodek JPEG (`mjpeg`) jest napisany
natywnie, więc **nie da się „podmienić” go na MozJPEG** (nie ma `--enable-libmjpeg` ani
`--enable-libjpeg`; drop-in trik działa tylko dla narzędzi, które faktycznie linkują
libjpeg-turbo, np. libvips/ImageMagick — nie dla FFmpeg).

Dlatego prawdziwy MozJPEG dostarczamy **osobno**: build buduje też jego CLI **`cjpeg`**
(z tych samych źródeł mozjpeg, co moduł natywny w aplikacji) i wrzuca do `dist/`. Serwer
robi JPEG z trellisem w potoku: `ffmpeg` dekoduje/skaluje → `cjpeg` koduje MozJPEG
(patrz [`docs/server-usage.md`](docs/server-usage.md)). Masz więc **oba**: szybki natywny
`mjpeg` w FFmpeg i mniejszy prawdziwy MozJPEG przez `cjpeg`.

## Broker `mediatool` (upraszcza wołanie z serwera)

Zamiast składać komendy ffmpeg/cjpeg ręcznie, serwer woła [`tools/mediatool.js`](tools/mediatool.js)
(Node, zero zależności): podajesz jednolite `--to/--quality/--effort/--scale`, a broker **sam**
decyduje FFmpeg vs MozJPEG, mapuje jakość/moc na parametry kodeka, wstrzykuje „moc kompresji" do
metadanych (PNG `tEXt`, JPEG `COM`) i zwraca **JSON z użytymi wartościami** (do zapisania jako
`imageQuality` w manifeście). Szczegóły i przykład integracji: [`docs/server-usage.md`](docs/server-usage.md).

## Platformy

`linux`, `macos`, `windows` (przez MSYS2/UCRT64), `android` (cross-compile przez NDK).
Zależności (`zlib`, `opus`, `libwebp`, `aom`, `libjxl`) budują się **ze źródeł przez CMake**
— jedna ścieżka na wszystkich platformach, bez `meson`/`nasm` (aom w trybie `generic`).

### Wymagania

- **Wszędzie:** `git`, `cmake` (≥3.22), `ninja`, `make`, kompilator C/C++ (clang/gcc), `pkg-config`.
- **Linux:** np. `sudo apt install git cmake ninja-build make clang pkg-config`.
- **macOS:** Xcode Command Line Tools + `brew install cmake ninja pkg-config`.
- **Windows:** [MSYS2](https://www.msys2.org) — `build.ps1` sam doinstaluje pakiety UCRT64.
- **Android:** Android NDK (r26/r27+); ustaw `ANDROID_NDK_ROOT`.

## Użycie

```bash
# Linux / macOS (natywnie)
./build.sh

# macOS pod konkretną architekturę
./build.sh --arch arm64        # albo --arch x86_64

# Android (cross-compile) — wymaga ANDROID_NDK_ROOT
export ANDROID_NDK_ROOT=/ścieżka/do/ndk/27.0.12077973
./build.sh --platform android --arch arm64-v8a      # albo armeabi-v7a | x86_64
```

```powershell
# Windows (PowerShell) — wymaga MSYS2
pwsh -File .\build.ps1
# Android z Windows:
$env:ANDROID_NDK_ROOT = "C:\...\ndk\27.0.12077973"
pwsh -File .\build.ps1 -Platform android -Arch arm64-v8a
```

Opcje `build.sh`: `--platform`, `--arch`, `--android-api 26`, `--jobs N`, `--clean`, `--prefix DIR`.

## Wynik

- `dist/<platforma>-<arch>/`: `ffmpeg`, `ffprobe`, **`cjpeg`** (MozJPEG), `djpeg` (na Windows z `.exe`).
- Pełny prefix (biblioteki + nagłówki + binarki): `work/<platforma>-<arch>/prefix/`.

Szybki test zawartości:
```bash
ffmpeg -hide_banner -encoders | grep -E 'opus|webp|jxl|aom|mjpeg|png'
ffmpeg -hide_banner -decoders | grep -E 'opus|webp|jxl|av1|mjpeg|png'
```

## Wersje zależności

Przypięte w [`build.sh`](build.sh): FFmpeg `release/7.1`, zlib `1.3.1`, opus `1.5.2`,
libwebp `1.4.0`, aom `3.9.0`, libjxl `0.11.1`, mozjpeg `4.1.1`. Zmieniasz je w jednym miejscu.

## Uwaga o weryfikacji

Skrypty budują ze źródeł i są **cross-platformowe**, ale każdą platformę trzeba zbudować
**na niej** (albo z poprawnym NDK dla Androida). Nie są wstępnie skompilowane. Pierwszy
przebieg klonuje i buduje zależności (kilka–kilkanaście minut), kolejne są szybsze.
