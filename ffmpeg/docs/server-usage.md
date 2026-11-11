# Użycie z serwera (przykładowe komendy)

## Najprościej: broker `mediatool` (zalecane)

[`tools/mediatool.js`](../tools/mediatool.js) (Node, zero zależności) ukrywa całą składnię:
serwer podaje **jednolite** `--to/--quality/--effort/--scale`, a broker sam decyduje, czy
użyć FFmpeg czy MozJPEG (`cjpeg`), mapuje jakość/moc na parametry kodeka i **zwraca JSON z
faktycznie użytymi wartościami** (do zapisania w manifeście jako `imageQuality`). Dla PNG/JPEG
wstrzykuje je też w metadane pliku (PNG `tEXt`, JPEG `COM`).

```bash
node tools/mediatool.js --in in.png --out out.jxl  --to jxl     --quality 82 --effort 70 --scale 1280
node tools/mediatool.js --in in.png --out out.jpg  --to mozjpeg --quality 80               # prawdziwy MozJPEG
node tools/mediatool.js --in in.png --out out.avif --to avif    --quality 80 --effort 60
cat in.wav | node tools/mediatool.js --in - --out - --to opus --quality 60 > out.opus
```

Integracja w Node (serwer społeczności):
```js
const { execFile } = require("node:child_process");
function convert(job) {                       // job: {in,out,to,quality,effort,scale}
  const args = ["tools/mediatool.js", "--in", job.in, "--out", job.out, "--to", job.to,
    "--quality", String(job.quality), "--effort", String(job.effort)];
  if (job.scale) args.push("--scale", String(job.scale));
  return new Promise((res, rej) => execFile(process.execPath, args, (e, stdout, stderr) => {
    if (e) return rej(new Error(stderr || e.message));
    const meta = JSON.parse((stdout || stderr).trim().split("\n").pop()); // {quality, effort, bytes, ...}
    res(meta);                                 // -> zapisz meta.quality jako imageQuality w manifeście
  }));
}
```

Poniżej „surowe" komendy, jeśli wolisz wołać ffmpeg/cjpeg bezpośrednio.


Serwer (np. Node) woła zbudowaną binarkę `ffmpeg` na lokalnych plikach albo przez potok
(`pipe:`), bez sieci. Poniżej typowe operacje dla dozwolonych formatów. Zakładamy zmienną
`FFMPEG` wskazującą na `dist/<platforma>-<arch>/ffmpeg`.

## Skalowanie (wspólny wzorzec)

`scale` zachowujący proporcje do maks. szerokości 1080 (parzyste wymiary):
```bash
-vf "scale='min(1080,iw)':-2"
```
Twarde 512×512 z dopełnieniem:
```bash
-vf "scale=512:512:force_original_aspect_ratio=decrease,pad=512:512:(ow-iw)/2:(oh-ih)/2"
```

## Obrazy — konwersja + skalowanie

```bash
# do WEBP (jakość 1..100)
"$FFMPEG" -i in.png -vf "scale='min(1280,iw)':-2" -c:v libwebp -quality 80 out.webp

# do JXL (distance: 0=bezstratnie, ~1 = wysoka jakość; mniejsze = lepsze)
"$FFMPEG" -i in.jpg -vf "scale='min(1280,iw)':-2" -c:v libjxl -distance 1.0 out.jxl

# do AVIF (enkoder libaom; crf 0..63, mniejsze = lepsze; cpu-used 0..8 szybkość)
"$FFMPEG" -i in.png -c:v libaom-av1 -crf 30 -cpu-used 6 -still-picture 1 out.avif

# do PNG (bezstratny)
"$FFMPEG" -i in.webp out.png

# do JPEG — szybki, natywny mjpeg FFmpeg (q:v 2=wysoka .. 31=niska)
"$FFMPEG" -i in.png -c:v mjpeg -q:v 3 out.jpg
```

### Prawdziwy MozJPEG — przez dołączony `cjpeg`
FFmpeg nie linkuje libjpeg, więc jego JPEG to natywny mjpeg (bez trellisa). Prawdziwy
MozJPEG (mniejsze pliki) robimy dołączonym `cjpeg` w potoku. `cjpeg` czyta **PPM** (zbudowany
bez PNG), więc FFmpeg wypuszcza PPM; trellis/progresja są w MozJPEG domyślnie włączone.
```bash
CJPEG="dist/<platforma>-<arch>/cjpeg"
# dekod + skalowanie w FFmpeg, kompresja MozJPEG w cjpeg (jakość 1..100)
"$FFMPEG" -i in.png -vf "scale='min(1280,iw)':-2" -f image2pipe -vcodec ppm - \
  | "$CJPEG" -quality 80 > out.jpg
```
Masz więc oba: `-c:v mjpeg` (szybko) albo `cjpeg` (mniejszy plik, MozJPEG).

## Audio — Opus

```bash
# dowolne wejście audio -> Opus w .opus/.ogg (bitrate w b/s)
"$FFMPEG" -i in.wav -c:a libopus -b:a 96k out.opus

# przez potok (bez plików tymczasowych)
cat in.wav | "$FFMPEG" -i pipe:0 -c:a libopus -b:a 96k -f ogg pipe:1 > out.opus
```

## Odczyt metadanych (ffprobe)

```bash
"$FFMPEG"probe -v error -select_streams v:0 -show_entries stream=width,height,codec_name \
  -of json in.avif
```

## Wskazówki dla integracji

- **Potoki zamiast plików tymczasowych:** `-i pipe:0` / `pipe:1` (`-f` wymusza format wyjścia).
- **Determinizm/bezpieczeństwo:** binarka ma `--disable-network`; operuje tylko na plikach/potokach.
- **Limity:** ustaw rozsądny `-threads`, a przy AVIF `-cpu-used 6..8` dla szybkości (aom jest wolny).
- **Sprawdzenie dostępnych elementów:** `ffmpeg -hide_banner -encoders|-decoders|-filters`.
