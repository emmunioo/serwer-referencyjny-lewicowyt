// Konwersja wgrywanych multimediów do formatów, które aplikacja lewicowYT przyjmuje (protokół, sekcja 10).
// Operator wgrywa DOWOLNY plik, a serwer sam go przygotowuje:
//   obrazy   → JPEG XL (preferowany; WebP, gdy brak kodera JXL; animacje → animowany WebP), najwyżej 6 000 000 B
//              i 4096 px na bok; miniatura powiadomienia → mały WebP (do ok. 6 kB, mieści się w budziku);
//   film     → MP4 z H.265 (preferowany) oraz H.264 (zapas), najwyżej 30 kl/s i 1920 px, dźwięk Opus, spis (moov)
//              na początku (faststart);
//   dźwięk   → Opus w Ogg.
// Re-kodowanie z -map_metadata -1 usuwa przy okazji metadane (EXIF/GPS, lokalizację w filmach).
//
// Wymaga zewnętrznych programów (nie ma zależności npm): ffmpeg (+ ffprobe) i — dla JPEG XL — cjxl.
// Szukane kolejno: zmienne FFMPEG_PATH / FFPROBE_PATH / CJXL_PATH, katalog tools/ obok serwera, PATH.
// Bez ffmpeg serwer działa jak dotąd: przyjmuje tylko pliki już w poprawnym formacie i odrzuca resztę.

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";

import * as logger from "./logger.js";
import { DATA_DIR } from "./store.js";
const HERE = dirname(fileURLToPath(import.meta.url));
const EXE = process.platform === "win32" ? ".exe" : "";

export const MAX_IMAGE_BYTES = 6_000_000;   // limit aplikacji na plik obrazu
export const MAX_IMAGE_SIDE = 4096;         // aplikacja dekoduje w pełni do 4096 px na bok
export const MAX_THUMB_BYTES = 6000;        // miniatura w budziku (po E2E i Base64 musi się zmieścić w 16 KiB)
export const MAX_VIDEO_FPS = 30;
export const MAX_VIDEO_SIDE = 1920;
const VIDEO_TIMEOUT_MS = 60 * 60 * 1000;
const IMAGE_TIMEOUT_MS = 5 * 60 * 1000;

export class ConvertError extends Error {}

// ---------- wykrywanie narzędzi ----------
let toolsCache = null;

function works(cmd, args = ["-version"]) {
  try { return spawnSync(cmd, args, { stdio: "ignore", timeout: 8000 }).status === 0; } catch { return false; }
}
function firstWorking(candidates, args) {
  for (const c of candidates.filter(Boolean)) if (works(c, args)) return c;
  return null;
}

/** { ffmpeg, ffprobe, cjxl, jxl } — ścieżki albo null; jxl: "cjxl" | "ffmpeg" | null (czym kodujemy JPEG XL). */
export function tools(refresh = false) {
  if (toolsCache && !refresh) return toolsCache;
  if (process.env.LEWICOWYT_NO_CONVERT === "1") return (toolsCache = { ffmpeg: null, ffprobe: null, cjxl: null, jxl: null }); // wyłącznik konwersji
  const ffmpeg = firstWorking([process.env.FFMPEG_PATH, join(HERE, "tools", "ffmpeg" + EXE), "ffmpeg"], ["-version"]);
  let ffprobe = null;
  if (ffmpeg) {
    const sibling = ffmpeg.includes("/") || ffmpeg.includes("\\") ? join(dirname(ffmpeg), "ffprobe" + EXE) : null;
    ffprobe = firstWorking([process.env.FFPROBE_PATH, sibling, join(HERE, "tools", "ffprobe" + EXE), "ffprobe"], ["-version"]);
  }
  const cjxl = firstWorking([process.env.CJXL_PATH, join(HERE, "tools", "cjxl" + EXE), "cjxl"], ["--version"]);
  let jxl = cjxl ? "cjxl" : null;
  if (!jxl && ffmpeg) {
    try {
      const enc = spawnSync(ffmpeg, ["-hide_banner", "-encoders"], { encoding: "utf8", timeout: 8000 }).stdout || "";
      if (/\blibjxl\b/.test(enc)) jxl = "ffmpeg";
    } catch { /* brak */ }
  }
  toolsCache = { ffmpeg, ffprobe, cjxl, jxl };
  return toolsCache;
}

export function available() { return !!tools().ffmpeg; }

// ---------- pomocnicze ----------
function run(cmd, args, { timeout = IMAGE_TIMEOUT_MS } = {}) {
  return new Promise((resolve) => {
    let err = "";
    let child;
    // A-37: ffmpeg czyta wejście wyłącznie z plików i potoków (żadnych playlist/protokołów sieciowych wskazanych wewnątrz pliku)
    const finalArgs = toolsCache && cmd === toolsCache.ffmpeg ? args.flatMap((a) => (a === "-i" ? ["-protocol_whitelist", "file,pipe", "-i"] : [a])) : args;
    try { child = spawn(cmd, finalArgs, { stdio: ["ignore", "ignore", "pipe"], windowsHide: true }); }
    catch (e) { resolve({ code: -1, err: String(e.message || e) }); return; }
    const timer = setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* ignore */ } err += "\n[przekroczono limit czasu]"; }, timeout);
    child.stderr.on("data", (c) => { err = (err + c.toString("utf8")).slice(-4000); });
    child.on("error", (e) => { clearTimeout(timer); resolve({ code: -1, err: String(e.message || e) }); });
    child.on("close", (code) => { clearTimeout(timer); resolve({ code: code ?? -1, err }); });
  });
}

function runCapture(cmd, args, timeout = 60_000) {
  const r = spawnSync(cmd, args, { encoding: "utf8", timeout, windowsHide: true, maxBuffer: 8 * 1024 * 1024 });
  return { code: r.status ?? -1, out: r.stdout || "", err: r.stderr || "" };
}

// A-24: katalog roboczy konwersji leży w danych serwera (nie w katalogu systemowym), a pozostałości po awarii są sprzątane przy starcie
const TMP_BASE = join(DATA_DIR, "tmp");
export function cleanupTemp() {
  try { fs.rmSync(TMP_BASE, { recursive: true, force: true }); } catch { /* ignore */ }
  try { for (const n of fs.readdirSync(os.tmpdir())) if (/^lewicowyt-(conv|probe)-/.test(n)) fs.rmSync(join(os.tmpdir(), n), { recursive: true, force: true }); } catch { /* ignore */ }
}

async function withTemp(fn) {
  fs.mkdirSync(TMP_BASE, { recursive: true });
  const dir = fs.mkdtempSync(join(TMP_BASE, "conv-"));
  try { return await fn(dir); }
  finally { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ } }
}

/** ffmpeg z filtrem -vf; gdy format pikseli jest egzotyczny (1-bitowy WBMP itp.) i filtr się nie uda, ponawia z konwersją do RGB. */
async function runVf(t, head, vf, tail, opts) {
  let r = await run(t.ffmpeg, [...head, "-vf", vf, ...tail], opts);
  if (r.code !== 0) r = await run(t.ffmpeg, [...head, "-vf", "format=rgb24," + vf, ...tail], opts);
  return r;
}

/** Zapisuje wejście pod nazwą, po której ffmpeg je odczyta (formaty bez sygnatury — WBMP, TGA — poznaje po rozszerzeniu). */
async function readableInput(t, dir, buf) {
  for (const name of ["in.bin", "in.wbmp", "in.tga"]) {
    const file = join(dir, name);
    fs.writeFileSync(file, buf);
    const r = await run(t.ffmpeg, ["-v", "error", "-i", file, "-map", "0:v:0", "-frames:v", "1", "-f", "null", "-"], { timeout: 60_000 });
    if (r.code !== 0) continue;
    if (name === "in.bin") return file;
    // format rozpoznany tylko po rozszerzeniu (1-bitowy WBMP itp.) — normalizujemy do zwykłego PNG, żeby dalsze filtry działały
    const png = join(dir, "norm.png");
    const n = await run(t.ffmpeg, ["-y", "-v", "error", "-i", file, "-frames:v", "1", "-pix_fmt", "rgb24", png], { timeout: 60_000 });
    if (n.code === 0 && fs.existsSync(png)) return png;
  }
  throw new ConvertError("Nie rozpoznaję tego pliku jako obrazu.");
}

/** Skalowanie: najdłuższy bok ≤ maxSide, dodatkowo współczynnik factor (0–1); wynik zaokrąglony do liczb parzystych, gdy even. */
function scaleFilter(maxSide, factor = 1, even = false) {
  const k = `min(1,${maxSide}/max(iw,ih))*${factor}`;
  const dim = (d) => (even ? `max(2,trunc(${k}*${d}/2)*2)` : `max(1,trunc(${k}*${d}))`);
  return `scale='${dim("iw")}':'${dim("ih")}'`;
}

function ensureTools() {
  const t = tools();
  if (!t.ffmpeg) throw new ConvertError("Konwersja wymaga programu ffmpeg (ustaw FFMPEG_PATH albo umieść go w PATH).");
  return t;
}

function animated(buf, kind) {
  if (kind === "gif" || (buf.length > 6 && buf.toString("latin1", 0, 4) === "GIF8")) return true;
  if (buf.length > 30 && buf.toString("latin1", 0, 4) === "RIFF" && buf.toString("latin1", 8, 12) === "WEBP" && buf.toString("latin1", 12, 16) === "VP8X") {
    return (buf[20] & 0x02) !== 0;
  }
  if (buf.length > 8 && buf.toString("latin1", 0, 8) === "\x89PNG\r\n\x1a\n") return buf.subarray(0, 4096).includes("acTL"); // APNG
  return false;
}

// ---------- obrazy ----------
/**
 * Obraz statyczny/animowany do formatu przyjmowanego przez aplikację jako obraz zakładki.
 * Zwraca { bytes, ext, quality } (quality — jakość JXL do `imageQuality`, albo null).
 * @param {Buffer} buf  oryginał, @param {string|null} kind  wynik sniffImage (może być null dla formatów nieznanych serwerowi)
 */
export async function convertImage(buf, kind = null, { maxBytes = MAX_IMAGE_BYTES, maxSide = MAX_IMAGE_SIDE, startQuality = null } = {}) {
  const t = ensureTools();
  // jakość startowa (1–100) wybrana przez operatora w panelu; domyślnie 90. Gdy plik nie mieści się w limicie, schodzimy niżej.
  const q0 = Number.isInteger(startQuality) && startQuality >= 1 && startQuality <= 100 ? startQuality : 90;
  return withTemp(async (dir) => {
    const inFile = await readableInput(t, dir, buf);
    if (animated(buf, kind)) return convertAnimation(t, dir, inFile, maxBytes, maxSide);

    // przy zbyt dużym pliku/obrazie schodzimy z jakością, a potem z rozdzielczością
    const steps = [];
    for (const f of [1, 0.75, 0.5, 0.35]) for (const q of f === 1 ? [q0, ...[90, 80, 70, 60].filter((x) => x < q0)] : [Math.min(q0, 80)]) steps.push({ factor: f, q });
    let last = null;
    for (const { factor, q } of steps) {
      const png = join(dir, "step.png");
      const dec = await runVf(t, ["-y", "-v", "error", "-i", inFile, "-frames:v", "1", "-map_metadata", "-1"], scaleFilter(maxSide, factor), [png]);
      if (dec.code !== 0 || !fs.existsSync(png)) throw new ConvertError("Nie rozpoznaję tego pliku jako obrazu (ffmpeg: " + dec.err.trim().split("\n").pop() + ")");
      let out, ext, quality = null;
      if (t.jxl === "cjxl") {
        out = join(dir, "out.jxl"); ext = "jxl"; quality = q;
        const r = await run(t.cjxl, [png, out, "-q", String(q), "-e", "7", "--quiet"]);
        if (r.code !== 0 || !fs.existsSync(out)) throw new ConvertError("Kodowanie JPEG XL nie powiodło się: " + r.err.trim().split("\n").pop());
      } else if (t.jxl === "ffmpeg") {
        out = join(dir, "out.jxl"); ext = "jxl"; quality = q;
        const distance = String(Math.max(0.1, (100 - q) / 10)); // q 90 → odległość 1,0
        const r = await run(t.ffmpeg, ["-y", "-v", "error", "-i", png, "-c:v", "libjxl", "-distance", distance, "-map_metadata", "-1", out]);
        if (r.code !== 0 || !fs.existsSync(out)) throw new ConvertError("Kodowanie JPEG XL (ffmpeg) nie powiodło się: " + r.err.trim().split("\n").pop());
      } else {
        out = join(dir, "out.webp"); ext = "webp";
        const r = await run(t.ffmpeg, ["-y", "-v", "error", "-i", png, "-c:v", "libwebp", "-quality", String(Math.min(q, 85)), "-map_metadata", "-1", out]);
        if (r.code !== 0 || !fs.existsSync(out)) throw new ConvertError("Kodowanie WebP nie powiodło się: " + r.err.trim().split("\n").pop());
      }
      const bytes = fs.readFileSync(out);
      last = { bytes, ext, quality };
      if (bytes.length <= maxBytes) return last;
    }
    throw new ConvertError(`Obraz po konwersji nadal przekracza ${maxBytes} bajtów (${last ? last.bytes.length : "?"}).`);
  });
}

async function convertAnimation(t, dir, inFile, maxBytes, maxSide) {
  let last = null;
  for (const { factor, q } of [{ factor: 1, q: 70 }, { factor: 1, q: 50 }, { factor: 0.75, q: 50 }, { factor: 0.5, q: 45 }, { factor: 0.35, q: 40 }]) {
    const out = join(dir, "anim.webp");
    const r = await run(t.ffmpeg, ["-y", "-v", "error", "-i", inFile, "-vf", scaleFilter(Math.min(maxSide, 1280), factor), "-c:v", "libwebp_anim", "-loop", "0", "-quality", String(q), "-map_metadata", "-1", out]);
    if (r.code !== 0 || !fs.existsSync(out)) throw new ConvertError("Nie udało się przekonwertować animacji: " + r.err.trim().split("\n").pop());
    last = { bytes: fs.readFileSync(out), ext: "webp", quality: null };
    if (last.bytes.length <= maxBytes) return last;
  }
  throw new ConvertError(`Animacja po konwersji nadal przekracza ${maxBytes} bajtów.`);
}

/** Mały WebP do powiadomienia (a przy okazji do budzika, gdy ≤ MAX_THUMB_BYTES). */
export async function makeThumbnail(buf, { maxBytes = MAX_THUMB_BYTES } = {}) {
  const t = ensureTools();
  return withTemp(async (dir) => {
    const inFile = await readableInput(t, dir, buf);
    let smallest = null;
    for (const side of [320, 256, 200, 160, 128]) {
      for (const q of [70, 55, 40, 30]) {
        const out = join(dir, "t.webp");
        const r = await runVf(t, ["-y", "-v", "error", "-i", inFile, "-frames:v", "1"], scaleFilter(side), ["-c:v", "libwebp", "-quality", String(q), "-map_metadata", "-1", out]);
        if (r.code !== 0 || !fs.existsSync(out)) throw new ConvertError("Nie udało się zrobić miniatury powiadomienia.");
        const bytes = fs.readFileSync(out);
        if (!smallest || bytes.length < smallest.length) smallest = bytes;
        if (bytes.length <= maxBytes) return { bytes, ext: "webp", quality: null, fitsWake: true };
      }
    }
    return { bytes: smallest, ext: "webp", quality: null, fitsWake: smallest.length <= maxBytes };
  });
}

/** Awatar autora: mały WebP (do 512 px). */
export async function makeAvatar(buf) {
  const t = ensureTools();
  return withTemp(async (dir) => {
    const inFile = await readableInput(t, dir, buf);
    const out = join(dir, "a.webp");
    const r = await runVf(t, ["-y", "-v", "error", "-i", inFile, "-frames:v", "1"], scaleFilter(512), ["-c:v", "libwebp", "-quality", "80", "-map_metadata", "-1", out]);
    if (r.code !== 0 || !fs.existsSync(out)) throw new ConvertError("Nie rozpoznaję tego pliku jako obrazu.");
    return { bytes: fs.readFileSync(out), ext: "webp", quality: null };
  });
}

// ---------- film ----------
function probeVideo(t, file) {
  if (!t.ffprobe) return { fps: null, hasAudio: true };
  const v = runCapture(t.ffprobe, ["-v", "error", "-select_streams", "v:0", "-show_entries", "stream=avg_frame_rate,r_frame_rate,width,height", "-of", "json", file]);
  const a = runCapture(t.ffprobe, ["-v", "error", "-select_streams", "a:0", "-show_entries", "stream=codec_name", "-of", "json", file]);
  let fps = null;
  try {
    const s = JSON.parse(v.out).streams?.[0];
    if (!s) return null; // brak ścieżki wideo
    const parse = (x) => { const [n, d] = String(x || "0/1").split("/").map(Number); return d ? n / d : 0; };
    fps = Math.max(parse(s.avg_frame_rate), parse(s.r_frame_rate)) || null;
  } catch { return null; }
  let hasAudio = false;
  try { hasAudio = (JSON.parse(a.out).streams || []).length > 0; } catch { /* brak */ }
  return { fps, hasAudio };
}

// ---------- kodery wideo: GPU (jeśli jest) zamiast CPU ----------
// Kolejność automatyczna: NVIDIA NVENC → Intel QuickSync → AMD AMF → Apple VideoToolbox → VAAPI (Linux) → CPU.
// Dla każdego kodera są dwa zestawy parametrów: „bogaty” (look-ahead, adaptacyjna kwantyzacja, B-ramki — poprawiają
// jakość/bitrate przy zerowym albo znikomym koszcie) i „podstawowy” (dla starszych sterowników/ffmpeg).
// Dostępność sprawdzamy PRAWDZIWYM kodowaniem próbnym (sama obecność kodera w ffmpeg nie znaczy, że jest karta).
// numeracja kart NVIDIA w ffmpeg (-gpu N) ma zgadzać się z nvidia-smi (kolejność magistrali PCI), a nie z „najszybsza pierwsza”
process.env.CUDA_DEVICE_ORDER ||= "PCI_BUS_ID";
const VAAPI_DEVICE = process.env.VAAPI_DEVICE || "/dev/dri/renderD128";
const HW_ORDER = ["nvenc", "qsv", "amf", "videotoolbox", "vaapi"];
const HW_LABEL = { nvenc: "NVIDIA NVENC", qsv: "Intel Quick Sync", amf: "AMD AMF", videotoolbox: "Apple VideoToolbox", vaapi: "VAAPI (Linux)", cpu: "CPU (x264/x265)" };
const ENC_NAME = { nvenc: { hevc: "hevc_nvenc", avc: "h264_nvenc" }, qsv: { hevc: "hevc_qsv", avc: "h264_qsv" }, amf: { hevc: "hevc_amf", avc: "h264_amf" },
  videotoolbox: { hevc: "hevc_videotoolbox", avc: "h264_videotoolbox" }, vaapi: { hevc: "hevc_vaapi", avc: "h264_vaapi" } };

/** { pre: argumenty przed -i, vfTail: końcówka filtra, args: kodek, pixfmt: czy dodać -pix_fmt yuv420p } */
function encoderSpec(kind, codec, level, device = null) {
  const hevc = codec === "hevc";
  const tag = hevc ? ["-tag:v", "hvc1"] : ["-profile:v", "main"];
  const c = ENC_NAME[kind]?.[codec];
  const rich = level === "rich";
  switch (kind) {
    case "nvenc":
      return { pre: [], vfTail: "", pixfmt: true, args: rich
        ? ["-c:v", c, ...(device != null ? ["-gpu", String(device)] : []), "-preset", "p6", "-tune", "hq", "-rc", "vbr", "-cq", hevc ? "28" : "26", "-b:v", "0", "-spatial-aq", "1", "-temporal-aq", "1", "-rc-lookahead", "32", "-bf", "3", ...(hevc ? ["-b_ref_mode", "middle"] : []), ...tag]
        : ["-c:v", c, ...(device != null ? ["-gpu", String(device)] : []), "-preset", "slow", "-rc", "vbr", "-cq", hevc ? "28" : "26", "-b:v", "0", ...tag] };
    case "qsv":
      return { pre: device != null ? ["-init_hw_device", `qsv=hw:hw_any,child_device=${device},child_device_type=d3d11va`] : [], vfTail: "", pixfmt: true, args: rich
        ? ["-c:v", c, "-preset", "slow", "-global_quality", hevc ? "28" : "26", "-look_ahead", "1", "-look_ahead_depth", "40", "-adaptive_i", "1", "-adaptive_b", "1", ...tag]
        : ["-c:v", c, "-global_quality", hevc ? "28" : "26", ...tag] };
    case "amf":
      return { pre: device != null ? ["-init_hw_device", `amf=hw:${device}`] : [], vfTail: "", pixfmt: true, args: rich
        ? ["-c:v", c, "-usage", "transcoding", "-quality", "quality", "-rc", "qvbr", "-qvbr_quality_level", hevc ? "25" : "23", "-preanalysis", "1", "-vbaq", "1", ...tag]
        : ["-c:v", c, "-quality", "quality", "-rc", "cqp", "-qp_i", "24", "-qp_p", "26", "-qp_b", "28", ...tag] };
    case "videotoolbox":
      return { pre: [], vfTail: "", pixfmt: true, args: rich
        ? ["-c:v", c, "-q:v", "60", "-allow_sw", "0", ...tag]
        : ["-c:v", c, "-b:v", "3M", ...tag] };
    case "vaapi":
      return { pre: ["-vaapi_device", device || VAAPI_DEVICE], vfTail: "format=nv12,hwupload", pixfmt: false, args: ["-c:v", c, "-qp", hevc ? "28" : "26", ...tag] };
    default: // cpu: look-ahead i adaptacyjna kwantyzacja w x264/x265 prawie nic nie kosztują, a oszczędzają bitrate
      return { pre: [], vfTail: "", pixfmt: true, args: hevc
        ? ["-c:v", "libx265", "-crf", "28", "-preset", "medium", "-tag:v", "hvc1", "-x265-params", "log-level=error:aq-mode=3:rc-lookahead=40:b-adapt=2:weightb=1"]
        : ["-c:v", "libx264", "-crf", "26", "-preset", "medium", "-profile:v", "main", "-x264-params", "aq-mode=3:rc-lookahead=40:b-adapt=2:weightp=2"] };
  }
}

let encoderProbe = null; // Promise<{ encoders: [{ id, kind, device, label, hevc: level|null, avc: level|null }] }>
let preference = "auto"; // "auto" | "cpu" | id kodera (np. "nvenc:0", "qsv", "vaapi:/dev/dri/renderD129")
const ENV_PREF = (process.env.VIDEO_ENCODER || "").replace(/^[A-Za-z]+/, (m) => m.toLowerCase()); // wielkość liter części po „:” (ścieżka VAAPI) zostaje // wymusza wybór i blokuje zmianę w panelu

function nvidiaNames() {
  try {
    const r = spawnSync("nvidia-smi", ["--query-gpu=name", "--format=csv,noheader"], { encoding: "utf8", timeout: 6000, windowsHide: true });
    return r.status === 0 ? r.stdout.split(/\r?\n/).map((x) => x.trim()).filter(Boolean) : [];
  } catch { return []; }
}

/** Liczba adapterów DXGI (indeksy 0…n-1 dla -init_hw_device) — sprawdzana próbą inicjalizacji kolejnych indeksów. */
async function dxgiAdapterCount(t) {
  let n = 0;
  for (let i = 0; i < 8; i++) {
    const r = await run(t.ffmpeg, ["-v", "error", "-init_hw_device", `d3d11va=d3d:${i}`, "-f", "lavfi", "-i", "color=c=black:s=64x64:d=0.1", "-frames:v", "1", "-f", "null", "-"], { timeout: 15_000 });
    if (r.code !== 0) break;
    n++;
  }
  return n;
}

let adapterCache = null;
/** Nazwy kart graficznych z systemu (Windows: Win32_VideoController); gdzie się nie da — pusta lista (podajemy wtedy samego producenta). */
function adapterNames() {
  if (adapterCache) return adapterCache;
  adapterCache = [];
  try {
    if (process.platform === "win32") {
      const r = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name"], { encoding: "utf8", timeout: 15000, windowsHide: true });
      if (r.status === 0) adapterCache = r.stdout.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
    }
  } catch { /* bez nazw */ }
  return adapterCache;
}
/** Nazwa konkretnej karty danego producenta, jeśli jest jednoznaczna (dokładnie jedna); inaczej samo „Producent”. */
function vendorLabel(vendorRe, vendor, tech) {
  const m = adapterNames().filter((n) => vendorRe.test(n));
  return m.length === 1 ? `${m[0]} (${tech})` : `${vendor} ${tech}`;
}

/** Kandydaci do sprawdzenia: każdy może być osobnym urządzeniem (np. dwie karty NVIDIA, dwa węzły VAAPI). */
function encoderCandidates() {
  const out = [];
  const names = nvidiaNames();
  for (let i = 0; i < 8; i++) out.push({ kind: "nvenc", device: i, label: `${names[i] || "NVIDIA GPU"}${names.length > 1 || i > 0 ? ` — GPU ${i}` : ""} (NVENC)` });
  out.push({ kind: "qsv", device: null, label: vendorLabel(/intel/i, "Intel", "Quick Sync") });
  out.push({ kind: "amf", device: null, label: vendorLabel(/amd|radeon/i, "AMD", "AMF") });
  if (process.platform === "darwin") out.push({ kind: "videotoolbox", device: null, label: "Apple VideoToolbox" });
  if (process.platform === "linux") {
    let nodes = [];
    try { nodes = fs.readdirSync("/dev/dri").filter((n) => /^renderD\d+$/.test(n)).sort().map((n) => "/dev/dri/" + n); } catch { /* brak */ }
    for (const n of nodes) out.push({ kind: "vaapi", device: n, label: `VAAPI ${n}` });
  }
  return out.map((c) => ({ ...c, id: c.device == null ? c.kind : `${c.kind}:${c.device}` }));
}

/** Sprawdza (raz) które kodery sprzętowe działają na tym komputerze — WSZYSTKIE, żeby można było wybrać. */
export function probeVideoEncoders() {
  if (encoderProbe) return encoderProbe;
  encoderProbe = (async () => {
    const t = tools();
    const encoders = [];
    if (!t.ffmpeg || ENV_PREF === "cpu") return { encoders };
    let listing = "";
    try { listing = spawnSync(t.ffmpeg, ["-hide_banner", "-encoders"], { encoding: "utf8", timeout: 8000 }).stdout || ""; } catch { /* brak */ }
    const hasEnc = (kind, codec) => new RegExp("\\b" + ENC_NAME[kind][codec] + "\\b").test(listing);
    let nvenc404 = false; // kolejna karta NVIDIA istnieje tylko, jeśli poprzednia indeksem działała
    const candidates = encoderCandidates();
    // Windows: Quick Sync i AMF mogą działać na kilku kartach naraz (np. Arc + zintegrowana) — sprawdzamy każdy adapter DXGI osobno
    const adapters = process.platform === "win32" ? await dxgiAdapterCount(t) : 0;
    for (let i = 0; i < adapters; i++) {
      candidates.push({ kind: "qsv", device: i, label: `Intel Quick Sync (adapter ${i})`, id: `qsv:${i}`, indexed: true });
      candidates.push({ kind: "amf", device: i, label: `AMD AMF (adapter ${i})`, id: `amf:${i}`, indexed: true });
    }
    for (const c of candidates) {
      if (c.kind === "nvenc" && nvenc404) continue;
      const entry = { ...c, hevc: null, avc: null };
      for (const codec of ["hevc", "avc"]) {
        if (!hasEnc(c.kind, codec)) continue;
        for (const level of ["rich", "basic"]) {
          const sp = encoderSpec(c.kind, codec, level, c.device);
          const vf = ["scale=640:360", sp.vfTail].filter(Boolean).join(",");
          const r = await run(t.ffmpeg, ["-v", "error", ...sp.pre, "-f", "lavfi", "-i", "testsrc2=size=640x360:rate=30", "-frames:v", "20", "-vf", vf, ...sp.args, ...(sp.pixfmt ? ["-pix_fmt", "yuv420p"] : []), "-f", "null", "-"], { timeout: 30_000 });
          if (r.code === 0) { entry[codec] = level; break; }
        }
      }
      if (entry.hevc || entry.avc) encoders.push(entry);
      else if (c.kind === "nvenc") nvenc404 = true;
    }
    // Quick Sync / AMF: gdy działa więcej niż jeden adapter danego rodzaju — zostają wpisy indeksowane (z nazwami kart),
    // w przeciwnym razie jedna pozycja domyślna (tak jak dotąd)
    for (const kind of ["qsv", "amf"]) {
      const indexed = encoders.filter((e) => e.kind === kind && e.indexed);
      const plain = encoders.findIndex((e) => e.kind === kind && !e.indexed);
      if (indexed.length >= 2) {
        if (plain >= 0) encoders.splice(plain, 1);
        const names = adapterNames().filter((n) => (kind === "qsv" ? /intel/i : /amd|radeon/i).test(n));
        indexed.forEach((e, k) => { e.label = names.length === indexed.length ? `${names[k]} (${kind === "qsv" ? "Quick Sync" : "AMF"})` : `${kind === "qsv" ? "Intel Quick Sync" : "AMD AMF"} — adapter ${e.device}`; });
      } else {
        for (const e of indexed) encoders.splice(encoders.indexOf(e), 1);
      }
    }
    if (ENV_PREF && ENV_PREF !== "auto" && ENV_PREF !== "cpu" && !encoders.some((e) => e.id === ENV_PREF)) console.warn(`[wideo] VIDEO_ENCODER=${ENV_PREF}: taki działający koder nie został wykryty — używam kodera automatycznie`);
    console.log(`[wideo] kodery sprzętowe: ${encoders.length ? encoders.map((e) => e.label).join("; ") : "brak (kodowanie na CPU)"}`);
    for (const codec of ["hevc", "avc"]) console.log(`[wideo] ${codec === "hevc" ? "H.265" : "H.264"}: używam ${pickEncoder(codec, { encoders }).label}`);
    return { encoders };
  })();
  return encoderProbe;
}

const CPU_ENTRY = { id: "cpu", kind: "cpu", device: null, label: "CPU (x264/x265)", hevc: "rich", avc: "rich" };

/** Wybór kodera dla danego kodeka wg preferencji (auto = pierwszy działający sprzętowy, inaczej CPU). */
function pickEncoder(codec, probe) {
  const pref = ENV_PREF || preference;
  const usable = (probe?.encoders || []).filter((e) => e[codec]);
  if (pref === "cpu") return CPU_ENTRY;
  const chosen = pref !== "auto" ? usable.find((e) => e.id === pref) : null;
  return chosen || usable[0] || CPU_ENTRY;
}

export function setVideoEncoderPreference(p) { preference = typeof p === "string" && p ? p : "auto"; }

/** Stan do panelu: dostępne kodery, wybór, co faktycznie zostanie użyte. */
export async function videoEncoderStatus() {
  const probe = await probeVideoEncoders();
  const eff = (codec) => pickEncoder(codec, probe).label;
  return {
    preference: ENV_PREF || preference,
    locked: !!ENV_PREF,
    options: [
      { id: "auto", label: "Automatycznie (pierwszy działający koder sprzętowy, inaczej CPU)" },
      ...probe.encoders.map((e) => ({ id: e.id, label: e.label, hevc: !!e.hevc, avc: !!e.avc })),
      { id: "cpu", label: CPU_ENTRY.label, hevc: true, avc: true },
    ],
    effective: { hevc: eff("hevc"), avc: eff("avc") },
  };
}

/**
 * Dowolny film → MP4 w wariancie `want` ("hevc" | "avc"): ≤ 30 kl/s, ≤ 1920 px, dźwięk Opus (albo brak),
 * spis na początku, bez metadanych.
 */
export async function convertVideo(buf, want) {
  const tStart = Date.now();
  const t = ensureTools();
  return withTemp(async (dir) => {
    const inFile = join(dir, "in.bin");
    fs.writeFileSync(inFile, buf);
    const info = probeVideo(t, inFile);
    if (info === null) throw new ConvertError("W tym pliku nie ma ścieżki wideo, którą umiem odczytać.");
    const filters = [scaleFilter(MAX_VIDEO_SIDE, 1, true)];
    if (info.fps === null || info.fps > MAX_VIDEO_FPS + 0.05) filters.push(`fps=${MAX_VIDEO_FPS}`);
    const out = join(dir, "out.mp4");
    const probe = await probeVideoEncoders();
    const attempt = async (enc) => {
      const sp = encoderSpec(enc.kind, want, enc[want], enc.device);
      try { fs.rmSync(out, { force: true }); } catch { /* ignore */ }
      const vf = [...filters, sp.vfTail].filter(Boolean).join(",");
      const vArgs = ["-vf", vf, ...sp.args, ...(sp.pixfmt ? ["-pix_fmt", "yuv420p"] : [])];
      if (enc.kind === "cpu") {
        return run(t.ffmpeg, ["-y", "-v", "error", ...sp.pre, "-i", inFile, "-map", "0:v:0", "-map", "0:a:0?", ...vArgs,
          "-c:a", "libopus", "-b:a", "48k", "-map_metadata", "-1", "-map_chapters", "-1", "-movflags", "+faststart", out], { timeout: VIDEO_TIMEOUT_MS });
      }
      // koder sprzętowy: obraz osobno (bez dźwięku), potem scalenie — w jednym przebiegu część sterowników (np. Intel QSV)
      // przerywa kodowanie dźwięku Opus („Invalid argument”)
      const vOnly = join(dir, "video-hw.mp4");
      try { fs.rmSync(vOnly, { force: true }); } catch { /* ignore */ }
      const r1 = await run(t.ffmpeg, ["-y", "-v", "error", ...sp.pre, "-i", inFile, "-map", "0:v:0", "-an", ...vArgs, "-map_metadata", "-1", "-map_chapters", "-1", vOnly], { timeout: VIDEO_TIMEOUT_MS });
      if (r1.code !== 0 || !fs.existsSync(vOnly)) return r1;
      return run(t.ffmpeg, ["-y", "-v", "error", "-i", vOnly, "-i", inFile, "-map", "0:v:0", "-map", "1:a:0?", "-c:v", "copy",
        "-c:a", "libopus", "-b:a", "48k", "-map_metadata", "-1", "-map_chapters", "-1", "-movflags", "+faststart", out], { timeout: VIDEO_TIMEOUT_MS });
    };
    const pick = pickEncoder(want, probe);
    let r = await attempt(pick);
    if ((r.code !== 0 || !fs.existsSync(out)) && pick.kind !== "cpu") {
      console.warn(`[wideo] ${pick.label} nie dał rady (${r.err.trim().split("\n").pop()}) — kodowanie na CPU`);
      r = await attempt(CPU_ENTRY);
    }
    if (r.code !== 0 || !fs.existsSync(out)) {
      logger.error("media", "film-blad", "konwersja filmu nie powiodła się", { kodek: want, koder: pick.label, ffmpeg: r.err.trim().split("\n").pop() });
      throw new ConvertError("Konwersja filmu nie powiodła się: " + r.err.trim().split("\n").pop());
    }
    const result = fs.readFileSync(out);
    logger.info("media", "film", `film przekodowany: ${want}`, { kodek: want, koder: pick.label, wejscieB: buf.length, wyjscieB: result.length, ms: Date.now() - tStart, fpsWejscia: info.fps });
    return result;
  });
}

// ---------- dźwięk ----------
/** Dowolny dźwięk (także ścieżka z filmu) → Opus w Ogg, 48 kb/s. */
export async function convertAudio(buf) {
  const t = ensureTools();
  return withTemp(async (dir) => {
    const inFile = join(dir, "in.bin");
    fs.writeFileSync(inFile, buf);
    const out = join(dir, "out.opus");
    const r = await run(t.ffmpeg, ["-y", "-v", "error", "-i", inFile, "-vn", "-map", "0:a:0", "-c:a", "libopus", "-b:a", "48k", "-map_metadata", "-1", "-f", "ogg", out], { timeout: VIDEO_TIMEOUT_MS });
    if (r.code !== 0 || !fs.existsSync(out)) throw new ConvertError("Nie rozpoznaję w tym pliku dźwięku (ffmpeg: " + r.err.trim().split("\n").pop() + ")");
    return fs.readFileSync(out);
  });
}

export function describeTools() {
  const t = tools();
  return {
    available: !!t.ffmpeg,
    ffmpeg: !!t.ffmpeg,
    ffprobe: !!t.ffprobe,
    jpegxl: t.jxl,           // "cjxl" | "ffmpeg" | null
    note: !t.ffmpeg ? "Bez ffmpeg serwer przyjmuje tylko pliki w poprawnych formatach." : t.jxl ? "" : "Brak kodera JPEG XL — obrazy będą kodowane do WebP.",
  };
}

/** Wymiary obrazu przez ffprobe ({width,height}) albo null, gdy się nie da (brak ffprobe / nieznany format). */
export function imageSize(buf) {
  const t = tools();
  if (!t.ffprobe) return null;
  const dir = fs.mkdtempSync(join(os.tmpdir(), "lewicowyt-probe-"));
  try {
    const f = join(dir, "in.bin");
    fs.writeFileSync(f, buf);
    const r = runCapture(t.ffprobe, ["-v", "error", "-select_streams", "v:0", "-show_entries", "stream=width,height", "-of", "json", f]);
    const s = JSON.parse(r.out).streams?.[0];
    return s && s.width && s.height ? { width: s.width, height: s.height } : null;
  } catch { return null; }
  finally { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ } }
}
