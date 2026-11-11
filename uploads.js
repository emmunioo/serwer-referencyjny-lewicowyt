// Wgrywanie multimediów do wpisu (obraz, miniatura powiadomienia, awatar, dźwięk, film).
// Z ffmpeg (patrz convert.js) serwer przyjmuje DOWOLNY plik i sam przygotowuje go do postaci, którą przyjmuje
// aplikacja: obrazy → JPEG XL (albo WebP), film → H.265 + H.264 (≤ 30 kl/s, Opus, faststart), dźwięk → Opus.
// Bez ffmpeg przyjmowane są tylko pliki już w poprawnym formacie (jak w wersjach wcześniejszych), ale z pełną
// kontrolą limitów aplikacji. W obu trybach z plików znikają metadane (EXIF/GPS, lokalizacja w filmach).

import fs from "node:fs";
import { join, basename } from "node:path";
import { randomBytes } from "node:crypto";
import * as store from "./store.js";
import * as push from "./push.js";
import * as logger from "./logger.js";
import { sniffImage, formatMatches, sniffAudio, oggOpusDurationMs, mp4VideoInfo, mp4AudioCodec, webmAudioIsOpus, mp4FastStart } from "./media.js";
import { stripImageMetadata, mp4StripMetadata } from "./metadata.js";
import * as convert from "./convert.js";

const MB = 1024 * 1024;
const MAX_AUDIO_BYTES = 80 * MB;          // limit aplikacji na plik dźwiękowy
const MAX_VIDEO_BYTES = 200 * MB;         // limit aplikacji na jeden wariant filmu
const MAX_INPUT_IMAGE = 64 * MB;          // wejście do konwersji (np. nieskompresowany PNG)
const MAX_INPUT_AUDIO = 200 * MB;
const MAX_INPUT_VIDEO = 400 * MB;
const MAX_AVATAR_KEEP = 300 * 1024;       // większy awatar zmniejszamy
const IMAGE_TYPES = { "image/jxl": "jxl", "image/avif": "avif", "image/webp": "webp", "image/png": "png", "image/jpeg": "jpg" };
const AUDIO_TYPES = { "audio/ogg": "opus", "audio/opus": "opus", "application/ogg": "opus", "audio/webm": "webm", "video/webm": "webm" };
const FEED = ["jxl", "avif", "webp"];     // formaty obrazu zakładki (imageUrl)
const NOTIFY = ["jpg", "png", "webp"];    // formaty obrazu powiadomienia (notifyImageUrl)

const fail = (code, error) => ({ fail: { code, error } });

// ---------- film ----------
function videoProblem(info, soundtrack, want) {
  if (!info) return "To nie jest film MP4 ze ścieżką wideo";
  if (info.codec !== want) return `Ten plik ma kodek ${info.codec.toUpperCase()}, a to pole wymaga ${want === "hevc" ? "H.265 (HEVC)" : "H.264 (AVC)"}`;
  if (info.fragmented || !info.fps) return "Nie da się sprawdzić liczby klatek (plik pofragmentowany). Zapisz zwykłe MP4, np. ffmpeg bez -movflags frag_keyframe.";
  if (soundtrack && soundtrack !== "Opus") return `Dźwięk w filmie to ${soundtrack === "mp4a" ? "AAC" : soundtrack} — aplikacja odtwarza tylko Opus. Przekoduj dźwięk: ffmpeg … -c:a libopus -b:a 48k`;
  if (info.fps > convert.MAX_VIDEO_FPS + 0.05) return `Film ma ${info.fps} kl/s — dozwolone najwyżej ${convert.MAX_VIDEO_FPS}. Aplikacja go nie odtworzy. Przekoduj: ffmpeg … -r 30`;
  if (Math.max(info.width, info.height) > convert.MAX_VIDEO_SIDE) return `Rozdzielczość ${info.width}×${info.height} — najwyżej ${convert.MAX_VIDEO_SIDE} px na dłuższy bok`;
  return null;
}

async function prepareVideo(input, want, conv) {
  let bytes = input;
  let info = mp4VideoInfo(bytes);
  let problem = videoProblem(info, info ? mp4AudioCodec(bytes) : null, want);
  if (problem && conv) {
    try { bytes = await convert.convertVideo(input, want); }
    catch (e) { return fail(415, e.message || "Konwersja filmu nie powiodła się"); }
    info = mp4VideoInfo(bytes);
    problem = videoProblem(info, info ? mp4AudioCodec(bytes) : null, want);
  }
  if (problem) return fail(415, problem);
  // spis (moov) na początek: aplikacja sprawdza film z pierwszych KB i przerywa zły plik bez pobierania całości
  const fast = mp4FastStart(bytes);
  if (!fast) return fail(415, "Nie udało się przenieść spisu filmu (moov) na początek. Zapisz z: ffmpeg … -movflags +faststart");
  // S-01: bez lokalizacji i danych urządzenia (udta/meta/uuid) — film widzą wszyscy
  const clean = mp4StripMetadata(fast);
  if (!clean) return fail(415, "Nie udało się usunąć metadanych filmu (np. lokalizacji). Zapisz go ponownie, np. ffmpeg … -map_metadata -1 -movflags +faststart");
  if (clean.length > MAX_VIDEO_BYTES) return fail(413, `Film po przygotowaniu ma ${Math.round(clean.length / MB)} MB — limit aplikacji to ${MAX_VIDEO_BYTES / MB} MB na wariant`);
  return { bytes: clean, info };
}

// ---------- obraz ----------
/** Decyzja i przygotowanie obrazu: { bytes, ext, quality } albo { fail }. */
async function prepareImage(bytes, imgKind, ctype, conv, startQuality = null) {
  const real = sniffImage(bytes);
  // --- bez konwertera: tylko poprawne formaty, ale z pełną kontrolą ---
  if (!conv) {
    const ext = IMAGE_TYPES[ctype];
    if (!ext) return fail(415, "Dozwolone: JXL / AVIF / WEBP (obraz zakładki), JPG / PNG / WEBP (miniatura). Inne formaty przyjmę, gdy zainstalujesz ffmpeg (serwer sam je przekonwertuje).");
    if (!formatMatches(real, ext)) {
      return fail(415, real ? `To nie jest ${ext.toUpperCase()}, tylko ${real.toUpperCase()} — wybierz plik jeszcze raz albo zapisz go jako ${ext.toUpperCase()}` : "Plik nie jest obrazem JXL/AVIF/WEBP/PNG/JPG");
    }
    if (imgKind === "image" && !FEED.includes(real)) return fail(415, `${real.toUpperCase()} aplikacja pokaże tylko jako miniaturę powiadomienia, nie jako obraz wpisu. Wgraj JXL, AVIF lub WEBP — albo zainstaluj ffmpeg, a serwer sam przekonwertuje plik.`);
    if (imgKind === "thumb" && !NOTIFY.includes(real)) return fail(415, "Miniatura powiadomienia: JPG, PNG albo WEBP");
    if (imgKind === "avatar" && !FEED.includes(real)) return fail(415, "Awatar: WEBP, JXL albo AVIF");
    if (bytes.length > convert.MAX_IMAGE_BYTES) return fail(413, `Obraz ma ${(bytes.length / 1e6).toFixed(1)} MB — aplikacja przyjmuje najwyżej ${convert.MAX_IMAGE_BYTES / 1e6} MB. Zmniejsz go albo zainstaluj ffmpeg (serwer sam to zrobi).`);
    return stripOnly(bytes, real);
  }
  // --- z konwerterem ---
  try {
    if (imgKind === "thumb") {
      if (NOTIFY.includes(real) && bytes.length <= convert.MAX_THUMB_BYTES) return stripOnly(bytes, real);
      const t = await convert.makeThumbnail(bytes);
      return { bytes: t.bytes, ext: t.ext, quality: null, warning: t.fitsWake ? undefined : `Miniatura ma ${Math.round(t.bytes.length / 1024)} KB — do budzika trafia tylko plik do ${Math.round(convert.MAX_THUMB_BYTES / 1000)} KB, więc apka pobierze ją osobno` };
    }
    if (imgKind === "avatar") {
      if (FEED.includes(real) && bytes.length <= MAX_AVATAR_KEEP) return stripOnly(bytes, real);
      return await convert.makeAvatar(bytes);
    }
    // obraz zakładki: zostawiamy to, co już jest dobre (JXL/AVIF/WEBP w limitach), resztę zamieniamy na JXL
    if (real && FEED.includes(real) && bytes.length <= convert.MAX_IMAGE_BYTES && withinSide(bytes)) return stripOnly(bytes, real);
    return await convert.convertImage(bytes, real, { startQuality });
  } catch (e) {
    return fail(415, e.message || "Nie udało się przygotować obrazu");
  }
}

function withinSide(bytes) {
  const s = convert.imageSize(bytes);
  return !s || Math.max(s.width, s.height) <= convert.MAX_IMAGE_SIDE; // bez ffprobe nie wiemy — przepuszczamy
}

function stripOnly(bytes, real) {
  const clean = stripImageMetadata(bytes, real);
  if (!clean) return fail(415, "Nie udało się usunąć z obrazu metadanych (np. lokalizacji GPS). Zapisz obraz ponownie, najlepiej jako WEBP.");
  return { bytes: clean, ext: real, quality: null };
}

// ---------- obsługa żądania ----------
export async function handleItemImage({ req, res, json, readBody, invalidateManifest }) {
  const url = new URL(req.url, "http://x");
  const d = store.load();
  const item = store.findItem(d, url.searchParams.get("itemId"));
  if (!item) return json(res, 404, { error: "Nie ma takiego wpisu" });
  const ctype = (req.headers["content-type"] || "").split(";")[0].trim();
  const kind = url.searchParams.get("kind");
  const conv = convert.available();
  const rm = (name) => { if (name) store.deleteMedia(basename(name)); };
  const put = (name, bytes) => store.putMedia(name, bytes);
  const commit = () => { store.bumpRev(item); store.save(d); invalidateManifest(); };
  const body = async (limit) => { try { return await readBody(req, limit); } catch { return null; } };
  const tooBig = (limit) => json(res, 413, { error: `Plik za duży (max ${Math.round(limit / MB)} MB)` });

  // ----- film -----
  if (kind === "video" || kind === "video_hevc" || kind === "video_avc") {
    if (!["post", "article", "foreign", "meme"].includes(item.type)) return json(res, 400, { error: "Film można dodać do posta, artykułu, wpisu z innej platformy albo mema" });
    if (kind === "video" && !conv) return json(res, 400, { error: "Automatyczne przygotowanie filmu wymaga ffmpeg. Bez niego wgraj osobno gotowe pliki H.265 i H.264 (MP4)." });
    const limit = conv ? MAX_INPUT_VIDEO : MAX_VIDEO_BYTES;
    const raw = await body(limit);
    if (!raw) return tooBig(limit);
    const wants = kind === "video" ? ["hevc", "avc"] : [kind === "video_hevc" ? "hevc" : "avc"];
    const prepared = {};
    for (const want of wants) {
      const r = await prepareVideo(raw, want, conv);
      if (r.fail) return json(res, r.fail.code, { error: r.fail.error });
      prepared[want] = r;
    }
    const video = item.video || {};
    for (const want of wants) {
      const { bytes, info } = prepared[want];
      const target = `${item.id}-${want}-${randomBytes(4).toString("hex")}.mp4`;
      if (video[want]?.file) rm(video[want].file);
      put(target, bytes);
      video[want] = { file: target, width: info.width, height: info.height, fps: info.fps, bytes: bytes.length };
      video.durationMs = info.durationMs || video.durationMs || null;
    }
    item.video = video;
    commit();
    return json(res, 200, { ok: true, video: item.video });
  }

  // ----- dźwięk -----
  if (kind === "audio") {
    if (!["post", "article", "foreign", "meme"].includes(item.type)) return json(res, 400, { error: "Dźwięk można dodać do posta, artykułu, wpisu z innej platformy albo mema" });
    if (!conv && !AUDIO_TYPES[ctype] && ctype !== "application/octet-stream") return json(res, 415, { error: "Dźwięk: plik Opus (.opus / .ogg) albo WebM" });
    const limit = conv ? MAX_INPUT_AUDIO : MAX_AUDIO_BYTES;
    let bytes = await body(limit);
    if (!bytes) return tooBig(limit);
    let real = sniffAudio(bytes);
    let good = !!real && !(real === "webm" && !webmAudioIsOpus(bytes));
    if (!good) {
      if (!conv) {
        return json(res, 415, { error: real === "webm"
          ? "Ten plik WebM nie ma dźwięku w Opusie. Aplikacja odtwarza tylko Opus."
          : "To nie jest dźwięk Opus (Ogg/WebM). Zapisz plik jako Opus, np. w Audacity: Eksportuj → Opus — albo zainstaluj ffmpeg, a serwer przekonwertuje go sam." });
      }
      try { bytes = await convert.convertAudio(bytes); } catch (e) { return json(res, 415, { error: e.message || "Konwersja dźwięku nie powiodła się" }); }
      real = sniffAudio(bytes);
      if (real !== "opus") return json(res, 415, { error: "Po konwersji plik nie jest dźwiękiem Opus." });
    }
    if (bytes.length > MAX_AUDIO_BYTES) return json(res, 413, { error: `Dźwięk ma ${Math.round(bytes.length / MB)} MB — limit aplikacji to ${MAX_AUDIO_BYTES / MB} MB` });
    const target = `${item.id}-${randomBytes(4).toString("hex")}.${real}`;
    rm(item.audio?.file);
    put(target, bytes);
    item.audio = { file: target, durationMs: oggOpusDurationMs(bytes) };
    commit();
    return json(res, 200, { ok: true, audio: item.audio });
  }

  // ----- obrazy: image | thumb | avatar -----
  const imgKind = kind || "image";
  if (!["image", "thumb", "avatar"].includes(imgKind)) return json(res, 400, { error: "Nieznany rodzaj obrazu" });
  if (imgKind === "avatar" && item.type !== "post") return json(res, 400, { error: "Awatar autora jest tylko przy postach" });
  const append = imgKind === "image" && url.searchParams.get("append") === "1" && item.type === "meme";
  if (append && item.images.length >= store.MAX_MEME_IMAGES) return json(res, 400, { error: `Mem moze miec najwyzej ${store.MAX_MEME_IMAGES} zdjec` });
  const limit = conv ? MAX_INPUT_IMAGE : convert.MAX_IMAGE_BYTES;
  const original = await body(limit);
  if (!original) return tooBig(limit);
  const tPrep = Date.now();
  const r = await prepareImage(original, imgKind, ctype, conv, Number.isInteger(item.jxlQuality) ? item.jxlQuality : null);
  if (r.fail) logger.warn("media", "obraz-odrzucony", r.fail.error || "obraz odrzucony", { itemId: item.id, rodzaj: imgKind, kod: r.fail.code, wejscieB: original.length });
  else logger.info("media", "obraz", "obraz przygotowany", { itemId: item.id, rodzaj: imgKind, wejscie: sniffImage(original), wejscieB: original.length, wyjscie: r.ext, wyjscieB: r.bytes.length, jakosc: r.quality || null, ms: Date.now() - tPrep });
  if (r.fail) return json(res, r.fail.code, { error: r.fail.error });
  // nowa nazwa przy każdej zmianie: aplikacja trzyma obrazy w pamięci podręcznej po URL-u
  const target = `${item.id}-${randomBytes(4).toString("hex")}.${r.ext}`;
  let warning = r.warning;
  if (imgKind !== "image") {
    rm(item[imgKind]);
    put(target, r.bytes);
    item[imgKind] = target;
    if (imgKind === "thumb" && !warning && r.bytes.length > push.MAX_WAKE_IMG_BYTES) {
      warning = `Miniatura ma ${Math.round(r.bytes.length / 1024)} KB — do budzika trafia tylko plik do ${Math.round(push.MAX_WAKE_IMG_BYTES / 1000)} KB, wiec apka pobierze ja osobno`;
    }
    commit();
    return json(res, 200, { ok: true, [imgKind]: target, warning });
  }
  if (!append) {
    for (const old of item.images) rm(old);
    item.images = [];
  }
  put(target, r.bytes);
  item.images.push(target);
  // aplikacja nie odczyta jakości JXL z pliku — gdy kodowaliśmy my, deklarujemy ją sami; dla gotowego JXL, którego jakości
  // nie znamy, podajemy 90 (punkt startowy drabinki dokompresji w aplikacji), żeby limit rozmiaru nie ukrył obrazu
  if (r.quality) item.jxlQuality = item.jxlQuality ? Math.min(item.jxlQuality, r.quality) : r.quality;
  else if (r.ext === "jxl" && !item.jxlQuality) item.jxlQuality = 90;
  // brak miniatury powiadomienia → robimy ją sami z oryginału (JXL/AVIF nie nadają się do powiadomień)
  let autoThumb = null;
  if (conv && !item.thumb) {
    try {
      const t = await convert.makeThumbnail(original);
      const tname = `${item.id}-${randomBytes(4).toString("hex")}.${t.ext}`;
      put(tname, t.bytes);
      item.thumb = tname;
      autoThumb = tname;
    } catch { /* miniatura jest opcjonalna */ }
  }
  commit();
  return json(res, 200, { ok: true, image: target, images: item.images, converted: r.ext !== sniffImage(original), quality: r.quality || null, thumb: autoThumb, warning });
}
