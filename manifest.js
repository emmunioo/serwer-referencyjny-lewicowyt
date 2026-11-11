// Buduje manifest zgodny z kontraktem aplikacji lewicowYT (contractVersion 1). Z jednej ogólnej listy
// `items` emituje właściwe tablice: posts / memes / articles / foreignItems / ads / contests / creators.
// Dokłada blok `push` (UnifiedPush/LEP — rejestracja/wyrejestrowanie), BEZ `fcm` → serwer jest w pełni
// prywatny. Obrazy i adresy push budujemy na TYM hoście, z którego apka pobrała manifest (wymóg
// anty-beacon aplikacji: inny host = pole odrzucone), więc manifest jest osobny per adres serwera.

import { createHash } from "node:crypto";

const MAX_CONTENT_FILES = 10_000; // apka czyta do 10 000 nazw w `content`
/** Plik z listą usunięć — manifest niesie wyłącznie konfigurację i listę plików, więc `deletions` leżą w osobnym pliku. */
export const DELETIONS_FILE = "post/usuniecia.json";
// I-03: apka ODRZUCA odpowiedź > 1 000 000 znaków (cały serwer znika). Liczymy na dokładnie tym ciągu,
// który wysyłamy (kompaktowy JSON, buildManifestBody), z zapasem.
const MAX_MANIFEST_CHARS = 900_000;
const NOTIFY_WINDOW_MS = 48 * 60 * 60 * 1000; // I-01: tyle wpis niesie update: significant
const MAX_TEXT = 5_000;
const MAX_TITLE = 300;
const MAX_LINK_PLATFORMS = 30;
const MAX_ALT_ENDPOINTS = 8;

// formaty dozwolone przez aplikację: feed (imageUrl) vs powiadomienie (notifyImageUrl, bez JXL/AVIF)
const FEED_EXT = new Set(["jxl", "avif", "webp"]);
const NOTIFY_EXT = new Set(["jpg", "jpeg", "png", "webp"]);

const CAP = {
  post: "youtube_community_posts",
  meme: "memes",
  article: "media_publications",
  foreign: "foreign_platform_items",
  ad: "ads",
  contest: "contests",
  creator: "community_creators",
};
const LIST = { post: "posts", meme: "memes", article: "articles", foreign: "foreignItems", ad: "ads", contest: "contests", creator: "creators" };

const clean = (o) => {
  const r = {};
  for (const [k, v] of Object.entries(o)) {
    if (v === null || v === undefined || v === "" || v === false) continue;
    if (Array.isArray(v) && v.length === 0) continue;
    r[k] = v;
  }
  return r;
};
const cut = (s, n) => (typeof s === "string" && s.length ? s.slice(0, n) : undefined);
const extOf = (file) => String(file).split(".").pop().toLowerCase();

const httpsOnly = (u) => {
  try {
    return new URL(String(u)).protocol === "https:" ? String(u) : undefined;
  } catch {
    return undefined;
  }
};

/**
 * Obrazy pozycji podzielone na feed (JXL/AVIF/WEBP) i powiadomienie (JPG/PNG/WEBP). I-13: obraz
 * powiadomienia to okładka (pierwszy obraz feedu), gdy jest WEBP; inaczej pierwszy JPG/PNG/WEBP.
 */
function imagesFor(item, base) {
  const files = Array.isArray(item.images) ? item.images : [];
  const url = (f) => `${base}/media/${encodeURIComponent(f)}`;
  const feedFiles = files.filter((f) => FEED_EXT.has(extOf(f)));
  const cover = feedFiles[0];
  const notifyFile = cover && extOf(cover) === "webp" ? cover : files.find((f) => NOTIFY_EXT.has(extOf(f)));
  const quality = Number.isInteger(item.jxlQuality) ? item.jxlQuality : undefined;
  const feed = feedFiles.map((f) => ({ url: url(f), quality: extOf(f) === "jxl" ? quality : undefined }));
  // osobna miniatura powiadomienia (mały JPG/PNG/WEBP) ma pierwszeństwo — ta sama trafia też do budzika
  const thumb = item.thumb && NOTIFY_EXT.has(extOf(item.thumb)) ? item.thumb : null;
  const avatar = item.avatar && FEED_EXT.has(extOf(item.avatar)) ? url(item.avatar) : undefined;
  return { feed, notify: thumb ? url(thumb) : notifyFile ? url(notifyFile) : undefined, avatar };
}

/** I-01: `significant` tylko w oknie po dodaniu/edycji — nowy subskrybent nie dostaje zbiorczego powiadomienia o starociach. */
function updateFieldOf(it, now) {
  if (it.update === "minor") return "minor";
  if (it.update !== "significant") return undefined;
  // okno liczymy od publikacji, gdy wpis był zaplanowany na później
  const at = Math.max(it.updateAt || it.updatedAt || it.createdAt || 0, it.publishedAt || 0);
  return now - at <= NOTIFY_WINDOW_MS ? "significant" : undefined;
}

/**
 * Stały link pozycji = jej tożsamość w aplikacji (bez linku apka liczy klucz z treści, więc edycja
 * robiłaby duplikat, a usunięcie byłoby niemożliwe). Gdy operator nie podał linku, a serwer ma HTTPS,
 * dajemy własną stronę wpisu /e/<id>. Aplikacja przyjmuje tylko linki https.
 */
export function permalinkOf(item, httpsBase) {
  const own = httpsOnly(item.url);
  if (own) return own;
  if (!httpsBase || item.type === "ad" || item.type === "contest") return undefined;
  return `${httpsBase}/e/${item.id}`;
}

/** Ręczne platformy z panelu (pierwszeństwo) + wyliczone z pozycji „inna platforma”. */
function mergedLinkPlatforms(manual, items) {
  const out = [];
  const ids = new Set();
  for (const p of [...(Array.isArray(manual) ? manual : []), ...linkPlatformsFrom(items)]) {
    if (!p?.id || ids.has(p.id)) continue;
    ids.add(p.id);
    out.push(clean({ id: p.id, name: p.name || p.id, hosts: p.hosts || [] }));
    if (out.length >= MAX_LINK_PLATFORMS) break;
  }
  return out;
}

function linkPlatformsFrom(items) {
  const byId = new Map();
  for (const it of items) {
    if (it.type !== "foreign" || !it.platform) continue;
    const id = it.platform.trim().toLowerCase().replace(/\s+/g, "-").slice(0, 64);
    if (!id) continue;
    const entry = byId.get(id) || { id, name: it.platform.trim().slice(0, 200), hosts: new Set() };
    try {
      const h = new URL(String(it.url)).hostname.toLowerCase().replace(/^www\./, "");
      if (h) entry.hosts.add(h);
    } catch { /* bez linku — platforma bez hostów */ }
    byId.set(id, entry);
  }
  return [...byId.values()].slice(0, MAX_LINK_PLATFORMS).map((p) => clean({ id: p.id, name: p.name, hosts: [...p.hosts] }));
}

/** Dźwięk wpisu (Opus) — ten sam host co manifest; apka odtwarza go natywnie (w tle, pętla, do 3×). */
function audioFor(it, base) {
  const file = it.audio?.file;
  if (!file || !/\.(opus|webm)$/i.test(file)) return undefined;
  return clean({
    url: `${base}/media/${encodeURIComponent(file)}`,
    durationMs: Number.isInteger(it.audio.durationMs) && it.audio.durationMs > 0 ? it.audio.durationMs : undefined,
    title: cut(it.audioTitle, MAX_TITLE),
  });
}

/**
 * Film wpisu: wariant H.265 (główny) i/lub H.264 (zapasowy). Aplikacja wybiera H.265, gdy telefon ma do niego
 * sprzętowy dekoder, inaczej H.264; każdy wariant ma najwyżej 30 kl/s (serwer sprawdza przy wgrywaniu).
 */
function videoFor(it, base) {
  const v = it.video;
  if (!v) return undefined;
  const variant = (x) => (x?.file && /\.mp4$/i.test(x.file) && x.fps && x.fps <= 30.05
    ? clean({ url: `${base}/media/${encodeURIComponent(x.file)}`, width: x.width, height: x.height, fps: x.fps, bytes: x.bytes })
    : undefined);
  const hevc = variant(v.hevc), avc = variant(v.avc);
  if (!hevc && !avc) return undefined;
  return clean({ hevc, avc, durationMs: Number.isInteger(v.durationMs) && v.durationMs > 0 ? v.durationMs : undefined, title: cut(it.videoTitle, MAX_TITLE) });
}

function entryFor(it, base, httpsBase, now) {
  if (it.publishedAt && it.publishedAt > now) return null; // zaplanowany — jeszcze niewidoczny
  const { feed, notify, avatar } = imagesFor(it, base);
  const audio = audioFor(it, base);
  const video = videoFor(it, base);
  const url = permalinkOf(it, httpsBase);
  const common = {
    imageUrl: feed[0]?.url,
    notifyImageUrl: notify, // WEBP pasuje do obu, więc mem z samym WEBP ma też obraz powiadomienia
    imageQuality: feed[0]?.quality,
    publishedAtMillis: it.publishedAt || undefined,
    update: updateFieldOf(it, now),
  };
  switch (it.type) {
    case "post":
      return clean({ author: cut(it.author, 200), authorImageUrl: avatar, text: cut(it.text, MAX_TEXT), type: it.postType || undefined, url, audio, video, ...common });
    case "meme": {
      if (!feed.length) return null; // mem bez obrazu w formacie feedu aplikacja i tak pominie
      const images = feed.slice(0, 20).map((f, i) => clean({ imageUrl: f.url, imageQuality: f.quality, notifyImageUrl: i === 0 ? common.notifyImageUrl : undefined }));
      return clean({
        title: cut(it.title, MAX_TITLE),
        source: cut(it.source, 200),
        images,
        url,
        audio,
        video,
        publishedAtMillis: common.publishedAtMillis,
        update: common.update,
      });
    }
    case "article":
      if (it.articleKind !== "newsletter" && !url) return null;
      return clean({
        kind: it.articleKind === "newsletter" ? "newsletter" : "article",
        source: cut(it.source, 200),
        author: cut(it.author, 200),
        title: cut(it.title, MAX_TITLE),
        text: cut(it.text, MAX_TEXT),
        url,
        audio,
        video,
        ...common,
      });
    case "foreign":
      return clean({
        platform: cut(it.platform, 200),
        author: cut(it.author, 200),
        type: it.foreignType || undefined,
        title: cut(it.title, MAX_TITLE),
        text: cut(it.text, MAX_TEXT),
        url,
        audio,
        video,
        ...common,
      });
    case "ad":
      return clean({ title: cut(it.title, MAX_TITLE), text: cut(it.text, MAX_TEXT), url, ...common });
    case "contest":
      return clean({ title: cut(it.title, MAX_TITLE), text: cut(it.text, MAX_TEXT), url, thirdParty: it.thirdParty === true, ...common });
    case "creator":
      return clean({ id: it.id, name: cut(it.name, 200), channelUrl: httpsOnly(it.channelUrl) });
    default:
      return null;
  }
}

/** Nazwa pliku treści wpisu: post/<id>.json — stała przez całe życie wpisu (wersja idzie w `contentVersions`). */
export function contentNameOf(item) {
  return `post/${item.id}.json`;
}

/**
 * Plik treści jednego wpisu (protokół: „Pliki treści”) — ta sama struktura co listy w manifeście, tu
 * z JEDNĄ pozycją, np. {"posts":[{…}]}. null, gdy wpis nie daje poprawnej pozycji (np. mem bez obrazu).
 */
export function buildContentFile(item, base, ctx = {}) {
  const e = entryFor(item, base, ctx.httpsBase || null, ctx.now || Date.now());
  if (!e || !LIST[item.type]) return null;
  return JSON.stringify({ [LIST[item.type]]: [e] });
}

/** Lista linków usuniętych pozycji (najwyżej 200 ostatnich) — bez permalinków ukrytych dla danego adresu. */
function deletionsOf(data, ctx = {}) {
  const hidden = ctx.hidePermalinksOf ? `${ctx.hidePermalinksOf}/e/` : null;
  return (data.deletions || []).map((d) => d.url).filter((u) => httpsOnly(u) && !(hidden && u.startsWith(hidden))).slice(-200);
}

/** Plik usunięć (`{"deletions":[…]}`) albo null, gdy nic nie ma do usunięcia. Aplikacja stosuje `deletions` także z plików treści. */
export function buildDeletionsFile(data, ctx = {}) {
  const list = deletionsOf(data, ctx);
  return list.length ? JSON.stringify({ deletions: list }) : null;
}

/**
 * @param data      dane serwera (store)
 * @param base      adres serwera, którym apka pobrała manifest (np. http://xyz.onion:2137)
 * @param ctx.httpsBase   https://domena — do stałych linków wpisów (null, gdy brak HTTPS)
 * @param ctx.altEndpoints adresy LAN (http) — obejście hairpin-NAT; pomijane dla .onion
 * @returns obiekt manifestu; do wysłania użyj buildManifestBody (pilnuje limitu na wysyłanym ciągu)
 */
export function buildManifest(data, base, ctx = {}) {
  return JSON.parse(buildManifestBody(data, base, ctx));
}

/**
 * Kompaktowy JSON manifestu. Manifest niesie TYLKO informacje o serwerze (nazwa, regulamin, push, …) oraz
 * listę `content` — nazwy plików, po jednym na wpis (post/<id>.json) — i `contentVersions` (nazwa → wersja).
 * Apka pobiera plik, gdy jest nowy albo zmieniła się jego wersja; plik zdjęty z listy zabiera swoje pozycje.
 * Starsze apki ignorują `contentVersions` i pobierają każdy plik raz. Kolejność: od najstarszej zmiany.
 */
export function buildManifestBody(data, base, ctx = {}) {
  const now = ctx.now || Date.now();
  const c = data.config;
  const isOnion = /^http:\/\/[^/]+\.onion(:\d+)?$/i.test(base);
  // tylko wpisy, z których wychodzi poprawna pozycja (np. mem z obrazem w formacie feedu)
  const valid = data.items.filter((it) => LIST[it.type] && entryFor(it, base, ctx.httpsBase || null, now));
  const ordered = valid.sort((a, b) => (a.revAt || a.createdAt || 0) - (b.revAt || b.createdAt || 0));
  const capabilities = [...new Set(valid.map((it) => CAP[it.type]))];
  // usunięcia idą w OSOBNYM pliku (manifest = tylko konfiguracja + lista plików; im mniej w manifeście, tym rzadziej
  // zmienia się jego SHA-256/ETag). Stałe linki /e/<id> z domeny nie trafiają do wersji .onion.
  const delBody = buildDeletionsFile(data, ctx);
  const delVersion = delBody ? createHash("sha256").update(delBody).digest("hex").slice(0, 16) : null;
  const alt = isOnion ? [] : (ctx.altEndpoints || []).filter((u) => u !== base).slice(0, MAX_ALT_ENDPOINTS);

  const build = (names) => clean({
    contractVersion: 1,
    name: c.serverName,
    description: c.description || undefined,
    transport: isOnion ? "onion" : "https",
    canBePrimary: false, // ręczna treść: bez filmów i bez primaryFeed — nie może zastąpić serwera domyślnego
    capabilities,
    terms: { version: c.termsVersion || "1", text: c.termsText },
    push: {
      register: `${base}/push/register`,
      unregister: `${base}/push/unregister`,
      // LEP obsługuje ten sam serwer (/lep/pub, /lep/sub), więc bez `relay`; bez `fcm` → zero Google.
    },
    altEndpoints: alt,
    linkPlatforms: mergedLinkPlatforms(c.linkPlatforms, data.items),
    content: delBody ? [...names, DELETIONS_FILE] : names,
    contentVersions: { ...Object.fromEntries(names.map((n) => [n, String(revOf.get(n) || 1)])), ...(delBody ? { [DELETIONS_FILE]: delVersion } : {}) },
  });

  const revOf = new Map(ordered.map((it) => [contentNameOf(it), it.rev || 1]));
  // apka czyta do 10 000 nazw; przy przekroczeniu (albo limitu znaków) odpadają najstarsze
  let names = ordered.map(contentNameOf).slice(-(MAX_CONTENT_FILES - (delBody ? 1 : 0)));
  let body = JSON.stringify(build(names));
  while (body.length > MAX_MANIFEST_CHARS && names.length) {
    names = names.slice(Math.ceil(names.length * 0.1));
    body = JSON.stringify(build(names));
  }
  return body;
}
