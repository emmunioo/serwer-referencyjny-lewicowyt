// Serwer społeczności dla aplikacji lewicowYT — pełna konfiguracja z przeglądarki (panel /admin):
// treści (posty, memy, artykuły, pozycje z innych platform, reklamy, konkursy), regulamin, sieć.
// Powiadomienia przez UnifiedPush (wbudowany LEP albo np. ntfy) z szyfrowaniem E2E — BEZ Google. Tor (.onion)
// i HTTPS z Let's Encrypt w zestawie. SEND-ONLY publicznie: jedyny publiczny POST to rejestracja push.
//
// Uruchomienie:  node server.js            (HTTP i HTTPS na :2137; panel lokalnie na 127.0.0.1:2138)
//                HTTP_PORT=8080 node server.js

import http from "node:http";
import https from "node:https";
import net from "node:net";
import fs from "node:fs";
import { join, basename } from "node:path";
import { randomBytes, createHash } from "node:crypto";
import * as store from "./store.js";
import { buildManifestBody, buildContentFile, buildDeletionsFile, DELETIONS_FILE, permalinkOf } from "./manifest.js";
import { loginPage, appPage, escapeHtml } from "./admin.js";
import { CertManager } from "./acme.js";
import { listLanIps, primaryLanIp, fetchWanIp, TorManager } from "./network.js";
import * as push from "./push.js";
import * as updater from "./update.js";
import * as logger from "./logger.js";
import { buildEncryptedHtml } from "./logexport.js";

// ratunek po nieudanej aktualizacji: node server.js --rollback (nie wymaga klucza bazy)
if (process.argv.includes("--rollback")) {
  try { const r = updater.rollback(); console.log(`Przywrócono wersję ${r.restoredTo}. Uruchom serwer ponownie.`); process.exit(0); }
  catch (e) { console.error("Nie udało się cofnąć aktualizacji:", e.message); process.exit(1); }
}

// dziennik zdarzeń: ZAWSZE włączony; od pierwszej linii zbiera też całą konsolę (zapis do bazy po jej odblokowaniu)
logger.install();
import { isLep, handleLep, startLepCleanup, lepStats, configureLep } from "./lep.js";
import { sniffImage } from "./media.js";
import { stripImageMetadata, mp4StripMetadata } from "./metadata.js";
import { handleItemImage } from "./uploads.js";
import * as convert from "./convert.js";

const ENV_HTTP_PORT = Number(process.env.HTTP_PORT || 2137);
const ENV_HTTPS_PORT = Number(process.env.HTTPS_PORT || 443);
const STARTED_AT = Date.now();
const ADMIN_PORT = Number(process.env.ADMIN_PORT) || 2138;
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const MAX_IMPORT = 400 * 1024 * 1024; // kopia zapasowa z obrazami (base64)
const BACKUP_FORMAT = "lewicowyt-community-backup";
const SCHEDULER_TICK_MS = 20_000;

const LOGIN_BACKOFF_BASE_MS = 500;
const LOGIN_BACKOFF_MAX_MS = 30_000;
let loginFailures = 0;
let loginLock = Promise.resolve();
/** Próby logowania wykonujemy po jednej: bramka (429) i opóźnienie liczone są po sprawdzeniu hasła, więc równoległe zgadywanie nic nie daje. */
const withLoginLock = (fn) => { const p = loginLock.then(fn, fn); loginLock = p.catch(() => {}); return p; };
const PANEL_CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src * data: blob:; media-src *; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
const LOCAL_HOST_RE = /^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/i;
let loginNextAllowedMs = 0;

const MEDIA_TYPES = { jxl: "image/jxl", avif: "image/avif", webp: "image/webp", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", opus: "audio/ogg", webm: "audio/webm", mp4: "video/mp4" };

function httpPort() { return store.load().config.network.httpPort || ENV_HTTP_PORT; }
function httpsPort() { return store.load().config.network.httpsPort || ENV_HTTPS_PORT; }

// baza danych jest szyfrowana: przed pierwszym odczytem ustalamy klucz (plik klucza / DB_KEY / hasło) i szyfr
await store.unlock();
logger.attach();
logger.snapshot({ ...store.cryptoBrief(), conversion: convert.describeTools() });
logger.startMetrics(() => ({ subscribers: Object.keys(store.load().push.subscribers).length, items: store.load().items.length, sessions: sessions.size }));
convert.cleanupTemp();
convert.setVideoEncoderPreference(store.load().videoEncoder || "auto");
convert.probeVideoEncoders().catch(() => {}); // w tle: które kodery GPU (NVENC/QSV/AMF/VideoToolbox/VAAPI) działają na tym komputerze

const tor = new TorManager({ dir: join(store.DATA_DIR, "tor"), storage: { get: store.getFile, put: store.putFile, list: store.listFiles } });
let wanIp = { value: null, at: 0 };

const challenges = new Map();
const sessions = new Map();
const certs = new CertManager({ storage: { get: store.getFile, put: store.putFile }, challenges });

// zapomniane hasło: `node server.js --reset-password` (albo start.bat --reset-password) — nadaje nowe i kończy
if (process.argv.includes("--reset-password")) {
  const d = store.load();
  const pw = randomBytes(12).toString("base64url");
  await store.setPassword(d, pw);
  store.save(d);
  console.log("\n=====================================================");
  logger.audit("haslo.reset", "hasło administratora zresetowane z konsoli (--reset-password)");
  console.log("  Nowe haslo administratora (stare przestalo dzialac):");
  logger.raw.log("  " + pw);
  console.log("=====================================================\n");
  logger.shutdown("reset hasła"); store.flush(); store.close();
  process.exit(0);
}

// pierwszy start: wygeneruj hasło administratora i wypisz w konsoli
const data0 = store.load();
if (!data0.adminPasswordHash) {
  const pw = randomBytes(9).toString("base64url");
  await store.setPassword(data0, pw);
  store.save(data0);
  logger.audit("haslo.pierwszy-start", "wygenerowano hasło administratora przy pierwszym starcie");
  console.log("\n=====================================================");
  console.log("  Haslo administratora (zmien je w panelu po zalogowaniu):");
  logger.raw.log("  " + pw);
  console.log("=====================================================\n");
}

function publicBase() {
  const d = store.load().config.domain;
  if (certs.hasHttps() && d) return httpsPort() === 443 ? `https://${d}` : `https://${d}:${httpsPort()}`;
  const onion = tor.status().onion;
  if (onion) { const vp = tor.status().virtualPort; return `http://${onion}${vp === 80 ? "" : ":" + vp}`; }
  const p = httpPort() === 80 ? "" : `:${httpPort()}`;
  return `http://${primaryLanIp()}${p}`;
}

function endpoints() {
  const cfg = store.load().config;
  const list = [];
  // I-04: apka dopisuje :2137, gdy w adresie nie ma portu — dlatego HTTPS działa także na porcie HTTP
  // (rozpoznajemy TLS po pierwszym bajcie). W aplikacji wystarczy wpisać samą domenę.
  const tlsPort = httpPort() === 443 ? "" : `:${httpPort()}`;
  if (certs.hasHttps() && cfg.domain) list.push({ kind: "Domena (HTTPS) — w aplikacji wpisz samą domenę", url: `https://${cfg.domain}${tlsPort}/manifest.json` });
  else if (cfg.domain) list.push({ kind: "Domena (czeka na certyfikat)", url: `https://${cfg.domain}${tlsPort}/manifest.json` });
  if (cfg.canonicalHttpsBase && !(certs.hasHttps() && cfg.domain)) list.push({ kind: "HTTPS przez reverse proxy", url: cfg.canonicalHttpsBase + "/manifest.json" });
  const hp = httpPort() === 80 ? "" : `:${httpPort()}`;
  for (const a of listLanIps().filter((x) => x.family === "IPv4")) {
    list.push({ kind: `LAN (${a.iface})`, url: `http://${a.address}${hp}/manifest.json` });
  }
  if (wanIp.value) list.push({ kind: "WAN (publiczny IP)", url: `http://${wanIp.value}${hp}/manifest.json` });
  const onion = tor.status().onion;
  if (onion) {
    const vp = tor.status().virtualPort;
    list.push({ kind: "Tor (.onion)", url: `http://${onion}${vp === 80 ? "" : ":" + vp}/manifest.json` });
  }
  return list;
}

/**
 * Kanoniczny adres HTTPS serwera (I-02/I-05): ten, pod którym apka nas zna przez TLS — z certyfikatu w Node
 * albo nauczony z żądań przez reverse proxy (X-Forwarded-Proto). Z niego budujemy stałe linki /e/<id>
 * (tożsamość wpisów — ta sama w manifeście i w `deletions`) oraz adresy w manifeście dla żądań z LAN.
 */
function httpsBase() {
  const cfg = store.load().config;
  if (cfg.canonicalHttpsBase) {
    // wartość nauczona/zapisana wcześniej obowiązuje tylko, gdy zgadza się z domeną z panelu
    try { if (cfg.domain && new URL(cfg.canonicalHttpsBase).hostname === cfg.domain.toLowerCase()) return cfg.canonicalHttpsBase; } catch { /* zły adres */ }
  }
  if (!certs.hasHttps() || !cfg.domain) return null;
  return httpPort() === 443 ? `https://${cfg.domain}` : `https://${cfg.domain}:${httpPort()}`;
}

/** Zapamiętuje adres HTTPS z żądania (pierwszy raz albo po zmianie domeny). */
function learnCanonical(base) {
  let host;
  try { host = new URL(base).hostname; } catch { return; }
  if (net.isIP(host.replace(/^\[|\]$/g, "")) || host === "localhost") return; // tylko nazwa domenowa
  const d = store.load();
  if (d.config.canonicalHttpsBase === base) return;
  // A-01 (audyt): bez domeny ustawionej w panelu NIE uczymy się niczego z nagłówków Host/X-Forwarded-Proto — każde
  // połączenie przez Tor i każdy reverse proxy przychodzi z loopbacka, więc obcy klient mógłby podmienić adres serwera
  if (!d.config.domain || host !== d.config.domain.toLowerCase()) return;
  d.config.canonicalHttpsBase = base;
  store.saveSoon(d);
  invalidateManifest();
}

const isPrivateV4 = (ip) => {
  const [a, b] = ip.split(".").map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
};

/** Adresy LAN serwera (http) — `altEndpoints` na wypadek routera bez hairpin-NAT (I-10: tylko prywatne). */
function lanAltEndpoints() {
  const hp = httpPort() === 80 ? "" : `:${httpPort()}`;
  return listLanIps().filter((a) => a.family === "IPv4" && isPrivateV4(a.address)).map((a) => `http://${a.address}${hp}`);
}

const HOST_RE = /^(?:[a-z0-9-]+(?:\.[a-z0-9-]+)*|\[[0-9a-f:.]+\])(?::\d{1,5})?$/i;

/**
 * Adres serwera, którym apka nas pobrała (z nagłówka Host). Aplikacja przyjmuje obrazy i adresy push
 * WYŁĄCZNIE z hosta manifestu — gdyby manifest dla .onion podawał domenę (albo odwrotnie), push i obrazy
 * po cichu by nie działały. Za lokalnym reverse proxy z TLS honorujemy X-Forwarded-Proto.
 */
function requestBase(req, isSecure) {
  const host = String(req.headers.host || "").toLowerCase();
  if (!host || host.length > 255 || !HOST_RE.test(host)) return publicBase();
  const fromLoopback = ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(req.socket?.remoteAddress);
  const proto = isSecure || (fromLoopback && req.headers["x-forwarded-proto"] === "https") ? "https" : "http";
  const base = `${proto}://${host}`;
  if (proto === "https") learnCanonical(base);
  return base;
}

/** Czy Host to adres z sieci lokalnej (IP prywatne) — wtedy apka mogła przyjść failoverem LAN. */
function isPrivateHostBase(base) {
  let host;
  try { host = new URL(base).hostname.replace(/^\[|\]$/g, ""); } catch { return false; }
  return (net.isIPv4(host) && isPrivateV4(host)) || host.endsWith(".local");
}

// --- manifest (cache per adres, z ETagiem = SHA-256 treści) ---
const manifestCache = new Map();
const MANIFEST_CACHE_MAX = 32; // Host jest od klienta — ograniczamy liczbę wariantów w pamięci
const MANIFEST_CACHE_TTL_MS = 30_000; // adresy LAN / certyfikat mogą się zmienić bez zmiany danych
function invalidateManifest() { manifestCache.clear(); }
/**
 * Adres, na którym budujemy linki dla tego żądania. I-05: apka przy failoverze LAN (R-08) waliduje obrazy
 * względem hosta KANONICZNEGO, nie adresu LAN. Gdy znamy adres HTTPS, na żądanie z prywatnego IP oddajemy
 * adresy kanoniczne — inaczej memy znikały, a ulubione dublowały się. Bez adresu HTTPS zostaje adres z żądania.
 */
function effectiveBase(requestedBase) {
  const canonical = httpsBase();
  const base = canonical && isPrivateHostBase(requestedBase) ? canonical : requestedBase;
  const isOnion = /\.onion(:\d+)?$/i.test(base);
  return { base, canonical, isOnion };
}

function manifest(requestedBase) {
  const { base, canonical } = effectiveBase(requestedBase);
  const hit = manifestCache.get(base);
  if (hit && Date.now() - hit.at < MANIFEST_CACHE_TTL_MS) return hit;
  const isOnion = effectiveBase(requestedBase).isOnion;
  // I-03: kompaktowy JSON — limit apki dotyczy dokładnie tego ciągu
  const body = buildManifestBody(store.load(), base, {
    httpsBase: isOnion ? null : canonical, // stałe linki: nie wypychamy domeny do manifestu .onion
    hidePermalinksOf: isOnion ? canonical : null,
    altEndpoints: base.startsWith("https://") ? lanAltEndpoints() : [],
  });
  const etag = '"sha256-' + createHash("sha256").update(body).digest("hex") + '"';
  if (manifestCache.size >= MANIFEST_CACHE_MAX) manifestCache.delete(manifestCache.keys().next().value);
  const entry = { body, etag, at: Date.now() };
  manifestCache.set(base, entry);
  return entry;
}

/** Linki, pod którymi apka mogła zapamiętać wpis (własny link albo strona /e/<id>). */
function knownLinksOf(item) {
  const out = new Set();
  const hb = httpsBase();
  const own = permalinkOf(item, null);
  if (own) out.add(own);
  if (hb) { const p = permalinkOf(item, hb); if (p) out.add(p); }
  return [...out];
}

// --- tematy LEP zarejestrowanych subskrybentów (I-08) ---
let lepTopicMap = null; // topic -> endpoint; przebudowa leniwa po zmianie listy subskrybentów
function topicMap() {
  if (!lepTopicMap) lepTopicMap = push.lepTopics(store.load());
  return lepTopicMap;
}
function subscribersChanged() { lepTopicMap = null; }
const POLL_SAVE_EVERY_MS = 60 * 60 * 1000;
configureLep({
  isKnownTopic: (topic) => topicMap().has(topic),
  onPoll: (topic) => {
    const ep = topicMap().get(topic);
    const d = store.load();
    const sub = ep && d.push.subscribers[ep];
    if (!sub) return;
    const now = Date.now();
    if (now - (sub.polledAt || 0) > POLL_SAVE_EVERY_MS) { sub.polledAt = now; store.saveSoon(d, 5000); }
  },
});

// --- budziki push po nowej treści (debounce) ---
// Krótkie okno skleja kilka zapisów tuż po sobie w jeden budzik. 1 s zamiast dawnych 3 s: wgrywanie obrazów/filmu
// i tak czeka na `item/ready` (S-03), więc dłuższe okno tylko opóźniało powiadomienie u wszystkich subskrybentów.
const NOTIFY_DEBOUNCE_MS = 1000;
let notifyTimer = null;
function scheduleNotify() {
  if (notifyTimer) return;
  notifyTimer = setTimeout(async () => {
    notifyTimer = null;
    try {
      const d = store.load();
      const r = await push.notifyAll(d, { img: wakeThumbnail(d), jitterSec: d.config.push?.realJitterSec || 0 });
      if (r.pruned) subscribersChanged();
      if (r.sent || r.pruned) console.log(`[push] budziki wyslane: ${r.sent}, usunieci subskrybenci: ${r.pruned}`);
    } catch (e) { console.warn("[push] notifyAll:", e.message); }
  }, NOTIFY_DEBOUNCE_MS);
  notifyTimer.unref?.();
}

/**
 * Miniatura do budzika (pole `img`): mały plik JPG/PNG/WEBP najnowszego istotnego wpisu. Apka pokaże ją
 * w powiadomieniu bez pobierania z sieci — serwer nie zobaczy IP osoby, która dostała powiadomienie.
 * Tylko z wpisu, o którym jest ten budzik (najnowsza istotna zmiana), i tylko gdy plik jest mały.
 */
function wakeThumbnail(d, now = Date.now()) {
  const recent = d.items
    .filter((it) => store.isVisible(it, now) && it.update === "significant")
    .map((it) => ({ it, at: Math.max(it.updateAt || 0, it.publishedAt || 0) }))
    .filter((x) => now - x.at <= 48 * 3600_000)
    .sort((a, b) => b.at - a.at)[0]?.it;
  if (!recent) return undefined;
  for (const file of [recent.thumb, ...(recent.images || [])].filter(Boolean)) {
    if (!/\.(jpe?g|png|webp)$/i.test(file)) continue;
    try {
      const size = store.mediaSize(basename(file));
      if (size != null && size <= push.MAX_WAKE_IMG_BYTES) return store.getMedia(basename(file)).toString("base64");
    } catch { /* brak pliku */ }
  }
  return undefined;
}

/** Automatyczny budzik po zapisie istotnego, już widocznego wpisu (gdy włączone w ustawieniach). */
function autoNotifyFor(d, item) {
  if (d.config.autoNotify !== false && item.update === "significant" && store.isVisible(item)) scheduleNotify();
}

/**
 * S-03: panel zapisuje wpis, a obrazy/miniaturę/film wgrywa DOPIERO potem. Budzik wysłany od razu łapał wpis
 * bez nich (nowy mem w ogóle niewidoczny → bez powiadomienia; budzik bez miniatury `img`). Z `deferNotify`
 * budzik czeka na `item/ready`; gdyby panel nie dał znaku (zamknięta karta), idzie sam po DEFER_MAX_MS.
 */
const DEFER_MAX_MS = 10 * 60 * 1000;
const deferredWakes = new Map(); // id wpisu -> timer
function notifyOrDefer(d, item, defer) {
  if (!defer) { autoNotifyFor(d, item); return; }
  releaseDeferred(item.id);
  const t = setTimeout(() => {
    deferredWakes.delete(item.id);
    const cur = store.load();
    const it = store.findItem(cur, item.id);
    if (it) autoNotifyFor(cur, it);
  }, DEFER_MAX_MS);
  t.unref?.();
  deferredWakes.set(item.id, t);
}
function releaseDeferred(id) {
  const t = deferredWakes.get(id);
  if (t) { clearTimeout(t); deferredWakes.delete(id); }
}

// --- pomocnicze ---
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0, over = false;
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) {
        if (!over) { over = true; chunks.length = 0; reject(new Error("za duze zadanie")); req.resume(); setTimeout(() => req.destroy(), 1500).unref?.(); } // dajemy czas na odpowiedź 413
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}
function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function sessionOf(req) {
  const token = parseCookies(req).admin;
  if (!token) return null;
  const s = sessions.get(token);
  if (!s || s.expires < Date.now()) { if (s) sessions.delete(token); return null; }
  return { token, ...s };
}
function json(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(obj));
}
function csrfOk(req, session) {
  const header = req.headers["x-csrf-token"];
  return session && header && header === session.csrf;
}

const MEDIA_CHUNK = 1024 * 1024;
async function serveMedia(res, req, path) {
  let name;
  try { name = basename(decodeURIComponent(path.slice("/media/".length))); } catch { res.writeHead(400); res.end(); return; }
  const ext = name.split(".").pop().toLowerCase();
  const type = MEDIA_TYPES[ext];
  const size = /^[A-Za-z0-9_.-]+$/.test(name) && type ? store.mediaSize(name) : null;
  if (size == null) { res.writeHead(404); res.end(); return; }
  const headers = { "Content-Type": type, "Content-Length": size, "Cache-Control": "public, max-age=86400", "X-Content-Type-Options": "nosniff", "Access-Control-Allow-Origin": "*" };
  if (req.method === "HEAD") { res.writeHead(200, headers); res.end(); return; }
  res.writeHead(200, headers);
  // plik leży w bazie jako BLOB: oddajemy go kawałkami po 1 MiB (film do 200 MiB nie trafia w całości do pamięci)
  let offset = 0;
  let closed = false;
  res.on("close", () => { closed = true; });
  while (offset < size && !closed) {
    const chunk = store.readMediaChunk(name, offset, Math.min(MEDIA_CHUNK, size - offset));
    if (!chunk || !chunk.length) break;
    offset += chunk.length;
    if (!res.write(chunk)) await new Promise((r) => { res.once("drain", r); res.once("close", r); });
  }
  res.end();
}

// --- kopia zapasowa (punkt 5) ---
const TOR_HS_PREFIX = "tor/hs/";
const SAFE_NAME = /^[A-Za-z0-9_.-]{1,128}$/;

/** Jeden plik JSON: konfiguracja, wpisy, usunięcia, subskrybenci push, obrazy i klucz adresu .onion. Bez hasła. */
function exportBackup(res) {
  const d = store.load();
  // A-09: cała kopia jest jednym napisem w pamięci (multimedia w Base64) — limit napisu V8 ≈ 512 MiB, a import przyjmuje 400 MiB
  let mediaBytes = 0;
  for (const it of d.items) for (const f of [...(it.images || []), it.thumb, it.avatar, it.audio?.file, it.video?.hevc?.file, it.video?.avc?.file]) if (f) mediaBytes += store.mediaSize(basename(f)) || 0;
  if (mediaBytes * 1.34 > 300 * 1024 * 1024) {
    return json(res, 400, { error: `Multimedia zajmują ${Math.round(mediaBytes / 1048576)} MB — za dużo na kopię JSON z panelu (limit ok. 220 MB). Zatrzymaj serwer i skopiuj pliki bazy: serwer.db, klucz-bazy.key (albo klucz-bazy.haslo.json) i szyfrowanie.json.` });
  }
  logger.audit("kopia.eksport", "pobrano kopię zapasową", { wpisow: d.items.length });
  const { adminPasswordHash: _pw, postHashes: _h, ...rest } = d;
  const media = {};
  const files = new Set(d.items.flatMap((it) => [...(it.images || []), it.thumb, it.avatar, it.audio?.file, it.video?.hevc?.file, it.video?.avc?.file]).filter(Boolean));
  for (const name of files) {
    if (!SAFE_NAME.test(name)) continue;
    const bytes = store.getMedia(name);
    if (bytes) media[name] = bytes.toString("base64");
  }
  const tor = {};
  for (const path of store.listFiles(TOR_HS_PREFIX)) {
    const name = path.slice(TOR_HS_PREFIX.length);
    if (SAFE_NAME.test(name)) tor[name] = store.getFile(path).toString("base64");
  }
  const body = JSON.stringify({ format: BACKUP_FORMAT, version: 1, exportedAt: Date.now(), data: rest, media, tor });
  const stamp = new Date().toISOString().slice(0, 10);
  res.writeHead(200, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Disposition": `attachment; filename="kopia-serwera-${stamp}.json"`,
    "Cache-Control": "no-store",
  });
  res.end(body);
}

/**
 * Wczytuje kopię: zastępuje treść, konfigurację (poza ustawieniami sieci tej maszyny i hasłem), usunięcia
 * i subskrybentów; dogrywa obrazy i klucz .onion (ten zadziała po restarcie serwera).
 */
/** Pola wpisu z kopii o złych typach nie mogą wywrócić serwera (np. images nie będące tablicą). */
function sanitizeImportedItem(it) {
  const str = (v) => (typeof v === "string" ? v : null);
  const out = { ...it };
  out.images = Array.isArray(it.images) ? it.images.filter((x) => typeof x === "string" && SAFE_NAME.test(x)) : [];
  for (const k of ["thumb", "avatar"]) out[k] = str(it[k]) && SAFE_NAME.test(it[k]) ? it[k] : null;
  for (const k of ["title", "text", "author", "source", "platform", "url", "name", "channelUrl", "postType", "foreignType"]) if (out[k] != null) out[k] = str(out[k]);
  out.rev = Number.isInteger(it.rev) && it.rev > 0 ? it.rev : 1;
  if (it.audio && typeof it.audio !== "object") out.audio = null;
  if (it.video && typeof it.video !== "object") out.video = null;
  return out;
}

function importBackup(b) {
  logger.audit("kopia.import", "wczytywanie kopii zapasowej", { wpisow: Array.isArray(b?.data?.items) ? b.data.items.length : null });
  if (!b || b.format !== BACKUP_FORMAT || b.version !== 1 || !b.data || !Array.isArray(b.data.items)) {
    return { ok: false, error: "To nie jest kopia tego serwera (zly format)" };
  }
  const d = store.load();
  const items = b.data.items.filter((it) => it && /^[a-f0-9]{16}$/.test(it.id) && store.ITEM_TYPES.includes(it.type)).map(sanitizeImportedItem);
  let mediaCount = 0;
  for (const [name, b64] of Object.entries(b.media || {})) {
    if (!SAFE_NAME.test(name) || typeof b64 !== "string") continue;
    store.putMedia(name, Buffer.from(b64, "base64"));
    mediaCount += 1;
  }
  let torRestored = false;
  const torFiles = Object.entries(b.tor || {}).filter(([n, v]) => SAFE_NAME.test(n) && typeof v === "string");
  if (torFiles.length) {
    for (const [name, b64] of torFiles) store.putFile(TOR_HS_PREFIX + name, Buffer.from(b64, "base64"));
    torRestored = true;
  }
  const network = d.config.network; // porty i Tor tej maszyny zostają
  const bc = b.data.config && typeof b.data.config === "object" ? b.data.config : {};
  d.config = { ...d.config, ...store.normalizeConfig({ serverName: bc.serverName, description: bc.description, termsText: bc.termsText, termsVersion: bc.termsVersion, domain: bc.domain, email: bc.email, autoNotify: bc.autoNotify, decoyPerDay: bc.push?.decoyPerDay, realJitterSec: bc.push?.realJitterSec, linkPlatformsText: Array.isArray(bc.linkPlatforms) ? bc.linkPlatforms.map((p) => `${p?.id}|${p?.name}|${(p?.hosts || []).join(",")}`).join("\n") : undefined }, d.config), network };
  d.items = items;
  d.deletions = Array.isArray(b.data.deletions) ? b.data.deletions : [];
  d.push = { subscribers: (b.data.push && typeof b.data.push.subscribers === "object") ? b.data.push.subscribers : {} };
  d.config.mediaScrubbed = 0; // S-01: obrazy z kopii (np. ze starszej wersji) też bez metadanych
  store.save(d);
  // multimedia, do których nie odwołuje się żaden wpis (stare pliki sprzed importu), usuwamy
  const used = new Set(items.flatMap((it) => [...(it.images || []), it.thumb, it.avatar, it.audio?.file, it.video?.hevc?.file, it.video?.avc?.file]).filter(Boolean).map((f) => basename(f)));
  for (const name of store.listMedia()) if (!used.has(name)) store.deleteMedia(name);
  try { scrubExistingMedia(); } catch (e) { console.warn("[media] czyszczenie metadanych:", e.message); }
  subscribersChanged();
  invalidateManifest();
  return { ok: true, items: items.length, media: mediaCount, torRestored, subscribers: Object.keys(d.push.subscribers).length };
}

/**
 * Plik treści jednego wpisu: /post/<id>.json (protokół: `content`; wersja wpisu idzie w `contentVersions`
 * manifestu — po edycji apka pobiera ten sam plik ponownie).
 */
function serveContentFile(res, req, path, isSecure) {
  const m = /^\/post\/([a-f0-9]{16})\.json$/.exec(path);
  const isDeletions = path === "/" + DELETIONS_FILE;
  const item = m ? store.findItem(store.load(), m[1]) : null;
  if (!item && !isDeletions) { res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }); res.end("Nie znaleziono"); return; }
  const { base, canonical, isOnion } = effectiveBase(requestBase(req, isSecure));
  // plik usunięć (manifest ich nie niesie) — ten sam kontekst co w manifeście, więc wersja w `contentVersions` się zgadza
  const body = isDeletions
    ? buildDeletionsFile(store.load(), { hidePermalinksOf: isOnion ? canonical : null })
    : buildContentFile(item, base, { httpsBase: isOnion ? null : canonical });
  if (!body) { res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }); res.end("Nie znaleziono"); return; }
  res.writeHead(200, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-cache", // update: significant wygasa po 48 h — nie chcemy starej kopii w cache
    Vary: "Host",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(req.method === "HEAD" ? undefined : body);
}

/** Strona wpisu /e/<id> — stały link (tożsamość pozycji w aplikacji) i coś sensownego po kliknięciu. */
function servePermalink(res, req, path) {
  const id = path.slice("/e/".length);
  const item = /^[a-f0-9]{16}$/.test(id) ? store.findItem(store.load(), id) : null; // A-18: zaplanowany (jeszcze nieopublikowany) wpis nie jest dostępny
  if (!item || !store.isVisible(item)) { res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }); res.end("Nie znaleziono"); return; }
  const cfg = store.load().config;
  const title = item.title || item.name || item.author || item.platform || cfg.serverName;
  const imgs = (item.images || []).filter((f) => /\.(webp|png|jpe?g|avif|jxl)$/i.test(f))
    .map((f) => `<img src="/media/${encodeURIComponent(f)}" alt="" loading="lazy">`).join("");
  const link = item.url ? `<p><a href="${escapeHtml(item.url)}" rel="noopener noreferrer">${escapeHtml(item.url)}</a></p>` : "";
  const sound = item.audio?.file ? `<audio controls preload="none" src="/media/${encodeURIComponent(item.audio.file)}"></audio>` : "";
  // przeglądarki najpewniej grają H.264 — dajemy go pierwszego, H.265 jako drugie źródło
  const vsrc = ["avc", "hevc"].map((k) => item.video?.[k]?.file).filter(Boolean)
    .map((f) => `<source src="/media/${encodeURIComponent(f)}" type="video/mp4">`).join("");
  const film = vsrc ? `<video controls preload="none" style="max-width:100%">${vsrc}</video>` : "";
  const meta = [cfg.serverName, item.source, item.publishedAt ? new Date(item.publishedAt).toLocaleString("pl-PL") : null]
    .filter(Boolean).map(escapeHtml).join(" · ");
  const byline = item.author && item.author !== title ? `<p class="m">${escapeHtml(item.author)}</p>` : "";
  const html = `<!doctype html><html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title>
<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:24px auto;padding:0 16px;line-height:1.5}
img{max-width:100%;height:auto;border-radius:8px;margin:8px 0}.m{opacity:.7;font-size:.9rem}
@media(prefers-color-scheme:dark){body{background:#17171b;color:#eee}a{color:#f88}}</style></head><body>
<p class="m">${meta}</p><h1>${escapeHtml(title)}</h1>${byline}
${imgs}${film}${sound}<div style="white-space:pre-wrap">${escapeHtml(item.text || "")}</div>${link}</body></html>`;
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": "default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
  });
  res.end(req.method === "HEAD" ? undefined : html);
}

// --- publiczny POST: rejestracja/wyrejestrowanie push (jedyny publiczny POST) ---
async function handlePush(req, res, action) {
  let body = {};
  try { body = JSON.parse((await readBody(req, 8 * 1024)).toString("utf8") || "{}"); } catch { return json(res, 400, { error: "zly JSON" }); }
  if (!body || typeof body !== "object") return json(res, 400, { error: "zly JSON" });
  const d = store.load();
  const r = action === "register" ? await push.register(d, body) : push.unregister(d, body);
  if (r.ok) {
    // I-08: apka rejestruje się przy każdej synchronizacji — zapis tylko przy realnej zmianie, odroczony
    if (r.changed) { subscribersChanged(); store.saveSoon(d); }
    return json(res, 200, { ok: true });
  }
  if (r.code === 429) res.setHeader("Retry-After", "5");
  return json(res, r.code || 400, { error: r.error || "blad" });
}

// --- panel: API ---
/** Sprawdzanie wydań łączy się wprost z GitHubem (ujawnia IP) — przy serwerze na Torze domyślnie wyłączone, dopóki operator tego nie zmieni. */
const autoCheckOn = (d) => (d.updates?.autoCheck !== undefined ? d.updates.autoCheck !== false : !d.config.network.torEnabled);
const QUIET_ACTIONS = new Set(["crypto/status", "update/status", "video/status", "network/wan", "state"]);
async function handleAdminApi(req, res, path, isSecure) {
  const session = sessionOf(req);
  const action = path.slice("/admin/api/".length);

  if (action === "logout") {
    if (session) { sessions.delete(session.token); logger.audit("wylogowanie", "wylogowano z panelu"); }
    res.setHeader("Set-Cookie", `admin=; Path=/admin; Max-Age=0`);
    return json(res, 200, { ok: true });
  }
  if (!session) return json(res, 401, { error: "Niezalogowano" });

  if (req.method === "GET" && action === "state") {
    const d = store.load();
    return json(res, 200, {
      config: d.config,
      items: d.items,
      publicBase: publicBase(),
      pushSubscribers: Object.keys(d.push.subscribers).length,
      subscriberStats: push.subscriberStats(d),
      maxWakeImgBytes: push.MAX_WAKE_IMG_BYTES,
      conversion: convert.describeTools(),
      now: Date.now(),
      lep: lepStats(),
      httpsBase: httpsBase(),
      https: {
        enabled: certs.hasHttps(),
        domain: certs.domain || d.config.domain || "",
        daysLeft: certs.current ? Math.floor(certs.daysLeft(certs.current.cert)) : 0,
      },
      network: {
        uptimeSec: Math.floor((Date.now() - STARTED_AT) / 1000),
        httpPort: httpPort(),
        httpsPort: httpsPort(),
        httpListening: httpServer?.listening === true,
        httpsListening: httpsServer?.listening === true,
        lanIps: listLanIps(),
        wanIp: wanIp.value,
        domain: d.config.domain || "",
        tor: tor.status(),
        endpoints: endpoints(),
      },
    });
  }


  if (req.method !== "POST" || !csrfOk(req, session)) return json(res, 403, { error: "Brak/niepoprawny token CSRF" });

  if (action === "import") {
    let raw;
    try { raw = await readBody(req, MAX_IMPORT); } catch { return json(res, 413, { error: "Kopia za duza" }); }
    let backup;
    try { backup = JSON.parse(raw.toString("utf8")); } catch { return json(res, 400, { error: "To nie jest plik kopii (zly JSON)" }); }
    const r = importBackup(backup);
    if (!r.ok) return json(res, 400, { error: r.error });
    return json(res, 200, r);
  }

  // upload multimediów dla wpisu (obraz, miniatura, awatar, dźwięk, film) + konwersja — uploads.js
  if (action === "item/image") return handleItemImage({ req, res, json, readBody, invalidateManifest });
  if (action === "item/image/delete") {
    let input = {};
    try { input = JSON.parse((await readBody(req, 4096)).toString("utf8") || "{}"); } catch { return json(res, 400, { error: "Zly JSON" }); }
    const d = store.load();
    const item = store.findItem(d, input.itemId);
    const vVariant = item && input.file && ["hevc", "avc"].find((k) => item.video?.[k]?.file === input.file);
    if (vVariant) {
      delete item.video[vVariant];
      if (!item.video.hevc && !item.video.avc) item.video = null;
      store.bumpRev(item);
      store.deleteMedia(basename(input.file));
      store.save(d); invalidateManifest();
      return json(res, 200, { ok: true, images: item.images });
    }
    if (item && input.file && item.audio?.file === input.file) {
      item.audio = null;
      store.bumpRev(item);
      store.deleteMedia(basename(input.file));
      store.save(d); invalidateManifest();
      return json(res, 200, { ok: true, images: item.images });
    }
    if (item && input.file && (item.thumb === input.file || item.avatar === input.file)) {
      if (item.thumb === input.file) item.thumb = null; else item.avatar = null;
      store.bumpRev(item);
      store.deleteMedia(basename(input.file));
      store.save(d); invalidateManifest();
      return json(res, 200, { ok: true, images: item.images });
    }
    if (!item || !item.images.includes(input.file)) return json(res, 404, { error: "Nie ma takiego obrazu" });
    item.images = item.images.filter((f) => f !== input.file);
    store.bumpRev(item);
    store.deleteMedia(basename(input.file));
    store.save(d); invalidateManifest();
    return json(res, 200, { ok: true, images: item.images });
  }

  let input = {};
  try { input = JSON.parse((await readBody(req, 1024 * 1024)).toString("utf8") || "{}"); } catch (e) { return json(res, /duze/.test(e?.message || "") ? 413 : 400, { error: /duze/.test(e?.message || "") ? "Zadanie za duze" : "Zly JSON" }); }
  const d = store.load();
  if (!QUIET_ACTIONS.has(action) && !action.startsWith("logs/")) {
    logger.audit("panel.akcja", action, { action, id: input.id || input.itemId || undefined, type: input.type || undefined, pola: Object.keys(input).slice(0, 25) });
  }

  switch (action) {
    case "config":
      d.config = store.normalizeConfig(input, d.config);
      store.save(d); invalidateManifest();
      return json(res, 200, { ok: true });
    case "password":
      if (!(await store.verifyPassword(d, input.current))) return json(res, 400, { error: "Obecne haslo niepoprawne" });
      if (!input.next || String(input.next).length < 12) return json(res, 400, { error: "Nowe haslo min. 12 znakow" });
      await store.setPassword(d, input.next); store.save(d);
      // po zmianie hasła wylogowujemy wszystkie INNE sesje (ktoś mógł znać stare hasło)
      for (const t of [...sessions.keys()]) if (t !== session.token) sessions.delete(t);
      return json(res, 200, { ok: true });
    case "sessions/logout-all": {
      const n = sessions.size;
      sessions.clear();
      res.setHeader("Set-Cookie", `admin=; Path=/admin; Max-Age=0`);
      return json(res, 200, { ok: true, loggedOut: n });
    }
    case "item/create": {
      const r = store.createItem(d, input);
      if (!r.ok) return json(res, 400, { error: r.error });
      for (const link of knownLinksOf(r.item)) store.dropDeletion(d, link);
      store.save(d); invalidateManifest();
      notifyOrDefer(d, r.item, input.deferNotify === true);
      return json(res, 200, { ok: true, item: { id: r.item.id }, scheduled: !store.isVisible(r.item) });
    }
    case "item/ready": {
      // S-03: panel skończył wgrywać obrazy/miniaturę/dźwięk/film wstrzymanego wpisu — teraz budzik
      const item = store.findItem(d, input.id);
      if (!item) return json(res, 404, { error: "Brak takiego wpisu" });
      releaseDeferred(item.id);
      autoNotifyFor(d, item);
      return json(res, 200, { ok: true });
    }
    case "item/update": {
      const before = store.findItem(d, input.id);
      const oldLinks = before ? knownLinksOf(before) : [];
      const r = store.updateItem(d, input, { linkOf: (it) => permalinkOf(it, httpsBase()) || null });
      if (!r.ok) return json(res, 400, { error: r.error });
      // zmiana linku = nowa tożsamość w aplikacji; stary wpis kasujemy przez `deletions`
      const newLinks = knownLinksOf(r.item);
      for (const link of oldLinks) if (!newLinks.includes(link)) store.addDeletion(d, link);
      for (const link of newLinks) store.dropDeletion(d, link);
      store.save(d); invalidateManifest();
      // budzik tylko przy JAWNEJ istotnej zmianie — drobna poprawka, która zachowała `significant` (S-02), nie budzi
      if (input.significant === true) notifyOrDefer(d, r.item, input.deferNotify === true);
      return json(res, 200, { ok: true, item: { id: r.item.id }, scheduled: !store.isVisible(r.item) });
    }
    case "item/delete": {
      const r = store.deleteItem(d, input.id);
      if (!r.ok) return json(res, 404, { error: r.error });
      for (const f of [...(r.item.images || []), r.item.thumb, r.item.avatar, r.item.audio?.file, r.item.video?.hevc?.file, r.item.video?.avc?.file].filter(Boolean)) store.deleteMedia(basename(f));
      // aplikacja usunie wpis u siebie tylko, gdy znała go po linku (inaczej zniknie z czasem sam)
      for (const link of knownLinksOf(r.item)) store.addDeletion(d, link);
      store.save(d); invalidateManifest();
      return json(res, 200, { ok: true });
    }
    case "item/publish": {
      // zapis + natychmiastowy budzik push (operator skończył dodawać i chce powiadomić)
      scheduleNotify();
      return json(res, 200, { ok: true, subscribers: Object.keys(d.push.subscribers).length });
    }
    case "network": {
      const prevHttp = httpPort(), prevLocal = !!d.config.network.bindLocalOnly;
      d.config.network = store.normalizeNetwork(input, d.config.network);
      store.save(d); invalidateManifest();
      if (httpPort() !== prevHttp || prevLocal !== !!d.config.network.bindLocalOnly) restartHttp();
      await tor.configure({ enabled: d.config.network.torEnabled, virtualPort: d.config.network.torVirtualPort, localPort: httpPort() });
      return json(res, 200, { ok: true, httpPort: httpPort() });
    }
    case "network/wan": {
      const ip = await fetchWanIp();
      wanIp = { value: ip, at: Date.now() };
      return json(res, 200, { ok: true, wanIp: ip });
    }
    case "cert/issue": {
      const cfg = d.config;
      if (!cfg.domain) return json(res, 400, { error: "Najpierw ustaw domene" });
      ensureAcmePort80();
      const ok = await certs.ensure(cfg.domain, cfg.email);
      if (ok) { invalidateManifest(); ensureHttpsServer(); }
      return json(res, 200, { ok });
    }
    case "export": {
      if (!(await store.verifyPassword(d, input.adminPassword))) return json(res, 400, { error: "Hasło administratora niepoprawne" });
      return exportBackup(res);
    }
    case "logs/status":
      return json(res, 200, { ok: true, stats: logger.stats() });
    case "logs/verify": {
      const v = logger.verify();
      if (!v.ok) logger.audit("dziennik.integralnosc", "WYKRYTO naruszenie integralności dziennika", { problemy: v.problems.slice(0, 10) });
      return json(res, 200, { ok: true, verify: v, stats: logger.stats() });
    }
    case "logs/query": {
      const entries = logger.query({ minLevel: String(input.minLevel || "debug"), cat: String(input.cat || ""), q: String(input.q || ""), limit: Math.min(1000, Math.max(1, Number(input.limit) || 300)), beforeSeq: Number.isFinite(Number(input.beforeSeq)) && input.beforeSeq != null ? Number(input.beforeSeq) : null });
      return json(res, 200, { ok: true, entries });
    }
    case "logs/export": {
      // hasło pliku = hasło administratora w chwili tworzenia (panel żąda go przy eksporcie i je sprawdza)
      if (!(await store.verifyPassword(d, input.adminPassword))) return json(res, 400, { error: "Hasło administratora niepoprawne" });
      const days = Math.max(0, Math.min(3650, Number(input.days) || 0));
      const minLevel = ["debug", "info", "warn", "error", "security"].includes(input.minLevel) ? input.minLevel : "debug";
      const verifyResult = logger.verify();
      const entries = logger.collect({ sinceTs: days ? Date.now() - days * 86_400_000 : 0, minLevel });
      logger.audit("dziennik.eksport", "wyeksportowano dziennik do zaszyfrowanego pliku HTML", { wpisow: entries.length, dni: days || "wszystko", minLevel, integralnosc: verifyResult.ok });
      const meta = { created: Date.now(), server: d.config.serverName, version: updater.currentVersion(), range: days ? `ostatnie ${days} dni` : "cały dziennik", minLevel, truncated: entries.truncated === true, integrity: { ok: verifyResult.ok, blocks: verifyResult.blocks, prunedPrefix: verifyResult.prunedPrefix, headHash: verifyResult.headHash, problems: verifyResult.problems.slice(0, 10) } };
      const html = buildEncryptedHtml({ entries, meta, password: input.adminPassword });
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Disposition": `attachment; filename="dziennik-serwera-${new Date().toISOString().slice(0, 10)}.html"`, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
      res.end(html);
      return;
    }
    case "video/status":
      return json(res, 200, { ok: true, ...(await convert.videoEncoderStatus()) });
    case "video/encoder": {
      const st = await convert.videoEncoderStatus();
      if (st.locked) return json(res, 400, { error: "Koder wymuszony zmienną VIDEO_ENCODER — zmień ją tam" });
      const pick = String(input.encoder || "auto");
      if (!st.options.some((o) => o.id === pick)) return json(res, 400, { error: "Nieznany koder" });
      d.videoEncoder = pick;
      store.save(d);
      convert.setVideoEncoderPreference(pick);
      return json(res, 200, { ok: true, ...(await convert.videoEncoderStatus()) });
    }
    case "update/status":
      return json(res, 200, { ok: true, ...updater.status(), autoCheck: autoCheckOn(d), supervised: process.env.LEWICOWYT_SUPERVISED === "1" });
    case "update/check":
      return json(res, 200, { ok: true, ...(await updater.check()), autoCheck: autoCheckOn(d), supervised: process.env.LEWICOWYT_SUPERVISED === "1" });
    case "update/config":
      d.updates = { ...(d.updates || {}), autoCheck: input.autoCheck !== false };
      store.save(d);
      return json(res, 200, { ok: true, autoCheck: d.updates.autoCheck });
    case "update/install": {
      if (!(await store.verifyPassword(d, input.adminPassword))) return json(res, 400, { error: "Hasło administratora niepoprawne" });
      try {
        const r = await updater.install();
        const restarting = scheduleRestartIfSupervised();
        return json(res, 200, { ...r, restarting, supervised: process.env.LEWICOWYT_SUPERVISED === "1" });
      } catch (e) { return json(res, 400, { error: e.message }); }
    }
    case "update/rollback": {
      if (!(await store.verifyPassword(d, input.adminPassword))) return json(res, 400, { error: "Hasło administratora niepoprawne" });
      try {
        const r = updater.rollback();
        return json(res, 200, { ...r, restarting: scheduleRestartIfSupervised() });
      } catch (e) { return json(res, 400, { error: e.message }); }
    }
    case "update/restart": {
      if (!scheduleRestartIfSupervised()) return json(res, 400, { error: "Serwer nie działa pod start.bat / start.sh — zamknij go i uruchom ponownie ręcznie" });
      return json(res, 200, { ok: true });
    }
    case "crypto/status":
      return json(res, 200, { ok: true, ...store.cryptoStatus({ fresh: input.fresh === true }) });
    case "crypto/cipher": {
      // zmiana szyfru przepisuje całą bazę na nowy szyfr (może potrwać przy dużych plikach)
      const pref = String(input.cipher || "auto");
      if (pref === "none" && (input.confirmNone !== true || !(await store.verifyPassword(d, input.adminPassword)))) {
        return json(res, 400, { error: "Wyłączenie szyfrowania wymaga potwierdzenia i hasła administratora" });
      }
      try {
        const r = store.setCipher(pref);
        return json(res, 200, { ok: true, rewritten: r.rewritten, ...store.cryptoStatus({ fresh: true }) });
      } catch (e) { return json(res, 400, { error: e.message }); }
    }
    case "crypto/key": {
      if (!(await store.verifyPassword(d, input.adminPassword))) return json(res, 400, { error: "Hasło administratora niepoprawne" });
      try {
        store.setKeyMode(input.mode, input.passphrase);
        return json(res, 200, { ok: true, ...store.cryptoStatus() });
      } catch (e) { return json(res, 400, { error: e.message }); }
    }
    default:
      return json(res, 404, { error: "Nieznana akcja" });
  }
}

async function handleAdmin(req, res, path, isSecure) {
  if (path === "/admin/login" && req.method === "POST") {
    const bodyStr = (await readBody(req, 64 * 1024)).toString("utf8"); // poza blokadą — wolny klient nie wstrzyma innych
    return withLoginLock(async () => {
    const now = Date.now();
    if (now < loginNextAllowedMs) {
      res.writeHead(429, { "Content-Type": "text/html; charset=utf-8", "Retry-After": String(Math.ceil((loginNextAllowedMs - now) / 1000)) });
      res.end(loginPage("Zbyt wiele prob logowania. Odczekaj chwile."));
      return;
    }
    const password = new URLSearchParams(bodyStr).get("password") || "";
    if (!(await store.verifyPassword(store.load(), password))) {
      loginFailures += 1;
      logger.audit("logowanie.blad", "nieudane logowanie do panelu", { kolejnaPorazka: loginFailures, secure: isSecure });
      loginNextAllowedMs = Date.now() + Math.min(LOGIN_BACKOFF_MAX_MS, LOGIN_BACKOFF_BASE_MS * 2 ** Math.min(loginFailures, 10));
      res.writeHead(401, { "Content-Type": "text/html; charset=utf-8" });
      res.end(loginPage("Bledne haslo."));
      return;
    }
    loginFailures = 0; loginNextAllowedMs = 0;
    logger.audit("logowanie.ok", "zalogowano do panelu", { secure: isSecure });
    const token = randomBytes(24).toString("base64url");
    sessions.set(token, { csrf: randomBytes(24).toString("base64url"), expires: Date.now() + SESSION_TTL_MS });
    const secure = isSecure ? " Secure;" : "";
    res.writeHead(302, { "Set-Cookie": `admin=${token}; HttpOnly; SameSite=Strict; Path=/admin;${secure} Max-Age=${SESSION_TTL_MS / 1000}`, Location: "/admin" });
    res.end();
    return;
    });
  }
  if (path.startsWith("/admin/api/")) return handleAdminApi(req, res, path, isSecure);

  const session = sessionOf(req);
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Content-Security-Policy": PANEL_CSP, "X-Frame-Options": "DENY" });
  res.end(session ? appPage(session.csrf) : loginPage(null));
}

process.on("unhandledRejection", (e) => { logger.error("blad", "unhandledRejection", String(e?.message || e), { err: e }); logger.raw.error("unhandledRejection:", e?.message || e); });
process.on("uncaughtException", (e) => { logger.error("blad", "uncaughtException", String(e?.message || e), { err: e }); logger.raw.error("uncaughtException:", e?.message || e); });

const handlerCore = (isSecure, allowAdmin = false) => async (req, res) => {
  res.sendDate = false;
  if (allowAdmin) {
    // A-12: panel odpowiada tylko na żądania z nagłówkiem Host wskazującym loopback (obrona przed DNS rebinding) i — dla POST — z zgodnym Origin
    const host = String(req.headers.host || "");
    const origin = req.headers.origin;
    const originOk = !origin || (() => { try { return new URL(origin).host.toLowerCase() === host.toLowerCase(); } catch { return false; } })();
    if (!LOCAL_HOST_RE.test(host) || (req.method === "POST" && !originOk)) {
      logger.audit("panel.odrzucone", "żądanie do panelu z obcym Host/Origin", { hostOk: LOCAL_HOST_RE.test(host), originOk });
      res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" }); res.end("Zabronione"); return;
    }
  }
  try {
    const path = (req.url || "/").split("?")[0];

    if (path.startsWith("/.well-known/acme-challenge/")) {
      const token = path.slice("/.well-known/acme-challenge/".length);
      const keyAuth = challenges.get(token);
      if (keyAuth) { res.writeHead(200, { "Content-Type": "text/plain" }); res.end(keyAuth); }
      else { res.writeHead(404); res.end(); }
      return;
    }

    if (path.startsWith("/admin")) {
      if (!allowAdmin) { res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }); res.end("Nie znaleziono"); return; }
      if (req.method !== "GET" && req.method !== "POST") { res.writeHead(405, { Allow: "GET, POST" }); res.end(); return; }
      return await handleAdmin(req, res, path, isSecure);
    }

    // jedyny publiczny POST (poza LEP): rejestracja push (reszta publiczna to tylko GET/HEAD)
    if (req.method === "POST" && (path === "/push/register" || path === "/push/unregister")) {
      return await handlePush(req, res, path.slice("/push/".length));
    }
    // LEP: wbudowany push — POST /lep/pub/<topic> (serwer wrzuca budzik) i GET /lep/sub/<topic> (apka long-polluje)
    if (isLep(path)) return await handleLep(req, res, path);

    if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405, { Allow: "GET, HEAD" }); res.end(); return; }

    if (path.startsWith("/media/")) return await serveMedia(res, req, path);

    if (path.startsWith("/e/")) return servePermalink(res, req, path);

    if (path.startsWith("/post/")) return serveContentFile(res, req, path, isSecure);

    if (path === "/manifest.json" || path === "/") {
      const m = manifest(requestBase(req, isSecure));
      // I-12: manifest zależy od Host — cache pośredni nie może podać wersji dla innego adresu
      const headers = { "Content-Type": "application/json; charset=utf-8", ETag: m.etag, "Cache-Control": "public, max-age=60", Vary: "Host", "X-Content-Type-Options": "nosniff", "Access-Control-Allow-Origin": "*" };
      if ((req.headers["if-none-match"] || "") === m.etag) { res.writeHead(304, headers); res.end(); return; }
      res.writeHead(200, headers);
      res.end(req.method === "HEAD" ? undefined : m.body);
      return;
    }
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Nie znaleziono");
  } catch (e) {
    // I-14: zepsute %-kodowanie w ścieżce to błąd klienta, nie serwera
    const bad = e instanceof URIError;
    if (!res.headersSent) res.writeHead(bad ? 400 : 500, { "Content-Type": "text/plain; charset=utf-8" });
    res.end(bad ? "Zle zadanie" : "Blad serwera");
    if (!bad) console.error("handler:", e?.message || e);
  }
};

function hostKind(host) {
  const h = String(host || "").toLowerCase().replace(/:\d+$/, "");
  if (h.endsWith(".onion")) return "onion";
  if (h === "localhost" || h === "127.0.0.1" || h === "[::1]") return "loopback";
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(h)) return "lan";
  return "domena";
}

/** Opakowanie: każde żądanie → wpis w dzienniku (metoda, klasa trasy, status, czas, bajty). Bez adresów IP i nagłówków klienta. */
const handler = (isSecure, allowAdmin = false) => {
  const core = handlerCore(isSecure, allowAdmin);
  return (req, res) => {
    const t0 = process.hrtime.bigint();
    const b0 = req.socket?.bytesWritten || 0;
    const path = (req.url || "/").split("?")[0];
    const route = logger.routeClass(path, allowAdmin);
    res.once("close", () => {
      try {
        const f = { method: req.method, route, status: res.statusCode, ms: +(Number(process.hrtime.bigint() - t0) / 1e6).toFixed(2), bytes: Math.max(0, (req.socket?.bytesWritten || 0) - b0), tls: !!req.socket?.encrypted, host: hostKind(req.headers.host), done: res.writableFinished };
        if (["media", "plik-tresci", "permalink", "nieznana"].includes(route)) f.path = path.slice(0, 120);
        logger.request(f);
      } catch { /* dziennik nie może psuć obsługi żądań */ }
    });
    return core(req, res);
  };
};

// publiczny nasłuch (manifest/media/push; NIE panel). I-04: apka dopisuje do adresu bez portu :2137 także
// dla https://domena — więc na TYM SAMYM porcie obsługujemy HTTP i TLS. Rozróżniamy po pierwszym bajcie
// połączenia (0x16 = TLS ClientHello) i przekazujemy gniazdo właściwemu serwerowi.
const plainServer = http.createServer(handler(false));
plainServer.on("clientError", (_e, sock) => sock.destroy());
let tlsServer = null; // powstaje, gdy jest certyfikat (ensureHttpsServer)
let httpServer = null; // gniazdo nasłuchu na httpPort
function startHttp() {
  httpServer = net.createServer((sock) => {
    sock.on("error", () => {});
    const idle = setTimeout(() => sock.destroy(), 30_000); // nic nie przyszło — nie trzymamy gniazda
    sock.once("data", (buf) => {
      clearTimeout(idle);
      sock.pause();
      sock.unshift(buf);
      const target = buf[0] === 0x16 ? tlsServer : plainServer;
      if (!target) { sock.destroy(); return; } // TLS bez certyfikatu
      target.emit("connection", sock);
      process.nextTick(() => sock.resume());
    });
  });
  httpServer.on("error", (e) => console.error(`HTTP (:${httpPort()}):`, e.message));
  const bindHost = store.load().config.network.bindLocalOnly ? "127.0.0.1" : undefined; // A-15: serwer „tylko Tor” nie musi być widoczny w sieci
  httpServer.listen(httpPort(), bindHost, () => console.log(`HTTP${tlsServer ? " i HTTPS" : ""} slucha na :${httpPort()} (manifest/push; panel NIE jest tu dostepny)`));
}

// panel TYLKO na loopbacku
let adminServer = null;
function startAdmin() {
  adminServer = http.createServer(handler(false, true));
  adminServer.on("error", (e) => console.error(`ADMIN (127.0.0.1:${ADMIN_PORT}):`, e.message));
  adminServer.listen(ADMIN_PORT, "127.0.0.1", () =>
    console.log(`Panel: http://127.0.0.1:${ADMIN_PORT}/admin  (tylko lokalnie; z innej maszyny uzyj tunelu SSH)`));
}
function restartHttp() {
  console.log(`Przekladam HTTP na port :${httpPort()} ...`);
  // stary nasłuch zamykamy od razu (połączenia w toku — np. długie odpytywanie LEP — dokończą się same), nowy startuje bez przerwy
  if (httpServer) httpServer.close();
  startHttp();
}

let acmeServer = null;
function ensureAcmePort80() {
  // ACME_HTTP01=off: bez pomocniczego nasłuchu na :80 (testy, maszyna z własnym serwerem WWW na 80)
  if (acmeServer || httpPort() === 80 || process.env.ACME_HTTP01 === "off") return;
  acmeServer = http.createServer((req, res) => {
    const path = (req.url || "/").split("?")[0];
    if (path.startsWith("/.well-known/acme-challenge/")) {
      const key = challenges.get(path.slice("/.well-known/acme-challenge/".length));
      if (key) { res.writeHead(200, { "Content-Type": "text/plain" }); res.end(key); return; }
    }
    res.writeHead(404); res.end();
  });
  acmeServer.on("error", (e) => { console.warn(`[acme] Nie moge nasluchiwac na :80 (${e.code || e.message}).`); acmeServer = null; });
  acmeServer.listen(80, () => console.log("[acme] Pomocniczy nasluch http-01 na :80 aktywny."));
}

let httpsServer = null; // osobny nasłuch na httpsPort (domyślnie 443) — dla przeglądarek i adresów bez :2137
function ensureHttpsServer() {
  if (!certs.hasHttps()) return;
  if (!tlsServer) {
    tlsServer = https.createServer({ SNICallback: (_name, cb) => cb(null, certs.secureContext()) }, handler(true));
    tlsServer.on("tlsClientError", (_e, sock) => sock.destroy());
    console.log(`HTTPS dziala tez na :${httpPort()} (https://${store.load().config.domain}:${httpPort()})`);
  }
  if (httpsServer || httpsPort() === httpPort()) return;
  httpsServer = https.createServer({ SNICallback: (_name, cb) => cb(null, certs.secureContext()) }, handler(true));
  httpsServer.on("error", (e) => console.error("HTTPS:", e.message));
  httpsServer.listen(httpsPort(), () => console.log(`HTTPS slucha na :${httpsPort()} (https://${store.load().config.domain})`));
}

// punkt 2: zaplanowane wpisy — o czasie publikacji pojawiają się w manifeście i (gdy istotne) dostają budzik
setInterval(() => {
  const d = store.load();
  const now = Date.now();
  let changed = false;
  for (const it of d.items) {
    if (it.pendingWake && store.isVisible(it, now)) {
      it.pendingWake = false;
      changed = true;
      if (d.config.autoNotify !== false) scheduleNotify();
    }
  }
  if (changed) { store.save(d); invalidateManifest(); }
  else if (d.items.some((it) => it.publishedAt > now - SCHEDULER_TICK_MS && it.publishedAt <= now)) invalidateManifest();
}, SCHEDULER_TICK_MS).unref?.();

/**
 * S-01: jednorazowo czyścimy z metadanych pliki wgrane przez starsze wersje (te same nazwy — apka i tak trzyma
 * je w pamięci podręcznej po URL-u; chodzi o kolejne pobrania). Film po zmianie ma nowy rozmiar → `bytes` i wersja.
 */
function scrubExistingMedia() {
  const d = store.load();
  if (d.config.mediaScrubbed === 1) return;
  let files = 0, failed = 0;
  const rewrite = (name, fn) => {
    const buf = store.getMedia(basename(name));
    if (!buf) return null;
    const out = fn(buf);
    if (!out) { failed += 1; console.warn(`[media] nie udało się usunąć metadanych: ${name}`); return null; }
    if (out !== buf) { store.putMedia(basename(name), out); files += 1; }
    return out;
  };
  for (const it of d.items) {
    for (const f of [...(it.images || []), it.thumb, it.avatar].filter(Boolean)) {
      rewrite(f, (buf) => { const k = sniffImage(buf); return k ? stripImageMetadata(buf, k) : buf; });
    }
    for (const k of ["hevc", "avc"]) {
      const v = it.video?.[k];
      if (!v?.file) continue;
      const out = rewrite(v.file, mp4StripMetadata);
      if (out && out.length !== v.bytes) { v.bytes = out.length; store.bumpRev(it); }
    }
  }
  d.config.mediaScrubbed = 1;
  store.save(d);
  if (files || failed) console.log(`[media] usunięto metadane z ${files} plików` + (failed ? `, nieudane: ${failed}` : ""));
}
try { scrubExistingMedia(); } catch (e) { console.warn("[media] czyszczenie metadanych:", e.message); }

startHttp();
startAdmin();
startLepCleanup();
push.startDecoys(() => store.load());
// I-08: subskrybenci LEP, których apka nie odpytuje od tygodnia, wypadają (raz na 6 h)
setInterval(() => {
  const d = store.load();
  const n = push.pruneIdleLep(d);
  if (n) { subscribersChanged(); store.save(d); console.log(`[push] wygaszeni nieaktywni subskrybenci: ${n}`); }
}, 6 * 60 * 60 * 1000).unref?.();

(async () => {
  const cfg = store.load().config;
  if (cfg.network.torEnabled) await tor.configure({ enabled: true, virtualPort: cfg.network.torVirtualPort, localPort: httpPort() });
  if (cfg.domain) {
    ensureAcmePort80();
    const ok = await certs.ensure(cfg.domain, cfg.email).catch(() => false);
    if (ok) { invalidateManifest(); ensureHttpsServer(); }
  }
  certs.startAutoRenew();
})();

/** Restart po aktualizacji: kod 75 → start.bat / start.sh (LEWICOWYT_SUPERVISED=1) uruchamiają serwer od nowa. */
function scheduleRestartIfSupervised() {
  if (process.env.LEWICOWYT_SUPERVISED !== "1") return false;
  setTimeout(() => { try { logger.shutdown(); store.flush(); store.close(); tor.shutdown(); } catch { /* ignore */ } process.exit(updater.RESTART_EXIT_CODE); }, 1200);
  return true;
}
updater.startBackgroundChecks(() => autoCheckOn(store.load()));

process.on("SIGINT", () => { logger.shutdown(); tor.shutdown(); store.flush(); store.close(); process.exit(0); });
process.on("SIGTERM", () => { logger.shutdown(); tor.shutdown(); store.flush(); store.close(); process.exit(0); });

setInterval(() => { const now = Date.now(); for (const [t, s] of sessions) if (s.expires < now) sessions.delete(t); }, 60 * 60 * 1000).unref?.();
