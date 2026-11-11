// Trwały magazyn serwera społeczności — JEDNA baza danych SQLite (data/serwer.db, wbudowany moduł node:sqlite,
// bez zewnętrznych zależności), SZYFROWANA domyślnie. W bazie jest WSZYSTKO: konfiguracja, hasło administratora
// (skrót), wpisy, usunięcia, subskrybenci push, pliki multimedialne, certyfikaty HTTPS i klucz usługi ukrytej Tora.
//
// Szyfrowanie (dbcrypto.js): każda wartość w bazie (wiersz wpisu, konfiguracja, kawałek pliku…) jest szyfrowana
// i uwierzytelniana (AEAD), a szyfr wybierany jest od najlepszego do najgorszego pod kątem przyspieszenia
// sprzętowego CPU (AES-NI / ARM AES, PCLMULQDQ / PMULL, SHA-NI). Domyślnie „auto”; użytkownik może wybrać
// inny szyfr (sprzętowy albo programowy) w panelu lub zmienną DB_CIPHER. Jawne zostają tylko nazwy plików,
// identyfikatory wpisów i rozmiary.
//
// Tabele (v2):  meta(key, value)           — konfiguracja, usunięcia, skrót hasła, ustawienia push
//               items(id, data)            — jeden wiersz na wpis
//               subscribers(ref, data)     — subskrybenci push (ref = HMAC adresu, sam adres jest w zaszyfrowanej treści)
//               media(name, size, chunks)  + media_chunks(name, idx, data) — multimedia w zaszyfrowanych kawałkach po 1 MiB
//               files(path, data)          — certyfikaty (cert/…) i klucz usługi ukrytej Tora (tor/hs/…)
//
// Wszystko konfigurowalne z panelu w przeglądarce; tutaj tylko odczyt/zapis + walidacja. Model treści jest
// OGÓLNY: jedna lista `items`, każdy z polem `type` (post / meme / article / foreign / ad / contest / creator).
// Osobno trzymamy subskrybentów push (endpoint UnifiedPush + klucz publiczny E2E) i listę usuniętych linków
// (`deletions`), żeby aplikacja skasowała u siebie to, co operator usunął.

import fs from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes, scrypt, timingSafeEqual, createHash } from "node:crypto";
import zlib from "node:zlib";
import { promisify } from "node:util";
import { DatabaseSync } from "node:sqlite";
import * as dbc from "./dbcrypto.js";

const scryptAsync = promisify(scrypt);

const __dirname = dirname(fileURLToPath(import.meta.url));
// DATA_DIR z env — do testów i do trzymania danych poza folderem programu
export const DATA_DIR = process.env.DATA_DIR || join(__dirname, "data");
export const DB_FILE = join(DATA_DIR, "serwer.db");
const SCHEMA_VERSION = 2;
// układ sprzed bazy danych (do jednorazowej migracji): data.json + post/<id>.json + media/ + cert/ + tor/hs/
const LEGACY = {
  dataFile: join(DATA_DIR, "data.json"),
  postDir: join(DATA_DIR, "post"),
  mediaDir: join(DATA_DIR, "media"),
  certDir: join(DATA_DIR, "cert"),
  torHsDir: join(DATA_DIR, "tor", "hs"),
  moved: join(DATA_DIR, "stare-przed-baza"),
};
const ID_RE = /^[a-f0-9]{16}$/;
const MEDIA_NAME_RE = /^[A-Za-z0-9_.-]{1,128}$/;

const MAX_TITLE = 300;
const MAX_TEXT = 5_000; // aplikacja i tak tnie tekst do 5000 znaków
const MAX_NAME = 200;
// I-03: regulamin wchodzi w całości do manifestu, a apka odrzuca odpowiedź > 1 000 000 znaków.
// Zostawiamy miejsce na treść (manifest pilnuje ~900 tys. znaków łącznie).
export const MAX_TERMS = 400_000;
const MAX_URL = 4096; // I-11: dłuższy link apka odrzuca (MAX_URL_CHARS), a artykuł bez linku znika
export const NOTIFY_WINDOW_MS = 48 * 60 * 60 * 1000; // I-01: jak długo wpis niesie update: significant
export const ITEM_TYPES = ["post", "meme", "article", "foreign", "ad", "contest", "creator"];
export const MAX_MEME_IMAGES = 20; // karuzela memu — limit aplikacji
const MAX_DELETIONS = 200; // aplikacja czyta do 200 pozycji `deletions`
const MAX_DECOY_PER_DAY = 24;
const MAX_JITTER_SEC = 600; // rozmywanie prawdziwych budzików: najwyżej 10 min opóźnienia
const MAX_LINK_PLATFORMS = 30;

function emptyData() {
  return {
    config: {
      serverName: "Mój serwer społeczności",
      description: "",
      termsText:
        "Regulamin serwera społeczności.\n\n" +
        "1. Serwer tylko WYSYŁA treści — nie zbiera Twoich danych, nie loguje Cię, nie prowadzi telemetrii.\n" +
        "2. Powiadomienia idą przez UnifiedPush (wbudowany w aplikację albo np. ntfy) — bez Google. Serwer dostaje tylko ulotny " +
        "adres dostarczenia i Twój klucz publiczny; nie zna Twojej tożsamości. Budziki są szyfrowane E2E.\n" +
        "3. Akceptując regulamin, zgadzasz się na pobieranie i wyświetlanie tych treści na swoim urządzeniu.",
      termsVersion: "1",
      domain: "",
      email: "",
      // I-02/I-05: adres HTTPS, pod którym apka nas zna (domena[:port]) — uczony z żądań TLS/proxy.
      // Z niego są stałe linki /e/<id> i adresy w manifeście oddawanym na adres LAN (failover apki).
      canonicalHttpsBase: null,
      // budzik push wysyłany sam po dodaniu/edycji istotnego wpisu (i o czasie publikacji zaplanowanego)
      autoNotify: true,
      // platformy linków zadeklarowane ręcznie (np. dla linków w artykułach): [{ id, name, hosts[] }]
      linkPlatforms: [],
      network: {
        httpPort: null, // null = użyj HTTP_PORT z env albo 2137
        httpsPort: null, // null = użyj HTTPS_PORT z env albo 443
        torEnabled: false,
        torVirtualPort: 2137, // aplikacja oczekuje serwera .onion na :2137
      },
      push: {
        decoyPerDay: 0, // puste budziki (szum) na subskrybenta na dobę; 0 = wyłączone
        realJitterSec: 0, // prawdziwy budzik do każdego adresu z losowym opóźnieniem 0..N s; 0 = od razu
      },
    },
    items: [],
    deletions: [], // [{ url, at }] — linki usuniętych wpisów, aplikacja kasuje je u siebie
    push: { subscribers: {} }, // endpoint -> { pubkey, at }
    adminPasswordHash: null,
  };
}

export function id() {
  return randomBytes(8).toString("hex");
}

// --- klucz i szyfr ---
let crypt = null; // dbc.Crypt
let logCrypt = null; // dbc.Crypt — dziennik: ZAWSZE najlepszy szyfr akcelerowany przez CPU, niezależnie od wyboru szyfru bazy
let settings = null; // zawartość data/szyfrowanie.json
let keyInfo = { via: "", created: false };
let cpuInfo = null;
let autoTrace = null;

function cpuCached() {
  if (!cpuInfo) cpuInfo = dbc.detectCpu();
  return cpuInfo;
}

/** Który szyfr ma być używany do NOWYCH zapisów: wybór użytkownika albo „auto” (najlepszy dla tego CPU). */
function resolveCipherId(pref) {
  if (pref && pref !== "auto") {
    const c = dbc.cipherByName(pref);
    if (c && dbc.selfTest(c.id)) return c.id;
    console.warn(`[szyfrowanie] szyfr „${pref}” niedostępny w tym Node.js — używam trybu auto`);
  }
  const cpu = cpuCached();
  const sig = `${cpu.platform}|${cpu.arch}|${cpu.model}|${process.versions.openssl}`;
  const cache = settings?.autoCache;
  if (cache && cache.sig === sig && dbc.cipherById(cache.id) && dbc.selfTest(cache.id)) { autoTrace = cache.trace || null; return cache.id; }
  const r = dbc.chooseAuto(cpu);
  autoTrace = r.trace;
  if (settings) settings.autoCache = { sig, id: r.id, trace: r.trace };
  return r.id;
}

function openRaw() {
  if (db) return db;
  fs.mkdirSync(DATA_DIR, { recursive: true });
  db = new DatabaseSync(DB_FILE);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000; PRAGMA secure_delete = ON;");
  return db;
}

const hasTable = (name) => !!sql("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?").get(name);
const tableColumns = (name) => sql(`PRAGMA table_info(${name})`).all().map((c) => c.name);

function createSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS items (id TEXT PRIMARY KEY, data BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS subscribers (ref TEXT PRIMARY KEY, data BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS media (name TEXT PRIMARY KEY, size INTEGER NOT NULL, chunks INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS media_chunks (name TEXT NOT NULL, idx INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (name, idx));
    CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, data BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS logs (
      first_seq INTEGER PRIMARY KEY, last_seq INTEGER NOT NULL, ts_first INTEGER NOT NULL, ts_last INTEGER NOT NULL,
      count INTEGER NOT NULL, raw_bytes INTEGER NOT NULL, comp_bytes INTEGER NOT NULL,
      prev_hash TEXT NOT NULL, hash TEXT NOT NULL, data BLOB NOT NULL);
  `);
}

const text = (v) => (typeof v === "string" ? v : Buffer.from(v).toString("utf8"));
const encJson = (aad, str) => crypt.encrypt(Buffer.from(str, "utf8"), aad);
const decJson = (aad, blob) => crypt.decrypt(blob, aad).toString("utf8");

/** Baza z wersji 1.10.0 (jawna, tabele json/data) → v2 (zaszyfrowana). Stare strony są nadpisywane (secure_delete + VACUUM). */
function upgradeFromV1() {
  console.log("[szyfrowanie] przepisuję bazę z wersji jawnej do zaszyfrowanej…");
  inTransaction(() => {
    for (const t of ["meta", "items", "subscribers", "media", "files"]) if (hasTable(t)) db.exec(`ALTER TABLE ${t} RENAME TO ${t}_v1`);
    createSchema();
    for (const r of sql("SELECT key, value FROM meta_v1").all()) sql("INSERT INTO meta (key, value) VALUES (?, ?)").run(r.key, encJson(dbc.aad.meta(r.key), text(r.value)));
    for (const r of sql("SELECT id, json FROM items_v1").all()) sql("INSERT INTO items (id, data) VALUES (?, ?)").run(r.id, encJson(dbc.aad.item(r.id), r.json));
    for (const r of sql("SELECT endpoint, json FROM subscribers_v1").all()) {
      const ref = crypt.ref(r.endpoint);
      sql("INSERT INTO subscribers (ref, data) VALUES (?, ?)").run(ref, encJson(dbc.aad.subscriber(ref), JSON.stringify({ endpoint: r.endpoint, v: JSON.parse(r.json) })));
    }
    for (const r of sql("SELECT name, data FROM media_v1").all()) writeMedia(r.name, Buffer.from(r.data));
    for (const r of sql("SELECT path, data FROM files_v1").all()) sql("INSERT INTO files (path, data) VALUES (?, ?)").run(r.path, crypt.encrypt(Buffer.from(r.data), dbc.aad.file(r.path)));
    for (const t of ["meta", "items", "subscribers", "media", "files"]) if (hasTable(t + "_v1")) db.exec(`DROP TABLE ${t}_v1`);
    db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
  });
  stmts.clear();
  try { db.exec("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;"); } catch (e) { console.warn("[szyfrowanie] VACUUM:", e.message); }
}

function dbHasData() {
  return hasTable("meta") && !!sql("SELECT 1 FROM meta LIMIT 1").get();
}

/**
 * Odblokowanie: ustala klucz główny i szyfr, otwiera bazę, dokonuje ewentualnej migracji schematu.
 * Wywoływane raz przy starcie (`await store.unlock()`); `load()` wywoła wersję synchroniczną, jeśli ktoś zapomni.
 */
/** Awaria w trakcie zmiany klucza: jeśli baza otwiera się kluczem zapisanym jako „.nowy”, wprowadzamy go na stałe; w przeciwnym razie sprzątamy. */
function recoverPendingKey(passphrase) {
  const kp = dbc.keyFilePath(DATA_DIR) + ".nowy";
  const wp = dbc.wrappedFilePath(DATA_DIR) + ".nowy";
  if (!fs.existsSync(kp) && !fs.existsSync(wp)) return;
  const row = sql("SELECT value FROM meta WHERE key = 'main'").get();
  const works = (key) => { try { new dbc.Crypt(key, 5, { allowNone: true }).decrypt(row.value, dbc.aad.meta("main")); return true; } catch { return false; } };
  if (row && fs.existsSync(kp)) {
    try {
      const key = dbc.readKeyFile(kp);
      if (works(key)) { fs.renameSync(kp, dbc.keyFilePath(DATA_DIR)); settings.keyMode = "file"; settings.wrapped = null; dbc.shredFile(dbc.wrappedFilePath(DATA_DIR)); dbc.shredFile(wp); dbc.writeSettings(DATA_DIR, settings); console.warn("[szyfrowanie] dokończono przerwaną zmianę klucza (plik klucza)"); return; }
    } catch { /* uszkodzony */ }
  }
  const pass = passphrase || process.env.DB_PASSPHRASE;
  const w = dbc.readWrappedFile(DATA_DIR, ".nowy");
  if (row && w && pass) {
    try {
      const key = dbc.unwrapKey(w, pass);
      if (works(key)) { dbc.writeWrappedFile(DATA_DIR, w); dbc.shredFile(wp); settings.wrapped = w; settings.keyMode = "passphrase"; dbc.removeKeyFile(DATA_DIR); dbc.writeSettings(DATA_DIR, settings); console.warn("[szyfrowanie] dokończono przerwaną zmianę klucza (hasło)"); return; }
    } catch { /* złe hasło */ }
  }
}

function unlockSync({ passphrase = null } = {}) {
  if (crypt) return;
  settings = dbc.readSettings(DATA_DIR);
  const envCipher = process.env.DB_CIPHER;
  if (envCipher) settings.cipher = envCipher === "auto" ? "auto" : (dbc.cipherByName(envCipher) ? envCipher : "auto");
  openRaw();
  if (settings.keyMode === "passphrase" && settings.cipher === "none") {
    // A-06 (audyt): jawny plik szyfrowanie.json nie może wyłączyć szyfrowania bazy chronionej hasłem
    console.warn("[szyfrowanie] tryb hasła nie pozwala na wyłączenie szyfrowania — ignoruję cipher=none z szyfrowanie.json / DB_CIPHER");
    settings.cipher = "auto";
  }
  const existing = hasTable("meta") || hasTable("items");
  const userVersion = Number(sql("PRAGMA user_version").get().user_version);
  const v1 = existing && userVersion < SCHEMA_VERSION; // jawna baza z 1.10.0 (albo pusta)
  const encryptedExisting = existing && !v1 && dbHasData();
  if (encryptedExisting) recoverPendingKey(passphrase);
  const mk = dbc.resolveMasterKey(DATA_DIR, settings, { passphrase, mayCreate: !encryptedExisting });
  keyInfo = mk;
  const cipherId = resolveCipherId(settings.cipher);
  crypt = new dbc.Crypt(mk.key, cipherId, { allowNone: (settings.cipher === "none" || v1 || settings.keyMode !== "passphrase") });
  logCrypt = new dbc.Crypt(dbc.deriveMaster(mk.key, "log"), resolveCipherId("auto"));
  if (v1) upgradeFromV1();
  else createSchema();
  db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
  const mainRow = sql("SELECT value FROM meta WHERE key = 'main'").get();
  let legacyNone = false;
  if (mainRow) {
    try { crypt.decrypt(mainRow.value, dbc.aad.meta("main")); legacyNone = dbc.Crypt.cipherIdOf(mainRow.value) === 0; }
    catch { crypt = null; throw new Error("Nie można odszyfrować bazy — zły klucz/hasło albo uszkodzone dane."); }
  }
  // A-21: baza pracowała bez szyfrowania (DB_CIPHER=none), a teraz wybrano szyfr — przepisujemy wartości zamiast zgłaszać „zły klucz”
  if (legacyNone && settings.cipher !== "none") {
    crypt.allowNone = true;
    const n = reencryptAll(crypt.cipherId);
    console.log(`[szyfrowanie] baza była niezaszyfrowana — zaszyfrowano wartości: ${n}`);
  }
  crypt.allowNone = settings.cipher === "none";
  dbc.writeSettings(DATA_DIR, settings);
  const c = crypt.cipher;
  console.log(`[szyfrowanie] baza: ${c.label}${c.id === 0 ? " — WYŁĄCZONE" : ""} (${settings.cipher === "auto" ? "wybór automatyczny" : "wybór użytkownika"}); klucz: ${mk.via}${mk.created ? " [utworzony]" : ""}`);
  if (mk.created) console.log("[szyfrowanie] WAŻNE: zrób kopię pliku klucza — bez niego zaszyfrowanej bazy nie da się odczytać.");
}

export async function unlock() {
  if (crypt) return;
  try {
    unlockSync();
  } catch (e) {
    if (e.code !== "NEED_PASSPHRASE") throw e;
    for (let tries = 0; tries < 3; tries++) {
      const pass = await dbc.promptHidden("Hasło do bazy danych: ");
      try { unlockSync({ passphrase: pass }); return; } catch (err) { console.error(err.message); }
    }
    throw new Error("Nie podano poprawnego hasła do bazy.");
  }
}

// --- baza danych ---
let db = null;
const stmts = new Map();
function sql(text) {
  let s = stmts.get(text);
  if (!s) { s = openRaw().prepare(text); stmts.set(text, s); }
  return s;
}

/** Zamyka bazę (checkpoint WAL) — przy zamykaniu serwera. */
export function close() {
  if (!db) return;
  try { db.exec("PRAGMA wal_checkpoint(TRUNCATE)"); } catch { /* ignore */ }
  try { db.close(); } catch { /* ignore */ }
  db = null; stmts.clear(); crypt = null; logCrypt = null; cache = null; logHeadHash = null;
}

let cache = null;
// co jest już w bazie (zapisujemy tylko różnice) — wartości jawne, porównujemy tekst przed szyfrowaniem
let savedMain = null;
const savedItems = new Map(); // id -> json
const savedSubs = new Map(); // endpoint -> json

const itemJson = (it) => JSON.stringify(it);

let txDepth = 0;
function inTransaction(fn) {
  if (txDepth > 0) return fn();
  openRaw().exec("BEGIN IMMEDIATE");
  txDepth++;
  try { const r = fn(); db.exec("COMMIT"); return r; }
  catch (e) { try { db.exec("ROLLBACK"); } catch { /* ignore */ } throw e; }
  finally { txDepth--; }
}

// --- jednorazowa migracja z układu plikowego (wersje ≤ 1.9.0) ---
function migrateFromFiles() {
  if (!fs.existsSync(LEGACY.dataFile) && !fs.existsSync(LEGACY.postDir) && !fs.existsSync(LEGACY.mediaDir)) return false;
  let main = {};
  try { main = JSON.parse(fs.readFileSync(LEGACY.dataFile, "utf8")); } catch { /* brak/uszkodzony — zaczynamy od domyślnych */ }
  const items = [];
  const seen = new Set();
  try {
    for (const name of fs.readdirSync(LEGACY.postDir)) {
      const iid = name.slice(0, -5);
      if (!name.endsWith(".json") || !ID_RE.test(iid)) continue;
      try {
        const it = JSON.parse(fs.readFileSync(join(LEGACY.postDir, name), "utf8"));
        if (it && typeof it === "object") { it.id = iid; items.push(it); seen.add(iid); }
      } catch { console.warn(`[store] migracja: pomijam uszkodzony plik post/${name}`); }
    }
  } catch { /* brak katalogu */ }
  for (const it of Array.isArray(main.items) ? main.items : []) {
    if (it && ID_RE.test(it.id) && !seen.has(it.id)) items.push(it); // wpisy z najstarszego układu (w data.json)
  }
  const { items: _legacyItems, postHashes: _h, ...rest } = main;
  const subscribers = (rest.push && typeof rest.push.subscribers === "object" && rest.push.subscribers) || {};
  inTransaction(() => {
    putMain(JSON.stringify({ ...rest, push: { ...(rest.push || {}), subscribers: undefined } }));
    for (const it of items) putItemRow(it.id, itemJson(it));
    for (const [ep, v] of Object.entries(subscribers)) putSubscriberRow(ep, JSON.stringify(v));
    const putAll = (dir, prefix, kind) => {
      try {
        for (const name of fs.readdirSync(dir)) {
          const p = join(dir, name);
          if (!fs.statSync(p).isFile() || name.endsWith(".tmp")) continue;
          const bytes = fs.readFileSync(p);
          if (kind === "media") { if (MEDIA_NAME_RE.test(name)) writeMedia(name, bytes); }
          else putFile(prefix + name, bytes);
        }
      } catch { /* brak katalogu */ }
    };
    putAll(LEGACY.mediaDir, "", "media");
    putAll(LEGACY.certDir, "cert/", "files");
    putAll(LEGACY.torHsDir, "tor/hs/", "files");
  });
  // stare pliki odkładamy na bok (nic nie kasujemy) — po sprawdzeniu można usunąć cały katalog
  fs.mkdirSync(LEGACY.moved, { recursive: true });
  for (const p of [LEGACY.dataFile, LEGACY.dataFile + ".tmp", LEGACY.postDir, LEGACY.mediaDir, LEGACY.certDir, LEGACY.torHsDir]) {
    try { if (fs.existsSync(p)) fs.renameSync(p, join(LEGACY.moved, p.slice(DATA_DIR.length + 1).replace(/[\\/]/g, "_"))); } catch (e) { console.warn(`[store] migracja: nie przeniesiono ${p}: ${e.message}`); }
  }
  // klucze prywatne (HTTPS, usługa .onion) są już w zaszyfrowanej bazie — jawnych kopii nie zostawiamy na dysku
  for (const [dir, prefix, moved] of [[LEGACY.certDir, "cert/", "cert"], [LEGACY.torHsDir, "tor/hs/", "tor_hs"]]) {
    const where = join(LEGACY.moved, moved);
    try {
      if (!fs.existsSync(where)) continue;
      const n = fs.readdirSync(where).filter((f) => fs.statSync(join(where, f)).isFile() && !f.endsWith(".tmp")).length;
      if (n <= listFiles(prefix).length) { fs.rmSync(where, { recursive: true, force: true }); console.log(`[store] migracja: usunięto jawne pliki kluczy (${moved}) — kopie są w zaszyfrowanej bazie`); }
    } catch (e) { console.warn(`[store] migracja: nie usunięto jawnych kluczy (${where}): ${e.message}`); }
  }
  console.log(`[store] zmigrowano dane do zaszyfrowanej bazy ${DB_FILE} (wpisy: ${items.length}); stare, JAWNE pliki: ${LEGACY.moved} — usuń je po sprawdzeniu`);
  return true;
}

// --- niskopoziomowy zapis zaszyfrowanych wierszy ---
const putMain = (txt) => sql("INSERT OR REPLACE INTO meta (key, value) VALUES ('main', ?)").run(encJson(dbc.aad.meta("main"), txt));
const putItemRow = (iid, txt) => sql("INSERT OR REPLACE INTO items (id, data) VALUES (?, ?)").run(iid, encJson(dbc.aad.item(iid), txt));
function putSubscriberRow(endpoint, txt) {
  const ref = crypt.ref(endpoint);
  sql("INSERT OR REPLACE INTO subscribers (ref, data) VALUES (?, ?)").run(ref, encJson(dbc.aad.subscriber(ref), JSON.stringify({ endpoint, v: JSON.parse(txt) })));
}

export function load() {
  if (cache) return cache;
  if (!crypt) unlockSync();
  let mainRow = sql("SELECT value FROM meta WHERE key = 'main'").get();
  if (!mainRow && migrateFromFiles()) mainRow = sql("SELECT value FROM meta WHERE key = 'main'").get();
  let main = {};
  let mainTxt = null;
  if (mainRow) { mainTxt = decJson(dbc.aad.meta("main"), mainRow.value); try { main = JSON.parse(mainTxt); } catch { main = {}; } }
  const items = [];
  savedItems.clear(); savedSubs.clear();
  for (const row of sql("SELECT id, data FROM items").all()) {
    try { const j = decJson(dbc.aad.item(row.id), row.data); const it = JSON.parse(j); if (it && typeof it === "object") { it.id = row.id; items.push(it); savedItems.set(row.id, j); } }
    catch (e) { console.error(`[store] BŁĄD: wpis ${row.id} nie przechodzi uwierzytelnienia i został pominięty (uszkodzenie albo ingerencja w bazę): ${e.message}`); }
  }
  const subscribers = {};
  for (const row of sql("SELECT ref, data FROM subscribers").all()) {
    try { const o = JSON.parse(decJson(dbc.aad.subscriber(row.ref), row.data)); subscribers[o.endpoint] = o.v; savedSubs.set(o.endpoint, JSON.stringify(o.v)); } catch (e) { console.error(`[store] BŁĄD: subskrybent ${String(row.ref).slice(0, 8)}… nie przechodzi uwierzytelnienia i został pominięty: ${e.message}`); }
  }
  savedMain = mainTxt;
  cache = { ...emptyData(), ...main, items, push: { ...(main.push || {}), subscribers } };
  const def = emptyData();
  cache.config = { ...def.config, ...(cache.config || {}) };
  cache.config.network = { ...def.config.network, ...(cache.config.network || {}) };
  cache.config.push = { ...def.config.push, ...(cache.config.push || {}) };
  // serwer z ręczną treścią nie dostarcza filmów ani primaryFeed — jako „główny” zgubiłby userowi
  // powiadomienia o filmach. Starsze dane mogły mieć tu true; wymuszamy false.
  delete cache.config.canBePrimary;
  for (const it of cache.items) {
    // migracja: jeden imageFile → lista images (karuzela memów)
    if (!Array.isArray(it.images)) it.images = it.imageFile ? [it.imageFile] : [];
    delete it.imageFile;
    if (!Number.isInteger(it.rev) || it.rev < 1) it.rev = 1;
    if (!it.revAt) it.revAt = it.updatedAt || it.createdAt || Date.now();
  }
  cache.deletions = Array.isArray(cache.deletions) ? cache.deletions : [];
  if (!cache.push.subscribers || typeof cache.push.subscribers !== "object") cache.push.subscribers = {};
  save(cache); // zapisze różnice po normalizacji (przy świeżej bazie — wartości domyślne)
  return cache;
}

/** Nowa wersja wpisu (po edycji albo zmianie obrazów) — aplikacja pobierze go pod nową nazwą. */
export function bumpRev(item) {
  item.rev = (item.rev || 1) + 1;
  item.revAt = Date.now();
}

let saveTimer = null;
export function save(data) {
  cache = data;
  if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
  const { items, push, postHashes: _h, ...rest } = data;
  const { subscribers, ...pushRest } = push || {};
  const mainTxt = JSON.stringify({ ...rest, push: pushRest });
  const newItems = new Map();
  for (const it of items) newItems.set(it.id, itemJson(it));
  const newSubs = new Map();
  for (const [ep, v] of Object.entries(subscribers || {})) newSubs.set(ep, JSON.stringify(v));
  inTransaction(() => {
    if (mainTxt !== savedMain) putMain(mainTxt);
    for (const [iid, txt] of newItems) if (savedItems.get(iid) !== txt) putItemRow(iid, txt);
    for (const iid of savedItems.keys()) if (!newItems.has(iid)) sql("DELETE FROM items WHERE id = ?").run(iid);
    for (const [ep, txt] of newSubs) if (savedSubs.get(ep) !== txt) putSubscriberRow(ep, txt);
    for (const ep of savedSubs.keys()) if (!newSubs.has(ep)) sql("DELETE FROM subscribers WHERE ref = ?").run(crypt.ref(ep));
  });
  savedMain = mainTxt;
  savedItems.clear(); for (const [k, v] of newItems) savedItems.set(k, v);
  savedSubs.clear(); for (const [k, v] of newSubs) savedSubs.set(k, v);
}
/**
 * I-08: zapis odroczony — dla częstych, mało ważnych zmian (rejestracje push, czas ostatniego odpytania).
 * Wiele zmian w ciągu sekundy = jeden zapis do bazy zamiast zapisu przy każdym żądaniu.
 */
export function saveSoon(data, delayMs = 1000) {
  cache = data;
  if (saveTimer) return;
  saveTimer = setTimeout(() => { saveTimer = null; try { save(cache); } catch (e) { console.error("[store] zapis:", e.message); } }, delayMs);
  saveTimer.unref?.();
}
/** Zapisuje odroczone zmiany natychmiast (przy zamykaniu serwera). */
export function flush() {
  if (saveTimer && cache) save(cache);
}

// --- multimedia w bazie: zaszyfrowane kawałki po 1 MiB (BLOB) ---
export const isMediaName = (name) => typeof name === "string" && MEDIA_NAME_RE.test(name);
function writeMedia(name, b) {
  const chunks = Math.max(1, Math.ceil(b.length / dbc.CHUNK));
  inTransaction(() => {
    sql("DELETE FROM media_chunks WHERE name = ?").run(name);
    for (let i = 0; i < chunks; i++) {
      const part = b.subarray(i * dbc.CHUNK, Math.min(b.length, (i + 1) * dbc.CHUNK));
      sql("INSERT INTO media_chunks (name, idx, data) VALUES (?, ?, ?)").run(name, i, crypt.encrypt(part, dbc.aad.chunk(name, i, chunks, b.length)));
    }
    sql("INSERT OR REPLACE INTO media (name, size, chunks) VALUES (?, ?, ?)").run(name, b.length, chunks);
  });
  lastChunk = null;
}
export function putMedia(name, bytes) {
  if (!isMediaName(name)) throw new Error("zła nazwa pliku");
  writeMedia(name, Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes));
}
/** Rozmiar pliku w bajtach albo null, gdy go nie ma. */
export function mediaSize(name) {
  const r = sql("SELECT size FROM media WHERE name = ?").get(name);
  return r ? Number(r.size) : null;
}
export function hasMedia(name) { return mediaSize(name) != null; }
let lastChunk = null; // { key, data } — ostatnio odszyfrowany kawałek (serwowanie sekwencyjne nie odszyfrowuje dwa razy)
function chunkPlain(name, idx, chunks, size) {
  const key = `${name}:${idx}:${chunks}:${size}`;
  if (lastChunk?.key === key) return lastChunk.data;
  const row = sql("SELECT data FROM media_chunks WHERE name = ? AND idx = ?").get(name, idx);
  if (!row) throw new Error(`brak kawałka ${idx} pliku ${name}`);
  const data = crypt.decrypt(row.data, dbc.aad.chunk(name, idx, chunks, size));
  lastChunk = { key, data };
  return data;
}
/** Cały plik (Buffer) albo null. */
export function getMedia(name) {
  const m = sql("SELECT size, chunks FROM media WHERE name = ?").get(name);
  if (!m) return null;
  const parts = [];
  for (let i = 0; i < m.chunks; i++) parts.push(chunkPlain(name, i, Number(m.chunks), Number(m.size)));
  return Buffer.concat(parts);
}
/** Fragment pliku [offset, offset+length) — do strumieniowania dużych filmów bez ładowania całości do pamięci. */
export function readMediaChunk(name, offset, length) {
  const m = sql("SELECT size, chunks FROM media WHERE name = ?").get(name);
  if (!m || offset >= m.size) return null;
  const size = Number(m.size), chunks = Number(m.chunks);
  const end = Math.min(size, offset + length);
  const parts = [];
  for (let i = Math.floor(offset / dbc.CHUNK); i <= Math.floor((end - 1) / dbc.CHUNK); i++) {
    const plain = chunkPlain(name, i, chunks, size);
    const from = Math.max(0, offset - i * dbc.CHUNK);
    const to = Math.min(plain.length, end - i * dbc.CHUNK);
    parts.push(plain.subarray(from, to));
  }
  return Buffer.concat(parts);
}
export function deleteMedia(name) {
  if (!isMediaName(name)) return;
  inTransaction(() => { sql("DELETE FROM media_chunks WHERE name = ?").run(name); sql("DELETE FROM media WHERE name = ?").run(name); });
  lastChunk = null;
}
export function listMedia() { return sql("SELECT name FROM media ORDER BY name").all().map((r) => r.name); }

// --- pliki pomocnicze w bazie: certyfikaty (cert/…), klucz usługi ukrytej Tora (tor/hs/…) ---
export function putFile(path, bytes) {
  sql("INSERT OR REPLACE INTO files (path, data) VALUES (?, ?)").run(path, crypt.encrypt(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes), dbc.aad.file(path)));
}
export function getFile(path) {
  const r = sql("SELECT data FROM files WHERE path = ?").get(path);
  return r ? crypt.decrypt(r.data, dbc.aad.file(path)) : null;
}
export function deleteFile(path) { sql("DELETE FROM files WHERE path = ?").run(path); }
export function listFiles(prefix) { return sql("SELECT path FROM files WHERE path LIKE ? ESCAPE '\\' ORDER BY path").all(prefix.replace(/[\\%_]/g, "\\$&") + "%").map((r) => r.path); }

// --- dziennik zdarzeń w bazie: blok → ZSTD(3) → szyfr CPU (logCrypt) → szyfr bazy ---
const ZERO_HASH = "0".repeat(64);
let logHeadHash = null;
const zstd = (buf) => zlib.zstdCompressSync(buf, { params: { [zlib.constants.ZSTD_c_compressionLevel]: 3, [zlib.constants.ZSTD_c_checksumFlag]: 1 } });

export function logNextSeq() {
  const r = sql("SELECT max(last_seq) AS m FROM logs").get();
  return (r && r.m != null ? Number(r.m) : 0) + 1;
}
function logHead() {
  if (logHeadHash) return logHeadHash;
  const r = sql("SELECT hash FROM logs ORDER BY first_seq DESC LIMIT 1").get();
  return (logHeadHash = r ? r.hash : ZERO_HASH);
}
export function dbSizeMB() {
  let n = 0;
  for (const f of [DB_FILE, DB_FILE + "-wal"]) { try { n += fs.statSync(f).size; } catch { /* brak */ } }
  return Math.round(n / 1048576 * 10) / 10;
}

/** Zapisuje blok wpisów (JSON lines). Łańcuch: hash = SHA-256(poprzedni hash ‖ zaszyfrowany blok). */
export function logAppendBlock(meta, jsonl) {
  if (!logCrypt) unlockSync();
  const prev = logHead();
  const comp = zstd(jsonl);
  const inner = logCrypt.encrypt(comp, dbc.aad.logInner2(meta.firstSeq, meta.lastSeq, meta.count, prev, meta.tsFirst, meta.tsLast));
  const hash = createHash("sha256").update(Buffer.from(prev, "hex")).update(inner).digest("hex");
  const outer = crypt.encrypt(inner, dbc.aad.logOuter(meta.firstSeq));
  inTransaction(() => {
    sql("INSERT INTO logs (first_seq, last_seq, ts_first, ts_last, count, raw_bytes, comp_bytes, prev_hash, hash, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(meta.firstSeq, meta.lastSeq, meta.tsFirst, meta.tsLast, meta.count, jsonl.length, comp.length, prev, hash, outer);
    // uwierzytelniony stan głowy łańcucha — pozwala wykryć obcięcie końca i usunięcie całości
    const h0 = readLogHead();
    const tail = sql("SELECT max(last_seq) AS m FROM logs WHERE first_seq < ?").get(meta.firstSeq);
    const actualPrev = tail && tail.m != null ? Number(tail.m) : 0;
    const next = { ...(h0 && !h0.broken ? h0 : { pruned: 0, prunedUpTo: 0 }), lastSeq: meta.lastSeq, hash };
    // koniec łańcucha nie zgadza się z zapisanym stanem głowy = ktoś usunął najnowsze bloki; zapisujemy to trwale
    if (h0 && !h0.broken && ((h0.lastSeq || 0) !== actualPrev || (h0.hash || ZERO_HASH) !== prev) && !h0.anomaly) {
      next.anomaly = { at: Date.now(), oczekiwanoSeq: h0.lastSeq || 0, bylo: actualPrev };
    }
    putLogHead(next);
  });
  logHeadHash = hash;
}

function readLogHead() {
  const r = sql("SELECT value FROM meta WHERE key = 'loghead'").get();
  if (!r) return null;
  try { return JSON.parse(decJson(dbc.aad.meta("loghead"), r.value)); } catch { return { broken: true }; }
}
function putLogHead(h) {
  sql("INSERT OR REPLACE INTO meta (key, value) VALUES ('loghead', ?)").run(encJson(dbc.aad.meta("loghead"), JSON.stringify(h)));
}

function openLogBlock(row) {
  const inner = crypt.decrypt(row.data, dbc.aad.logOuter(row.first_seq));
  let comp, legacy = false;
  try {
    comp = logCrypt.decrypt(inner, dbc.aad.logInner2(row.first_seq, row.last_seq, row.count, row.prev_hash, row.ts_first, row.ts_last));
  } catch (e) {
    try { comp = logCrypt.decrypt(inner, dbc.aad.logInner(row.first_seq, row.last_seq, row.count, row.prev_hash)); legacy = true; } catch { throw e; }
  }
  return { inner, legacy, jsonl: zlib.zstdDecompressSync(comp).toString("utf8") };
}

/** Bloki dziennika po kolei (rosnąco albo malejąco): { meta, entries }. Uszkodzony blok → { meta, entries: [], error }. */
export function* logIterate({ reverse = false, minTs = 0 } = {}) {
  if (!logCrypt) unlockSync();
  const it = sql(`SELECT first_seq, last_seq, ts_first, ts_last, count, prev_hash, hash, data FROM logs WHERE ts_last >= ? ORDER BY first_seq ${reverse ? "DESC" : "ASC"}`).iterate(minTs);
  for (const row of it) {
    const meta = { firstSeq: Number(row.first_seq), lastSeq: Number(row.last_seq), tsFirst: Number(row.ts_first), tsLast: Number(row.ts_last), count: Number(row.count) };
    try {
      const { jsonl } = openLogBlock({ ...row, first_seq: meta.firstSeq, last_seq: meta.lastSeq, count: meta.count, ts_first: meta.tsFirst, ts_last: meta.tsLast });
      yield { meta, entries: jsonl ? jsonl.split("\n").map((l) => JSON.parse(l)) : [] };
    } catch (e) {
      yield { meta, entries: [], error: e.message };
    }
  }
}

export function logStats() {
  const r = sql("SELECT count(*) AS blocks, coalesce(sum(count), 0) AS entries, coalesce(sum(raw_bytes), 0) AS raw, coalesce(sum(comp_bytes), 0) AS comp, min(ts_first) AS t0, max(ts_last) AS t1, min(first_seq) AS s0, max(last_seq) AS s1 FROM logs").get();
  const stored = sql("SELECT coalesce(sum(length(data)), 0) AS n FROM logs").get().n;
  return {
    blocks: Number(r.blocks), entries: Number(r.entries), rawBytes: Number(r.raw), compressedBytes: Number(r.comp), storedBytes: Number(stored),
    firstTs: r.t0 == null ? null : Number(r.t0), lastTs: r.t1 == null ? null : Number(r.t1),
    firstSeq: r.s0 == null ? null : Number(r.s0), lastSeq: r.s1 == null ? null : Number(r.s1),
    headHash: logHead(), cipher: logCrypt?.cipher.label || null, zstdLevel: 3,
  };
}

/** Sprawdza całość: ciągłość numerów, łańcuch skrótów, uwierzytelnienie obu warstw szyfrowania, liczbę wpisów w blokach. */
export function logVerify() {
  if (!logCrypt) unlockSync();
  const problems = [];
  let blocks = 0, entries = 0, prevHash = null, prevLast = null, firstSeq = null, lastSeq = null, pruned = false;
  const add = (kind, seq, msg) => { if (problems.length < 25) problems.push({ kind, seq, msg }); };
  let legacyBlocks = 0;
  for (const row of sql("SELECT first_seq, last_seq, ts_first, ts_last, count, prev_hash, hash, data FROM logs ORDER BY first_seq ASC").iterate()) {
    const first = Number(row.first_seq), last = Number(row.last_seq), count = Number(row.count);
    blocks++;
    if (firstSeq == null) { firstSeq = first; pruned = row.prev_hash !== ZERO_HASH; }
    else {
      if (first !== prevLast + 1) add("luka", first, `brakuje wpisów ${prevLast + 1}–${first - 1} (usunięty blok?)`);
      if (row.prev_hash !== prevHash) add("lancuch", first, "łańcuch skrótów przerwany — blok usunięty, podmieniony albo dodany");
    }
    try {
      const { inner, jsonl, legacy } = openLogBlock({ ...row, first_seq: first, last_seq: last, count, ts_first: Number(row.ts_first), ts_last: Number(row.ts_last) });
      if (legacy) legacyBlocks++;
      const expect = createHash("sha256").update(Buffer.from(row.prev_hash, "hex")).update(inner).digest("hex");
      if (expect !== row.hash) add("skrot", first, "skrót bloku nie zgadza się z zawartością");
      const n = jsonl ? jsonl.split("\n").length : 0;
      if (n !== count) add("liczba", first, `blok deklaruje ${count} wpisów, ma ${n}`);
      entries += n;
    } catch (e) {
      add("odszyfrowanie", first, `blok nie przechodzi uwierzytelnienia/odszyfrowania: ${e.message}`);
    }
    prevHash = row.hash; prevLast = last; lastSeq = last;
  }
  // uwierzytelniona głowa: wykrywa obcięcie końca, usunięcie całości i usunięcie najstarszych bloków poza przycinaniem
  const head = readLogHead();
  if (head == null) { if (blocks > 0) { putLogHead({ lastSeq, hash: prevHash, pruned: 0, prunedUpTo: (firstSeq || 1) - 1 }); } }
  else if (head.anomaly) add("obciecie", head.anomaly.oczekiwanoSeq, `przy zapisie wykryto obcięcie dziennika (${new Date(head.anomaly.at).toISOString()}): oczekiwano końca na wpisie #${head.anomaly.oczekiwanoSeq}, był #${head.anomaly.bylo}`);
  else if (head.broken) add("glowa", null, "uwierzytelniony stan głowy dziennika jest uszkodzony albo podmieniony");
  else {
    if ((head.lastSeq || 0) !== (lastSeq || 0) || (head.hash || ZERO_HASH) !== (prevHash || ZERO_HASH)) {
      add("obciecie", head.lastSeq, `koniec dziennika różni się od zapisanego stanu (oczekiwano wpisu #${head.lastSeq}, jest #${lastSeq ?? 0}) — usunięto lub podmieniono najnowsze bloki`);
    }
    if (blocks > 0 && firstSeq !== (head.prunedUpTo || 0) + 1) add("poczatek", firstSeq, `początek dziennika (#${firstSeq}) nie zgadza się z zapisanym przycięciem (#${(head.prunedUpTo || 0) + 1}) — usunięto najstarsze bloki poza przycinaniem`);
  }
  return { ok: problems.length === 0, blocks, entries, firstSeq, lastSeq, prunedPrefix: pruned, prunedBlocks: head?.pruned || 0, legacyBlocks, problems, headHash: prevHash || ZERO_HASH };
}

/** Przycinanie najstarszych bloków (limit rozmiaru / wieku). Najnowszy blok zostaje zawsze. */
export function logPrune({ maxBytes, olderThanTs }) {
  let removed = 0, lastRemovedSeq = 0, firstRemovedSeq = null, tsFrom = null, tsTo = null;
  for (;;) {
    const total = Number(sql("SELECT coalesce(sum(length(data)), 0) AS n FROM logs").get().n);
    const old = sql("SELECT first_seq, last_seq, ts_first, ts_last FROM logs ORDER BY first_seq ASC LIMIT 2").all();
    if (old.length < 2) break;
    if (total <= maxBytes && Number(old[0].ts_last) >= olderThanTs) break;
    sql("DELETE FROM logs WHERE first_seq = ?").run(old[0].first_seq);
    removed++;
    if (firstRemovedSeq == null) { firstRemovedSeq = Number(old[0].first_seq); tsFrom = Number(old[0].ts_first); }
    lastRemovedSeq = Number(old[0].last_seq); tsTo = Number(old[0].ts_last);
  }
  if (removed) {
    const h = readLogHead() || { lastSeq: 0, hash: ZERO_HASH, pruned: 0, prunedUpTo: 0 };
    putLogHead({ ...h, pruned: (h.pruned || 0) + removed, prunedUpTo: lastRemovedSeq });
  }
  return { removed, firstSeq: firstRemovedSeq, lastSeq: lastRemovedSeq, tsFrom, tsTo };
}

// --- zarządzanie szyfrowaniem (panel) ---
const TABLES_WITH_DATA = [
  { t: "meta", k: "key", aad: (k) => dbc.aad.meta(k) },
  { t: "items", k: "id", aad: (k) => dbc.aad.item(k) },
  { t: "subscribers", k: "ref", aad: (k) => dbc.aad.subscriber(k) },
  { t: "files", k: "path", aad: (k) => dbc.aad.file(k) },
  { t: "logs", k: "first_seq", aad: (k) => dbc.aad.logOuter(k) },
];

/** Przepisuje wszystkie wartości na szyfr docelowy (tylko te, które mają inny). Zwraca liczbę przepisanych. */
function reencryptAll(targetId) {
  let n = 0;
  inTransaction(() => {
    for (const { t, k, aad } of TABLES_WITH_DATA) {
      const col = t === "meta" ? "value" : "data";
      for (const r of sql(`SELECT ${k} AS k, ${col} AS v FROM ${t}`).all()) {
        if (dbc.Crypt.cipherIdOf(r.v) === targetId) continue;
        const plain = crypt.decrypt(r.v, aad(r.k));
        sql(`UPDATE ${t} SET ${col} = ? WHERE ${k} = ?`).run(crypt.encrypt(plain, aad(r.k), targetId), r.k);
        n++;
      }
    }
    for (const m of sql("SELECT name, size, chunks FROM media").all()) {
      for (const r of sql("SELECT idx, data FROM media_chunks WHERE name = ?").all(m.name)) {
        if (dbc.Crypt.cipherIdOf(r.data) === targetId) continue;
        const a = dbc.aad.chunk(m.name, r.idx, Number(m.chunks), Number(m.size));
        sql("UPDATE media_chunks SET data = ? WHERE name = ? AND idx = ?").run(crypt.encrypt(crypt.decrypt(r.data, a), a, targetId), m.name, r.idx);
        n++;
      }
    }
  });
  lastChunk = null;
  return n;
}

/** Wybór szyfru: „auto” albo nazwa (np. „chacha20-poly1305”). Przepisuje całą bazę na nowy szyfr. */
export function setCipher(pref) {
  if (!crypt) unlockSync();
  if (pref !== "auto" && !dbc.cipherByName(pref)) throw new Error("nieznany szyfr");
  if (pref === "none" && settings.keyMode === "passphrase") throw new Error("W trybie klucza z hasła nie można wyłączyć szyfrowania");
  const prevPref = settings.cipher, prevId = crypt.cipherId, prevNone = crypt.allowNone;
  try {
    settings.cipher = pref;
    if (pref === "auto") settings.autoCache = null;
    const id = resolveCipherId(pref);
    crypt.allowNone = true; // odczyt starych wartości (także jawnych) na czas przepisywania
    crypt.setCipher(id);
    const rewritten = reencryptAll(id);
    countsCache = null;
    crypt.allowNone = pref === "none";
    dbc.writeSettings(DATA_DIR, settings);
    try { db.exec("PRAGMA wal_checkpoint(TRUNCATE)"); } catch { /* ignore */ }
    console.log(`[szyfrowanie] zmieniono szyfr na ${crypt.cipher.label} (przepisano wartości: ${rewritten})`);
    return { ok: true, active: crypt.cipher.name, rewritten };
  } catch (e) {
    settings.cipher = prevPref; crypt.setCipher(prevId); crypt.allowNone = prevNone;
    throw e;
  }
}

/**
 * Zmiana klucza GŁÓWNEGO: losujemy nowy klucz i przepisujemy całą bazę (wartości, kawałki plików, subskrybentów,
 * dziennik z nowym łańcuchem skrótów) w jednej transakcji. Dzięki temu stary klucz (np. kopia pliku klucza) przestaje
 * otwierać bazę. Dziennik: przed przepisaniem sprawdzamy integralność, żeby rotacja nie „wyprała” śladu ingerencji.
 */
function rotateMaster(newMaster) {
  const oldCrypt = crypt, oldLog = logCrypt;
  const prevAllow = oldCrypt.allowNone;
  oldCrypt.allowNone = true;
  const newCrypt = new dbc.Crypt(newMaster, oldCrypt.cipherId, { allowNone: prevAllow });
  const newLog = new dbc.Crypt(dbc.deriveMaster(newMaster, "log"), oldLog.cipherId);
  let lastHash = null;
  try {
    const verdict = logVerify();
    inTransaction(() => {
      const head = readLogHead();
      // dane z tabel „zwykłych”
      for (const { t, k, aad } of TABLES_WITH_DATA.filter((x) => x.t !== "logs" && x.t !== "subscribers")) {
        const col = t === "meta" ? "value" : "data";
        for (const r of sql(`SELECT ${k} AS k, ${col} AS v FROM ${t}`).all()) {
          sql(`UPDATE ${t} SET ${col} = ? WHERE ${k} = ?`).run(newCrypt.encrypt(oldCrypt.decrypt(r.v, aad(r.k)), aad(r.k)), r.k);
        }
      }
      // subskrybenci: klucz wiersza (HMAC adresu) zależy od klucza głównego
      const subs = sql("SELECT ref, data FROM subscribers").all().map((r) => JSON.parse(oldCrypt.decrypt(r.data, dbc.aad.subscriber(r.ref)).toString("utf8")));
      sql("DELETE FROM subscribers").run();
      for (const o of subs) {
        const ref = newCrypt.ref(o.endpoint);
        sql("INSERT INTO subscribers (ref, data) VALUES (?, ?)").run(ref, newCrypt.encrypt(Buffer.from(JSON.stringify(o), "utf8"), dbc.aad.subscriber(ref)));
      }
      // multimedia
      for (const m of sql("SELECT name, size, chunks FROM media").all()) {
        for (const r of sql("SELECT idx, data FROM media_chunks WHERE name = ?").all(m.name)) {
          const a2 = dbc.aad.chunk(m.name, r.idx, Number(m.chunks), Number(m.size));
          sql("UPDATE media_chunks SET data = ? WHERE name = ? AND idx = ?").run(newCrypt.encrypt(oldCrypt.decrypt(r.data, a2), a2), m.name, r.idx);
        }
      }
      // dziennik: nowy klucz wewnętrzny i nowy łańcuch skrótów
      let prev = null;
      for (const row of sql("SELECT first_seq, last_seq, ts_first, ts_last, count, prev_hash, data FROM logs ORDER BY first_seq ASC").all()) {
        const inner = oldCrypt.decrypt(row.data, dbc.aad.logOuter(row.first_seq));
        let comp;
        try { comp = oldLog.decrypt(inner, dbc.aad.logInner2(row.first_seq, row.last_seq, row.count, row.prev_hash, row.ts_first, row.ts_last)); }
        catch { comp = oldLog.decrypt(inner, dbc.aad.logInner(row.first_seq, row.last_seq, row.count, row.prev_hash)); }
        const prevHash = prev == null ? row.prev_hash : prev;
        const ni = newLog.encrypt(comp, dbc.aad.logInner2(row.first_seq, row.last_seq, row.count, prevHash, row.ts_first, row.ts_last));
        const hash = createHash("sha256").update(Buffer.from(prevHash, "hex")).update(ni).digest("hex");
        sql("UPDATE logs SET prev_hash = ?, hash = ?, data = ? WHERE first_seq = ?").run(prevHash, hash, newCrypt.encrypt(ni, dbc.aad.logOuter(row.first_seq)), row.first_seq);
        prev = hash;
      }
      lastHash = prev;
      crypt = newCrypt; logCrypt = newLog; // od tej chwili zapisy (głowa dziennika) idą nowym kluczem
      if (head && !head.broken) {
        const next = { ...head, hash: lastHash || head.hash };
        if (!verdict.ok && !next.anomaly) next.anomaly = { at: Date.now(), oczekiwanoSeq: head.lastSeq || 0, bylo: verdict.lastSeq ?? 0, uwaga: "wykryte przed zmianą klucza" };
        putLogHead(next);
      }
    });
  } catch (e) {
    crypt = oldCrypt; logCrypt = oldLog; oldCrypt.allowNone = prevAllow;
    throw e;
  }
  newCrypt.allowNone = prevAllow;
  countsCache = null;
  logHeadHash = lastHash || logHeadHash;
  lastChunk = null;
  try { db.exec("PRAGMA wal_checkpoint(TRUNCATE)"); } catch { /* ignore */ }
}

/** Tryb klucza: hasło (klucz główny zaszyfrowany scryptem, brak pliku klucza) albo plik klucza obok danych. */
export function setKeyMode(mode, passphrase) {
  if (!crypt) unlockSync();
  if (process.env.DB_KEY) throw new Error("Klucz jest podany zmienną DB_KEY — zmień go tam.");
  if (mode !== "passphrase" && mode !== "file") throw new Error("nieznany tryb klucza");
  if (mode === "passphrase" && (typeof passphrase !== "string" || passphrase.length < 12)) throw new Error("Hasło do bazy: min. 12 znaków");
  const newMaster = randomBytes(32);
  // nowy klucz zapisujemy na dysk PRZED przepisaniem bazy (pod nazwą tymczasową) — awaria w trakcie nie zostawi bazy bez klucza
  if (mode === "passphrase") dbc.writeWrappedFile(DATA_DIR, dbc.wrapKey(newMaster, passphrase), ".nowy");
  else dbc.writeKeyFile(dbc.keyFilePath(DATA_DIR) + ".nowy", newMaster);
  try { rotateMaster(newMaster); }
  catch (e) { dbc.shredFile(dbc.wrappedFilePath(DATA_DIR) + ".nowy"); dbc.shredFile(dbc.keyFilePath(DATA_DIR) + ".nowy"); throw e; }
  // baza jest już na nowym kluczu — wprowadzamy go na stałe i niszczymy stary
  if (mode === "passphrase") {
    const w = dbc.readWrappedFile(DATA_DIR, ".nowy");
    dbc.writeWrappedFile(DATA_DIR, w);
    dbc.shredFile(dbc.wrappedFilePath(DATA_DIR) + ".nowy");
    settings.wrapped = w;
    settings.keyMode = "passphrase";
    if (settings.cipher === "none") { settings.cipher = "auto"; setCipherAfterRotate(); }
    dbc.writeSettings(DATA_DIR, settings);
    dbc.removeKeyFile(DATA_DIR);
  } else {
    fs.renameSync(dbc.keyFilePath(DATA_DIR) + ".nowy", dbc.keyFilePath(DATA_DIR));
    dbc.shredFile(dbc.wrappedFilePath(DATA_DIR));
    settings.keyMode = "file";
    settings.wrapped = null;
    dbc.writeSettings(DATA_DIR, settings);
  }
  keyInfo = { via: mode === "passphrase" ? "hasło (scrypt)" : "plik klucza", created: false };
  console.log(`[szyfrowanie] zmieniono klucz główny (nowy, wylosowany) — tryb: ${mode === "passphrase" ? "hasło" : "plik klucza"}; stary klucz nie otwiera już bazy`);
  return { ok: true, keyMode: settings.keyMode, rotated: true };
}
function setCipherAfterRotate() { try { reencryptAll(resolveCipherId("auto")); crypt.setCipher(resolveCipherId("auto")); } catch { /* zostaje poprzedni */ } }

/** Krótki opis szyfrowania (bez pomiarów) — do dziennika. */
export function cryptoBrief() {
  return {
    dbCipher: crypt?.cipher.label, dbCipherPreference: settings?.cipher, keyMode: settings?.keyMode, keySource: keyInfo.via,
    logCipher: logCrypt?.cipher.label, logCompression: "ZSTD-3", cpu: cpuCached().model, cpuFeatures: cpuCached().features,
  };
}

let benchCache = null;
let countsCache = null;
/** Stan szyfrowania do panelu: CPU, lista szyfrów (od najlepszego) z pomiarem, aktywny szyfr, rozkład wartości. */
export function cryptoStatus({ fresh = false } = {}) {
  if (!crypt) unlockSync();
  const cpu = cpuCached();
  if (fresh || !benchCache || Date.now() - benchCache.at > 10 * 60_000) {
    benchCache = { at: Date.now(), mbps: Object.fromEntries(dbc.CIPHERS.map((c) => [c.id, dbc.benchmark(c.id)])) };
  }
  let counts = countsCache && !fresh && Date.now() - countsCache.at < 300_000 ? countsCache.counts : null;
  if (!counts) {
  counts = {};
  for (const { t } of TABLES_WITH_DATA) {
    const col = t === "meta" ? "value" : "data";
    for (const r of sql(`SELECT hex(substr(${col}, 2, 1)) AS h, count(*) AS c FROM ${t} GROUP BY h`).all()) counts[parseInt(r.h, 16)] = (counts[parseInt(r.h, 16)] || 0) + Number(r.c);
  }
  for (const r of sql("SELECT hex(substr(data, 2, 1)) AS h, count(*) AS c FROM media_chunks GROUP BY h").all()) counts[parseInt(r.h, 16)] = (counts[parseInt(r.h, 16)] || 0) + Number(r.c);
  countsCache = { at: Date.now(), counts };
  }
  const auto = benchCache.auto || (benchCache.auto = dbc.chooseAuto(cpu));
  return {
    cpu: { model: cpu.model, arch: cpu.arch, platform: cpu.platform, cores: cpu.cores, features: cpu.features, source: cpu.source, known: cpu.known },
    preference: settings.cipher,
    active: { id: crypt.cipherId, name: crypt.cipher.name, label: crypt.cipher.label },
    autoWouldChoose: dbc.cipherById(auto.id).name,
    autoTrace: auto.trace.map((t) => ({ ...t, label: dbc.cipherById(t.id).label })),
    ciphers: dbc.CIPHERS.map((c) => ({
      id: c.id, name: c.name, label: c.label, hwText: c.hwText, note: c.note, software: !!c.soft,
      accelerated: dbc.accelerated(c, cpu), supported: dbc.selfTest(c.id), mbps: benchMbps(c.id), rows: counts[c.id] || 0,
    })),
    keyMode: settings.keyMode,
    keySource: keyInfo.via,
    keyFile: settings.keyMode === "file" && !process.env.DB_KEY ? dbc.keyFilePath(DATA_DIR) : null,
    keyFromEnv: !!process.env.DB_KEY,
  };
}
const benchMbps = (id) => benchCache?.mbps?.[id] ?? null;

// --- hasło administratora (scrypt, asynchronicznie) ---
export async function setPassword(data, plain) {
  const salt = randomBytes(16);
  const hash = await scryptAsync(String(plain), salt, 32);
  data.adminPasswordHash = `scrypt$${salt.toString("hex")}$${hash.toString("hex")}`;
}

export async function verifyPassword(data, plain) {
  const stored = data.adminPasswordHash;
  if (!stored) return false;
  const [, saltHex, hashHex] = stored.split("$");
  if (!saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, "hex");
  const actual = await scryptAsync(String(plain), Buffer.from(saltHex, "hex"), expected.length);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

// --- walidacja / sanityzacja ---
const str = (v, max) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const opt = (v, max) => {
  const s = str(v, max);
  return s.length ? s : null;
};
// link do aplikacji dla artykułów/reklam/konkursów/foreign musi być HTTPS; inaczej apka go odrzuci.
// I-11: zapisujemy postać znormalizowaną (new URL) i pilnujemy limitu apki.
const httpsUrl = (v) => {
  const s = typeof v === "string" ? v.trim() : "";
  if (!s || s.length > MAX_URL) return null;
  try {
    const u = new URL(s);
    const out = u.toString();
    return u.protocol === "https:" && !u.username && !u.password && out.length <= MAX_URL ? out : null;
  } catch {
    return null;
  }
};
const whenMs = (v) => (Number.isFinite(+v) && +v > 0 ? +v : Date.now());

export function normalizeConfig(input, current) {
  const c = { ...current };
  if (input.serverName !== undefined) c.serverName = str(input.serverName, MAX_NAME) || current.serverName;
  if (input.description !== undefined) c.description = str(input.description, 2000);
  if (input.termsText !== undefined) c.termsText = str(input.termsText, MAX_TERMS) || current.termsText;
  if (input.canonicalHttpsBase !== undefined) c.canonicalHttpsBase = input.canonicalHttpsBase || null;
  if (input.termsVersion !== undefined) c.termsVersion = str(input.termsVersion, 64) || "1";
  if (input.domain !== undefined) {
    c.domain = str(input.domain, 253).toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  }
  if (input.email !== undefined) c.email = str(input.email, 254);
  if (input.decoyPerDay !== undefined) {
    const n = Math.trunc(Number(input.decoyPerDay));
    c.push = { ...c.push, decoyPerDay: Number.isFinite(n) ? Math.min(MAX_DECOY_PER_DAY, Math.max(0, n)) : 0 };
  }
  if (input.realJitterSec !== undefined) {
    const n = Math.trunc(Number(input.realJitterSec));
    c.push = { ...c.push, realJitterSec: Number.isFinite(n) ? Math.min(MAX_JITTER_SEC, Math.max(0, n)) : 0 };
  }
  if (input.autoNotify !== undefined) c.autoNotify = input.autoNotify === true;
  if (input.linkPlatformsText !== undefined) c.linkPlatforms = parseLinkPlatformsText(input.linkPlatformsText);
  return c;
}

/**
 * Ręczne platformy linków z pola tekstowego panelu — linia na platformę: `id | Nazwa | host1, host2`.
 * Apka dopasowuje link do platformy po hoście i otwiera go wg wyboru użytkownika (jak YouTube).
 */
export function parseLinkPlatformsText(text) {
  const out = [];
  const seen = new Set();
  for (const line of String(text || "").split(/\r?\n/)) {
    const [rawId, rawName, rawHosts] = line.split("|").map((x) => (x || "").trim());
    const pid = (rawId || "").toLowerCase().replace(/[^a-z0-9_-]/g, "").slice(0, 64);
    if (!pid || seen.has(pid)) continue;
    const hosts = (rawHosts || "").split(/[,\s]+/).map((h) => h.toLowerCase().replace(/^https?:\/\//, "").replace(/[/:].*$/, "").replace(/^www\./, ""))
      .filter((h) => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(h)).slice(0, 20);
    out.push({ id: pid, name: (rawName || pid).slice(0, 200), hosts });
    seen.add(pid);
    if (out.length >= MAX_LINK_PLATFORMS) break;
  }
  return out;
}

/** Czy wpis jest już opublikowany (zaplanowane — z datą w przyszłości — czekają ukryte). */
export function isVisible(item, now = Date.now()) {
  return !item.publishedAt || item.publishedAt <= now;
}

const port = (v) => {
  const n = Math.trunc(Number(v));
  return Number.isFinite(n) && n >= 1 && n <= 65535 ? n : null;
};

export function normalizeNetwork(input, current) {
  const n = { ...current };
  if (input.httpPort !== undefined) n.httpPort = input.httpPort === null || input.httpPort === "" ? null : port(input.httpPort);
  if (input.httpsPort !== undefined) n.httpsPort = input.httpsPort === null || input.httpsPort === "" ? null : port(input.httpsPort);
  if (input.torEnabled !== undefined) n.torEnabled = input.torEnabled === true;
  if (input.torVirtualPort !== undefined) n.torVirtualPort = port(input.torVirtualPort) || 2137;
  if (input.bindLocalOnly !== undefined) n.bindLocalOnly = input.bindLocalOnly === true;
  return n;
}

// --- treść: jeden ogólny item z polem `type` ---
export function findItem(data, itemId) {
  return data.items.find((it) => it.id === itemId) || null;
}

/** Buduje/aktualizuje pola itemu wg typu. Zwraca { ok, error } albo { ok:true }. */
function applyItemFields(item, input) {
  item.type = ITEM_TYPES.includes(input.type) ? input.type : item.type;
  item.publishedAt = input.publishedAt !== undefined ? whenMs(input.publishedAt) : item.publishedAt;
  item.title = opt(input.title, MAX_TITLE);
  item.text = opt(input.text, MAX_TEXT);
  item.author = opt(input.author, MAX_NAME);
  item.source = opt(input.source, MAX_NAME);
  item.platform = opt(input.platform, MAX_NAME);
  item.foreignType = opt(input.foreignType, MAX_NAME);
  item.articleKind = input.articleKind === "newsletter" ? "newsletter" : "article";
  item.postType = opt(input.postType, 64);
  if (input.audioTitle !== undefined) item.audioTitle = opt(input.audioTitle, MAX_TITLE);
  if (input.videoTitle !== undefined) item.videoTitle = opt(input.videoTitle, MAX_TITLE);
  item.name = opt(input.name, MAX_NAME);
  item.thirdParty = input.thirdParty === true;
  if (input.jxlQuality !== undefined) {
    const q = Math.trunc(Number(input.jxlQuality));
    item.jxlQuality = Number.isFinite(q) && q >= 1 && q <= 100 ? q : null;
  }
  if (input.url !== undefined) {
    const raw = typeof input.url === "string" ? input.url.trim() : "";
    if (raw) {
      const u = httpsUrl(raw);
      if (!u) return { ok: false, error: `Link musi zaczynać się od https:// i mieć najwyżej ${MAX_URL} znaków` };
      item.url = u;
    } else {
      item.url = null;
    }
  }
  if (input.channelUrl !== undefined) item.channelUrl = httpsUrl(input.channelUrl || "");
  // walidacja minimalnych wymagań per typ
  switch (item.type) {
    case "post":
      if (!item.author || !item.text) return { ok: false, error: "Post wymaga autora i treści" };
      break;
    case "meme":
      // obraz jest wymagany, ale dochodzi osobnym uploadem — sprawdzamy przy zapisie w serwerze
      break;
    case "article":
      if (!item.title || !item.source) return { ok: false, error: "Artykuł wymaga tytułu i źródła" };
      if (item.articleKind === "article" && !httpsUrl(item.url || "")) {
        return { ok: false, error: "Artykuł wymaga linku HTTPS (newsletter może być bez linku)" };
      }
      break;
    case "foreign":
      if (!item.platform) return { ok: false, error: "Pozycja z innej platformy wymaga nazwy platformy" };
      if (!item.title && !item.text && !httpsUrl(item.url || "")) {
        return { ok: false, error: "Podaj tytuł, treść albo link (HTTPS)" };
      }
      break;
    case "ad":
    case "contest":
      if (!item.title) return { ok: false, error: "Podaj tytuł" };
      if (!httpsUrl(item.url || "")) return { ok: false, error: "Podaj link HTTPS" };
      break;
    case "creator":
      if (!item.name) return { ok: false, error: "Twórca wymaga nazwy" };
      break;
  }
  return { ok: true };
}

export function createItem(data, input) {
  const now = Date.now();
  const item = { id: id(), rev: 1, revAt: now, images: [], update: null, updateAt: null, createdAt: now, updatedAt: now, publishedAt: now };
  const r = applyItemFields(item, input);
  if (!r.ok) return r;
  // I-01: apka powiadamia WYŁĄCZNIE o pozycjach z update: significant — nowy wpis bez tego trafi do zakładki
  // po cichu. Domyślnie powiadamiamy (operator może odznaczyć); reklamy i twórcy nigdy nie powiadamiają.
  if (input.notify !== false && item.type !== "ad" && item.type !== "creator") {
    item.update = "significant";
    item.updateAt = now;
  }
  // zaplanowany (data publikacji w przyszłości): budzik pójdzie o czasie publikacji
  item.pendingWake = !isVisible(item, now) && item.update === "significant";
  data.items.push(item);
  return { ok: true, item };
}

/**
 * opts.linkOf(item) — stały link wpisu (własny https albo /e/<id>) albo null; służy S-02 (niżej).
 */
export function updateItem(data, input, opts = {}) {
  const item = findItem(data, input.id);
  if (!item) return { ok: false, error: "Brak takiego wpisu" };
  const previousUrl = item.url || null;
  const linkBefore = opts.linkOf ? opts.linkOf(item) : null;
  const wasFreshSignificant = item.update === "significant" &&
    Date.now() - Math.max(item.updateAt || item.updatedAt || item.createdAt || 0, item.publishedAt || 0) <= NOTIFY_WINDOW_MS;
  const r = applyItemFields(item, input);
  if (!r.ok) return r;
  item.updatedAt = Date.now();
  bumpRev(item);
  // protokół: ta sama pozycja wysłana ponownie z `update` — istotna (może powiadomić) albo drobna (cicho).
  // Apka powiadamia raz na link wpisu, więc ponowne „istotne" działa tylko dla wpisu, o którym jeszcze nie było.
  const linkAfter = opts.linkOf ? opts.linkOf(item) : null;
  if (input.significant === true) { item.update = "significant"; item.updateAt = item.updatedAt; }
  else if (wasFreshSignificant && linkBefore && linkBefore === linkAfter) {
    // S-02: drobna poprawka świeżego, istotnego wpisu (np. literówka 5 min po dodaniu) NIE zdejmuje
    // `significant` — inaczej urządzenia, które jeszcze go nie pobrały (offline, tryb oszczędny, rozmyte
    // budziki), nigdy nie dostałyby powiadomienia. Apka powiadamia raz na link, więc nie będzie dubli.
    // Okno 48 h liczy się dalej od pierwotnego oznaczenia (updateAt bez zmian). Wpis BEZ stałego linku
    // (serwer tylko .onion) apka rozpoznaje po treści — tam zmieniony tekst dałby drugie powiadomienie,
    // więc zostaje dawne zachowanie (minor).
  } else { item.update = "minor"; item.updateAt = item.updatedAt; }
  item.pendingWake = !isVisible(item) && item.update === "significant";
  return { ok: true, item, previousUrl };
}

export function deleteItem(data, itemId) {
  const item = findItem(data, itemId);
  if (!item) return { ok: false, error: "Brak takiego wpisu" };
  data.items = data.items.filter((x) => x.id !== itemId);
  return { ok: true, item };
}

/** Zapamiętuje link usuniętej/przeniesionej pozycji — trafi do `deletions` w manifeście. */
export function addDeletion(data, url) {
  if (!url) return;
  data.deletions = data.deletions.filter((d) => d.url !== url);
  data.deletions.push({ url, at: Date.now() });
  if (data.deletions.length > MAX_DELETIONS) data.deletions.splice(0, data.deletions.length - MAX_DELETIONS);
}
/** Link wrócił do użytku (np. operator przywrócił wpis z tym samym adresem) — nie kasuj go w aplikacji. */
export function dropDeletion(data, url) {
  if (url) data.deletions = data.deletions.filter((d) => d.url !== url);
}

// --- subskrybenci push (UnifiedPush endpoint + klucz publiczny E2E) ---
/** Zwraca true, gdy coś się zmieniło (I-08: ponowna rejestracja tego samego adresu nie przepisuje pliku). */
export function addSubscriber(data, endpoint, pubkey) {
  const prev = data.push.subscribers[endpoint];
  const now = Date.now();
  if (prev && prev.pubkey === (pubkey || null)) {
    prev.seenAt = now; // żywy — apka rejestruje się przy każdej synchronizacji
    return false;
  }
  data.push.subscribers[endpoint] = { pubkey: pubkey || null, at: now, seenAt: now };
  return true;
}
export function removeSubscriber(data, endpoint) {
  delete data.push.subscribers[endpoint];
}
export function listSubscribers(data) {
  return Object.entries(data.push.subscribers).map(([endpoint, v]) => ({ endpoint, ...v }));
}

export { httpsUrl, str };
