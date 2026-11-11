// Push przez UnifiedPush — BEZ Google. Apka rejestruje swój ulotny adres dostarczenia (endpoint) + klucz
// publiczny E2E (P-256). Gdy pojawi się nowa treść, serwer szyfruje malutki budzik osobno dla każdego
// subskrybenta (ECIES, e2e.js) i dostarcza go:
//   - wbudowany dystrybutor aplikacji (LEP, endpoint ".../lep/pub/<topic>") — LOKALNIE, prosto do kolejki
//     lep.js, bez HTTP do samego siebie (to by nie zadziałało przez .onion ani bez hairpin-NAT);
//   - zewnętrzny dystrybutor (np. ntfy) — POST na jego publiczny adres https (port 443).
// Pośrednik widzi tylko szum i nieprzezroczysty adres — nie zna tożsamości ani treści.

import net from "node:net";
import dns from "node:dns";
import https from "node:https";
import { encryptFor, isValidPublicKey } from "./e2e.js";
import { publishLocal, lepTopicOf, dropTopic } from "./lep.js";
import * as logger from "./logger.js";
import * as store from "./store.js";

const MAX_SUBSCRIBERS = 50_000;
const MAX_PER_EXTERNAL_HOST = 5_000; // I-07: anonim nie zrobi z serwera wzmacniacza 50 tys. POST-ów na jeden host
const SEND_CONCURRENCY = 32; // tyle POST-ów naraz — 50 tys. równoległych gniazd zabiłoby serwer
const SEND_TIMEOUT_MS = 10_000;
const LEP_IDLE_PRUNE_MS = 7 * 24 * 60 * 60 * 1000; // I-08: temat nieodpytywany tydzień = apka odinstalowana
// limity rozmiaru jednego budzika: kolejka LEP przyjmuje 16 KB, zewnętrzne dystrybutory (ntfy) ~4 KB.
// Gdy miniatura (img) nie mieści się w limicie, budzik idzie bez niej (powiadomienie zostaje tekstowe).
const MAX_BLOB_LEP = 16 * 1024;
const MAX_BLOB_EXTERNAL = 4000;
export const MAX_WAKE_IMG_BYTES = 6000; // surowy plik miniatury: po base64 + E2E + base64 mieści się w 16 KB

// --- walidacja adresu dostarczenia ---

/** Adresy, na które serwer nigdy nie wysyła (sieć lokalna, loopback, link-local, CGNAT, NAT64, multicast…). */
export function isBlockedIp(ip) {
  const h = String(ip).replace(/^\[|\]$/g, "").toLowerCase();
  const v = net.isIP(h);
  if (v === 4) {
    const [a, b] = h.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19)) || a >= 224;
  }
  if (v === 6) {
    if (h === "::1" || h === "::") return true;
    if (h.startsWith("::ffff:")) return isBlockedIp(h.slice(7)) || !net.isIPv4(h.slice(7)); // IPv4 w IPv6
    // fc00::/7 (ULA), fe80::/10 (link-local), ff00::/8 (multicast), 64:ff9b::/96 i 64:ff9b:1::/48 (NAT64),
    // 2002::/16 (6to4 — osadza dowolny IPv4), 100::/64 (discard)
    if (/^::[0-9.]+$/.test(h)) return true; // ::a.b.c.d (zgodny z IPv4, zdeprecjonowany)
    return /^f[cd]/.test(h) || /^fe[89abcdef]/.test(h) || h.startsWith("ff") || h.startsWith("64:ff9b:") ||
      h.startsWith("2002:") || h.startsWith("100::");
  }
  return true; // nie-IP traktujemy jak zablokowany
}

/**
 * Zwraca { kind:"lep", topic, endpoint } dla wbudowanego dystrybutora, { kind:"http", endpoint, host } dla
 * zewnętrznego albo null. Zewnętrzny musi być publicznym https na porcie 443 — inaczej każdy mógłby kazać
 * serwerowi słać POST-y do sieci lokalnej operatora (SSRF: router, panel na 127.0.0.1, inne usługi).
 * Nazwy DNS sprawdzamy dodatkowo przy rejestracji ORAZ przy każdym połączeniu (safeLookup).
 */
export function classifyEndpoint(raw) {
  let url;
  try { url = new URL(String(raw)); } catch { return null; }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  if (url.username || url.password) return null;
  const topic = lepTopicOf(url.pathname);
  // LEP: host nieistotny (apka mogła nas znać jako .onion, domenę, IP z LAN albo 10.0.2.2 w emulatorze) —
  // i tak NIGDY nie robimy na niego żądania, tylko wrzucamy budzik do własnej kolejki po temacie.
  if (topic) return { kind: "lep", topic, endpoint: url.toString() };
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (url.protocol !== "https:" || (url.port && url.port !== "443")) return null;
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".onion") ||
      host.endsWith(".internal") || host.endsWith(".lan") || host.endsWith(".home.arpa")) return null;
  if (net.isIP(host) && isBlockedIp(host)) return null;
  if (!net.isIP(host) && !host.includes(".")) return null; // goła nazwa = sieć lokalna
  return { kind: "http", endpoint: url.toString(), host };
}

/** dns.lookup, który odrzuca adresy prywatne — także przy samym połączeniu (bez luki „DNS rebinding”). */
function safeLookup(hostname, options, cb) {
  dns.lookup(hostname, { ...options, all: true }, (err, addrs) => {
    if (err) return cb(err);
    const list = Array.isArray(addrs) ? addrs : [{ address: addrs, family: options.family || 4 }];
    if (!list.length || list.some((a) => isBlockedIp(a.address))) {
      return cb(Object.assign(new Error("adres prywatny — odmowa"), { code: "EBLOCKED" }));
    }
    if (options.all) return cb(null, list);
    cb(null, list[0].address, list[0].family);
  });
}

async function resolvesPublic(host) {
  if (net.isIP(host)) return !isBlockedIp(host);
  try {
    const addrs = await dns.promises.lookup(host, { all: true });
    return addrs.length > 0 && !addrs.some((a) => isBlockedIp(a.address));
  } catch {
    return false;
  }
}

// I-08: limit tempa rejestracji (kubełek żetonów). Legalna apka rejestruje się przy synchronizacji,
// więc limit jest hojny dla ludzi, ale przycina skrypt zalewający serwer tysiącami rejestracji.
const REG_RATE_PER_SEC = 20;
const REG_BURST = 200;
let regTokens = REG_BURST;
let regLast = Date.now();
function takeRegToken() {
  const now = Date.now();
  regTokens = Math.min(REG_BURST, regTokens + ((now - regLast) / 1000) * REG_RATE_PER_SEC);
  regLast = now;
  if (regTokens < 1) return false;
  regTokens -= 1;
  return true;
}

/**
 * POST /push/register — body { endpoint, pubkey? }. token1 (FCM) świadomie ignorujemy: serwer jest prywatny.
 * pubkey opcjonalny (protokół): bez niego wysyłamy jawny, mały budzik {"t":"1"} (I-09).
 */
export async function register(data, body) {
  if (!takeRegToken()) return { ok: false, code: 429, error: "Za dużo rejestracji — spróbuj za chwilę" };
  const target = classifyEndpoint(body?.endpoint);
  if (!target) return { ok: false, code: 400, error: "Brak/niepoprawny endpoint (wymagany publiczny https:443 albo wbudowany LEP)" };
  const pubkey = body?.pubkey == null || body.pubkey === "" ? null : String(body.pubkey);
  if (pubkey && !isValidPublicKey(pubkey)) return { ok: false, code: 400, error: "Niepoprawny klucz publiczny" };
  const exists = !!data.push.subscribers[target.endpoint];
  if (!exists) {
    if (Object.keys(data.push.subscribers).length >= MAX_SUBSCRIBERS) return { ok: false, code: 507, error: "Limit subskrybentów" };
    if (target.kind === "http") {
      if (!(await resolvesPublic(target.host))) return { ok: false, code: 400, error: "Adres dystrybutora wskazuje sieć prywatną" };
      const sameHost = store.listSubscribers(data).filter((s) => classifyEndpoint(s.endpoint)?.host === target.host).length;
      if (sameHost >= MAX_PER_EXTERNAL_HOST) return { ok: false, code: 507, error: "Limit adresów u tego dystrybutora" };
    }
  }
  const changed = store.addSubscriber(data, target.endpoint, pubkey);
  return { ok: true, changed };
}

/** POST /push/unregister — body { endpoint }. Idempotentne: nieznany adres to też 200. */
export function unregister(data, body) {
  const target = classifyEndpoint(body?.endpoint);
  const ep = target ? target.endpoint : typeof body?.endpoint === "string" ? body.endpoint : null;
  const existed = !!(ep && data.push.subscribers[ep]);
  if (existed) store.removeSubscriber(data, ep);
  if (target?.kind === "lep") dropTopic(target.topic);
  return { ok: true, changed: existed };
}

/** Tematy LEP zarejestrowanych subskrybentów (dla lep.js: tylko one dostają kolejkę). */
export function lepTopics(data) {
  const out = new Map();
  for (const ep of Object.keys(data.push.subscribers)) {
    const t = classifyEndpoint(ep);
    if (t?.kind === "lep") out.set(t.topic, ep);
  }
  return out;
}

/**
 * I-08: subskrybent LEP zawsze „przyjmuje” budzik (lokalna kolejka), więc nigdy nie wypadał po 404/410.
 * Wygaszamy tych, których temat nie był odpytywany od tygodnia (apka odinstalowana / wyczyszczona).
 */
export function pruneIdleLep(data, now = Date.now()) {
  let removed = 0;
  for (const s of store.listSubscribers(data)) {
    const t = classifyEndpoint(s.endpoint);
    if (t?.kind !== "lep") continue;
    const last = Math.max(s.seenAt || 0, s.polledAt || 0, s.at || 0);
    if (now - last > LEP_IDLE_PRUNE_MS) { store.removeSubscriber(data, s.endpoint); dropTopic(t.topic); removed += 1; }
  }
  return removed;
}

// --- wysyłka ---

function postHttps(url, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, {
      method: "POST",
      headers: { "Content-Type": "text/plain", "Content-Length": Buffer.byteLength(body) },
      lookup: safeLookup, // I-07: sprawdzenie adresu przy KAŻDYM połączeniu, nie tylko przy rejestracji
      timeout: SEND_TIMEOUT_MS,
    }, (res) => { res.resume(); resolve(res.statusCode); }); // bez podążania za przekierowaniami
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end(body);
  });
}

/** Dostarcza jeden budzik. Zwraca "sent" | "dead" | "retry". */
async function deliverOne(sub, plaintext, log) {
  const target = classifyEndpoint(sub.endpoint);
  if (!target) return "dead"; // np. stary wpis sprzed walidacji SSRF
  let blob;
  if (sub.pubkey) {
    blob = encryptFor(sub.pubkey, plaintext);
    if (!blob) return "dead"; // zły klucz → bezużyteczny subskrybent
    // miniatura nie zmieściła się w limicie tego kanału — wysyłamy budzik bez niej
    const limit = target.kind === "lep" ? MAX_BLOB_LEP : MAX_BLOB_EXTERNAL;
    if (blob.length > limit && plaintext.img) {
      const { img: _img, ...rest } = plaintext;
      blob = encryptFor(sub.pubkey, rest);
    }
  } else {
    if (plaintext.t === "decoy") return "sent"; // jawny szum nic nie ukrywa — nie budzimy telefonu na darmo
    blob = JSON.stringify({ t: "1" }); // protokół: bez pubkey mały, jawny sygnał (bez miniatury — byłaby jawna)
  }
  if (target.kind === "lep") return publishLocal(target.topic, blob) != null ? "sent" : "retry";
  try {
    const status = await postHttps(target.endpoint, blob);
    if (status === 404 || status === 410) return "dead";
    return status >= 200 && status < 300 ? "sent" : "retry";
  } catch (e) {
    if (e.code === "EBLOCKED") return "dead"; // nazwa zaczęła wskazywać sieć prywatną — usuwamy
    // sieć/timeout — nie usuwamy (endpoint może być chwilowo niedostępny)
    log.warn?.(`[push] dystrybutor ${target.host || "?"}: ${e.message}`); // A-17: bez ścieżki (to tajny temat subskrybenta)
    return "retry";
  }
}

async function forEachLimited(list, limit, fn) {
  let next = 0, done = 0;
  const workers = Array.from({ length: Math.min(limit, list.length) }, async () => {
    while (next < list.length) {
      await fn(list[next++]);
      // A-02: wysyłka do tematów LEP nie ma operacji wejścia-wyjścia, więc bez tego pętla zdarzeń stałaby do końca listy
      if (++done % 64 === 0) await new Promise((r) => setImmediate(r));
    }
  });
  await Promise.all(workers);
}

async function sendTo(data, subs, plaintextFor, { save = true, log = console } = {}) {
  let sent = 0;
  const dead = [];
  await forEachLimited(subs, SEND_CONCURRENCY, async (s) => {
    const r = await deliverOne(s, plaintextFor(), log);
    if (r === "sent") sent += 1;
    else if (r === "dead") dead.push(s.endpoint);
  });
  for (const ep of dead) store.removeSubscriber(data, ep);
  if (dead.length && save) store.save(data);
  return { sent, pruned: dead.length };
}

/**
 * Wysyła budzik do WSZYSTKICH subskrybentów. Best-effort, z ograniczoną równoległością.
 * Subskrybentów, których adres zniknął (404/410, zły klucz), usuwamy. Zwraca { sent, pruned }.
 * opts.img — miniatura (base64 JPG/PNG/WEBP) do pokazania w powiadomieniu BEZ pobierania z sieci
 * (serwer nie zobaczy IP czytelnika). opts.jitterSec — każdy adres dostaje budzik z osobnym, losowym
 * opóźnieniem 0..N s (protokół: zatarcie, który budzik był prawdziwy); przy włączonym szumie część adresów
 * dostaje dodatkowo pusty budzik w tym samym oknie.
 */
export async function notifyAll(data, opts = {}) {
  const t0 = Date.now();
  const subs = store.listSubscribers(data).length;
  const r = await notifyAllImpl(data, opts);
  logger.info("push", "budzik", `wysłano budziki: ${r.sent} z ${subs} (wygaszono: ${r.pruned})`, { subskrybentow: subs, wyslano: r.sent, wygaszono: r.pruned, ms: Date.now() - t0, rozmycieSek: opts.jitterSec || 0, miniatura: !!opts.img });
  return r;
}

async function notifyAllImpl(data, opts = {}) {
  let subs = store.listSubscribers(data);
  // A-02: temat LEP, którego nikt ani razu nie odpytał przez 15 min od rejestracji, to nie aplikacja (aplikacja
  // odpytuje od razu) — nie szyfrujemy dla niego budzika i nie odkładamy mu pamięci, wygaszamy go
  const nowTs = Date.now();
  const ghost = subs.filter((s) => classifyEndpoint(s.endpoint)?.kind === "lep" && !s.polledAt && nowTs - (s.at || 0) > 15 * 60_000);
  if (ghost.length) {
    for (const s of ghost) { store.removeSubscriber(data, s.endpoint); dropTopic(classifyEndpoint(s.endpoint).topic); }
    store.saveSoon(data);
    subs = subs.filter((s) => !ghost.includes(s));
  }
  if (!subs.length) return { sent: 0, pruned: ghost.length };
  // nowy plaintext (z nowym `at`) dla każdego — i tak każdy budzik ma osobną parę efemeryczną i iv
  const plaintext = () => (opts.img ? { t: "significant", at: Date.now(), ts: Date.now(), img: opts.img } : { t: "significant", at: Date.now(), ts: Date.now() });
  const jitterMs = Math.max(0, (opts.jitterSec || 0) * 1000);
  if ((data.config.push?.decoyPerDay || 0) > 0) scheduleDecoysNearReal(() => data, subs, Math.max(jitterMs, 120_000), opts.log || console);
  if (!jitterMs) return sendTo(data, subs, plaintext, opts);
  // rozmyte: każdy adres w swoim losowym momencie (bez wspólnej sekundy dla wszystkich)
  const results = await Promise.all(subs.map((sub) => new Promise((resolve) => {
    const t = setTimeout(() => sendTo(data, [sub], plaintext, opts).then(resolve, () => resolve({ sent: 0, pruned: 0 })),
      Math.floor(Math.random() * jitterMs));
    t.unref?.();
  })));
  return results.reduce((a, r) => ({ sent: a.sent + r.sent, pruned: a.pruned + r.pruned }), { sent: 0, pruned: 0 });
}

// --- puste budziki (szum / cover traffic) ---
// Protokół: budzik bez nowej treści, który rozmywa wzorzec czasowy („kiedy ktoś dostaje budziki”).
// Każdemu adresowi losujemy NIEZALEŻNIE: liczba z rozkładu Poissona wokół decoyPerDay, pory ważone jak
// zwykły ruch (więcej wieczorem, mało w nocy), czasy z jitterem do sekundy. Wyłączone, gdy decoyPerDay = 0.

const HOUR_WEIGHTS = [1, 0.5, 0.3, 0.3, 0.3, 0.5, 1, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 6, 7, 8, 8, 7, 5, 2];
const WEIGHT_SUM = HOUR_WEIGHTS.reduce((a, b) => a + b, 0);
const decoyTimers = new Set();
// dzienny limit szumu NA ADRES (protokół: szum kosztuje baterię — rozkład Poissona ma długi ogon)
const decoyCount = new Map(); // endpoint -> { day, n }
function decoyAllowed(endpoint, perDay) {
  const day = new Date().toDateString();
  if (decoyCount.size > 5000) { for (const [k, v] of decoyCount) if (v.day !== day) decoyCount.delete(k); } // A-26: mapa nie rośnie bez końca
  const cap = Math.max(1, Math.ceil(perDay * 1.5));
  const c = decoyCount.get(endpoint);
  if (!c || c.day !== day) { decoyCount.set(endpoint, { day, n: 1 }); return true; }
  if (c.n >= cap) return false;
  c.n += 1;
  return true;
}

function sendDecoyLater(getData, endpoint, delayMs, log) {
  const t = setTimeout(async () => {
    decoyTimers.delete(t);
    const d = getData();
    const current = d.push.subscribers[endpoint];
    const perDay = d.config.push?.decoyPerDay || 0;
    if (!current || perDay <= 0 || !current.pubkey) return; // wyrejestrowany, szum wyłączony albo bez E2E
    if (!decoyAllowed(endpoint, perDay)) return;
    await sendTo(d, [{ endpoint, ...current }], () => ({ t: "decoy", at: Date.now() }), { log });
  }, delayMs);
  t.unref?.();
  decoyTimers.add(t);
}

/** Szum obok prawdziwego budzika: ~30% adresów dostaje pusty budzik w tym samym oknie czasowym. */
function scheduleDecoysNearReal(getData, subs, windowMs, log) {
  for (const sub of subs) {
    if (sub.pubkey && Math.random() < 0.3) sendDecoyLater(getData, sub.endpoint, Math.floor(Math.random() * windowMs), log);
  }
}

function poisson(lambda) {
  let k = 0, p = 1;
  const l = Math.exp(-lambda);
  do { k += 1; p *= Math.random(); } while (p > l);
  return k - 1;
}

/** Planuje szum na najbliższą godzinę; woła się co godzinę (startDecoys). */
function planDecoyHour(getData, log) {
  const data = getData();
  const perDay = data.config.push?.decoyPerDay || 0;
  if (perDay <= 0) return;
  const hour = new Date().getHours();
  const lambda = (perDay * HOUR_WEIGHTS[hour]) / WEIGHT_SUM;
  for (const sub of store.listSubscribers(data)) {
    if (!sub.pubkey) continue; // szum ma sens tylko zaszyfrowany
    const count = poisson(lambda);
    for (let i = 0; i < count; i += 1) sendDecoyLater(getData, sub.endpoint, Math.floor(Math.random() * 3_600_000), log);
  }
}

/** Statystyki subskrybentów do panelu (bez adresów — tylko liczby). */
export function subscriberStats(data, now = Date.now()) {
  const st = { total: 0, lep: 0, external: 0, withoutKey: 0, active24h: 0, active7d: 0, new24h: 0 };
  for (const s of store.listSubscribers(data)) {
    st.total += 1;
    const t = classifyEndpoint(s.endpoint);
    if (t?.kind === "lep") st.lep += 1; else st.external += 1;
    if (!s.pubkey) st.withoutKey += 1;
    const last = Math.max(s.seenAt || 0, s.polledAt || 0, s.at || 0);
    if (now - last <= 24 * 3600_000) st.active24h += 1;
    if (now - last <= 7 * 24 * 3600_000) st.active7d += 1;
    if (now - (s.at || 0) <= 24 * 3600_000) st.new24h += 1;
  }
  return st;
}

export function startDecoys(getData, log = console) {
  planDecoyHour(getData, log);
  const iv = setInterval(() => planDecoyHour(getData, log), 3_600_000);
  iv.unref?.();
  return iv;
}
