// Dziennik zdarzeń serwera — ZAWSZE włączony (nie ma przełącznika ani zmiennej, która by go wyłączała).
//
//  • Wpisy są strukturalne (JSON): numer kolejny, czas, poziom, kategoria, zdarzenie, komunikat, pola.
//  • Zbierane są: start/zatrzymanie i migawka systemu, każde żądanie HTTP (bez adresów IP i nagłówków klientów),
//    działania w panelu (audyt), logowania, zmiany konfiguracji i szyfrowania, wgrywanie i konwersja multimediów,
//    budziki push (same liczby — nigdy adresy subskrybentów), aktualizacje, Tor, certyfikaty, błędy z pełnym stosem,
//    cały strumień konsoli oraz co minutę metryki (pamięć, opóźnienie pętli zdarzeń, procesor, liczniki ruchu).
//  • Wpisy trafiają w blokach do tabeli `logs` w bazie danych: blok → ZSTD (poziom 3) → szyfrowanie najlepszym
//    szyfrem akcelerowanym przez CPU (niezależnie od wyboru szyfru bazy i także gdy baza nie jest szyfrowana) →
//    (jeśli baza jest szyfrowana) drugi raz szyfrem bazy. Bloki tworzą łańcuch skrótów SHA-256 — usunięcie albo
//    podmiana bloku jest wykrywalna (`verify`).
//  • Prywatność: pola o nazwach sugerujących sekrety (hasło, token, ciasteczko, adres push, klucz…) są zastępowane
//    „[ukryte]”, w komunikatach z adresów URL obcinane są zapytania, a długie ciągi przypominające tokeny maskowane.

import util from "node:util";
import os from "node:os";
import { monitorEventLoopDelay } from "node:perf_hooks";
import * as store from "./store.js";

export const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, security: 50 };
const LEVEL_NAMES = Object.fromEntries(Object.entries(LEVELS).map(([k, v]) => [v, k]));
export const levelName = (n) => LEVEL_NAMES[n] || String(n);

// oryginalna konsola — dla wypisań, które NIE mogą trafić do dziennika (hasła) i dla błędów samego dziennika
export const raw = {
  log: console.log.bind(console), info: console.info.bind(console), warn: console.warn.bind(console),
  error: console.error.bind(console), debug: console.debug.bind(console),
};

const FLUSH_MS = 1000;
const FLUSH_ENTRIES = 400;
const FLUSH_BYTES = 256 * 1024;
const MAX_PENDING = 20_000; // zanim baza zostanie odblokowana albo gdy zapis nie działa
const SECRET_KEY = /(pass|has[lł]o|secret|token|cookie|authoriz|csrf|endpoint|pubkey|privkey|api[-_]?key|master|klucz|session)/i;

let pending = [];
let pendingBytes = 0;
let ready = false;
let nextSeq = null;
let timer = null;
let flushing = false;
let blocksSincePrune = 0;
let dropped = 0;
const counters = { req: 0, s2: 0, s3: 0, s4: 0, s5: 0, bytes: 0, byRoute: {} };

// ------------------------------------------------------------------ oczyszczanie ---------------------------
export function maskText(s) {
  return maskPaths(String(s))
    .replace(/(https?:\/\/[^\s?#"']+)[?#][^\s"']*/g, "$1")           // zapytania i fragmenty URL
    .replace(/((?:pass(?:word|phrase)?|has[lł]o|secret|token|api[-_]?key|authorization|cookie|csrf)["']?\s*[:=]\s*)((?:Bearer\s+|Basic\s+)?(?:"[^"]*"|'[^']*'|\S+))/gi, "$1[ukryte]") // „hasło: xyz”, „token=abc”
    .replace(/[A-Za-z0-9_-]{40,}/g, (m) => (/^[0-9a-f]{64}$/i.test(m) ? m : "[…]"))   // tokeny (skróty SHA-256 zostają)
    .slice(0, 2000);
}

/** Ukrywa nazwę konta w ścieżkach (C:\Users\<konto>, /home/<konto>) — dziennik bywa udostępniany. */
function maskPaths(s) {
  return String(s).replace(/([A-Za-z]:[\\/]Users[\\/])[^\\/\s"']+/gi, "$1[ukryte]").replace(/(\/(?:home|Users)\/)[^\/\s"']+/g, "$1[ukryte]");
}

function clean(v, depth = 0) {
  if (v == null || typeof v === "number" || typeof v === "boolean") return v;
  if (typeof v === "string") return maskPaths(v.length > 600 ? v.slice(0, 600) + "…" : v);
  if (typeof v === "bigint") return Number(v);
  if (v instanceof Error) return { name: v.name, message: maskText(v.message), stack: String(v.stack || "").split("\n").slice(0, 12).map((l) => maskText(l)) };
  if (Buffer.isBuffer(v)) return `[${v.length} B]`;
  if (depth >= 3) return "[…]";
  if (Array.isArray(v)) return v.slice(0, 40).map((x) => clean(x, depth + 1));
  if (typeof v === "object") {
    const out = {};
    for (const [k, x] of Object.entries(v).slice(0, 60)) out[k] = SECRET_KEY.test(k) ? "[ukryte]" : clean(x, depth + 1);
    return out;
  }
  return String(v);
}

// ------------------------------------------------------------------ zapis --------------------------------------
function emit(level, cat, ev, msg, fields) {
  const e = { ts: Date.now(), level: LEVELS[level] ?? 20, cat, ev, msg: maskText(msg ?? "") };
  if (fields && Object.keys(fields).length) e.f = clean(fields);
  if (pending.length >= MAX_PENDING) { pending.shift(); dropped++; }
  pending.push(e);
  pendingBytes += 200 + e.msg.length;
  if (ready && (pending.length >= FLUSH_ENTRIES || pendingBytes >= FLUSH_BYTES)) flush();
  else if (ready && !timer) { timer = setTimeout(flush, FLUSH_MS); timer.unref?.(); }
}

export const debug = (cat, ev, msg, f) => emit("debug", cat, ev, msg, f);
export const info = (cat, ev, msg, f) => emit("info", cat, ev, msg, f);
export const warn = (cat, ev, msg, f) => emit("warn", cat, ev, msg, f);
export const error = (cat, ev, msg, f) => emit("error", cat, ev, msg, f);
/** Zdarzenie z obszaru bezpieczeństwa / audytu (logowania, zmiany kluczy, haseł, konfiguracji, aktualizacje). */
export const audit = (ev, msg, f) => emit("security", "audyt", ev, msg, f);

/** Zapisuje oczekujące wpisy jako jeden blok (ZSTD → szyfr → szyfr bazy). */
export function flush() {
  if (timer) { clearTimeout(timer); timer = null; }
  flushTraffic(false);
  if (!ready || flushing || !pending.length) return;
  flushing = true;
  const batch = pending;
  pending = []; pendingBytes = 0;
  try {
    if (nextSeq == null) nextSeq = store.logNextSeq();
    const first = nextSeq;
    for (const e of batch) e.seq = nextSeq++;
    const lines = batch.map((e) => JSON.stringify(e)).join("\n");
    store.logAppendBlock({ firstSeq: first, lastSeq: nextSeq - 1, tsFirst: batch[0].ts, tsLast: batch[batch.length - 1].ts, count: batch.length }, Buffer.from(lines, "utf8"));
    if (++blocksSincePrune >= 50) { blocksSincePrune = 0; prune(); }
  } catch (e) {
    // nie gubimy wpisów: wracają na początek kolejki, błąd idzie na prawdziwą konsolę
    for (const x of batch) delete x.seq;
    nextSeq = null;
    pending = batch.concat(pending).slice(-MAX_PENDING);
    raw.error("[dziennik] zapis bloku nie powiódł się:", e.message);
  } finally {
    flushing = false;
  }
}

function prune() {
  const maxMb = Math.max(16, Number(process.env.LOG_MAX_MB) || 512);
  const maxDays = Math.max(30, Number(process.env.LOG_MAX_DAYS) || 365);
  const r = store.logPrune({ maxBytes: maxMb * 1024 * 1024, olderThanTs: Date.now() - maxDays * 86_400_000 });
  if (r.removed) {
    // przycięcie zostawia ślad poziomu security z zakresem usuniętych wpisów (nie da się go zrobić po cichu)
    audit("dziennik.przycinanie", `przycięto najstarsze bloki dziennika: ${r.removed} (wpisy #${r.firstSeq}–#${r.lastSeq}); limit ${maxMb} MB / ${maxDays} dni`,
      { bloki: r.removed, odSeq: r.firstSeq, doSeq: r.lastSeq, odCzasu: r.tsFrom ? new Date(r.tsFrom).toISOString() : null, doCzasu: r.tsTo ? new Date(r.tsTo).toISOString() : null });
  }
}

/** Podpina bazę (po odblokowaniu) i zapisuje wszystko, co zebrano od startu procesu. */
export function attach() {
  ready = true;
  nextSeq = null;
  if (dropped) warn("dziennik", "utracone", `przed uruchomieniem bazy odrzucono ${dropped} najstarszych wpisów (przepełnienie bufora)`, { dropped });
  flush();
}

/** Koniec pracy: zapisuje resztę wpisów (wołać przed zamknięciem bazy). */
export function shutdown(reason = "zatrzymanie") {
  stopMetrics();
  flushTraffic(true);
  info("system", "stop", `serwer kończy pracę (${reason})`, { uptimeSec: Math.round(process.uptime()) });
  flush();
}

// ------------------------------------------------------------------ konsola i błędy procesu ---------------------
export function install() {
  const wrap = (name, level) => {
    console[name] = (...args) => {
      raw[name](...args);
      try { emit(level, "konsola", name, util.format(...args), null); } catch { /* nigdy nie psujemy konsoli */ }
    };
  };
  wrap("log", "info"); wrap("info", "info"); wrap("warn", "warn"); wrap("error", "error"); wrap("debug", "debug");
  process.on("exit", (code) => { try { info("system", "exit", `proces kończy się kodem ${code}`, { code }); flush(); } catch { /* ignore */ } });
}

// ------------------------------------------------------------------ żądania HTTP --------------------------------
/** Klasa trasy bez danych identyfikujących (tematy LEP, nazwy plików push) — do dziennika i liczników. */
export function routeClass(path, isAdmin) {
  if (path.startsWith("/admin/api/")) return "panel-api:" + path.slice("/admin/api/".length).split("?")[0].slice(0, 40);
  if (path.startsWith("/admin")) return "panel";
  if (path.startsWith("/media/")) return "media";
  if (path.startsWith("/post/")) return path === "/post/usuniecia.json" ? "plik-usuniec" : "plik-tresci";
  if (path.startsWith("/e/")) return "permalink";
  if (path === "/manifest.json" || path === "/") return "manifest";
  if (path.startsWith("/lep/sub/")) return "lep-sub";
  if (path.startsWith("/lep/pub/")) return "lep-pub";
  if (path === "/push/register") return "push-rejestracja";
  if (path === "/push/unregister") return "push-wyrejestrowanie";
  if (path.startsWith("/.well-known/acme-challenge/")) return "acme";
  return isAdmin ? "inne" : "nieznana";
}

// A-03: żądania publiczne (manifest, pliki, media, nieznane trasy…) są zapisywane ZBIORCZO co okno czasu — inaczej anonimowy
// klient mógłby samymi żądaniami wypchnąć z dziennika ślad audytu. Osobne wpisy dostają: panel, push, błędy 5xx i 4xx (z limitem).
const TRAFFIC_WINDOW_MS = Math.max(1, Number(process.env.LOG_TRAFFIC_WINDOW_SEC) || 60) * 1000;
const traffic = new Map();
let trafficSince = Date.now();
let individualBudget = 30, budgetAt = Date.now(), suppressed = 0;
function takeIndividual() {
  const now = Date.now();
  if (now - budgetAt >= 60_000) {
    if (suppressed) { warn("http", "pominiete", `pominięto ${suppressed} pojedynczych wpisów żądań z błędem (limit 30 na minutę); liczą się w zbiorczych`, { pominiete: suppressed }); suppressed = 0; }
    budgetAt = now; individualBudget = 30;
  }
  if (individualBudget > 0) { individualBudget--; return true; }
  suppressed++;
  return false;
}
function flushTraffic(force = false) {
  if (!traffic.size || (!force && Date.now() - trafficSince < TRAFFIC_WINDOW_MS)) return;
  const trasy = [...traffic.entries()].slice(0, 60).map(([k, v]) => { const [route, status] = k.split("|"); return { route, status: Number(status), n: v.n, msSrednio: +(v.ms / v.n).toFixed(2), msMax: +v.max.toFixed(2), bajty: v.bytes }; });
  const total = trasy.reduce((n, t) => n + t.n, 0);
  traffic.clear();
  const sec = Math.round((Date.now() - trafficSince) / 1000);
  trafficSince = Date.now();
  emit("debug", "http", "ruch", `ruch publiczny: ${total} żądań w ${sec} s`, { okno: sec, trasy });
}

export function request(f) {
  counters.req++;
  const individual = f.route.startsWith("panel") || f.route.startsWith("push") || f.route === "lep-pub" || f.status >= 500 || (f.status >= 400 && f.status !== 404 && takeIndividual());
  if (!individual) {
    const k = `${f.route}|${f.status}`;
    const a = traffic.get(k) || { n: 0, ms: 0, max: 0, bytes: 0 };
    a.n++; a.ms += f.ms || 0; a.max = Math.max(a.max, f.ms || 0); a.bytes += f.bytes || 0;
    traffic.set(k, a);
    countOnly(f);
    flushTraffic();
    return;
  }
  countOnly(f);
  const level = f.status >= 500 ? "error" : f.status >= 400 && f.status !== 404 ? "warn" : "info";
  emit(level, "http", "zadanie", `${f.method} ${f.route} → ${f.status}`, f);
}

function countOnly(f) {
  counters.req += 0;
  const c = Math.floor(f.status / 100);
  if (c === 2) counters.s2++; else if (c === 3) counters.s3++; else if (c === 4) counters.s4++; else if (c >= 5) counters.s5++;
  counters.bytes += f.bytes || 0;
  counters.byRoute[f.route] = (counters.byRoute[f.route] || 0) + 1;
}

// ------------------------------------------------------------------ metryki ------------------------------------
let metricsTimer = null;
let loop = null;
let lastCpu = null;
let lastCounters = null;

export function startMetrics(extras = () => ({})) {
  stopMetrics();
  try { loop = monitorEventLoopDelay({ resolution: 20 }); loop.enable(); } catch { loop = null; }
  lastCpu = process.cpuUsage();
  lastCounters = JSON.stringify(counters);
  const tick = () => {
    flushTraffic(false);
    const mem = process.memoryUsage();
    const cpu = process.cpuUsage(lastCpu);
    lastCpu = process.cpuUsage();
    const snap = {
      rssMB: Math.round(mem.rss / 1048576), heapMB: Math.round(mem.heapUsed / 1048576), externalMB: Math.round(mem.external / 1048576),
      cpuMsUser: Math.round(cpu.user / 1000), cpuMsSys: Math.round(cpu.system / 1000),
      loopP50ms: loop ? +(loop.percentile(50) / 1e6).toFixed(2) : null, loopP99ms: loop ? +(loop.percentile(99) / 1e6).toFixed(2) : null, loopMaxMs: loop ? +(loop.max / 1e6).toFixed(2) : null,
      load1: +os.loadavg()[0].toFixed(2), freeMemMB: Math.round(os.freemem() / 1048576),
      requests: { ...counters, byRoute: { ...counters.byRoute } },
      dbMB: store.dbSizeMB(),
      ...extras(),
    };
    if (loop) loop.reset();
    emit("debug", "metryki", "puls", "metryki procesu", snap);
  };
  metricsTimer = setInterval(tick, 60_000);
  metricsTimer.unref?.();
}
function stopMetrics() { if (metricsTimer) clearInterval(metricsTimer); metricsTimer = null; try { loop?.disable(); } catch { /* ignore */ } }

/** Migawka systemu przy starcie — pełny obraz środowiska, w którym pracuje serwer. */
export function snapshot(extra = {}) {
  const cpus = os.cpus();
  info("system", "start", "serwer startuje", {
    pid: process.pid, node: process.version, v8: process.versions.v8, openssl: process.versions.openssl, sqlite: process.versions.sqlite,
    platform: process.platform, arch: process.arch, release: os.release(), hostname: "[ukryte]",
    cpu: cpus[0]?.model?.trim(), threads: cpus.length, totalMemMB: Math.round(os.totalmem() / 1048576),
    argv: process.argv.slice(2).filter((a) => !/pass|haslo/i.test(a)),
    supervised: process.env.LEWICOWYT_SUPERVISED === "1", ...extra,
  });
}

// ------------------------------------------------------------------ odczyt -------------------------------------
/** Wpisy (najnowsze pierwsze) z filtrami; łączy bufor w pamięci z zapisanymi blokami. */
export function query({ minLevel = "debug", cat = "", q = "", limit = 300, beforeSeq = null, sinceTs = 0 } = {}) {
  flush();
  const min = LEVELS[minLevel] ?? 10;
  const needle = String(q || "").toLowerCase();
  const catN = String(cat || "").toLowerCase();
  const match = (e) => e.level >= min && e.ts >= sinceTs && (!catN || String(e.cat).toLowerCase().includes(catN))
    && (!needle || (e.msg + " " + e.ev + " " + (e.f ? JSON.stringify(e.f) : "")).toLowerCase().includes(needle));
  const out = [];
  for (const block of store.logIterate({ reverse: true, minTs: sinceTs })) {
    for (let i = block.entries.length - 1; i >= 0; i--) {
      const e = block.entries[i];
      if (beforeSeq != null && e.seq >= beforeSeq) continue;
      if (match(e)) { out.push(e); if (out.length >= limit) return out; }
    }
  }
  return out;
}

/** Wszystkie wpisy z zakresu (najstarsze pierwsze) — do eksportu. */
export function collect({ sinceTs = 0, minLevel = "debug", maxEntries = 1_000_000 } = {}) {
  flush();
  const min = LEVELS[minLevel] ?? 10;
  const out = [];
  let truncated = false;
  // idziemy od NAJNOWSZYCH: przy przekroczeniu limitu giną najstarsze wpisy, nie ostatnie zdarzenia
  outer: for (const block of store.logIterate({ reverse: true, minTs: sinceTs })) {
    for (let i = block.entries.length - 1; i >= 0; i--) {
      const e = block.entries[i];
      if (e.level >= min && e.ts >= sinceTs) {
        if (out.length >= maxEntries) { truncated = true; break outer; }
        out.push(e);
      }
    }
  }
  out.reverse();
  out.truncated = truncated;
  return out;
}

export const stats = () => { flush(); return { ...store.logStats(), pending: pending.length, dropped }; };
export const verify = () => { flush(); return store.logVerify(); };
