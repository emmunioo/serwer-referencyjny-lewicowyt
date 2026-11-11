// LEP (lewicowYT Embedded Push) — ta sama logika co dedykowany relay, wbudowana w serwer spolecznosci,
// zeby obsluzyc wbudowane dystrybutory aplikacji BEZ osobnego relay. ZERO-KNOWLEDGE: plynie wylacznie
// zaszyfrowany (E2E) ciphertext; `topic` to losowy, nieprzezroczysty id aplikacji.
//   POST /lep/pub/<topic>          - budzik do tematu (to "endpoint", ktory rejestruje apka)
//   GET  /lep/sub/<topic>?after=N  - apka long-polluje (trzyma ~50 s)
// Stan (kolejka) powstaje tylko dla tematow zarejestrowanych w /push/register (I-08): obcy nie zapchaja
// pamieci losowymi tematami, a apka, ktora jeszcze sie nie zarejestrowala, dostaje zwykle puste czekanie.

const HOLD_MS = 50_000;
const MAX_QUEUE = 50;
const MAX_TOPICS = 200_000;
const MAX_UNKNOWN_WAITERS = 1_000; // czekajacy na temat jeszcze niezarejestrowany — bez stanu, z limitem
const MAX_BODY = 16 * 1024;
const TOPIC_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const TOPIC_RE = /^[A-Za-z0-9_-]{16,128}$/;

const MAX_TOTAL_BYTES = 96 * 1024 * 1024; // A-02: łączny limit pamięci wszystkich kolejek
let totalBytes = 0;
const sizeOf = (t) => t.q.reduce((n, m) => n + m.data.length, 0);
const topics = new Map(); // topic -> { q:[{seq,data}], seq, waiters:Set<res>, at }
let unknownWaiters = 0;

// serwer podaje, ktore tematy sa zarejestrowane, i dostaje sygnal o odpytaniu (subskrybent zyje)
let isKnownTopic = () => true;
let onPoll = () => {};
export function configureLep(opts = {}) {
  if (opts.isKnownTopic) isKnownTopic = opts.isKnownTopic;
  if (opts.onPoll) onPoll = opts.onPoll;
}

function touch(name, create) {
  let t = topics.get(name);
  if (!t && create) {
    if (topics.size >= MAX_TOPICS) return null;
    t = { q: [], seq: 0, waiters: new Set(), at: Date.now() };
    topics.set(name, t);
  }
  if (t) t.at = Date.now();
  return t || null;
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    let over = false;
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) { if (!over) { over = true; chunks.length = 0; reject(new Error("too big")); req.resume(); setTimeout(() => req.destroy(), 1500).unref?.(); } return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}
function send(res, code, obj, extra = {}) {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*", ...extra });
  res.end(JSON.stringify(obj));
}
function deliver(t) {
  if (!t.waiters.size || !t.q.length) return;
  for (const res of [...t.waiters]) {
    const after = res.__after || 0;
    const msgs = t.q.filter((m) => m.seq > after);
    if (msgs.length) { t.waiters.delete(res); clearTimeout(res.__timer); send(res, 200, { msgs, cursor: t.q[t.q.length - 1].seq }); }
  }
}
/** Temat z konca sciezki albo null (zly format / zepsute %-kodowanie — I-14). */
function topicFrom(path, prefix) {
  let name;
  try { name = decodeURIComponent(path.slice(prefix.length)); } catch { return null; }
  return TOPIC_RE.test(name) ? name : null;
}

/**
 * Wrzuca budzik do tematu bez HTTP — serwer uzywa tego dla wlasnych subskrybentow LEP. Wysylka przez
 * siec do samego siebie nie dziala dla .onion (Node nie ma Tora) ani przy routerze bez hairpin-NAT.
 * Zwraca seq albo null (zly temat / brak miejsca).
 */
export function publishLocal(name, data) {
  if (!TOPIC_RE.test(name) || Buffer.byteLength(String(data)) > MAX_BODY) return null;
  const t = touch(name, true);
  if (!t) return null;
  // A-22: seq monotoniczny miedzy restartami (baza Date.now()).
  t.seq = Math.max(t.seq + 1, Date.now());
  const msg = { seq: t.seq, data: String(data) };
  if (totalBytes + msg.data.length > MAX_TOTAL_BYTES) {
    // brak miejsca: zwalniamy najstarsze wiadomości tego tematu; jeśli to nie wystarczy — odmowa (wysyłka policzy "retry")
    while (t.q.length && totalBytes + msg.data.length > MAX_TOTAL_BYTES) totalBytes -= t.q.shift().data.length;
    if (totalBytes + msg.data.length > MAX_TOTAL_BYTES) return null;
  }
  t.q.push(msg);
  totalBytes += msg.data.length;
  if (t.q.length > MAX_QUEUE) for (const old of t.q.splice(0, t.q.length - MAX_QUEUE)) totalBytes -= old.data.length;
  deliver(t);
  return t.seq;
}

/** Temat LEP ze sciezki "/lep/pub/<topic>" albo null. */
export function lepTopicOf(pathname) {
  if (!pathname.startsWith("/lep/pub/")) return null;
  return topicFrom(pathname, "/lep/pub/");
}

/** Czy sciezka nalezy do LEP. */
export function isLep(path) { return path.startsWith("/lep/pub/") || path.startsWith("/lep/sub/"); }

/** Obsluguje kazde zadanie na sciezce LEP (inne metody → 405, I-06). */
export async function handleLep(req, res, path) {
  const isPub = path.startsWith("/lep/pub/");
  if (isPub && req.method !== "POST") { send(res, 405, { error: "method" }, { Allow: "POST" }); return; }
  if (!isPub && req.method !== "GET") { send(res, 405, { error: "method" }, { Allow: "GET" }); return; }
  const name = topicFrom(path, isPub ? "/lep/pub/" : "/lep/sub/");
  if (!name) { send(res, 400, { error: "bad topic" }); return; }

  if (isPub) {
    // z zewnatrz tylko do zarejestrowanych tematow — inaczej ktos zapchalby pamiec kolejkami
    if (!isKnownTopic(name)) { send(res, 404, { error: "unknown topic" }); return; }
    let body; try { body = await readBody(req, MAX_BODY); } catch { send(res, 413, { error: "too big" }); return; }
    const seq = publishLocal(name, body.toString("utf8"));
    if (seq == null) { send(res, 507, { error: "capacity" }); return; }
    send(res, 200, { ok: true, seq });
    return;
  }

  const u = new URL(req.url, "http://x");
  const rawAfter = Math.max(0, parseInt(u.searchParams.get("after") || "0", 10) || 0);
  const known = isKnownTopic(name);
  if (!known && !topics.has(name)) {
    // apka odpytuje temat, ktorego rejestracja jeszcze nie doszla (albo obcy) — nie alokujemy stanu
    if (u.searchParams.get("wait") === "0") { send(res, 200, { msgs: [], cursor: rawAfter }); return; }
    if (unknownWaiters >= MAX_UNKNOWN_WAITERS) { send(res, 429, { error: "busy" }, { "Retry-After": "30" }); return; }
    unknownWaiters += 1;
    let done = false;
    const finish = () => { if (!done) { done = true; unknownWaiters -= 1; } };
    const timer = setTimeout(() => { finish(); send(res, 200, { msgs: [], cursor: rawAfter }); }, HOLD_MS);
    req.on("close", () => { clearTimeout(timer); finish(); });
    return;
  }
  const t = touch(name, true);
  if (!t) { send(res, 507, { error: "capacity" }); return; }
  onPoll(name);
  // A-22: kursor klienta wyprzedzajacy nasz ostatni seq (restart/TTL) traktujemy jak 0.
  const lastSeq = t.q.length ? t.q[t.q.length - 1].seq : 0;
  const after = rawAfter > lastSeq ? 0 : rawAfter;
  const pending = t.q.filter((m) => m.seq > after);
  if (pending.length) { send(res, 200, { msgs: pending, cursor: lastSeq }); return; }
  // tryb oszczedny apki: wait=0 → nie trzymamy polaczenia, zwracamy od razu (pusto, gdy nic nowego)
  if (u.searchParams.get("wait") === "0") { send(res, 200, { msgs: [], cursor: lastSeq }); return; }
  res.__after = after;
  res.__timer = setTimeout(() => { t.waiters.delete(res); send(res, 200, { msgs: [], cursor: after }); }, HOLD_MS);
  t.waiters.add(res);
  req.on("close", () => { t.waiters.delete(res); clearTimeout(res.__timer); });
}

/** Usuwa kolejke tematu (subskrybent wyrejestrowany albo wygasly). */
export function dropTopic(name) {
  const t = topics.get(name);
  if (t && !t.waiters.size) { totalBytes -= sizeOf(t); topics.delete(name); }
}

export function startLepCleanup() {
  return setInterval(() => {
    const now = Date.now();
    for (const [name, t] of topics) if (!t.waiters.size && now - t.at > TOPIC_TTL_MS) { totalBytes -= sizeOf(t); topics.delete(name); }
  }, 60 * 60 * 1000).unref?.();
}

export function lepStats() { return { topics: topics.size, unknownWaiters, queuedBytes: totalBytes }; }
