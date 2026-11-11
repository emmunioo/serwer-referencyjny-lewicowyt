// Test end-to-end serwera: uruchamia go na tymczasowych danych (porty 23137/23138) i sprawdza protokół
// oraz poprawki z audytu 22.10.2026 (I-01…I-16). Uruchom: npm test
// Nic nie wychodzi do internetu poza rozwiązywaniem nazw DNS w teście SSRF; dane testowe są kasowane.
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import { join, basename } from "node:path";
import crypto from "node:crypto";
import http from "node:http";
import https from "node:https";
import { fileURLToPath, pathToFileURL } from "node:url";
import { DatabaseSync } from "node:sqlite";

const SRV = process.argv[2] || fileURLToPath(new URL(".", import.meta.url));
const HP = 23137, AP = 23138, TLS_ALT = 23443;
let failures = 0;
const ok = (cond, msg) => { console.log((cond ? "  OK  " : "  FAIL") + " " + msg); if (!cond) failures++; };
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

function req(port, method, path, { headers = {}, body, timeout = 8000, tls = false, servername } = {}) {
  return new Promise((resolve) => {
    const mod = tls ? https : http;
    const r = mod.request({ host: "127.0.0.1", port, method, path, headers, servername, rejectUnauthorized: false, timeout }, (res) => {
      const chunks = []; res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8"), raw: Buffer.concat(chunks) }));
    });
    r.on("timeout", () => { r.destroy(); resolve({ status: 0, headers: {}, body: "", timedOut: true }); });
    r.on("error", (e) => resolve({ status: 0, headers: {}, body: "", error: e.message }));
    if (body) r.write(body);
    r.end();
  });
}

const dbc = await import(pathToFileURL(join(SRV, "dbcrypto.js")).href);

/** podgląd bazy serwera (tylko do odczytu) — dane w data/serwer.db są ZASZYFROWANE; klucz bierzemy z katalogu danych */
function readDb(dir, passphrase = null) {
  const db = new DatabaseSync(join(dir, "serwer.db"), { readOnly: true });
  const q = (text, ...p) => db.prepare(text).all(...p);
  const settings = dbc.readSettings(dir);
  const key = dbc.resolveMasterKey(dir, settings, { mayCreate: false, passphrase }).key;
  const cr = new dbc.Crypt(key, 5, { allowNone: true });
  const media = (name) => {
    const m = q("SELECT size, chunks FROM media WHERE name = ?", name)[0];
    if (!m) return null;
    const parts = q("SELECT idx, data FROM media_chunks WHERE name = ? ORDER BY idx", name)
      .map((r) => cr.decrypt(r.data, dbc.aad.chunk(name, r.idx, Number(m.chunks), Number(m.size))));
    return Buffer.concat(parts);
  };
  return {
    main: () => JSON.parse(cr.decrypt(q("SELECT value FROM meta WHERE key = 'main'")[0].value, dbc.aad.meta("main")).toString("utf8")),
    items: () => q("SELECT id, data FROM items").map((r) => JSON.parse(cr.decrypt(r.data, dbc.aad.item(r.id)).toString("utf8"))),
    media,
    file: (path) => { const r = q("SELECT data FROM files WHERE path = ?", path)[0]; return r ? cr.decrypt(r.data, dbc.aad.file(path)) : null; },
    cipherIds: () => new Set(q("SELECT data FROM items").map((r) => r.data[1])),
    close: () => db.close(),
  };
}

async function startServer(dataDir, extraEnv = {}) {
  const child = spawn(process.execPath, ["server.js"], {
    cwd: SRV,
    env: { ...process.env, LEWICOWYT_NO_CONVERT: "1", DATA_DIR: dataDir, HTTP_PORT: String(HP), ADMIN_PORT: String(AP), HTTPS_PORT: String(TLS_ALT), ACME_HTTP01: "off", ...extraEnv },
  });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 60 && !/Panel:/.test(out); i++) await wait(100);
  await wait(300);
  return { child, out: () => out };
}

async function adminSession(pw) {
  const login = await req(AP, "POST", "/admin/login", { headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "password=" + encodeURIComponent(pw) });
  const cookie = (login.headers["set-cookie"] || [""])[0].split(";")[0];
  const page = await req(AP, "GET", "/admin", { headers: { Cookie: cookie } });
  const csrf = (page.body.match(/name="csrf" content="([^"]+)"/) || [])[1];
  const api = async (action, obj) => {
    const r = await req(AP, "POST", "/admin/api/" + action, { headers: { Cookie: cookie, "X-CSRF-Token": csrf, "Content-Type": "application/json" }, body: JSON.stringify(obj) });
    let j = {}; try { j = JSON.parse(r.body || "{}"); } catch { /* */ }
    return { status: r.status, json: j };
  };
  const upload = async (itemId, type, bytes, append, kind) => {
    const r = await req(AP, "POST", `/admin/api/item/image?itemId=${itemId}${append ? "&append=1" : ""}${kind ? "&kind=" + kind : ""}`, { headers: { Cookie: cookie, "X-CSRF-Token": csrf, "Content-Type": type }, body: bytes });
    return { status: r.status, ...JSON.parse(r.body || "{}") };
  };
  const getAdmin = (path) => req(AP, "GET", path, { headers: { Cookie: cookie } });
  const postRaw = (path, body) => req(AP, "POST", path, { headers: { Cookie: cookie, "X-CSRF-Token": csrf, "Content-Type": "application/json" }, body, timeout: 30000 });
  return { ok: login.status === 302 && !!csrf, api, upload, getAdmin, postRaw };
}

function decrypt(app, blobB64) {
  const j = JSON.parse(Buffer.from(blobB64, "base64").toString());
  const shared = app.computeSecret(Buffer.from(j.epk, "base64"));
  const key = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.alloc(0), Buffer.from("lewicowyt/push/e2e/v1"), 32));
  const dec = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(j.iv, "base64")); dec.setAuthTag(Buffer.from(j.tag, "base64"));
  return JSON.parse(Buffer.concat([dec.update(Buffer.from(j.ct, "base64")), dec.final()]).toString());
}

// S-01: serwer rozbiera JPEG na segmenty (usuwa metadane), więc fikstury muszą mieć poprawną strukturę:
// SOI, APP0 (JFIF), [dodatkowe segmenty], SOS, dane obrazu (bez 0xFF), EOI
const jpegSeg = (marker, body) => { const h = Buffer.alloc(4); h[0] = 0xff; h[1] = marker; h.writeUInt16BE(body.length + 2, 2); return Buffer.concat([h, body]); };
const jpeg = (dataLen = 400, extra = []) => Buffer.concat([
  Buffer.from([0xff, 0xd8]),
  jpegSeg(0xe0, Buffer.from("JFIF\0\x01\x01\0\0\x01\0\x01\0\0", "latin1")),
  ...extra,
  jpegSeg(0xda, Buffer.from([1, 1, 0, 0, 0x3f, 0])),
  Buffer.from(crypto.randomBytes(dataLen).map((x) => x & 0x7f)),
  Buffer.from([0xff, 0xd9]),
]);

// ===================== przebieg A: serwer bez certyfikatu =====================
const DATA = fs.mkdtempSync(join(os.tmpdir(), "lwyt-srv-"));
const A = await startServer(DATA);
const pw = (A.out().match(/zalogowaniu\):\s*\n\s*(\S+)/) || [])[1];
ok(!!pw, "serwer wystartował i wypisał hasło");

try {
  const { ok: logged, api, upload, getAdmin, postRaw } = await adminSession(pw);
  ok(logged, "logowanie do panelu + token CSRF");
  const get = (host, extra = {}) => req(HP, "GET", "/manifest.json", { headers: { Host: host, ...extra } });
  const onionHost = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz23.onion:2137";
  // jak aplikacja: manifest + każdy plik z `content` (ten sam host), listy sklejone w jeden obiekt
  const LISTS = ["posts", "memes", "articles", "foreignItems", "ads", "contests", "creators"];
  const full = async (host, extra = {}) => {
    const man = JSON.parse((await get(host, extra)).body);
    for (const name of man.content || []) {
      const r = await req(HP, "GET", "/" + name, { headers: { Host: host, ...extra } });
      if (r.status !== 200) { man.__bad = (man.__bad || 0) + 1; continue; }
      const part = JSON.parse(r.body);
      for (const k of LISTS) if (part[k]) man[k] = [...(man[k] || []), ...part[k]];
      if (part.deletions) man.deletions = [...(man.deletions || []), ...part.deletions];
    }
    return man;
  };

  // --- treści ---
  const post = (await api("item/create", { type: "post", author: "Ala", text: "Pierwszy <script>alert(1)</script> post" })).json.item.id;
  const silent = (await api("item/create", { type: "post", author: "Ola", text: "Cichy wpis", notify: false })).json.item.id;
  const meme = (await api("item/create", { type: "meme", title: "Mem" })).json.item.id;
  await upload(meme, "image/webp", Buffer.from("RIFFxxxxWEBP"), false);
  await upload(meme, "image/webp", Buffer.from("RIFFyyyyWEBP"), true);
  const jpgAppend = await upload(meme, "image/jpeg", jpeg(), true);
  const memeJpg = (await api("item/create", { type: "meme", title: "Tylko JPG" })).json.item.id;
  const jpgOnly = await upload(memeJpg, "image/jpeg", jpeg(), false);
  ok(jpgAppend.status === 415 && jpgOnly.status === 415, "JPG/PNG (albo atrapa obrazu) jako obraz wpisu: 415 z wyjaśnieniem, nie po cichu do powiadomienia");
  const jxl = (await api("item/create", { type: "post", author: "J", text: "z JXL", jxlQuality: 85 })).json.item.id;
  await upload(jxl, "image/jxl", Buffer.from([0xff, 0x0a]), false);
  const art = (await api("item/create", { type: "article", title: "Tekst", source: "Gazeta", url: "https://example.org/a/1" })).json.item.id;
  await api("item/create", { type: "foreign", platform: "Twitter", author: "x", text: "tweet", url: "https://x.com/a/status/1" });
  await api("item/create", { type: "creator", name: "Kanał", channelUrl: "https://www.youtube.com/@kanal" });
  await api("item/create", { type: "contest", title: "Konkurs", url: "https://example.org/k", thirdParty: true });
  ok((await api("item/create", { type: "post", author: "A", text: "t", url: "http://example.org" })).status === 400, "link http (nie https) odrzucony przy zapisie");
  ok((await api("item/create", { type: "post", author: "A", text: "t", url: "https://e.org/" + "a".repeat(5000) })).status === 400, "I-11: link > 4096 znaków odrzucony");
  const norm = (await api("item/create", { type: "post", author: "N", text: "norm", url: "  https://EXAMPLE.org/p?q=1  " })).json.item.id;

  // --- manifest per host ---
  const mo = await full(onionHost);
  const ml = await full("192.168.1.50:2137");
  ok(mo.transport === "onion" && mo.push.register === `http://${onionHost}/push/register`, "manifest .onion: transport onion, push na adresie .onion");
  ok(ml.push.register === "http://192.168.1.50:2137/push/register", "manifest LAN (bez adresu HTTPS): push na adresie LAN");
  ok(mo.memes[0]?.images?.every((i) => i.imageUrl.startsWith(`http://${onionHost}/media/`)), "obrazy memu na hoście .onion");
  ok(mo.memes.length === 1 && mo.memes[0].images.length === 2, "mem: karuzela 2× WEBP, mem z samym JPG pominięty");
  ok(mo.memes[0].images[0].notifyImageUrl === mo.memes[0].images[0].imageUrl, "I-13: obraz powiadomienia memu = okładka WEBP");
  const pj = mo.posts.find((p) => p.text === "z JXL");
  ok(pj?.imageUrl?.endsWith(".jxl") && pj.imageQuality === 85, "I-13: JXL ma imageQuality");
  ok(mo.posts.find((p) => p.text === "norm")?.url === "https://example.org/p?q=1", "I-11: link znormalizowany (trim, małe litery hosta)");
  ok(!mo.altEndpoints, ".onion bez altEndpoints");
  const bare = JSON.parse((await get(onionHost)).body);
  ok(!bare.posts && !bare.memes && Array.isArray(bare.content) && bare.content.every((n) => /^post\/([a-f0-9]{16}|usuniecia)\.json$/.test(n)),
    "manifest bez treści — tylko lista plików post/<id>.json (+ ewentualnie post/usuniecia.json)");
  ok(!("deletions" in bare), "manifest minimalny: usunięcia nie leżą w manifeście, tylko w osobnym pliku");
  ok(bare.content.every((n) => n === "post/usuniecia.json" || /^[1-9]d*$/.test(bare.contentVersions?.[n] || "")) && bare.contentVersions[`post/${post}.json`] === "1" && bare.contentVersions[`post/${meme}.json`] === "3",
    "contentVersions: wersja każdego pliku (nowy wpis = 1, mem po 2 zdjęciach = 3)");
  ok(!mo.__bad && mo.content.length === bare.content.length, `każdy wpis to osobny plik (${bare.content.length} plików, wszystkie 200)`);
  ok(!bare.content.some((n) => n.includes(memeJpg)), "mem bez obrazu feedu nie ma pliku w content");
  const dbA = readDb(DATA);
  const rows = dbA.items();
  ok(rows.some((it) => it.id === post && it.text.startsWith("Pierwszy")), `w bazie danych: wiersz na wpis (${rows.length} wpisów w tabeli items)`);
  ok(!fs.existsSync(join(DATA, "data.json")) && !fs.existsSync(join(DATA, "post")) && !fs.existsSync(join(DATA, "media")),
    "na dysku nie ma data.json, post/ ani media/ — wszystko jest w serwer.db");
  ok(!!dbA.main().adminPasswordHash && !("items" in dbA.main()), "w bazie: konfiguracja i skrót hasła osobno od wpisów");
  dbA.close();
  // --- szyfrowanie bazy ---
  const rawBytes = () => Buffer.concat(["serwer.db", "serwer.db-wal"].map((n) => { try { return fs.readFileSync(join(DATA, n)); } catch { return Buffer.alloc(0); } }));
  const rawA = rawBytes();
  ok(rawA.length > 0 && !rawA.includes("Pierwszy") && !rawA.includes("termsText") && !rawA.includes("serverName"),
    "baza jest zaszyfrowana: w plikach serwer.db/-wal nie ma jawnego tekstu wpisu ani konfiguracji");
  ok(fs.existsSync(join(DATA, "klucz-bazy.key")) && fs.existsSync(join(DATA, "szyfrowanie.json")), "klucz główny w pliku klucza obok bazy, ustawienia w szyfrowanie.json");
  const st0 = (await api("crypto/status", {})).json;
  ok(st0.ok && st0.preference === "auto" && st0.active.name === st0.autoWouldChoose && st0.ciphers.length === 6, `szyfr domyślnie wybierany automatycznie: ${st0.active.label} (CPU: ${st0.cpu.model})`);
  ok(st0.autoTrace.length > 0 && st0.ciphers.every((c) => typeof c.accelerated === "boolean" && c.supported), "status: lista szyfrów, wykryte cechy CPU, ślad wyboru automatycznego");
  const bestHw = st0.ciphers.filter((c) => c.accelerated && c.id !== 5 && c.id !== 0).map((c) => c.id);
  ok(!st0.cpu.features.aes || bestHw.length === 0 || st0.active.id === 1 || st0.active.id === 2 || st0.active.id === 3 || st0.active.id === 5,
    "auto wybiera szyfr z listy, a gdy jest sprzętowy AES — nie wybiera szyfru bez przyspieszenia");
  const getPost = async () => JSON.parse((await req(HP, "GET", `/post/${post}.json`)).body).posts[0].text;
  const before = await getPost();
  for (const name of ["chacha20-poly1305", "aes-256-ocb", "aes-256-ctr+hmac-sha256", "aes-128-gcm", "aes-256-gcm"]) {
    const r = (await api("crypto/cipher", { cipher: name })).json;
    ok(r.ok && r.active.name === name && r.preference === name, `wybór szyfru ${name}: baza przepisana (wartości: ${r.rewritten})`);
    const idOf = r.ciphers.find((c) => c.name === name).id;
    ok(r.ciphers.filter((c) => c.id !== idOf).every((c) => c.rows === 0) && r.ciphers.find((c) => c.name === name).rows > 0, "  wszystkie wartości mają nagłówek nowego szyfru");
    ok((await getPost()) === before, "  wpis nadal poprawnie serwowany po zmianie szyfru");
  }
  const mixed = (await api("item/create", { type: "post", author: "A", text: "Po zmianie szyfru", notify: false })).json.item.id;
  const dbMix = readDb(DATA);
  ok(dbMix.items().some((it) => it.id === mixed && it.text === "Po zmianie szyfru") && dbMix.items().some((it) => it.id === post), "odczyt z bazy po zmianach szyfru: stare i nowe wpisy poprawne");
  dbMix.close();
  ok((await api("crypto/cipher", { cipher: "none" })).status === 400, "wyłączenie szyfrowania bez potwierdzenia i hasła jest odrzucone");
  ok((await api("crypto/cipher", { cipher: "szyfr-ktorego-nie-ma" })).status === 400, "nieznany szyfr jest odrzucany");
  const back = (await api("crypto/cipher", { cipher: "auto" })).json;
  ok(back.ok && back.preference === "auto" && back.active.name === st0.autoWouldChoose, "powrót do wyboru automatycznego");
  ok((await req(HP, "GET", "/post/0000000000000000.json")).status === 404, "nieznany wpis → 404");
  ok((await req(HP, "GET", "/post/../data.json")).status === 404, "/post/ nie wychodzi poza wpisy");
  ok(mo.capabilities.includes("foreign_platform_items") && mo.capabilities.includes("community_creators"), "kanoniczne capability + twórcy");
  ok(mo.creators?.[0]?.name === "Kanał" && mo.contests?.[0]?.thirdParty === true, "twórca i konkurs strony trzeciej");
  ok(mo.linkPlatforms?.[0]?.id === "twitter" && mo.linkPlatforms[0].hosts.includes("x.com"), "linkPlatforms wyliczone z pozycji");
  ok(mo.canBePrimary === undefined, "canBePrimary nie jest deklarowane (false)");
  // I-01: nowe wpisy powiadamiają, chyba że operator odznaczył
  ok(mo.posts.find((p) => p.author === "Ala")?.update === "significant", "I-01: nowy wpis → update: significant");
  ok(mo.posts.find((p) => p.author === "Ola")?.update === undefined, "I-01: wpis z odznaczonym „Powiadom” bez update");
  ok(mo.creators[0].update === undefined, "I-01: twórca nigdy nie powiadamia");
  const raw = await get(onionHost);
  ok(!raw.body.includes("\n  "), "I-03: manifest wysyłany kompaktowo");
  ok(raw.headers.vary === "Host", "I-12: Vary: Host");
  ok((await req(HP, "GET", "/manifest.json", { headers: { Host: onionHost, "If-None-Match": raw.headers.etag } })).status === 304, "ETag/304 działa");
  ok(/^"sha256-[0-9a-f]{64}"$/.test(raw.headers.etag), "ETag = SHA-256 manifestu");

  // --- LEP: metody, kodowanie, nieznane tematy ---
  for (const [m, p] of [["PUT", "/lep/pub/aaaaaaaaaaaaaaaaaaaa"], ["GET", "/lep/pub/aaaaaaaaaaaaaaaaaaaa"], ["HEAD", "/lep/sub/aaaaaaaaaaaaaaaaaaaa"], ["POST", "/lep/sub/aaaaaaaaaaaaaaaaaaaa"], ["DELETE", "/lep/sub/aaaaaaaaaaaaaaaaaaaa"]]) {
    const r = await req(HP, m, p, { timeout: 3000 });
    ok(r.status === 405, `I-06: ${m} ${p.slice(0, 9)}… → 405 (było: brak odpowiedzi)`);
  }
  ok((await req(HP, "GET", "/media/%E0%A4%A")).status === 400, "I-14: zepsute %-kodowanie /media → 400");
  ok((await req(HP, "GET", "/lep/sub/%E0%A4%A")).status === 400, "I-14: zepsute %-kodowanie /lep → 400");
  const unknownSub = await req(HP, "GET", "/lep/sub/obcytematobcytematobcy?wait=0");
  ok(unknownSub.status === 200 && JSON.parse(unknownSub.body).msgs.length === 0, "I-08: nieznany temat (wait=0) → pusto, bez błędu");
  ok((await req(HP, "POST", "/lep/pub/obcytematobcytematobcy", { body: "x" })).status === 404, "I-08: publikacja z zewnątrz do niezarejestrowanego tematu → 404");

  // --- push: SSRF + LEP + bez klucza ---
  const app = crypto.createECDH("prime256v1"); const pub = app.generateKeys().toString("base64");
  const reg = (endpoint, pubkey = pub) => req(HP, "POST", "/push/register", { headers: { "Content-Type": "application/json" }, body: JSON.stringify(pubkey ? { endpoint, pubkey } : { endpoint }) });
  ok((await reg("http://127.0.0.1:23138/admin/api/config")).status === 400, "SSRF: http na loopback odrzucony");
  ok((await reg("https://192.168.1.1/x")).status === 400, "SSRF: https na adres prywatny odrzucony");
  ok((await reg("https://localhost/x")).status === 400, "SSRF: localhost odrzucony");
  ok((await reg("https://[64:ff9b::7f00:1]/x")).status === 400, "I-07: NAT64 na loopback odrzucony");
  ok((await reg("https://push.example.com:8443/x")).status === 400, "I-07: port inny niż 443 odrzucony");
  ok((await reg("https://localtest.me/x")).status === 400, "I-07: nazwa DNS wskazująca 127.0.0.1 odrzucona");
  ok((await reg("https://127.0.0.1.nip.io/x")).status === 400, "I-07: nip.io na loopback odrzucony");
  const topic = crypto.randomBytes(18).toString("base64url");
  ok((await reg(`http://${onionHost}/lep/pub/${topic}`)).status === 200, "endpoint LEP (.onion) przyjęty");
  const topicPlain = crypto.randomBytes(18).toString("base64url");
  ok((await reg(`http://${onionHost}/lep/pub/${topicPlain}`, null)).status === 200, "I-09: rejestracja bez pubkey przyjęta");
  await api("item/publish", {});
  await wait(4000);
  const sub = JSON.parse((await req(HP, "GET", `/lep/sub/${topic}?after=0&wait=0`)).body);
  ok(sub.msgs?.length === 1, "budzik doręczony LOKALNIE do kolejki LEP (bez HTTP do .onion)");
  if (sub.msgs?.[0]) ok(decrypt(app, sub.msgs[0].data).t === "significant", "budzik odszyfrowany kluczem aplikacji");
  const subPlain = JSON.parse((await req(HP, "GET", `/lep/sub/${topicPlain}?after=0&wait=0`)).body);
  ok(subPlain.msgs?.[0]?.data === '{"t":"1"}', "I-09: subskrybent bez klucza dostaje jawny {\"t\":\"1\"}");
  ok((await req(HP, "POST", `/lep/pub/${topic}`, { body: "z zewnatrz" })).status === 200, "publikacja do zarejestrowanego tematu działa");
  const unreg = await req(HP, "POST", "/push/unregister", { headers: { "Content-Type": "application/json" }, body: JSON.stringify({ endpoint: "https://nieznany.example/x" }) });
  ok(unreg.status === 200, "unregister nieznanego adresu = 200 (idempotentnie)");

  // --- update + deletions (link własny) ---
  await api("item/update", { id: art, type: "article", title: "Tekst v2", source: "Gazeta", url: "https://example.org/a/1", significant: true });
  let m = await full(onionHost);
  ok(m.articles[0].update === "significant" && m.articles[0].title === "Tekst v2", "edycja z flagą istotnej zmiany → update: significant");
  ok(m.content[m.content.length - 1] === `post/${art}.json` && m.contentVersions[`post/${art}.json`] === "2",
    "edycja → ta sama nazwa pliku, wersja 2 w contentVersions, na końcu content (aplikacja pobierze ponownie)");
  await api("item/update", { id: art, type: "article", title: "Tekst v3", source: "Gazeta", url: "https://example.org/a/2" });
  m = await full(onionHost);
  ok(m.deletions?.includes("https://example.org/a/1") && m.articles[0].update === "minor", "zmiana linku → stary link w deletions, drobna zmiana = minor");
  await api("item/delete", { id: art });
  m = await full(onionHost);
  ok(m.deletions.includes("https://example.org/a/2") && !m.articles, "usunięcie → link w deletions, wpis zniknął");

  // --- strona /e/<id> ---
  const pl = await req(HP, "GET", `/e/${post}`);
  ok(pl.status === 200 && pl.body.includes("&lt;script&gt;") && !pl.body.includes("<script>alert"), "strona /e/<id> działa i escapuje HTML");
  ok((await req(HP, "GET", "/e/../../etc")).status === 404, "/e/ z dziwną ścieżką → 404");
  ok((await req(HP, "GET", "/admin")).status === 404, "panel niedostępny na porcie publicznym");

  // --- reverse proxy z TLS (X-Forwarded-Proto z loopbacku) ---
  { const fut = (await api("item/create", { type: "post", author: "Z", text: "Zaplanowany wpis", publishedAt: Date.now() + 3_600_000, notify: false })).json.item.id;
    ok((await req(HP, "GET", "/e/" + fut)).status === 404 && (await req(HP, "GET", "/post/" + fut + ".json")).status === 404, "A-18: zaplanowany wpis nie jest dostępny ani pod /e/<id>, ani jako plik treści");
    await api("item/delete", { id: fut }); }
  // audyt A-01: bez domeny w panelu obcy Host + X-Forwarded-Proto NIE zmienia adresu kanonicznego serwera
  await req(HP, "GET", "/manifest.json", { headers: { Host: "evil-attacker.example", "X-Forwarded-Proto": "https" } });
  const stAtk = JSON.parse((await getAdmin("/admin/api/state")).body);
  ok(!stAtk.config.canonicalHttpsBase && !stAtk.httpsBase, "A-01: obcy Host + X-Forwarded-Proto nie podmienia adresu kanonicznego (bez domeny w panelu)");
  await api("config", { domain: "example.org" });
  const proxied = await full("example.org", { "X-Forwarded-Proto": "https" });
  const silentLink = proxied.posts.find((p) => p.author === "Ola")?.url;
  ok(silentLink === `https://example.org/e/${silent}`, "proxy: stały link /e/<id> na adresie HTTPS");
  ok(proxied.push.register === "https://example.org/push/register", "proxy: push na adresie HTTPS");
  await api("item/delete", { id: silent });
  m = await full("example.org", { "X-Forwarded-Proto": "https" });
  ok(m.deletions.includes(`https://example.org/e/${silent}`), "I-02: usunięcie za proxy → /e/<id> w deletions");
  // I-05: po poznaniu adresu HTTPS żądanie z IP LAN dostaje adresy kanoniczne
  const lan = await full("192.168.1.50:2137");
  ok(lan.memes?.[0]?.images?.[0]?.imageUrl.startsWith("https://example.org/media/"), "I-05: manifest dla adresu LAN ma obrazy na hoście kanonicznym");
  ok(lan.posts.find((p) => p.author === "Ala")?.url === `https://example.org/e/${post}`, "I-05: wpis bez linku ma ten sam klucz /e/<id> przez LAN");
  const onionAfter = await full(onionHost);
  ok(!JSON.stringify(onionAfter).includes("example.org/e/") && onionAfter.push.register.includes(".onion"), "domena NIE trafia do manifestu .onion");

  // ===== nowe funkcje (punkty 1–8) =====
  const JPG = jpeg(400);
  const PNG = Buffer.from("89504e470d0a1a0a0000000d49484452", "hex");
  const lastWake = async (t, after = 0) => {
    const r = JSON.parse((await req(HP, "GET", `/lep/sub/${t}?after=${after}&wait=0`)).body);
    return r.msgs || [];
  };
  const t2 = crypto.randomBytes(18).toString("base64url");
  ok((await reg(`http://${onionHost}/lep/pub/${t2}`)).status === 200, "nowy temat LEP do testów budzików");

  // 4: weryfikacja formatu po bajtach
  const vp = (await api("item/create", { type: "post", author: "V", text: "format", notify: false })).json.item.id;
  const fake = await upload(vp, "image/webp", PNG);
  ok(fake.status === 415 && /PNG/.test(fake.error || ""), "4: PNG udający WEBP odrzucony (rozpoznany po bajtach)");
  ok((await upload(vp, "image/webp", Buffer.from("RIFFxxxxWEBP"))).status === 200, "4: prawdziwy WEBP przyjęty");

  // 2 + 1: automatyczny budzik po dodaniu wpisu, z miniaturą w środku
  const before2 = (await lastWake(t2)).length;
  const auto = (await api("item/create", { type: "post", author: "Auto", text: "z miniaturą" })).json.item.id;
  const th = await upload(auto, "image/jpeg", JPG, false, "thumb");
  ok(th.status === 200 && !th.warning, "1: miniatura powiadomienia przyjęta (mieści się w budziku)");
  await wait(4500);
  const w2 = await lastWake(t2);
  ok(w2.length > before2, "2: budzik wysłany SAM po dodaniu istotnego wpisu (bez przycisku)");
  const pt2 = w2.length ? decrypt(app, w2[w2.length - 1].data) : {};
  ok(pt2.img === JPG.toString("base64"), "1: budzik niesie miniaturę (img) — apka nie musi jej pobierać");
  const thumbUrl = (await full(onionHost)).posts.find((p) => p.author === "Auto")?.notifyImageUrl || "";
  ok(thumbUrl.endsWith(".jpg") && thumbUrl.includes(".onion"), "1: miniatura jest też obrazem powiadomienia w treści wpisu");
  const big = await upload(vp, "image/jpeg", jpeg(9400), false, "thumb");
  ok(big.status === 200 && /KB/.test(big.warning || ""), "1: za duża miniatura → ostrzeżenie (nie trafi do budzika)");

  // 3: awatar autora posta
  ok((await upload(auto, "image/webp", Buffer.from("RIFFzzzzWEBP"), false, "avatar")).status === 200, "3: awatar autora wgrany");
  ok(((await full(onionHost)).posts.find((p) => p.author === "Auto")?.authorImageUrl || "").endsWith(".webp"), "3: authorImageUrl w treści posta");
  ok((await upload(auto, "image/jpeg", JPG, false, "avatar")).status === 415, "3: awatar w JPG odrzucony (apka pokazuje tylko WEBP/JXL/AVIF)");

  // dźwięk Opus: minimalny Ogg (nagłówki wystarczą do rozpoznania i długości: 2 s przy pre-skip 312)
  const granule = Buffer.alloc(8); granule.writeBigInt64LE(BigInt(48000 * 2 + 312));
  const OPUS = Buffer.concat([Buffer.from("OggS"), Buffer.alloc(24), Buffer.from("OpusHead"), Buffer.from([1, 1, 0x38, 0x01]), Buffer.alloc(40),
    Buffer.from("OggS"), Buffer.from([0, 4]), granule, Buffer.alloc(16)]);
  const au = await upload(auto, "audio/ogg", OPUS, false, "audio");
  ok(au.status === 200 && au.audio?.durationMs === 2000, `dźwięk: Opus przyjęty, długość odczytana z nagłówków (${au.audio?.durationMs} ms)`);
  await api("item/update", { id: auto, type: "post", author: "Auto", text: "z miniaturą", audioTitle: "Odcinek 1" });
  const withAudio = (await full(onionHost)).posts.find((p) => p.author === "Auto");
  ok(withAudio?.audio?.url?.startsWith(`http://${onionHost}/media/`) && withAudio.audio.url.endsWith(".opus") && withAudio.audio.durationMs === 2000 && withAudio.audio.title === "Odcinek 1",
    "dźwięk: pole audio {url na hoście manifestu, durationMs, title} w treści posta");
  ok((await upload(auto, "audio/ogg", PNG, false, "audio")).status === 415, "dźwięk: plik niebędący Opusem odrzucony (sprawdzenie po bajtach)");
  const aMedia = await req(HP, "GET", "/media/" + withAudio.audio.url.split("/media/")[1]);
  ok(aMedia.status === 200 && aMedia.headers["content-type"] === "audio/ogg", "dźwięk: plik serwowany jako audio/ogg");
  ok((await req(HP, "GET", `/e/${auto}`)).body.includes("<audio controls"), "dźwięk: strona /e/<id> ma odtwarzacz dla czytelników spoza aplikacji");

  // wideo: syntetyczne nagłówki MP4 (ftyp + moov/trak z hdlr vide, mdhd, stsd, stts) — tyle czyta serwer
  const box = (type, ...parts) => { const body = Buffer.concat(parts); const h = Buffer.alloc(8); h.writeUInt32BE(8 + body.length); h.write(type, 4, "latin1"); return Buffer.concat([h, body]); };
  const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
  const mp4 = (fourcc, fps, seconds, w = 1280, h = 720, sound = null) => {
    const entry = Buffer.alloc(86); entry.writeUInt32BE(86); entry.write(fourcc, 4, "latin1"); entry.writeUInt16BE(w, 32); entry.writeUInt16BE(h, 34);
    const mdhd = Buffer.alloc(24); mdhd.writeUInt32BE(1000, 12); mdhd.writeUInt32BE(seconds * 1000, 16);
    const hdlr = Buffer.alloc(24); hdlr.write("vide", 8, "latin1");
    const stbl = box("stbl", box("stsd", u32(0), u32(1), entry), box("stts", u32(0), u32(1), u32(fps * seconds), u32(1000 / fps | 0)));
    // opcjonalna ścieżka dźwiękowa (hdlr soun + stsd z kodekiem, np. "mp4a" = AAC, "Opus")
    const sHdlr = Buffer.alloc(24); sHdlr.write("soun", 8, "latin1");
    const sEntry = Buffer.alloc(36); sEntry.writeUInt32BE(36); sEntry.write(sound || "Opus", 4, "latin1");
    const soundTrak = sound ? box("trak", box("mdia", box("mdhd", mdhd), box("hdlr", sHdlr), box("minf", box("stbl", box("stsd", u32(0), u32(1), sEntry))))) : Buffer.alloc(0);
    return Buffer.concat([box("ftyp", Buffer.from("isom"), u32(512)), box("moov", box("trak", box("mdia", box("mdhd", mdhd), box("hdlr", hdlr), box("minf", stbl))), soundTrak), box("mdat", Buffer.alloc(64))]);
  };
  const vh = await upload(auto, "video/mp4", mp4("hvc1", 30, 4), false, "video_hevc");
  ok(vh.status === 200 && vh.video?.hevc?.fps === 30 && vh.video.durationMs === 4000, "wideo: H.265 30 kl/s przyjęty (kl/s i długość z nagłówków MP4)");
  ok((await upload(auto, "video/mp4", mp4("avc1", 25, 4, 854, 480), false, "video_avc")).status === 200, "wideo: zapasowy H.264 przyjęty");
  const v60 = await upload(auto, "video/mp4", mp4("hvc1", 60, 4), false, "video_hevc");
  ok(v60.status === 415 && /60/.test(v60.error || ""), "wideo: 60 kl/s odrzucone przy wgrywaniu (limit 30)");
  ok((await upload(auto, "video/mp4", mp4("avc1", 30, 4), false, "video_hevc")).status === 415, "wideo: H.264 w polu H.265 odrzucony (zły kodek)");
  ok((await upload(auto, "video/mp4", PNG, false, "video_avc")).status === 415, "wideo: plik niebędący MP4 odrzucony");
  const aac = await upload(auto, "video/mp4", mp4("hvc1", 30, 4, 1280, 720, "mp4a"), false, "video_hevc");
  ok(aac.status === 415 && /AAC/.test(aac.error || ""), "tylko Opus: film z dźwiękiem AAC odrzucony");
  ok((await upload(auto, "video/mp4", mp4("hvc1", 30, 4, 1280, 720, "Opus"), false, "video_hevc")).status === 200, "tylko Opus: film z dźwiękiem Opus przyjęty");
  const vpost = (await full(onionHost)).posts.find((p) => p.author === "Auto")?.video || {};
  ok(vpost.hevc?.url?.endsWith(".mp4") && vpost.hevc.url.includes(".onion") && vpost.hevc.fps === 30 && vpost.avc?.width === 854 && vpost.durationMs === 4000,
    "wideo: pole video {hevc, avc, durationMs} w treści posta, na hoście manifestu");
  ok((await req(HP, "GET", `/e/${auto}`)).body.includes("<video controls"), "wideo: strona /e/<id> ma odtwarzacz przeglądarki");

  // faststart: plik z moov NA KOŃCU (domyślne wyjście ffmpeg) — serwer przenosi spis na początek i przesuwa
  // przesunięcia porcji (stco), żeby aplikacja mogła sprawdzić film z pierwszych KB i przerwać zły plik
  {
    const entry = Buffer.alloc(86); entry.writeUInt32BE(86); entry.write("avc1", 4, "latin1"); entry.writeUInt16BE(640, 32); entry.writeUInt16BE(360, 34);
    const mdhd = Buffer.alloc(24); mdhd.writeUInt32BE(1000, 12); mdhd.writeUInt32BE(4000, 16);
    const hdlr = Buffer.alloc(24); hdlr.write("vide", 8, "latin1");
    const ftyp = box("ftyp", Buffer.from("isom"), u32(512));
    const mdat = box("mdat", Buffer.from("DANE-FILMU".repeat(8)));
    const dataAt = ftyp.length + 8; // pierwszy bajt danych w mdat
    const stbl = box("stbl", box("stsd", u32(0), u32(1), entry), box("stts", u32(0), u32(1), u32(120), u32(33)), box("stco", u32(0), u32(1), u32(dataAt)));
    const moov = box("moov", box("trak", box("mdia", box("mdhd", mdhd), box("hdlr", hdlr), box("minf", stbl))));
    const r = await upload(auto, "video/mp4", Buffer.concat([ftyp, mdat, moov]), false, "video_avc");
    ok(r.status === 200, "faststart: film z moov na końcu przyjęty");
    const vfile = (await full(onionHost)).posts.find((p) => p.author === "Auto")?.video?.avc?.url || "";
    const got = (await req(HP, "GET", "/media/" + vfile.split("/media/")[1])).raw || Buffer.alloc(0);
    const t2 = got.toString("latin1", ftyp.length + 4, ftyp.length + 8);
    const stcoAt = got.indexOf("stco", 0, "latin1");
    const off = stcoAt > 0 ? got.readUInt32BE(stcoAt + 12) : -1;
    ok(t2 === "moov" && got.toString("latin1", off, off + 10) === "DANE-FILMU",
      "faststart: serwowany plik ma moov zaraz za ftyp, a stco nadal wskazuje dane w mdat");
  }

  // ===== S-01: metadane (EXIF/GPS, XMP, lokalizacja filmu) usuwane przy wgrywaniu =====
  {
    const mediaOf = async (file) => (await req(HP, "GET", "/media/" + file)).raw || Buffer.alloc(0);
    const s1 = (await api("item/create", { type: "post", author: "Meta", text: "metadane", notify: false })).json.item.id;
    const exif = jpegSeg(0xe1, Buffer.from("Exif\0\0GPSLatitude=52.2297N", "latin1"));
    const icc = jpegSeg(0xe2, Buffer.from("ICC_PROFILE\0\x01\x01profil", "latin1"));
    const withExif = jpeg(300, [exif, icc, jpegSeg(0xfe, Buffer.from("komentarz autora"))]);
    const tail = Buffer.concat([withExif, Buffer.from("\xff\xd8MPF-drugie-zdjecie-GPS", "latin1")]);
    const rj = await upload(s1, "image/jpeg", tail, false, "thumb");
    const gotJ = await mediaOf(rj.thumb);
    ok(rj.status === 200 && !gotJ.includes("GPSLatitude") && !gotJ.includes("komentarz") && !gotJ.includes("MPF-drugie"),
      "S-01: JPEG bez EXIF/GPS, komentarza i danych za końcem obrazu");
    ok(gotJ.includes("ICC_PROFILE") && gotJ[0] === 0xff && gotJ[1] === 0xd8 && gotJ.subarray(-2).equals(Buffer.from([0xff, 0xd9])),
      "S-01: JPEG nadal poprawny (SOI…EOI), profil kolorów ICC zostaje");
    // WEBP: VP8X z flagami EXIF+XMP, chunk EXIF i XMP
    const chunk = (t, body) => { const h = Buffer.alloc(8); h.write(t, 0, "latin1"); h.writeUInt32LE(body.length, 4); return Buffer.concat([h, body, body.length & 1 ? Buffer.alloc(1) : Buffer.alloc(0)]); };
    const vp8x = Buffer.alloc(10); vp8x[0] = 0x08 | 0x04;
    const wbody = Buffer.concat([chunk("VP8X", vp8x), chunk("VP8L", Buffer.from("obraz-bezstratny")), chunk("EXIF", Buffer.from("GPS-WEBP")), chunk("XMP ", Buffer.from("<x:xmpmeta/>"))]);
    const whead = Buffer.alloc(12); whead.write("RIFF", 0, "latin1"); whead.writeUInt32LE(wbody.length + 4, 4); whead.write("WEBP", 8, "latin1");
    const rw = await upload(s1, "image/webp", Buffer.concat([whead, wbody]), false, "avatar");
    const gotW = await mediaOf(rw.avatar);
    const vflags = gotW[12 + 8];
    ok(rw.status === 200 && !gotW.includes("GPS-WEBP") && !gotW.includes("xmpmeta") && gotW.includes("obraz-bezstratny") && (vflags & 0x0c) === 0 && gotW.readUInt32LE(4) === gotW.length - 8,
      "S-01: WEBP bez EXIF/XMP, flagi VP8X wyzerowane, rozmiar RIFF poprawny");
    // PNG: tEXt z lokalizacją
    const crc = Buffer.alloc(4);
    const pchunk = (t, body) => { const h = Buffer.alloc(8); h.writeUInt32BE(body.length); h.write(t, 4, "latin1"); return Buffer.concat([h, body, crc]); };
    const png = Buffer.concat([Buffer.from("89504e470d0a1a0a", "hex"), pchunk("IHDR", Buffer.alloc(13)), pchunk("tEXt", Buffer.from("Location\0Warszawa")), pchunk("IDAT", Buffer.from("piksele")), pchunk("IEND", Buffer.alloc(0))]);
    const rp = await upload(s1, "image/png", png, false, "thumb");
    const gotP = await mediaOf(rp.thumb);
    ok(rp.status === 200 && !gotP.includes("Warszawa") && gotP.includes("piksele") && gotP.includes("IEND"), "S-01: PNG bez tEXt (lokalizacja)");
    // MP4: lokalizacja w moov/udta (©xyz) i moov/meta, moov na końcu — po faststart i usunięciu stco dalej trafia w dane
    const entry = Buffer.alloc(86); entry.writeUInt32BE(86); entry.write("avc1", 4, "latin1"); entry.writeUInt16BE(640, 32); entry.writeUInt16BE(360, 34);
    const mdhd = Buffer.alloc(24); mdhd.writeUInt32BE(1000, 12); mdhd.writeUInt32BE(4000, 16);
    const hdlr = Buffer.alloc(24); hdlr.write("vide", 8, "latin1");
    const ftyp = box("ftyp", Buffer.from("isom"), u32(512));
    const mdat = box("mdat", Buffer.from("KLATKI-FILMU".repeat(6)));
    const dataAt = ftyp.length + 8;
    const stbl = box("stbl", box("stsd", u32(0), u32(1), entry), box("stts", u32(0), u32(1), u32(120), u32(33)), box("stco", u32(0), u32(1), u32(dataAt)));
    const udta = box("udta", box("\xa9xyz", Buffer.from("+52.2297+021.0122/", "latin1")));
    const moov = box("moov", box("trak", box("mdia", box("mdhd", mdhd), box("hdlr", hdlr), box("minf", stbl)), box("udta", Buffer.from("trak-meta"))), udta, box("meta", Buffer.from("com.apple.quicktime.location")));
    const rv = await upload(s1, "video/mp4", Buffer.concat([ftyp, mdat, moov]), false, "video_avc");
    const gotV = await mediaOf(rv.video?.avc?.file || "x");
    const stcoAt = gotV.indexOf("stco", 0, "latin1");
    const off = stcoAt > 0 ? gotV.readUInt32BE(stcoAt + 12) : -1;
    ok(rv.status === 200 && !gotV.includes("+52.2297") && !gotV.includes("quicktime.location") && !gotV.includes("trak-meta"),
      "S-01: MP4 bez udta/meta (lokalizacja ©xyz, metadane Apple) w moov i trak");
    ok(gotV.toString("latin1", off, off + 12) === "KLATKI-FILMU" && rv.video.avc.bytes === gotV.length,
      "S-01: MP4 po usunięciu metadanych — stco wskazuje dane, bytes = rozmiar pliku");
  }

  // ===== S-02: drobna poprawka nie zdejmuje `significant` ze świeżego wpisu ze stałym linkiem =====
  {
    const fileOf = async (id) => JSON.parse((await req(HP, "GET", `/post/${id}.json`, { headers: { Host: onionHost } })).body).posts[0];
    const linked = (await api("item/create", { type: "post", author: "Link", text: "literówak", url: "https://example.org/p/s02", notify: true })).json.item.id;
    await api("item/update", { id: linked, type: "post", author: "Link", text: "literówka", url: "https://example.org/p/s02" });
    ok((await fileOf(linked)).update === "significant", "S-02: poprawka literówki — wpis ze stałym linkiem nadal `significant` (urządzenia, które go nie pobrały, dostaną powiadomienie)");
    await api("item/update", { id: linked, type: "post", author: "Link", text: "literówka", url: "https://example.org/p/inny" });
    ok((await fileOf(linked)).update === "minor", "S-02: zmiana linku (nowa tożsamość w apce) → minor, bez drugiego powiadomienia");
  }

  // ===== S-03: budzik wstrzymany do końca wgrywania (deferNotify + item/ready) =====
  {
    await wait(4000); // budziki z poprzednich kroków już poszły
    const base3 = (await lastWake(t2)).length;
    const dm = (await api("item/create", { type: "meme", title: "Mem z opóźnionym budzikiem", deferNotify: true })).json.item.id;
    await wait(4500);
    ok((await lastWake(t2)).length === base3, "S-03: wstrzymany budzik nie wychodzi przed wgraniem obrazu");
    await upload(dm, "image/webp", Buffer.from("RIFF\x04\0\0\0WEBP", "latin1"), false);
    await upload(dm, "image/jpeg", jpeg(200), false, "thumb");
    ok((await api("item/ready", { id: dm })).status === 200, "S-03: item/ready przyjęte");
    await wait(4500);
    const w3 = await lastWake(t2);
    ok(w3.length > base3, "S-03: budzik po item/ready");
    const p3 = w3.length ? decrypt(app, w3[w3.length - 1].data) : {};
    ok(!!p3.img, "S-03: budzik niesie miniaturę wgraną PO zapisie wpisu");
  }

  // 2: planowanie publikacji
  const sched = (await api("item/create", { type: "post", author: "Plan", text: "zaplanowany", publishedAt: Date.now() + 6000 }));
  const schedId = sched.json.item.id;
  ok(sched.json.scheduled === true, "2: wpis z datą w przyszłości oznaczony jako zaplanowany");
  ok(!(await full(onionHost)).posts.some((p) => p.author === "Plan"), "2: zaplanowany wpis niewidoczny przed czasem");
  ok((await req(HP, "GET", `/post/${schedId}.json`)).status === 404, "2: plik zaplanowanego wpisu niedostępny przed czasem");
  const before3 = (await lastWake(t2)).length;
  await wait(28000); // tick harmonogramu co 20 s
  ok((await full(onionHost)).posts.some((p) => p.author === "Plan"), "2: zaplanowany wpis pojawia się o czasie");
  ok((await lastWake(t2)).length > before3, "2: zaplanowany wpis dostał budzik o czasie publikacji");

  // 6: ręczne platformy linków
  await api("config", { linkPlatformsText: "twitch | Twitch | https://www.twitch.tv/x\nzle id!! |  | " });
  const lp = (await full(onionHost)).linkPlatforms || [];
  ok(lp[0]?.id === "twitch" && lp[0].hosts[0] === "twitch.tv" && lp.some((p) => p.id === "twitter"), "6: ręczne platformy linków + automatyczne z wpisów");

  // 7: rozmywanie prawdziwych budzików
  await api("config", { realJitterSec: 3 });
  const before4 = (await lastWake(t2)).length;
  await api("item/publish", {});
  await wait(1500);
  const mid = (await lastWake(t2)).length;
  await wait(6000);
  ok((await lastWake(t2)).length > before4, `7: budzik z rozmyciem doszedł w oknie 0–3 s (po 1,5 s: ${mid > before4 ? "już był" : "jeszcze nie"})`);
  await api("config", { realJitterSec: 0, decoyPerDay: 0 });

  // 8: statystyki subskrybentów
  const st = JSON.parse((await getAdmin("/admin/api/state")).body).subscriberStats;
  ok(st && st.lep >= 2 && st.withoutKey >= 1 && st.active24h >= 2 && typeof st.external === "number", `8: statystyki subskrybentów (LEP ${st?.lep}, bez E2E ${st?.withoutKey}, aktywni 24 h ${st?.active24h})`);

  // 5: kopia zapasowa — eksport, usunięcie, import
  ok((await getAdmin("/admin/api/export")).status === 403 || (await getAdmin("/admin/api/export")).status === 404, "A-34: GET /admin/api/export nie istnieje (kopia tylko przez POST z hasłem)");
  ok((await api("export", { adminPassword: "zle-haslo" })).status === 400, "A-34: pobranie kopii wymaga hasła administratora");
  const exp = await postRaw("/admin/api/export", JSON.stringify({ adminPassword: pw }));
  const backup = JSON.parse(exp.body || "{}");
  ok(exp.status === 200 && backup.format === "lewicowyt-community-backup" && backup.data.items.length > 5 && Object.keys(backup.media).length > 3 && !("adminPasswordHash" in backup.data),
    `5: eksport kopii (wpisów ${backup.data?.items?.length}, obrazów ${Object.keys(backup.media || {}).length}, bez hasła)`);
  await api("item/delete", { id: auto });
  ok(!(await full(onionHost)).posts.some((p) => p.author === "Auto"), "5: wpis usunięty przed importem");
  const imp = await postRaw("/admin/api/import", exp.body);
  ok(imp.status === 200 && JSON.parse(imp.body).items === backup.data.items.length, "5: import kopii");
  ok((await full(onionHost)).posts.find((p) => p.author === "Auto")?.authorImageUrl, "5: po imporcie wpis i jego obrazy wróciły");
  ok((await postRaw("/admin/api/import", '{"format":"cos innego"}')).status === 400, "5: obcy plik odrzucony przy imporcie");

  // --- limit tempa rejestracji (na końcu — zużywa kubełek) ---
  const codes = [];
  for (let i = 0; i < 260; i++) codes.push((await reg(`http://x/lep/pub/${crypto.randomBytes(12).toString("hex")}`)).status);
  ok(codes.includes(429) && codes.filter((c) => c === 200).length >= 150, `I-08: limit tempa rejestracji (200 OK: ${codes.filter((c) => c === 200).length}, 429: ${codes.filter((c) => c === 429).length})`);
  // 5: wyloguj wszystkie sesje
  const sess2 = await adminSession(pw);
  await sess2.api("sessions/logout-all", {});
  ok((await getAdmin("/admin/api/state")).status === 401, "5: „wyloguj wszystkie sesje” unieważnia też inne sesje");
} catch (e) {
  console.log("  FAIL wyjątek:", e.stack);
  failures++;
} finally {
  A.child.kill();
}

// 5: reset hasła z konsoli (serwer zatrzymany)
await wait(500);
const hashOf = () => { const d = readDb(DATA); try { return d.main().adminPasswordHash; } finally { d.close(); } };
const hashBefore = hashOf();
const reset = spawnSync(process.execPath, ["server.js", "--reset-password"], { cwd: SRV, env: { ...process.env, DATA_DIR: DATA }, encoding: "utf8", timeout: 20000 });
const newPw = (reset.stdout.match(/stare przestalo dzialac\):\s*\n\s*(\S+)/) || [])[1];
ok(reset.status === 0 && !!newPw && hashOf() !== hashBefore,
  "5: --reset-password nadaje nowe hasło i kończy bez uruchamiania serwera");

// ===================== przebieg B: certyfikat → HTTPS i HTTP na tym samym porcie (I-04) =====================
const DATA_B = fs.mkdtempSync(join(os.tmpdir(), "lwyt-srv-tls-"));
const openssl = spawnSync("openssl", ["version"], { encoding: "utf8" });
if (openssl.status === 0) {
  fs.mkdirSync(join(DATA_B, "cert"), { recursive: true });
  const gen = spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "365",
    "-subj", "/CN=test.example", "-keyout", join(DATA_B, "cert", "test.example.key"), "-out", join(DATA_B, "cert", "test.example.crt")], { encoding: "utf8" });
  fs.writeFileSync(join(DATA_B, "data.json"), JSON.stringify({ config: { serverName: "TLS", termsText: "T", domain: "test.example" } }));
  if (gen.status === 0) {
    const B = await startServer(DATA_B);
    try {
      await wait(800);
      const t = await req(HP, "GET", "/manifest.json", { tls: true, servername: "test.example", headers: { Host: "test.example:2137" } });
      ok(t.status === 200 && JSON.parse(t.body).push.register === "https://test.example:2137/push/register", "I-04: HTTPS na porcie 2137 (ten sam co HTTP)");
      const h = await req(HP, "GET", "/manifest.json", { headers: { Host: "10.0.0.5:2137" } });
      ok(h.status === 200, "I-04: zwykły HTTP na tym samym porcie dalej działa");
      const dbB = readDb(DATA_B);
      ok(!!dbB.file("cert/test.example.crt") && !fs.existsSync(join(DATA_B, "data.json")) && fs.existsSync(join(DATA_B, "stare-przed-baza")),
        "migracja: certyfikat z cert/ trafił do bazy, stare pliki odłożone do stare-przed-baza/");
      dbB.close();
      ok(JSON.parse(h.body).push.register.startsWith("https://test.example"), "I-05: z certyfikatem manifest dla LAN ma adresy kanoniczne");
    } finally {
      B.child.kill();
    }
  } else ok(false, "nie udało się wygenerować certyfikatu testowego: " + gen.stderr);
} else {
  console.log("  SKIP I-04 (brak openssl)");
}

// ===================== przebieg D: migracja układu plikowego (≤ 1.9.0) do bazy danych =====================
{
  const DATA_D = fs.mkdtempSync(join(os.tmpdir(), "lwyt-srv-mig-"));
  const pid = "0123456789abcdef";
  fs.mkdirSync(join(DATA_D, "post"), { recursive: true });
  fs.mkdirSync(join(DATA_D, "media"), { recursive: true });
  fs.writeFileSync(join(DATA_D, "data.json"), JSON.stringify({ config: { serverName: "Stary", termsText: "T" }, deletions: [{ url: "https://example.org/stary", at: 1 }], push: { subscribers: { "https://ntfy.example/abc": { pubkey: null, at: 1, seenAt: 1 } } } }));
  fs.writeFileSync(join(DATA_D, "post", pid + ".json"), JSON.stringify({ id: pid, type: "post", author: "Autor", text: "Stary wpis z pliku", url: "https://example.org/stary-wpis", publishedAt: 1, createdAt: 1, images: [], rev: 1 }, null, 2));
  fs.writeFileSync(join(DATA_D, "media", "stary.webp"), Buffer.from("RIFF\x04\x00\x00\x00WEBPVP8 ", "latin1"));
  const bigMedia = crypto.randomBytes(2_600_000);
  fs.writeFileSync(join(DATA_D, "media", "duzy.webp"), bigMedia);
  const D = await startServer(DATA_D);
  try {
    await wait(800);
    const man = JSON.parse((await req(HP, "GET", "/manifest.json", { headers: { Host: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz23.onion:2137" } })).body);
    ok(man.name === "Stary" && man.content.includes("post/" + pid + ".json"), "migracja: konfiguracja i wpis z plików są w manifeście");
    const pf = JSON.parse((await req(HP, "GET", "/post/" + pid + ".json")).body);
    ok(pf.posts?.[0]?.text === "Stary wpis z pliku", "migracja: plik wpisu serwowany z bazy");
    const mr = await req(HP, "GET", "/media/stary.webp");
    ok(mr.status === 200 && mr.headers["content-type"] === "image/webp" && Number(mr.headers["content-length"]) === mr.raw.length, "migracja: multimedia serwowane z bazy (Content-Length zgodny)");
    ok((await req(HP, "HEAD", "/media/nie-ma.webp")).status === 404, "brak pliku w bazie → 404");
    const bigRes = await req(HP, "GET", "/media/duzy.webp", { timeout: 20000 });
    ok(bigRes.status === 200 && bigRes.raw.equals(bigMedia) && Number(bigRes.headers["content-length"]) === bigMedia.length,
      "plik 2,6 MB (3 zaszyfrowane kawałki po 1 MiB) oddany bajt w bajt, z poprawnym Content-Length");
    const dbD = readDb(DATA_D);
    ok(dbD.main().deletions?.[0]?.url === "https://example.org/stary", "migracja: lista usunięć w bazie");
    dbD.close();
    ok(fs.existsSync(join(DATA_D, "stare-przed-baza")) && !fs.existsSync(join(DATA_D, "post")) && !fs.existsSync(join(DATA_D, "media")), "migracja: stare pliki odłożone do stare-przed-baza/ (nic nie skasowano)");
  } finally {
    D.child.kill();
  }
  await wait(300);
  fs.rmSync(DATA_D, { recursive: true, force: true, maxRetries: 25, retryDelay: 200 });
}

// ===================== przebieg F: jawna baza z wersji 1.10.0 → zaszyfrowana =====================
{
  const DATA_F = fs.mkdtempSync(join(os.tmpdir(), "lwyt-srv-v1-"));
  const pid = "fedcba9876543210";
  const v1 = new DatabaseSync(join(DATA_F, "serwer.db"));
  v1.exec(`
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE items (id TEXT PRIMARY KEY, json TEXT NOT NULL);
    CREATE TABLE subscribers (endpoint TEXT PRIMARY KEY, json TEXT NOT NULL);
    CREATE TABLE media (name TEXT PRIMARY KEY, size INTEGER NOT NULL, data BLOB NOT NULL);
    CREATE TABLE files (path TEXT PRIMARY KEY, data BLOB NOT NULL);`);
  v1.prepare("INSERT INTO meta (key, value) VALUES ('main', ?)").run(JSON.stringify({ config: { serverName: "Jawna baza 1.10", termsText: "T" }, deletions: [], push: {} }));
  v1.prepare("INSERT INTO items (id, json) VALUES (?, ?)").run(pid, JSON.stringify({ id: pid, type: "post", author: "A", text: "Wpis z jawnej bazy", publishedAt: 1, createdAt: 1, images: [], rev: 1 }));
  v1.prepare("INSERT INTO subscribers (endpoint, json) VALUES (?, ?)").run("https://ntfy.example/tajny-temat", JSON.stringify({ pubkey: null, at: 1, seenAt: 1 }));
  v1.prepare("INSERT INTO media (name, size, data) VALUES (?, ?, ?)").run("jawny.webp", 5, Buffer.from("12345"));
  v1.close();
  const F = await startServer(DATA_F);
  try {
    await wait(800);
    const man = JSON.parse((await req(HP, "GET", "/manifest.json", { headers: { Host: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz23.onion:2137" } })).body);
    ok(man.name === "Jawna baza 1.10" && man.content.includes("post/" + pid + ".json"), "aktualizacja: dane z jawnej bazy 1.10 widoczne po przejściu na szyfrowanie");
    ok((await req(HP, "GET", "/media/jawny.webp")).raw.toString() === "12345", "aktualizacja: plik z jawnej bazy serwowany");
    await wait(300);
    const raw = fs.readFileSync(join(DATA_F, "serwer.db"));
    ok(!raw.includes("Wpis z jawnej bazy") && !raw.includes("tajny-temat") && !raw.includes("Jawna baza 1.10"), "aktualizacja: po przepisaniu w pliku bazy nie ma już jawnego tekstu (także adresu subskrybenta)");
    const dbF = readDb(DATA_F);
    ok(dbF.items().some((it) => it.id === pid) && dbF.cipherIds().size === 1, "aktualizacja: wpis odszyfrowywany kluczem z pliku klucza");
    dbF.close();
  } finally {
    F.child.kill();
  }
  await wait(1500);
  fs.rmSync(DATA_F, { recursive: true, force: true, maxRetries: 25, retryDelay: 200 });
}

// ===================== przebieg K: panel — Host/Origin, logowanie równoległe, 413, nasłuch lokalny, import (audyt A-12/A-15/A-28/A-29) =====================
{
  const DATA_K = fs.mkdtempSync(join(os.tmpdir(), "lwyt-srv-panel-"));
  const K = await startServer(DATA_K);
  try {
    const pwK = (K.out().match(/zalogowaniu\):\s*\n\s*(\S+)/) || [])[1];
    const sK = await adminSession(pwK);
    ok((await req(AP, "GET", "/admin", { headers: { Host: "evil.example:" + AP } })).status === 403, "A-12: panel odrzuca żądanie z obcym nagłówkiem Host (DNS rebinding)");
    ok((await req(AP, "POST", "/admin/login", { headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "https://evil.example" }, body: "password=x" })).status === 403, "A-12: logowanie z obcym Origin odrzucone");
    const page = await req(AP, "GET", "/admin");
    ok(/frame-ancestors 'none'/.test(page.headers["content-security-policy"] || "") && page.headers["x-frame-options"] === "DENY", "A-12: panel ma Content-Security-Policy (frame-ancestors 'none') i X-Frame-Options");
    const tries = await Promise.all(Array.from({ length: 30 }, () => req(AP, "POST", "/admin/login", { headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "password=zle-haslo-" + Math.random() })));
    const n401 = tries.filter((r) => r.status === 401).length;
    ok(n401 <= 3 && tries.filter((r) => r.status === 429).length >= 25, `A-12: 30 równoległych prób logowania → tylko ${n401} sprawdzone hasłem, reszta 429 (limit działa mimo równoległości)`);
    await wait(2500); // koniec blokady
    const big = await sK.postRaw("/admin/api/config", JSON.stringify({ serverName: "x".repeat(1_200_000) }));
    ok(big.status === 413, "A-28: za duże żądanie → odpowiedź 413 (nie zerwane połączenie), status=" + big.status);

    // import: dane o złych typach nie wywracają serwera, osierocone multimedia znikają
    const sK2 = await adminSession(pwK);
    const iid = (await sK2.api("item/create", { type: "post", author: "A", text: "Do kopii", notify: false })).json.item.id;
    const ex = await sK2.postRaw("/admin/api/export", JSON.stringify({ adminPassword: pwK }));
    const bk = JSON.parse(ex.body);
    bk.data.items[0].images = "to-nie-tablica";
    bk.data.items[0].thumb = 12345;
    bk.data.config.serverName = ["tablica"];
    bk.media = { ...(bk.media || {}), "sierota.webp": Buffer.from("RIFF....WEBP").toString("base64") };
    const imp = await sK2.postRaw("/admin/api/import", JSON.stringify(bk));
    ok(imp.status === 200 && (await req(HP, "GET", "/e/" + iid)).status === 200, "A-29: import kopii ze złymi typami pól (images nie jest tablicą) nie wywraca serwera");
    ok((await req(HP, "GET", "/media/sierota.webp")).status === 404, "A-29: po imporcie multimedia bez wpisu (osierocone) zostają usunięte");

    // A-15: nasłuch tylko lokalny
    const lan = Object.values(os.networkInterfaces()).flat().find((i) => i && i.family === "IPv4" && !i.internal)?.address;
    if (lan) {
      const reach = async () => (await req(HP, "GET", "/manifest.json", { host: lan })).status === 200;
      const before = await new Promise((r) => { const q = http.get({ host: lan, port: HP, path: "/manifest.json", timeout: 3000, agent: false }, (x) => { x.resume(); r(x.statusCode === 200); }); q.on("error", () => r(false)); q.on("timeout", () => { q.destroy(); r(false); }); });
      await sK2.api("network", { bindLocalOnly: true });
      await wait(1500);
      const after = await new Promise((r) => { const q = http.get({ host: lan, port: HP, path: "/manifest.json", timeout: 3000, agent: false }, (x) => { x.resume(); r(x.statusCode === 200); }); q.on("error", () => r(false)); q.on("timeout", () => { q.destroy(); r(false); }); });
      const local = (await req(HP, "GET", "/manifest.json")).status === 200;
      ok(before && !after && local, `A-15: nasłuch tylko lokalny — przez adres LAN ${lan} przed: ${before}, po: ${after}; przez 127.0.0.1: ${local}`);
    } else console.log("  SKIP A-15 (brak adresu LAN)");
  } finally {
    K.child.kill();
    await wait(1500);
    fs.rmSync(DATA_K, { recursive: true, force: true, maxRetries: 25, retryDelay: 200 });
  }
  // A-14: certyfikat bliski wygaśnięcia, ale jeszcze ważny, nie wyłącza HTTPS
  const sslv = spawnSync("openssl", ["version"], { encoding: "utf8" });
  if (sslv.status === 0) {
    const TMPC = fs.mkdtempSync(join(os.tmpdir(), "lwyt-cert-"));
    const gen = spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "20", "-subj", "/CN=krotki.example", "-keyout", join(TMPC, "k.pem"), "-out", join(TMPC, "c.pem")], { encoding: "utf8" });
    if (gen.status === 0) {
      const { CertManager } = await import(pathToFileURL(join(SRV, "acme.js")).href);
      const files = new Map([["cert/krotki.example.key", fs.readFileSync(join(TMPC, "k.pem"))], ["cert/krotki.example.crt", fs.readFileSync(join(TMPC, "c.pem"))]]);
      const cm = new CertManager({ storage: { get: (p) => files.get(p) || null, put: (p, b) => files.set(p, Buffer.from(b)) }, challenges: new Map(), log: { log() {}, warn() {}, error() {} } });
      const okc = await cm.ensure("krotki.example", "");
      ok(okc === true && cm.hasHttps(), "A-14: certyfikat ważny jeszcze 20 dni (≤ 30) jest używany od razu, odnowienie idzie w tle");
    }
    fs.rmSync(TMPC, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}

// ===================== przebieg J: baza bez szyfrowania → szyfrowana (A-21) =====================
{
  const DATA_N = fs.mkdtempSync(join(os.tmpdir(), "lwyt-srv-none-"));
  let N = await startServer(DATA_N, { DB_CIPHER: "none" });
  try {
    const pwN = (N.out().match(/zalogowaniu\):\s*\n\s*(\S+)/) || [])[1];
    const sN = await adminSession(pwN);
    const nid = (await sN.api("item/create", { type: "post", author: "A", text: "Z bazy bez szyfrowania", notify: false })).json.item.id;
    await wait(300);
    N.child.kill(); await wait(1500);
    N = await startServer(DATA_N, { DB_CIPHER: "aes-256-gcm" });
    await wait(500);
    const pf = JSON.parse((await req(HP, "GET", "/post/" + nid + ".json")).body);
    const rawN = fs.readFileSync(join(DATA_N, "serwer.db"));
    ok(pf.posts?.[0]?.text === "Z bazy bez szyfrowania" && !rawN.includes("Z bazy bez szyfrowania"), "A-21: po DB_CIPHER=none → inny szyfr serwer startuje, a wartości zostają zaszyfrowane");
  } finally {
    try { N.child.kill(); } catch { /* ignore */ }
    await wait(1500);
    fs.rmSync(DATA_N, { recursive: true, force: true, maxRetries: 25, retryDelay: 200 });
  }
}

// ===================== przebieg E: klucz chroniony hasłem =====================
{
  const DATA_E = fs.mkdtempSync(join(os.tmpdir(), "lwyt-srv-pass-"));
  const E = await startServer(DATA_E);
  const PASS = "bardzo-tajne-haslo-do-bazy-123";
  let adminPw = null;
  try {
    adminPw = (E.out().match(/zalogowaniu\):\s*\n\s*(\S+)/) || [])[1];
    const { api } = await adminSession(adminPw);
    const pid = (await api("item/create", { type: "post", author: "A", text: "Tajny wpis chroniony hasłem", notify: false })).json.item.id;
    ok((await api("crypto/key", { mode: "passphrase", passphrase: "krotkie", adminPassword: adminPw })).status === 400, "hasło do bazy krótsze niż 12 znaków jest odrzucone");
    ok((await api("crypto/key", { mode: "passphrase", passphrase: PASS, adminPassword: "zle-haslo" })).status === 400, "zmiana klucza wymaga hasła administratora");
    const oldKeyHex = Buffer.from(fs.readFileSync(join(DATA_E, "klucz-bazy.key"), "utf8").split(/\r?\n/)[1], "base64").toString("hex");
    const r = await api("crypto/key", { mode: "passphrase", passphrase: PASS, adminPassword: adminPw });
    ok(r.json.ok && r.json.keyMode === "passphrase" && !fs.existsSync(join(DATA_E, "klucz-bazy.key")), "klucz chroniony hasłem: pliku klucza już nie ma na dysku");
    ok(!!dbc.readSettings(DATA_E).wrapped && !JSON.stringify(dbc.readSettings(DATA_E)).includes(PASS), "w szyfrowanie.json tylko zaszyfrowany (scrypt) klucz, bez hasła");
    ok(fs.existsSync(join(DATA_E, "klucz-bazy.haslo.json")), "A-08: opakowany klucz zapisany także w osobnym pliku klucz-bazy.haslo.json (do kopii zapasowej)");
    E.child.kill();
    await wait(1500);
    const run = (env) => spawnSync(process.execPath, ["server.js"], { cwd: SRV, env: { ...process.env, LEWICOWYT_NO_CONVERT: "1", DATA_DIR: DATA_E, HTTP_PORT: String(HP), ADMIN_PORT: String(AP), HTTPS_PORT: String(TLS_ALT), ACME_HTTP01: "off", DB_PASSPHRASE: "", ...env }, encoding: "utf8", timeout: 20000, stdio: ["ignore", "pipe", "pipe"] });
    const noPass = run({});
    ok(noPass.status !== 0 && /hasło|haslo/i.test(noPass.stdout + noPass.stderr), "bez hasła serwer nie startuje i wyjaśnia dlaczego");
    const wrong = run({ DB_PASSPHRASE: "zupelnie-inne-haslo-123" });
    ok(wrong.status !== 0 && /błędne hasło/i.test(wrong.stdout + wrong.stderr), "złe hasło: serwer nie startuje");
    const oldKeyTry = run({ DB_KEY: oldKeyHex });
    ok(oldKeyTry.status !== 0 && /odszyfrować/.test(oldKeyTry.stdout + oldKeyTry.stderr), "A-07: po przejściu na hasło STARY klucz (z kopii pliku) nie otwiera już bazy — klucz główny został wymieniony");
    // A-06: edycja szyfrowanie.json nie wyłączy szyfrowania bazy chronionej hasłem
    const setPath = join(DATA_E, "szyfrowanie.json");
    const orig = fs.readFileSync(setPath, "utf8");
    fs.writeFileSync(setPath, JSON.stringify({ ...JSON.parse(orig), cipher: "none" }));
    const E3 = await startServer(DATA_E, { DB_PASSPHRASE: PASS });
    try {
      await wait(500);
      ok((await req(HP, "GET", "/post/" + pid + ".json")).status === 200 && dbc.readSettings(DATA_E).cipher === "auto", "A-06: cipher=none w szyfrowanie.json jest ignorowane w trybie hasła (szyfrowanie zostaje)");
    } finally { E3.child.kill(); await wait(1500); }
    // A-08: zgubiony szyfrowanie.json — klucz odtwarzany z klucz-bazy.haslo.json
    fs.rmSync(setPath, { force: true });
    const E4 = await startServer(DATA_E, { DB_PASSPHRASE: PASS });
    try {
      await wait(500);
      ok((await req(HP, "GET", "/post/" + pid + ".json")).status === 200, "A-08: po utracie szyfrowanie.json baza otwiera się hasłem dzięki klucz-bazy.haslo.json");
    } finally { E4.child.kill(); await wait(1500); }
    const E2 = await startServer(DATA_E, { DB_PASSPHRASE: PASS });
    try {
      await wait(500);
      const pf = JSON.parse((await req(HP, "GET", "/post/" + pid + ".json")).body);
      ok(pf.posts?.[0]?.text === "Tajny wpis chroniony hasłem", "z poprawnym hasłem serwer startuje i serwuje wcześniejsze dane");
      const bytes = fs.readFileSync(join(DATA_E, "serwer.db"));
      ok(!bytes.includes("Tajny wpis"), "wpis nie leży w bazie jawnie");
    } finally {
      E2.child.kill();
    }
  } finally {
    try { E.child.kill(); } catch { /* ignore */ }
    await wait(1500);
    fs.rmSync(DATA_E, { recursive: true, force: true, maxRetries: 25, retryDelay: 200 });
  }
}

// ===================== przebieg G: aktualizacje serwera z GitHub Releases (mock GitHuba) =====================
{
  const upd = await import(pathToFileURL(join(SRV, "update.js")).href);
  ok(upd.compareVersions("1.0.0-beta.2", "1.0.0-beta.10") < 0 && upd.compareVersions("1.0.0", "1.0.0-rc.1") > 0 && upd.compareVersions("v1.12.0", "1.2.0") > 0 && upd.compareVersions("2.0", "2.0.0") === 0,
    "aktualizacje: porównanie wersji (semver, wersje wstępne) jak w aplikacji");
  const goodAsset = { name: "serwer-1.0.0.zip", size: 100, browser_download_url: "https://github.com/a/b/releases/download/v1.0.0/serwer-1.0.0.zip", digest: "sha256:" + "a".repeat(64) };
  const rel = (tag, extra = {}) => ({ tag_name: tag, html_url: `https://github.com/a/b/releases/tag/${tag}`, assets: [goodAsset], body: "", ...extra });
  const sel = (releases, cur) => upd.selectUpdate(releases, cur, "a/b");
  ok(sel([rel("v1.0.1"), rel("v1.0.0")], "1.0.0").version === "1.0.1", "aktualizacje: wybiera najnowsze wydanie nowsze od bieżącej wersji");
  ok(sel([rel("v1.0.0")], "1.0.0").state === "uptodate", "aktualizacje: brak nowszego → aktualna");
  ok(sel([rel("v1.1.0-rc.1", { prerelease: true }), rel("v1.0.1")], "1.0.0").version === "1.0.1", "aktualizacje: wersje wstępne pomijane, gdy bieżąca jest stabilna");
  ok(sel([rel("v1.1.0-rc.1", { prerelease: true }), rel("v1.0.1")], "1.0.0-beta").version === "1.1.0-rc.1", "aktualizacje: wersja wstępna widzi wydania wstępne");
  ok(sel([rel("v2.0.0", { draft: true }), rel("v1.0.1")], "1.0.0").version === "1.0.1", "aktualizacje: szkice pomijane");
  ok(sel([rel("v1.0.1", { body: "Naprawa. [SECURITY-MANDATORY]" })], "1.0.0").mandatory === true, "aktualizacje: wymagana tylko po jawnym markerze w opisie");
  const throwsAll = (releases) => { try { sel(releases, "1.0.0"); return false; } catch { return true; } };
  ok(throwsAll([rel("v1.0.1", { assets: [{ ...goodAsset, browser_download_url: "https://evil.example/a/b/releases/download/v1/x.zip" }] })])
    && throwsAll([rel("v1.0.1", { assets: [{ ...goodAsset, browser_download_url: "https://github.com/inny/repo/releases/download/v1/x.zip" }] })])
    && throwsAll([rel("v1.0.1", { assets: [{ ...goodAsset, browser_download_url: "http://github.com/a/b/releases/download/v1/x.zip" }] })]),
    "aktualizacje: paczka spoza github.com / z innego repozytorium / po http jest odrzucana");
  ok(throwsAll([rel("v1.0.1", { assets: [{ ...goodAsset, digest: undefined }] })]) && throwsAll([rel("v1.0.1", { assets: [{ ...goodAsset, name: "../x.zip" }] })]),
    "aktualizacje: paczka bez skrótu SHA-256 albo z niebezpieczną nazwą jest odrzucana");

  const lg = await import(pathToFileURL(join(SRV, "logger.js")).href);
  const masked = lg.maskText("hasło: Tajne123 oraz password=abc456 i token: \"xyz789\" Authorization: Bearer q1w2e3");
  ok(!/Tajne123|abc456|xyz789|q1w2e3/.test(masked) && masked.includes("[ukryte]"), "dziennik: hasła i sekrety zapisane w tekście komunikatu są maskowane (audyt A-01)");
  const badZip = (name) => { try { upd.normalizeEntries([{ name, data: Buffer.alloc(1), mode: 0 }, { name: "server.js", data: Buffer.alloc(1), mode: 0 }]); return false; } catch { return true; } };
  ok(badZip("/server.js") && badZip("C:/server.js") && badZip("\server.js") && badZip("a/../../x.js") && !badZip("serwer-1/x.js"), "aktualizacje: ścieżki bezwzględne, z literą dysku i z .. odrzucane przed odcięciem katalogu głównego (audyt A-02)");

  const mediaMod = await import(pathToFileURL(join(SRV, "media.js")).href);
  const mp4Src = [process.env.TEST_MP4].filter(Boolean).find((p) => fs.existsSync(p)); // opcjonalnie: TEST_MP4=ścieżka/do/filmu.mp4
  if (mp4Src) {
    const full = fs.readFileSync(mp4Src);
    let thrown = 0;
    for (let n = 0; n < full.length && n < 4000; n += 7) { try { mediaMod.mp4VideoInfo(full.subarray(0, n)); } catch { thrown++; } }
    for (let i = 0; i < 300; i++) { const c = Buffer.from(full.subarray(0, 3000)); c[Math.floor(Math.random() * c.length)] ^= 0xff; try { mediaMod.mp4VideoInfo(c); } catch { thrown++; } }
    ok(thrown === 0, "media: uszkodzone i obcięte nagłówki MP4 nie rzucają wyjątków (audyt B-03)");
    {
      const metaMod = await import(pathToFileURL(join(SRV, "metadata.js")).href);
      const marked = Buffer.from(full);
      const i = marked.indexOf("mvhd");
      const o = i + 4 + 4; // po typie: wersja+flagi, potem data utworzenia
      const ver = marked[i + 4];
      marked.writeUInt32BE(3_800_000_000, o);
      marked.writeUInt32BE(3_800_000_001, o + (ver === 1 ? 8 : 4));
      const cleaned = metaMod.mp4StripMetadata(marked);
      const j = cleaned ? cleaned.indexOf("mvhd") : -1;
      ok(!!cleaned && j > 0 && cleaned.readUInt32BE(j + 8) === 0 && cleaned.readUInt32BE(j + 8 + (cleaned[j + 4] === 1 ? 8 : 4)) === 0, "media: daty utworzenia/modyfikacji w mvhd są zerowane przy usuwaniu metadanych (audyt A-23)");
    }
  } else console.log("  SKIP B-03 (brak pliku MP4 do testu)");

  // --- serwer uruchomiony z KOPII kodu (instalacja podmienia pliki) + mock GitHuba ---
  const APP = fs.mkdtempSync(join(os.tmpdir(), "lwyt-app-"));
  for (const n of fs.readdirSync(SRV)) if (/\.(js|json|sh|bat|ps1|md)$/.test(n) && n !== "package-lock.json") fs.copyFileSync(join(SRV, n), join(APP, n));
  const realPkg = JSON.parse(fs.readFileSync(join(APP, "package.json"), "utf8"));
  const DATA_G = fs.mkdtempSync(join(os.tmpdir(), "lwyt-srv-upd-"));
  const MOCK = 23900;
  const newServerJs = fs.readFileSync(join(APP, "server.js"), "utf8") + "\n// ZAKTUALIZOWANO\n";
  const zipOf = (version, extra = []) => upd.buildZip([
    { name: "server.js", data: newServerJs },
    { name: "package.json", data: JSON.stringify({ ...realPkg, version }, null, 2) },
    { name: "data/zly-plik.txt", data: "nie wolno ruszac data/" },
    { name: "nowy-modul.js", data: "export const x = 1;\n" },
    ...extra,
  ]);
  let mode = "good";
  let zip = zipOf("9.9.9");
  const releases = () => [
    { tag_name: "v9.9.9", html_url: "https://github.com/test/repo/releases/tag/v9.9.9", body: "Nowości.\n[security-mandatory]", draft: false, prerelease: false,
      assets: [{ name: "serwer-lewicowyt-9.9.9.zip", size: zip.length, browser_download_url: `http://127.0.0.1:${MOCK}/download/serwer-lewicowyt-9.9.9.zip`,
        digest: "sha256:" + (mode === "badhash" ? "0".repeat(64) : crypto.createHash("sha256").update(zip).digest("hex")) }] },
    { tag_name: "v9.9.8", html_url: "https://github.com/test/repo/releases/tag/v9.9.8", body: "", assets: [] },
  ];
  const mock = http.createServer((rq, rs) => {
    if (rq.url.startsWith("/repos/test/repo/releases")) { rs.writeHead(200, { "Content-Type": "application/json" }); rs.end(JSON.stringify(releases())); return; }
    if (rq.url.startsWith("/download/")) { rs.writeHead(200, { "Content-Type": "application/zip", "Content-Length": zip.length }); rs.end(zip); return; }
    rs.writeHead(404); rs.end();
  });
  await new Promise((r) => mock.listen(MOCK, "127.0.0.1", r));
  const env = { ...process.env, LEWICOWYT_NO_CONVERT: "1", DATA_DIR: DATA_G, HTTP_PORT: String(HP), ADMIN_PORT: String(AP), HTTPS_PORT: String(TLS_ALT), ACME_HTTP01: "off",
    UPDATE_API_BASE: `http://127.0.0.1:${MOCK}`, UPDATE_REPO: "test/repo", UPDATE_ALLOW_INSECURE_TEST: "1", NODE_ENV: "test", LEWICOWYT_SUPERVISED: "1" };
  const launch = async () => {
    const child = spawn(process.execPath, ["server.js"], { cwd: APP, env });
    let out = ""; const exit = new Promise((r) => child.on("exit", (c) => r(c)));
    child.stdout.on("data", (d) => { out += d; }); child.stderr.on("data", (d) => { out += d; });
    for (let i = 0; i < 80 && !/Panel:/.test(out); i++) await wait(100);
    await wait(300);
    return { child, exit, out: () => out };
  };
  const readApp = (n) => fs.readFileSync(join(APP, n), "utf8");
  let G = await launch();
  try {
    const pw = (G.out().match(/zalogowaniu\):\s*\n\s*(\S+)/) || [])[1];
    const { api } = await adminSession(pw);
    const st = (await api("update/status", {})).json;
    ok(st.current === realPkg.version && st.repository === "test/repo" && st.autoCheck === true && st.supervised === true, "aktualizacje: status — bieżąca wersja, repozytorium, sprawdzanie automatyczne włączone");
    const ck = (await api("update/check", {})).json;
    ok(ck.result?.state === "available" && ck.result.version === "9.9.9" && ck.result.mandatory === true, "aktualizacje: sprawdzenie widzi wersję 9.9.9 (wymagana)");
    ok((await api("update/install", { adminPassword: "zle-haslo" })).status === 400, "aktualizacje: instalacja wymaga hasła administratora");

    mode = "badhash";
    let r = await api("update/install", { adminPassword: pw });
    ok(r.status === 400 && /SHA-256/.test(r.json.error) && readApp("package.json").includes(realPkg.version), "aktualizacje: zły skrót SHA-256 → odmowa, pliki bez zmian");
    mode = "good";

    zip = zipOf("9.9.0");
    r = await api("update/install", { adminPassword: pw });
    ok(r.status === 400 && /Wersja w paczce/.test(r.json.error) && !fs.existsSync(join(APP, "nowy-modul.js")), "aktualizacje: wersja w paczce ≠ wersja wydania → odmowa");

    zip = zipOf("9.9.9", [{ name: "../ucieczka.js", data: "x" }]);
    r = await api("update/install", { adminPassword: pw });
    ok(r.status === 400 && /niebezpieczna ścieżka/.test(r.json.error) && !fs.existsSync(join(APP, "..", "ucieczka.js")), "aktualizacje: ścieżka wychodząca (../) w paczce → odmowa");

    zip = zipOf("9.9.9", [{ name: "zepsuty.js", data: "export const = ;" }]);
    r = await api("update/install", { adminPassword: pw });
    ok(r.status === 400 && /błąd składni/.test(r.json.error) && !fs.existsSync(join(APP, "zepsuty.js")), "aktualizacje: plik JS z błędem składni w paczce → odmowa przed podmianą (audyt A-11)");

    zip = zipOf("9.9.9", [{ name: "Data/szyfrowanie.json", data: "{}" }, { name: "Tools/ffmpeg.exe", data: "x" }, { name: "ENGINE/node.exe", data: "x" }]);
    const before = readApp("server.js");
    r = await api("update/install", { adminPassword: pw });
    ok(r.status === 200 && r.json.ok && r.json.from === realPkg.version && r.json.to === "9.9.9" && r.json.restarting === true, "aktualizacje: poprawna paczka zainstalowana, serwer zapowiada restart");
    const code = await Promise.race([G.exit, wait(15000).then(() => "timeout")]);
    ok(code === 75, "aktualizacje: serwer kończy się kodem 75 (prosi start.bat / start.sh o restart)");
    ok(JSON.parse(readApp("package.json")).version === "9.9.9" && readApp("server.js").includes("// ZAKTUALIZOWANO") && fs.existsSync(join(APP, "nowy-modul.js")), "aktualizacje: pliki podmienione, nowy plik dodany");
    ok(!fs.existsSync(join(APP, "data")) && !fs.existsSync(join(APP, "Data")) && !fs.existsSync(join(APP, "Tools")) && !fs.existsSync(join(APP, "ENGINE")), "aktualizacje: wpisy data/…, Data/…, Tools/…, ENGINE/… z paczki pominięte — także przy innej wielkości liter (audyt A-19)");
    ok(upd.isSafeRel("a/b.js") && !upd.isSafeRel("a/../b") && !upd.isSafeRel("x:y") && !upd.isSafeRel("a/b.") && !upd.isSafeRel("a/b ") && !upd.isSafeRel("") && !upd.isSafeRel("/abs"), "aktualizacje: walidacja ścieżek względnych (kropka/spacja na końcu, dwukropek, ..) — także przy cofaniu (audyt A-20)");
    const bk = fs.readdirSync(join(DATA_G, "aktualizacje")).filter((n) => n.startsWith("kopia-"));
    ok(bk.length === 1 && fs.readFileSync(join(DATA_G, "aktualizacje", bk[0], "pliki", "server.js"), "utf8") === before, "aktualizacje: kopia zastąpionych plików zapisana w data/aktualizacje/");

    // --- po restarcie: nowa wersja działa, cofnięcie przywraca starą ---
    G = await launch();
    const { api: api2 } = await adminSession(pw);
    const st2 = (await api2("update/status", {})).json;
    ok(st2.current === "9.9.9" && st2.backups.length === 1, "aktualizacje: po restarcie serwer działa w nowej wersji i widzi kopię do cofnięcia");
    ok((await api2("update/rollback", { adminPassword: "zle" })).status === 400, "aktualizacje: cofnięcie wymaga hasła administratora");
    const rb = await api2("update/rollback", { adminPassword: pw });
    ok(rb.status === 200 && rb.json.restoredTo === realPkg.version, "aktualizacje: cofnięcie przywraca poprzednią wersję");
    const code2 = await Promise.race([G.exit, wait(15000).then(() => "timeout")]);
    ok(fs.readdirSync(join(DATA_G, "aktualizacje")).some((n) => n.startsWith("cofnieta-")) && !fs.readdirSync(join(DATA_G, "aktualizacje")).some((n) => n.startsWith("kopia-")), "aktualizacje: po cofnięciu kopia oznaczona jako cofnięta (zmiana nazwy tylko katalogu kopii — audyt B-02)");
    ok(code2 === 75 && JSON.parse(readApp("package.json")).version === realPkg.version && readApp("server.js") === before && !fs.existsSync(join(APP, "nowy-modul.js")),
      "aktualizacje: po cofnięciu pliki jak przed aktualizacją (nowy plik usunięty), restart zapowiedziany");
  } finally {
    try { G.child.kill(); } catch { /* ignore */ }
    mock.close();
    await wait(1500);
    fs.rmSync(DATA_G, { recursive: true, force: true, maxRetries: 25, retryDelay: 200 });
    fs.rmSync(APP, { recursive: true, force: true, maxRetries: 25, retryDelay: 200 });
  }
}

// ===================== przebieg H: dziennik zdarzeń (zawsze włączony, ZSTD, szyfrowany, eksport HTML) =====================
{
  const zlibMod = await import("node:zlib");
  const DATA_H = fs.mkdtempSync(join(os.tmpdir(), "lwyt-srv-log-"));
  // baza BEZ szyfrowania (DB_CIPHER=none): dziennik i tak musi być szyfrowany
  let H = await startServer(DATA_H, { DB_CIPHER: "none", LOG_TRAFFIC_WINDOW_SEC: "1" });
  let pw, relogin;
  try {
    pw = (H.out().match(/zalogowaniu\):\s*\n\s*(\S+)/) || [])[1];
    const sess = await adminSession(pw);
    const { api } = sess;
    await api("item/create", { type: "post", author: "A", text: "Wpis do dziennika", notify: false });
    for (let i = 0; i < 3; i++) { await wait(1300); await req(HP, "GET", "/manifest.json"); await api("logs/status", {}); await api("config", { serverName: "Dziennik " + i }); }
    await req(HP, "GET", "/to-nie-istnieje");
    await wait(1300);
    const q = (await api("logs/query", { minLevel: "debug", limit: 1000 })).json.entries;
    const has = (pred) => q.some(pred);
    ok(has((e) => e.cat === "system" && e.ev === "start" && e.f?.node && e.f?.cpu && e.f?.dbCipherPreference === "none"), "dziennik: migawka systemu przy starcie (Node, CPU, szyfrowanie)");
    const traffic = q.filter((e) => e.cat === "http" && e.ev === "ruch").flatMap((e) => e.f.trasy);
    ok(traffic.some((t) => t.route === "manifest" && t.status === 200 && t.n >= 1 && typeof t.msSrednio === "number"), "dziennik: ruch publiczny zbiorczo — manifest (liczba, średni i maksymalny czas, bajty)");
    ok(traffic.some((t) => t.route === "nieznana" && t.status === 404), "dziennik: nieznana trasa → 404 w zestawieniu ruchu");
    ok(!JSON.stringify(q).includes("to-nie-istnieje"), "dziennik: ścieżki nieznanych tras nie są zapisywane (audyt A-03)");
    const before = (await api("logs/status", {})).json.stats.entries;
    await Promise.all(Array.from({ length: 40 }, (_, i) => Promise.all(Array.from({ length: 50 }, (_, j) => req(HP, "GET", "/zalew/" + i + "/" + j)))));
    await wait(2300); await req(HP, "GET", "/manifest.json"); await wait(300);
    const after = (await api("logs/status", {})).json.stats.entries;
    ok(after - before < 15, `dziennik: 2000 żądań na nieistniejące trasy dodało tylko ${after - before} wpisów (zbiorczo) — nie wypchną audytu (audyt A-03)`);
    ok(has((e) => e.level === 50 && e.ev === "logowanie.ok") && has((e) => e.ev === "panel.akcja" && e.f?.action === "config"), "dziennik: audyt — logowanie i akcje panelu");
    ok(has((e) => e.cat === "konsola"), "dziennik: strumień konsoli jest przechwytywany");
    const dump = JSON.stringify(q);
    const httpDump = JSON.stringify(q.filter((e) => e.cat === "http"));
    ok(!dump.includes(pw) && !/d{1,3}.d{1,3}.d{1,3}.d{1,3}/.test(httpDump) && !/userAgent|user-agent|remoteAddress/i.test(dump), "dziennik: nie zawiera hasła administratora, adresów IP klientów ani nagłówków User-Agent");
    const st = (await api("logs/status", {})).json.stats;
    ok(st.entries > 10 && st.blocks >= 3 && st.compressedBytes < st.rawBytes && st.zstdLevel === 3, `dziennik: bloki skompresowane ZSTD-3 (${st.entries} wpisów, ${st.rawBytes} B → ${st.compressedBytes} B)`);
    ok(st.cipher && st.cipher !== "Bez szyfrowania (niezalecane)" && /AES|ChaCha/.test(st.cipher), `dziennik: szyfr ${st.cipher} (najlepszy dla CPU) mimo wyłączonego szyfrowania bazy`);
    const v = (await api("logs/verify", {})).json.verify;
    ok(v.ok && v.blocks >= st.blocks && !v.prunedPrefix, "dziennik: weryfikacja integralności (łańcuch skrótów, oba szyfry, liczby wpisów) OK");
    const raw = Buffer.concat(["serwer.db", "serwer.db-wal"].map((n) => { try { return fs.readFileSync(join(DATA_H, n)); } catch { return Buffer.alloc(0); } }));
    ok(!raw.includes("zalogowano do panelu") && !raw.includes("serwer startuje") && !raw.includes("manifest →"), "dziennik: w pliku bazy nie ma jawnych wpisów dziennika (baza bez szyfrowania, dziennik szyfrowany)");
    ok(!(await api("logs/disable", {})).json.ok && !(await api("config", { logging: false, dziennik: false })).json.error, "dziennik: brak jakiejkolwiek akcji wyłączającej dziennik");

    // --- eksport do szyfrowanego HTML ---
    ok((await api("logs/export", { adminPassword: "zle-haslo" })).status === 400, "eksport dziennika wymaga hasła administratora");
    const ex = await sess.postRaw("/admin/api/logs/export", JSON.stringify({ adminPassword: pw, days: 7, minLevel: "info" }));
    ok(ex.status === 200 && /text\/html/.test(ex.headers["content-type"]) && /attachment/.test(ex.headers["content-disposition"]), "eksport: plik HTML do pobrania");
    const html = ex.body;
    ok(!html.includes("Wpis do dziennika") && !html.includes("logowanie.ok") && !html.includes(pw) && /Content-Security-Policy/.test(html), "eksport: zawartość zaszyfrowana, hasła w pliku nie ma, jest CSP");
    const blob = JSON.parse(html.match(/<script id="blob" type="application\/json">([^<]+)<\/script>/)[1]);
    const open = (password) => {
      const key = crypto.pbkdf2Sync(password.normalize("NFC"), Buffer.from(blob.salt, "base64"), blob.iter, 32, "sha256");
      const ct = Buffer.from(blob.ct, "base64");
      const d = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(blob.iv, "base64"), { authTagLength: 16 });
      d.setAuthTag(ct.subarray(ct.length - 16));
      return JSON.parse(zlibMod.gunzipSync(Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()])).toString("utf8"));
    };
    let wrong = false; try { open("inne-haslo-123456"); } catch { wrong = true; }
    const plain = open(pw);
    ok(wrong && blob.iter === 600000 && plain.entries.some((e) => e.ev === "logowanie.ok") && plain.entries.every((e) => e.level >= 20) && plain.meta.integrity.ok,
      `eksport: odszyfrowuje się TYLKO hasłem administratora (PBKDF2 600k + AES-256-GCM), ${plain.entries.length} wpisów, filtr poziomu, integralność w nagłówku`);

    // --- ingerencja: usunięcie środkowego bloku musi być wykryte po restarcie ---
    H.child.kill(); await wait(1500);
    const dbw = new DatabaseSync(join(DATA_H, "serwer.db"));
    const mid = dbw.prepare("SELECT first_seq FROM logs ORDER BY first_seq").all();
    dbw.prepare("DELETE FROM logs WHERE first_seq = ?").run(mid[2].first_seq);
    dbw.close();
    H = await startServer(DATA_H, { DB_CIPHER: "none", LOG_TRAFFIC_WINDOW_SEC: "1" });
    const s2 = await adminSession(pw);
    const v2 = (await s2.api("logs/verify", {})).json.verify;
    ok(!v2.ok && v2.problems.some((p) => p.kind === "luka" || p.kind === "lancuch"), "dziennik: usunięcie bloku wykryte (luka w numeracji / przerwany łańcuch skrótów)");
    await wait(1300);
    const all2 = (await s2.api("logs/query", { limit: 1000 })).json.entries;
    const seqs = all2.map((e) => e.seq);
    ok(all2.filter((e) => e.ev === "start").length === 2 && new Set(seqs).size === seqs.length && Math.max(...seqs) > Math.max(...q.map((e) => e.seq)),
      "dziennik: po restarcie serwer dalej pisze (dwa starty w dzienniku, numeracja bez powtórzeń i rosnąca)");
  } finally {
    try { H.child.kill(); } catch { /* ignore */ }
    await wait(1500);
    fs.rmSync(DATA_H, { recursive: true, force: true, maxRetries: 25, retryDelay: 200 });
  }
  // --- audyt A-04: obcięcie końca, usunięcie całości i najstarszych bloków (poza blokiem ze środka) ---
  for (const variant of ["koniec", "calosc", "poczatek"]) {
    const DATA_T = fs.mkdtempSync(join(os.tmpdir(), "lwyt-srv-trunc-"));
    let T = await startServer(DATA_T, { LOG_TRAFFIC_WINDOW_SEC: "1" });
    try {
      const pwT = (T.out().match(/zalogowaniu\):\s*\n\s*(\S+)/) || [])[1];
      const sT = await adminSession(pwT);
      for (let i = 0; i < 4; i++) { await wait(1200); await sT.api("config", { serverName: "T" + i }); }
      ok((await sT.api("logs/verify", {})).json.verify.ok, `obcięcie (${variant}): przed ingerencją weryfikacja OK`);
      T.child.kill(); await wait(1500);
      const dbt = new DatabaseSync(join(DATA_T, "serwer.db"));
      const rows = dbt.prepare("SELECT first_seq FROM logs ORDER BY first_seq").all();
      if (variant === "koniec") for (const r of rows.slice(-2)) dbt.prepare("DELETE FROM logs WHERE first_seq = ?").run(r.first_seq);
      else if (variant === "calosc") dbt.exec("DELETE FROM logs");
      else for (const r of rows.slice(0, 2)) dbt.prepare("DELETE FROM logs WHERE first_seq = ?").run(r.first_seq);
      dbt.close();
      T = await startServer(DATA_T, { LOG_TRAFFIC_WINDOW_SEC: "1" });
      const sT2 = await adminSession(pwT);
      await wait(1300);
      const vT = (await sT2.api("logs/verify", {})).json.verify;
      ok(!vT.ok && vT.problems.some((p) => ["obciecie", "poczatek", "luka", "lancuch"].includes(p.kind)), `dziennik: ingerencja "${variant}" wykryta mimo dalszych zapisów po restarcie (${vT.problems[0]?.kind})`);
    } finally {
      try { T.child.kill(); } catch { /* ignore */ }
      await wait(1500);
      fs.rmSync(DATA_T, { recursive: true, force: true, maxRetries: 25, retryDelay: 200 });
    }
  }
}

// ===================== testy jednostkowe manifestu (bez serwera) =====================
const { buildManifestBody, buildContentFile, permalinkOf } = await import(pathToFileURL(join(SRV, "manifest.js")).href);
const big = { config: { serverName: "S", termsText: "T", termsVersion: "1" }, deletions: [], items: [] };
for (let i = 0; i < 1400; i++) big.items.push({ id: crypto.randomBytes(8).toString("hex"), type: ["post", "article", "foreign", "contest", "ad", "creator", "meme"][i % 7], author: "a", source: "s", platform: "p", name: "n", title: "t".repeat(300), text: "x".repeat(720 + (i % 40)), url: `https://e.org/${i}`, articleKind: "article", images: [], publishedAt: 1_700_000_000_000 + i });
const sent = buildManifestBody(big, "https://s.example", { httpsBase: "https://s.example", altEndpoints: ["http://192.168.0.2:2137"] });
ok(sent.length <= 900_000, `I-03: WYSYŁANY manifest ${sent.length} znaków ≤ 900 000 (apka odrzuca > 1 000 000)`);
const bm = JSON.parse(sent);
ok(bm.content.length === 1200, `1400 wpisów → ${bm.content.length} plików (memy bez obrazu pominięte)`);
const many = { ...big, items: Array.from({ length: 12000 }, (_, i) => ({ id: i.toString(16).padStart(16, "0"), type: "post", author: "a", text: "t", images: [], createdAt: i })) };
ok(JSON.parse(buildManifestBody(many, "https://s.example", {})).content.length === 10000, "najwyżej 10 000 plików w content (najnowsze)");
ok(bm.altEndpoints?.[0] === "http://192.168.0.2:2137", "altEndpoints LAN w manifeście https");
ok(permalinkOf({ id: "abc", type: "post" }, "https://s.example") === "https://s.example/e/abc", "stały link /e/<id> dla wpisu bez linku");
ok(permalinkOf({ id: "abc", type: "ad" }, "https://s.example") === undefined, "reklama bez własnego linku nie dostaje /e/");
const now = Date.now();
const win = { config: big.config, deletions: [], items: [
  { id: "a1", type: "post", author: "a", text: "świeży", update: "significant", updateAt: now - 3600_000, images: [] },
  { id: "a2", type: "post", author: "a", text: "stary", update: "significant", updateAt: now - 72 * 3600_000, images: [] },
] };
const fresh = JSON.parse(buildContentFile(win.items[0], "https://s.example", { now })).posts[0];
const stale = JSON.parse(buildContentFile(win.items[1], "https://s.example", { now })).posts[0];
ok(fresh.update === "significant" && stale.update === undefined,
  "I-01: update: significant wygasa po 48 h (nowy subskrybent nie dostaje zbiorczego powiadomienia o starociach)");

// S-02 (jednostkowo): wpis BEZ stałego linku (serwer tylko .onion, bez HTTPS) — drobna poprawka daje minor,
// bo apka rozpoznaje taki wpis po treści i zmieniony tekst dałby drugie powiadomienie
{
  const store = await import(pathToFileURL(join(SRV, "store.js")).href);
  const d = { items: [] };
  const it = store.createItem(d, { type: "post", author: "a", text: "tekst" }).item;
  store.updateItem(d, { id: it.id, type: "post", author: "a", text: "tekst poprawiony" }, { linkOf: () => null });
  ok(it.update === "minor", "S-02: wpis bez stałego linku → minor po drobnej poprawce");
  const it2 = store.createItem(d, { type: "post", author: "a", text: "x", url: "https://e.org/1" }).item;
  it2.updateAt -= 49 * 3600_000; it2.publishedAt -= 49 * 3600_000; it2.createdAt -= 49 * 3600_000;
  store.updateItem(d, { id: it2.id, type: "post", author: "a", text: "y", url: "https://e.org/1" }, { linkOf: (x) => x.url });
  ok(it2.update === "minor", "S-02: po oknie 48 h drobna poprawka daje minor (flaga i tak by wygasła)");
}


// ===================== przebieg C: konwersja multimediów (wymaga ffmpeg; bez niego pomijany) =====================
{
  const conv = await import(pathToFileURL(join(SRV, "convert.js")).href);
  const media = await import(pathToFileURL(join(SRV, "media.js")).href);
  const T = conv.tools(true);
  if (!T.ffmpeg) {
    console.log("  --   przebieg C pominięty: brak ffmpeg (ustaw FFMPEG_PATH, żeby sprawdzić konwersję)");
  } else {
    const DATA_C = fs.mkdtempSync(join(os.tmpdir(), "lwyt-srv-conv-"));
    const TMP = fs.mkdtempSync(join(os.tmpdir(), "lwyt-media-"));
    const ff = (...args) => spawnSync(T.ffmpeg, ["-y", "-v", "error", ...args], { encoding: "utf8" });
    // pliki wejściowe w formatach, których aplikacja NIE przyjmuje (albo przyjmuje tylko w limitach)
    const png = join(TMP, "duzy.png");   ff("-f", "lavfi", "-i", "mandelbrot=size=2400x1800", "-frames:v", "1", "-compression_level", "0", png);
    const wbmp = join(TMP, "maly.wbmp"); ff("-f", "lavfi", "-i", "testsrc2=size=320x240", "-frames:v", "1", "-pix_fmt", "monob", "-c:v", "wbmp", wbmp);
    const gif = join(TMP, "anim.gif");   ff("-f", "lavfi", "-i", "testsrc2=size=160x120:rate=8:duration=1", gif);
    const v60 = join(TMP, "v60.mp4");    ff("-f", "lavfi", "-i", "testsrc2=size=320x240:rate=60:duration=2", "-f", "lavfi", "-i", "sine=frequency=300:duration=2", "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", v60);
    const vp9 = join(TMP, "vp9.webm");   ff("-f", "lavfi", "-i", "testsrc2=size=320x240:rate=30:duration=2", "-c:v", "libvpx-vp9", "-b:v", "300k", vp9);
    const wav = join(TMP, "dzwiek.wav"); ff("-f", "lavfi", "-i", "sine=frequency=440:duration=2", wav);
    const vorbis = join(TMP, "v.ogg");   ff("-f", "lavfi", "-i", "sine=frequency=440:duration=2", "-c:a", "libvorbis", vorbis);
    // JPEG z "metadanymi" (znacznik w segmencie Exif) — po konwersji nie może go być
    const base = join(TMP, "b.jpg"); ff("-f", "lavfi", "-i", "mandelbrot=size=640x480", "-frames:v", "1", "-q:v", "3", base);
    const jb = fs.readFileSync(base);
    const exifSeg = jpegSeg(0xe1, Buffer.concat([Buffer.from("Exif\0\0MM\0*", "latin1"), Buffer.from("SEKRETNE-GPS-51.1N-17.0E", "latin1")]));
    const jpgExif = Buffer.concat([jb.subarray(0, 2), exifSeg, jb.subarray(2)]);

    const C = await startServer(DATA_C, { LEWICOWYT_NO_CONVERT: "0" });
    try {
      const pwC = (C.out().match(/zalogowaniu\):\s*\n\s*(\S+)/) || [])[1];
      const { api, upload } = await adminSession(pwC);
      const mk = async (type, extra = {}) => (await api("item/create", { type, ...extra })).json.item.id;
      const read = (p) => fs.readFileSync(p);
      const HOST = { Host: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz23.onion:2137" };
      const man = async () => JSON.parse((await req(HP, "GET", "/manifest.json", { headers: HOST })).body);
      const file = async (name) => JSON.parse((await req(HP, "GET", "/" + name, { headers: HOST })).body);
      const mediaOf = (name) => { const d = readDb(DATA_C); try { return d.media(basename(name)) || Buffer.alloc(0); } finally { d.close(); } };

      // --- obrazy ---
      const mPng = await mk("meme", { title: "PNG" });
      const rPng = await upload(mPng, "image/png", read(png), false);
      ok(rPng.status === 200 && /\.(jxl|webp)$/.test(rPng.images?.[0] || ""), "PNG (kilka MB, bez kompresji) → " + (T.jxl ? "JPEG XL" : "WebP") + " (" + (rPng.images?.[0] || rPng.error) + ")");
      ok(!T.jxl || rPng.images?.[0]?.endsWith(".jxl"), "gdy jest koder JPEG XL, wynik to JXL");
      const outPng = rPng.images?.[0] ? mediaOf(rPng.images[0]) : Buffer.alloc(0);
      ok(outPng.length > 0 && outPng.length <= 6_000_000, "wynik ≤ 6 000 000 B (" + outPng.length + " B)");
      ok(!T.jxl || rPng.quality > 0, "jakość JXL zadeklarowana automatycznie (imageQuality)");
      const mQ = await mk("meme", { title: "Jakość 70", jxlQuality: 70 });
      const rQ = await upload(mQ, "image/png", read(png), false);
      ok(!T.jxl || (rQ.quality === 70 && rQ.images?.[0]?.endsWith(".jxl")), "jakość JXL ustawiona w panelu (70) jest użyta przy kodowaniu i zadeklarowana w imageQuality (" + rQ.quality + ")");
      ok(rPng.thumb && /\.webp$/.test(rPng.thumb) && mediaOf(rPng.thumb).length <= 6000, "brak miniatury → serwer zrobił ją sam (WebP ≤ 6 kB, mieści się w budziku)");
      const mWb = await mk("meme", { title: "WBMP" });
      const rWb = await upload(mWb, "application/octet-stream", read(wbmp), false);
      ok(rWb.status === 200 && /\.(jxl|webp)$/.test(rWb.images?.[0] || ""), "WBMP (format spoza listy aplikacji) → przekonwertowany (" + (rWb.images?.[0] || rWb.error) + ")");
      const pJ = await mk("post", { author: "J", text: "z JPG" });
      const rJ = await upload(pJ, "image/jpeg", jpgExif, false);
      ok(rJ.status === 200 && !mediaOf(rJ.images[0]).includes("SEKRETNE-GPS"), "JPG z EXIF/GPS → obraz bez metadanych");
      const mGif = await mk("meme", { title: "GIF" });
      const rG = await upload(mGif, "image/gif", read(gif), false);
      ok(rG.status === 200 && /\.webp$/.test(rG.images?.[0] || "") && media.sniffImage(mediaOf(rG.images[0])) === "webp", "animowany GIF → animowany WebP");
      const bad = await mk("meme", { title: "śmieć" });
      const rBad = await upload(bad, "image/png", Buffer.from("to nie jest obraz"), false);
      ok(rBad.status === 415 && rBad.error, "plik, który nie jest obrazem → 415 z komunikatem");

      // --- film ---
      const pV = await mk("post", { author: "V", text: "film 60 kl/s z AAC" });
      const rV = await upload(pV, "application/octet-stream", read(v60), false, "video");
      ok(rV.status === 200 && rV.video?.hevc && rV.video?.avc, "film 60 kl/s + AAC → H.265 i H.264");
      for (const k of ["hevc", "avc"]) {
        const b = rV.video?.[k] ? mediaOf(rV.video[k].file) : null;
        const info = b && media.mp4VideoInfo(b);
        ok(info && info.codec === k && info.fps <= 30.05 && media.mp4AudioCodec(b) === "Opus" && media.mp4FastStart(b) === b,
          k.toUpperCase() + ": kodek, ≤ 30 kl/s (" + (info && info.fps) + "), dźwięk Opus, moov na początku");
      }
      const pW = await mk("post", { author: "W", text: "film VP9/WebM" });
      const rW = await upload(pW, "application/octet-stream", read(vp9), false, "video");
      ok(rW.status === 200 && rW.video?.hevc && rW.video?.avc, "film VP9 w WebM → MP4 (H.265 + H.264)");

      // --- dźwięk ---
      const pA = await mk("post", { author: "A", text: "dźwięk" });
      const rA = await upload(pA, "audio/wav", read(wav), false, "audio");
      ok(rA.status === 200 && media.sniffAudio(mediaOf(rA.audio.file)) === "opus", "WAV → Opus w Ogg");
      const rA2 = await upload(pA, "audio/ogg", read(vorbis), false, "audio");
      ok(rA2.status === 200 && media.sniffAudio(mediaOf(rA2.audio.file)) === "opus", "Ogg Vorbis → Opus");

      // --- manifest minimalny + usunięcia w osobnym pliku ---
      const m0 = await man();
      const allowed = ["altEndpoints", "canBePrimary", "capabilities", "content", "contentVersions", "contractVersion", "description", "linkPlatforms", "name", "push", "terms", "transport"];
      ok(Object.keys(m0).every((k) => allowed.includes(k)), "manifest zawiera tylko konfigurację i listę plików (klucze: " + Object.keys(m0).join(", ") + ")");
      ok(!m0.posts && !m0.memes && !m0.articles && !("deletions" in m0), "w manifeście nie ma ani treści, ani usunięć");
      const art = (await api("item/create", { type: "article", title: "Kasowany", source: "S", url: "https://example.org/del/2" })).json.item.id;
      ok((await api("item/delete", { id: art })).status === 200, "usunięcie wpisu");
      const m1 = await man();
      ok(m1.content.at(-1) === "post/usuniecia.json" && /^[0-9a-f]{16}$/.test(m1.contentVersions["post/usuniecia.json"]), "post/usuniecia.json na końcu listy plików, wersja = skrót listy");
      const del = await file("post/usuniecia.json");
      ok(del.deletions?.includes("https://example.org/del/2") && !("deletions" in m1), "usunięty link leży w pliku usunięć, nie w manifeście");
    } finally {
      C.child.kill();
      await wait(1500);
      fs.rmSync(DATA_C, { recursive: true, force: true, maxRetries: 25, retryDelay: 200 });
      fs.rmSync(TMP, { recursive: true, force: true, maxRetries: 25, retryDelay: 200 });
    }
  }
}

// I-16: autotest e2e.js wypisuje wynik także na Windows
const selfTest = spawnSync(process.execPath, [join(SRV, "e2e.js")], { encoding: "utf8" });
ok(/E2E self-test: OK/.test(selfTest.stdout), "I-16: `node e2e.js` wypisuje wynik");

await wait(500);
fs.rmSync(DATA, { recursive: true, force: true, maxRetries: 25, retryDelay: 200 });
fs.rmSync(DATA_B, { recursive: true, force: true, maxRetries: 25, retryDelay: 200 });
console.log(failures ? `\nWYNIK: ${failures} błędów` : "\nWYNIK: wszystko OK");
process.exit(failures ? 1 : 0);
