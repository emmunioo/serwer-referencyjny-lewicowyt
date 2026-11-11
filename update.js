// Aktualizacje serwera z GitHub Releases — odpowiednik modułu aktualizacji aplikacji lewicowYT
// (GitHubUpdateChecker / AppUpdateManager), dostosowany do serwera:
//  • sprawdza listę wydań repozytorium (https://api.github.com/repos/<repo>/releases),
//  • wybiera NAJNOWSZE wydanie nowsze od bieżącej wersji (porównanie semver z wersjami wstępnymi; wydania wstępne
//    tylko gdy bieżąca wersja też jest wstępna; szkice pomijane),
//  • aktualizacja „wymagana” tylko po jawnym markerze [security-mandatory] w opisie wydania,
//  • pobiera plik .zip wydania wyłącznie z github.com (i jego hostów plików), sprawdza SHA-256 z GitHuba (`digest`)
//    i rozmiar, nic nie instaluje bez zgodnego skrótu,
//  • rozpakowuje własnym, ostrożnym czytnikiem ZIP (bez ścieżek wychodzących, bez dowiązań, z limitami),
//    sprawdza, że w paczce jest server.js i package.json z TĄ SAMĄ wersją co wydanie,
//  • robi kopię zastępowanych plików (można cofnąć) i podmienia pliki; data/, tools/, engine*/ i node_modules/
//    nigdy nie są ruszane,
//  • restart: serwer kończy się kodem 75, a start.bat / start.sh uruchamiają go ponownie w tym samym oknie.
// Instalacja jest ZAWSZE ręczna (przycisk w panelu); w tle serwer co 12 h tylko sprawdza, czy jest nowa wersja.

import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import zlib from "node:zlib";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { join, dirname, posix } from "node:path";
import { fileURLToPath } from "node:url";
import { DATA_DIR } from "./store.js";

export const APP_DIR = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_REPO = "emmunioo/serwer-referencyjny-lewicowyt";
export const RESTART_EXIT_CODE = 75;
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const API_BASE = process.env.UPDATE_API_BASE || "https://api.github.com";
const TEST_MODE = process.env.UPDATE_ALLOW_INSECURE_TEST === "1" && process.env.NODE_ENV === "test"; // wyłącznie testy: mock na 127.0.0.1
const MANDATORY_MARKER = "[security-mandatory]";
const MAX_ASSET_BYTES = 200 * 1024 * 1024;
const MAX_UNPACKED_BYTES = 400 * 1024 * 1024;
const MAX_FILE_BYTES = 150 * 1024 * 1024;
const MAX_ENTRIES = 3000;
const MAX_NOTES = 20_000;
const SAFE_ASSET = /^[A-Za-z0-9._-]{1,200}$/;
const SKIP_PREFIXES = ["data/", "tools/", "engine/", "engine-tor/", "node_modules/", ".git/"];
const SKIP_FILES = new Set([".enginepath"]);
const PACKAGE_NAME = "lewicowyt-serwer-spolecznosci";
const KEEP_BACKUPS = 3;

export const repository = () => (REPO_RE.test(process.env.UPDATE_REPO || "") ? process.env.UPDATE_REPO : DEFAULT_REPO);
export function currentVersion() {
  return JSON.parse(fs.readFileSync(join(APP_DIR, "package.json"), "utf8")).version;
}

// ------------------------------------------------------------------ wersje (jak w aplikacji) -------------
function parseVersion(raw) {
  const n = String(raw).trim().replace(/^[vV]/, "").split("+")[0];
  const dash = n.indexOf("-");
  const core = dash < 0 ? n : n.slice(0, dash);
  const pre = dash < 0 ? "" : n.slice(dash + 1);
  if (!/^\d+(\.\d+)*$/.test(core)) throw new Error(`Nieprawidłowy numer wersji: ${raw}`);
  if (pre && !/^[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*$/.test(pre)) throw new Error(`Nieprawidłowa wersja wstępna: ${raw}`);
  return { core: core.split(".").map(BigInt), pre: pre ? pre.split(".") : [] };
}

export function compareVersions(a, b) {
  const x = parseVersion(a), y = parseVersion(b);
  for (let i = 0; i < Math.max(x.core.length, y.core.length); i++) {
    const l = x.core[i] ?? 0n, r = y.core[i] ?? 0n;
    if (l !== r) return l < r ? -1 : 1;
  }
  if (!x.pre.length && !y.pre.length) return 0;
  if (!x.pre.length) return 1;
  if (!y.pre.length) return -1;
  for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
    const l = x.pre[i], r = y.pre[i];
    if (l === undefined) return -1;
    if (r === undefined) return 1;
    const ln = /^\d+$/.test(l), rn = /^\d+$/.test(r);
    let c;
    if (ln && rn) c = BigInt(l) < BigInt(r) ? -1 : BigInt(l) > BigInt(r) ? 1 : 0;
    else if (ln) c = -1;
    else if (rn) c = 1;
    else c = l < r ? -1 : l > r ? 1 : 0;
    if (c) return c;
  }
  return 0;
}

const allowsPrereleases = (current) => { try { return parseVersion(current).pre.length > 0; } catch { return false; } };

// ------------------------------------------------------------------ wybór wydania ------------------------
/** Zwraca { state: "available"|"uptodate", ... }; rzuca Error, gdy repozytorium nie ma poprawnego wydania. */
export function selectUpdate(releases, current, repo = repository()) {
  if (!Array.isArray(releases)) throw new Error("Nieoczekiwana odpowiedź GitHuba");
  const includePre = allowsPrereleases(current);
  const candidates = [];
  let anyValid = false;
  for (const r of releases) {
    try {
      if (!r || r.draft) continue;
      const tag = String(r.tag_name || "").trim();
      if (tag.length < 1 || tag.length > 100) continue;
      const version = tag.replace(/^[vV]/, "");
      const parsed = parseVersion(version);
      const asset = pickAsset(r.assets, repo);
      if (!asset) continue;
      anyValid = true;
      if (!includePre && (r.prerelease || parsed.pre.length)) continue;
      const body = String(r.body || "").trim();
      candidates.push({
        version,
        releasePage: safeReleasePage(r.html_url, repo),
        asset,
        notes: body.slice(0, MAX_NOTES),
        mandatory: body.toLowerCase().includes(MANDATORY_MARKER),
        publishedAt: r.published_at || null,
      });
    } catch { /* wadliwe wydanie pomijamy */ }
  }
  if (!anyValid) throw new Error("Repozytorium nie ma publicznego wydania z plikiem .zip serwera i skrótem SHA-256.");
  const newer = candidates.filter((c) => compareVersions(c.version, current) > 0).sort((a, b) => compareVersions(b.version, a.version))[0];
  return newer ? { state: "available", ...newer } : { state: "uptodate", version: current };
}

function pickAsset(assets, repo) {
  const zips = (Array.isArray(assets) ? assets : []).map((a) => {
    const name = String(a?.name || "").trim();
    const size = Number(a?.size);
    if (!SAFE_ASSET.test(name) || name.includes("..") || !/\.zip$/i.test(name) || !(size >= 1 && size <= MAX_ASSET_BYTES)) return null;
    const url = safeDownloadUrl(String(a.browser_download_url || ""), repo);
    const m = /^sha256:([a-fA-F0-9]{64})$/.exec(String(a.digest || ""));
    if (!url || !m) return null; // bez skrótu nie instalujemy kodu
    return { name, size, url, sha256: m[1].toLowerCase() };
  }).filter(Boolean);
  return zips.find((z) => /^serwer/i.test(z.name)) || zips[0] || null;
}

function safeDownloadUrl(value, repo) {
  let u;
  try { u = new URL(value); } catch { return null; }
  if (u.username || u.password) return null;
  if (TEST_MODE && u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost")) return u.toString();
  if (u.protocol !== "https:" || u.hostname.toLowerCase() !== "github.com" || (u.port && u.port !== "443")) return null;
  if (!u.pathname.toLowerCase().startsWith(`/${repo.toLowerCase()}/releases/download/`)) return null;
  return u.toString();
}

function safeReleasePage(value, repo) {
  try {
    const u = new URL(String(value));
    if (u.protocol === "https:" && u.hostname.toLowerCase() === "github.com" && u.pathname.toLowerCase().startsWith(`/${repo.toLowerCase()}/`)) return u.toString();
  } catch { /* nic */ }
  return `https://github.com/${repo}/releases`;
}

// ------------------------------------------------------------------ pobieranie ---------------------------
function hostAllowed(host) {
  const h = host.toLowerCase();
  return h === "github.com" || h === "api.github.com" || h === "objects.githubusercontent.com" || h === "release-assets.githubusercontent.com";
}

function fetchBuffer(url, { maxBytes, headers = {}, redirects = 6, timeoutMs = 120_000 } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch { reject(new Error("zły adres")); return; }
    const insecureOk = TEST_MODE && u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost");
    if (!insecureOk && (u.protocol !== "https:" || !hostAllowed(u.hostname))) { reject(new Error(`adres spoza GitHuba odrzucony: ${u.hostname}`)); return; }
    const mod = u.protocol === "http:" ? http : https;
    const req = mod.get(u, { headers: { "User-Agent": "lewicowyt-serwer-aktualizacja", Accept: "*/*", ...headers }, timeout: timeoutMs }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        if (redirects <= 0) { reject(new Error("za dużo przekierowań")); return; }
        fetchBuffer(new URL(res.headers.location, u).toString(), { maxBytes, headers, redirects: redirects - 1, timeoutMs }).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) { res.resume(); reject(new Error(res.statusCode === 404 ? "HTTP 404" : `HTTP ${res.statusCode}`)); return; }
      const declared = Number(res.headers["content-length"]);
      if (declared > maxBytes) { res.destroy(); reject(new Error("plik za duży")); return; }
      const chunks = []; let n = 0;
      res.on("data", (c) => { n += c.length; if (n > maxBytes) { res.destroy(); reject(new Error("plik za duży")); return; } chunks.push(c); });
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new Error("przekroczono czas")));
    req.on("error", reject);
  });
}

// ------------------------------------------------------------------ ZIP: czytnik i budowniczy ------------
/** Ostrożny czytnik ZIP (store/deflate, bez ZIP64, bez szyfrowania). Zwraca [{ name, data, mode }]. */
export function readZip(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65535); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error("to nie jest poprawny plik ZIP");
  const count = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOff = buf.readUInt32LE(eocd + 16);
  if (count === 0xffff || cdOff === 0xffffffff || cdOff + cdSize > buf.length) throw new Error("ZIP64 / uszkodzony ZIP nieobsługiwany");
  if (count > MAX_ENTRIES) throw new Error("za dużo plików w paczce");
  const out = [];
  let p = cdOff, total = 0;
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error("uszkodzony katalog ZIP");
    const made = buf.readUInt16LE(p + 4);
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const csize = buf.readUInt32LE(p + 20);
    const usize = buf.readUInt32LE(p + 24);
    const nlen = buf.readUInt16LE(p + 28), elen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32);
    const ext = buf.readUInt32LE(p + 38);
    const lho = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nlen).toString("utf8");
    p += 46 + nlen + elen + clen;
    if (name.endsWith("/")) continue; // katalog
    if (flags & 1) throw new Error("zaszyfrowany ZIP nieobsługiwany");
    const unixMode = (made >> 8) === 3 ? (ext >>> 16) : 0;
    if ((unixMode & 0o170000) === 0o120000) throw new Error(`dowiązanie symboliczne w paczce odrzucone: ${name}`);
    if (usize > MAX_FILE_BYTES) throw new Error(`plik za duży w paczce: ${name}`);
    total += usize;
    if (total > MAX_UNPACKED_BYTES) throw new Error("paczka po rozpakowaniu za duża");
    if (buf.readUInt32LE(lho) !== 0x04034b50) throw new Error("uszkodzony nagłówek pliku w ZIP");
    const start = lho + 30 + buf.readUInt16LE(lho + 26) + buf.readUInt16LE(lho + 28);
    const raw = buf.subarray(start, start + csize);
    let data;
    if (method === 0) data = Buffer.from(raw);
    else if (method === 8) data = zlib.inflateRawSync(raw, { maxOutputLength: usize + 1 });
    else throw new Error(`nieobsługiwana metoda kompresji (${method})`);
    if (data.length !== usize) throw new Error(`zły rozmiar pliku w ZIP: ${name}`);
    if (zlib.crc32(data) !== crc) throw new Error(`zła suma kontrolna pliku w ZIP: ${name}`);
    out.push({ name, data, mode: unixMode & 0o777 });
  }
  return out;
}

/** Buduje ZIP (deflate) z listy { name, data, mode? } — do pakowania wydań i do testów. */
export function buildZip(files) {
  const locals = [], central = [];
  let offset = 0;
  for (const f of files) {
    const name = Buffer.from(f.name, "utf8");
    const data = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data);
    const comp = zlib.deflateRawSync(data, { level: 9 });
    const useDeflate = comp.length < data.length;
    const body = useDeflate ? comp : data;
    const crc = zlib.crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x0800, 6); lh.writeUInt16LE(useDeflate ? 8 : 0, 8);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(body.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(name.length, 26);
    locals.push(lh, name, body);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(0x031e, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x0800, 8); ch.writeUInt16LE(useDeflate ? 8 : 0, 10);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(body.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(((0o100000 | (f.mode ?? 0o644)) << 16) >>> 0, 38); ch.writeUInt32LE(offset, 42);
    central.push(ch, name);
    offset += lh.length + name.length + body.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

// ------------------------------------------------------------------ stan, sprawdzanie ---------------------
const state = { checking: false, installing: false, last: null, lastError: null, checkedAt: 0, pendingRestart: false };

export function status() {
  const cur = currentVersion();
  return {
    repository: repository(),
    current: cur,
    checking: state.checking,
    installing: state.installing,
    checkedAt: state.checkedAt || null,
    result: state.last ? { ...state.last } : null,
    error: state.lastError,
    pendingRestart: state.pendingRestart,
    backups: listBackups().map((b) => ({ id: b.id, from: b.manifest.from, to: b.manifest.to, at: b.manifest.at })),
    restartHint: "Po instalacji serwer kończy się kodem 75; start.bat / start.sh (albo systemd z Restart=always) uruchamiają go ponownie.",
  };
}

export async function check() {
  if (state.checking) return status();
  state.checking = true;
  try {
    const cur = currentVersion();
    const body = await fetchBuffer(`${API_BASE}/repos/${repository()}/releases?per_page=100`, { maxBytes: 4_000_000, headers: { Accept: "application/vnd.github+json" }, timeoutMs: 30_000 }).catch((e) => {
      throw new Error(e.message === "HTTP 404" ? "Repozytorium nie ma jeszcze opublikowanego wydania (albo nie jest publiczne)." : `Nie udało się sprawdzić wydań: ${e.message}`);
    });
    state.last = selectUpdate(JSON.parse(body.toString("utf8")), cur);
    state.lastError = null;
    if (state.last.state === "available") console.log(`[aktualizacje] dostępna nowa wersja ${state.last.version}${state.last.mandatory ? " (WYMAGANA — bezpieczeństwo)" : ""}`);
  } catch (e) {
    state.lastError = e.message;
    state.last = null;
  } finally {
    state.checkedAt = Date.now();
    state.checking = false;
  }
  return status();
}

// ------------------------------------------------------------------ instalacja ---------------------------
const backupsDir = () => join(DATA_DIR, "aktualizacje");

function listBackups() {
  try {
    return fs.readdirSync(backupsDir()).filter((n) => n.startsWith("kopia-")).map((id) => {
      try { return { id, dir: join(backupsDir(), id), manifest: JSON.parse(fs.readFileSync(join(backupsDir(), id, "manifest.json"), "utf8")) }; } catch { return null; }
    }).filter(Boolean).sort((a, b) => (b.manifest.at || 0) - (a.manifest.at || 0)); // najnowsza pierwsza (nie leksykalnie: 1.13.10 < 1.13.9 jako tekst)
  } catch { return []; }
}

/** Ścieżka względna: segmenty tylko [A-Za-z0-9._-], bez „..”, bez końcowej kropki/spacji (Windows) i bez dwukropka (strumienie NTFS). */
export function isSafeRel(rel) {
  return typeof rel === "string" && rel.length > 0 && rel.length <= 300 && rel.split("/").every((seg) => /^[A-Za-z0-9._-]+$/.test(seg) && seg !== "." && seg !== ".." && !/[. ]$/.test(seg));
}

export function normalizeEntries(entries) {
  // paczka może mieć jeden katalog główny (np. serwer-1.2.0/) — odcinamy go
  for (const e of entries) {
    const n = e.name;
    if (n.startsWith("/") || n.startsWith("\\") || /^[A-Za-z]:/.test(n) || n.includes("\\") || n.split("/").some((seg) => seg === "..") || [...n].some((c) => c < " ")) {
      throw new Error(`niebezpieczna ścieżka w paczce: ${n}`);
    }
  }
  const names = entries.map((e) => e.name.replace(/\\/g, "/"));
  const roots = new Set(names.map((n) => n.split("/")[0]));
  const strip = roots.size === 1 && names.every((n) => n.includes("/")) ? [...roots][0] + "/" : "";
  const out = [];
  const seen = new Set();
  for (const [i, e] of entries.entries()) {
    let rel = names[i].slice(strip.length);
    if (!rel) continue;
    if (e.name.includes("\\") || rel.startsWith("/") || /^[A-Za-z]:/.test(rel) || rel.split("/").some((s) => s === ".." || s === "." || s === "") || [...rel].some((c) => c < " ")) {
      throw new Error(`niebezpieczna ścieżka w paczce: ${e.name}`);
    }
    if (!isSafeRel(rel)) throw new Error(`niebezpieczna ścieżka w paczce: ${e.name}`);
    rel = posix.normalize(rel);
    if (seen.has(rel.toLowerCase())) throw new Error(`powtórzona ścieżka w paczce: ${rel}`);
    seen.add(rel.toLowerCase());
    const low = rel.toLowerCase();
    if (SKIP_FILES.has(low) || SKIP_PREFIXES.some((p) => low.startsWith(p))) continue; // dane i silnik użytkownika zostają (także gdy paczka użyje innej wielkości liter — Windows/macOS)
    out.push({ rel, data: e.data, mode: e.mode });
  }
  return out;
}

/** Pobiera, weryfikuje i instaluje wydanie wskazane przez ostatnie sprawdzenie. Zwraca { ok, from, to }. */
export async function install() {
  if (state.installing) throw new Error("Aktualizacja już trwa");
  state.installing = true;
  try {
    await check();
    if (!state.last || state.last.state !== "available") throw new Error(state.lastError || "Brak nowszej wersji do zainstalowania");
    const rel = state.last;
    const cur = currentVersion();
    console.log(`[aktualizacje] pobieram ${rel.asset.name} (${rel.version})…`);
    const buf = await fetchBuffer(rel.asset.url, { maxBytes: rel.asset.size + 1024 });
    if (buf.length !== rel.asset.size) throw new Error(`Rozmiar pobranego pliku (${buf.length}) różni się od zadeklarowanego (${rel.asset.size})`);
    const got = crypto.createHash("sha256").update(buf).digest("hex");
    if (got !== rel.asset.sha256) throw new Error("Skrót SHA-256 pobranego pliku NIE zgadza się z podanym przez GitHub — przerywam, nic nie zmieniono");
    const files = normalizeEntries(readZip(buf));
    const pkgEntry = files.find((f) => f.rel === "package.json");
    if (!pkgEntry || !files.some((f) => f.rel === "server.js")) throw new Error("W paczce brakuje server.js albo package.json");
    let pkg;
    try { pkg = JSON.parse(pkgEntry.data.toString("utf8")); } catch { throw new Error("package.json w paczce jest uszkodzony"); }
    if (pkg.name !== PACKAGE_NAME) throw new Error("To nie jest paczka serwera lewicowYT");
    if (compareVersions(pkg.version, rel.version) !== 0) throw new Error(`Wersja w paczce (${pkg.version}) nie zgadza się z wydaniem (${rel.version})`);
    if (compareVersions(pkg.version, cur) <= 0) throw new Error("Paczka nie jest nowsza od bieżącej wersji");

    // A-11: zanim cokolwiek podmienimy — kontrola składni każdego pliku JavaScript z paczki (Node --check na kopii w katalogu tymczasowym)
    const stage = join(backupsDir(), `staging-${Date.now()}`);
    try {
      for (const f of files) { const p = join(stage, f.rel); fs.mkdirSync(dirname(p), { recursive: true }); fs.writeFileSync(p, f.data); }
      for (const f of files.filter((x) => /\.(m?js)$/.test(x.rel))) {
        const r = spawnSync(process.execPath, ["--check", join(stage, f.rel)], { encoding: "utf8", timeout: 30_000 });
        if (r.status !== 0) throw new Error(`Plik ${f.rel} z paczki ma błąd składni — przerywam, nic nie zmieniono: ${(r.stderr || "").split("\n").find((l) => /Error/.test(l)) || ""}`);
      }
    } finally { try { fs.rmSync(stage, { recursive: true, force: true }); } catch { /* ignore */ } }

    // kopia zastępowanych plików (do cofnięcia)
    const id = `kopia-${cur}-${Date.now()}`;
    const bdir = join(backupsDir(), id);
    fs.mkdirSync(bdir, { recursive: true });
    const replaced = [], created = [];
    for (const f of files) {
      const target = join(APP_DIR, f.rel);
      if (fs.existsSync(target)) {
        const dest = join(bdir, "pliki", f.rel);
        fs.mkdirSync(dirname(dest), { recursive: true });
        fs.copyFileSync(target, dest);
        replaced.push(f.rel);
      } else created.push(f.rel);
    }
    fs.writeFileSync(join(bdir, "manifest.json"), JSON.stringify({ from: cur, to: rel.version, at: Date.now(), replaced, created }, null, 2));

    try {
      for (const f of files) writeAtomic(join(APP_DIR, f.rel), f.data, f.rel.endsWith(".sh") ? 0o755 : (f.mode || 0o644));
    } catch (e) {
      restoreBackup(bdir, { replaced, created });
      throw new Error(`Podmiana plików nie powiodła się (${e.message}) — przywrócono poprzednią wersję`);
    }
    pruneBackups();
    state.pendingRestart = true;
    state.last = { state: "installed", version: rel.version };
    console.log(`[aktualizacje] zainstalowano ${rel.version} (z ${cur}); wymagany restart serwera`);
    return { ok: true, from: cur, to: rel.version, files: files.length, backup: id };
  } finally {
    state.installing = false;
  }
}

function writeAtomic(path, data, mode) {
  fs.mkdirSync(dirname(path), { recursive: true });
  const tmp = path + ".nowy";
  fs.writeFileSync(tmp, data, { mode });
  fs.renameSync(tmp, path);
}

function restoreBackup(bdir, m) {
  const ok = (rel) => isSafeRel(rel) && !SKIP_PREFIXES.some((p) => rel.toLowerCase().startsWith(p));
  for (const rel of (m.replaced || []).filter(ok)) {
    try { fs.copyFileSync(join(bdir, "pliki", rel), join(APP_DIR, rel)); } catch { /* najlepsza próba */ }
  }
  for (const rel of (m.created || []).filter(ok)) { try { fs.unlinkSync(join(APP_DIR, rel)); } catch { /* ignore */ } }
}

function pruneBackups() {
  for (const b of listBackups().slice(KEEP_BACKUPS)) { try { fs.rmSync(b.dir, { recursive: true, force: true }); } catch { /* ignore */ } }
}

/** Cofa ostatnią aktualizację (pliki z kopii). */
export function rollback() {
  const b = listBackups()[0];
  if (!b) throw new Error("Brak kopii poprzedniej wersji");
  restoreBackup(b.dir, b.manifest);
  // zmieniamy tylko NAZWĘ katalogu kopii, nie całą ścieżkę (katalog nadrzędny też może zawierać „kopia-”)
  try { fs.renameSync(b.dir, join(dirname(b.dir), b.id.replace(/^kopia-/, "cofnieta-"))); } catch { /* ignore */ }
  state.pendingRestart = true;
  state.last = null;
  console.log(`[aktualizacje] przywrócono wersję ${b.manifest.from}; wymagany restart serwera`);
  return { ok: true, restoredTo: b.manifest.from };
}

// ------------------------------------------------------------------ sprawdzanie w tle ---------------------
const CHECK_EVERY_MS = 12 * 60 * 60 * 1000;
export function startBackgroundChecks(isEnabled) {
  const tick = () => { if (isEnabled()) check().catch(() => {}); };
  const first = setTimeout(tick, 2 * 60 * 1000);
  const loop = setInterval(tick, CHECK_EVERY_MS + Math.floor(Math.random() * 30 * 60 * 1000));
  first.unref?.(); loop.unref?.();
}
