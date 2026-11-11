// Szyfrowanie bazy danych serwera — z przyspieszeniem sprzętowym CPU.
//
// Co robi ten plik:
//  1) wykrywa możliwości procesora (AES-NI / ARM AES, PCLMULQDQ / PMULL, SHA-NI / ARM SHA2, AVX2 / NEON),
//  2) trzyma listę szyfrów od NAJLEPSZEGO do najgorszego i wybiera pierwszy, który CPU naprawdę przyspiesza
//     (i który przeszedł test poprawności oraz test szybkości),
//  3) szyfruje i odszyfrowuje pojedyncze wartości (wiersze bazy, kawałki plików) z uwierzytelnieniem (AEAD),
//  4) zarządza kluczem głównym: plik klucza obok danych (domyślnie) albo hasło (klucz zaszyfrowany scryptem).
//
// Szyfrowanie robi OpenSSL wbudowany w Node.js (crypto) — sam, w czasie działania, korzysta z instrukcji AES-NI,
// PCLMULQDQ, SHA-NI, AVX2 (x86) albo AES/PMULL/SHA2/NEON (ARM), jeśli procesor je ma. Kod w tym pliku decyduje,
// KTÓRY algorytm wybrać, żeby to przyspieszenie faktycznie wykorzystać.
//
// Format zaszyfrowanej wartości:  [wersja=1][id szyfru][nonce/IV][szyfrogram][tag/MAC]
// Id szyfru jest w nagłówku każdej wartości, więc zmiana szyfru nie wymaga zatrzymania serwera ani
// jednoczesnego przepisania wszystkiego (stare wartości odszyfrowują się swoim szyfrem).

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

export const FORMAT_VERSION = 1;
/** Plik multimedialny jest szyfrowany w kawałkach tej wielkości (strumieniowanie bez ładowania całości). */
export const CHUNK = 1024 * 1024;

// ------------------------------------------------------------------ szyfry (od najlepszego) ------------
// hw: cechy CPU, które przyspieszają dany szyfr. auto: kolejność wyboru automatycznego (mniejsza = lepszy).
export const CIPHERS = [
  { id: 1, name: "aes-256-gcm", label: "AES-256-GCM", kind: "aead", keyLen: 32, ivLen: 12, hw: ["aes", "clmul"], auto: 1,
    hwText: "AES-NI (x86) / AES (ARM) + PCLMULQDQ / PMULL",
    note: "standard branżowy; z przyspieszeniem sprzętowym najszybszy i najlepiej zbadany" },
  { id: 2, name: "aes-256-ocb", label: "AES-256-OCB", kind: "aead", keyLen: 32, ivLen: 12, hw: ["aes"], auto: 2,
    hwText: "AES-NI (x86) / AES (ARM)",
    note: "wymaga tylko instrukcji AES (bez mnożenia bez przeniesień); szybki, uwierzytelniony" },
  { id: 3, name: "aes-256-ctr+hmac-sha256", label: "AES-256-CTR + HMAC-SHA-256", kind: "etm", keyLen: 32, ivLen: 16, hw: ["aes"], hwBonus: ["sha"], auto: 3,
    hwText: "AES-NI (x86) / AES (ARM); SHA-NI / SHA2 przyspiesza uwierzytelnianie",
    note: "klasyczne „szyfruj, potem uwierzytelnij”; działa nawet gdy brak PCLMULQDQ/OCB" },
  { id: 4, name: "aes-128-gcm", label: "AES-128-GCM", kind: "aead", keyLen: 16, ivLen: 12, hw: ["aes", "clmul"], auto: null,
    hwText: "AES-NI (x86) / AES (ARM) + PCLMULQDQ / PMULL",
    note: "klucz 128-bitowy: odrobinę szybszy, nadal bezpieczny; wybierany tylko ręcznie" },
  { id: 5, name: "chacha20-poly1305", label: "ChaCha20-Poly1305", kind: "aead", keyLen: 32, ivLen: 12, hw: [], soft: true, auto: 4,
    hwText: "bez wymagań (programowy; używa SSE2/AVX2/NEON, jeśli są)",
    note: "najlepszy wybór bez sprzętowego AES (stare procesory, część ARM i maszyn wirtualnych)" },
  { id: 0, name: "none", label: "Bez szyfrowania (niezalecane)", kind: "none", keyLen: 0, ivLen: 0, hw: [], auto: null,
    hwText: "—", note: "dane w bazie jawne; tylko do testów i diagnostyki" },
];
const BY_ID = new Map(CIPHERS.map((c) => [c.id, c]));
export const cipherById = (id) => BY_ID.get(id) || null;
export const cipherByName = (name) => CIPHERS.find((c) => c.name === name) || null;

const TAG_LEN = 16;
const MAC_LEN = 32;
const HEADER = 2;

// ------------------------------------------------------------------ wykrywanie CPU ----------------------
function parseFlagList(text) {
  return new Set(String(text).toLowerCase().split(/[\s,]+/).filter(Boolean));
}

function featuresFromFlags(flags) {
  const has = (...n) => n.some((x) => flags.has(x));
  return {
    aes: has("aes"),
    clmul: has("pclmulqdq", "pclmul", "pmull"),
    sha: has("sha_ni", "sha", "sha2", "sha256"),
    simd: has("avx2", "avx", "ssse3", "asimd", "neon"),
  };
}

function linuxFlags() {
  const txt = fs.readFileSync("/proc/cpuinfo", "utf8");
  const line = txt.split("\n").find((l) => /^(flags|features)\s*:/i.test(l));
  if (!line) return null;
  return { flags: parseFlagList(line.split(":").slice(1).join(":")), source: "/proc/cpuinfo" };
}

function darwinFlags() {
  const sysctl = (k) => { try { return execFileSync("sysctl", ["-n", k], { encoding: "utf8", timeout: 4000 }).trim(); } catch { return ""; } };
  if (process.arch === "arm64" || sysctl("hw.optional.arm64") === "1") {
    // Apple Silicon: AES, PMULL, SHA1/SHA2 i NEON są w każdym układzie
    return { flags: new Set(["aes", "pmull", "sha2", "asimd"]), source: "Apple Silicon (hw.optional.arm64)" };
  }
  const f = `${sysctl("machdep.cpu.features")} ${sysctl("machdep.cpu.leaf7_features")}`;
  return f.trim() ? { flags: parseFlagList(f), source: "sysctl machdep.cpu" } : null;
}

function windowsFlags() {
  // 1) PowerShell 7 (jeśli jest) zna instrukcje CPU wprost
  try {
    const out = execFileSync("pwsh", ["-NoProfile", "-NonInteractive", "-Command",
      "[pscustomobject]@{aes=[Runtime.Intrinsics.X86.Aes]::IsSupported;pclmul=[Runtime.Intrinsics.X86.Pclmulqdq]::IsSupported;sha=[Runtime.Intrinsics.X86.Sha]::IsSupported;avx2=[Runtime.Intrinsics.X86.Avx2]::IsSupported;ssse3=[Runtime.Intrinsics.X86.Ssse3]::IsSupported}|ConvertTo-Json -Compress"],
    { encoding: "utf8", timeout: 15000, windowsHide: true, stdio: ["ignore", "pipe", "ignore"] });
    const j = JSON.parse(out);
    const flags = new Set();
    if (j.aes) flags.add("aes");
    if (j.pclmul) flags.add("pclmulqdq");
    if (j.sha) flags.add("sha_ni");
    if (j.avx2) flags.add("avx2");
    if (j.ssse3) flags.add("ssse3");
    return { flags, source: "PowerShell 7 (System.Runtime.Intrinsics)" };
  } catch { /* brak pwsh */ }
  // 2) kernel32!IsProcessorFeaturePresent z Windows PowerShell
  const script =
    "$s='[DllImport(\"kernel32.dll\")] public static extern bool IsProcessorFeaturePresent(uint f);';" +
    "Add-Type -MemberDefinition $s -Name K -Namespace W;" +
    "$o=@{};foreach($f in 30,36,40){$o[[string]$f]=[W.K]::IsProcessorFeaturePresent($f)};$o|ConvertTo-Json -Compress";
  const out = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script],
    { encoding: "utf8", timeout: 20000, windowsHide: true, stdio: ["ignore", "pipe", "ignore"] });
  const j = JSON.parse(out);
  const flags = new Set();
  if (j["30"]) { flags.add("aes"); flags.add("pmull"); flags.add("sha2"); flags.add("asimd"); } // ARMv8 Crypto Extensions
  // x86: Windows nie ma osobnej flagi AES-NI. AVX2 (flaga 40) mają wyłącznie procesory z AES-NI i PCLMULQDQ
  // (Haswell+/Zen+), więc to jest bezpieczny wniosek. Brak AVX2 → nie wiemy: decyduje test szybkości.
  if (j["40"]) { flags.add("avx2"); flags.add("aes"); flags.add("pclmulqdq"); }
  else if (j["36"]) flags.add("ssse3");
  return { flags, source: j["30"] ? "IsProcessorFeaturePresent (ARMv8 Crypto)" : j["40"] ? "IsProcessorFeaturePresent (AVX2 ⇒ AES-NI + PCLMULQDQ)" : "IsProcessorFeaturePresent (bez AVX2 — AES-NI nieustalone)" };
}

/** Wykrywa procesor i jego instrukcje przyspieszające szyfrowanie. `known` = czy flagi AES są pewne. */
export function detectCpu() {
  const cpus = os.cpus();
  const out = {
    arch: process.arch, platform: process.platform, model: (cpus[0]?.model || "?").trim(), cores: cpus.length,
    features: { aes: false, clmul: false, sha: false, simd: false }, source: "nie wykryto", known: false,
  };
  let got = null;
  try {
    if (process.platform === "linux" || process.platform === "android") got = linuxFlags();
    else if (process.platform === "darwin") got = darwinFlags();
    else if (process.platform === "win32") got = windowsFlags();
  } catch { got = null; }
  if (got) {
    out.features = featuresFromFlags(got.flags);
    out.source = got.source;
    // pewność: mamy listę flag (poza przypadkiem Windows x86 bez AVX2, gdzie AES-NI jest nieustalone)
    out.known = got.flags.size > 0 && !/AES-NI nieustalone/.test(got.source);
  }
  return out;
}

// ------------------------------------------------------------------ narzędzia szyfrujące -----------------
function subkey(master, cipher, purpose = "enc") {
  const len = cipher.kind === "etm" ? cipher.keyLen + 32 : cipher.keyLen;
  return Buffer.from(crypto.hkdfSync("sha256", master, Buffer.alloc(32), `lewicowyt/db/v1/${cipher.name}/${purpose}`, len));
}

/** Klucz do skrótów nazw (np. adresów subskrybentów push), żeby nie leżały w bazie jawnie. */
export function indexKey(master) {
  return Buffer.from(crypto.hkdfSync("sha256", master, Buffer.alloc(32), "lewicowyt/db/v1/index", 32));
}

export class Crypt {
  constructor(master, cipherId, { allowNone = false } = {}) {
    if (!Buffer.isBuffer(master) || master.length !== 32) throw new Error("klucz główny musi mieć 32 bajty");
    this.master = master;
    this.allowNone = allowNone;
    this.keys = new Map();
    this.setCipher(cipherId);
    this.index = indexKey(master);
  }

  setCipher(id) {
    const c = cipherById(id);
    if (!c) throw new Error(`nieznany szyfr ${id}`);
    this.cipherId = id;
  }

  get cipher() { return cipherById(this.cipherId); }

  keyFor(c) {
    let k = this.keys.get(c.id);
    if (!k) { k = subkey(this.master, c); this.keys.set(c.id, k); }
    return k;
  }

  /** Szyfruje `plain` (Buffer/string); `aad` wiąże szyfrogram z miejscem w bazie (tabela:klucz). */
  encrypt(plain, aad, cipherId = this.cipherId) {
    const p = Buffer.isBuffer(plain) ? plain : Buffer.from(String(plain), "utf8");
    const c = cipherById(cipherId);
    const head = Buffer.from([FORMAT_VERSION, c.id]);
    if (c.kind === "none") return Buffer.concat([head, p]);
    const key = this.keyFor(c);
    const iv = crypto.randomBytes(c.ivLen);
    const a = Buffer.from(String(aad), "utf8");
    if (c.kind === "aead") {
      const ci = crypto.createCipheriv(c.name, key, iv, { authTagLength: TAG_LEN });
      ci.setAAD(a);
      const ct = Buffer.concat([ci.update(p), ci.final()]);
      return Buffer.concat([head, iv, ct, ci.getAuthTag()]);
    }
    // szyfruj-potem-uwierzytelnij: AES-256-CTR + HMAC-SHA-256 (osobne podklucze)
    const ci = crypto.createCipheriv("aes-256-ctr", key.subarray(0, 32), iv);
    const ct = Buffer.concat([ci.update(p), ci.final()]);
    const mac = crypto.createHmac("sha256", key.subarray(32)).update(head).update(iv).update(lenBuf(a.length)).update(a).update(ct).digest();
    return Buffer.concat([head, iv, ct, mac]);
  }

  decrypt(blob, aad) {
    const b = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
    if (b.length < HEADER || b[0] !== FORMAT_VERSION) throw new Error("nieznany format zaszyfrowanej wartości");
    const c = cipherById(b[1]);
    if (!c) throw new Error(`nieznany szyfr w nagłówku (${b[1]})`);
    if (c.kind === "none") {
      if (!this.allowNone) throw new Error("wartość bez szyfrowania w zaszyfrowanej bazie (podmiana?)");
      return b.subarray(HEADER);
    }
    const key = this.keyFor(c);
    const a = Buffer.from(String(aad), "utf8");
    const tail = c.kind === "aead" ? TAG_LEN : MAC_LEN;
    if (b.length < HEADER + c.ivLen + tail) throw new Error("zaszyfrowana wartość za krótka");
    const iv = b.subarray(HEADER, HEADER + c.ivLen);
    const ct = b.subarray(HEADER + c.ivLen, b.length - tail);
    const t = b.subarray(b.length - tail);
    if (c.kind === "aead") {
      const d = crypto.createDecipheriv(c.name, key, iv, { authTagLength: TAG_LEN });
      d.setAAD(a);
      d.setAuthTag(t);
      return Buffer.concat([d.update(ct), d.final()]); // final() rzuca przy złym kluczu/zmienionych danych
    }
    const mac = crypto.createHmac("sha256", key.subarray(32)).update(b.subarray(0, HEADER)).update(iv).update(lenBuf(a.length)).update(a).update(ct).digest();
    if (!crypto.timingSafeEqual(mac, t)) throw new Error("błędny klucz albo zmienione dane (MAC)");
    const d = crypto.createDecipheriv("aes-256-ctr", key.subarray(0, 32), iv);
    return Buffer.concat([d.update(ct), d.final()]);
  }

  /** Id szyfru, którym zaszyfrowano wartość. */
  static cipherIdOf(blob) { return blob && blob.length >= HEADER ? blob[1] : null; }
  /** Skrót nazwy (hex) do użycia jako klucz wiersza zamiast jawnej nazwy. */
  ref(name) { return crypto.createHmac("sha256", this.index).update(String(name)).digest("hex"); }
}

function lenBuf(n) { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; }

/** Niezależny klucz główny dla osobnego zastosowania (np. dziennik zdarzeń) — HKDF z klucza głównego bazy. */
export function deriveMaster(master, purpose) {
  return Buffer.from(crypto.hkdfSync("sha256", master, Buffer.alloc(32), `lewicowyt/db/v1/derive/${purpose}`, 32));
}

export const aad = {
  logOuter: (firstSeq) => `logs:${firstSeq}`,
  logInner: (first, last, count, prevHash) => `log:${first}:${last}:${count}:${prevHash}`, // format 1 (bloki sprzed audytu)
  logInner2: (first, last, count, prevHash, tsFirst, tsLast) => `log2:${first}:${last}:${count}:${prevHash}:${tsFirst}:${tsLast}`, // format 2: czasy uwierzytelnione
  meta: (key) => `meta:${key}`,
  item: (id) => `items:${id}`,
  subscriber: (ref) => `subscribers:${ref}`,
  file: (path) => `files:${path}`,
  chunk: (name, idx, chunks, size) => `media:${name}:${idx}:${chunks}:${size}`,
};

// ------------------------------------------------------------------ test poprawności i szybkości --------
/** Czy ten szyfr działa w tym Node.js: szyfruje, odszyfrowuje i wykrywa zmianę danych. */
export function selfTest(cipherId) {
  const c = cipherById(cipherId);
  if (!c) return false;
  if (c.kind === "none") return true;
  try {
    const t = new Crypt(crypto.randomBytes(32), cipherId);
    const msg = crypto.randomBytes(1000);
    const blob = t.encrypt(msg, "test:1");
    if (!t.decrypt(blob, "test:1").equals(msg)) return false;
    const bad = Buffer.from(blob); bad[bad.length - 40] ^= 1;
    try { t.decrypt(bad, "test:1"); return false; } catch { /* oczekiwane */ }
    try { t.decrypt(blob, "test:2"); return false; } catch { /* oczekiwane */ }
    return true;
  } catch { return false; }
}

/** Przepustowość szyfrowania w MB/s (kilka przebiegów po 1 MiB — tak jak zapisujemy pliki). */
export function benchmark(cipherId, { totalMiB = 16 } = {}) {
  const c = cipherById(cipherId);
  if (!c || c.kind === "none") return null;
  try {
    const t = new Crypt(crypto.randomBytes(32), cipherId);
    const buf = crypto.randomBytes(CHUNK);
    t.encrypt(buf, "bench"); // rozgrzewka
    const start = process.hrtime.bigint();
    for (let i = 0; i < totalMiB; i++) t.encrypt(buf, "bench");
    const sec = Number(process.hrtime.bigint() - start) / 1e9;
    return Math.round(totalMiB / Math.max(sec, 1e-6));
  } catch { return null; }
}

/** Czy szyfr jest przyspieszany sprzętowo na tym CPU (wg wykrytych cech). */
export function accelerated(cipher, cpu) {
  if (cipher.kind === "none") return false;
  if (cipher.soft) return !!cpu.features.simd; // ChaCha20 korzysta z SIMD, jeśli jest
  return cipher.hw.every((f) => cpu.features[f]);
}

/**
 * Wybór automatyczny — od najlepszego do najgorszego. Bierze pierwszy szyfr z listy, którego wymagania sprzętowe
 * CPU spełnia, który przechodzi test poprawności i który jest faktycznie szybki (nie wolniejszy niż ~60%
 * ChaCha20 — chroni przed fałszywym „AES-NI” w maszynach wirtualnych). Gdy flag AES nie da się ustalić
 * (np. Windows bez AVX2), pomiar szybkości AES jest rozstrzygający.
 */
export function chooseAuto(cpu) {
  const order = CIPHERS.filter((c) => c.auto != null).sort((a, b) => a.auto - b.auto);
  const chacha = benchmark(5) || 0;
  const trace = [];
  for (const c of order) {
    if (!selfTest(c.id)) { trace.push({ id: c.id, ok: false, why: "ten Node.js nie obsługuje tego szyfru" }); continue; }
    if (c.soft) { trace.push({ id: c.id, ok: true, why: "programowy zapas" }); return { id: c.id, trace }; }
    let hw = c.hw.every((f) => cpu.features[f]);
    let measured = null;
    if (!hw && !cpu.known && c.hw.every((f) => f === "aes" || f === "clmul")) {
      // flagi nieznane: jeśli AES jest ewidentnie szybki, uznajemy sprzęt za obecny
      measured = benchmark(c.id);
      hw = measured != null && chacha > 0 && measured >= chacha * 1.3;
    }
    if (!hw) { trace.push({ id: c.id, ok: false, why: "CPU nie ma wymaganych instrukcji (" + c.hw.join("+") + ")" }); continue; }
    measured = measured ?? benchmark(c.id);
    if (chacha > 0 && measured != null && measured < chacha * 0.6) {
      trace.push({ id: c.id, ok: false, why: `instrukcje są, ale szyfr działa wolno (${measured} MB/s < ChaCha20 ${chacha} MB/s)` });
      continue;
    }
    trace.push({ id: c.id, ok: true, why: `przyspieszany sprzętowo (${measured ?? "?"} MB/s)` });
    return { id: c.id, trace };
  }
  return { id: 5, trace };
}

// ------------------------------------------------------------------ klucz główny i ustawienia ------------
const KEY_HEADER = "LEWICOWYT-DB-KEY-1";
export const settingsPath = (dir) => join(dir, "szyfrowanie.json");
export const keyFilePath = (dir) => process.env.DB_KEY_FILE || join(dir, "klucz-bazy.key");

export function defaultSettings() {
  return { format: 1, cipher: "auto", keyMode: "file", wrapped: null, autoCache: null };
}

export function readSettings(dir) {
  try {
    const s = { ...defaultSettings(), ...JSON.parse(fs.readFileSync(settingsPath(dir), "utf8")) };
    if (s.cipher !== "auto" && !cipherByName(s.cipher)) s.cipher = "auto";
    if (!["file", "passphrase"].includes(s.keyMode)) s.keyMode = "file";
    return s;
  } catch {
    return defaultSettings();
  }
}

export function writeSettings(dir, s) {
  fs.mkdirSync(dir, { recursive: true });
  const tmp = settingsPath(dir) + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(s, null, 2), "utf8");
  fs.renameSync(tmp, settingsPath(dir));
}

export class NeedPassphraseError extends Error {
  constructor() { super("baza jest chroniona hasłem — podaj hasło (DB_PASSPHRASE / DB_PASSPHRASE_FILE albo wpisz je przy starcie)"); this.code = "NEED_PASSPHRASE"; }
}

function readKeyFile(path) {
  const txt = fs.readFileSync(path, "utf8").trim().split(/\r?\n/);
  if (txt[0] !== KEY_HEADER) throw new Error(`plik klucza ${path} ma zły nagłówek`);
  const k = Buffer.from(txt[1] || "", "base64");
  if (k.length !== 32) throw new Error(`plik klucza ${path} ma zły klucz`);
  return k;
}

function writeKeyFile(path, key) {
  fs.mkdirSync(join(path, ".."), { recursive: true });
  fs.writeFileSync(path, `${KEY_HEADER}\n${key.toString("base64")}\n`, { mode: 0o600 });
  try { fs.chmodSync(path, 0o600); } catch { /* Windows */ }
}

const SCRYPT = { N: 1 << 15, r: 8, p: 1 };
function kekFrom(pass, salt, params) {
  return crypto.scryptSync(String(pass), salt, 32, { ...params, maxmem: 256 * 1024 * 1024 });
}

export function wrapKey(master, pass) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", kekFrom(pass, salt, SCRYPT), iv, { authTagLength: TAG_LEN });
  c.setAAD(Buffer.from("lewicowyt/db/keywrap"));
  const ct = Buffer.concat([c.update(master), c.final()]);
  return { kdf: "scrypt", ...SCRYPT, salt: salt.toString("base64"), iv: iv.toString("base64"), ct: ct.toString("base64"), tag: c.getAuthTag().toString("base64") };
}

export function unwrapKey(w, pass) {
  try {
    const d = crypto.createDecipheriv("aes-256-gcm", kekFrom(pass, Buffer.from(w.salt, "base64"), { N: w.N, r: w.r, p: w.p }), Buffer.from(w.iv, "base64"), { authTagLength: TAG_LEN });
    d.setAAD(Buffer.from("lewicowyt/db/keywrap"));
    d.setAuthTag(Buffer.from(w.tag, "base64"));
    return Buffer.concat([d.update(Buffer.from(w.ct, "base64")), d.final()]);
  } catch {
    throw new Error("błędne hasło do bazy");
  }
}

/**
 * Znajduje klucz główny. Kolejność: DB_KEY (64 znaki hex, np. z menedżera sekretów) → hasło (gdy tryb
 * „passphrase”) → plik klucza. `mayCreate` = wolno wygenerować nowy klucz (tylko gdy baza jest pusta/nowa).
 */
export function resolveMasterKey(dir, settings, { passphrase = null, mayCreate }) {
  const env = process.env.DB_KEY;
  if (env) {
    const k = Buffer.from(env.trim(), "hex");
    if (k.length !== 32) throw new Error("DB_KEY musi mieć 64 znaki szesnastkowe (32 bajty)");
    return { key: k, via: "DB_KEY (zmienna środowiskowa)" };
  }
  const wrappedFromFile = readWrappedFile(dir);
  if (settings.keyMode === "file" && !fs.existsSync(keyFilePath(dir)) && wrappedFromFile) { settings.keyMode = "passphrase"; settings.wrapped = wrappedFromFile; } // szyfrowanie.json zgubione — odtwarzamy tryb hasła z klucz-bazy.haslo.json
  if (settings.keyMode === "passphrase" && !settings.wrapped && wrappedFromFile) settings.wrapped = wrappedFromFile;
  if (settings.keyMode === "passphrase" && settings.wrapped) {
    let pass = passphrase || process.env.DB_PASSPHRASE || null;
    if (pass == null && process.env.DB_PASSPHRASE_FILE) pass = fs.readFileSync(process.env.DB_PASSPHRASE_FILE, "utf8").replace(/\r?\n$/, "");
    if (pass == null) throw new NeedPassphraseError();
    return { key: unwrapKey(settings.wrapped, pass), via: "hasło (scrypt)" };
  }
  const kp = keyFilePath(dir);
  if (fs.existsSync(kp)) return { key: readKeyFile(kp), via: `plik klucza (${kp})` };
  if (!mayCreate) {
    throw new Error(`Baza jest zaszyfrowana, a pliku klucza nie ma (${kp}); nie ma też zapisanego klucza chronionego hasłem (klucz-bazy.haslo.json). Przywróć ${"klucz-bazy.key"} albo klucz-bazy.haslo.json (razem z szyfrowanie.json) z kopii albo ustaw DB_KEY / DB_KEY_FILE. ` +
      "Bez klucza danych nie da się odzyskać — serwer celowo nie tworzy nowego klucza.");
  }
  const key = crypto.randomBytes(32);
  writeKeyFile(kp, key);
  return { key, via: `nowy plik klucza (${kp})`, created: true };
}

export function installKeyFile(dir, key) { writeKeyFile(keyFilePath(dir), key); }

/** Nadpisuje plik losowymi bajtami i usuwa (najlepsza próba — na SSD i w migawkach nie daje gwarancji). */
export function shredFile(path) {
  try {
    const size = fs.statSync(path).size;
    fs.writeFileSync(path, crypto.randomBytes(Math.max(size, 64)));
    fs.unlinkSync(path);
  } catch { /* brak pliku */ }
}
export function removeKeyFile(dir) { shredFile(keyFilePath(dir)); }

/** Osobna kopia zapakowanego (hasłem) klucza — do zrobienia kopii zapasowej obok szyfrowanie.json. */
export const wrappedFilePath = (dir) => join(dir, "klucz-bazy.haslo.json");
export function readWrappedFile(dir, suffix = "") {
  try { const w = JSON.parse(fs.readFileSync(wrappedFilePath(dir) + suffix, "utf8")); return w && w.ct ? w : null; } catch { return null; }
}
export function writeWrappedFile(dir, wrapped, suffix = "") { fs.writeFileSync(wrappedFilePath(dir) + suffix, JSON.stringify(wrapped, null, 2), { mode: 0o600 }); }
export function keyFileExists(dir) { return fs.existsSync(keyFilePath(dir)); }
export { writeKeyFile, readKeyFile, keyFilePath as _keyFilePath };

/** Wczytuje hasło z terminala bez echa (gdy serwer startuje w oknie konsoli). */
export function promptHidden(question) {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) { reject(new NeedPassphraseError()); return; }
    process.stdout.write(question);
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    let buf = "";
    const onData = (ch) => {
      for (const c of ch) {
        if (c === "\r" || c === "\n") {
          stdin.setRawMode(false); stdin.pause(); stdin.removeListener("data", onData);
          process.stdout.write("\n");
          resolve(buf);
          return;
        }
        if (c === "\u0003") { stdin.setRawMode(false); process.stdout.write("\n"); process.exit(130); }
        if (c === "\u007f" || c === "\b") buf = buf.slice(0, -1); else buf += c;
      }
    };
    stdin.on("data", onData);
  });
}
