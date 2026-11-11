// Szyfrowanie E2E budzika (ECIES): aplikacja rejestruje swoj klucz PUBLICZNY (P-256, punkt
// nieskompresowany 65 B, base64), a serwer szyfruje maly ladunek tak, ze odczyta go TYLKO ta apka.
// Posrednik (relay LEP, ntfy) widzi jedynie szum. Zero zaleznosci (node:crypto).
//
// Schemat (musi sie zgadzac z aplikacja — CommunityE2E.kt):
//   eph = efemeryczna para P-256
//   shared = ECDH(eph.priv, pub_apki)              // 32 B (wspolrzedna X)
//   key = HKDF-SHA256(ikm=shared, salt="", info="lewicowyt/push/e2e/v1", 32 B)
//   iv = 12 losowych B; {ct, tag} = AES-256-GCM(key, iv, plaintext)
//   blob(base64) = JSON { v:1, epk, iv, ct, tag }  // wszystkie pola base64
//
// plaintext (po odszyfrowaniu) = JSON { t, at, img? } gdzie:
//   t   — typ zdarzenia ("significant"), at — znacznik czasu zmiany,
//   img — OPCJONALNA miniatura base64; apka pokazuje ja w powiadomieniu BEZ pobierania z sieci
//         (zero korelacji obrazek↔push po IP). Trzymaj mala — budzik LEP ma limit 16 KB.

import crypto from "node:crypto";
import { pathToFileURL } from "node:url";

const CURVE = "prime256v1";
const INFO = Buffer.from("lewicowyt/push/e2e/v1");
const b64 = (b) => Buffer.from(b).toString("base64");

/**
 * Czy string to poprawny klucz publiczny P-256 (65 B, prefiks 0x04) LEŻĄCY NA KRZYWEJ.
 * F-08: sama długość+prefiks nie wystarcza — punkt spoza krzywej przechodził walidację, a potem
 * `computeSecret` rzucał ERR_CRYPTO_ECDH_INVALID_PUBLIC_KEY (poison-pill zrywał wysyłkę do wszystkich).
 * Tu wymuszamy odrzucenie takiego punktu już przy walidacji (próbny ECDH rzuca dla punktu off-curve).
 */
const keyOk = new Map();
export function isValidPublicKey(pubB64) {
  const memo = keyOk.get(pubB64);
  if (memo !== undefined) return memo;
  const ok = isValidPublicKeyRaw(pubB64);
  if (keyOk.size > 20000) keyOk.clear();
  keyOk.set(pubB64, ok);
  return ok;
}
function isValidPublicKeyRaw(pubB64) {
  try {
    const raw = Buffer.from(String(pubB64), "base64");
    if (raw.length !== 65 || raw[0] !== 0x04) return false;
    const probe = crypto.createECDH(CURVE);
    probe.generateKeys();
    probe.computeSecret(raw); // rzuci, gdy punkt nie leży na krzywej P-256
    return true;
  } catch { return false; }
}

/**
 * Szyfruje obiekt do apki o kluczu publicznym pubB64. Zwraca base64 blob albo null,
 * gdy brak/zly klucz (wtedy wolajacy wysle zwykly, niezaszyfrowany budzik).
 */
export function encryptFor(pubB64, plaintextObj) {
  if (!isValidPublicKey(pubB64)) return null;
  const pub = Buffer.from(pubB64, "base64");
  const ecdh = crypto.createECDH(CURVE);
  const epk = ecdh.generateKeys(); // punkt nieskompresowany 65 B
  const shared = ecdh.computeSecret(pub); // 32 B (X)
  const key = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.alloc(0), INFO, 32));
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const pt = Buffer.from(JSON.stringify(plaintextObj), "utf8");
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();
  return b64(JSON.stringify({ v: 1, epk: b64(epk), iv: b64(iv), ct: b64(ct), tag: b64(tag) }));
}

// --- self-test (uruchom: node e2e.js) — sprawdza szyfrowanie i deszyfrowanie po stronie Node ---
// I-16: pathToFileURL — na Windows `file://${argv[1]}` (F:…) nigdy nie równał się import.meta.url
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const app = crypto.createECDH(CURVE);
  const appPub = app.generateKeys();
  const blob = encryptFor(b64(appPub), { t: "significant", at: 123 });
  const j = JSON.parse(Buffer.from(blob, "base64").toString());
  const shared = app.computeSecret(Buffer.from(j.epk, "base64"));
  const key = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.alloc(0), INFO, 32));
  const dec = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(j.iv, "base64"));
  dec.setAuthTag(Buffer.from(j.tag, "base64"));
  const pt = Buffer.concat([dec.update(Buffer.from(j.ct, "base64")), dec.final()]).toString();
  console.log(pt === JSON.stringify({ t: "significant", at: 123 }) ? "E2E self-test: OK" : "E2E self-test: BLAD");
}
