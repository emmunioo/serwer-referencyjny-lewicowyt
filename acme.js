// Automatyczny certyfikat Let's Encrypt (ACME v2, wyzwanie http-01) + samoodnawianie.
// Jedyna zewnętrzna zależność całego serwera: `acme-client` (dojrzała biblioteka ACME —
// ręczne ASN.1/CSR bez zależności byłoby kruche). Ładujemy ją DYNAMICZNIE: bez niej serwer
// nadal działa po HTTP (tryb LAN/testowy), tylko bez HTTPS.
//
// Cert i klucz trzymamy w data/cert/. Serwer HTTPS bierze kontekst przez secureContext()
// i podmienia go po odnowieniu bez restartu (SNICallback). Wyzwania http-01 lądują w
// współdzielonej mapie `challenges`, którą serwer HTTP wystawia pod /.well-known/acme-challenge/.

import fs from "node:fs";
import { join } from "node:path";
import tls from "node:tls";
import { X509Certificate } from "node:crypto";

const RENEW_BEFORE_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;

export class CertManager {
  /** storage: { get(path) → Buffer|null, put(path, bytes) } — certyfikaty i klucze leżą w bazie danych serwera. */
  constructor({ storage, challenges, log = console }) {
    this.storage = storage;
    this.challenges = challenges; // Map<token, keyAuthorization>
    this.log = log;
    this.current = null; // { key, cert }
    this.context = null; // tls.SecureContext
    this.domain = null;
    this.email = null;
    this.staging = process.env.LE_STAGING === "1";
    this.busy = false;
  }

  keyPath(domain) { return `cert/${domain}.key`; }
  crtPath(domain) { return `cert/${domain}.crt`; }
  accountKeyPath() { return "cert/account.key"; }

  hasHttps() { return this.context != null; }

  secureContext() { return this.context; }

  loadFromDisk(domain) {
    try {
      const key = this.storage.get(this.keyPath(domain))?.toString("utf8");
      const cert = this.storage.get(this.crtPath(domain))?.toString("utf8");
      if (key && cert) return { key, cert };
    } catch { /* brak plików */ }
    return null;
  }

  daysLeft(certPem) {
    try {
      const validTo = new Date(new X509Certificate(certPem).validTo).getTime();
      return (validTo - Date.now()) / DAY_MS;
    } catch {
      return -1;
    }
  }

  applyContext(pair) {
    this.current = pair;
    this.context = tls.createSecureContext({ key: pair.key, cert: pair.cert });
  }

  /** Zapewnia ważny certyfikat dla domeny: z dysku jeśli świeży, inaczej wystawia nowy. */
  async ensure(domain, email) {
    this.domain = domain;
    this.email = email;
    const existing = this.loadFromDisk(domain);
    if (existing && this.daysLeft(existing.cert) > RENEW_BEFORE_DAYS) {
      this.applyContext(existing);
      this.log.log(`[acme] Certyfikat z bazy ważny jeszcze ${Math.floor(this.daysLeft(existing.cert))} dni.`);
      return true;
    }
    // A-14: certyfikat bliski wygaśnięcia, ale JESZCZE WAŻNY, uruchamiamy od razu i odnawiamy w tle — nieudane odnowienie nie wyłącza HTTPS
    if (existing && this.daysLeft(existing.cert) > 0) {
      this.applyContext(existing);
      this.log.warn(`[acme] Certyfikat ważny jeszcze ${Math.floor(this.daysLeft(existing.cert))} dni — próbuję go odnowić.`);
      this.issue(domain, email).catch(() => {});
      return true;
    }
    return this.issue(domain, email);
  }

  async issue(domain, email) {
    if (this.busy) return false;
    this.busy = true;
    try {
      const acme = await import("acme-client").catch(() => null);
      if (!acme) {
        this.log.warn("[acme] Brak pakietu 'acme-client' (npm install acme-client) — pomijam HTTPS.");
        return false;
      }
      const accountKey = await this.loadOrCreateAccountKey(acme);
      const client = new acme.Client({
        directoryUrl: this.staging
          ? acme.directory.letsencrypt.staging
          : acme.directory.letsencrypt.production,
        accountKey,
      });
      const [key, csr] = await acme.crypto.createCsr({ commonName: domain });
      this.log.log(`[acme] Zamawiam certyfikat dla ${domain} (${this.staging ? "staging" : "produkcja"})…`);
      const cert = await client.auto({
        csr,
        email: email || undefined,
        termsOfServiceAgreed: true,
        challengePriority: ["http-01"],
        challengeCreateFn: async (_authz, challenge, keyAuthorization) => {
          if (challenge.type === "http-01") this.challenges.set(challenge.token, keyAuthorization);
        },
        challengeRemoveFn: async (_authz, challenge) => {
          if (challenge.type === "http-01") this.challenges.delete(challenge.token);
        },
      });
      const keyPem = key.toString();
      const certPem = cert.toString();
      this.storage.put(this.keyPath(domain), keyPem);
      this.storage.put(this.crtPath(domain), certPem);
      this.applyContext({ key: keyPem, cert: certPem });
      this.log.log(`[acme] Certyfikat wystawiony (ważny ~${Math.floor(this.daysLeft(certPem))} dni).`);
      return true;
    } catch (e) {
      this.log.error(`[acme] Nie udało się wystawić certyfikatu: ${e?.message || e}`);
      return false;
    } finally {
      this.busy = false;
    }
  }

  async loadOrCreateAccountKey(acme) {
    try {
      const pem = this.storage.get(this.accountKeyPath())?.toString("utf8");
      if (pem) return pem;
    } catch { /* utworzymy nowy */ }
    const key = await acme.crypto.createPrivateKey(); // acme-client v5: async
    this.storage.put(this.accountKeyPath(), key.toString());
    return key;
  }

  /** Samoodnawianie: raz dziennie sprawdza i odnawia, gdy zostało < 30 dni. */
  startAutoRenew() {
    const tick = async () => {
      if (!this.domain || !this.current) return;
      const left = this.daysLeft(this.current.cert);
      if (left <= RENEW_BEFORE_DAYS) {
        this.log.log(`[acme] Zostało ${Math.floor(left)} dni — odnawiam.`);
        await this.issue(this.domain, this.email);
      }
    };
    this.renewTimer = setInterval(tick, DAY_MS);
    this.renewTimer.unref?.();
  }
}
