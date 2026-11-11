// Zaawansowane opcje sieciowe: adresy LAN, adres WAN (publiczny), oraz usługa ukryta Tor (.onion).
// Wszystko best-effort i bez twardych zależności: Tor uruchamiamy, jeśli w systemie jest binarka
// `tor`; gdy jej nie ma, i tak pokazujemy gotowy wpis do torrc i czytamy adres .onion, jeśli
// użytkownik postawił usługę ukrytą sam.

import os from "node:os";
import fs from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";

/** Wszystkie adresy IPv4 (i IPv6 globalne) z interfejsów – bez loopbacku. */
export function listLanIps() {
  const out = [];
  for (const [iface, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.internal) continue;
      if (a.family === "IPv4") out.push({ iface, address: a.address, family: "IPv4" });
      else if (a.family === "IPv6" && !a.address.startsWith("fe80")) out.push({ iface, address: a.address, family: "IPv6" });
    }
  }
  return out;
}

export function primaryLanIp() {
  return listLanIps().find((a) => a.family === "IPv4")?.address || "localhost";
}

/** Publiczny adres WAN – pytamy kilka usług „co widzisz jako moje IP". Best-effort, z timeoutem. */
export async function fetchWanIp() {
  const services = ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"];
  for (const url of services) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 5000);
      const res = await fetch(url, { signal: ctrl.signal, headers: { "User-Agent": "curl/8" } });
      clearTimeout(t);
      if (!res.ok) continue;
      const ip = (await res.text()).trim();
      if (/^[0-9a-fA-F:.]{3,45}$/.test(ip)) return ip;
    } catch { /* następna usługa */ }
  }
  return null;
}

/**
 * Usługa ukryta Tor: mapuje <onion>:virtualPort → 127.0.0.1:localPort. Jeśli jest binarka `tor`,
 * uruchamiamy własny proces z wygenerowanym torrc; adres .onion czytamy z pliku hostname.
 */
export class TorManager {
  /** storage: { get, put, list } — klucz usługi ukrytej (tor/hs/*) jest trzymany w bazie; na dysk trafia tylko dla procesu tor. */
  constructor({ dir, storage = null, log = console }) {
    this.storage = storage;
    this.dir = dir; // katalog roboczy (torrc + usługa ukryta)
    this.log = log;
    this.hsDir = join(dir, "hs");
    this.torrcPath = join(dir, "torrc");
    this.proc = null;
    this.enabled = false;
    this.virtualPort = 80;
    this.localPort = 80;
    this.binaryFound = null; // null = nieznane, true/false po próbie startu
  }

  torrcText() {
    return [
      `DataDirectory ${join(this.dir, "data")}`,
      `SocksPort 0`,
      `HiddenServiceDir ${this.hsDir}`,
      `HiddenServicePort ${this.virtualPort} 127.0.0.1:${this.localPort}`,
      "",
    ].join("\n");
  }

  onionAddress() {
    try {
      const h = fs.readFileSync(join(this.hsDir, "hostname"), "utf8").trim();
      return h || null;
    } catch {
      return null;
    }
  }

  running() {
    return this.proc != null && this.proc.exitCode == null;
  }

  /** Włącza/wyłącza i (re)startuje usługę ukrytą pod aktualną konfigurację portów. */
  async configure({ enabled, virtualPort, localPort }) {
    this.virtualPort = Number(virtualPort) || 80;
    this.localPort = Number(localPort) || 80;
    if (!enabled) {
      this.stop();
      this.enabled = false;
      return;
    }
    this.enabled = true;
    fs.mkdirSync(this.hsDir, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(this.hsDir, 0o700); } catch { /* windows */ }
    fs.writeFileSync(this.torrcPath, this.torrcText(), "utf8");
    this.restoreHiddenService();
    this.start();
    this.watchHiddenService();
  }

  /** Przed startem Tora: odtwarza klucz usługi ukrytej z bazy (jeśli go nie ma na dysku). */
  restoreHiddenService() {
    if (!this.storage) return;
    try {
      for (const path of this.storage.list("tor/hs/")) {
        const name = path.slice("tor/hs/".length);
        const target = join(this.hsDir, name);
        if (!/^[A-Za-z0-9_.-]+$/.test(name) || fs.existsSync(target)) continue;
        fs.writeFileSync(target, this.storage.get(path), { mode: 0o600 });
      }
    } catch (e) { this.log.warn(`[tor] odtwarzanie klucza z bazy: ${e.message}`); }
  }

  /** Po utworzeniu usługi ukrytej przez Tora kopiuje jej pliki (klucze, hostname) do bazy. */
  persistHiddenService() {
    if (!this.storage) return false;
    let saved = false;
    try {
      for (const name of fs.readdirSync(this.hsDir)) {
        const p = join(this.hsDir, name);
        if (!/^[A-Za-z0-9_.-]+$/.test(name) || !fs.statSync(p).isFile()) continue;
        const bytes = fs.readFileSync(p);
        const prev = this.storage.get("tor/hs/" + name);
        if (!prev || !prev.equals(bytes)) { this.storage.put("tor/hs/" + name, bytes); saved = true; }
      }
    } catch { /* usługa jeszcze nie powstała */ }
    return saved;
  }

  watchHiddenService() {
    if (!this.storage) return;
    clearInterval(this.watchTimer);
    let tries = 0;
    this.watchTimer = setInterval(() => {
      this.persistHiddenService();
      if (++tries >= 60 || (this.onionAddress() && tries >= 3)) clearInterval(this.watchTimer);
    }, 2000);
    this.watchTimer.unref?.();
  }

  start() {
    if (this.running()) { this.stop(); }
    try {
      const bin = process.env.TOR_BINARY || "tor";
      this.proc = spawn(bin, ["-f", this.torrcPath], { stdio: ["ignore", "pipe", "pipe"] });
      this.proc.on("error", (e) => {
        this.binaryFound = false;
        this.proc = null;
        this.log.warn(`[tor] Nie uruchomiono procesu tor (${e.code || e.message}). ` +
          `Zainstaluj Tora albo użyj gotowego wpisu torrc z panelu. Adres .onion odczytam, ` +
          `gdy usługa ukryta powstanie.`);
      });
      this.proc.stdout?.on("data", (d) => {
        if (this.binaryFound === null) this.binaryFound = true;
        if (/Bootstrapped 100%/.test(d.toString())) this.log.log(`[tor] Gotowe. Adres: ${this.onionAddress() || "(czekam na hostname)"}`);
      });
      this.proc.on("exit", (code) => this.log.log(`[tor] proces zakończony (kod ${code}).`));
    } catch (e) {
      this.binaryFound = false;
      this.log.warn(`[tor] spawn nieudany: ${e.message}`);
    }
  }

  stop() {
    if (this.proc) { try { this.proc.kill(); } catch { /* ignore */ } this.proc = null; }
  }

  /** Koniec pracy serwera: klucz usługi ukrytej zapisujemy w bazie i niszczymy jawne pliki w katalogu Tora (odtworzymy je przy następnym starcie). */
  shutdown() {
    this.stop();
    if (!this.storage) return;
    try {
      this.persistHiddenService();
      for (const name of fs.readdirSync(this.hsDir)) {
        const p = join(this.hsDir, name);
        try { if (fs.statSync(p).isFile() && /secret|key/i.test(name)) { fs.writeFileSync(p, Buffer.alloc(Math.max(fs.statSync(p).size, 64), 0)); fs.unlinkSync(p); } } catch { /* zablokowany plik — najlepsza próba */ }
      }
    } catch { /* usługa nie istniała */ }
  }

  status() {
    return {
      enabled: this.enabled,
      running: this.running(),
      binaryFound: this.binaryFound,
      onion: this.onionAddress(),
      virtualPort: this.virtualPort,
      torrc: this.torrcText(),
    };
  }
}
