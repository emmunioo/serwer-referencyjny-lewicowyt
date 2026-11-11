// Buduje dwa samorozpakowujące się instalatory serwera:
//   dist/lewicowyt-serwer-<wersja>-instalator.exe   — Windows x64 (Go, go:embed; wymaga zainstalowanego Go TYLKO do zbudowania)
//   dist/lewicowyt-serwer-<wersja>.run              — Linux/macOS (skrypt sh + archiwum tar.gz)
//   node zrob-instalatory.mjs
// Zawartość obu = te same pliki co w paczce wydania (bez data/, tools/, engine*/, node_modules/, testów i archiwów).
// Instalatory same pobierają Node.js, Tora, FFmpeg, cjxl i acme-client (install.ps1 / install.sh) z weryfikacją SHA-256.
import fs from "node:fs";
import os from "node:os";
import crypto from "node:crypto";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { buildZip } from "./update.js";

const here = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(fs.readFileSync(join(here, "package.json"), "utf8"));
const version = pkg.version;
const dist = join(here, "dist");
fs.mkdirSync(dist, { recursive: true });

// --- lista plików paczki (jak w zrob-wydanie.mjs) ---
const skipFiles = new Set([".enginepath", "test-e2e.mjs", "package-lock.json", "zrob-wydanie.mjs", "zrob-instalatory.mjs", "zrob-ffmpeg.mjs", "instalator-run.sh.tpl"]);
const files = [];
for (const name of fs.readdirSync(here)) {
  const p = join(here, name);
  if (!fs.statSync(p).isFile() || skipFiles.has(name) || name.startsWith(".") || /^test-.*\.mjs$/.test(name) ||
    /\.(zip|nowy|log|tmp|swp|bak|exe|run)$/i.test(name) || name.endsWith("~")) continue;
  files.push({ name, data: fs.readFileSync(p), mode: /\.sh$/.test(name) ? 0o755 : 0o644 });
}
for (const need of ["install.ps1", "install.sh", "install.bat", "start.bat", "start.sh", "server.js", "package.json"]) {
  if (!files.some((f) => f.name === need)) throw new Error(`Brak pliku w paczce: ${need}`);
}
console.log(`Pliki w paczce: ${files.length}`);

// --- FFmpeg wbudowany w serwer: binarki danej platformy trafiają do tools/ w instalatorze ---
// Szukamy w ffmpeg/dist/<platforma>-*/ (wynik build.sh / CI), a w drugiej kolejności w tools/ (po node zrob-ffmpeg.mjs).
const noFfmpeg = process.argv.includes("--bez-ffmpeg");
function ffmpegFiles(plat) {
  const exe = plat === "windows" ? ".exe" : "";
  const distRoot = join(here, "ffmpeg", "dist");
  const dirs = [];
  if (fs.existsSync(distRoot)) for (const d of fs.readdirSync(distRoot)) if (d.startsWith(plat + "-")) dirs.push(join(distRoot, d));
  if (plat === (process.platform === "win32" ? "windows" : "linux")) dirs.push(join(here, "tools"));
  const out = [];
  for (const name of ["ffmpeg", "ffprobe"]) {
    const hit = dirs.map((d) => join(d, name + exe)).find((f) => fs.existsSync(f));
    if (!hit) return null;
    out.push({ name: `tools/${name}${exe}`, data: fs.readFileSync(hit), mode: 0o755 });
  }
  return out;
}
function platformFiles(plat) {
  if (noFfmpeg) return files;
  const ff = ffmpegFiles(plat);
  if (!ff) return null;
  console.log(`FFmpeg (${plat}): ${ff.map((f) => (f.data.length / 1048576).toFixed(1) + " MB").join(" + ")}`);
  return [...files, ...ff];
}

// --- Linux: .run ---
const runFiles = platformFiles("linux");
const stage = fs.mkdtempSync(join(os.tmpdir(), "lewicowyt-run-"));
try {
  if (!runFiles) throw new Error("SKIP");
  for (const f of runFiles) {
    const t = join(stage, f.name);
    fs.mkdirSync(dirname(t), { recursive: true });
    fs.writeFileSync(t, f.data);
    fs.chmodSync(t, f.mode);
  }
  // ścieżki RELATYWNE (cwd = katalog tymczasowy): GNU tar na Windows traktuje "D:\..." jako adres zdalnego hosta
  const tgz = join(os.tmpdir(), `lewicowyt-payload-${process.pid}.tgz`);
  const rel = (p) => basename(p); // oba są bezpośrednimi dziećmi katalogu tymczasowego
  const topts = { cwd: os.tmpdir(), encoding: "utf8" };
  let r = spawnSync("tar", ["--owner=0", "--group=0", "--numeric-owner", "-czf", rel(tgz), "-C", rel(stage), "."], topts);
  if (r.status !== 0) r = spawnSync("tar", ["-czf", rel(tgz), "-C", rel(stage), "."], topts);
  if (r.status !== 0) throw new Error("tar nie powiodl sie: " + (r.stderr || r.error));
  const payloadTgz = fs.readFileSync(tgz);
  fs.rmSync(tgz, { force: true });
  const sha = crypto.createHash("sha256").update(payloadTgz).digest("hex");
  const header = fs.readFileSync(join(here, "instalator-run.sh.tpl"), "utf8").replace(/\r\n/g, "\n")
    .replaceAll("@VERSION@", version).replaceAll("@SHA256@", sha);
  const runPath = join(dist, `lewicowyt-serwer-${version}.run`);
  fs.writeFileSync(runPath, Buffer.concat([Buffer.from(header, "utf8"), payloadTgz]));
  fs.chmodSync(runPath, 0o755);
  console.log(`Zapisano ${runPath} (${(fs.statSync(runPath).size / 1048576).toFixed(2)} MB, SHA-256 archiwum ${sha.slice(0, 16)}…)`);
} catch (e) {
  if (e.message !== "SKIP") throw e;
  console.warn("POMINIĘTO .run: brak binarek FFmpeg dla Linuxa (ffmpeg/dist/linux-*/ albo workflow CI). Użyj --bez-ffmpeg, żeby zbudować bez nich.");
} finally {
  fs.rmSync(stage, { recursive: true, force: true });
}

// --- Windows: .exe (Go) ---
const goDir = join(here, "instalator-exe");
const payloadZip = join(goDir, "payload.zip");
const exeFiles = platformFiles("windows");
if (!exeFiles) console.warn("POMINIĘTO .exe: brak binarek FFmpeg dla Windows (ffmpeg/dist/windows-*/ albo node zrob-ffmpeg.mjs). Użyj --bez-ffmpeg, żeby zbudować bez nich.");
else {
fs.writeFileSync(payloadZip, buildZip(exeFiles));
try {
  const out = join(dist, `lewicowyt-serwer-${version}-instalator.exe`);
  const env = { ...process.env, GOOS: "windows", GOARCH: "amd64", CGO_ENABLED: "0" };
  const r = spawnSync("go", ["build", "-trimpath", "-ldflags", `-s -w -X main.version=${version}`, "-o", out, "."], { cwd: goDir, env, encoding: "utf8" });
  if (r.status !== 0) throw new Error("go build nie powiodl sie:\n" + (r.stdout || "") + (r.stderr || r.error || ""));
  const exeSha = crypto.createHash("sha256").update(fs.readFileSync(out)).digest("hex");
  console.log(`Zapisano ${out} (${(fs.statSync(out).size / 1048576).toFixed(2)} MB, SHA-256 ${exeSha})`);
} finally {
  fs.rmSync(payloadZip, { force: true });
}
}
console.log("Gotowe. Pliki w katalogu dist/. Exe nie jest podpisany (SmartScreen może ostrzegać).");
