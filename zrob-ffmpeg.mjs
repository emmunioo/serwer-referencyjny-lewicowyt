// Buduje FFmpeg wbudowany w serwer (z katalogu ffmpeg/) i kładzie ffmpeg + ffprobe w tools/, gdzie szuka ich convert.js.
//   node zrob-ffmpeg.mjs            # buduje dla bieżącego systemu (Windows: MSYS2/UCRT64; Linux/macOS: bash build.sh)
//   node zrob-ffmpeg.mjs --copy     # tylko skopiuj już zbudowane pliki z ffmpeg/dist/<system>-*/ do tools/
// Wymagania do budowania: patrz ffmpeg/README.md (Windows: MSYS2; Linux: build-essential cmake ninja-build nasm pkg-config git libva-dev libdrm-dev).
import fs from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const ff = join(here, "ffmpeg");
const win = process.platform === "win32";
const plat = win ? "windows" : process.platform === "darwin" ? "macos" : "linux";
const exe = win ? ".exe" : "";

if (!process.argv.includes("--copy")) {
  const r = win
    ? spawnSync("powershell", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", join(ff, "build.ps1")], { stdio: "inherit" })
    : spawnSync("bash", [join(ff, "build.sh")], { stdio: "inherit", cwd: ff });
  if (r.status !== 0) { console.error("Budowanie FFmpeg nie powiodło się."); process.exit(r.status || 1); }
}

const distRoot = join(ff, "dist");
const dir = fs.existsSync(distRoot) ? fs.readdirSync(distRoot).find((d) => d.startsWith(plat + "-")) : null;
if (!dir) { console.error(`Brak ffmpeg/dist/${plat}-*/ — najpierw zbuduj FFmpeg.`); process.exit(1); }
const tools = join(here, "tools");
fs.mkdirSync(tools, { recursive: true });
for (const name of ["ffmpeg", "ffprobe"]) {
  const src = join(distRoot, dir, name + exe);
  if (!fs.existsSync(src)) { console.error("Brak pliku: " + src); process.exit(1); }
  fs.copyFileSync(src, join(tools, name + exe));
  if (!win) fs.chmodSync(join(tools, name + exe), 0o755);
  console.log(`tools/${name}${exe}  (${(fs.statSync(src).size / 1048576).toFixed(1)} MB)`);
}
console.log("Gotowe: FFmpeg jest teraz częścią serwera (tools/). Następny krok: node zrob-instalatory.mjs");
