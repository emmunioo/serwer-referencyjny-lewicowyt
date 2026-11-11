// Pakuje serwer do pliku serwer-lewicowyt-<wersja>.zip — wgraj go jako zasób (asset) wydania GitHub Release
// o tagu równym wersji (np. v1.12.0). GitHub sam doda skrót SHA-256 (`digest`), który serwery sprawdzają.
//   node zrob-wydanie.mjs
// W paczce NIE ma: data/, tools/, engine*/, node_modules/, plików testowych i innych archiwów.
import fs from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildZip } from "./update.js";

const here = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(fs.readFileSync(join(here, "package.json"), "utf8"));
const skipDirs = new Set(["data", "tools", "engine", "engine-tor", "node_modules", ".git"]);
const skipFiles = new Set([".enginepath", "test-e2e.mjs", "package-lock.json", "zrob-wydanie.mjs"]);
const files = [];
for (const name of fs.readdirSync(here)) {
  const p = join(here, name);
  if (!fs.statSync(p).isFile() || skipFiles.has(name) || name.startsWith(".") || /^test-.*\.mjs$/.test(name) || /\.(zip|nowy|log|tmp|swp|bak)$/i.test(name) || name.endsWith("~")) continue;
  files.push({ name, data: fs.readFileSync(p), mode: /\.(sh)$/.test(name) ? 0o755 : 0o644 });
}
const out = join(here, `serwer-lewicowyt-${pkg.version}.zip`);
fs.writeFileSync(out, buildZip(files));
console.log(`Zapisano ${out} (${files.length} plików, wersja ${pkg.version})`);
console.log(`Opublikuj wydanie o tagu v${pkg.version} i dołącz ten plik. Wydanie wstępne (prerelease) zobaczą tylko serwery w wersji wstępnej.`);
