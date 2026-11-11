// Eksport dziennika zdarzeń jako SZYFROWANY, samodzielny plik HTML.
//
// Plik otwiera się w zwykłej przeglądarce (bez serwera, bez internetu): prosi o hasło, odszyfrowuje wpisy lokalnie
// (WebCrypto: PBKDF2-SHA-256, 600 000 iteracji → AES-256-GCM, dane skompresowane gzipem) i pokazuje przeglądarkę
// dziennika z filtrami. Hasło = hasło administratora z chwili tworzenia pliku (panel żąda go przy eksporcie
// i sprawdza). Nic w pliku nie jest jawne poza nagłówkiem i parametrami szyfrowania.

import zlib from "node:zlib";
import { randomBytes, pbkdf2Sync, createCipheriv } from "node:crypto";

const ITERATIONS = 600_000;

export function buildEncryptedHtml({ entries, meta, password }) {
  const payload = Buffer.from(JSON.stringify({ meta, entries }), "utf8");
  const gz = zlib.gzipSync(payload, { level: 9 });
  const salt = randomBytes(16), iv = randomBytes(12);
  const key = pbkdf2Sync(String(password).normalize("NFC"), salt, ITERATIONS, 32, "sha256");
  const c = createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
  const ct = Buffer.concat([c.update(gz), c.final(), c.getAuthTag()]); // WebCrypto oczekuje znacznika na końcu
  const blob = JSON.stringify({ v: 1, kdf: "PBKDF2-SHA256", iter: ITERATIONS, salt: salt.toString("base64"), iv: iv.toString("base64"), ct: ct.toString("base64") });
  return PAGE.replace("__CREATED__", new Date(meta.created).toLocaleString("pl-PL")).replace("__BLOB__", () => blob);
}

const VIEWER_JS = String.raw`
const $ = (id) => document.getElementById(id);
const LV = {10:['debug','#7a8696'],20:['info','#2f7fd1'],30:['warn','#c98a00'],40:['error','#d1342f'],50:['security','#8a3fd1']};
let DATA = null, ROWS = [], shown = 0;
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function unlock(pw) {
  const b = JSON.parse($('blob').textContent);
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64(b.salt), iterations: b.iter, hash: 'SHA-256' }, km, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(b.iv) }, key, b64(b.ct));
  const text = await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  return JSON.parse(text);
}

$('go').onclick = async () => {
  $('err').textContent = '';
  $('go').disabled = true; $('go').textContent = 'Odszyfrowuję…';
  try {
    DATA = await unlock($('pw').value);
  } catch (e) {
    $('err').textContent = 'Nie udało się odszyfrować: złe hasło albo uszkodzony plik.';
    $('go').disabled = false; $('go').textContent = 'Odblokuj'; return;
  }
  $('pw').value = '';
  $('lock').style.display = 'none'; $('app').style.display = '';
  start();
};
$('pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('go').click(); });

function start() {
  const m = DATA.meta;
  $('title').textContent = 'Dziennik zdarzeń — ' + (m.server || 'serwer lewicowYT');
  const i = m.integrity || {};
  $('meta').textContent = 'Utworzono: ' + new Date(m.created).toLocaleString('pl-PL') + ' · wpisów w pliku: ' + DATA.entries.length +
    ' · zakres: ' + (m.range || '—') + ' · wersja serwera: ' + (m.version || '?') +
    ' · integralność łańcucha w chwili eksportu: ' + (i.ok ? 'OK (' + i.blocks + ' bloków)' : 'NARUSZONA!') + (i.prunedPrefix ? ' (najstarsze bloki przycięte wg limitu)' : '') + (m.truncated ? ' · UWAGA: eksport obcięty do najnowszych 1 000 000 wpisów (najstarsze pominięto)' : '');
  $('meta').className = i.ok ? 'meta' : 'meta bad';
  const cats = [...new Set(DATA.entries.map((e) => e.cat))].sort();
  for (const c of cats) { const o = document.createElement('option'); o.value = c; o.textContent = c; $('cat').append(o); }
  const counts = {};
  for (const e of DATA.entries) counts[e.level] = (counts[e.level] || 0) + 1;
  $('counts').textContent = Object.keys(LV).map((k) => LV[k][0] + ': ' + (counts[k] || 0)).join(' · ');
  for (const id of ['lvl', 'cat', 'q', 'from', 'to', 'order']) $(id).addEventListener('input', render);
  $('more').onclick = () => draw(500);
  $('lockBtn').onclick = () => location.reload();
  render();
}

function render() {
  const min = Number($('lvl').value), cat = $('cat').value, q = $('q').value.toLowerCase();
  const from = $('from').value ? Date.parse($('from').value) : 0, to = $('to').value ? Date.parse($('to').value) : Infinity;
  ROWS = DATA.entries.filter((e) => e.level >= min && (!cat || e.cat === cat) && e.ts >= from && e.ts <= to &&
    (!q || (e.msg + ' ' + e.ev + ' ' + e.cat + ' ' + (e.f ? JSON.stringify(e.f) : '')).toLowerCase().includes(q)));
  if ($('order').value === 'new') ROWS.reverse();
  $('tbody').textContent = ''; shown = 0;
  $('found').textContent = 'Pasuje: ' + ROWS.length;
  draw(500);
}

function draw(n) {
  const end = Math.min(ROWS.length, shown + n);
  for (; shown < end; shown++) {
    const e = ROWS[shown];
    const tr = document.createElement('tr');
    const td = (t, cls) => { const x = document.createElement('td'); x.textContent = t; if (cls) x.className = cls; tr.append(x); return x; };
    td('#' + e.seq, 'num'); td(new Date(e.ts).toISOString().replace('T', ' ').slice(0, 23), 'num');
    const lv = td(LV[e.level] ? LV[e.level][0] : e.level, 'lv'); lv.style.color = LV[e.level] ? LV[e.level][1] : '';
    td(e.cat); td(e.ev); td(e.msg);
    tr.onclick = () => {
      const nx = tr.nextSibling;
      if (nx && nx.className === 'det') { nx.remove(); return; }
      const d = document.createElement('tr'); d.className = 'det';
      const c = document.createElement('td'); c.colSpan = 6;
      const pre = document.createElement('pre'); pre.textContent = JSON.stringify(e, null, 2);
      c.append(pre); d.append(c); tr.after(d);
    };
    $('tbody').append(tr);
  }
  $('more').style.display = shown < ROWS.length ? '' : 'none';
}
`;

const PAGE = `<!doctype html>
<html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<title>Dziennik zdarzeń (zaszyfrowany)</title>
<style>
:root{--bg:#f6f7f9;--fg:#1c2128;--card:#fff;--line:#d7dce2;--mut:#5b6672}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e6e9ed;--card:#1d2127;--line:#303640;--mut:#9aa5b1}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,Segoe UI,Roboto,sans-serif}
main{max-width:1200px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:14px}
h1{font-size:20px;margin:0 0 6px}.meta{color:var(--mut)}.bad{color:#d1342f;font-weight:600}
input,select,button{font:inherit;padding:7px 10px;border:1px solid var(--line);border-radius:7px;background:var(--card);color:var(--fg)}
button{cursor:pointer;background:#2f7fd1;color:#fff;border-color:#2f7fd1}
.row{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}
td.num{white-space:nowrap;font-variant-numeric:tabular-nums;color:var(--mut)}td.lv{font-weight:600}
tr.det td{background:var(--bg)}pre{margin:0;white-space:pre-wrap;word-break:break-word;font-size:12px}
tbody tr{cursor:pointer}#err{color:#d1342f;margin-top:8px}
</style></head>
<body><main>
<div id="lock" class="card">
<h1>🔒 Dziennik zdarzeń serwera lewicowYT — plik zaszyfrowany</h1>
<p class="meta">Utworzono: __CREATED__. Zawartość jest zaszyfrowana (AES-256-GCM). Podaj hasło administratora serwera z chwili tworzenia tego pliku. Odszyfrowanie odbywa się wyłącznie w tej przeglądarce.</p>
<div class="row"><input id="pw" type="password" placeholder="Hasło" autocomplete="off" autofocus><button id="go">Odblokuj</button></div>
<div id="err"></div>
</div>
<div id="app" style="display:none">
<div class="card"><h1 id="title"></h1><div id="meta" class="meta"></div><div id="counts" class="meta"></div>
<div class="row">
<select id="lvl"><option value="10">od: debug</option><option value="20">od: info</option><option value="30">od: warn</option><option value="40">od: error</option><option value="50">tylko: security</option></select>
<select id="cat"><option value="">wszystkie kategorie</option></select>
<input id="q" placeholder="Szukaj w treści…" size="28">
<input id="from" type="datetime-local" title="od"><input id="to" type="datetime-local" title="do">
<select id="order"><option value="new">najnowsze pierwsze</option><option value="old">najstarsze pierwsze</option></select>
<button id="lockBtn" style="background:#6b7580;border-color:#6b7580">Zablokuj</button></div>
<div id="found" class="meta"></div></div>
<div class="card" style="overflow:auto"><table><thead><tr><th>Nr</th><th>Czas (UTC)</th><th>Poziom</th><th>Kategoria</th><th>Zdarzenie</th><th>Komunikat</th></tr></thead><tbody id="tbody"></tbody></table>
<div class="row"><button id="more">Pokaż więcej</button></div></div>
</div>
</main>
<script id="blob" type="application/json">__BLOB__</script>
<script>${VIEWER_JS}</script>
</body></html>`;
