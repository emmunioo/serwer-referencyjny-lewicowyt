// Panel administracyjny w przeglądarce (bez zależności front-endowych). Strona to statyczny szkielet;
// całą treść pobiera z /admin/api/* i renderuje przez DOM (textContent) — nic z danych nie trafia do
// innerHTML, więc nie ma XSS. Jedyna zmienna w szablonie to token CSRF (losowy).

export function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

const STYLE = `
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#f4f4f6;color:#16161a}
@media(prefers-color-scheme:dark){body{background:#17171b;color:#eee}}
header{background:#8b1e1e;color:#fff;padding:14px 20px;display:flex;justify-content:space-between;align-items:center}
main{max-width:920px;margin:0 auto;padding:20px}
.card{background:#fff;border-radius:10px;padding:16px;margin:0 0 16px;box-shadow:0 1px 3px rgba(0,0,0,.12)}
@media(prefers-color-scheme:dark){.card{background:#222228}}
h2{margin:.2em 0 .6em;font-size:1.1rem}
label{display:block;font-size:.85rem;margin:.5em 0 .2em;opacity:.85}
input,textarea,select{width:100%;padding:8px;border:1px solid #bbb;border-radius:7px;background:transparent;color:inherit;font:inherit}
textarea{min-height:90px;resize:vertical}
button{cursor:pointer;border:0;border-radius:7px;padding:8px 14px;font:inherit;background:#8b1e1e;color:#fff}
button.sec{background:#4444;color:inherit}
button.danger{background:#b3261e}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.item{border:1px solid #8883;border-radius:8px;padding:10px;margin:8px 0}
.muted{opacity:.7;font-size:.85rem}
.pill{font-size:.72rem;background:#8882;border-radius:999px;padding:2px 8px}
.big{font-size:1.05rem}
#toast{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:#222;color:#fff;padding:10px 16px;border-radius:8px;opacity:0;transition:.2s;pointer-events:none}
#toast.show{opacity:1}
`;

export function loginPage(error) {
  return `<!doctype html><html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Panel — logowanie</title>
<style>${STYLE}</style></head><body>
<header><b>Serwer społeczności</b><span>logowanie</span></header>
<main><div class="card"><h2>Zaloguj się</h2>
${error ? `<p style="color:#c0392b">${escapeHtml(error)}</p>` : ""}
<form method="POST" action="/admin/login">
<label>Hasło administratora</label>
<input type="password" name="password" autofocus autocomplete="current-password">
<div style="margin-top:12px"><button type="submit">Zaloguj</button></div>
</form></div>
<p class="muted">Hasło ustawiasz przy pierwszym starcie serwera (jest wypisywane w konsoli).</p>
</main></body></html>`;
}

export function appPage(csrf) {
  return `<!doctype html><html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Panel serwera społeczności</title>
<meta name="csrf" content="${escapeHtml(csrf)}">
<style>${STYLE}</style></head><body>
<header><b>Serwer społeczności</b>
<span class="row"><span id="httpsBadge" class="pill">…</span>
<button class="sec" id="logout">Wyloguj</button></span></header>
<main>

<div class="card"><h2>📝 Treści</h2>
<p class="muted">Dodawaj wpisy ręcznie. Wpis z zaznaczonym „Powiadom o tym wpisie" aplikacja pokaże jako powiadomienie (przez 48 h od publikacji — potem już tylko w zakładce).
Budzik push idzie sam po zapisaniu takiego wpisu (można to wyłączyć w konfiguracji); przycisk „Powiadom subskrybentów" wysyła go ręcznie.
<b>Data publikacji w przyszłości = wpis zaplanowany</b>: pojawi się w aplikacji (i dostanie budzik) dopiero o tej godzinie.
Obrazy w aplikacji: <b>WEBP</b> (najprościej), JXL albo AVIF. JPG/PNG aplikacja pokaże tylko w powiadomieniu — nie w zakładce.
Reklama pokaże się dopiero przy co najmniej 20 zwykłych wpisach (1 reklama na 20).</p>
<p class="muted" id="identityNote"></p>
<div class="row">
<select id="newType" style="max-width:220px">
<option value="post">Post</option>
<option value="meme">Mem (obrazek)</option>
<option value="article">Artykuł / newsletter</option>
<option value="foreign">Inna platforma (np. Twitter)</option>
<option value="ad">Reklama</option>
<option value="contest">Konkurs</option>
<option value="creator">Twórca YouTube (polecany kanał)</option>
</select>
<button id="addItem">+ Dodaj</button>
<button class="sec" id="notifyNow">🔔 Powiadom subskrybentów (<span id="subCount">0</span>)</button>
</div>
<div id="items" style="margin-top:10px"></div>
</div>

<div class="card"><h2>⚙️ Konfiguracja serwera</h2>
<label>Nazwa serwera</label><input id="cfgName">
<label>Opis</label><input id="cfgDesc">
<label>Regulamin (wymagany — użytkownik akceptuje go w aplikacji; do 400 000 znaków)</label><textarea id="cfgTerms"></textarea>
<label>Wersja regulaminu (zmień, gdy zmieniasz treść — aplikacja poprosi o ponowną akceptację)</label><input id="cfgTermsVer" style="max-width:120px">
<label class="row" style="margin-top:10px"><input type="checkbox" id="cfgAutoNotify" style="width:auto"> wysyłaj budzik push sam po dodaniu/edycji istotnego wpisu (i o czasie publikacji zaplanowanego)</label>
<p class="muted">Ten serwer nie może być „serwerem głównym" w aplikacji: treść wpisujesz ręcznie, a serwer główny musi sam dostarczać filmy YouTube. Dzięki temu nikt nie zgubi powiadomień o filmach.</p>
<div style="margin-top:12px"><button id="saveCfg">Zapisz konfigurację</button></div>
</div>

<div class="card"><h2>🔗 Platformy linków</h2>
<p class="muted">Aplikacja pozwala wybrać dla każdej platformy, czym otwierać jej linki (jak dla YouTube). Platformy z wpisów „Inna platforma" dodają się same; tu dopiszesz inne — np. dla linków w artykułach. Jedna linia na platformę: <code>id | Nazwa | host1, host2</code>, np. <code>twitch | Twitch | twitch.tv</code>.</p>
<textarea id="cfgLinkPlatforms" style="min-height:80px;font-family:monospace" placeholder="twitch | Twitch | twitch.tv"></textarea>
<div style="margin-top:12px"><button id="saveLinkPlatforms">Zapisz platformy</button></div>
</div>

<div class="card"><h2>🔔 Powiadomienia push</h2>
<p class="muted" id="pushStatus"></p>
<p class="muted">Aplikacja odbiera budziki przez wbudowany dystrybutor (obsługuje go ten serwer — nic nie konfigurujesz) albo przez zewnętrzny (np. ntfy). Bez Google. Każdy budzik jest szyfrowany osobno dla urządzenia.</p>
<div id="subStats" class="muted"></div>
<label>Puste budziki (szum) na urządzenie na dobę — 0 = wyłączone. Utrudniają zgadnięcie z samych godzin budzików, co ktoś czyta; kosztują trochę baterii użytkowników (rozsądnie: 2–8). Każde urządzenie ma twardy dzienny limit (półtora raza tyle), a przy prawdziwym budziku część urządzeń dostaje obok niego pusty.</label>
<input id="cfgDecoy" inputmode="numeric" placeholder="0" style="max-width:120px">
<label>Rozmywanie prawdziwych budzików (sekundy, 0–600): każde urządzenie dostaje budzik w swoim losowym momencie w tym oknie, więc nie da się wskazać, który był „ten prawdziwy". 0 = od razu.</label>
<input id="cfgJitter" inputmode="numeric" placeholder="0" style="max-width:120px">
<p class="muted">Miniatura w budziku: gdy wpis ma mały obraz JPG/PNG/WEBP (do 6 KB — pole „Miniatura powiadomienia" w edytorze), trafia zaszyfrowana prosto do budzika i aplikacja pokaże ją bez pobierania z sieci (serwer nie widzi wtedy, kto dostał powiadomienie).</p>
<div style="margin-top:12px"><button id="saveDecoy">Zapisz</button></div>
</div>

<div class="card"><h2>🧅 Sieć i dostępność</h2>
<p id="netStatus" class="muted"></p>
<h3 style="font-size:.95rem;margin:14px 0 4px">Tor (usługa ukryta .onion) — zalecane: omija CGNAT, ukrywa IP serwera</h3>
<label class="row"><input type="checkbox" id="torOn" style="width:auto"> uruchom jako usługę ukrytą Tor</label>
<label>Port wirtualny .onion (aplikacja oczekuje 2137)</label><input id="torPort" inputmode="numeric" placeholder="2137" style="max-width:120px">
<div style="margin-top:10px"><button id="saveTor">Zapisz Tor</button></div>
<p id="torInfo" class="muted"></p>
<label>Wpis do własnego torrc (jeśli nie masz binarki „tor" / wolisz własny proces):</label>
<textarea id="torrc" readonly style="min-height:90px;font-family:monospace"></textarea>
<h3 style="font-size:.95rem;margin:14px 0 4px">Porty</h3>
<div class="row">
<div style="flex:1"><label>Port HTTP</label><input id="netHttp" inputmode="numeric" placeholder="2137"></div>
<div style="flex:1"><label>Port HTTPS</label><input id="netHttps" inputmode="numeric" placeholder="443"></div>
</div>
<label class="row"><input type="checkbox" id="netLocal" style="width:auto"> nasłuchuj tylko lokalnie (127.0.0.1) — dla serwera dostępnego wyłącznie przez Tor; wyłącza dostęp z sieci lokalnej i z internetu</label>
<p class="muted" id="netLocalWarn"></p>
<div style="margin-top:10px"><button id="saveNet">Zapisz porty</button></div>
<h3 style="font-size:.95rem;margin:14px 0 4px">Widoczny pod adresami (wpisz je w aplikacji)</h3>
<div id="netEndpoints" class="muted big"></div>
<div class="row" style="margin-top:6px"><span id="netWan" class="muted"></span>
<button class="sec" id="refreshWan">Sprawdź IP WAN</button></div>
</div>

<div class="card"><h2>🔒 HTTPS / Let's Encrypt (opcjonalnie — tylko jeśli chcesz adres z domeny)</h2>
<label>Domena (np. serwer.twojadomena.pl) — wskazuje na ten host, porty 80 i 2137 otwarte. W aplikacji wpisujesz samą domenę.</label><input id="cfgDomain">
<label>E-mail do Let's Encrypt</label><input id="cfgEmail">
<div class="row" style="margin-top:12px"><button id="saveHttps">Zapisz</button>
<button class="sec" id="issueCert">Wystaw / odnów certyfikat teraz</button></div>
<p class="muted" id="httpsInfo"></p>
</div>

<div class="card"><h2>🔑 Zmień hasło administratora</h2>
<label>Obecne hasło</label><input id="pwCur" type="password" autocomplete="current-password">
<label>Nowe hasło (min. 12 znaków)</label><input id="pwNew" type="password" autocomplete="new-password">
<div style="margin-top:12px" class="row"><button id="savePw">Zmień hasło</button>
<button class="danger" id="logoutAll">Wyloguj wszystkie sesje</button></div>
<p class="muted">Zmiana hasła wylogowuje pozostałe sesje. Zapomniane hasło: zatrzymaj serwer i uruchom <code>start.bat --reset-password</code> (Linux: <code>sh start.sh --reset-password</code>) — w oknie pojawi się nowe hasło.</p>
</div>

<div class="card"><h2>📜 Dziennik zdarzeń (zawsze włączony)</h2>
<p class="muted">Serwer zapisuje szczegółowy dziennik: start i stan systemu, każde żądanie (metoda, trasa, status, czas — <b>bez adresów IP</b>), działania w panelu, logowania, konwersje multimediów, budziki push (same liczby), błędy i co minutę metryki. Dziennik jest w bazie danych, kompresowany ZSTD (poziom 3) i szyfrowany <b>zawsze</b> najlepszym szyfrem akcelerowanym przez CPU (a przy zaszyfrowanej bazie — dodatkowo szyfrem bazy). Nie da się go wyłączyć ani skasować z panelu; bloki tworzą łańcuch skrótów, więc ingerencję widać w „Sprawdź integralność”. Nie zawiera haseł ani adresów subskrybentów.</p>
<div id="logStats" class="muted"></div>
<div class="row" style="margin-top:10px">
<select id="logLvl"><option value="debug">od: debug</option><option value="info" selected>od: info</option><option value="warn">od: warn</option><option value="error">od: error</option><option value="security">tylko: security</option></select>
<input id="logCat" placeholder="kategoria (np. http)" style="max-width:170px"><input id="logQ" placeholder="szukaj…" style="max-width:200px">
<button id="logRefresh" class="sec">Odśwież</button><button id="logVerify" class="sec">Sprawdź integralność</button></div>
<div id="logVerifyOut" class="muted"></div>
<div id="logBox" style="max-height:380px;overflow:auto;font-family:monospace;font-size:12px;border:1px solid #8884;border-radius:6px;padding:6px;margin-top:8px"></div>
<h3 style="margin-top:18px">Eksport do szyfrowanego pliku HTML</h3>
<p class="muted">Plik otwierasz w przeglądarce; hasłem jest <b>hasło administratora z chwili eksportu</b> (podaj je poniżej — serwer je sprawdzi). Zmiana hasła później nie zmienia haseł starych plików.</p>
<div class="row"><select id="logDays"><option value="1">ostatnia doba</option><option value="7" selected>ostatnie 7 dni</option><option value="30">ostatnie 30 dni</option><option value="90">ostatnie 90 dni</option><option value="0">cały dziennik</option></select>
<select id="logExpLvl"><option value="debug">wszystkie poziomy</option><option value="info">od: info</option><option value="warn">od: warn</option><option value="error">od: error</option></select></div>
<label>Hasło administratora</label><input id="logPw" type="password" autocomplete="current-password">
<div class="row" style="margin-top:12px"><button id="logExport">Eksportuj dziennik (HTML, zaszyfrowany)</button></div>
</div>

<div class="card"><h2>🎞️ Kodowanie filmów (akceleracja sprzętowa)</h2>
<p class="muted">Serwer sprawdził, z których akceleratorów (karty graficzne, zintegrowana grafika) może skorzystać przy kodowaniu H.265 i H.264. Przy kilku akceleratorach (np. procesor ze zintegrowaną grafiką + osobna karta) wybierz, który ma pracować. „Automatycznie” bierze pierwszy działający.</p>
<div id="vidOpts"></div>
<p class="muted" id="vidInfo"></p>
</div>

<div class="card"><h2>⬆️ Aktualizacje serwera</h2>
<p class="muted" id="updInfo">Sprawdzam…</p>
<div id="updNotes" class="muted" style="white-space:pre-wrap;max-height:200px;overflow:auto;margin:8px 0"></div>
<div class="row"><button id="updCheck" class="sec">Sprawdź teraz</button><button id="updInstall" style="display:none">Pobierz i zainstaluj</button><button id="updRollback" class="danger" style="display:none">Cofnij ostatnią aktualizację</button></div>
<label>Hasło administratora (potrzebne do instalacji i cofnięcia)</label><input id="updPw" type="password" autocomplete="current-password">
<label style="margin-top:10px"><input type="checkbox" id="updAuto" style="width:auto"> Sprawdzaj nowe wersje co ok. 12 godzin (zapytanie do GitHuba z adresu IP tego komputera; nic nie jest instalowane bez Twojego kliknięcia)</label>
<p class="muted">Źródło: GitHub Releases. Instalacja pobiera paczkę .zip tylko z github.com, sprawdza skrót SHA-256 i wersję, robi kopię zastępowanych plików i nie rusza katalogów <code>data/</code> ani <code>tools/</code>. Po instalacji serwer sam uruchomi się ponownie (gdy działa pod <code>start.bat</code> / <code>start.sh</code>).</p>
</div>

<div class="card"><h2>🔐 Szyfrowanie bazy danych</h2>
<p class="muted">Cała baza (wpisy, konfiguracja, subskrybenci, pliki, certyfikaty, klucz .onion) jest szyfrowana i uwierzytelniana. Serwer sprawdza procesor i domyślnie wybiera <b>najlepszy szyfr przyspieszany sprzętowo</b> (AES-NI / ARM AES, PCLMULQDQ, SHA). Możesz wybrać inny — sprzętowy albo programowy.</p>
<div id="cryCpu" class="muted"></div>
<table id="cryTable" style="width:100%;margin-top:10px"><thead><tr><th></th><th style="text-align:left">Szyfr</th><th style="text-align:left">Przyspieszenie CPU</th><th>MB/s</th><th>Wartości</th></tr></thead><tbody></tbody></table>
<div class="row" style="margin-top:12px"><button id="cryRefresh" class="sec">Zmierz ponownie</button>
<span class="muted" id="cryActive"></span></div>
<h3 style="margin-top:18px">Klucz</h3>
<p class="muted" id="cryKey"></p>
<label>Hasło administratora (potrzebne do zmiany klucza lub wyłączenia szyfrowania)</label><input id="cryAdminPw" type="password" autocomplete="current-password">
<label>Hasło do bazy (min. 12 znaków) — zamiast pliku klucza; po restarcie serwer zapyta o nie w konsoli albo użyje DB_PASSPHRASE</label><input id="cryPass" type="password" autocomplete="new-password">
<div class="row" style="margin-top:12px"><button id="cryUsePass">Chroń kluczem z hasła</button><button class="sec" id="cryUseFile">Wróć do pliku klucza</button></div>
<p class="muted"><b>Zrób kopię pliku klucza</b> (<code>klucz-bazy.key</code>) w bezpiecznym miejscu. Bez klucza (albo hasła) zaszyfrowanej bazy nie da się odzyskać. Plik klucza obok bazy chroni przed skopiowaniem samego pliku bazy; hasło chroni także przed przejęciem całego dysku.</p>
</div>

<div class="card"><h2>💾 Kopia zapasowa</h2>
<p class="muted">Jeden plik z całym serwerem: konfiguracja, regulamin, wszystkie wpisy z obrazami, lista usunięć, subskrybenci push i <b>klucz adresu .onion</b> (po przeniesieniu na inny komputer adres się nie zmieni). Bez hasła administratora. <b>Trzymaj kopię w bezpiecznym miejscu — to jawny (niezaszyfrowany) plik JSON</b> — kto ma klucz .onion, może podszyć się pod Twój serwer.</p>
<label>Hasło administratora (potrzebne do pobrania kopii)</label><input id="bkPw" type="password" autocomplete="current-password">
<div class="row"><button id="exportBackup">Pobierz kopię</button>
<label class="sec" style="margin:0"><input type="file" id="importBackup" accept=".json,application/json" style="display:none"><span class="pill" style="cursor:pointer;padding:8px 14px">Wczytaj kopię…</span></label></div>
<p class="muted">Wczytanie kopii ZASTĘPUJE wpisy i konfigurację (porty i ustawienia Tora tego komputera zostają). Klucz .onion zadziała po ponownym uruchomieniu serwera.</p>
</div>

</main>
<div id="toast"></div>
<script>${APP_JS}</script>
</body></html>`;
}

const APP_JS = String.raw`
const CSRF = document.querySelector('meta[name=csrf]').content;
const $ = (id) => document.getElementById(id);
function toast(m){const t=$('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2400);}
async function api(path, body){
  const opt = { method: body===undefined?'GET':'POST', headers: {'X-CSRF-Token': CSRF} };
  if(body!==undefined){ opt.headers['Content-Type']='application/json'; opt.body=JSON.stringify(body); }
  const r = await fetch('/admin/api/'+path, opt);
  if(r.status===401){ location.href='/admin'; throw new Error('wylogowano'); }
  const j = await r.json().catch(()=>({}));
  if(!r.ok){ toast(j.error||('Blad '+r.status)); throw new Error(j.error||r.status); }
  return j;
}
function el(tag, props={}, ...kids){ const e=document.createElement(tag); Object.assign(e,props);
  for(const k of kids){ if(k!=null) e.append(k.nodeType?k:document.createTextNode(k)); } return e; }
function fmt(ms){ try{return new Date(ms).toLocaleString('pl-PL');}catch{return '';} }
function toLocalInput(ms){ const d=new Date(ms||Date.now()); const p=(n)=>String(n).padStart(2,'0');
  return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+'T'+p(d.getHours())+':'+p(d.getMinutes()); }
function fromLocalInput(v){ const t=Date.parse(v); return Number.isFinite(t)?t:Date.now(); }

const TYPE_LABEL = {post:'post', meme:'mem', article:'artykul/newsletter', foreign:'inna platforma', ad:'reklama', contest:'konkurs', creator:'tworca'};
const FEED_EXT = ['jxl','avif','webp'];
const extOf = (f) => String(f).split('.').pop().toLowerCase();
// specyfikacja pol edytora per typ
const FIELDS = {
  post:    [['author','Autor',{req:1}],['text','Tresc',{ta:1,req:1}],['postType','Rodzaj (opc., np. post / zdjecie / ankieta)',{}],['url','Link https do oryginalu (opc.)',{}]],
  meme:    [['title','Podpis (opcjonalny)',{}],['source','Zrodlo (opcjonalne)',{}],['url','Link https (opcjonalny)',{}]],
  article: [['articleKind','Rodzaj',{sel:[['article','Artykul'],['newsletter','Newsletter']]}],['source','Zrodlo',{req:1}],['author','Autor (opc.)',{}],['title','Tytul',{req:1}],['text','Tresc / zajawka (opc.)',{ta:1}],['url','Link https (wymagany dla artykulu)',{}]],
  foreign: [['platform','Platforma (np. twitter)',{req:1}],['author','Autor (opc.)',{}],['foreignType','Typ (opc., np. tweet)',{}],['title','Tytul (opc.)',{}],['text','Tresc (opc.)',{ta:1}],['url','Link https (opc.)',{}]],
  ad:      [['title','Tytul',{req:1}],['text','Opis (opc.)',{ta:1}],['url','Link https (wymagany)',{req:1}]],
  contest: [['title','Tytul',{req:1}],['text','Opis (opc.)',{ta:1}],['url','Link https (wymagany)',{req:1}],['thirdParty','Konkurs strony trzeciej (nie mój)',{cb:1}]],
  creator: [['name','Nazwa tworcy',{req:1}],['channelUrl','Link https do kanalu (opc.)',{}]],
};
const IMAGE_NOTE = {meme:'WYMAGANY, do 20 zdjec — karuzela', post:'opcjonalny', article:'opcjonalny', foreign:'opcjonalny', ad:'opcjonalny', contest:'opcjonalny'};

let STATE=null;
async function refresh(){ STATE = await api('state'); render(); }

function itemSummary(it){
  return it.title || it.name || it.text || it.author || it.platform || it.source || '(bez tytulu)';
}

function render(){
  const c=STATE.config;
  $('cfgName').value=c.serverName||''; $('cfgDesc').value=c.description||'';
  $('cfgTerms').value=c.termsText||''; $('cfgTermsVer').value=c.termsVersion||'1';
  if(document.activeElement!==$('cfgDecoy')) $('cfgDecoy').value=(c.push&&c.push.decoyPerDay)||0;
  if(document.activeElement!==$('cfgJitter')) $('cfgJitter').value=(c.push&&c.push.realJitterSec)||0;
  $('cfgAutoNotify').checked = c.autoNotify!==false;
  if(document.activeElement!==$('cfgLinkPlatforms')) $('cfgLinkPlatforms').value=(c.linkPlatforms||[]).map((p)=>p.id+' | '+p.name+' | '+(p.hosts||[]).join(', ')).join('\n');
  $('pushStatus').textContent='Subskrybenci: '+(STATE.pushSubscribers||0)+' · aktywne tematy wbudowanego push: '+((STATE.lep&&STATE.lep.topics)||0);
  const st=STATE.subscriberStats||{};
  $('subStats').textContent='Wbudowany push (LEP): '+(st.lep||0)+' · zewnetrzny dystrybutor: '+(st.external||0)+' · bez szyfrowania E2E: '+(st.withoutKey||0)
    +' · aktywni w 24 h: '+(st.active24h||0)+' · w 7 dni: '+(st.active7d||0)+' · nowi w 24 h: '+(st.new24h||0)
    +'. (Serwer nie zna tozsamosci subskrybentow — to tylko liczby.)';
  $('identityNote').textContent = 'Kazdy wpis to osobny plik dla aplikacji: po edycji aplikacja pobiera go ponownie, a usuniety wpis znika tez u ludzi (nowsze wersje aplikacji; ulubione zostaja, chyba ze wpis ma link https'+(STATE.httpsBase?' albo staly adres '+STATE.httpsBase+'/e/…':'')+').';
  $('cfgDomain').value=c.domain||''; $('cfgEmail').value=c.email||'';
  $('subCount').textContent = STATE.pushSubscribers||0;
  const h=STATE.https;
  $('httpsBadge').textContent = h.enabled ? 'HTTPS ✓' : (STATE.network.tor?.onion ? 'Tor .onion ✓' : 'HTTP');
  $('httpsInfo').textContent = h.enabled
    ? ('Certyfikat aktywny dla '+h.domain+' — zostalo ~'+h.daysLeft+' dni (odnawia sie automatycznie).')
    : 'Brak certyfikatu. Do serwera .onion NIE jest potrzebny. HTTPS ustaw tylko, jesli chcesz adres z domeny.';

  renderNetwork(STATE.network);

  const wrap=$('items'); wrap.textContent='';
  const items=[...STATE.items].sort((a,b)=>(b.publishedAt||0)-(a.publishedAt||0));
  if(!items.length){ wrap.append(el('p',{className:'muted'},'Brak tresci. Wybierz typ i kliknij „Dodaj".')); }
  for(const it of items){ wrap.append(itemRow(it)); }
}

function renderNetwork(n){
  if(!n) return;
  const up=(s)=>{const h=Math.floor(s/3600),m=Math.floor(s%3600/60);return h+'h '+m+'m';};
  $('netStatus').textContent = 'Serwer dziala ✓ · uptime '+up(n.uptimeSec)
    +' · HTTP '+(n.httpListening?('na :'+n.httpPort):'—')
    +(n.httpsListening?(' · HTTPS na :'+n.httpsPort):'');
  if(document.activeElement!==$('netHttp')) $('netHttp').value = STATE.config.network.httpPort||'';
  if(document.activeElement!==$('netHttps')) $('netHttps').value = STATE.config.network.httpsPort||'';
  $('netWan').textContent = n.wanIp ? ('WAN: '+n.wanIp) : 'WAN: (nieznany — kliknij „Sprawdz")';
  const eps=$('netEndpoints'); eps.textContent='';
  for(const p of n.endpoints){ const d=el('div',{}); d.append(el('b',{},p.kind+': '),document.createTextNode(p.url)); eps.append(d); }
  if(!n.endpoints.length) eps.textContent='(brak — wlacz Tor albo ustaw domene/porty)';
  $('torOn').checked=!!STATE.config.network.torEnabled;
  $('netLocal').checked=!!STATE.config.network.bindLocalOnly;
  $('netLocalWarn').textContent=(STATE.config.network.torEnabled&&!STATE.config.network.bindLocalOnly)?'Uwaga: Tor jest włączony, ale port HTTP nasłuchuje na wszystkich interfejsach — ten sam manifest widać pod adresem IP tego komputera (wiąże go to z adresem .onion). Zaznacz nasłuch lokalny, jeśli serwer ma być dostępny tylko przez Tor.':'';
  if(document.activeElement!==$('torPort')) $('torPort').value=STATE.config.network.torVirtualPort||2137;
  const t=n.tor;
  $('torInfo').textContent = !t.enabled ? 'Tor wylaczony.'
    : (t.onion ? ('Adres .onion: '+t.onion+(t.running?' · proces tor dziala':''))
       : (t.binaryFound===false ? 'Brak binarki „tor" — uzyj wpisu torrc ponizej we wlasnym Torze; adres pojawi sie, gdy usluga ukryta powstanie.'
          : 'Tor wlaczony — czekam na adres .onion (moze potrwac kilkadziesiat sekund).'));
  $('torrc').value=t.torrc||'';
}

function itemRow(it){
  const row=el('div',{className:'item'});
  row.append(el('div',{className:'row'},
    el('span',{className:'pill'}, TYPE_LABEL[it.type]||it.type),
    el('b',{}, String(itemSummary(it)).slice(0,80)),
    (it.publishedAt>STATE.now)?el('span',{className:'pill',style:'background:#7a5a00;color:#fff'},'⏰ zaplanowany'):null,
    (it.images&&it.images.length)?el('span',{className:'pill'},'🖼 '+it.images.length):null,
    it.thumb?el('span',{className:'pill'},'🔔 miniatura'):null,
    (it.audio&&it.audio.file)?el('span',{className:'pill'},'🎧 '+(it.audio.durationMs?fmtDur(it.audio.durationMs):'dzwiek')):null,
    it.video?el('span',{className:'pill'},'🎬 '+[it.video.hevc?'H.265':null,it.video.avc?'H.264':null].filter(Boolean).join('+')):null,
    (it.video&&it.video.hevc&&!it.video.avc)?el('span',{className:'pill',style:'background:#7a5a00;color:#fff'},'brak H.264 — slabe telefony nie odtworza'):null,
    imageWarning(it)?el('span',{className:'pill',style:'background:#b3261e;color:#fff'},imageWarning(it)):null,
    el('span',{className:'muted'}, fmt(it.publishedAt))));
  row.append(el('div',{className:'row',style:'margin-top:6px'},
    el('button',{className:'sec',textContent:'Edytuj',onclick:()=>openEditor(it.type,it)}),
    el('button',{className:'danger',textContent:'Usun',onclick:async()=>{
      if(!confirm('Usunac ten wpis?'))return;
      await api('item/delete',{id:it.id}); refresh();
    }})));
  return row;
}

function fmtDur(ms){ const t=Math.round(ms/1000), h=Math.floor(t/3600), m=Math.floor(t%3600/60), s=t%60;
  const p=(n)=>String(n).padStart(2,'0'); return h?(h+':'+p(m)+':'+p(s)):(m+':'+p(s)); }

function imageWarning(it){
  const imgs=it.images||[];
  if(it.type==='creator') return null;
  const feed=imgs.filter((f)=>FEED_EXT.includes(extOf(f)));
  if(it.type==='meme' && !feed.length) return 'mem niewidoczny: wgraj WEBP/JXL/AVIF';
  if(imgs.length && !feed.length) return 'obraz tylko w powiadomieniu (JPG/PNG)';
  return null;
}

function openEditor(type, it){
  const isNew=!it; it=it||{type,publishedAt:Date.now()};
  const ov=el('div',{style:'position:fixed;inset:0;background:#0008;display:flex;align-items:center;justify-content:center;padding:16px;z-index:9'});
  const card=el('div',{className:'card',style:'max-width:640px;width:100%;max-height:90vh;overflow:auto'});
  card.append(el('h2',{}, (isNew?'Nowy: ':'Edytuj: ')+(TYPE_LABEL[type]||type)));
  const inputs={};
  for(const [key,label,opt] of FIELDS[type]){
    card.append(el('label',{},label));
    let input;
    if(opt.cb){ input=el('input',{type:'checkbox',checked:!!it[key],style:'width:auto'}); }
    else if(opt.sel){ input=el('select'); for(const [v,t] of opt.sel) input.append(el('option',{value:v,textContent:t})); input.value=it[key]||opt.sel[0][0]; }
    else if(opt.ta){ input=el('textarea',{value:it[key]||''}); }
    else { input=el('input',{value:it[key]||''}); }
    inputs[key]=input; card.append(input);
  }
  const date=el('input',{type:'datetime-local',value:toLocalInput(it.publishedAt)});
  let img=null;
  if(type!=='creator'){
    card.append(el('label',{},'Data publikacji')); card.append(date);
    const CONV=!!(STATE.conversion&&STATE.conversion.available);
    card.append(el('p',{className:'muted'},CONV?'Konwersja mediow wlaczona (ffmpeg'+(STATE.conversion.jpegxl?', JPEG XL':', bez kodera JPEG XL — obrazy beda w WebP')+'): wgraj plik w DOWOLNYM formacie, serwer sam przygotuje go dla aplikacji i usunie metadane (GPS, EXIF).':'Konwersja mediow wylaczona (brak ffmpeg): wgrywaj pliki juz w formatach przyjmowanych przez aplikacje — obrazy JXL/AVIF/WEBP, film H.265/H.264 MP4 do 30 kl/s, dzwiek Opus. Zainstaluj ffmpeg, a serwer zrobi to za Ciebie.'));
    card.append(el('label',{},'Obraz ('+(IMAGE_NOTE[type]||'opcjonalny')+')'+(CONV?' — dowolny format (np. PNG, JPG, WEBP, GIF, WBMP); serwer zamieni go na JPEG XL, max 6 MB':' — JXL, AVIF albo WEBP (max 6 MB)')));
    img=el('input',{type:'file',multiple:type==='meme',accept:CONV?'image/*,.wbmp,.bmp,.gif,.tif,.tiff,.heic,.heif,.jxl,.avif,.webp,.png,.jpg,.jpeg':'.jxl,.avif,.webp,image/jxl,image/avif,image/webp'}); card.append(img);
    // I-13: przy limicie rozmiaru JXL apka potrzebuje zadeklarowanej jakości, inaczej pomija obraz
    card.append(el('label',{},'Jakosc JPEG XL (1–100) — przy konwersji serwer zakoduje obraz z ta jakoscia (puste = 90; gdy plik przekroczy 6 MB, zejdzie nizej). Ta liczba trafia tez do manifestu, zeby apka z limitem KB nie pominela obrazu. Ustaw PRZED wgraniem obrazu i zapisz wpis.'));
    inputs.jxlQuality=el('input',{inputmode:'numeric',placeholder:'np. 90',value:it.jxlQuality||'',style:'max-width:120px'}); card.append(inputs.jxlQuality);
    const list=el('div',{});
    const drawImages=()=>{ list.textContent='';
      for(const f of (it.images||[])){
        list.append(el('div',{className:'row muted'}, f+(FEED_EXT.includes(extOf(f))?'':' (tylko powiadomienie)'),
          el('button',{className:'sec',textContent:'Usun obraz',onclick:async()=>{
            const r=await api('item/image/delete',{itemId:it.id,file:f}); it.images=r.images; drawImages(); }})));
      } };
    if(!isNew) drawImages();
    card.append(list);
    // punkt 1: mała miniatura do budzika (bez pobierania z sieci przy powiadomieniu)
    card.append(el('label',{},CONV?'Miniatura powiadomienia (opc.) — jesli nie wgrasz, serwer zrobi ja sam z pierwszego obrazu (maly WebP, do 6 KB, trafia zaszyfrowana do budzika)':'Miniatura powiadomienia (opc.) — maly JPG/PNG/WEBP do 6 KB, np. 96×96; trafia zaszyfrowana do budzika'));
    inputs.__thumb=el('input',{type:'file',accept:CONV?'image/*':'.jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp'}); card.append(inputs.__thumb);
    if(it.thumb) card.append(el('div',{className:'row muted'},'Aktualna miniatura: '+it.thumb,
      el('button',{className:'sec',textContent:'Usun miniature',onclick:async()=>{ await api('item/image/delete',{itemId:it.id,file:it.thumb}); it.thumb=null; toast('Usunieto'); }})));
    if(['post','article','foreign','meme'].includes(type)){
      // dzwiek Opus: aplikacja gra go natywnie — w tle, w petli i do 3x (nie w przegladarce)
      card.append(el('label',{},CONV?'Dzwiek (opc.) — dowolny plik dzwiekowy (MP3, M4A, WAV, OGG…) albo film; serwer zrobi z niego Opus (48 kb/s), do 80 MB po konwersji':'Dzwiek (opc.) — plik Opus (.opus / .ogg) albo WebM, do 80 MB; mowa: 24–48 kb/s wystarczy'));
      inputs.__audio=el('input',{type:'file',accept:CONV?'audio/*,video/*,.opus,.ogg,.oga,.webm,.mp3,.m4a,.wav,.flac,.aac':'.opus,.ogg,.oga,.webm,audio/ogg,audio/opus,audio/webm'}); card.append(inputs.__audio);
      card.append(el('label',{},'Tytul dzwieku (opc.)'));
      inputs.audioTitle=el('input',{value:it.audioTitle||''}); card.append(inputs.audioTitle);
      // film: H.265 dla wiekszosci telefonow + H.264 dla tych bez sprzetowego H.265; zawsze najwyzej 30 kl/s
      if(CONV){
        card.append(el('label',{},'Film (opc.) — dowolny format (MP4, MKV, WEBM, MOV…); serwer zrobi z niego H.265 (glowny) i H.264 (zapas), najwyzej 30 kl/s, dzwiek Opus. Konwersja trwa kilka minut'));
        inputs.__video=el('input',{type:'file',accept:'video/*,.mp4,.mkv,.webm,.mov,.avi,.m4v,.ts'}); card.append(inputs.__video);
      } else {
      card.append(el('label',{},'Film H.265 (MP4, najwyzej 30 kl/s, do 200 MB) — glowny, najmniejszy plik'));
      inputs.__videoHevc=el('input',{type:'file',accept:'.mp4,video/mp4'}); card.append(inputs.__videoHevc);
      card.append(el('label',{},'Film H.264 (MP4, najwyzej 30 kl/s) — zapasowy dla slabych telefonow bez sprzetowego H.265'));
      inputs.__videoAvc=el('input',{type:'file',accept:'.mp4,video/mp4'}); card.append(inputs.__videoAvc);
      }
      card.append(el('p',{className:'muted'},'Przekodowanie w ffmpeg: H.265 → ffmpeg -i wejscie.mp4 -r 30 -c:v libx265 -crf 28 -tag:v hvc1 -c:a libopus -b:a 48k wyjscie-h265.mp4 ; H.264 → … -r 30 -c:v libx264 -crf 26 -profile:v main … Pliki powyzej 30 kl/s serwer odrzuci (aplikacja i tak by ich nie odtworzyla).'));
      card.append(el('label',{},'Tytul filmu (opc.)'));
      inputs.videoTitle=el('input',{value:it.videoTitle||''}); card.append(inputs.videoTitle);
      for(const k of ['hevc','avc']){
        const v=it.video&&it.video[k];
        if(v) card.append(el('div',{className:'row muted'},'Film '+(k==='hevc'?'H.265':'H.264')+': '+v.width+'×'+v.height+', '+v.fps+' kl/s'+(it.video.durationMs?', '+fmtDur(it.video.durationMs):''),
          el('button',{className:'sec',textContent:'Usun',onclick:async()=>{ await api('item/image/delete',{itemId:it.id,file:v.file}); delete it.video[k]; toast('Usunieto film'); }})));
      }
      if(it.audio&&it.audio.file) card.append(el('div',{className:'row muted'},'Aktualny dzwiek: '+it.audio.file+(it.audio.durationMs?' ('+fmtDur(it.audio.durationMs)+')':''),
        el('button',{className:'sec',textContent:'Usun dzwiek',onclick:async()=>{ await api('item/image/delete',{itemId:it.id,file:it.audio.file}); it.audio=null; toast('Usunieto dzwiek'); }})));
    }
    if(type==='post'){
      card.append(el('label',{},'Awatar autora (opc.) — WEBP/JXL/AVIF, maly kwadrat'));
      inputs.__avatar=el('input',{type:'file',accept:CONV?'image/*':'.webp,.jxl,.avif,image/webp,image/jxl,image/avif'}); card.append(inputs.__avatar);
      if(it.avatar) card.append(el('div',{className:'row muted'},'Aktualny awatar: '+it.avatar,
        el('button',{className:'sec',textContent:'Usun awatar',onclick:async()=>{ await api('item/image/delete',{itemId:it.id,file:it.avatar}); it.avatar=null; toast('Usunieto'); }})));
    }
  }
  let significant=null, notify=null;
  if(isNew && type!=='creator' && type!=='ad'){
    // I-01: aplikacja powiadamia tylko o wpisach oznaczonych jako istotne — domyslnie tak
    notify=el('input',{type:'checkbox',checked:true,style:'width:auto'});
    card.append(el('label',{className:'row',style:'margin-top:10px'},notify,
      ' Powiadom o tym wpisie (aplikacja pokaze powiadomienie; bez zaznaczenia wpis pojawi sie tylko w zakladce)'));
  }
  if(!isNew && type!=='creator' && type!=='ad'){
    significant=el('input',{type:'checkbox',style:'width:auto'});
    card.append(el('label',{className:'row',style:'margin-top:10px'},significant,
      ' Istotna zmiana — powiadom (dziala, jesli aplikacja jeszcze nie powiadamiala o tym wpisie; o kazdym linku powiadamia tylko raz). Bez zaznaczenia: drobna poprawka, po cichu.'));
  }

  const save=el('button',{textContent:'Zapisz',onclick:async()=>{
    const files=img?[...img.files]:[];
    if(type==='meme' && isNew && !files.length){ toast('Mem wymaga obrazu'); return; }
    if(type==='meme' && files.length && !files.some((x)=>FEED_EXT.includes(extOf(x.name))) && !(it.images||[]).some((x)=>FEED_EXT.includes(extOf(x)))){
      toast('Mem wymaga obrazu WEBP, JXL albo AVIF — JPG/PNG aplikacja nie pokaze w zakladce'); return; }
    const payload={type};
    for(const k in inputs){ if(k.startsWith('__')) continue; payload[k]=inputs[k].type==='checkbox'?inputs[k].checked:inputs[k].value; }
    payload.publishedAt=fromLocalInput(date.value);
    if(significant) payload.significant=significant.checked;
    if(notify) payload.notify=notify.checked;
    // S-03: budzik dopiero po wgraniu obrazow/miniatury/filmu (item/ready nizej) — inaczej szedl przed nimi
    const wantsWake=(isNew && notify && notify.checked) || (significant && significant.checked);
    if(wantsWake) payload.deferNotify=true;
    let saved;
    try{
      if(isNew){ saved=await api('item/create',payload); }
      else { saved=await api('item/update',{id:it.id,...payload}); }
    }catch{ return; }
    const itemId = saved.item?.id || it.id;
    for(let i=0;i<files.length;i++){ await uploadImage(itemId, files[i], type==='meme' && (i>0 || !isNew)); }
    if(inputs.__thumb && inputs.__thumb.files[0]) await uploadImage(itemId, inputs.__thumb.files[0], false, 'thumb');
    if(inputs.__avatar && inputs.__avatar.files[0]) await uploadImage(itemId, inputs.__avatar.files[0], false, 'avatar');
    if(inputs.__audio && inputs.__audio.files[0]){ toast('Wgrywam dzwiek…'); await uploadImage(itemId, inputs.__audio.files[0], false, 'audio'); }
    if(inputs.__video && inputs.__video.files[0]){ toast('Przygotowuje film (H.265 + H.264) — to moze potrwac kilka minut…'); await uploadImage(itemId, inputs.__video.files[0], false, 'video'); }
    if(inputs.__videoHevc && inputs.__videoHevc.files[0]){ toast('Wgrywam film H.265…'); await uploadImage(itemId, inputs.__videoHevc.files[0], false, 'video_hevc'); }
    if(inputs.__videoAvc && inputs.__videoAvc.files[0]){ toast('Wgrywam film H.264…'); await uploadImage(itemId, inputs.__videoAvc.files[0], false, 'video_avc'); }
    if(wantsWake){ try{ await api('item/ready',{id:itemId}); }catch{} }
    ov.remove(); toast(saved.scheduled?'Zapisano — wpis zaplanowany na '+fmt(payload.publishedAt):'Zapisano'); refresh();
  }});
  const cancel=el('button',{className:'sec',textContent:'Anuluj',onclick:()=>ov.remove()});
  card.append(el('div',{className:'row',style:'margin-top:14px'},save,cancel));
  ov.append(card); ov.onclick=(ev)=>{ if(ev.target===ov) ov.remove(); }; document.body.append(ov);
}

const MIME_BY_EXT={jpg:'image/jpeg',jpeg:'image/jpeg',png:'image/png',webp:'image/webp',avif:'image/avif',jxl:'image/jxl',opus:'audio/ogg',ogg:'audio/ogg',oga:'audio/ogg',webm:'audio/webm'};
async function uploadImage(itemId, file, append, kind){
  // przegladarki czesto nie znaja typu JXL/AVIF — bierzemy go z rozszerzenia; serwer i tak sprawdza zawartosc
  const type=(kind==='video'?'application/octet-stream':null)||(kind&&kind.startsWith('video')?'video/mp4':null)||(kind==='audio'?MIME_BY_EXT[extOf(file.name)]:null)||file.type||MIME_BY_EXT[extOf(file.name)]||'application/octet-stream';
  const r=await fetch('/admin/api/item/image?itemId='+encodeURIComponent(itemId)+(append?'&append=1':'')+(kind?'&kind='+kind:''),
    {method:'POST',headers:{'X-CSRF-Token':CSRF,'Content-Type':type},body:file});
  const j=await r.json().catch(()=>({}));
  if(!r.ok){ toast(j.error||'Nie udalo sie wgrac obrazu'); return; }
  if(j.warning) toast(j.warning);
}

$('addItem').onclick=()=>openEditor($('newType').value, null);
$('notifyNow').onclick=async()=>{ const r=await api('item/publish',{}); toast('Wysylam budziki do '+(r.subscribers||0)+' subskrybentow…'); };
$('saveCfg').onclick=async()=>{ await api('config',{serverName:$('cfgName').value,description:$('cfgDesc').value,
  termsText:$('cfgTerms').value,termsVersion:$('cfgTermsVer').value,autoNotify:$('cfgAutoNotify').checked}); toast('Zapisano'); refresh(); };
$('saveDecoy').onclick=async()=>{ await api('config',{decoyPerDay:$('cfgDecoy').value||0,realJitterSec:$('cfgJitter').value||0}); toast('Zapisano'); refresh(); };
$('saveLinkPlatforms').onclick=async()=>{ await api('config',{linkPlatformsText:$('cfgLinkPlatforms').value}); toast('Zapisano platformy'); refresh(); };
$('logoutAll').onclick=async()=>{ if(!confirm('Wylogowac wszystkie sesje (takze te)?'))return; await api('sessions/logout-all',{}); location.href='/admin'; };
$('exportBackup').onclick=async()=>{
  if(!$('bkPw').value){ toast('Podaj hasło administratora'); return; }
  const r=await fetch('/admin/api/export',{method:'POST',headers:{'X-CSRF-Token':CSRF,'Content-Type':'application/json'},body:JSON.stringify({adminPassword:$('bkPw').value})});
  $('bkPw').value='';
  if(!r.ok){ const j=await r.json().catch(()=>({})); toast(j.error||'Nie udalo sie pobrac kopii'); return; }
  const blob=await r.blob(); const a=el('a',{href:URL.createObjectURL(blob),download:'kopia-serwera-'+new Date().toISOString().slice(0,10)+'.json'});
  document.body.append(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(a.href),5000); toast('Kopia pobrana');
};
$('importBackup').onchange=async(ev)=>{
  const file=ev.target.files[0]; ev.target.value=''; if(!file) return;
  if(!confirm('Wczytac kopie '+file.name+'? Obecne wpisy i konfiguracja zostana ZASTAPIONE.')) return;
  const r=await fetch('/admin/api/import',{method:'POST',headers:{'X-CSRF-Token':CSRF,'Content-Type':'application/json'},body:file});
  const j=await r.json().catch(()=>({}));
  if(!r.ok){ toast(j.error||'Nie udalo sie wczytac kopii'); return; }
  toast('Wczytano: wpisow '+j.items+', obrazow '+j.media+(j.torRestored?' · klucz .onion — uruchom serwer ponownie':''));
  refresh();
};
$('saveHttps').onclick=async()=>{ await api('config',{domain:$('cfgDomain').value,email:$('cfgEmail').value}); toast('Zapisano'); refresh(); };
$('issueCert').onclick=async()=>{ toast('Zamawiam certyfikat…'); const r=await api('cert/issue',{}); toast(r.ok?'Certyfikat gotowy':'Nie udalo sie (sprawdz konsole)'); refresh(); };
$('savePw').onclick=async()=>{ await api('password',{current:$('pwCur').value,next:$('pwNew').value}); $('pwCur').value='';$('pwNew').value=''; toast('Haslo zmienione'); };
$('saveNet').onclick=async()=>{ await api('network',{httpPort:$('netHttp').value||null,httpsPort:$('netHttps').value||null,bindLocalOnly:$('netLocal').checked}); toast('Zapisano porty'); setTimeout(refresh,500); };
$('refreshWan').onclick=async()=>{ toast('Sprawdzam…'); const r=await api('network/wan',{}); toast(r.wanIp?('WAN: '+r.wanIp):'Nie udalo sie'); refresh(); };
$('saveTor').onclick=async()=>{ await api('network',{torEnabled:$('torOn').checked,torVirtualPort:$('torPort').value||2137}); toast('Zapisano Tor'); setTimeout(refresh,1000); };
async function loadCrypto(fresh){
  const s=await api('crypto/status',{fresh:!!fresh});
  const f=s.cpu.features;
  $('cryCpu').textContent='Procesor: '+s.cpu.model+' ('+s.cpu.arch+', '+s.cpu.cores+' wątków) · AES '+(f.aes?'tak':'nie')+', PCLMULQDQ/PMULL '+(f.clmul?'tak':'nie')+', SHA '+(f.sha?'tak':'nie')+', SIMD '+(f.simd?'tak':'nie')+' · źródło: '+s.cpu.source+(s.cpu.known?'':' (nie wszystkie cechy da się ustalić — pomaga pomiar szybkości)');
  const tb=document.querySelector('#cryTable tbody'); tb.textContent='';
  for(const c of s.ciphers){
    const radio=el('input',{type:'radio',name:'cryCipher',value:c.name,disabled:!c.supported});
    radio.checked=(c.id===s.active.id)&&s.preference!=='auto';
    radio.onchange=()=>chooseCipher(c.name);
    const tr=el('tr',{}, el('td',{},radio), el('td',{style:'text-align:left'}, el('b',{},c.label), el('div',{className:'muted'},c.note)),
      el('td',{style:'text-align:left'}, c.id===0?'—':(c.accelerated?'✔ ':'✘ ')+c.hwText), el('td',{},c.mbps==null?'—':String(c.mbps)), el('td',{},String(c.rows)));
    tb.append(tr);
  }
  const autoRadio=el('input',{type:'radio',name:'cryCipher',value:'auto'}); autoRadio.checked=s.preference==='auto'; autoRadio.onchange=()=>chooseCipher('auto');
  tb.prepend(el('tr',{}, el('td',{},autoRadio), el('td',{style:'text-align:left'}, el('b',{},'Automatycznie (domyślnie)'), el('div',{className:'muted'},'od najlepszego do najgorszego wybiera pierwszy szyfr, który ten CPU akceleruje: teraz '+s.ciphers.find(x=>x.name===s.autoWouldChoose).label)), el('td',{}), el('td',{}), el('td',{})));
  $('cryActive').textContent='Aktywny szyfr: '+s.active.label+(s.preference==='auto'?' (wybór automatyczny)':' (wybór użytkownika)');
  $('cryKey').textContent=s.keyFromEnv?'Klucz pochodzi ze zmiennej DB_KEY.':(s.keyMode==='passphrase'?'Klucz główny jest zaszyfrowany Twoim hasłem (brak pliku klucza na dysku).':'Klucz leży w pliku: '+s.keyFile);
}
async function chooseCipher(name){
  let body={cipher:name};
  if(name==='none'){ if(!confirm('Wyłączyć szyfrowanie? Dane w bazie będą jawne.')) return loadCrypto(); body.confirmNone=true; body.adminPassword=$('cryAdminPw').value; }
  toast('Przepisuję bazę na nowy szyfr…'); const r=await api('crypto/cipher',body); toast('Gotowe: przepisano wartości: '+r.rewritten); loadCrypto();
}
$('cryRefresh').onclick=()=>{ toast('Mierzę…'); loadCrypto(true); };
$('cryUsePass').onclick=async()=>{ await api('crypto/key',{mode:'passphrase',passphrase:$('cryPass').value,adminPassword:$('cryAdminPw').value}); $('cryPass').value=''; toast('Klucz chroniony hasłem'); loadCrypto(); };
$('cryUseFile').onclick=async()=>{ await api('crypto/key',{mode:'file',adminPassword:$('cryAdminPw').value}); toast('Klucz w pliku'); loadCrypto(); };
loadCrypto().catch(()=>{});
const LOGLV = {10:'debug',20:'info',30:'warn',40:'error',50:'security'};
const LOGCOL = {10:'#7a8696',20:'#2f7fd1',30:'#c98a00',40:'#d1342f',50:'#8a3fd1'};
async function loadLogs(){
  const q=await api('logs/query',{minLevel:$('logLvl').value,cat:$('logCat').value,q:$('logQ').value,limit:300});
  const box=$('logBox'); box.textContent='';
  for(const e of q.entries){
    const row=el('div',{style:'padding:2px 0;border-bottom:1px solid #8882;cursor:pointer;white-space:pre-wrap;word-break:break-word'},
      '#'+e.seq+' '+new Date(e.ts).toISOString().replace('T',' ').slice(0,23)+' ',
      el('b',{style:'color:'+(LOGCOL[e.level]||'')},LOGLV[e.level]||e.level),' ['+e.cat+'/'+e.ev+'] '+e.msg);
    row.onclick=()=>{ const n=row.nextSibling; if(n&&n.dataset&&n.dataset.det){n.remove();return;} const d=el('pre',{style:'margin:2px 0 6px;font-size:11px'},JSON.stringify(e.f||{},null,1)); d.dataset.det='1'; row.after(d); };
    box.append(row);
  }
  if(!q.entries.length) box.textContent='Brak wpisów dla tych filtrów.';
  const s=await api('logs/status',{}); const st=s.stats;
  $('logStats').textContent='Wpisów: '+st.entries+' w '+st.blocks+' blokach · zajmuje '+Math.round(st.storedBytes/1024)+' KB (surowo '+Math.round(st.rawBytes/1024)+' KB, ZSTD '+Math.round(st.compressedBytes/1024)+' KB) · szyfr dziennika: '+st.cipher+' · od '+(st.firstTs?fmt(st.firstTs):'—')+' · skrót końca łańcucha: '+String(st.headHash).slice(0,16)+'…';
}
$('logRefresh').onclick=()=>loadLogs();
$('logVerify').onclick=async()=>{ $('logVerifyOut').textContent='Sprawdzam…'; const r=await api('logs/verify',{}); const v=r.verify;
  $('logVerifyOut').textContent=v.ok?('Integralność OK: '+v.blocks+' bloków, '+v.entries+' wpisów, łańcuch skrótów ciągły'+(v.prunedPrefix?' (najstarsze bloki przycięte wg limitu)':'')+'.'):('NARUSZONA: '+v.problems.map(p=>p.msg).join('; ')); };
$('logExport').onclick=async()=>{
  if(!$('logPw').value){ toast('Podaj hasło administratora'); return; }
  toast('Tworzę zaszyfrowany plik (to chwilę trwa)…');
  const r=await fetch('/admin/api/logs/export',{method:'POST',headers:{'X-CSRF-Token':CSRF,'Content-Type':'application/json'},body:JSON.stringify({adminPassword:$('logPw').value,days:Number($('logDays').value),minLevel:$('logExpLvl').value})});
  if(!r.ok){ const j=await r.json().catch(()=>({})); toast(j.error||'Nie udało się wyeksportować'); return; }
  const blob=await r.blob(); const a=el('a',{href:URL.createObjectURL(blob),download:'dziennik-serwera-'+new Date().toISOString().slice(0,10)+'.html'});
  document.body.append(a); a.click(); a.remove(); $('logPw').value=''; toast('Zapisano zaszyfrowany plik HTML');
};
loadLogs().catch(()=>{});
async function loadVideo(){
  const s=await api('video/status',{});
  const box=$('vidOpts'); box.textContent='';
  for(const o of s.options){
    const radio=el('input',{type:'radio',name:'vidEnc',value:o.id,disabled:s.locked,style:'width:auto'});
    radio.checked=(o.id===s.preference);
    radio.onchange=async()=>{ try{ await api('video/encoder',{encoder:o.id}); toast('Zapisano'); }catch(e){} loadVideo(); };
    const note=o.id==='auto'?'':(' — '+[o.hevc?'H.265':'',o.avc?'H.264':''].filter(Boolean).join(' + '));
    box.append(el('label',{style:'display:flex;gap:8px;align-items:center'},radio,o.label+note));
  }
  $('vidInfo').textContent='Teraz: H.265 — '+s.effective.hevc+'; H.264 — '+s.effective.avc+(s.locked?' (wymuszone zmienną VIDEO_ENCODER)':'')+'. Gdy wybrany akcelerator zawiedzie, zadanie przechodzi na CPU.';
}
loadVideo().catch(()=>{});
async function loadUpdates(check){
  const s=await api(check?'update/check':'update/status',{});
  const r=s.result; const info=$('updInfo'); $('updNotes').textContent='';
  $('updAuto').checked=s.autoCheck; $('updInstall').style.display='none'; $('updRollback').style.display=s.backups&&s.backups.length?'':'none';
  let t='Wersja serwera: '+s.current+' · repozytorium: '+s.repository+' · ';
  if(s.pendingRestart) t+='ZAINSTALOWANO — '+(s.supervised?'trwa restart…':'uruchom serwer ponownie (zamknij okno i start.bat / start.sh).');
  else if(s.error) t+='błąd: '+s.error;
  else if(!r) t+='jeszcze nie sprawdzano.';
  else if(r.state==='available'){ t+='DOSTĘPNA WERSJA '+r.version+(r.mandatory?' — WYMAGANA (aktualizacja bezpieczeństwa)':'')+' ('+Math.round(r.asset.size/1024)+' KB)'; $('updNotes').textContent=r.notes||''; $('updInstall').style.display=''; }
  else t+='masz najnowszą wersję.';
  if(s.checkedAt) t+=' · sprawdzono '+fmt(s.checkedAt);
  info.textContent=t;
}
$('updCheck').onclick=async()=>{ toast('Sprawdzam…'); await loadUpdates(true); };
$('updAuto').onchange=async()=>{ await api('update/config',{autoCheck:$('updAuto').checked}); toast('Zapisano'); };
$('updInstall').onclick=async()=>{ if(!confirm('Zainstalować aktualizację? Serwer uruchomi się ponownie.')) return; toast('Pobieram i instaluję…'); const r=await api('update/install',{adminPassword:$('updPw').value}); toast('Zainstalowano '+r.to+(r.restarting?' — restart…':' — uruchom serwer ponownie')); loadUpdates(false); };
$('updRollback').onclick=async()=>{ if(!confirm('Cofnąć ostatnią aktualizację?')) return; const r=await api('update/rollback',{adminPassword:$('updPw').value}); toast('Przywrócono '+r.restoredTo); loadUpdates(false); };
loadUpdates(false).catch(()=>{});
$('logout').onclick=async()=>{ await api('logout',{}); location.href='/admin'; };
refresh().catch(()=>{});
setInterval(()=>{ if(!document.querySelector('[style*="z-index:9"]')) refresh().catch(()=>{}); }, 15000);
`;
