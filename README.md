# Serwer referencyjny lewicowYT — kod źródłowy

To jest **cały kod źródłowy** serwera referencyjnego społeczności lewicowYT w jednym miejscu: serwer (Node.js), instalatory
(Windows `.exe`, Linux `.run`) i **FFmpeg zbudowany specjalnie dla serwera**. FFmpeg nie jest osobną aplikacją ani
zależnością do ściągnięcia — jego źródła i skrypty budowania leżą w katalogu `ffmpeg/`, a gotowe `ffmpeg`/`ffprobe`
wchodzą do paczek instalatorów jako część serwera.

## Układ repozytorium
| Ścieżka | Co to jest |
|---|---|
| `*.js`, `package.json`, `test-e2e.mjs` | serwer (Node.js ≥ 22.15, bez zależności; opcjonalnie `acme-client`) |
| `ffmpeg/` | **FFmpeg dla serwera**: `build.sh` (Linux/macOS/Windows-MSYS2/Android), `build.ps1`, `ffmpeg-config.sh` (jedna lista flag dla wszystkich platform), `LICENSE-NOTES.md` |
| `.github/workflows/ffmpeg.yml` | budowanie FFmpeg w CI: Linux na `ubuntu-22.04` (glibc 2.35 → działa na starszych dystrybucjach) i Windows (MSYS2) |
| `install.ps1`, `install.bat`, `install.sh` | instalatory „online”: sanityzacja danych, Node.js, Tor, cjxl, acme-client (każdy plik z SHA-256) |
| `instalator-exe/` | kod instalatora Windows (Go, `go:embed`) — samorozpakowujący `.exe` |
| `instalator-run.sh.tpl` | nagłówek instalatora Linux `.run` (skrypt sh + archiwum tar.gz) |
| `zrob-ffmpeg.mjs` | buduje FFmpeg z `ffmpeg/` i kładzie `ffmpeg` + `ffprobe` w `tools/` (tam szuka ich `convert.js`) |
| `zrob-instalatory.mjs` | składa `dist/…-instalator.exe` i `dist/….run` **razem z FFmpeg** danej platformy |
| `zrob-wydanie.mjs` | paczka `.zip` do aktualizacji serwerów (bez `data/`, `tools/`, `engine*/`, `node_modules/`) |

## FFmpeg wbudowany w serwer
Jedna konfiguracja (`ffmpeg/ffmpeg-config.sh`), dwie binarki (formaty `.exe` i ELF nie są wymienne):
- **obrazy:** PNG, JPEG, WebP (też animowany), JPEG XL, AVIF; **audio:** Opus; **wideo:** H.264 (x264) i H.265 (x265) do MP4;
- **akceleracja sprzętowa:** NVIDIA (NVENC) na Windows i Linux, AMD (AMF) i Intel (QSV) na Windows, Intel/AMD przez VAAPI na Linux;
  gdy sterownika brak, serwer sam wraca do x264/x265 (`convert.js` sprawdza enkodery próbą kodowania);
- licencja wyniku: **GPL** (x264/x265) — patrz `ffmpeg/LICENSE-NOTES.md`.

Budowanie lokalne:
```
node zrob-ffmpeg.mjs          # Windows (MSYS2 w C:\msys64 albo MSYS2_ROOT) lub Linux (build-essential cmake ninja-build nasm pkg-config git libva-dev libdrm-dev)
node zrob-instalatory.mjs     # → dist/lewicowyt-serwer-<wersja>-instalator.exe oraz dist/lewicowyt-serwer-<wersja>.run
```
Wydanie dla obu systemów najłatwiej złożyć z artefaktów workflow `ffmpeg` (Linux zbudowany na starszej glibc): pobierz je do
`ffmpeg/dist/linux-x86_64/` i `ffmpeg/dist/windows-x86_64/` i uruchom `node zrob-instalatory.mjs`.

---

# Serwer społeczności (lewicowYT) — wersja idiotoodporna

Kompletny serwer treści dla aplikacji **lewicowYT**, **w całości konfigurowalny z przeglądarki**.
Wszystko wpisujesz **ręcznie** (żadnych scraperów YouTube/Instagrama) — a aplikacja dostaje:
**posty, memy (także karuzele do 20 zdjęć), artykuły/newslettery, pozycje z innych platform, polecanych
twórców YouTube, reklamy i konkursy**, plus **powiadomienia push bez Google** (wbudowany UnifiedPush/LEP +
szyfrowanie E2E), przez **Tor (.onion)**, LAN albo HTTPS — wszystkie adresy działają jednocześnie.

## Co dostajesz
- 🗄️ **Jedna, zaszyfrowana baza danych** – cała treść, konfiguracja, multimedia, certyfikaty i klucz .onion w jednym pliku SQLite (`data/serwer.db`), szyfrowana domyślnie najlepszym szyfrem przyspieszanym sprzętowo przez Twój procesor (AES-NI / ARM AES…).
- 🧅 **Tor (.onion)** – serwer osiągalny bez publicznego IP (omija CGNAT). Żeby adres IP operatora naprawdę nie był powiązany z usługą, zaznacz w panelu „nasłuchuj tylko lokalnie (127.0.0.1)” — inaczej port HTTP jest otwarty na wszystkich interfejsach i ten sam manifest widać pod IP komputera.
- 🔔 **Powiadomienia bez Google** – serwer sam obsługuje **wbudowany dystrybutor aplikacji (LEP)**, więc
  użytkownik nic nie instaluje; działa też zewnętrzny dystrybutor (np. ntfy). Każdy budzik jest szyfrowany
  osobno do urządzenia (ECIES P-256) – pośrednik widzi tylko szum. Opcjonalnie **puste budziki (szum)**.
- 📝 **Wszystkie typy treści** – dodajesz z panelu, z obrazami, dźwiękiem i filmem w **dowolnym formacie** — serwer sam je
  przygotowuje dla aplikacji (JPEG XL, H.265/H.264, Opus), gdy ma **ffmpeg** (patrz „Konwersja multimediów”).
- ✏️ **Edycja i usuwanie, które działają w aplikacji** – „istotna zmiana” może ponownie powiadomić,
  usunięty wpis znika też u ludzi (przez `deletions`).
- 🔒 **HTTPS z Let's Encrypt** (opcjonalnie, gdy chcesz adres z domeny) – automatyczne odnawianie.
- 🛡️ **Prywatny i send-only** – jedyny publiczny `POST` to rejestracja push; panel tylko lokalnie.

## Wymagania
**Nic nie musisz instalować.** Instalator sam pobiera silnik (Node.js) i — jeśli chcesz — Tora.
Potrzebny jest tylko system Windows albo Linux/macOS i połączenie z internetem przy pierwszym starcie.

## Szybki start — Windows (dla każdego)
1. Rozpakuj folder serwera gdziekolwiek.
2. **Dwuklik `start.bat`.** Przy pierwszym uruchomieniu instalator zapyta:
   - gdzie zainstalować **silnik** — *lokalnie* (tylko dla tego serwera, folder `engine\`) albo *systemowo*
     (do użytku ogólnego, bez uprawnień administratora),
   - czy pobrać **Tora** (zalecane — daje adres `.onion`).
   Potem serwer startuje automatycznie.
3. W oknie serwera pojawi się **hasło administratora** — skopiuj je.
4. Wejdź na **http://127.0.0.1:2138/admin** (panel **tylko lokalnie**), zaloguj się, zmień hasło.
5. W sekcji **Sieć** zaznacz **„uruchom jako usługę ukrytą Tor"** → za chwilę pojawi się adres `.onion`.
   Ten adres (`http://…onion:2137`) wpisujesz w aplikacji lewicowYT jako serwer.

> Samą instalację (bez startu) odpalisz dwuklikiem `install.bat`. Kolejne uruchomienia: po prostu `start.bat`.

## Szybki start — Linux / macOS (np. VPS)
```
sh start.sh
```
Jak wyżej: przy pierwszym razie pobierze silnik (lokalnie/systemowo) i opcjonalnie Tora, potem wystartuje.

## Gotowe instalatory: .exe (Windows) i .run (Linux)
Zamiast rozpakowywać paczkę ręcznie możesz użyć jednego pliku:
- **Windows:** `lewicowyt-serwer-<wersja>-instalator.exe` — dwuklik, wybierasz katalog (domyślnie `%USERPROFILE%lewicowYT-serwer`),
  plik rozpakowuje serwer i uruchamia `install.ps1`. Parametry: `-dir KATALOG`, `-nopause`, `-extract-only`, a także te
  z `install.ps1` (`-Mode`, `-Tor`, `-Clean`, `-Yes`, `-CheckOnly`). Plik **nie jest podpisany** certyfikatem Authenticode, więc
  SmartScreen może ostrzec („Więcej informacji → Uruchom mimo to”).
- **Linux/macOS:** `sh lewicowyt-serwer-<wersja>.run` — rozpakowuje do `~/lewicowyt-serwer` (`--target KATALOG` zmienia),
  uruchamia `install.sh`. `--verify` sprawdza tylko sumę SHA-256, `--noexec` tylko rozpakowuje. Zawartość obejrzysz bez
  uruchamiania: `sed '1,/^__ARCHIVE_BELOW__$/d' plik.run | tar -tzf -`.
- **Budowanie (dla autora):** `node zrob-instalatory.mjs` → katalog `dist/` (do .exe potrzebny jest zainstalowany Go).
  Ponowne uruchomienie na istniejącym katalogu nadpisuje tylko pliki kodu — `data/`, `engine/`, `tools/` zostają.

## Jak działa instalator (dla ciekawych)
`install.bat` / `install.sh` badają **6 komponentów niezależnie** i pobierają **tylko brakujące**: Node.js (≥ 22.15) + npm,
Tor, FFmpeg, FFprobe, `cjxl` (koder JPEG XL) oraz pakiet npm `acme-client` (HTTPS z Let's Encrypt). Gdy wszystko jest —
nic nie pobierają. Każdy pobrany plik ma **sprawdzaną sumę SHA-256** (lista sum dostawcy albo suma przypięta dla niezmiennego
wydania); niezgodny plik jest usuwany. Podpisów GPG instalator nie sprawdza — zrób to ręcznie, jeśli chcesz.
- **Krok 0 — sanityzacja.** Jeśli paczka zawiera bazę/klucz z komputera autora (rozpoznawane po kluczu deweloperskim),
  instalator **odkłada je do `data/_kopia-<data>/`**, żeby serwer założył własny klucz, bazę i hasło administratora. Własnych
  danych (inny klucz) nie rusza. `-Clean` / `--clean` robi to samo na życzenie (z potwierdzeniem; `-Yes` / `--yes` je pomija).
  Zawsze zeruje też cache szybkości szyfrów w `data/szyfrowanie.json` (serwer policzy go od nowa), usuwa martwy `.enginepath`
  oraz `data/tmp` i pliki `*.tmp`.
- **Node.js:** linia LTS 24 z `nodejs.org`. `-Mode local` (domyślnie) = pełny pakiet w `engine\` (Node + npm), `-Mode system` =
  `%LOCALAPPDATA%\lewicowyt-engine` (Linux: `~/.local/lewicowyt-engine`) + PATH i `.enginepath`.
- **Tor:** z `dist.torproject.org` do `engine-tor\`. Najnowszy katalog wydań bywa niepełny (np. tylko paczki na Androida), więc
  instalator schodzi do najnowszej wersji, która ma paczkę dla Twojego systemu. `-Tor yes|no|ask`.
- **FFmpeg/FFprobe:** Windows i Linux x64/arm64 — buildy BtbN (GPL) do `tools\`, na Windows z zapasem gyan.dev; kopiowana jest tylko
  brakująca binarka. **macOS:** brak zweryfikowalnego oficjalnego źródła — instalator podpowiada `brew install ffmpeg`.
- **cjxl:** Windows x64 (libjxl 0.11.2; wydanie 0.12.0 używa kompresji ZIP, której Windows nie rozpakuje) i Linux x86_64 (libjxl 0.11.2) z GitHub Releases z przypiętą sumą SHA-256. Linux arm64
  i macOS: pakiet systemowy (`libjxl-tools` / `brew install jpeg-xl`).
- **acme-client:** `npm install --no-save acme-client@^5.4.0` (nie zmienia `package.json`). Brak tego pakietu nie blokuje startu.
- `-CheckOnly` / `--check-only`: tylko sanityzacja i raport, nic nie pobiera.
- **Lokalnie** silnik jedzie razem z folderem serwera; **systemowo** jest dostępny jako `node` wszędzie.
- Silnik jest lekki w działaniu — serwer zużywa rzędu kilkudziesięciu MB RAM.

> Panel nigdy nie jest dostępny z sieci ani przez `.onion` — tylko z `127.0.0.1`. Z innego komputera
> użyj tunelu SSH: `ssh -L 2138:127.0.0.1:2138 user@serwer`, potem otwórz `http://127.0.0.1:2138/admin`.

## Dodawanie treści
W panelu, karta **„Treści"**: wybierz typ (post / mem / artykuł / inna platforma / reklama / konkurs),
kliknij **Dodaj**, wypełnij pola, ewentualnie wgraj obraz. Po zapisaniu istotnego wpisu — i po wgraniu jego
obrazów, miniatury, dźwięku i filmu — serwer **sam** wyśle zaszyfrowany budzik do wszystkich, którzy mają włączone powiadomienia tego serwera (wyłączysz to w
„Konfiguracji”); przycisk **„🔔 Powiadom subskrybentów"** wysyła budzik ręcznie. Aplikacja po budziku sama
dociągnie treść i pokaże nowości.

**Planowanie:** ustaw **datę publikacji w przyszłości** — wpis będzie ukryty (także jego plik i strona
`/e/<id>`), a o tej godzinie pojawi się w aplikacji i dostanie budzik. W panelu ma znaczek „⏰ zaplanowany”.

**Miniatura powiadomienia:** serwer z ffmpeg robi ją **sam** z pierwszego obrazu wpisu (mały WebP do 6 KB); możesz też
wgrać własną (JPG/PNG/WEBP, do **6 KB**, np. 96×96). Serwer wkłada ją zaszyfrowaną prosto do budzika, więc aplikacja pokazuje go w powiadomieniu **bez
pobierania z sieci** — serwer nie widzi, kto dostał powiadomienie. Większy plik też zadziała, ale aplikacja
pobierze go osobno (panel o tym ostrzega). Przy postach możesz też dodać **awatar autora** (z ffmpeg: dowolny obraz, serwer zmniejszy go do 512 px).

**Powiadomienie systemowe** (dymek na telefonie) aplikacja pokazuje tylko dla wpisów oznaczonych jako istotne
(`update: significant`). Dlatego przy dodawaniu wpisu pole **„Powiadom o tym wpisie”** jest domyślnie
zaznaczone — odznacz je, jeśli wpis ma się pojawić tylko w zakładce. Oznaczenie trwa **48 h** od dodania:
później wpis zostaje w zakładce, ale nowy subskrybent nie dostanie zbiorczego powiadomienia o starych wpisach.
Reklamy i twórcy nigdy nie powiadamiają.

Minimalne wymagania pól:
- **Post** – autor + treść (rodzaj i link do oryginału opcjonalne).
- **Mem** – co najmniej jeden obraz **WEBP/JXL/AVIF** (do 20 — karuzela); podpis/źródło/link opcjonalne.
- **Artykuł** – tytuł + źródło + link **https**; *newsletter* może być bez linku (sama treść).
- **Inna platforma** – nazwa platformy + (tytuł albo treść albo link https). Platformy z linkami pojawią
  się same w ustawieniach aplikacji („Otwieranie linków platform”).
- **Twórca YouTube** – nazwa (+ link do kanału).
- **Reklama / konkurs** – tytuł + link **https**. Reklama wyświetla się dopiero przy 20+ zwykłych wpisach.

**Dźwięk (Opus):** do posta, artykułu, wpisu z innej platformy albo mema możesz dodać plik dźwiękowy
w formacie **Opus** (`.opus`/`.ogg` albo WebM, do 80 MB) i opcjonalny tytuł. Aplikacja gra go **sama** — w tle
(także przy wygaszonym ekranie), w pętli i z prędkością do 3× — a nie w przeglądarce. Serwer sprawdza, czy plik
naprawdę jest Opusem, i sam odczytuje jego długość. Do mowy wystarczy 24–48 kb/s mono; w Audacity: Plik →
Eksportuj → Opus. Na stronie wpisu `/e/<id>` dźwięk ma zwykły odtwarzacz przeglądarki.

**Film:** do tych samych wpisów możesz dodać film MP4 w dwóch wariantach: **H.265** (główny, najmniejszy
plik) i **H.264** (zapasowy dla słabych telefonów bez sprzętowego H.265 — bez niego taki telefon filmu nie
odtworzy). **Najwyżej 30 kl/s** — aplikacja sama mierzy klatki w pobranym pliku i film powyżej 30 kl/s
odrzuca, a serwer odrzuca go już przy wgrywaniu (sprawdza też kodek i rozdzielczość, maks. 1920 px, 200 MB
na wariant). **Dźwięk wyłącznie w Opusie** (albo film niemy) — film z AAC/MP3 serwer bez ffmpeg odrzuci, a aplikacja i tak
by go nie odtworzyła (z ffmpeg serwer przekoduje to sam; ręcznie:
`ffmpeg -i wejscie.mp4 -r 30 -c:v libx265 -crf 28 -tag:v hvc1 -pix_fmt yuv420p -c:a libopus -b:a 48k -movflags +faststart film-h265.mp4`
oraz `ffmpeg -i wejscie.mp4 -r 30 -c:v libx264 -crf 26 -profile:v main -pix_fmt yuv420p -c:a libopus -b:a 48k -movflags +faststart film-h264.mp4`).
Bez konwersji serwer przy wgrywaniu i tak sam przenosi spis filmu (`moov`) na początek pliku — aplikacja sprawdza kodek,
liczbę klatek i dźwięk z pierwszych KB i przerywa pobieranie złego filmu, zamiast ściągać całość.

**Konwersja multimediów (ffmpeg).** Wgraj plik w **dowolnym formacie**, a serwer sam przygotuje go dla aplikacji
(wymagania protokołu, sekcja 10) i usunie z niego metadane:
- **obraz** → **JPEG XL** (preferowany; WebP, gdy brak kodera JXL), najwyżej 6 000 000 B i 4096 px na bok; jakość
  JXL serwer deklaruje sam (`imageQuality`); animowany GIF/WebP/APNG → animowany WebP; PNG, JPG, WBMP, BMP itd. → JXL.
  Obraz, który już jest dobrym JXL/AVIF/WEBP w limitach, zostaje bez przekodowania (tylko bez metadanych);
- **Kodowanie filmu na GPU:** przy starcie serwer sprawdza (próbnym kodowaniem), czy komputer ma działający koder sprzętowy — kolejno NVIDIA NVENC → Intel Quick Sync → AMD AMF → Apple VideoToolbox → VAAPI (Linux) — i jeśli tak, WYMUSZA go zamiast CPU (osobno dla H.265 i H.264). Używa parametrów poprawiających jakość/bitrate prawie za darmo (look-ahead, adaptacyjna kwantyzacja przestrzenna i czasowa, B-ramki); na CPU: `aq-mode=3`, `rc-lookahead=40`, `b-adapt=2`. Gdy kodowanie na GPU zawiedzie, zadanie samo przechodzi na CPU. **Wiele akceleratorów:** serwer sprawdza wszystkie (kilka kart NVIDIA, zintegrowaną grafikę Intela przez Quick Sync, AMD AMF, kolejne węzły VAAPI) i w panelu („🎞️ Kodowanie filmów”) możesz wybrać, który ma pracować — np. zintegrowaną grafikę, żeby osobna karta była wolna do gier — albo zostawić „Automatycznie”. Wybór zapamiętuje baza; zmienna `VIDEO_ENCODER` (np. `nvenc:1`, `qsv`, `vaapi:/dev/dri/renderD129`, `cpu`) go wymusza i blokuje zmianę w panelu. **Kilka kart NVIDIA (np. dwa RTX 2080, także w SLI):** każda karta jest sprawdzana osobno (`-gpu 0…7`, numeracja jak w `nvidia-smi`) i pojawia się w panelu jako „… — GPU 0”, „… — GPU 1”. SLI nie ma znaczenia dla NVENC — każda karta koduje samodzielnie, a serwer używa jednej wybranej (automatycznie pierwszej); równoległe użycie obu kart jednocześnie nie jest zaimplementowane. **Kilka kart tego samego producenta (Windows):** serwer sprawdza każdy adapter DXGI osobno (`-init_hw_device qsv=…,child_device=N`, analogicznie AMF). Gdy Quick Sync lub AMF działa na co najmniej dwóch adapterach (np. Intel Arc + zintegrowana grafika, albo dwie karty AMD), w panelu pojawiają się osobne pozycje (`qsv:0`, `qsv:1`, `amf:0`…) z nazwami kart z systemu — przy jednej karcie zostaje jedna pozycja jak dotąd. Kolejność nazw przypisywana jest wg kolejności kart tego producenta w systemie; jeśli się nie zgadza, rozpoznaj kartę po wydajności. Wybór adaptera dla AMF zależy od wersji ffmpeg i nie został przetestowany na komputerze z dwiema kartami. Koder sprzętowy koduje obraz osobno, a dźwięk Opus dokłada przy scalaniu (omija błąd sterownika Intel QSV). `VIDEO_ENCODER=cpu|nvenc|qsv|amf|videotoolbox|vaapi` wymusza wybór (domyślnie `auto`). Uwaga: koder sprzętowy jest kilka razy szybszy, ale daje większe pliki niż x265/x264 przy tym samym nominalnym poziomie jakości.
- **film** → **H.265** (główny) **oraz H.264** (zapas dla telefonów bez sprzętowego H.265), najwyżej 30 kl/s i 1920 px,
  dźwięk Opus (albo brak), spis `moov` na początku. Konwersja trwa od kilkudziesięciu sekund do kilku minut;
- **dźwięk** → Opus w Ogg (48 kb/s), także ze ścieżki filmu; do 80 MB po konwersji;
- **miniatura powiadomienia** → mały WebP, jeśli jej nie wgrasz.

Skąd serwer bierze narzędzia (kolejno): zmienne `FFMPEG_PATH`, `FFPROBE_PATH`, `CJXL_PATH`; katalog `tools/` obok
`server.js`; `PATH`. **Do konwersji potrzebny jest ffmpeg** (z `libx265`, `libx264`, `libopus`, `libwebp`); **cjxl** (libjxl) — dla
JPEG XL (bez niego obrazy będą w WebP). Stan konwersji widać w panelu przy edycji wpisu. Zmienna
`LEWICOWYT_NO_CONVERT=1` wyłącza konwersję.

**Bez ffmpeg** serwer działa jak dawniej: przyjmuje tylko pliki już w poprawnym formacie (obraz zakładki: JXL/AVIF/WEBP
do 6 MB; film H.265/H.264 MP4 do 30 kl/s z Opusem; dźwięk Opus) i odrzuca resztę z wyjaśnieniem. Serwer sprawdza
**zawartość** pliku (pierwsze bajty), nie tylko nazwę, więc PNG przemianowany na `.webp` nie przejdzie.

**Metadane (prywatność):** zdjęcia z telefonu zwykle niosą EXIF — współrzędne GPS, czas, model aparatu —
a filmy lokalizację. Serwer **sam usuwa je przy wgrywaniu**: z JPG/PNG/WEBP/JXL (EXIF, XMP, komentarze,
dodatkowe zdjęcia doklejone za obrazem), z AVIF (dane EXIF/XMP zerowane) i z MP4 (pudełka `udta`/`meta`/`uuid`).
Obraz i dźwięk zostają nietknięte. Pliki wgrane starszą wersją serwera są czyszczone raz, przy pierwszym starcie.
Plik, którego nie da się bezpiecznie przetworzyć, jest odrzucany z komunikatem (zamiast trafić do ludzi z GPS).
Tagi w plikach Opus (tytuł, wykonawca) zostają — nie wpisuj tam niczego prywatnego.

**Edycja:** zaznacz „Istotna zmiana”, jeśli aplikacja ma o niej powiadomić; bez tego poprawka idzie po cichu.
Drobna poprawka **świeżego** wpisu (w ciągu 48 h od oznaczenia „Powiadom”), który ma stały link (https albo
`/e/<id>`), nie kasuje jego powiadomienia — telefony, które jeszcze go nie pobrały, nadal je dostaną (a te,
które już powiadomiły, nie dostaną drugiego).
Aplikacja powiadamia o danym wpisie (jego linku) **tylko raz** — jeśli już powiadomiła przy dodaniu, kolejna
„istotna zmiana” tego samego wpisu pojawi się w zakładce, ale bez nowego dymka. **Usuwanie:** plik wpisu
znika z listy, więc aplikacja kasuje wpis u siebie (patrz „Każdy wpis to osobny plik” niżej).

## Powiadomienia: co musi mieć użytkownik
Nic. Aplikacja ma **wbudowany dystrybutor UnifiedPush (LEP)**, a ten serwer sam go obsługuje
(`/lep/pub`, `/lep/sub`) — budziki dla wbudowanego dystrybutora wrzuca prosto do własnej kolejki, więc
działa to także przez `.onion` i za routerem bez hairpin-NAT. Kto woli zewnętrzny dystrybutor (np. ntfy),
też dostanie budziki. Bez pusha aplikacja i tak pobiera treści co ~2 h i ręcznie.

Serwer jest **w pełni prywatny**: manifest NIE zawiera konfiguracji FCM, więc aplikacja nigdy nie
kontaktuje Google w jego sprawie. Rejestracja push przyjmuje tylko wbudowany LEP albo zewnętrzny dystrybutor
pod publicznym `https` na porcie 443. Nazwę dystrybutora serwer sprawdza w DNS przy rejestracji **i przy
każdym połączeniu** — adres wskazujący sieć lokalną, loopback, link-local, CGNAT czy NAT64 jest odrzucany,
więc rejestracją push nie da się kazać serwerowi pukać do Twojej sieci. Do jednego zewnętrznego dystrybutora
trafia najwyżej 5000 adresów, a rejestracje mają limit tempa (ochrona przed użyciem serwera jako wzmacniacza).
Rejestracja bez klucza E2E jest przyjmowana (wtedy budzik to jawne `{"t":"1"}`, bez szumu).
Subskrybent wbudowanego pushu, którego aplikacja nie odpytuje od tygodnia, jest usuwany.

**Szum (opcjonalnie):** w panelu → „Powiadomienia push” ustawisz liczbę **pustych budzików** na urządzenie
na dobę. Serwer losuje je niezależnie dla każdego urządzenia, gęściej wieczorem, rzadziej w nocy — przez
to z samych godzin budzików trudniej zgadnąć, co ktoś czyta. Kosztuje to trochę baterii, więc rozsądnie 2–8.
Każde urządzenie ma **twardy dzienny limit** szumu (półtora raza ustawiona liczba), a przy prawdziwym budziku
część urządzeń dostaje w tym samym oknie dodatkowy pusty — trudniej wskazać, który był prawdziwy.
**Rozmywanie** (0–600 s): prawdziwy budzik idzie do każdego urządzenia w jego własnym, losowym momencie
w tym oknie zamiast do wszystkich w tej samej sekundzie.

**Statystyki:** panel pokazuje same liczby — ilu subskrybentów ma wbudowany push, a ilu zewnętrzny
dystrybutor, ilu bez szyfrowania E2E, ilu było aktywnych w 24 h / 7 dni i ilu doszło w 24 h. Serwer nie zna
tożsamości subskrybentów, więc nic więcej nie ma do pokazania.

## Platformy linków
Aplikacja pozwala wybrać dla każdej platformy, czym otwierać jej linki (jak dla YouTube). Platformy z wpisów
„Inna platforma” dodają się same. Inne — np. dla linków w artykułach — dopiszesz w panelu („🔗 Platformy
linków”), linia na platformę: `id | Nazwa | host1, host2`, np. `twitch | Twitch | twitch.tv`.

## Kopia zapasowa i dostęp
- **Kopia:** panel → „💾 Kopia zapasowa” → (podaj hasło administratora) **Pobierz kopię** — przy multimediach powyżej ok. 220 MB kopia z panelu nie jest możliwa (zatrzymaj serwer i skopiuj pliki bazy: `serwer.db`, klucz i `szyfrowanie.json`): jeden plik JSON z konfiguracją, regulaminem,
  wszystkimi wpisami i obrazami, listą usunięć, subskrybentami push i **kluczem adresu .onion** (bez hasła
  administratora). **Wczytaj kopię** zastępuje wpisy i konfigurację (porty i Tor tego komputera zostają);
  klucz .onion zadziała po ponownym uruchomieniu. Tak też przenosisz serwer na inny komputer — z tym samym
  adresem .onion. Kopię trzymaj bezpiecznie: kto ma klucz .onion, może podszyć się pod Twój serwer.
- **Zapomniane hasło:** zatrzymaj serwer i uruchom `start.bat --reset-password` (Linux/macOS:
  `sh start.sh --reset-password`) — w oknie pojawi się nowe hasło, stare przestaje działać.
- **Sesje:** zmiana hasła wylogowuje wszystkie pozostałe sesje; przycisk **„Wyloguj wszystkie sesje”**
  wylogowuje też bieżącą.

## Kilka adresów naraz
Ten sam serwer możesz mieć jednocześnie pod `.onion`, adresem z LAN i domeną z HTTPS. Manifest jest
budowany osobno dla adresu, którym aplikacja przyszła (obrazy i push muszą być na tym samym hoście co
manifest). Manifest pobrany przez HTTPS dostaje też prywatne adresy LAN (`altEndpoints`), więc telefon w
domowym Wi-Fi połączy się nawet przy routerze bez hairpin-NAT.

Gdy serwer zna już swój adres HTTPS, żądania przychodzące na **prywatny adres IP** dostają manifest z adresami
**HTTPS** (tak oczekuje aplikacja przy przełączeniu na adres LAN — inaczej memy znikały, a ulubione się
dublowały). Skutek uboczny: na serwerze z domeną testy w LAN (np. `10.0.2.2` w emulatorze) dostają obrazy
z domeny. Do testów w LAN użyj serwera bez ustawionej domeny.

## Serwer główny
Ten serwer **nie może** być „serwerem głównym” w aplikacji — serwer główny musi sam dostarczać filmy
YouTube i deklarować `primaryFeed`, a tu treść wpisujesz ręcznie. Dzięki temu nikt nie zgubi powiadomień
o filmach przez przypadkowe przełączenie.

## HTTPS z domeny (opcjonalnie)
1. Skieruj domenę (rekord A/AAAA) na serwer; otwórz porty **80** (wystawienie certyfikatu) i **2137**; `npm install`.
2. Panel → **HTTPS** → wpisz domenę + e-mail → **„Wystaw / odnów certyfikat teraz"**.
3. W aplikacji wpisz **samą domenę** (np. `serwer.twojadomena.pl`). Aplikacja dopisuje port **2137** i tam
   serwer odpowiada zarówno po HTTP, jak i po HTTPS (rozpoznaje TLS po pierwszym bajcie połączenia).
   Dodatkowo HTTPS słucha na 443 — dla przeglądarek i stron wpisów `/e/<id>`.
4. Certyfikat odnawia się sam. Testy: `LE_STAGING=1 node server.js`.

Za własnym reverse proxy (nginx, Caddy) z TLS: przekazuj ruch na `127.0.0.1:2137` z nagłówkami `Host` i
`X-Forwarded-Proto: https` — serwer nauczy się adresu HTTPS sam. Pamiętaj, że aplikacja dla adresu bez
portu łączy się na **2137**, więc proxy musi słuchać na 2137 (albo w aplikacji wpisz jawnie `domena:443`).

## Porty
- `2137` – publiczny HTTP **i HTTPS** (manifest + push); ten sam, którego aplikacja używa domyślnie.
- `2138` – panel administratora (**tylko 127.0.0.1**).
- `443` – dodatkowy HTTPS (gdy masz certyfikat), dla przeglądarek.
- `80` – tylko na czas wystawiania certyfikatu Let's Encrypt (wyłączysz przez `ACME_HTTP01=off`).
Zmienisz je w panelu albo przez `HTTP_PORT` / `HTTPS_PORT` / `ADMIN_PORT`.

## Pliki
- `server.js` – serwer HTTP/HTTPS, routing, panel, start Tora/ACME.
- `admin.js` – panel w przeglądarce (bez zależności front-endowych).
- `store.js` – magazyn: **zaszyfrowana baza SQLite** `data/serwer.db` (wbudowany `node:sqlite`, bez zależności): konfiguracja, hasło (skrót), wpisy,
  usunięcia, subskrybenci push, multimedia (zaszyfrowane kawałki), certyfikaty HTTPS i klucz adresu .onion; zapisy transakcyjne; migracje.
- `dbcrypto.js` – szyfrowanie bazy: wykrywanie instrukcji CPU, lista szyfrów od najlepszego, wybór automatyczny, klucz (plik / hasło).
- `manifest.js` – manifest (tylko informacje o serwerze + lista plików `content` i `contentVersions`) i pliki `post/<id>.json`.
- `push.js` – rejestracja UnifiedPush (z ochroną przed SSRF) + wysyłka zaszyfrowanych budzików + szum.
- `lep.js` – wbudowany dystrybutor push (LEP: long-poll, kolejka per temat).
- `media.js` – rozpoznawanie formatu obrazu po bajtach (JPG/PNG/WEBP/AVIF/JXL), kontrola MP4 i Opus.
- `convert.js` – konwersja multimediów przez ffmpeg/cjxl (obraz → JXL, film → H.265 + H.264, dźwięk → Opus, miniatura).
- `uploads.js` – obsługa wgrywania multimediów do wpisu (decyzja: zostawić czy skonwertować, limity, metadane).
- `metadata.js` – usuwanie metadanych (EXIF/GPS, XMP, lokalizacja filmu) z wgrywanych plików.
- `e2e.js` – szyfrowanie E2E (ECIES P-256), byte-zgodne z aplikacją. Test: `node e2e.js`.
- `logger.js` – dziennik zdarzeń (zbieranie, bloki, metryki, przeglądanie); `logexport.js` – szyfrowany eksport HTML.
- `update.js` – aktualizacje z GitHub Releases (wybór wydania, pobranie, SHA-256, czytnik ZIP, instalacja, cofnięcie); `zrob-wydanie.mjs` – pakowanie wydania.
- `network.js` – LAN/WAN + menedżer usługi ukrytej Tor.
- `acme.js` – Let's Encrypt (http-01, auto-odnawianie).
- `test-e2e.mjs` – test całości (`npm test`): manifest per adres, obrazy, SSRF, pętla push LEP, edycja/usuwanie.

### Dziennik zdarzeń (zawsze włączony)
Serwer prowadzi szczegółowy dziennik, którego **nie da się wyłączyć** (brak przełącznika, zmiennej i akcji w panelu) ani skasować z panelu.
- **Co zapisuje:** migawkę systemu przy starcie (Node, OpenSSL, SQLite, CPU, pamięć, szyfrowanie, narzędzia), **ruch HTTP** (metoda, klasa trasy, status, czas, bajty, rodzaj hosta — **bez adresów IP, bez nagłówków klientów i bez ścieżek nieznanych tras**). Żądania publiczne (manifest, pliki, media, nieznane trasy) trafiają do dziennika **zbiorczo co minutę** (liczba, średni i największy czas, bajty na trasę i status) — dzięki temu anonimowy klient nie wypchnie z dziennika śladu audytu samymi żądaniami; osobne wpisy mają panel, push, błędy 5xx i 4xx (do 30 na minutę), audyt panelu (logowania udane i nieudane, każda akcja, zmiany haseł/kluczy/szyfrów, aktualizacje, kopie zapasowe, eksporty dziennika), wgrywanie i konwersję multimediów (formaty, rozmiary, koder, czasy), budziki push (same liczby — nigdy adresy subskrybentów), Tor, certyfikaty, **całą konsolę**, błędy z pełnym stosem oraz **co minutę metryki** (pamięć, opóźnienie pętli zdarzeń, procesor, liczniki ruchu, rozmiar bazy). Pola o nazwach sugerujących sekrety są zastępowane „[ukryte]”, z adresów URL obcinane są zapytania, a hasła pokazywane w konsoli przy pierwszym starcie nie trafiają do dziennika.
- **Gdzie i jak:** w tabeli `logs` w bazie danych. Wpisy są zbierane w bloki → **ZSTD poziom 3** → **szyfrowanie zawsze najlepszym szyfrem akcelerowanym przez CPU** (to samo auto-wykrywanie co dla bazy, niezależnie od wybranego szyfru bazy i także gdy baza jest niezaszyfrowana) → gdy baza jest szyfrowana, jeszcze raz szyfrem bazy (czyli dwa razy). Klucz dziennika to osobny klucz pochodny od klucza głównego (HKDF).
- **Odporność na ingerencję:** każdy blok ma numer i skrót SHA-256 liczony z poprzedniego skrótu i zaszyfrowanej zawartości (łańcuch), a numeracja wpisów jest ciągła. Znaczniki czasu bloków są uwierzytelnione razem z zawartością, a uwierzytelniony wiersz bazy przechowuje stan „głowy” łańcucha (ostatni numer i skrót, liczbę przyciętych bloków). „Sprawdź integralność” w panelu wykrywa więc usunięty, podmieniony lub dodany blok, **obcięcie końca, usunięcie całości i usunięcie najstarszych bloków poza przycinaniem** (także gdy serwer zdążył już zapisać nowe wpisy — nieprawidłowość jest zapamiętywana na stałe), oraz uszkodzone szyfrogramy. Przycięcie wg limitu zostawia wpis poziomu security z zakresem usuniętych wpisów. **Uczciwie:** przy kluczu w pliku obok bazy ktoś, kto ma cały katalog `data/`, może przepisać dziennik razem z kluczem — łańcuch chroni wtedy tylko przed przypadkowym uszkodzeniem i niepełną ingerencją; skrót końca łańcucha (widoczny w panelu i w eksporcie) warto zanotować poza serwerem. Eksport obejmuje do 1 000 000 **najnowszych** wpisów (jeśli zakres jest większy, plik to oznacza).
- **Rozmiar:** domyślnie najstarsze bloki są przycinane po przekroczeniu 512 MB albo 365 dni (`LOG_MAX_MB`, `LOG_MAX_DAYS` — dolne granice 16 MB / 30 dni; to jedyne, co można ustawić).
- **Panel:** karta „📜 Dziennik zdarzeń” — przeglądarka z filtrami (poziom, kategoria, tekst), statystyki, sprawdzanie integralności i **eksport do szyfrowanego pliku HTML**: wybierasz zakres (doba / 7 / 30 / 90 dni / całość) i minimalny poziom, podajesz hasło administratora (serwer je sprawdza), a plik zostaje zaszyfrowany **tym samym hasłem** (PBKDF2-SHA-256 600 000 iteracji → AES-256-GCM, dane gzip, bo przeglądarki nie rozpakowują ZSTD). Plik jest samodzielny: otwierasz go w przeglądarce, wpisujesz hasło i dostajesz przeglądarkę z filtrami; nic nie jest wysyłane w sieć. Zmiana hasła administratora później nie zmienia haseł już utworzonych plików.
- Wymaga Node.js **22.15+** (wbudowany ZSTD w `zlib`).

**HTTPS (Let's Encrypt) wymaga pakietu `acme-client`:** w katalogu serwera uruchom `npm install` (instalator dostarcza pełny pakiet Node.js z `npm` i sam doinstaluje `acme-client`; jeśli to się nie uda, zainstaluj go ręcznie (`npm install`) albo użyj reverse proxy z własnym certyfikatem). Bez pakietu panel zgłosi tylko „nie udało się”, a szczegóły są w konsoli i w dzienniku.

**Let's Encrypt bez roota (Linux):** wyzwanie HTTP-01 wymaga portu 80, a zwykły użytkownik nie może go otworzyć (`EACCES`). Nadaj Node.js prawo albo przekieruj port: `sudo setcap 'cap_net_bind_service=+ep' $(which node)` lub `sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 2137`.

### Aktualizacje serwera (GitHub Releases)
Moduł działa jak aktualizacje w aplikacji lewicowYT: panel → „⬆️ Aktualizacje serwera”. Źródło: https://github.com/emmunioo/serwer-referencyjny-lewicowyt (zmienna `UPDATE_REPO` wskazuje inne repozytorium).
- **Sprawdzanie:** przy starcie (po ~2 min) i co ok. 12 h w tle (włączone domyślnie, **a gdy włączony jest Tor — domyślnie wyłączone**; zmienisz w panelu) oraz przyciskiem „Sprawdź teraz”. To jedyne zapytanie serwera do GitHuba i ujawnia GitHubowi adres IP tego komputera — przy serwerze tylko na Torze możesz je wyłączyć. Wybierane jest **najnowsze wydanie nowsze od bieżącej wersji**; wersje wstępne (`-beta`, `-rc`) widzą tylko serwery w wersji wstępnej; szkice są pomijane; aktualizacja „wymagana” tylko po jawnym markerze `[security-mandatory]` w opisie wydania.
- **Instalacja jest zawsze ręczna** (przycisk + hasło administratora). Serwer pobiera paczkę `.zip` **wyłącznie z github.com** (tego repozytorium), sprawdza rozmiar i **skrót SHA-256 podany przez GitHub** (wydanie bez skrótu jest ignorowane), rozpakowuje własnym czytnikiem (bez ścieżek wychodzących, dowiązań i bomb kompresji), sprawdza, że `package.json` w paczce ma tę samą wersję co wydanie, robi kopię zastępowanych plików w `data/aktualizacje/` i podmienia pliki. Katalogi `data/`, `tools/`, `engine*/` i `node_modules/` nigdy nie są ruszane. Błąd w trakcie = automatyczny powrót do poprzednich plików.
- **Restart:** po instalacji serwer kończy się kodem 75, a `start.bat` / `start.sh` uruchamiają go ponownie w tym samym oknie (przy trybie z hasłem do bazy zapyta o nie jak zwykle). Pod innym menedżerem (np. systemd z `Restart=always`) ustaw `LEWICOWYT_SUPERVISED=1`; bez tego panel poprosi o ręczne uruchomienie ponownie.
- **Cofnięcie:** przycisk „Cofnij ostatnią aktualizację” przywraca pliki z kopii (trzymane są 3 ostatnie).
- **Dla autora wydań:** `node zrob-wydanie.mjs` tworzy `serwer-lewicowyt-<wersja>.zip` (bez `data/`, `tools/`, testów); opublikuj wydanie GitHub o tagu `v<wersja>` zgodnym z `package.json` i dołącz ten plik. Jeśli zmieniły się zależności (`node_modules`) albo wersja Node.js, napisz o tym w opisie wydania — aktualizator ich nie instaluje.

### Szyfrowanie bazy danych (domyślnie włączone)
Każda wartość w bazie (wpis, konfiguracja, subskrybent, certyfikat, klucz .onion, kawałek pliku multimedialnego) jest szyfrowana i
uwierzytelniana — podmiana albo przestawienie danych w pliku bazy zostanie wykryte. Jawne zostają tylko identyfikatory wpisów, nazwy plików i rozmiary.

**Wybór szyfru — od najlepszego do najgorszego.** Serwer sprawdza procesor (Linux: `/proc/cpuinfo`, macOS: `sysctl`, Windows:
`IsProcessorFeaturePresent` / PowerShell 7) i testuje szybkość, a potem bierze pierwszy szyfr z listy, który CPU faktycznie przyspiesza:

| # | Szyfr | Przyspieszenie sprzętowe |
|---|---|---|
| 1 | AES-256-GCM | AES-NI (x86) / AES (ARM) + PCLMULQDQ / PMULL |
| 2 | AES-256-OCB | AES-NI (x86) / AES (ARM) |
| 3 | AES-256-CTR + HMAC-SHA-256 | AES-NI / AES; SHA-NI / SHA2 przyspiesza MAC |
| — | AES-128-GCM | jak #1 (tylko wybór ręczny) |
| 4 | ChaCha20-Poly1305 | brak wymagań — programowy (SSE2/AVX2/NEON, jeśli są); zapas, gdy CPU nie ma AES |

Szyfrowanie wykonuje OpenSSL wbudowany w Node.js, który sam używa instrukcji CPU. Kod serwera decyduje, **który** algorytm wybrać,
i pilnuje, żeby nie wybrać szyfru, który na tym komputerze byłby tylko programowy (albo wolny, np. fałszywe „AES-NI” w maszynie wirtualnej).
Wynik wyboru jest zapamiętany dla danego procesora (`data/szyfrowanie.json`) i sprawdzany ponownie po zmianie procesora lub Node.js.

**Zmiana szyfru:** panel → „🔐 Szyfrowanie bazy danych” (tabela szyfrów z oznaczeniem przyspieszenia CPU i pomiarem MB/s; „Automatycznie” jest
domyślne) albo zmienna `DB_CIPHER` (`auto`, `aes-256-gcm`, `aes-256-ocb`, `aes-256-ctr+hmac-sha256`, `aes-128-gcm`, `chacha20-poly1305`,
`none`). Zmiana szyfru przepisuje całą bazę na nowy (kilka sekund przy dużych plikach). Wyłączenie szyfrowania (`none`) wymaga w panelu
potwierdzenia i hasła administratora.

**Klucz:** domyślnie losowy klucz 256-bit w pliku `data/klucz-bazy.key` (utworzony przy pierwszym starcie) — chroni przed skopiowaniem
samego pliku `serwer.db`. **Zrób kopię tego pliku**: bez niego bazy nie da się odzyskać, a serwer celowo nie tworzy nowego klucza, gdy baza już istnieje.
Mocniejsza ochrona (także przy przejęciu całego dysku): w panelu „Chroń kluczem z hasła” — serwer **losuje nowy klucz główny i przepisuje całą bazę** (stary klucz, także z wcześniejszych kopii pliku, przestaje ją otwierać), nowy klucz jest szyfrowany Twoim hasłem
(scrypt), a plik klucza zostaje nadpisany i usunięty (na SSD i w migawkach dysku nie ma gwarancji wymazania). W tym trybie wyłączenie szyfrowania (`cipher`: `none`, także przez edycję `szyfrowanie.json`) jest ignorowane. **Zrób kopię `klucz-bazy.haslo.json` i `szyfrowanie.json`** (zamiast `klucz-bazy.key`) — bez opakowanego klucza hasło nic nie da; serwer odtworzy tryb hasła z `klucz-bazy.haslo.json`, gdy `szyfrowanie.json` zniknie; przy starcie serwer pyta o hasło w konsoli albo bierze je ze zmiennej `DB_PASSPHRASE` / pliku `DB_PASSPHRASE_FILE`.
Klucz można też podać zmienną `DB_KEY` (64 znaki hex) lub wskazać plik zmienną `DB_KEY_FILE`.

**Czego to nie obejmuje (uczciwie):** kopia zapasowa pobierana z panelu to zwykły, jawny plik JSON — chroń go sam; w trakcie konwersji
multimediów ffmpeg używa tymczasowych plików w `data/tmp/` (usuwanych po zakończeniu, a pozostałości po awarii przy starcie; to **jawne** kopie oryginałów, więc chroń ten katalog — albo wskaż `DATA_DIR` na zaszyfrowany wolumen);
jawny klucz usługi `.onion` leży w `data/tor/hs/` tylko podczas pracy Tora (przy zamknięciu serwera pliki kluczy są niszczone, a odtwarzane z bazy przy starcie — po awarii procesu mogą zostać); klucz w pliku obok bazy nie zabezpiecza przed kimś,
kto ma dostęp do całego katalogu `data/`; pamięć działającego procesu zawiera dane jawne.

### Wszystko w bazie danych, dla aplikacji każdy wpis to osobny plik
- **W bazie:** cały serwer siedzi w jednym pliku `data/serwer.db` (SQLite, tryb WAL; obok mogą leżeć `serwer.db-wal` i `serwer.db-shm`) — szyfrowanym.
  Tabele: `meta` (konfiguracja, regulamin, usunięcia, skrót hasła, ustawienia push), `items` (wiersz na wpis: post, mem, artykuł…),
  `subscribers` (subskrybenci push), `media` + `media_chunks` (obrazy, audio i filmy jako zaszyfrowane kawałki po 1 MiB) oraz `files` (certyfikaty HTTPS, klucz usługi ukrytej Tora).
  Zapisywane są tylko zmiany, w transakcjach. Na dysku poza bazą zostaje tylko to, co musi: katalog roboczy Tora (`tor/`).
  Wymagany jest Node.js **22.15 lub nowszy** (moduły `node:sqlite` i ZSTD w `zlib`); instalator pobiera aktualny.
- **Migracja:** jeśli w `data/` leży układ sprzed bazy (`data.json`, `post/`, `media/`, `cert/`, `tor/hs/`), serwer przy starcie wczytuje go do
  bazy, a stare pliki **odkłada** (nie kasuje) do `data/stare-przed-baza/` — po sprawdzeniu możesz ten katalog usunąć.
- **Dla aplikacji:** `manifest.json` jest **absolutnie minimalny**: niesie wyłącznie konfigurację serwera (nazwa, opis,
  regulamin, push, możliwości) i pole `content` — listę plików, **po jednym na wpis**: `post/<id>.json` — oraz
  `contentVersions` (plik → wersja). Nie ma w nim żadnej treści ani listy usunięć: usunięcia leżą w osobnym pliku
  `post/usuniecia.json` (ostatni na liście, gdy jest co usuwać). Dzięki temu skrót (SHA-256/ETag) manifestu zmienia się
  tylko wtedy, gdy zmienia się lista plików albo ich wersje. Każdy plik zawiera jeden wpis, np. `{"posts":[{…}]}`. Po edycji (albo
  zmianie obrazów) wpis dostaje wyższą wersję, a aplikacja pobiera **ten sam plik** ponownie i podmienia
  treść. Limit protokołu: 10 000 plików (najstarsze odpadają).
- **Edycja wpisów:** w panelu (pliki `post/<id>.json` są składane z bazy przy każdym żądaniu aplikacji).
- **Usunięcie wpisu:** jego plik znika z `content`, więc aplikacja kasuje wpis u siebie — także wpis bez
  linku (ulubione zostają; ulubione kasuje dopiero lista usunięć `post/usuniecia.json`, czyli wpisy z linkiem https albo `/e/<id>`).
- Wersje i usuwanie przez zdjęcie z listy rozumie aplikacja od tej wersji. Starsze wersje aplikacji
  pobiorą każdy plik raz i nie zauważą edycji ani usunięć (poza `deletions`).

Dane i media siedzą w `data/serwer.db` — żeby przenieść serwer, zatrzymaj go i skopiuj **`serwer.db` razem z `klucz-bazy.key` i `szyfrowanie.json`** (albo użyj „Kopia zapasowa” w panelu).
Inne miejsce na dane ustawisz zmienną `DATA_DIR`. Dane ze starszej wersji (jeden obraz na wpis) są przenoszone automatycznie przy starcie.
