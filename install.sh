#!/bin/sh
# Instalator ONLINE serwera spolecznosci lewicowYT (Linux/macOS), POSIX sh.
#
# Co robi:
#   0) sanityzacja: usuwa/odklada pozostalosci po komputerze autora (baza, klucz, cache CPU, martwy .enginepath, tmp);
#   1) bada 6 komponentow NIEZALEZNIE:  Node.js(>=22.15)+npm | Tor | FFmpeg | FFprobe | cjxl | acme-client (npm);
#   2) pobiera/instaluje TYLKO te, ktorych brakuje (kazdy pobrany plik jest weryfikowany SHA-256);
#   3) na koniec ponownie sprawdza wszystkie 6.
#
# Uzycie:   sh install.sh [--clean] [--yes] [--check-only]
#   zmienne: MODE=local|system|ask (domyslnie local)   TOR=yes|no|ask (domyslnie yes)   CLEAN=0|1   YES=0|1   CHECK_ONLY=0|1
#   --clean       przywraca data/ do stanu fabrycznego (dane NAJPIERW trafiaja do kopii data/_kopia-<data>)
#   --yes         nie pytaj o potwierdzenie przy --clean
#   --check-only  tylko sanityzacja i raport (nic nie pobiera) — do testow
#
# NOTA DLA AUDYTOROW: wszystkie adresy sa stale i pochodza od oficjalnych dostawcow (nodejs.org, dist.torproject.org,
# github.com/BtbN, github.com/libjxl, registry.npmjs.org). Kazdy plik binarny ma sume SHA-256 (z listy dostawcy albo
# przypieta ponizej dla niezmiennego wydania). Podpisow GPG nie sprawdzamy — zrob to recznie, jesli masz gpg.
# Dla macOS oraz Linux arm64 nie ma zweryfikowalnych oficjalnych binarek FFmpeg/cjxl — instalator wtedy tylko podpowiada
# pakiet systemowy (brew / apt), zamiast pobierac pliki z nieweryfikowalnych zrodel.
set -u
cd "$(dirname "$0")" || exit 1
ROOT="$(pwd)"
DATA="$ROOT/data"
ENGINE_DIR="$ROOT/engine"
ENGINE_PATH_FILE="$ROOT/.enginepath"
TOR_DIR="$ROOT/engine-tor"
TOOLS_DIR="$ROOT/tools"
MODE="${MODE:-local}"
TOR="${TOR:-yes}"
CLEAN="${CLEAN:-0}"
YES="${YES:-0}"
CHECK_ONLY="${CHECK_ONLY:-0}"
for a in "$@"; do
  case "$a" in
    --clean) CLEAN=1 ;;
    --yes) YES=1 ;;
    --check-only) CHECK_ONLY=1 ;;
    *) echo "Nieznany parametr: $a" >&2; exit 2 ;;
  esac
done

MIN_NODE="22.15.0"
DEV_KEY="qcdOqgKJm8B4wyG+KLKDoPzBofeNLLZSn89ZEBRKImw="   # klucz bazy z komputera autora
NODE_INDEX="https://nodejs.org/dist/latest-v24.x/"        # linia LTS 24 (>= 22.15)
TOR_INDEX="https://dist.torproject.org/torbrowser/"
BTBN="https://github.com/BtbN/FFmpeg-Builds/releases/latest/download/"
# cjxl: niezmienne wydanie libjxl; suma SHA-256 przypieta (zgodna z polem digest w GitHub Releases)
CJXL_LINUX_X64_URL="https://github.com/libjxl/libjxl/releases/download/v0.11.2/jxl-linux-x86_64-static.zip"
CJXL_LINUX_X64_SHA="f8f8c031881d4a76845d3b3482a4e0138bb017568dc76d33abd79d24856a4dec"

if [ -t 1 ]; then C_OK="$(printf '\033[32m')"; C_WARN="$(printf '\033[33m')"; C_ERR="$(printf '\033[31m')"; C_INFO="$(printf '\033[36m')"; C_OFF="$(printf '\033[0m')"
else C_OK=""; C_WARN=""; C_ERR=""; C_INFO=""; C_OFF=""; fi
info() { printf '%s%s%s\n' "$C_INFO" "$*" "$C_OFF"; }
ok() { printf '%s%s%s\n' "$C_OK" "$*" "$C_OFF"; }
warn() { printf '%s%s%s\n' "$C_WARN" "$*" "$C_OFF" >&2; }
fail() { printf '%s%s%s\n' "$C_ERR" "$*" "$C_OFF" >&2; }

TMP_LIST=""
cleanup() { for t in $TMP_LIST; do rm -rf "$t"; done; }
trap cleanup EXIT INT TERM
mktmp() { t="$(mktemp -d 2>/dev/null || mktemp -d -t lewicowyt)"; TMP_LIST="$TMP_LIST $t"; echo "$t"; }

# ------------------------------------------------------------------------------------------------------------------
# pomocnicze
# ------------------------------------------------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
run_ok() { "$@" >/dev/null 2>&1; }
fetch() { if have curl; then curl -fsSL --retry 3 "$1"; elif have wget; then wget -qO- "$1"; else fail "Brak curl i wget — nie moge pobierac."; return 1; fi; }
dl() { # dl URL DEST
  info "Pobieram: $1"
  if have curl; then curl -fSL --retry 3 -o "$2" "$1"; elif have wget; then wget -O "$2" "$1"; else fail "Brak curl i wget."; return 1; fi
}
sha256_of() { if have sha256sum; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
find_sha() { # find_sha NAME < lista "<hash>  <nazwa>"
  awk -v n="$1" '{ f=$2; sub(/^\*/, "", f); if (f == n) { print tolower($1); exit } }'
}
assert_sha() { # assert_sha FILE EXPECTED
  act="$(sha256_of "$1")"
  if [ "$act" != "$2" ]; then fail "Suma SHA-256 sie nie zgadza ($(basename "$1")) — plik usuniety. Oczekiwano $2, jest $act."; rm -f "$1"; return 1; fi
  ok "Suma SHA-256 zgodna."
}
extract_zip() { # extract_zip ZIP DESTDIR
  mkdir -p "$2"
  if have unzip; then unzip -qo "$1" -d "$2"
  elif have bsdtar; then bsdtar -xf "$1" -C "$2"
  elif have python3; then python3 -m zipfile -e "$1" "$2"
  else fail "Brak unzip/bsdtar/python3 — nie moge rozpakowac ZIP."; return 1; fi
}
ver_ge() { # ver_ge A B  -> 0, gdy A >= B (liczbowo, x.y.z)
  a1="${1%%.*}"; r="${1#*.}"; a2="${r%%.*}"; a3="${r#*.}"; a3="${a3%%[!0-9]*}"
  b1="${2%%.*}"; r="${2#*.}"; b2="${r%%.*}"; b3="${r#*.}"; b3="${b3%%[!0-9]*}"
  for p in 1 2 3; do eval "x=\${a$p:-0}; y=\${b$p:-0}"; [ "$x" -gt "$y" ] && return 0; [ "$x" -lt "$y" ] && return 1; done
  return 0
}
OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS" in Linux) OSK=linux ;; Darwin) OSK=darwin ;; *) OSK=other ;; esac
case "$ARCH" in x86_64|amd64) ARCHK=x64 ;; aarch64|arm64) ARCHK=arm64 ;; *) ARCHK=other ;; esac
if [ "$OSK" = linux ] && have ldd && ldd --version 2>&1 | grep -qi musl; then
  warn "Wykryto musl (np. Alpine): oficjalne buildy Node.js/Tora/FFmpeg wymagaja glibc — instalacja binarek sie nie uda."
fi

# ------------------------------------------------------------------------------------------------------------------
# KROK 0: sanityzacja pozostalosci po komputerze autora
# ------------------------------------------------------------------------------------------------------------------
sanitize() {
  info "== Krok 0: sanityzacja plikow =="
  key_file="$DATA/klucz-bazy.key"
  is_dev=0
  [ -f "$key_file" ] && grep -qF "$DEV_KEY" "$key_file" && is_dev=1
  do_wipe=0
  if [ "$is_dev" = 1 ]; then
    warn "Wykryto deweloperski klucz bazy z komputera autora — baza i klucze zostana odlozone do kopii."
    do_wipe=1
  elif [ "$CLEAN" = 1 ]; then
    if [ "$YES" = 1 ]; then do_wipe=1
    else
      warn "--clean przywroci data/ do stanu fabrycznego (baza, klucze, ustawienia szyfrowania). Dane trafia najpierw do kopii data/_kopia-<data>."
      printf 'Wpisz TAK, aby kontynuowac: '; read -r ans
      if [ "$ans" = "TAK" ]; then do_wipe=1; else warn "Pominieto czyszczenie danych."; fi
    fi
  elif [ -f "$key_file" ]; then
    ok "Klucz bazy jest wlasny (serwer juz tu dzialal) — baza i klucz zostaja nietkniete."
  fi

  if [ "$do_wipe" = 1 ] && [ -d "$DATA" ]; then
    backup="$DATA/_kopia-$(date +%Y%m%d-%H%M%S)"
    moved=0
    for n in serwer.db serwer.db-shm serwer.db-wal klucz-bazy.key klucz-bazy.haslo.json szyfrowanie.json tor; do
      if [ -e "$DATA/$n" ]; then mkdir -p "$backup"; mv "$DATA/$n" "$backup/"; moved=1; fi
    done
    [ "$moved" = 1 ] && ok "Odlozono do: $backup  (mozesz usunac ten katalog, jesli to dane autora). Serwer przy starcie utworzy wlasny klucz, baze i haslo administratora."
  fi

  # B) szyfrowanie.json: zerujemy cache szybkosci szyfrow z cudzego CPU (serwer policzy go od nowa); reszta zostaje
  enc="$DATA/szyfrowanie.json"
  if [ -f "$enc" ] && grep -q '"autoCache"[[:space:]]*:[[:space:]]*{' "$enc"; then
    t="$(mktemp)"
    awk '
      skip == 0 && /"autoCache"[[:space:]]*:[[:space:]]*\{/ {
        match($0, /^[[:space:]]*/); ind = substr($0, 1, RLENGTH); skip = 1; depth = 0
      }
      skip == 1 {
        n = gsub(/\{/, "{"); m = gsub(/\}/, "}"); depth += n - m
        if (depth <= 0) { printf "%s\"autoCache\": null%s\n", ind, ($0 ~ /\},[[:space:]]*$/ ? "," : ""); skip = 2 }
        next
      }
      { print }
    ' "$enc" > "$t" && [ -s "$t" ] && cat "$t" > "$enc"
    rm -f "$t"
    ok "Wyczyszczono cache procesora w data/szyfrowanie.json (serwer ustali go ponownie)."
  fi

  # C) martwy .enginepath
  if [ -f "$ENGINE_PATH_FILE" ]; then
    p="$(head -n 1 "$ENGINE_PATH_FILE" | tr -d '\r')"
    if [ -z "$p" ] || [ ! -f "$p" ] || ! run_ok "$p" -v; then
      rm -f "$ENGINE_PATH_FILE"; warn "Usunieto martwy plik .enginepath (wskazywal: $p)."
    fi
  fi

  # D) pliki tymczasowe i niedokonczone pobrania
  [ -d "$DATA/tmp" ] && find "$DATA/tmp" -mindepth 1 -exec rm -rf {} + 2>/dev/null
  [ -d "$DATA" ] && find "$DATA" -maxdepth 1 -type f -name '*.tmp' -exec rm -f {} + 2>/dev/null
  return 0
}

# ------------------------------------------------------------------------------------------------------------------
# Wykrywanie komponentow (kolejnosc i polecenia jak w kodzie serwera: convert.js, network.js, acme.js)
# ------------------------------------------------------------------------------------------------------------------
NODE_BIN=""; NODE_VER=""; NPM_BIN=""; TOR_BIN=""; FFMPEG_BIN=""; FFPROBE_BIN=""; CJXL_BIN=""; ACME_OK=0

TOO_OLD=""
try_node() { # try_node SCIEZKA -> ustawia NODE_BIN/NODE_VER, gdy dziala i wersja >= MIN_NODE
  c="$1"
  [ -n "$c" ] && [ -x "$c" ] || return 1
  v="$("$c" -p "process.versions.node" 2>/dev/null)" || return 1
  if ver_ge "$v" "$MIN_NODE"; then NODE_BIN="$c"; NODE_VER="$v"; return 0; fi
  TOO_OLD="$c ($v)"
  return 1
}
find_node() {
  NODE_BIN=""; NODE_VER=""; TOO_OLD=""
  if [ -f "$ENGINE_PATH_FILE" ]; then try_node "$(head -n 1 "$ENGINE_PATH_FILE" | tr -d '')" && return 0; fi
  try_node "$ENGINE_DIR/bin/node" && return 0
  try_node "$(command -v node 2>/dev/null || true)" && return 0
  [ -n "$TOO_OLD" ] && warn "Znaleziony Node.js jest za stary (wymagany >= $MIN_NODE): $TOO_OLD"
  return 1
}
find_npm() {
  NPM_BIN=""
  [ -n "$NODE_BIN" ] || return 1
  d="$(dirname "$NODE_BIN")"
  if [ -x "$d/npm" ]; then NPM_BIN="$d/npm"; return 0; fi
  if have npm; then NPM_BIN="$(command -v npm)"; return 0; fi
  return 1
}
find_tor() {
  TOR_BIN=""
  for c in "${TOR_BINARY:-}" "$TOR_DIR/tor/tor"; do
    [ -n "$c" ] && [ -x "$c" ] && run_ok "$c" --version && { TOR_BIN="$c"; return 0; }
  done
  have tor && run_ok tor --version && { TOR_BIN="$(command -v tor)"; return 0; }
  return 1
}
find_tool() { # find_tool VARNAME ENVVAR FILE TESTARG EXTRADIR
  eval "$1=''"
  eval "ev=\${$2:-}"
  for c in "$ev" "${5:+$5/$3}" "$TOOLS_DIR/$3"; do
    [ -n "$c" ] && [ -x "$c" ] && run_ok "$c" "$4" && { eval "$1=\$c"; return 0; }
  done
  have "$3" && run_ok "$3" "$4" && { eval "$1=\$(command -v \"$3\")"; return 0; }
  return 1
}
test_acme() {
  [ -n "$NODE_BIN" ] || return 1
  (cd "$ROOT" && "$NODE_BIN" -e "import('acme-client').then(()=>process.exit(0)).catch(()=>process.exit(1))" >/dev/null 2>&1)
}
detect_all() {
  find_node; find_npm; find_tor
  find_tool FFMPEG_BIN FFMPEG_PATH ffmpeg -version ""
  ffd=""; [ -n "$FFMPEG_BIN" ] && ffd="$(dirname "$FFMPEG_BIN")"
  find_tool FFPROBE_BIN FFPROBE_PATH ffprobe -version "$ffd"
  find_tool CJXL_BIN CJXL_PATH cjxl --version ""
  ACME_OK=0; test_acme && ACME_OK=1
  return 0
}
report_line() { # report_line LABEL OK DETAIL
  if [ "$2" = 1 ]; then ok "[OK]   Juz zainstalowano: $1${3:+ — $3}"; else warn "[BRAK] Do zainstalowania: $1"; fi
}
report() {
  info "== Stan komponentow =="
  n=0; [ -n "$NODE_BIN" ] && [ -n "$NPM_BIN" ] && n=1
  report_line "Node.js >= $MIN_NODE + npm" "$n" "$NODE_VER, $NODE_BIN"
  [ -n "$NODE_BIN" ] && [ -z "$NPM_BIN" ] && warn "       (Node.js jest, ale brakuje npm — zostanie zainstalowany pelny pakiet silnika)"
  report_line "Tor (Tor Expert Bundle)" "$([ -n "$TOR_BIN" ] && echo 1 || echo 0)" "$TOR_BIN"
  report_line "FFmpeg" "$([ -n "$FFMPEG_BIN" ] && echo 1 || echo 0)" "$FFMPEG_BIN"
  report_line "FFprobe" "$([ -n "$FFPROBE_BIN" ] && echo 1 || echo 0)" "$FFPROBE_BIN"
  report_line "cjxl (koder JPEG XL)" "$([ -n "$CJXL_BIN" ] && echo 1 || echo 0)" "$CJXL_BIN"
  report_line "Biblioteka npm acme-client" "$ACME_OK" "$([ "$ACME_OK" = 1 ] && echo node_modules/acme-client)"
}

# ------------------------------------------------------------------------------------------------------------------
# Instalacja brakujacych komponentow
# ------------------------------------------------------------------------------------------------------------------
install_node() {
  [ "$OSK" != other ] && [ "$ARCHK" != other ] || { fail "Nieobslugiwana platforma ($OS/$ARCH)."; return 1; }
  plat="$OSK-$ARCHK"
  sums="$(fetch "${NODE_INDEX}SHASUMS256.txt")" || return 1
  file="$(printf '%s\n' "$sums" | grep -oE "node-v[0-9]+\.[0-9]+\.[0-9]+-$plat\.tar\.gz" | head -n 1)"
  [ -n "$file" ] || { fail "Nie znalazlem buildu Node.js dla $plat."; return 1; }
  ver="$(printf '%s' "$file" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+')"
  expected="$(printf '%s\n' "$sums" | find_sha "$file")"
  [ -n "$expected" ] || { fail "Brak sumy SHA-256 dla $file."; return 1; }
  stage="$(mktmp)"
  dl "https://nodejs.org/dist/$ver/$file" "$stage/node.tar.gz" || return 1
  assert_sha "$stage/node.tar.gz" "$expected" || return 1
  mkdir -p "$stage/x" && tar -xzf "$stage/node.tar.gz" -C "$stage/x" --strip-components=1 || { fail "Rozpakowanie Node.js nie powiodlo sie."; return 1; }
  [ -x "$stage/x/bin/node" ] || { fail "Archiwum Node.js ma nieoczekiwana strukture."; return 1; }
  if [ "$MODE" = system ]; then target="$HOME/.local/lewicowyt-engine"; else target="$ENGINE_DIR"; fi
  rm -rf "$target"; mkdir -p "$(dirname "$target")"; mv "$stage/x" "$target"
  if [ "$MODE" = system ]; then
    mkdir -p "$HOME/.local/bin"; ln -sf "$target/bin/node" "$HOME/.local/bin/node" 2>/dev/null || true
    printf '%s\n' "$target/bin/node" > "$ENGINE_PATH_FILE"
    case ":$PATH:" in *":$HOME/.local/bin:"*) : ;; *) warn "Dodaj do PATH:  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;; esac
    ok "Node.js $ver zainstalowany SYSTEMOWO: $target/bin/node"
  else
    rm -f "$ENGINE_PATH_FILE"
    ok "Node.js $ver zainstalowany LOKALNIE: $target/bin/node (uzywany tylko przez ten serwer)"
  fi
}

install_tor() {
  case "$OSK" in linux) tos=linux ;; darwin) tos=macos ;; *) fail "Nieobslugiwana platforma dla Tora."; return 1 ;; esac
  case "$ARCHK" in x64) tarch=x86_64 ;; arm64) tarch=aarch64 ;; *) fail "Nieobslugiwana architektura dla Tora."; return 1 ;; esac
  # Najnowszy katalog wydan bywa niepelny (np. tylko paczki na Androida), wiec idziemy od najwyzszej wersji w dol
  # i bierzemy pierwsza, ktorej lista sum zawiera paczke dla tej platformy.
  vers="$(fetch "$TOR_INDEX" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?/' | tr -d / | sort -u | sort -t. -k1,1nr -k2,2nr -k3,3nr | head -n 8)"
  [ -n "$vers" ] || { fail "Nie udalo sie odczytac listy wersji Tora."; return 1; }
  for ver in $vers; do
    name="tor-expert-bundle-$tos-$tarch-$ver.tar.gz"
    sums="$(fetch "$TOR_INDEX$ver/sha256sums-signed-build.txt" 2>/dev/null)" || continue
    expected="$(printf '%s\n' "$sums" | find_sha "$name")"
    [ -n "$expected" ] || continue
    stage="$(mktmp)"
    dl "$TOR_INDEX$ver/$name" "$stage/tor.tar.gz" || return 1
    assert_sha "$stage/tor.tar.gz" "$expected" || return 1
    mkdir -p "$TOR_DIR" && tar -xzf "$stage/tor.tar.gz" -C "$TOR_DIR" || { fail "Rozpakowanie Tora nie powiodlo sie."; return 1; }
    [ -f "$TOR_DIR/tor/tor" ] && chmod +x "$TOR_DIR/tor/tor" 2>/dev/null
    [ -x "$TOR_DIR/tor/tor" ] && { ok "Tor $ver gotowy: $TOR_DIR/tor/tor"; return 0; }
    fail "Rozpakowano Tora, ale nie ma tor/tor w $TOR_DIR."; return 1
  done
  fail "Nie znalazlem paczki Tor Expert Bundle dla $tos/$tarch w ostatnich wydaniach."; return 1
}

install_ffmpeg() { # install_ffmpeg NEED_FFMPEG NEED_FFPROBE
  if [ "$OSK" != linux ] || [ "$ARCHK" = other ]; then
    warn "Brak zweryfikowalnego oficjalnego pliku FFmpeg dla $OS/$ARCH. Zainstaluj z menedzera pakietow:"
    [ "$OSK" = darwin ] && warn "  brew install ffmpeg" || warn "  sudo apt install ffmpeg   (albo odpowiednik Twojej dystrybucji)"
    return 1
  fi
  have xz || { fail "Brak narzedzia xz — zainstaluj (np. 'sudo apt install xz-utils') i uruchom instalator ponownie."; return 1; }
  if [ "$ARCHK" = x64 ]; then name="ffmpeg-master-latest-linux64-gpl.tar.xz"; else name="ffmpeg-master-latest-linuxarm64-gpl.tar.xz"; fi
  sums="$(fetch "${BTBN}checksums.sha256")" || return 1
  expected="$(printf '%s\n' "$sums" | find_sha "$name")"
  [ -n "$expected" ] || { fail "Brak sumy SHA-256 dla $name."; return 1; }
  stage="$(mktmp)"
  dl "$BTBN$name" "$stage/ff.tar.xz" || return 1
  assert_sha "$stage/ff.tar.xz" "$expected" || return 1
  mkdir -p "$stage/x" && tar -xJf "$stage/ff.tar.xz" -C "$stage/x" || { fail "Rozpakowanie FFmpeg nie powiodlo sie."; return 1; }
  mkdir -p "$TOOLS_DIR"; copied=0
  # kopiujemy TYLKO brakujace binarki — dzialajacej nie nadpisujemy
  if [ "$1" = 1 ]; then f="$(find "$stage/x" -type f -path '*/bin/ffmpeg' | head -n 1)"; [ -n "$f" ] && [ ! -e "$TOOLS_DIR/ffmpeg" ] && cp "$f" "$TOOLS_DIR/ffmpeg" && chmod +x "$TOOLS_DIR/ffmpeg" && copied=1; fi
  if [ "$2" = 1 ]; then f="$(find "$stage/x" -type f -path '*/bin/ffprobe' | head -n 1)"; [ -n "$f" ] && [ ! -e "$TOOLS_DIR/ffprobe" ] && cp "$f" "$TOOLS_DIR/ffprobe" && chmod +x "$TOOLS_DIR/ffprobe" && copied=1; fi
  [ "$copied" = 1 ] || { fail "W archiwum FFmpeg nie znalazlem brakujacych programow (albo pliki w tools/ juz istnieja, ale nie dzialaja — usun je)."; return 1; }
  ok "FFmpeg/FFprobe skopiowane do $TOOLS_DIR"
}

install_cjxl() {
  if [ "$OSK" != linux ] || [ "$ARCHK" != x64 ]; then
    warn "Brak oficjalnego, zweryfikowalnego pliku cjxl dla $OS/$ARCH. Zainstaluj z menedzera pakietow:"
    [ "$OSK" = darwin ] && warn "  brew install jpeg-xl" || warn "  sudo apt install libjxl-tools   (albo odpowiednik Twojej dystrybucji)"
    return 1
  fi
  stage="$(mktmp)"
  dl "$CJXL_LINUX_X64_URL" "$stage/jxl.zip" || return 1
  assert_sha "$stage/jxl.zip" "$CJXL_LINUX_X64_SHA" || return 1
  extract_zip "$stage/jxl.zip" "$stage/x" || return 1
  f="$(find "$stage/x" -type f -name cjxl | head -n 1)"
  [ -n "$f" ] || { fail "W archiwum libjxl nie ma cjxl."; return 1; }
  mkdir -p "$TOOLS_DIR"; cp "$f" "$TOOLS_DIR/cjxl"; chmod +x "$TOOLS_DIR/cjxl"
  ok "cjxl skopiowany do $TOOLS_DIR/cjxl"
}

install_acme() {
  [ -n "$NODE_BIN" ] || { fail "Brak dzialajacego Node.js — pomijam acme-client."; return 1; }
  [ -n "$NPM_BIN" ] || { fail "Brak npm — nie mozna zainstalowac acme-client."; return 1; }
  info "npm install acme-client@^5.4.0 ..."
  # --no-save: nie zmieniamy package.json (acme-client jest tam juz jako optionalDependency)
  (cd "$ROOT" && PATH="$(dirname "$NODE_BIN"):$PATH" "$NPM_BIN" install --no-audit --no-fund --no-save "acme-client@^5.4.0") || { fail "npm install zakonczyl sie bledem."; return 1; }
  test_acme || { fail "acme-client zainstalowany, ale import() nie dziala."; return 1; }
  ok "Biblioteka acme-client zainstalowana."
}

# ------------------------------------------------------------------------------------------------------------------
# PRZEBIEG
# ------------------------------------------------------------------------------------------------------------------
info "== Instalator serwera spolecznosci lewicowYT (Linux/macOS) =="
sanitize
detect_all
report
if [ "$CHECK_ONLY" = 1 ]; then info "Tryb --check-only: koniec (nic nie pobrano)."; exit 0; fi

node_ok=0; [ -n "$NODE_BIN" ] && [ -n "$NPM_BIN" ] && node_ok=1
if [ "$node_ok" = 1 ] && [ -n "$TOR_BIN" ] && [ -n "$FFMPEG_BIN" ] && [ -n "$FFPROBE_BIN" ] && [ -n "$CJXL_BIN" ] && [ "$ACME_OK" = 1 ]; then
  ok "Wszystkie wymagane biblioteki i narzedzia sa juz zainstalowane. Nic nie trzeba pobierac!"
  exit 0
fi

if [ "$MODE" = ask ] && [ "$node_ok" = 0 ]; then
  say_ask="Jak zainstalowac Node.js?  [L] LOKALNIE (./engine, nic nie zmienia w systemie)  [S] SYSTEMOWO (~/.local)"
  echo; echo "$say_ask"; printf 'Wybierz L lub S: '; read -r ans
  case "$ans" in [Ss]*) MODE=system ;; *) MODE=local ;; esac
fi
if [ "$TOR" = ask ] && [ -z "$TOR_BIN" ]; then
  printf 'Pobrac Tora (adres .onion, omija CGNAT)? [T]ak / [N]ie: '; read -r ans
  case "$ans" in [TtYy]*) TOR=yes ;; *) TOR=no ;; esac
fi

if [ "$node_ok" = 0 ]; then install_node || fail "Node.js: instalacja nie powiodla sie."; fi
if [ -z "$TOR_BIN" ]; then
  if [ "$TOR" = yes ]; then install_tor || warn "Tor: instalacja nie powiodla sie — mozesz uzyc wlasnego Tora (wpis torrc w panelu)."
  else warn "Pomijam Tora (TOR=no)."; fi
fi
need_ffmpeg=0; need_ffprobe=0; [ -z "$FFMPEG_BIN" ] && need_ffmpeg=1; [ -z "$FFPROBE_BIN" ] && need_ffprobe=1
if [ "$need_ffmpeg" = 1 ] || [ "$need_ffprobe" = 1 ]; then install_ffmpeg "$need_ffmpeg" "$need_ffprobe" || warn "FFmpeg: konwersja multimediow bedzie niedostepna."; fi
if [ -z "$CJXL_BIN" ]; then install_cjxl || warn "cjxl: obrazy JPEG XL beda kodowane inaczej albo wcale."; fi
if [ "$ACME_OK" = 0 ]; then
  find_node; find_npm
  install_acme || warn "acme-client: automatyczny HTTPS (Let's Encrypt) niedostepny."
fi

echo
info "== Test koncowy =="
detect_all
report
if [ -n "$NODE_BIN" ] && [ -n "$NPM_BIN" ]; then
  ok "Gotowe. Uruchom serwer:  sh start.sh"
  echo "Panel po starcie: http://127.0.0.1:2138/admin  (haslo bedzie w oknie serwera)"
  if [ -z "$FFMPEG_BIN" ] || [ -z "$FFPROBE_BIN" ] || [ -z "$CJXL_BIN" ] || [ "$ACME_OK" = 0 ] || [ -z "$TOR_BIN" ]; then
    warn "Czesc opcjonalnych narzedzi nie jest zainstalowana (patrz wyzej) — serwer ruszy, ale bez tych funkcji."
  fi
  exit 0
fi
fail "Nie udalo sie przygotowac silnika (Node.js). Sprawdz polaczenie z internetem i uruchom instalator ponownie."
exit 1
