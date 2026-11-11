#!/bin/sh
# lewicowYT — serwer spolecznosci: samorozpakowujacy instalator dla Linuxa (.run), wersja @VERSION@.
# Plik = ten skrypt + archiwum tar.gz doklejone po znaczniku __ARCHIVE_BELOW__. Nic nie jest instalowane w systemie:
# pliki serwera trafiaja do katalogu docelowego, a potem uruchamiany jest install.sh (pobiera brakujace: Node.js, Tor,
# FFmpeg, cjxl, acme-client — kazdy plik z weryfikacja SHA-256).
#
# Uzycie:   sh lewicowyt-serwer-@VERSION@.run [--target KATALOG] [--noexec] [--verify] [--help] [parametry install.sh]
#   --target KATALOG  gdzie rozpakowac (domyslnie ~/lewicowyt-serwer)
#   --noexec          tylko rozpakuj, nie uruchamiaj install.sh
#   --verify          tylko sprawdz sume SHA-256 archiwum
#   pozostale parametry (np. --clean --yes --check-only) i zmienne (MODE=system TOR=no) trafiaja do install.sh
#
# NOTA DLA AUDYTOROW: skrypt sprawdza SHA-256 doklejonego archiwum przed rozpakowaniem. Zawartosc mozna obejrzec bez
# uruchamiania:  sed '1,/^__ARCHIVE_BELOW__$/d' plik.run | tar -tzf -
set -u
EXPECTED_SHA="@SHA256@"
TARGET="${HOME:-.}/lewicowyt-serwer"
NOEXEC=0
VERIFY=0
FWD=""

while [ $# -gt 0 ]; do
  case "$1" in
    --target) [ $# -ge 2 ] || { echo "Brak wartosci po --target." >&2; exit 2; }; TARGET="$2"; shift 2 ;;
    --noexec) NOEXEC=1; shift ;;
    --verify) VERIFY=1; shift ;;
    --help|-h) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) FWD="$FWD $1"; shift ;;
  esac
done

SKIP="$(awk '/^__ARCHIVE_BELOW__$/ { print NR + 1; exit 0 }' "$0")"
[ -n "$SKIP" ] || { echo "Uszkodzony plik: brak archiwum." >&2; exit 1; }

sha256_of_stream() { if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi; }
ACTUAL="$(tail -n +"$SKIP" "$0" | sha256_of_stream)"
if [ "$ACTUAL" != "$EXPECTED_SHA" ]; then
  echo "Suma SHA-256 archiwum sie nie zgadza (plik uszkodzony lub zmieniony). Oczekiwano $EXPECTED_SHA, jest $ACTUAL." >&2
  exit 1
fi
echo "Suma SHA-256 archiwum zgodna."
[ "$VERIFY" = 1 ] && exit 0

mkdir -p "$TARGET" || { echo "Nie moge utworzyc $TARGET" >&2; exit 1; }
echo "Rozpakowuje do: $TARGET"
tail -n +"$SKIP" "$0" | tar -xzf - -C "$TARGET" || { echo "Rozpakowanie nie powiodlo sie." >&2; exit 1; }
chmod +x "$TARGET"/*.sh 2>/dev/null

if [ "$NOEXEC" = 1 ]; then echo "Rozpakowano (--noexec). Uruchom:  cd \"$TARGET\" && sh install.sh"; exit 0; fi
cd "$TARGET" || exit 1
# shellcheck disable=SC2086
sh ./install.sh $FWD
code=$?
[ "$code" = 0 ] && echo "Uruchom serwer:  cd \"$TARGET\" && sh start.sh"
exit "$code"
__ARCHIVE_BELOW__
