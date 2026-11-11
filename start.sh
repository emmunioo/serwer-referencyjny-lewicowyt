#!/bin/sh
# Uruchamia serwer. Sam znajduje silnik (lokalny ./engine, zapisany .enginepath, albo systemowy node);
# jak go nie ma, odpala instalator. Ustawia lokalnego Tora, jesli pobrany.
cd "$(dirname "$0")"
ROOT="$(pwd)"

resolve() {
  ENGINE=""
  [ -f "$ROOT/.enginepath" ] && ENGINE="$(cat "$ROOT/.enginepath")"
  [ -z "$ENGINE" ] && [ -x "$ROOT/engine/bin/node" ] && ENGINE="$ROOT/engine/bin/node"
  [ -z "$ENGINE" ] && command -v node >/dev/null 2>&1 && ENGINE="$(command -v node)"
  echo "$ENGINE"
}

ENGINE="$(resolve)"
if [ -z "$ENGINE" ]; then
  echo "Silnik nie jest zainstalowany - uruchamiam instalator..."
  sh "$ROOT/install.sh" || exit 1
  ENGINE="$(resolve)"
fi
[ -z "$ENGINE" ] && { echo "Nie udalo sie przygotowac silnika."; exit 1; }
if ! "$ENGINE" -e "const v=process.versions.node.split('.').map(Number);process.exit(v[0]>22||(v[0]===22&&v[1]>=15)?0:1)"; then
  echo "Ten silnik Node.js ($ENGINE) jest za stary - serwer wymaga wersji 22.15 lub nowszej."
  echo "Usun plik .enginepath i katalog engine/ albo zainstaluj nowszy Node.js, po czym uruchom ponownie."
  exit 1
fi

[ -x "$ROOT/engine-tor/tor/tor" ] && export TOR_BINARY="$ROOT/engine-tor/tor/tor"
echo "Silnik: $ENGINE"
echo "Panel: http://127.0.0.1:2138/admin  (haslo przy pierwszym starcie ponizej)"
export LEWICOWYT_SUPERVISED=1
while true; do
  "$ENGINE" "$ROOT/server.js" "$@"
  CODE=$?
  # kod 75 = serwer poprosil o restart (po aktualizacji z panelu)
  if [ "$CODE" -ne 75 ]; then
    [ "$CODE" -ne 0 ] && echo "Serwer zakonczyl sie bledem ($CODE). Jesli to zaraz po aktualizacji z panelu, cofnij ja: sh start.sh --rollback"
    exit "$CODE"
  fi
  echo "Restart serwera po aktualizacji..."
done
