# Instalator ONLINE serwera spolecznosci lewicowYT (Windows) — PowerShell 5.1+.
# Uzywa WYLACZNIE wbudowanych narzedzi Windows: Invoke-WebRequest, Get-FileHash, System.IO.Compression, tar.exe.
#
# Co robi:
#   0) sanityzacja: usuwa/odklada pozostalosci po komputerze autora (baza, klucz, cache CPU, martwy .enginepath, tmp);
#   1) bada 6 komponentow NIEZALEZNIE:  Node.js(>=22.15)+npm | Tor | FFmpeg | FFprobe | cjxl | acme-client (npm);
#   2) pobiera/instaluje TYLKO te, ktorych brakuje (kazdy pobrany plik jest weryfikowany SHA-256);
#   3) na koniec ponownie sprawdza wszystkie 6.
#
# Uzycie:   powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1 [-Mode local|system|ask] [-Tor yes|no|ask]
#                                                                           [-Clean] [-Yes] [-CheckOnly]
#   -Mode      gdzie postawic Node.js: local = .\engine (domyslnie), system = %LOCALAPPDATA%\lewicowyt-engine + PATH uzytkownika
#   -Tor       czy pobrac Tora, gdy go brak (domyslnie yes)
#   -Clean     wymusza przywrocenie data\ do stanu fabrycznego (dane NAJPIERW trafiaja do kopii data\_kopia-<data>)
#   -Yes       nie pytaj o potwierdzenie przy -Clean
#   -CheckOnly tylko sanityzacja i raport (nic nie pobiera) — do testow
#
# NOTA DLA AUDYTOROW: wszystkie adresy sa stale i pochodza od oficjalnych dostawcow (nodejs.org, dist.torproject.org,
# github.com/BtbN, github.com/libjxl, gyan.dev, registry.npmjs.org). Kazdy plik binarny ma sume SHA-256 (z listy dostawcy
# albo przypieta ponizej dla niezmiennego wydania). Podpisow GPG nie sprawdzamy (Windows nie ma gpg).

param(
  [ValidateSet("local", "system", "ask")] [string]$Mode = "local",
  [ValidateSet("yes", "no", "ask")] [string]$Tor = "yes",
  [switch]$Clean,
  [switch]$Yes,
  [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # Invoke-WebRequest bez paska = duzo szybciej
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem

$Root = $PSScriptRoot
$Data = Join-Path $Root "data"
$EngineDir = Join-Path $Root "engine"
$EnginePathFile = Join-Path $Root ".enginepath"
$TorDir = Join-Path $Root "engine-tor"
$ToolsDir = Join-Path $Root "tools"
$MinNode = [version]"22.15.0"
$DevKey = "qcdOqgKJm8B4wyG+KLKDoPzBofeNLLZSn89ZEBRKImw="        # klucz bazy z komputera autora (patrz sanityzacja)
$DevCpu = "AMD Ryzen 5 5600 6-Core Processor"                   # sygnatura CPU z komputera autora
$NODE_INDEX = "https://nodejs.org/dist/latest-v24.x/"           # linia LTS 24 (>= 22.15)
$TOR_INDEX = "https://dist.torproject.org/torbrowser/"
$BTBN = "https://github.com/BtbN/FFmpeg-Builds/releases/latest/download/"
$GYAN_ZIP = "https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip"
# cjxl: niezmienne wydanie libjxl; suma SHA-256 przypieta (zgodna z polem digest w GitHub Releases)
$CJXL_URL = "https://github.com/libjxl/libjxl/releases/download/v0.11.2/jxl-x64-windows-static.zip"
$CJXL_SHA = "97dc815bdd99ba243d8502050357342cf649251a5df069f8c3daee6828cbe0ce"

function Info($m) { Write-Host $m -ForegroundColor Cyan }
function Ok($m) { Write-Host $m -ForegroundColor Green }
function Warn($m) { Write-Host $m -ForegroundColor Yellow }
function Fail($m) { Write-Host $m -ForegroundColor Red }

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
function Write-Utf8($path, $text) { [IO.File]::WriteAllText($path, $text, $Utf8NoBom) }

# ------------------------------------------------------------------------------------------------------------------
# pomocnicze: uruchamianie programow, pobieranie, sumy, archiwa
# ------------------------------------------------------------------------------------------------------------------
function Test-Run($exe, [string[]]$arguments) {
  # prawda, gdy program sie uruchomil i zakonczyl kodem 0
  try {
    $null = & $exe @arguments 2>&1
    return ($LASTEXITCODE -eq 0)
  } catch { return $false }
}
function Get-Out($exe, [string[]]$arguments) {
  try {
    $o = & $exe @arguments 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    return ($o | Out-String).Trim()
  } catch { return $null }
}
function Download($url, $dest) {
  Info "Pobieram: $url"
  New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
  Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
}
function Get-Text($url) {
  # niektore serwery (np. GitHub Releases dla checksums.sha256) zwracaja application/octet-stream => Content to byte[]
  $c = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
  if ($c -is [byte[]]) { return [Text.Encoding]::UTF8.GetString($c) }
  return [string]$c
}
function Get-Sha($file) { (Get-FileHash -Algorithm SHA256 -Path $file).Hash.ToLower() }
function Assert-Sha($file, $expected) {
  $actual = Get-Sha $file
  if ($actual -ne $expected.ToLower()) {
    Remove-Item $file -Force -ErrorAction SilentlyContinue
    throw "Suma SHA-256 sie nie zgadza ($(Split-Path $file -Leaf)) — plik usuniety. Oczekiwano $expected, jest $actual."
  }
  Ok "Suma SHA-256 zgodna."
}
function Find-Sha($listText, $name) {
  # lista w formacie "<hash>  <nazwa>" lub "<hash> *<nazwa>"
  foreach ($line in ($listText -split "`n")) {
    $p = $line.Trim() -split '\s+'
    if ($p.Count -ge 2 -and $p[1].TrimStart('*') -eq $name) { return $p[0].ToLower() }
  }
  return $null
}
function New-TempFile($suffix) { Join-Path $env:TEMP ("lewicowyt-" + [guid]::NewGuid().ToString("N") + $suffix) }
function Expand-Entries($zip, [string]$pattern, $destDir, [switch]$OnlyMissing) {
  # rozpakowuje z ZIP-a tylko wpisy pasujace do wzorca (regex na pelnej sciezce wpisu), plasko do $destDir
  New-Item -ItemType Directory -Force -Path $destDir | Out-Null
  $arc = [IO.Compression.ZipFile]::OpenRead($zip)
  try {
    $n = 0
    foreach ($e in $arc.Entries) {
      if ($e.Name -and $e.FullName -match $pattern) {
        $target = Join-Path $destDir $e.Name
        if ($OnlyMissing -and (Test-Path $target)) { continue }
        try { [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $target, $true) }
        catch { Remove-Item $target -Force -ErrorAction SilentlyContinue; throw }   # nie zostawiamy uszkodzonego pliku
        $n++
      }
    }
    return $n
  } finally { $arc.Dispose() }
}

# ------------------------------------------------------------------------------------------------------------------
# KROK 0: sanityzacja pozostalosci po komputerze autora
# ------------------------------------------------------------------------------------------------------------------
function Invoke-Sanitize {
  Info "== Krok 0: sanityzacja plikow =="
  $keyFile = Join-Path $Data "klucz-bazy.key"
  $isDev = $false
  if (Test-Path $keyFile) {
    $isDev = (Get-Content $keyFile -Raw -ErrorAction SilentlyContinue) -like "*$DevKey*"
  }
  $doWipe = $false
  if ($isDev) {
    Warn "Wykryto deweloperski klucz bazy z komputera autora — baza i klucze zostana odlozone do kopii."
    $doWipe = $true
  } elseif ($Clean) {
    if ($Yes) { $doWipe = $true }
    else {
      Warn "-Clean przywroci data\ do stanu fabrycznego (baza, klucze, ustawienia szyfrowania). Dane trafia najpierw do kopii data\_kopia-<data>."
      $a = Read-Host "Wpisz TAK, aby kontynuowac"
      $doWipe = ($a -ceq "TAK")
      if (-not $doWipe) { Warn "Pominieto czyszczenie danych." }
    }
  } elseif (Test-Path $keyFile) {
    Ok "Klucz bazy jest wlasny (serwer juz tu dzialal) — baza i klucz zostaja nietkniete."
  }

  if ($doWipe -and (Test-Path $Data)) {
    $names = @("serwer.db", "serwer.db-shm", "serwer.db-wal", "klucz-bazy.key", "klucz-bazy.haslo.json", "szyfrowanie.json")
    $existing = @($names | Where-Object { Test-Path (Join-Path $Data $_) })
    $torData = Join-Path $Data "tor"
    if ($existing.Count -gt 0 -or (Test-Path $torData)) {
      $backup = Join-Path $Data ("_kopia-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
      New-Item -ItemType Directory -Force -Path $backup | Out-Null
      foreach ($n in $existing) { Move-Item -LiteralPath (Join-Path $Data $n) -Destination $backup -Force }
      if (Test-Path $torData) { Move-Item -LiteralPath $torData -Destination (Join-Path $backup "tor") -Force }
      Ok "Odlozono do: $backup  (mozesz usunac ten katalog, jesli to dane autora). Serwer przy starcie utworzy wlasny klucz, baze i haslo administratora."
    }
  }

  # B) szyfrowanie.json: zerujemy cache szybkosci szyfrow z cudzego CPU (serwer policzy go od nowa); reszta zostaje
  $encFile = Join-Path $Data "szyfrowanie.json"
  if (Test-Path $encFile) {
    try {
      $raw = Get-Content $encFile -Raw -Encoding UTF8
      $json = $raw | ConvertFrom-Json
      if ($null -ne $json.PSObject.Properties["autoCache"] -and $null -ne $json.autoCache) {
        $json.autoCache = $null
        Write-Utf8 $encFile (($json | ConvertTo-Json -Depth 20) + "`n")
        Ok "Wyczyszczono cache procesora w data\szyfrowanie.json (serwer ustali go ponownie)."
      }
    } catch {
      Warn "Nie udalo sie odczytac data\szyfrowanie.json ($($_.Exception.Message)) — zostawiam bez zmian."
    }
  }

  # C) martwy .enginepath
  if (Test-Path $EnginePathFile) {
    $p = (Get-Content $EnginePathFile -Raw -Encoding UTF8).Trim()
    if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf) -or -not (Test-Run $p @("-v"))) {
      Remove-Item $EnginePathFile -Force
      Warn "Usunieto martwy plik .enginepath (wskazywal: $p)."
    }
  }

  # D) pliki tymczasowe i niedokonczone pobrania
  $tmp = Join-Path $Data "tmp"
  if (Test-Path $tmp) { Get-ChildItem -LiteralPath $tmp -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
  if (Test-Path $Data) { Get-ChildItem -LiteralPath $Data -Filter "*.tmp" -File -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue }
}

# ------------------------------------------------------------------------------------------------------------------
# Wykrywanie komponentow (kolejnosc i polecenia jak w kodzie serwera: convert.js, network.js, acme.js)
# ------------------------------------------------------------------------------------------------------------------
$State = @{}

function Find-Node {
  $cands = @()
  if (Test-Path $EnginePathFile) { $cands += (Get-Content $EnginePathFile -Raw -Encoding UTF8).Trim() }
  $cands += (Join-Path $EngineDir "node.exe")
  $sys = Get-Command node -ErrorAction SilentlyContinue
  if ($sys) { $cands += $sys.Source }
  $tooOld = $null
  foreach ($c in $cands) {
    if (-not $c -or -not (Test-Path -LiteralPath $c -PathType Leaf)) { continue }
    $v = Get-Out $c @("-p", "process.versions.node")
    if (-not $v) { continue }
    $ver = $null
    if (-not [version]::TryParse(($v -split '-')[0], [ref]$ver)) { continue }
    if ($ver -ge $MinNode) { return @{ Path = $c; Version = $v } }
    $tooOld = "$c ($v)"
  }
  if ($tooOld) { Warn "Znaleziony Node.js jest za stary (wymagany >= $MinNode): $tooOld" }
  return $null
}
function Find-Npm($nodePath) {
  if (-not $nodePath) { return $null }
  $dir = Split-Path $nodePath
  foreach ($n in @("npm.cmd", "npm")) {
    $p = Join-Path $dir $n
    if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
  }
  $g = Get-Command npm -ErrorAction SilentlyContinue
  if ($g) { return $g.Source }
  return $null
}
function Find-Tor {
  foreach ($c in @($env:TOR_BINARY, (Join-Path $TorDir "tor\tor.exe"))) {
    if ($c -and (Test-Path -LiteralPath $c -PathType Leaf) -and (Test-Run $c @("--version"))) { return $c }
  }
  $g = Get-Command tor -ErrorAction SilentlyContinue
  if ($g -and (Test-Run $g.Source @("--version"))) { return $g.Source }
  return $null
}
function Find-Tool($envVar, $fileName, [string[]]$testArgs, $extraDirs) {
  $cands = @()
  $ev = [Environment]::GetEnvironmentVariable($envVar)
  if ($ev) { $cands += $ev }
  foreach ($d in $extraDirs) { if ($d) { $cands += (Join-Path $d $fileName) } }
  $cands += (Join-Path $ToolsDir $fileName)
  foreach ($c in $cands) {
    if ((Test-Path -LiteralPath $c -PathType Leaf) -and (Test-Run $c $testArgs)) { return $c }
  }
  $g = Get-Command ([IO.Path]::GetFileNameWithoutExtension($fileName)) -ErrorAction SilentlyContinue
  if ($g -and (Test-Run $g.Source $testArgs)) { return $g.Source }
  return $null
}
function Test-Acme($nodePath) {
  if (-not $nodePath) { return $false }
  Push-Location $Root
  try { return (Test-Run $nodePath @("-e", "import('acme-client').then(()=>process.exit(0)).catch(()=>process.exit(1))")) }
  finally { Pop-Location }
}

function Get-Status {
  $s = [ordered]@{}
  $node = Find-Node
  $s.node = $node
  $s.npm = if ($node) { Find-Npm $node.Path } else { $null }
  $s.tor = Find-Tor
  $s.ffmpeg = Find-Tool "FFMPEG_PATH" "ffmpeg.exe" @("-version") @()
  $ffDir = if ($s.ffmpeg) { Split-Path $s.ffmpeg } else { $null }
  $s.ffprobe = Find-Tool "FFPROBE_PATH" "ffprobe.exe" @("-version") @($ffDir)
  $s.cjxl = Find-Tool "CJXL_PATH" "cjxl.exe" @("--version") @()
  $s.acme = if ($node) { Test-Acme $node.Path } else { $false }
  return $s
}

function Show-Report($s) {
  Info "== Stan komponentow =="
  function Line($label, $ok, $detail) {
    if ($ok) { Ok ("[OK]   Juz zainstalowano: {0}{1}" -f $label, $(if ($detail) { " — $detail" } else { "" })) }
    else { Warn ("[BRAK] Do zainstalowania: {0}" -f $label) }
  }
  Line "Node.js >= $MinNode + npm" ($s.node -and $s.npm) $(if ($s.node) { "$($s.node.Version), $($s.node.Path)" })
  if ($s.node -and -not $s.npm) { Warn "       (Node.js jest, ale brakuje npm — zostanie zainstalowany pelny pakiet silnika)" }
  Line "Tor (Tor Expert Bundle)" ([bool]$s.tor) $s.tor
  Line "FFmpeg" ([bool]$s.ffmpeg) $s.ffmpeg
  Line "FFprobe" ([bool]$s.ffprobe) $s.ffprobe
  Line "cjxl (koder JPEG XL)" ([bool]$s.cjxl) $s.cjxl
  Line "Biblioteka npm acme-client" ([bool]$s.acme) $(if ($s.acme) { "node_modules\acme-client" })
}

# ------------------------------------------------------------------------------------------------------------------
# Instalacja brakujacych komponentow
# ------------------------------------------------------------------------------------------------------------------
function Install-Node {
  $sums = Get-Text "$($NODE_INDEX)SHASUMS256.txt"
  $m = [regex]::Match($sums, 'node-(v\d+\.\d+\.\d+)-win-x64\.zip')
  if (-not $m.Success) { throw "Nie ustalilem wersji Node.js." }
  $ver = $m.Groups[1].Value
  $name = "node-$ver-win-x64.zip"
  $expected = Find-Sha $sums $name
  if (-not $expected) { throw "Brak sumy SHA-256 dla $name." }
  $zip = New-TempFile ".zip"
  $stage = New-TempFile ".d"
  try {
    Download "https://nodejs.org/dist/$ver/$name" $zip
    Assert-Sha $zip $expected
    [IO.Compression.ZipFile]::ExtractToDirectory($zip, $stage)
    $inner = Join-Path $stage "node-$ver-win-x64"
    if (-not (Test-Path (Join-Path $inner "node.exe"))) { throw "Archiwum Node.js ma nieoczekiwana strukture." }
    $target = if ($Mode -eq "system") { Join-Path $env:LOCALAPPDATA "lewicowyt-engine" } else { $EngineDir }
    if (Test-Path $target) { Remove-Item $target -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    Get-ChildItem -LiteralPath $inner -Force | Move-Item -Destination $target -Force
  } finally {
    Remove-Item $zip -Force -ErrorAction SilentlyContinue
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
  }
  $nodeExe = Join-Path $target "node.exe"
  if ($Mode -eq "system") {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$target*") {
      [Environment]::SetEnvironmentVariable("Path", ($userPath.TrimEnd(';') + ";" + $target), "User")
      Warn "Dodano do PATH uzytkownika. Nowe okna terminala zobacza 'node' wszedzie."
    }
    Write-Utf8 $EnginePathFile $nodeExe
    Ok "Node.js $ver zainstalowany SYSTEMOWO: $nodeExe"
  } else {
    if (Test-Path $EnginePathFile) { Remove-Item $EnginePathFile -Force }
    Ok "Node.js $ver zainstalowany LOKALNIE: $nodeExe (uzywany tylko przez ten serwer)"
  }
}

function Install-Tor {
  # Najnowszy katalog wydan bywa niepelny (np. tylko paczki na Androida), wiec idziemy od najwyzszej wersji w dol
  # i bierzemy pierwsza, ktorej lista sum zawiera paczke dla Windows x86_64.
  $html = Get-Text $TOR_INDEX
  $vers = [regex]::Matches($html, '(\d+\.\d+(\.\d+)?)/') | ForEach-Object { $_.Groups[1].Value } |
    Sort-Object { [version]$_ } -Unique -Descending
  if (-not $vers) { throw "Nie udalo sie odczytac listy wersji Tora." }
  foreach ($ver in ($vers | Select-Object -First 8)) {
    $name = "tor-expert-bundle-windows-x86_64-$ver.tar.gz"
    try { $sums = Get-Text "$TOR_INDEX$ver/sha256sums-signed-build.txt" } catch { continue }
    $expected = Find-Sha $sums $name
    if (-not $expected) { continue }
    $tmp = New-TempFile ".tar.gz"
    try {
      Download "$TOR_INDEX$ver/$name" $tmp
      Assert-Sha $tmp $expected
      New-Item -ItemType Directory -Force -Path $TorDir | Out-Null
      Info "Rozpakowuje Tora (wbudowany tar)..."
      & tar -xzf $tmp -C $TorDir
      if ($LASTEXITCODE -ne 0) { throw "tar zakonczyl sie bledem $LASTEXITCODE" }
    } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    if (Test-Path (Join-Path $TorDir "tor\tor.exe")) { Ok "Tor $ver gotowy: $(Join-Path $TorDir 'tor\tor.exe')"; return }
    throw "Rozpakowano Tora, ale nie ma tor\tor.exe w $TorDir."
  }
  throw "Nie znalazlem paczki Tor Expert Bundle dla Windows x86_64 w ostatnich wydaniach."
}

function Install-FFmpeg($needFfmpeg, $needFfprobe) {
  # kopiujemy TYLKO brakujace binarki — dzialajacej nie nadpisujemy
  $zip = New-TempFile ".zip"
  try {
    $done = $false
    try {
      $sums = Get-Text "$($BTBN)checksums.sha256"
      $name = "ffmpeg-master-latest-win64-gpl.zip"
      $expected = Find-Sha $sums $name
      if (-not $expected) { throw "Brak sumy dla $name" }
      Download "$BTBN$name" $zip
      Assert-Sha $zip $expected
      $done = $true
    } catch {
      Warn "BtbN niedostepny lub bledna suma ($($_.Exception.Message)) — probuje gyan.dev."
      Remove-Item $zip -Force -ErrorAction SilentlyContinue
    }
    if (-not $done) {
      $expected = ((Get-Text "$GYAN_ZIP.sha256").Trim() -split '\s+')[0]
      if ($expected.Length -ne 64) { throw "gyan.dev: nieprawidlowa suma SHA-256." }
      Download $GYAN_ZIP $zip
      Assert-Sha $zip $expected
    }
    New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null
    $copied = 0
    if ($needFfmpeg) { $copied += Expand-Entries $zip '(^|/)bin/ffmpeg\.exe$' $ToolsDir -OnlyMissing }
    if ($needFfprobe) { $copied += Expand-Entries $zip '(^|/)bin/ffprobe\.exe$' $ToolsDir -OnlyMissing }
    if ($copied -eq 0) { throw "W archiwum FFmpeg nie znalazlem brakujacych programow." }
    Ok "FFmpeg/FFprobe skopiowane do $ToolsDir"
  } finally { Remove-Item $zip -Force -ErrorAction SilentlyContinue }
}

function Install-Cjxl {
  $zip = New-TempFile ".zip"
  try {
    Download $CJXL_URL $zip
    Assert-Sha $zip $CJXL_SHA
    New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null
    # to archiwum uzywa metody kompresji nieobslugiwanej przez .NET — rozpakowuje je wbudowany tar.exe (bsdtar)
    $stage = New-TempFile ".d"
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    try {
      & tar -xf $zip -C $stage
      if ($LASTEXITCODE -ne 0) { throw "tar zakonczyl sie bledem $LASTEXITCODE" }
      $f = Get-ChildItem -LiteralPath $stage -Recurse -File -Filter "cjxl.exe" | Select-Object -First 1
      if (-not $f) { throw "W archiwum libjxl nie ma cjxl.exe." }
      Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $ToolsDir "cjxl.exe") -Force
    } finally { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }
    Ok "cjxl skopiowany do $(Join-Path $ToolsDir 'cjxl.exe')"
  } finally { Remove-Item $zip -Force -ErrorAction SilentlyContinue }
}

function Install-Acme($nodePath, $npmPath) {
  if (-not $npmPath) { throw "Brak npm — nie mozna zainstalowac acme-client." }
  $oldPath = $env:PATH
  $env:PATH = (Split-Path $nodePath) + ";" + $env:PATH
  Push-Location $Root
  try {
    Info "npm install acme-client@^5.4.0 ..."
    # --no-save: nie zmieniamy package.json (acme-client jest tam juz jako optionalDependency)
    & $npmPath install --no-audit --no-fund --no-save "acme-client@^5.4.0"
    if ($LASTEXITCODE -ne 0) { throw "npm install zakonczyl sie bledem $LASTEXITCODE" }
  } finally { Pop-Location; $env:PATH = $oldPath }
  if (-not (Test-Acme $nodePath)) { throw "acme-client zainstalowany, ale import() nie dziala." }
  Ok "Biblioteka acme-client zainstalowana."
}

# ------------------------------------------------------------------------------------------------------------------
# PRZEBIEG
# ------------------------------------------------------------------------------------------------------------------
Info "== Instalator serwera spolecznosci lewicowYT (Windows) =="
Invoke-Sanitize
$s = Get-Status
Show-Report $s
if ($CheckOnly) { Info "Tryb -CheckOnly: koniec (nic nie pobrano)."; exit 0 }

$nodeOk = [bool]($s.node -and $s.npm)
$allOk = $nodeOk -and $s.tor -and $s.ffmpeg -and $s.ffprobe -and $s.cjxl -and $s.acme
if ($allOk) {
  Ok "Wszystkie wymagane biblioteki i narzedzia sa juz zainstalowane. Nic nie trzeba pobierac!"
  exit 0
}

$errors = @()
if ($Mode -eq "ask" -and -not $nodeOk) {
  Write-Host ""
  Write-Host "Jak zainstalowac Node.js?"
  Write-Host "  [L] LOKALNIE  - tylko dla tego serwera (katalog .\engine). Nic nie zmienia w systemie."
  Write-Host "  [S] SYSTEMOWO - do uzytku ogolnego (dostepny jako 'node' wszedzie, bez admina)."
  $c = Read-Host "Wybierz L lub S"
  $Mode = if ($c -match '^[Ss]') { "system" } else { "local" }
}
if ($Tor -eq "ask" -and -not $s.tor) {
  $t = Read-Host "Pobrac Tora (adres .onion, omija CGNAT)? [T]ak / [N]ie"
  $Tor = if ($t -match '^[TtYy]') { "yes" } else { "no" }
}

if (-not $nodeOk) {
  try { Install-Node } catch { $errors += "Node.js: $($_.Exception.Message)"; Fail $errors[-1] }
}
if (-not $s.tor) {
  if ($Tor -eq "yes") {
    try { Install-Tor } catch { Warn "Tor: $($_.Exception.Message) — mozesz uzyc wlasnego Tora (wpis torrc w panelu)." }
  } else { Warn "Pomijam Tora (wybrano -Tor no)." }
}
if (-not $s.ffmpeg -or -not $s.ffprobe) {
  try { Install-FFmpeg (-not $s.ffmpeg) (-not $s.ffprobe) } catch { Warn "FFmpeg: $($_.Exception.Message) — konwersja multimediow bedzie niedostepna."; $errors += "FFmpeg: $($_.Exception.Message)" }
}
if (-not $s.cjxl) {
  try { Install-Cjxl } catch { Warn "cjxl: $($_.Exception.Message) — obrazy JPEG XL beda kodowane inaczej albo wcale."; $errors += "cjxl: $($_.Exception.Message)" }
}
if (-not $s.acme) {
  $n = Find-Node
  if ($n) {
    try { Install-Acme $n.Path (Find-Npm $n.Path) } catch { Warn "acme-client: $($_.Exception.Message) — automatyczny HTTPS (Let's Encrypt) niedostepny."; $errors += "acme-client: $($_.Exception.Message)" }
  } else { Fail "Brak dzialajacego Node.js — pomijam acme-client." }
}

Write-Host ""
Info "== Test koncowy =="
$final = Get-Status
Show-Report $final
$critical = [bool]($final.node -and $final.npm)
if ($critical) {
  Ok "Gotowe. Uruchom serwer dwuklikiem w: start.bat"
  Write-Host "Panel po starcie: http://127.0.0.1:2138/admin  (haslo bedzie w oknie serwera)"
  if (-not ($final.ffmpeg -and $final.ffprobe -and $final.cjxl -and $final.acme -and $final.tor)) {
    Warn "Czesc opcjonalnych narzedzi nie jest zainstalowana (patrz wyzej) — serwer ruszy, ale bez tych funkcji."
  }
  exit 0
}
Fail "Nie udalo sie przygotowac silnika (Node.js). Sprawdz polaczenie z internetem i uruchom instalator ponownie."
exit 1
