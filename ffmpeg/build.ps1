# =============================================================================
#  build.ps1 — wejście dla Windows. Uruchamia build.sh w środowisku MSYS2/UCRT64
#  (te same, minimalne flagi FFmpeg co na Linux/macOS/Android).
#
#  Wymaga MSYS2 (https://www.msys2.org). Wskaż go przez -Msys2Root albo zmienną
#  środowiskową MSYS2_ROOT; domyślnie szuka w C:\msys64.
#
#  Przykład:
#    pwsh -File .\build.ps1                       # natywny x86_64 (windows)
#    pwsh -File .\build.ps1 -Platform android -Arch arm64-v8a   # cross na Androida
# =============================================================================
[CmdletBinding()]
param(
  [ValidateSet('windows','android')] [string]$Platform = 'windows',
  [string]$Arch = 'x86_64',
  [int]$Jobs = 0,
  [switch]$Clean,
  [string]$Msys2Root = $(if ($env:MSYS2_ROOT) { $env:MSYS2_ROOT } else { 'C:\msys64' })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSCommandPath

$bash = Join-Path $Msys2Root 'usr\bin\bash.exe'
if (-not (Test-Path $bash)) {
  throw "Nie znaleziono MSYS2 pod '$Msys2Root'. Zainstaluj z https://www.msys2.org lub podaj -Msys2Root."
}

# Narzędzia builda w UCRT64: toolchain, cmake, ninja, git, pkg-config, nasm (na
# wypadek, gdyby któraś zależność go chciała — nasze użycie aom jest 'generic').
Write-Host '>> Instaluję/aktualizuję pakiety MSYS2 (UCRT64)...' -ForegroundColor Cyan
& $bash -lc "pacman -S --needed --noconfirm git make cmake ninja pkgconf nasm mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja" | Out-Host

if ($Jobs -le 0) { $Jobs = [Environment]::ProcessorCount }

# Ścieżka projektu w formie MSYS (/g/android-apka/...)
$rootMsys = (& $bash -lc "cygpath -u '$root'").Trim()

$args = @("--platform", $Platform, "--arch", $Arch, "--jobs", "$Jobs")
if ($Clean) { $args += "--clean" }
# Android: przekaż NDK do środowiska bash
$envPrefix = ""
if ($Platform -eq 'android') {
  if (-not $env:ANDROID_NDK_ROOT) { throw "Ustaw ANDROID_NDK_ROOT na katalog NDK." }
  $ndkMsys = (& $bash -lc "cygpath -u '$($env:ANDROID_NDK_ROOT)'").Trim()
  $envPrefix = "export ANDROID_NDK_ROOT='$ndkMsys'; "
}

Write-Host ">> build.sh $($args -join ' ')  (UCRT64)" -ForegroundColor Cyan
# MSYSTEM=UCRT64 daje mingw toolchain na PATH
& $bash -lc "MSYSTEM=UCRT64 source /etc/profile; $envPrefix cd '$rootMsys' && ./build.sh $($args -join ' ')"
if ($LASTEXITCODE -ne 0) { throw "build.sh zakończył się kodem $LASTEXITCODE" }
Write-Host '>> Gotowe. Wynik w .\dist\' -ForegroundColor Green
