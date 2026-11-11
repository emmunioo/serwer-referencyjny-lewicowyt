#!/usr/bin/env bash
# =============================================================================
#  ffmpeg-serwer — minimalny, dedykowany FFmpeg dla serwera lewicowYT
#
#  Zakres (świadomie wąski, żeby binarka była mała i bezpieczna):
#    - WIDEO: nic (żadnych kodeków wideo)
#    - AUDIO: tylko Opus (libopus, kontener .opus/.ogg/.mka)
#    - OBRAZY: jpeg (natywny mjpeg), png, webp (libwebp), jxl (libjxl),
#              avif (dekod = natywny av1; kod = libaom)
#    - FILTRY: skalowanie i podstawowe przekształcenia obrazu/audio
#
#  Platformy: linux, macos, windows (MSYS2/UCRT64), android (NDK, cross-compile).
#  Wszystkie zależności budujemy przez CMake (jedna ścieżka; bez meson/nasm) i
#  linkujemy STATYCZNIE — wynik to jeden przenośny plik `ffmpeg`.
#
#  Użycie:
#    ./build.sh [--platform auto|linux|macos|windows|android]
#               [--arch x86_64|arm64|armv7]   (android: arm64-v8a|armeabi-v7a|x86_64)
#               [--android-api 26] [--jobs N] [--clean] [--prefix DIR]
#
#  Uwaga o „mozjpeg": FFmpeg NIE integruje biblioteki mozjpeg — jego JPEG to
#  natywny enkoder mjpeg. Prawdziwy MozJPEG (trellis) jest osobnym narzędziem
#  (cjpeg) i w aplikacji jest już jako moduł natywny. Tu JPEG = mjpeg.
# =============================================================================
set -euo pipefail

# MSYS2/MINGW czasem nie eksportuje PROCESSOR_ARCHITECTURE. Bez niego natywne CMake ma PUSTE
# CMAKE_SYSTEM_PROCESSOR, a mozjpeg wywala się na string(TOLOWER ${CMAKE_SYSTEM_PROCESSOR} ...).
# Ustawiamy sensowny domyślny dla builda natywnego (nie dotyczy cross-compile z toolchainem).
export PROCESSOR_ARCHITECTURE="${PROCESSOR_ARCHITECTURE:-AMD64}"

# ------------------------------- konfiguracja --------------------------------
FFMPEG_REF="release/7.1"
declare -A DEP_REPO=(
  [zlib]="https://github.com/madler/zlib.git"
  [opus]="https://github.com/xiph/opus.git"
  [libwebp]="https://chromium.googlesource.com/webm/libwebp"
  [aom]="https://aomedia.googlesource.com/aom"
  [libjxl]="https://github.com/libjxl/libjxl.git"
  [mozjpeg]="https://github.com/mozilla/mozjpeg.git"
  [x264]="https://code.videolan.org/videolan/x264.git"
  [x265]="https://bitbucket.org/multicoreware/x265_git.git"
  [nvcodec]="https://github.com/FFmpeg/nv-codec-headers.git"
  [amf]="https://github.com/GPUOpen-LibrariesAndSDKs/AMF.git"
  [libvpl]="https://github.com/intel/libvpl.git"
)
declare -A DEP_TAG=(
  [zlib]="v1.3.1"
  [opus]="v1.5.2"
  [libwebp]="v1.4.0"
  [aom]="v3.9.0"
  [libjxl]="v0.11.1"
  [mozjpeg]="v4.1.1"
  [x264]="stable"          # x264 nie ma tagów wydań — gałąź stable; commit przypięty niżej (DEP_COMMIT)
  [x265]="4.1"
  [nvcodec]="n12.1.14.1"   # nagłówki NVENC: najstarszy wymagany przez FFmpeg 7.1 => najszersza zgodność sterowników (>= 530.41)
  [amf]="v1.4.36"
  [libvpl]="v2.15.0"
)
# pełne skróty commitów (tag adnotowany = commit po dereferencji); fetch_source sprawdza zgodność
declare -A DEP_COMMIT=(
  [x264]="b35605ace3ddf7c1a5d67a2eb553f034aef41d55"
  [x265]="1d117bed4747758b51bd2c124d738527e30392cb"
  [nvcodec]="7c8e7fc751f803c672b42c37d9199c8a4f98b327"
  [amf]="16f7d73e0b45c473e903e46981ed0b91efc4c091"
)
# libjxl potrzebuje swoich submodułów (brotli, highway) — klonujemy rekurencyjnie
DEP_RECURSIVE_libjxl=1

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
PLATFORM="auto"
ARCH="native"
ANDROID_API="26"
CLEAN=0
PREFIX_OVERRIDE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --platform) PLATFORM="$2"; shift 2 ;;
    --arch) ARCH="$2"; shift 2 ;;
    --android-api) ANDROID_API="$2"; shift 2 ;;
    --jobs) JOBS="$2"; shift 2 ;;
    --clean) CLEAN=1; shift ;;
    --prefix) PREFIX_OVERRIDE="$2"; shift 2 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "Nieznany argument: $1" >&2; exit 2 ;;
  esac
done

# --------------------------- wykrywanie platformy ----------------------------
detect_platform() {
  case "$(uname -s)" in
    Linux)  echo linux ;;
    Darwin) echo macos ;;
    MINGW*|MSYS*|CYGWIN*) echo windows ;;
    *) echo "Nieznany system: $(uname -s)" >&2; exit 1 ;;
  esac
}
[ "$PLATFORM" = "auto" ] && PLATFORM="$(detect_platform)"

WORK_DIR="$ROOT_DIR/work/$PLATFORM-$ARCH"
SRC_DIR="$ROOT_DIR/work/src"
PREFIX="${PREFIX_OVERRIDE:-$WORK_DIR/prefix}"
OUT_DIR="$ROOT_DIR/dist/$PLATFORM-$ARCH"

if [ "$CLEAN" = "1" ]; then
  echo ">> Czyszczę $WORK_DIR i $OUT_DIR"
  rm -rf "$WORK_DIR" "$OUT_DIR"
fi
mkdir -p "$SRC_DIR" "$PREFIX" "$OUT_DIR" "$WORK_DIR"

# --------------------------- toolchain / cross ------------------------------
# Zmienne wypełniane per-platforma:
CMAKE_TOOLCHAIN_ARGS=()   # dodatkowe -D... dla CMake (cross)
FF_CROSS_ARGS=()          # dodatkowe flagi FFmpeg configure (cross)
HOST_TRIPLE=""

setup_toolchain() {
  case "$PLATFORM" in
    linux|macos|windows)
      if [ "$PLATFORM" = "macos" ] && [ "$ARCH" != "native" ]; then
        local mac_arch="$ARCH"; [ "$ARCH" = "arm64" ] && mac_arch="arm64"; [ "$ARCH" = "x86_64" ] && mac_arch="x86_64"
        CMAKE_TOOLCHAIN_ARGS+=("-DCMAKE_OSX_ARCHITECTURES=$mac_arch")
        FF_CROSS_ARGS+=("--extra-cflags=-arch $mac_arch" "--extra-ldflags=-arch $mac_arch")
      fi
      ;;
    android)
      : "${ANDROID_NDK_ROOT:?Ustaw ANDROID_NDK_ROOT na katalog NDK (np. .../ndk/27.x)}"
      local abi="$ARCH"
      case "$ARCH" in
        arm64|arm64-v8a) abi="arm64-v8a"; FF_ARCH="aarch64"; TRIPLE="aarch64-linux-android" ;;
        armv7|armeabi-v7a) abi="armeabi-v7a"; FF_ARCH="arm"; TRIPLE="armv7a-linux-androideabi" ;;
        x86_64) abi="x86_64"; FF_ARCH="x86_64"; TRIPLE="x86_64-linux-android" ;;
        *) echo "Android ABI: użyj arm64-v8a|armeabi-v7a|x86_64" >&2; exit 1 ;;
      esac
      ANDROID_ABI="$abi"
      local host_tag="linux-x86_64"
      case "$(uname -s)" in Darwin) host_tag="darwin-x86_64" ;; MINGW*|MSYS*) host_tag="windows-x86_64" ;; esac
      TOOLCHAIN="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/$host_tag"
      CC="$TOOLCHAIN/bin/${TRIPLE}${ANDROID_API}-clang"
      CXX="$TOOLCHAIN/bin/${TRIPLE}${ANDROID_API}-clang++"
      AR="$TOOLCHAIN/bin/llvm-ar"; RANLIB="$TOOLCHAIN/bin/llvm-ranlib"; STRIP="$TOOLCHAIN/bin/llvm-strip"
      CMAKE_TOOLCHAIN_ARGS+=(
        "-DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake"
        "-DANDROID_ABI=$abi" "-DANDROID_PLATFORM=android-$ANDROID_API"
      )
      FF_CROSS_ARGS+=(
        --enable-cross-compile --target-os=android "--arch=$FF_ARCH"
        "--cc=$CC" "--cxx=$CXX" "--ar=$AR" "--ranlib=$RANLIB" "--strip=$STRIP"
        "--sysroot=$TOOLCHAIN/sysroot" "--cross-prefix=$TOOLCHAIN/bin/llvm-"
      )
      ;;
    *) echo "Nieobsługiwana platforma: $PLATFORM" >&2; exit 1 ;;
  esac
}

# ------------------------------ pobieranie źródeł ----------------------------
fetch_source() {
  local name="$1"
  local dir="$SRC_DIR/$name"
  if [ -d "$dir/.git" ]; then echo ">> Źródło $name już pobrane"; return; fi
  local recvar="DEP_RECURSIVE_${name}" rec=""
  [ "${!recvar:-0}" = "1" ] && rec="--recurse-submodules --shallow-submodules"
  echo ">> Klonuję $name (${DEP_TAG[$name]})"
  git clone --depth 1 --branch "${DEP_TAG[$name]}" $rec "${DEP_REPO[$name]}" "$dir"
  if [ -n "${DEP_COMMIT[$name]:-}" ]; then
    local head; head="$(git -C "$dir" rev-parse HEAD)"
    if [ "$head" != "${DEP_COMMIT[$name]}" ]; then
      echo "BLAD: $name ma commit $head, oczekiwano ${DEP_COMMIT[$name]} (zmieniony tag/gałąź?) — przerywam." >&2; exit 1
    fi
  fi
}

# ------------------------------ build zależności -----------------------------
cmake_build() {
  local name="$1"; shift
  local src="$SRC_DIR/$name${CMAKE_SUBDIR:+/$CMAKE_SUBDIR}" bld="$WORK_DIR/build/$name"
  echo ">> Buduję $name ($PLATFORM/$ARCH)"
  cmake -S "$src" -B "$bld" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    "${CMAKE_TOOLCHAIN_ARGS[@]}" "$@"
  cmake --build "$bld" --parallel "$JOBS"
  cmake --install "$bld"
}

build_zlib()   { cmake_build zlib -DZLIB_BUILD_EXAMPLES=OFF; }
build_opus()   { cmake_build opus -DOPUS_BUILD_SHARED_LIBRARY=OFF -DOPUS_BUILD_TESTING=OFF -DOPUS_BUILD_PROGRAMS=OFF; }
build_libwebp(){ cmake_build libwebp -DWEBP_BUILD_ANIM_UTILS=OFF -DWEBP_BUILD_CWEBP=OFF -DWEBP_BUILD_DWEBP=OFF \
                   -DWEBP_BUILD_GIF2WEBP=OFF -DWEBP_BUILD_IMG2WEBP=OFF -DWEBP_BUILD_VWEBP=OFF \
                   -DWEBP_BUILD_WEBPINFO=OFF -DWEBP_BUILD_WEBPMUX=ON -DWEBP_BUILD_EXTRAS=OFF; }
# aom: tylko enkoder AVIF (dekod robi natywny av1 w FFmpeg), bez SIMD/NASM (generic) = przenośnie i mniej
build_aom() {
  cmake_build aom -DAOM_TARGET_CPU=generic -DCONFIG_AV1_DECODER=0 -DCONFIG_AV1_ENCODER=1 \
    -DENABLE_EXAMPLES=0 -DENABLE_TESTS=0 -DENABLE_TOOLS=0 -DENABLE_DOCS=0 -DCONFIG_RUNTIME_CPU_DETECT=0
}
build_libjxl() {
  cmake_build libjxl -DBUILD_TESTING=OFF -DJPEGXL_ENABLE_TOOLS=OFF -DJPEGXL_ENABLE_DOXYGEN=OFF \
    -DJPEGXL_ENABLE_MANPAGES=OFF -DJPEGXL_ENABLE_BENCHMARK=OFF -DJPEGXL_ENABLE_EXAMPLES=OFF \
    -DJPEGXL_ENABLE_JNI=OFF -DJPEGXL_ENABLE_SJPEG=OFF -DJPEGXL_ENABLE_OPENEXR=OFF \
    -DJPEGXL_ENABLE_SKCMS=ON -DJPEGXL_STATIC=ON -DJPEGXL_ENABLE_PLUGINS=OFF
}
# MozJPEG: budujemy JEGO CLI cjpeg/djpeg (prawdziwy MozJPEG, trellis) — FFmpeg NIE używa libjpeg,
# więc mozjpeg dostarczamy jako osobne narzędzie do wołania w potoku (ffmpeg → PNG/PPM → cjpeg).
# Bez SIMD/NASM (jak reszta) — trellis i tak działa, tracimy tylko na szybkości.
build_mozjpeg() {
  # mozjpeg: (1) stare cmake_minimum_required (<3.5) -> polityka 3.5; (2) w MSYS2 CMAKE_SYSTEM_PROCESSOR
  # bywa puste (string(TOLOWER ...) sypie się na pustym) -> ustawiamy jawnie. To NIE włącza cross-compile
  # (do tego trzeba CMAKE_SYSTEM_NAME), tylko dostarcza nazwę CPU do detekcji architektury mozjpeg.
  local cpu="${ARCH}"; [ "$cpu" = "native" ] && cpu="x86_64"
  cmake_build mozjpeg -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_SYSTEM_PROCESSOR="$cpu" \
    -DENABLE_SHARED=OFF -DENABLE_STATIC=ON -DWITH_SIMD=OFF \
    -DWITH_TURBOJPEG=OFF -DPNG_SUPPORTED=OFF -DREQUIRE_SIMD=OFF
}

# --- wideo: x264 / x265 (CPU, GPL), 8-bit (serwer koduje yuv420p 8-bit) ---
build_x264() {
  local src="$SRC_DIR/x264" bld="$WORK_DIR/build/x264"
  echo ">> Buduję x264 ($PLATFORM/$ARCH)"
  rm -rf "$bld"; mkdir -p "$bld"; ( cd "$bld"
    "$src/configure" --prefix="$PREFIX" --enable-static --enable-pic --disable-cli --disable-opencl       --disable-avs --disable-swscale --disable-lavf --disable-ffms --disable-gpac --disable-lsmash --bit-depth=8 "${X264_EXTRA[@]}"
    make -j"$JOBS"; make install )
}
build_x265() {
  # x265 4.1 ustawia polityki CMake CMP0025/CMP0054 na OLD, czego nowe CMake (>= 4.0) już nie dopuszcza — przełączamy na NEW
  sed -i -E 's/(cmake_policy\(SET CMP00(25|54)) OLD\)/\1 NEW)/' "$SRC_DIR/x265/source/CMakeLists.txt"
  # x265: 8-bit, bez CLI, z asemblerem (nasm); stara polityka cmake (<3.5) -> wymuszamy 3.5
  CMAKE_SUBDIR=source cmake_build x265 -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DENABLE_SHARED=OFF -DENABLE_CLI=OFF     -DHIGH_BIT_DEPTH=OFF -DENABLE_ASSEMBLY=ON -DENABLE_LIBNUMA=OFF -DENABLE_HDR10_PLUS=OFF     -DCMAKE_ASM_NASM_FLAGS= "${X265_EXTRA[@]}"
  # x265.pc każe linkować -lgcc_s (dynamiczne libgcc_s_seh-1.dll / libgcc_s.so.1) — zamieniamy na statyczne libgcc_eh,
  # inaczej binarka wymaga bibliotek kompilatora, których nie ma na czystym systemie
  sed -i 's/-lgcc_s/-lgcc_eh/g' "$PREFIX/lib/pkgconfig/x265.pc"
}
# --- akceleracja sprzętowa: tylko nagłówki/dispatcher (sterowniki ładuje system w czasie działania) ---
build_nvcodec_headers() { local src="$SRC_DIR/nvcodec"; echo ">> Instaluję nagłówki NVENC (ffnvcodec)"; make -C "$src" install PREFIX="$PREFIX"; }
build_amf_headers() {
  echo ">> Instaluję nagłówki AMF (AMD)"
  mkdir -p "$PREFIX/include/AMF"; cp -r "$SRC_DIR/amf/amf/public/include/." "$PREFIX/include/AMF/"
}
build_libvpl() {
  cmake_build libvpl -DBUILD_TESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TOOLS=OFF -DBUILD_EXPERIMENTAL=OFF     -DINSTALL_EXAMPLE_CODE=OFF -DBUILD_DISPATCHER_ONEVPL_EXPERIMENTAL=OFF
}

# --- VAAPI (Linux): libva statycznie, ze sterownikami ładowanymi z systemu w czasie działania ---
LIBVA_VER="2.22.0"
LIBVA_SHA256="e3da2250654c8d52b3f59f8cb3f3d8e7fb1a2ee64378dbc400fbc5663de7edb8"
build_libva() {
  local tb="$SRC_DIR/libva-$LIBVA_VER.tar.bz2" src="$SRC_DIR/libva" bld="$WORK_DIR/build/libva"
  [ -f "$tb" ] || curl -fsSL -o "$tb" "https://github.com/intel/libva/releases/download/$LIBVA_VER/libva-$LIBVA_VER.tar.bz2"
  echo "$LIBVA_SHA256  $tb" | sha256sum -c - || { echo "BLAD: zla suma SHA-256 libva" >&2; rm -f "$tb"; exit 1; }
  rm -rf "$src"; mkdir -p "$src" "$bld"; tar -xjf "$tb" -C "$src" --strip-components=1
  echo ">> Buduję libva $LIBVA_VER (statycznie)"
  ( cd "$bld"
    "$src/configure" --prefix="$PREFIX" --enable-static --disable-shared --with-pic --disable-docs --disable-x11 --disable-glx       --disable-wayland --enable-drm       --with-drivers-path=/usr/lib/x86_64-linux-gnu/dri:/usr/lib/aarch64-linux-gnu/dri:/usr/lib64/dri:/usr/lib/dri
    make -j"$JOBS"; make install )
  # katalog z samymi bibliotekami .a (linker bierze je przed .so): libdrm i zlib linkujemy statycznie
  mkdir -p "$PREFIX/static-only"
  for l in libdrm.a libz.a libstdc++.a; do
    local p; p="$(gcc -print-file-name=$l)"; [ -f "$p" ] && ln -sf "$p" "$PREFIX/static-only/$l"
  done
}

# ------------------------------ build FFmpeg ---------------------------------
source "$ROOT_DIR/ffmpeg-config.sh"   # dostarcza tablicę FFMPEG_FLAGS[]

build_ffmpeg() {
  local src="$SRC_DIR/ffmpeg" bld="$WORK_DIR/build/ffmpeg"
  if [ ! -d "$src/.git" ]; then
    echo ">> Klonuję FFmpeg ($FFMPEG_REF)"
    git clone --depth 1 --branch "$FFMPEG_REF" https://git.ffmpeg.org/ffmpeg.git "$src"
  fi
  # libjxl jest w C++ (std::thread/condition_variable) — statyczny link FFmpeg (C) musi dociągnąć
  # bibliotekę standardową C++, inaczej configure/link sypie „undefined reference to std::...".
  local cxxlibs="-lstdc++"
  [ "$PLATFORM" = "macos" ] && cxxlibs="-lc++"
  [ "$PLATFORM" = "windows" ] && cxxlibs="-lstdc++ -lwinpthread"
  local extra_ld=""
  if [ "$PLATFORM" = "windows" ]; then
    # w pełni statycznie: bez libstdc++-6.dll / libgcc_s_seh-1.dll / libwinpthread-1.dll / zlib1.dll (plik musi działać na czystym Windowsie)
    extra_ld="-static -static-libgcc -static-libstdc++"
  fi
  if [ "$PLATFORM" = "linux" ]; then
    # libc zostaje dynamiczny (sterowniki GPU ładowane przez dlopen); reszta statycznie => plik działa bez libva/libdrm/libstdc++
    extra_ld="-L$PREFIX/static-only -static-libgcc"; cxxlibs="-l:libstdc++.a -lm"
  fi
  rm -rf "$bld"; mkdir -p "$bld"; ( cd "$bld"
    echo ">> Konfiguruję FFmpeg ($PLATFORM/$ARCH)"
    PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:$PREFIX/lib64/pkgconfig:$PREFIX/share/pkgconfig" \
    "$src/configure" \
      --prefix="$PREFIX" \
      --pkg-config-flags=--static \
      --extra-cflags="-I$PREFIX/include" \
      --extra-ldflags="-L$PREFIX/lib -L$PREFIX/lib64 $extra_ld" \
      --extra-libs="$cxxlibs" \
      "${FFMPEG_FLAGS[@]}" \
      "${FF_CROSS_ARGS[@]}"
    make -j"$JOBS"
    make install
  )
}

# --------------------------------- main --------------------------------------
setup_toolchain

X264_EXTRA=(); X265_EXTRA=()
DEPS="zlib opus libwebp aom libjxl mozjpeg x264 x265"
case "$PLATFORM" in
  windows) DEPS="$DEPS nvcodec amf libvpl" ;;
  linux)   DEPS="$DEPS nvcodec" ;;
esac
for dep in $DEPS; do fetch_source "$dep"; done
build_zlib
build_opus
build_libwebp
build_aom
build_libjxl
build_mozjpeg
build_x264
build_x265
case "$PLATFORM" in
  windows) build_nvcodec_headers; build_amf_headers; build_libvpl ;;
  linux)   build_nvcodec_headers; build_libva ;;
esac
build_ffmpeg

EXE=""; [ "$PLATFORM" = "windows" ] && EXE=".exe"
cp -f "$PREFIX/bin/ffmpeg$EXE"  "$OUT_DIR/" 2>/dev/null || true
cp -f "$PREFIX/bin/ffprobe$EXE" "$OUT_DIR/" 2>/dev/null || true
cp -f "$PREFIX/bin/cjpeg$EXE"   "$OUT_DIR/" 2>/dev/null || true   # prawdziwy MozJPEG
cp -f "$PREFIX/bin/djpeg$EXE"   "$OUT_DIR/" 2>/dev/null || true
echo ""
echo "================================================================"
echo " GOTOWE w: $OUT_DIR"
echo "   ffmpeg$EXE  ffprobe$EXE  cjpeg$EXE (MozJPEG)  djpeg$EXE"
echo " Test:  \"$OUT_DIR/ffmpeg$EXE\" -hide_banner -encoders | grep -E 'opus|webp|jxl|aom|mjpeg|png'"
echo "        \"$OUT_DIR/cjpeg$EXE\" -version   # MozJPEG"
echo "================================================================"
