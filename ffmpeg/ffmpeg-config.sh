#!/usr/bin/env bash
# =============================================================================
#  Jedyne źródło prawdy: zestaw flag `configure` FFmpeg dla serwera lewicowYT.
#  Zaczynamy od --disable-everything i włączamy TYLKO to, czego potrzebujemy.
#  Współdzielone przez build.sh (Windows i Linux — TEN SAM zestaw funkcji na obu).
#
#  Zakres:
#    OBRAZY   png, jpeg (mjpeg), webp (+anim), jxl, avif (dekod natywny av1, kod libaom)
#    AUDIO    opus (kod i dekod), wejście: aac/mp3/vorbis/flac/ac3/pcm…
#    WIDEO    kodowanie H.264 (libx264) i H.265 (libx265) do MP4; wejście: h264/hevc/vp8/vp9/av1/mpeg4/…
#    AKCELERACJA SPRZĘTOWA (kodowanie):
#       NVIDIA  — NVENC  (h264_nvenc, hevc_nvenc)        Windows i Linux
#       AMD     — AMF    (h264_amf, hevc_amf)            Windows
#       Intel   — QSV    (h264_qsv, hevc_qsv, libvpl)    Windows
#       Intel+AMD na Linuxie — VAAPI (h264_vaapi, hevc_vaapi)
#    Sterowniki NIE są częścią pliku: biblioteki (nvEncodeAPI, amfrt64, libmfx/vpl, libva) ładuje system w czasie działania;
#    serwer wykrywa dostępne enkodery próbą kodowania (convert.js) i sam wraca do CPU (x264/x265), gdy ich brak.
#  Licencja wyniku: GPL (x264/x265) — patrz LICENSE-NOTES.md.
# =============================================================================

FFMPEG_FLAGS=(
  # --- rdzeń: statyczny, mały, bez zbędnych rzeczy ---
  --disable-everything
  --enable-static
  --disable-shared
  --enable-small
  --enable-pic
  --disable-debug
  --disable-doc
  --disable-network          # serwer działa na lokalnych plikach/potokach
  --disable-autodetect       # tylko jawnie włączone biblioteki
  --enable-avdevice           # tylko dla wejścia lavfi (testsrc2/color — convert.js wykrywa nim działające enkodery GPU)
  --disable-postproc
  --disable-ffplay
  --enable-ffmpeg
  --enable-ffprobe
  --enable-gpl               # libx264 / libx265

  # --- biblioteki zewnętrzne (zbudowane przez build.sh) ---
  --enable-zlib              # PNG
  --enable-libopus           # audio: Opus
  --enable-libwebp           # WEBP
  --enable-libjxl            # JPEG XL
  --enable-libaom            # AV1 -> enkoder AVIF
  --enable-libx264           # H.264 (CPU)
  --enable-libx265           # H.265 (CPU)

  # --- protokoły: tylko lokalne ---
  --enable-protocol=file,pipe,fd

  # --- dekodery (wejście) ---
  # obrazy: png/jpeg/webp/jxl/gif + av1 (AVIF) + hevc (HEIC); wideo z telefonów i przeglądarek: h264/hevc/vp8/vp9/av1/mpeg4;
  # audio: opus, aac, mp3, vorbis, flac, ac3, pcm
  --enable-decoder=wrapped_avframe,rawvideo,png,apng,mjpeg,mjpegb,webp,gif,libjxl,av1,hevc,h264,vp8,vp9,mpeg4,mpeg2video,libopus,opus,aac,aac_latm,mp3,mp3float,vorbis,flac,ac3,eac3,alac,pcm_s16le,pcm_s16be,pcm_s24le,pcm_f32le,pcm_u8

  # --- enkodery (wyjście) ---
  # obrazy + audio jak dotąd; wideo: x264/x265 (CPU); ppm: bufor do potoku MozJPEG (cjpeg)
  --enable-encoder=png,mjpeg,ppm,libwebp,libwebp_anim,libjxl,libaom_av1,libopus,pcm_s16le,libx264,libx265

  # --- demuksery (kontenery wejścia) ---
  --enable-demuxer=image2,image2pipe,png_pipe,webp_pipe,jpeg_pipe,jpegxl_pipe,gif,apng,mjpeg,mov,matroska,avi,mpegts,mpegps,flv,ogg,wav,mp3,aac,flac,ac3,h264,hevc,ivf,m4v
  --enable-indev=lavfi

  # --- muksery (kontenery wyjścia) ---
  --enable-muxer=image2,image2pipe,webp,avif,mp4,ogg,opus,matroska,mjpeg,null,md5

  # --- parsery ---
  --enable-parser=av1,hevc,h264,vp8,vp9,mpeg4video,mpegvideo,aac,aac_latm,ac3,mpegaudio,opus,vorbis,flac,mjpeg,gif

  # --- bitstream filtry potrzebne przy przepakowywaniu (TS/FLV/Annex-B -> MP4) ---
  --enable-bsf=aac_adtstoasc,h264_mp4toannexb,hevc_mp4toannexb,extract_extradata,vp9_superframe,vp9_superframe_split,av1_frame_merge,av1_frame_split,null,setts

  # --- filtry ---
  --enable-swscale
  --enable-swresample
  --enable-avfilter
  --enable-filter=scale,scale2ref,format,aformat,crop,pad,transpose,hflip,vflip,rotate,fps,setsar,setdar,overlay,thumbnail,aresample,anull,null,copy,trim,atrim,setpts,asetpts,hwupload,hwdownload,hwmap,testsrc2,color,anullsrc,sine,volume
)

# --- akceleracja sprzętowa: zależna od platformy ---------------------------------------------------------------
case "${PLATFORM:-}" in
  windows)
    FFMPEG_FLAGS+=(
      --enable-ffnvcodec --enable-nvenc          # NVIDIA: nvEncodeAPI64.dll ładowany przez sterownik
      --enable-amf                               # AMD: amfrt64.dll ze sterownika
      --enable-libvpl                            # Intel QSV (dispatcher oneVPL; runtime ze sterownika)
      --enable-d3d11va --enable-dxva2            # urządzenia D3D11 (wybór karty, QSV child_device) i dekodowanie sprzętowe
      --enable-encoder=h264_nvenc,hevc_nvenc,h264_amf,hevc_amf,h264_qsv,hevc_qsv
    )
    ;;
  linux)
    FFMPEG_FLAGS+=(
      --enable-ffnvcodec --enable-nvenc          # NVIDIA: libnvidia-encode ładowany przez sterownik (dlopen)
      --enable-encoder=h264_nvenc,hevc_nvenc
    )
    # VAAPI (Intel i AMD): libva budowana STATYCZNIE przez build.sh (build_libva) — dzięki temu plik uruchomi się też na serwerze
    # bez zainstalowanej libva/libdrm; sterownik (iHD / radeonsi) ładuje system przez dlopen w czasie działania
    FFMPEG_FLAGS+=(
      --enable-vaapi
      --enable-encoder=h264_vaapi,hevc_vaapi
    )
    ;;
  macos)
    FFMPEG_FLAGS+=( --enable-videotoolbox --enable-encoder=h264_videotoolbox,hevc_videotoolbox )
    ;;
esac
