// Rozpoznawanie formatu obrazu po pierwszych bajtach („magic numbers”), nie po nazwie ani typie MIME.
// Panel przyjmuje plik tylko, gdy jego zawartość zgadza się z deklarowanym formatem — inaczej aplikacja
// dostałaby np. PNG udający WEBP i po cichu by go nie pokazała. Bez zależności (konwersji formatów nie ma:
// wymagałaby bibliotek graficznych — operator zapisuje obraz jako WEBP we własnym programie).

/** Zwraca "jpg" | "png" | "webp" | "avif" | "jxl" albo null, gdy bajty nie pasują do żadnego z formatów. */
export function sniffImage(buf) {
  if (!buf || buf.length < 2) return null;
  const b = (i) => buf[i];
  const ascii = (from, len) => buf.length >= from + len ? buf.toString("latin1", from, from + len) : "";
  if (b(0) === 0xff && b(1) === 0xd8 && b(2) === 0xff) return "jpg";
  if (ascii(0, 8) === "\x89PNG\r\n\x1a\n") return "png";
  if (ascii(0, 4) === "RIFF" && ascii(8, 4) === "WEBP") return "webp";
  // AVIF: pudełko ftyp z marką avif/avis (główna albo zgodna)
  if (ascii(4, 4) === "ftyp") {
    const boxLen = Math.min(buf.readUInt32BE(0) || 0, buf.length, 64);
    for (let i = 8; i + 4 <= boxLen; i += 4) {
      const brand = ascii(i, 4);
      if (brand === "avif" || brand === "avis") return "avif";
    }
    return null;
  }
  // JPEG XL: goły kodek (FF 0A) albo kontener ISOBMFF („JXL ” po 12-bajtowym pudełku sygnatury)
  if (b(0) === 0xff && b(1) === 0x0a) return "jxl";
  if (buf.length >= 12 && buf.readUInt32BE(0) === 12 && ascii(4, 4) === "JXL ") return "jxl";
  return null;
}

/** Czy rozpoznany format pasuje do rozszerzenia z typu MIME (jpeg = jpg). */
export function formatMatches(sniffed, ext) {
  if (!sniffed) return false;
  const norm = (x) => (x === "jpeg" ? "jpg" : x);
  return norm(sniffed) === norm(ext);
}

/**
 * Dźwięk: "opus" (Ogg z nagłówkiem OpusHead), "webm" (EBML — WebM/Matroska) albo null. Aplikacja odtwarza Opus
 * natywnie (Android dekoduje go sam); inne kodeki w Ogg (np. Vorbis) odrzucamy, bo protokół mówi o Opusie.
 */
export function sniffAudio(buf) {
  if (!buf || buf.length < 4) return null;
  if (buf.toString("latin1", 0, 4) === "OggS") {
    // pierwsza strona Ogg niesie pakiet identyfikacyjny kodeka — dla Opusa zaczyna się od "OpusHead"
    return buf.indexOf("OpusHead", 0, "latin1") >= 0 && buf.indexOf("OpusHead", 0, "latin1") < 512 ? "opus" : null;
  }
  if (buf[0] === 0x1a && buf[1] === 0x45 && buf[2] === 0xdf && buf[3] === 0xa3) return "webm";
  return null;
}

/**
 * Długość pliku Ogg Opus w ms z pozycji granuli ostatniej strony (próbki 48 kHz) minus pre-skip z OpusHead.
 * Bez dekodowania — tylko nagłówki. null, gdy się nie da (np. WebM).
 */
export function oggOpusDurationMs(buf) {
  if (sniffAudio(buf) !== "opus") return null;
  const head = buf.indexOf("OpusHead", 0, "latin1");
  const preSkip = head >= 0 && head + 12 <= buf.length ? buf.readUInt16LE(head + 10) : 0;
  const last = buf.lastIndexOf("OggS", buf.length - 4, "latin1");
  if (last < 0 || last + 14 > buf.length) return null;
  const granule = buf.readBigInt64LE(last + 6);
  if (granule <= 0n) return null;
  const ms = Number(granule - BigInt(preSkip)) / 48;
  return Number.isFinite(ms) && ms > 0 ? Math.round(ms) : null;
}

// --- wideo (MP4) ---
// Czytamy tylko nagłówki MP4 (pudełka moov/trak), bez dekodowania obrazu: kodek, rozdzielczość, długość
// i PRAWDZIWĄ liczbę klatek na sekundę (liczba próbek ścieżki wideo / czas trwania). Protokół pozwala na
// najwyżej 30 kl/s — aplikacja i tak mierzy to sama i odmówi odtworzenia, więc serwer odrzuca to już przy
// wgrywaniu, żeby operator od razu wiedział, że plik trzeba przekodować.

function boxes(buf, start, end) {
  const out = [];
  let p = start;
  while (p + 8 <= end) {
    let size = buf.readUInt32BE(p);
    const type = buf.toString("latin1", p + 4, p + 8);
    let header = 8;
    if (size === 1) { if (p + 16 > end) break; size = Number(buf.readBigUInt64BE(p + 8)); header = 16; }
    else if (size === 0) size = end - p;
    if (size < header || p + size > end) break;
    out.push({ type, at: p, start: p + header, end: p + size });
    p += size;
  }
  return out;
}
const child = (buf, box, type) => boxes(buf, box.start, box.end).find((b) => b.type === type) || null;

/**
 * "faststart": spis pliku (moov) musi stać PRZED danymi (mdat). Aplikacja sprawdza kodek, kl/s i dźwięk
 * z pierwszych kilobajtów i przerywa pobieranie złego filmu — działa to tylko, gdy moov jest na początku.
 * Jeśli plik ma moov na końcu (domyślne wyjście ffmpeg), przenosimy go zaraz za ftyp i przesuwamy
 * przesunięcia porcji (stco / co64) o rozmiar moov. Zwraca nowy bufor, ten sam (już faststart) albo null.
 */
export function mp4FastStart(buf) {
  const top = boxes(buf, 0, buf.length);
  const moovIdx = top.findIndex((b) => b.type === "moov");
  const mdatIdx = top.findIndex((b) => b.type === "mdat");
  if (moovIdx < 0 || mdatIdx < 0) return null;
  if (moovIdx < mdatIdx) return buf;
  const ftyp = top[0]?.type === "ftyp" ? top[0] : null;
  if (!ftyp) return null;
  const moov = Buffer.from(buf.subarray(top[moovIdx].at, top[moovIdx].end));
  const shift = moov.length;
  // przesunięcia porcji w moov wskazują w mdat — po wstawieniu moov przed mdat rosną o jego rozmiar
  const walk = (start, end) => {
    for (const b of boxes(moov, start, end)) {
      if (["trak", "mdia", "minf", "stbl", "edts"].includes(b.type)) walk(b.start, b.end);
      else if (b.type === "stco") {
        const n = moov.readUInt32BE(b.start + 4);
        for (let i = 0; i < n; i++) {
          const p = b.start + 8 + i * 4;
          const v = moov.readUInt32BE(p) + shift;
          if (v > 0xFFFFFFFF) throw new Error("stco overflow");
          moov.writeUInt32BE(v, p);
        }
      } else if (b.type === "co64") {
        const n = moov.readUInt32BE(b.start + 4);
        for (let i = 0; i < n; i++) { const p = b.start + 8 + i * 8; moov.writeBigUInt64BE(moov.readBigUInt64BE(p) + BigInt(shift), p); }
      }
    }
  };
  const mv = boxes(moov, 0, moov.length)[0];
  try { walk(mv.start, mv.end); } catch { return null; }
  const rest = Buffer.concat(top.filter((_, i) => i !== 0 && i !== moovIdx).map((b) => {
    return buf.subarray(b.at, b.end);
  }));
  return Buffer.concat([buf.subarray(0, ftyp.end), moov, rest]);
}

/**
 * Informacje o pierwszej ścieżce wideo pliku MP4 albo null (to nie MP4 / brak ścieżki wideo).
 * codec: "hevc" (hvc1/hev1) | "avc" (avc1/avc3) | inny 4CC; fps liczone z tabeli próbek (stts).
 * fragmented: true, gdy plik jest pofragmentowany (moof) — wtedy liczby klatek nie da się sprawdzić z moov.
 */
export function mp4VideoInfo(buf) {
  // uszkodzony / obcięty plik nie może wywrócić obsługi żądania — traktujemy go jak nieczytelny
  try { return mp4VideoInfoRaw(buf); } catch { return null; }
}

function mp4VideoInfoRaw(buf) {
  if (!buf || buf.length < 12 || buf.toString("latin1", 4, 8) !== "ftyp") return null;
  const top = boxes(buf, 0, buf.length);
  const moov = top.find((b) => b.type === "moov");
  if (!moov) return null;
  const fragmented = top.some((b) => b.type === "moof");
  for (const trak of boxes(buf, moov.start, moov.end).filter((b) => b.type === "trak")) {
    const mdia = child(buf, trak, "mdia");
    const hdlr = mdia && child(buf, mdia, "hdlr");
    if (!hdlr || buf.toString("latin1", hdlr.start + 8, hdlr.start + 12) !== "vide") continue;
    const mdhd = child(buf, mdia, "mdhd");
    let timescale = 0, duration = 0;
    if (mdhd) {
      const v = buf[mdhd.start];
      if (v === 1) { timescale = buf.readUInt32BE(mdhd.start + 20); duration = Number(buf.readBigUInt64BE(mdhd.start + 24)); }
      else { timescale = buf.readUInt32BE(mdhd.start + 12); duration = buf.readUInt32BE(mdhd.start + 16); }
    }
    const stbl = child(buf, child(buf, mdia, "minf") || mdia, "stbl");
    const stsd = stbl && child(buf, stbl, "stsd");
    if (!stsd) return null;
    const entry = stsd.start + 8; // fullbox (4) + entry_count (4)
    const fourcc = buf.toString("latin1", entry + 4, entry + 8);
    const width = buf.readUInt16BE(entry + 32);
    const height = buf.readUInt16BE(entry + 34);
    const codec = fourcc === "hvc1" || fourcc === "hev1" ? "hevc" : fourcc === "avc1" || fourcc === "avc3" ? "avc" : fourcc;
    const stts = child(buf, stbl, "stts");
    let samples = 0;
    if (stts) {
      const n = buf.readUInt32BE(stts.start + 4);
      for (let i = 0; i < n && stts.start + 8 + i * 8 + 8 <= stts.end; i += 1) samples += buf.readUInt32BE(stts.start + 8 + i * 8);
    }
    const seconds = timescale ? duration / timescale : 0;
    const fps = samples && seconds ? samples / seconds : null;
    return { codec, width, height, durationMs: seconds ? Math.round(seconds * 1000) : null, fps: fps ? Math.round(fps * 100) / 100 : null, fragmented };
  }
  return null;
}

/**
 * Kodek pierwszej ścieżki DŹWIĘKOWEJ pliku MP4 (4CC z stsd: "Opus", "mp4a" = AAC, ".mp3", "ac-3"…) albo null,
 * gdy film jest niemy. Aplikacja akceptuje w filmach wyłącznie Opus — serwer odrzuca resztę przy wgrywaniu.
 */
export function mp4AudioCodec(buf) {
  if (!buf || buf.length < 12 || buf.toString("latin1", 4, 8) !== "ftyp") return null;
  const moov = boxes(buf, 0, buf.length).find((b) => b.type === "moov");
  if (!moov) return null;
  for (const trak of boxes(buf, moov.start, moov.end).filter((b) => b.type === "trak")) {
    const mdia = child(buf, trak, "mdia");
    const hdlr = mdia && child(buf, mdia, "hdlr");
    if (!hdlr || buf.toString("latin1", hdlr.start + 8, hdlr.start + 12) !== "soun") continue;
    const stbl = child(buf, child(buf, mdia, "minf") || mdia, "stbl");
    const stsd = stbl && child(buf, stbl, "stsd");
    if (!stsd) return "unknown";
    return buf.toString("latin1", stsd.start + 12, stsd.start + 16);
  }
  return null;
}

/** WebM/Matroska: czy dźwięk to Opus (CodecID „A_OPUS") i nie ma innej ścieżki dźwiękowej. */
export function webmAudioIsOpus(buf) {
  const s = buf.toString("latin1", 0, Math.min(buf.length, 64 * 1024));
  const codecs = s.match(/A_[A-Z0-9/_.-]{2,24}/g) || [];
  return codecs.length > 0 && codecs.every((c) => c.startsWith("A_OPUS"));
}
