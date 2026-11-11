// S-01: usuwanie metadanych z wgrywanych plików — bez zależności. Zdjęcie z telefonu niesie zwykle EXIF
// (współrzędne GPS, czas, model aparatu), a film — lokalizację w `udta`/`meta`. Serwer publikuje pliki każdemu,
// więc bez tego mógłby ujawnić, gdzie mieszka operator albo autor. Obraz i dźwięk zostają bajt w bajt — znikają
// tylko bloki metadanych.
//
//   JPEG  – segmenty APP1 (Exif/XMP), APP2 poza profilem ICC (np. MPF z dodatkowymi zdjęciami), APP3–APP13,
//           APP15, COM oraz wszystko po końcu obrazu (EOI). Zostają APP0 (JFIF), APP14 (Adobe), ICC.
//   PNG   – eXIf, tEXt, zTXt, iTXt, tIME.
//   WEBP  – chunki EXIF i XMP + flagi w VP8X.
//   JXL   – pudełka Exif, xml , jumb (także skompresowane brob) w kontenerze; goły kodek metadanych nie ma.
//   AVIF  – dane elementów Exif i XMP (mime application/rdf+xml) zerowane w miejscu (przesunięcia bez zmian).
//   MP4   – pudełka udta, meta i uuid w moov i trak (oraz na najwyższym poziomie); stco/co64 przeliczane.
//
// Funkcje zwracają nowy bufor (albo ten sam, gdy nie było czego usuwać) lub null, gdy pliku nie da się
// bezpiecznie przetworzyć (wtedy serwer odrzuca plik zamiast publikować go z metadanymi).

/** Obraz bez metadanych albo null. kind: "jpg" | "png" | "webp" | "jxl" | "avif" (z sniffImage). */
export function stripImageMetadata(buf, kind) {
  try {
    if (kind === "jpg") return stripJpeg(buf);
    if (kind === "png") return stripPng(buf);
    if (kind === "webp") return stripWebp(buf);
    if (kind === "jxl") return stripJxl(buf);
    if (kind === "avif") return stripAvif(buf);
  } catch { /* uszkodzony plik */ }
  return null;
}

// --- JPEG ---
function stripJpeg(buf) {
  if (buf[0] !== 0xff || buf[1] !== 0xd8) return null;
  const out = [buf.subarray(0, 2)];
  let p = 2;
  while (p < buf.length) {
    if (buf[p] !== 0xff) return null;
    while (p < buf.length && buf[p] === 0xff && buf[p + 1] === 0xff) p += 1; // bajty wypełnienia
    const marker = buf[p + 1];
    if (marker === undefined) return null;
    if (marker === 0xd9) { out.push(buf.subarray(p, p + 2)); return Buffer.concat(out); } // EOI bez obrazu
    if ((marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) { out.push(buf.subarray(p, p + 2)); p += 2; continue; }
    if (p + 4 > buf.length) return null;
    const len = buf.readUInt16BE(p + 2);
    if (len < 2 || p + 2 + len > buf.length) return null;
    const seg = buf.subarray(p, p + 2 + len);
    if (marker === 0xda) {
      // SOS: dalej dane obrazu (z kolejnymi skanami JPEG progresywnego) aż do EOI — reszta pliku za EOI
      // (np. dodatkowe zdjęcia MPF z własnym EXIF) odpada
      const eoi = findEoi(buf, p + 2 + len);
      if (eoi < 0) return null;
      out.push(buf.subarray(p, eoi + 2));
      return Buffer.concat(out);
    }
    if (!dropJpegSegment(marker, seg)) out.push(seg);
    p += 2 + len;
  }
  return null;
}

function dropJpegSegment(marker, seg) {
  if (marker === 0xfe) return true; // COM
  if (marker === 0xe2) return seg.toString("latin1", 4, 15) !== "ICC_PROFILE"; // APP2: tylko profil kolorów
  if (marker === 0xe0 || marker === 0xee) return false; // APP0 JFIF, APP14 Adobe (potrzebny do kolorów)
  return marker >= 0xe1 && marker <= 0xef; // pozostałe APPn: Exif, XMP, IPTC, dane producentów
}

function findEoi(buf, from) {
  for (let i = from; i + 1 < buf.length; i += 1) {
    if (buf[i] !== 0xff) continue;
    const m = buf[i + 1];
    if (m === 0xd9) return i;
    // w danych obrazu 0xFF jest zawsze 0xFF00 (wypełnienie), RSTn albo znacznikiem między skanami
  }
  return -1;
}

// --- PNG ---
const PNG_DROP = new Set(["eXIf", "tEXt", "zTXt", "iTXt", "tIME"]);
function stripPng(buf) {
  if (buf.toString("latin1", 0, 8) !== "\x89PNG\r\n\x1a\n") return null;
  const out = [buf.subarray(0, 8)];
  let p = 8;
  while (p + 12 <= buf.length) {
    const len = buf.readUInt32BE(p);
    const type = buf.toString("latin1", p + 4, p + 8);
    const end = p + 12 + len;
    if (end > buf.length) return null;
    if (!PNG_DROP.has(type)) out.push(buf.subarray(p, end));
    p = end;
    if (type === "IEND") return Buffer.concat(out);
  }
  return null;
}

// --- WEBP ---
function stripWebp(buf) {
  if (buf.toString("latin1", 0, 4) !== "RIFF" || buf.toString("latin1", 8, 12) !== "WEBP") return null;
  const chunks = [];
  let p = 12;
  while (p + 8 <= buf.length) {
    const type = buf.toString("latin1", p, p + 4);
    const size = buf.readUInt32LE(p + 4);
    const end = p + 8 + size + (size & 1);
    if (p + 8 + size > buf.length) return null;
    if (type !== "EXIF" && type !== "XMP ") {
      const c = Buffer.from(buf.subarray(p, Math.min(end, buf.length)));
      if (type === "VP8X" && size >= 1) c[8] &= ~(0x08 | 0x04); // flagi EXIF i XMP
      chunks.push(c);
    }
    p = end;
  }
  const body = Buffer.concat(chunks);
  const head = Buffer.alloc(12);
  head.write("RIFF", 0, "latin1");
  head.writeUInt32LE(body.length + 4, 4);
  head.write("WEBP", 8, "latin1");
  return Buffer.concat([head, body]);
}

// --- pudełka ISOBMFF (JXL, AVIF, MP4) ---
function boxes(buf, start, end) {
  const out = [];
  let p = start;
  while (p + 8 <= end) {
    let size = buf.readUInt32BE(p);
    const type = buf.toString("latin1", p + 4, p + 8);
    let header = 8;
    if (size === 1) {
      if (p + 16 > end) throw new Error("box");
      size = Number(buf.readBigUInt64BE(p + 8));
      header = 16;
    } else if (size === 0) size = end - p;
    if (size < header || size > end - p) throw new Error("box");
    out.push({ type, at: p, start: p + header, end: p + size, header });
    p += size;
  }
  // dopuszczamy tylko zerowe dopełnienie (< 8 B, np. terminator 32-bit w starych plikach QuickTime)
  for (let i = p; i < end; i += 1) if (buf[i] !== 0) throw new Error("box");
  return out;
}

// --- JPEG XL ---
const JXL_DROP = new Set(["Exif", "xml ", "jumb"]);
function stripJxl(buf) {
  if (buf[0] === 0xff && buf[1] === 0x0a) return buf; // goły kodek — bez metadanych
  const top = boxes(buf, 0, buf.length);
  const keep = top.filter((b) => {
    if (JXL_DROP.has(b.type)) return false;
    if (b.type === "brob") return !JXL_DROP.has(buf.toString("latin1", b.start, b.start + 4));
    return true;
  });
  if (keep.length === top.length) return buf;
  return Buffer.concat(keep.map((b) => buf.subarray(b.at, b.end)));
}

// --- AVIF ---
function stripAvif(buf) {
  const top = boxes(buf, 0, buf.length);
  const meta = top.find((b) => b.type === "meta");
  if (!meta) return buf;
  const inner = boxes(buf, meta.start + 4, meta.end); // meta to FullBox
  const iinf = inner.find((b) => b.type === "iinf");
  const iloc = inner.find((b) => b.type === "iloc");
  if (!iinf || !iloc) return buf;
  const ids = metadataItemIds(buf, iinf);
  if (!ids.size) return buf;
  const out = Buffer.from(buf);
  const idat = inner.find((b) => b.type === "idat");
  for (const ext of ilocExtents(buf, iloc)) {
    if (!ids.has(ext.id)) continue;
    let from;
    if (ext.method === 0) from = ext.offset;
    else if (ext.method === 1 && idat) from = idat.start + ext.offset;
    else return null; // inna metoda konstrukcji — nie zgadujemy
    const len = ext.length || (ext.method === 0 ? buf.length - from : idat.end - from);
    if (from < 0 || from + len > buf.length) return null;
    out.fill(0, from, from + len);
  }
  return out;
}

function readCString(buf, p, end) {
  let e = p;
  while (e < end && buf[e] !== 0) e += 1;
  return { s: buf.toString("utf8", p, e), next: e + 1 };
}

function metadataItemIds(buf, iinf) {
  const ids = new Set();
  const v = buf[iinf.start];
  const countSize = v === 0 ? 2 : 4;
  const first = iinf.start + 4 + countSize;
  for (const infe of boxes(buf, first, iinf.end)) {
    if (infe.type !== "infe") continue;
    const ver = buf[infe.start];
    if (ver < 2) continue;
    let p = infe.start + 4;
    const id = ver === 2 ? buf.readUInt16BE(p) : buf.readUInt32BE(p);
    p += ver === 2 ? 2 : 4;
    p += 2; // item_protection_index
    const type = buf.toString("latin1", p, p + 4);
    p += 4;
    const name = readCString(buf, p, infe.end);
    if (type === "Exif") ids.add(id);
    else if (type === "mime") {
      const ct = readCString(buf, name.next, infe.end).s.toLowerCase();
      if (ct.includes("rdf+xml") || ct.includes("xmp")) ids.add(id);
    }
  }
  return ids;
}

function readN(buf, p, n) {
  if (n === 0) return 0;
  if (n === 4) return buf.readUInt32BE(p);
  if (n === 8) return Number(buf.readBigUInt64BE(p));
  if (n === 2) return buf.readUInt16BE(p);
  throw new Error("iloc");
}

function ilocExtents(buf, iloc) {
  const v = buf[iloc.start];
  let p = iloc.start + 4;
  const offsetSize = buf[p] >> 4, lengthSize = buf[p] & 15;
  const baseSize = buf[p + 1] >> 4, indexSize = v === 1 || v === 2 ? buf[p + 1] & 15 : 0;
  p += 2;
  const count = v < 2 ? buf.readUInt16BE(p) : buf.readUInt32BE(p);
  p += v < 2 ? 2 : 4;
  const out = [];
  for (let i = 0; i < count; i += 1) {
    const id = v < 2 ? buf.readUInt16BE(p) : buf.readUInt32BE(p);
    p += v < 2 ? 2 : 4;
    let method = 0;
    if (v === 1 || v === 2) { method = buf.readUInt16BE(p) & 15; p += 2; }
    p += 2; // data_reference_index
    const base = readN(buf, p, baseSize);
    p += baseSize;
    const extents = buf.readUInt16BE(p);
    p += 2;
    for (let j = 0; j < extents; j += 1) {
      p += indexSize;
      const off = readN(buf, p, offsetSize);
      p += offsetSize;
      const len = readN(buf, p, lengthSize);
      p += lengthSize;
      out.push({ id, method, offset: base + off, length: len });
    }
    if (p > iloc.end) throw new Error("iloc");
  }
  return out;
}

// --- MP4 ---
const MP4_DROP = new Set(["udta", "meta", "uuid"]);

function rebuild(buf, box) {
  const parts = [];
  for (const c of boxes(buf, box.start, box.end)) {
    if (MP4_DROP.has(c.type)) continue;
    parts.push(c.type === "trak" ? rebuild(buf, c) : buf.subarray(c.at, c.end));
  }
  const body = Buffer.concat(parts);
  const head = Buffer.alloc(8);
  head.writeUInt32BE(8 + body.length, 0);
  head.write(box.type, 4, "latin1");
  return Buffer.concat([head, body]);
}

/**
 * MP4 bez udta/meta/uuid (lokalizacja, nazwa urządzenia, XMP) w moov, trak i na najwyższym poziomie.
 * Przesunięcia porcji (stco/co64) wskazują w mdat — liczymy je od nowa wg nowego położenia pudełek.
 */
export function mp4StripMetadata(buf) {
  try {
    const top = boxes(buf, 0, buf.length);
    if (!top.length || top[0].type !== "ftyp" || !top.some((b) => b.type === "moov")) return null;
    const kept = [];
    let pos = 0;
    for (const b of top) {
      if (MP4_DROP.has(b.type)) continue;
      const data = b.type === "moov" ? rebuild(buf, b) : buf.subarray(b.at, b.end);
      kept.push({ old: b, data, at: pos });
      pos += data.length;
    }
    const moov = kept.find((k) => k.old.type === "moov").data;
    const remap = (off) => {
      const k = kept.find((x) => x.old.type !== "moov" && off >= x.old.at && off < x.old.end);
      if (!k) throw new Error("offset");
      return off - k.old.at + k.at;
    };
    const walk = (start, end) => {
      for (const b of boxes(moov, start, end)) {
        if (["trak", "mdia", "minf", "stbl"].includes(b.type)) walk(b.start, b.end);
        else if (b.type === "mvhd" || b.type === "tkhd" || b.type === "mdhd") {
          // data utworzenia i modyfikacji (ślad urządzenia/czasu nagrania)
          const v = moov[b.start];
          if (v === 1) moov.fill(0, b.start + 4, b.start + 20); else moov.fill(0, b.start + 4, b.start + 12);
        } else if (b.type === "hdlr") {
          // nazwa obsługi (np. „VideoHandler”, nazwa kodera) — po 24 bajtach nagłówka
          if (b.end - b.start > 24) moov.fill(0, b.start + 24, b.end);
        } else if (b.type === "stco") {
          const n = moov.readUInt32BE(b.start + 4);
          for (let i = 0; i < n; i += 1) {
            const p = b.start + 8 + i * 4;
            const v = remap(moov.readUInt32BE(p));
            if (v > 0xffffffff) throw new Error("stco");
            moov.writeUInt32BE(v, p);
          }
        } else if (b.type === "co64") {
          const n = moov.readUInt32BE(b.start + 4);
          for (let i = 0; i < n; i += 1) {
            const p = b.start + 8 + i * 8;
            moov.writeBigUInt64BE(BigInt(remap(Number(moov.readBigUInt64BE(p)))), p);
          }
        }
      }
    };
    walk(8, moov.length);
    const result = Buffer.concat(kept.map((k) => k.data));
    return result.length === buf.length && result.equals(buf) ? buf : result;
  } catch {
    return null;
  }
}
