import { KhatmError, derBool, derOctet, derSmallInt, derUtf8, fromB64, tlv, utf8 } from "./bytes.ts";

export type Plist =
  | string
  | number
  | boolean
  | Uint8Array
  | Plist[]
  | { [key: string]: Plist };

export type PlistDict = { [key: string]: Plist };

const PLIST_HEADER =
  `<?xml version="1.0" encoding="UTF-8"?>\n` +
  `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
  `<plist version="1.0">\n`;

export function isDict(value: Plist): value is PlistDict {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array);
}

export function parsePlist(bytes: Uint8Array): Plist {
  if (bytes.length >= 8 && new TextDecoder().decode(bytes.subarray(0, 8)) === "bplist00") return parseBplist(bytes);
  const text = new TextDecoder().decode(bytes).replace(/^\uFEFF/, "");
  return parseXmlPlist(text);
}

export function parseXmlPlist(text: string): Plist {
  const src = text.replace(/^\uFEFF/, "").trim();
  const plistAt = src.indexOf("<plist");
  const body = plistAt >= 0 ? src.slice(plistAt) : src;
  const p = new XmlP(body);
  if (body.startsWith("<plist")) {
    p.skipUntil(">");
    p.i++;
    const value = p.value();
    return value;
  }
  return p.value();
}

/** Exact bytes sealed into the entitlements blob. A bare dict is wrapped; a full plist is kept. */
export function sealEntitlementsXml(source: string): { xml: Uint8Array; dict: PlistDict } {
  const trimmed = source.replace(/^\uFEFF/, "").trim();
  if (!trimmed) throw new KhatmError("entitlements", "Entitlements plist is empty.");
  const parsed = parseXmlPlist(trimmed);
  if (!isDict(parsed)) throw new KhatmError("entitlements", "Entitlements root must be a dict.");
  const hasWrapper = trimmed.includes("<plist");
  const text = hasWrapper ? trimmed.endsWith("\n") ? trimmed : `${trimmed}\n` : `${PLIST_HEADER}${emitValue(parsed, 0)}</plist>\n`;
  return { xml: utf8(text), dict: parsed };
}

export function emitEntitlements(dict: PlistDict): string {
  return `${PLIST_HEADER}${emitValue(dict, 0)}</plist>\n`;
}

function emitValue(value: Plist, indent: number): string {
  const pad = "\t".repeat(indent);
  const inner = "\t".repeat(indent + 1);
  if (typeof value === "boolean") return `${pad}${value ? "<true/>" : "<false/>"}\n`;
  if (typeof value === "number") return `${pad}<integer>${value}</integer>\n`;
  if (typeof value === "string") return `${pad}<string>${escapeXml(value)}</string>\n`;
  if (value instanceof Uint8Array) return `${pad}<data>${fromBytesB64(value)}</data>\n`;
  if (Array.isArray(value)) {
    return `${pad}<array>\n${value.map((v) => emitValue(v, indent + 1)).join("")}${pad}</array>\n`;
  }
  const keys = Object.keys(value);
  const rows = keys.map((k) => `${inner}<key>${escapeXml(k)}</key>\n${emitValue(value[k], indent + 1)}`).join("");
  return `${pad}<dict>\n${rows}${pad}</dict>\n`;
}

function escapeXml(s: string): string {
  return s.replaceAll("\u0026", "\u0026amp;").replaceAll("<", "\u0026lt;").replaceAll(">", "\u0026gt;");
}

function fromBytesB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

class XmlP {
  i = 0;
  src: string;
  constructor(src: string) {
    this.src = src;
  }

  value(): Plist {
    this.skipWs();
    if (this.src.startsWith("<dict", this.i)) return this.dict();
    if (this.src.startsWith("<array", this.i)) return this.array();
    if (this.src.startsWith("<string", this.i)) return this.textish("string");
    if (this.src.startsWith("<integer", this.i)) return Number(this.textish("integer"));
    if (this.src.startsWith("<real", this.i)) throw new KhatmError("plist", "real is not supported in entitlements.");
    if (this.src.startsWith("<data", this.i)) return fromB64(this.textish("data"));
    if (this.src.startsWith("<true", this.i)) {
      this.skipEmpty("true");
      return true;
    }
    if (this.src.startsWith("<false", this.i)) {
      this.skipEmpty("false");
      return false;
    }
    if (this.src.startsWith("<key", this.i)) throw new KhatmError("plist", "Key without a value.");
    throw new KhatmError("plist", `Unrecognized XML near: ${this.src.slice(this.i, this.i + 40)}`);
  }

  dict(): PlistDict {
    this.expectOpen("dict");
    const out: PlistDict = {};
    for (;;) {
      this.skipWs();
      if (this.src.startsWith("</dict>", this.i)) {
        this.i += 7;
        return out;
      }
      if (!this.src.startsWith("<key", this.i)) throw new KhatmError("plist", "dict expected a key.");
      const key = String(this.textish("key"));
      out[key] = this.value();
    }
  }

  array(): Plist[] {
    this.expectOpen("array");
    const out: Plist[] = [];
    for (;;) {
      this.skipWs();
      if (this.src.startsWith("</array>", this.i)) {
        this.i += 8;
        return out;
      }
      out.push(this.value());
    }
  }

  textish(tag: string): string {
    this.skipUntil(">");
    if (this.src[this.i - 1] === "/" || this.src.startsWith("/>", this.i - 1)) {
      // self-closing handled below
    }
    if (this.src[this.i] === ">" && this.src[this.i - 1] === "/") {
      this.i++;
      return "";
    }
    if (this.src[this.i] !== ">") {
      // skipUntil left us on '>'
    }
    if (this.src[this.i] === ">") this.i++;
    const end = this.src.indexOf(`</${tag}>`, this.i);
    if (end < 0) throw new KhatmError("plist", `Tag ${tag} is not closed.`);
    const raw = this.src.slice(this.i, end);
    this.i = end + tag.length + 3;
    return decodeXml(raw);
  }

  expectOpen(tag: string) {
    this.skipWs();
    if (!this.src.startsWith(`<${tag}`, this.i)) throw new KhatmError("plist", `Expected <${tag}>.`);
    this.skipUntil(">");
    this.i++;
  }

  skipEmpty(tag: string) {
    this.skipWs();
    this.skipUntil(">");
    this.i++;
    if (this.src.startsWith(`</${tag}>`, this.i)) this.i += tag.length + 3;
  }

  skipWs() {
    while (this.i < this.src.length && /\s/.test(this.src[this.i])) this.i++;
  }

  skipUntil(ch: string) {
    const at = this.src.indexOf(ch, this.i);
    if (at < 0) throw new KhatmError("plist", "Truncated XML.");
    this.i = at;
  }
}

function decodeXml(s: string): string {
  return s
    .replaceAll("\u0026lt;", "<")
    .replaceAll("\u0026gt;", ">")
    .replaceAll("\u0026quot;", '"')
    .replaceAll("\u0026apos;", "'")
    .replaceAll("\u0026amp;", "\u0026");
}

export function infoKeys(bytes: Uint8Array): { bundleId: string; executable: string; name: string; version: string; title: string } {
  const parsed = parsePlist(bytes);
  if (!isDict(parsed)) throw new KhatmError("plist", "Info.plist is not a dict.");
  const text = (value: unknown) => (typeof value === "string" ? value : "");
  const bundleId = text(parsed.CFBundleIdentifier);
  const executable = text(parsed.CFBundleExecutable);
  const name = text(parsed.CFBundleName) || bundleId;
  const version = text(parsed.CFBundleVersion) || text(parsed.CFBundleShortVersionString) || "1.0";
  const title = text(parsed.CFBundleDisplayName) || name;
  if (!bundleId || !executable) throw new KhatmError("plist", "Info.plist has no CFBundleIdentifier or CFBundleExecutable.");
  return { bundleId, executable, name, version, title };
}

export function replaceBundleId(bytes: Uint8Array, bundleId: string): Uint8Array {
  const parsed = parsePlist(bytes);
  if (!isDict(parsed)) throw new KhatmError("plist", "Info.plist is not a dict.");
  parsed.CFBundleIdentifier = bundleId;
  return utf8(emitEntitlements(parsed));
}

/**
 * Apple DER entitlements: APPLICATION [16] { INTEGER 1, CONTEXT [16] { SEQUENCE { UTF8String, value }... } }.
 * Keys are sorted. This is the payload after the 0xfade7172 blob header.
 */
export function derEntitlements(dict: PlistDict): Uint8Array {
  const body = concatParts([derSmallInt(1), derDict(dict)]);
  return tlv(0x70, body);
}

function derDict(dict: PlistDict): Uint8Array {
  const keys = Object.keys(dict).sort();
  const pairs = keys.map((key) => tlv(0x30, concatParts([derUtf8(key), derValue(dict[key])])));
  return tlv(0xb0, concatParts(pairs));
}

function derValue(value: Plist): Uint8Array {
  if (typeof value === "boolean") return derBool(value);
  if (typeof value === "string") return derUtf8(value);
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
      throw new KhatmError("entitlements", "Entitlement integers must be in 0 .. 2^32-1.");
    }
    return derSmallInt(value);
  }
  if (value instanceof Uint8Array) return derOctet(value);
  if (Array.isArray(value)) return tlv(0x30, concatParts(value.map(derValue)));
  return derDict(value);
}

function concatParts(parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function parseBplist(bytes: Uint8Array): Plist {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const trailer = bytes.length - 32;
  const offsetSize = bytes[trailer + 6];
  const refSize = bytes[trailer + 7];
  const count = readBE(view, trailer + 8, 8);
  const top = readBE(view, trailer + 16, 8);
  const table = readBE(view, trailer + 24, 8);
  const offsetOf = (index: number) => readBE(view, table + index * offsetSize, offsetSize);
  const cache = new Map<number, Plist>();
  const readObj = (index: number): Plist => {
    const hit = cache.get(index);
    if (hit !== undefined) return hit;
    const at = offsetOf(index);
    const marker = bytes[at];
    const high = marker >> 4;
    let low = marker & 0x0f;
    let cursor = at + 1;
    const readLen = (): number => {
      if (low !== 0x0f) return low;
      const sizeMarker = bytes[cursor];
      const sizeOfSize = 1 << (sizeMarker & 0x0f);
      cursor++;
      const n = readBE(view, cursor, sizeOfSize);
      cursor += sizeOfSize;
      return n;
    };
    if (marker === 0x00) return null as unknown as Plist;
    if (marker === 0x08) return false;
    if (marker === 0x09) return true;
    if (high === 0x1) {
      const size = 1 << low;
      const n = readBE(view, cursor, size);
      return n;
    }
    if (high === 0x2) return view.getFloat64(cursor);
    if (high === 0x3) return "date";
    if (high === 0x8) return readBE(view, cursor, low === 0 ? 1 : low);
    if (high === 0x4) {
      const len = readLen();
      return bytes.slice(cursor, cursor + len);
    }
    if (high === 0x5) {
      const len = readLen();
      return new TextDecoder().decode(bytes.subarray(cursor, cursor + len));
    }
    if (high === 0x6) {
      const len = readLen();
      return new TextDecoder("utf-16be").decode(bytes.subarray(cursor, cursor + len));
    }
    if (high === 0xa || high === 0xd) {
      const len = readLen();
      const refs: number[] = [];
      for (let i = 0; i < (high === 0xd ? len * 2 : len); i++) {
        refs.push(readBE(view, cursor + i * refSize, refSize));
      }
      if (high === 0xa) {
        const arr: Plist[] = [];
        cache.set(index, arr);
        for (let i = 0; i < len; i++) arr.push(readObj(refs[i]));
        return arr;
      }
      const dict: PlistDict = {};
      cache.set(index, dict);
      for (let i = 0; i < len; i++) {
        const key = readObj(refs[i]);
        if (typeof key !== "string") throw new KhatmError("plist", "bplist key is not a string.");
        dict[key] = readObj(refs[len + i]);
      }
      return dict;
    }
    throw new KhatmError("plist", `Unsupported bplist object: 0x${marker.toString(16)}`);
  };
  void count;
  return readObj(top);
}

function readBE(view: DataView, offset: number, size: number): number {
  let n = 0;
  for (let i = 0; i < size; i++) n = n * 256 + view.getUint8(offset + i);
  return n;
}
