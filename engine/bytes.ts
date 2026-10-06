/** Shared byte, hash, and DER helpers. Layout comments cite xnu osfmk/kern/cs_blobs.h. */

export class KhatmError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "KhatmError";
    this.code = code;
  }
}

export function concat(...parts: Uint8Array[]): Uint8Array {
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

export function u32(value: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, value >>> 0, false);
  return b;
}

export function u64(value: number | bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(value), false);
  return b;
}

export function align(n: number, a: number): number {
  return (n + a - 1) & ~(a - 1);
}

export function ascii(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function hex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function ownedBuffer(data: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(data.byteLength);
  new Uint8Array(copy).set(data);
  return copy;
}

export async function digest(alg: "SHA-256" | "SHA-1", data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest(alg, ownedBuffer(data));
  return new Uint8Array(buf);
}

export function sha256(data: Uint8Array): Promise<Uint8Array> {
  return digest("SHA-256", data);
}

export function b64(bytes: Uint8Array): string {
  let s = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(s);
}

export function fromB64(text: string): Uint8Array {
  const bin = atob(text.replace(/\s+/g, ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function pemArmor(label: string, der: Uint8Array): string {
  const raw = b64(der);
  const lines: string[] = [];
  for (let i = 0; i < raw.length; i += 64) lines.push(raw.slice(i, i + 64));
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/** DER tag-length-value. Shortest definite length, no indefinite form. */
export function tlv(tag: number, content: Uint8Array): Uint8Array {
  const len = content.length;
  let head: Uint8Array;
  if (len < 0x80) head = new Uint8Array([tag, len]);
  else if (len <= 0xff) head = new Uint8Array([tag, 0x81, len]);
  else if (len <= 0xffff) head = new Uint8Array([tag, 0x82, len >> 8, len & 0xff]);
  else if (len <= 0xffffff) head = new Uint8Array([tag, 0x83, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff]);
  else throw new KhatmError("der", "DER value is longer than this engine supports.");
  return concat(head, content);
}

export function derSeq(...parts: Uint8Array[]): Uint8Array {
  return tlv(0x30, concat(...parts));
}

export function derSet(members: Uint8Array[]): Uint8Array {
  const sorted = [...members].sort(compareBytes);
  return tlv(0x31, concat(...sorted));
}

export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

export function derOctet(bytes: Uint8Array): Uint8Array {
  return tlv(0x04, bytes);
}

export function derNull(): Uint8Array {
  return new Uint8Array([0x05, 0x00]);
}

export function derBool(value: boolean): Uint8Array {
  return new Uint8Array([0x01, 0x01, value ? 0xff : 0x00]);
}

export function derUtf8(s: string): Uint8Array {
  return tlv(0x0c, utf8(s));
}

/** Unsigned big-endian integer as a DER INTEGER (leading 0x00 if the high bit is set). */
export function derIntegerBytes(unsigned: Uint8Array): Uint8Array {
  let i = 0;
  while (i < unsigned.length - 1 && unsigned[i] === 0) i++;
  let body = unsigned.subarray(i);
  if (body[0] & 0x80) body = concat(new Uint8Array([0x00]), body);
  return tlv(0x02, body);
}

export function derSmallInt(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new KhatmError("der", "Integer is outside the supported range.");
  }
  if (n === 0) return new Uint8Array([0x02, 0x01, 0x00]);
  const tmp: number[] = [];
  let v = n;
  while (v > 0) {
    tmp.push(v & 0xff);
    v = Math.floor(v / 256);
  }
  tmp.reverse();
  return derIntegerBytes(new Uint8Array(tmp));
}

export function derOid(parts: number[]): Uint8Array {
  if (parts.length < 2) throw new KhatmError("der", "Truncated OID.");
  const body: number[] = [parts[0] * 40 + parts[1]];
  for (let p = 2; p < parts.length; p++) {
    const stack: number[] = [];
    let n = parts[p];
    stack.push(n & 0x7f);
    n = Math.floor(n / 128);
    while (n > 0) {
      stack.push((n & 0x7f) | 0x80);
      n = Math.floor(n / 128);
    }
    while (stack.length) body.push(stack.pop() as number);
  }
  return tlv(0x06, new Uint8Array(body));
}

export function derBitString(payload: Uint8Array): Uint8Array {
  return tlv(0x03, concat(new Uint8Array([0x00]), payload));
}

export function derUtcTime(date: Date): Uint8Array {
  const p = (n: number) => n.toString().padStart(2, "0");
  const text =
    p(date.getUTCFullYear() % 100) +
    p(date.getUTCMonth() + 1) +
    p(date.getUTCDate()) +
    p(date.getUTCHours()) +
    p(date.getUTCMinutes()) +
    p(date.getUTCSeconds()) +
    "Z";
  return tlv(0x17, ascii(text));
}

export type Tlv = {
  tag: number;
  headerStart: number;
  contentStart: number;
  contentEnd: number;
  end: number;
  content: Uint8Array;
  raw: Uint8Array;
};

export function readTlv(buf: Uint8Array, offset: number): Tlv {
  if (offset >= buf.length) throw new KhatmError("der", "Truncated DER.");
  const tag = buf[offset];
  let i = offset + 1;
  if (i >= buf.length) throw new KhatmError("der", "Truncated DER length.");
  let len = buf[i++];
  if (len === 0x80) throw new KhatmError("der", "Indefinite length is rejected. DER only.");
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || i + n > buf.length) throw new KhatmError("der", "Invalid DER length.");
    len = 0;
    for (let k = 0; k < n; k++) len = (len << 8) | buf[i++];
  }
  const contentStart = i;
  const contentEnd = i + len;
  if (contentEnd > buf.length) throw new KhatmError("der", "DER content runs past the buffer.");
  return {
    tag,
    headerStart: offset,
    contentStart,
    contentEnd,
    end: contentEnd,
    content: buf.subarray(contentStart, contentEnd),
    raw: buf.subarray(offset, contentEnd),
  };
}

export function readSequence(buf: Uint8Array, offset = 0): Tlv {
  const t = readTlv(buf, offset);
  if (t.tag !== 0x30) throw new KhatmError("der", `expected SEQUENCE, got 0x${t.tag.toString(16)}.`);
  return t;
}

export function sequenceItems(buf: Uint8Array, offset = 0): Tlv[] {
  const seq = readSequence(buf, offset);
  const out: Tlv[] = [];
  let o = seq.contentStart;
  while (o < seq.contentEnd) {
    const item = readTlv(buf, o);
    out.push(item);
    o = item.end;
  }
  if (o !== seq.contentEnd) throw new KhatmError("der", "SEQUENCE was not fully consumed.");
  return out;
}

export const OID = {
  sha256: derOid([2, 16, 840, 1, 101, 3, 4, 2, 1]),
  sha256WithRsa: derOid([1, 2, 840, 113549, 1, 1, 11]),
  rsaEncryption: derOid([1, 2, 840, 113549, 1, 1, 1]),
  ecPublicKey: derOid([1, 2, 840, 10045, 2, 1]),
  ecdsaWithSha256: derOid([1, 2, 840, 10045, 4, 3, 2]),
  prime256v1: derOid([1, 2, 840, 10045, 3, 1, 7]),
  secp384r1: derOid([1, 3, 132, 0, 34]),
  idData: derOid([1, 2, 840, 113549, 1, 7, 1]),
  idSignedData: derOid([1, 2, 840, 113549, 1, 7, 2]),
  attrContentType: derOid([1, 2, 840, 113549, 1, 9, 3]),
  attrMessageDigest: derOid([1, 2, 840, 113549, 1, 9, 4]),
  attrSigningTime: derOid([1, 2, 840, 113549, 1, 9, 5]),
  /** XML plist of truncated cdhashes. relic AttrCodeDirHashPlist. */
  attrAppleCdhashPlist: derOid([1, 2, 840, 113635, 100, 9, 1]),
  /** SET of { algorithm, full digest }. relic AttrCodeDirHashes. */
  attrAppleCdhashes: derOid([1, 2, 840, 113635, 100, 9, 2]),
  cn: derOid([2, 5, 4, 3]),
  ou: derOid([2, 5, 4, 11]),
  o: derOid([2, 5, 4, 10]),
  c: derOid([2, 5, 4, 6]),
};

export function oidEquals(a: Uint8Array, b: Uint8Array): boolean {
  return bytesEqual(a, b);
}
