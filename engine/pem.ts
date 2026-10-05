import {
  KhatmError,
  OID,
  bytesEqual,
  derBitString,
  derNull,
  derSeq,
  derSmallInt,
  derUtcTime,
  derUtf8,
  fromB64,
  oidEquals,
  ownedBuffer,
  pemArmor,
  readTlv,
  sequenceItems,
  tlv,
  utf8,
  type Tlv,
} from "./bytes.ts";

export type KeyKind = "RSA" | "ECDSA";

export type ParsedCert = {
  raw: Uint8Array;
  spki: Uint8Array;
  issuerDer: Uint8Array;
  serialDer: Uint8Array;
  serialHex: string;
  subjectCn: string;
  subjectOu: string[];
  subjectO: string;
  issuerCn: string;
  issuerO: string;
  notBefore: Date;
  notAfter: Date;
  appleIssued: boolean;
  rsaModulusBytes: number | null;
  curve: "P-256" | "P-384" | null;
};

export type PemMaterial = {
  leaf: ParsedCert;
  chain: ParsedCert[];
  privateKey: CryptoKey;
  kind: KeyKind;
  curve: "P-256" | "P-384" | null;
  /** CMS signature value length. RSA is exact; ECDSA is the DER upper bound. */
  signatureDerLength: number;
};

const PEM_RE = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;

/** Read certificates only. A .cer has no private key and cannot seal. */
export function inspectCertificates(input: string | Uint8Array): ParsedCert[] {
  if (typeof input !== "string") {
    const text = new TextDecoder().decode(input);
    if (text.includes("BEGIN CERTIFICATE") || text.includes("BEGIN TRUSTED CERTIFICATE")) return inspectCertificates(text);
    if (input.length < 2 || input[0] !== 0x30) {
      throw new KhatmError("not-pem", "Not a PEM or DER certificate.");
    }
    return [parseCert(input)];
  }
  const blocks: { label: string; der: Uint8Array }[] = [];
  for (const match of input.matchAll(PEM_RE)) blocks.push({ label: match[1], der: fromB64(match[2]) });
  const certs = blocks.filter((b) => b.label === "CERTIFICATE" || b.label === "TRUSTED CERTIFICATE").map((b) => parseCert(b.der));
  if (certs.length === 0) throw new KhatmError("no-cert", "No CERTIFICATE in the file.");
  return certs;
}

export async function loadPem(text: string): Promise<PemMaterial> {
  if (/\bBEGIN (PKCS12|PKCS7|ENCRYPTED PRIVATE KEY)\b/.test(text) || /Proc-Type:\s*4,ENCRYPTED/.test(text)) {
    throw new KhatmError(
      "pem-only",
      "Only unencrypted PEM is accepted: a certificate and a private key. PKCS#12, PKCS#7, and password-protected keys are rejected.",
    );
  }
  const blocks: { label: string; der: Uint8Array }[] = [];
  for (const match of text.matchAll(PEM_RE)) {
    blocks.push({ label: match[1], der: fromB64(match[2]) });
  }
  if (blocks.length === 0) {
    throw new KhatmError(
      "not-pem",
      "Not PEM. Export with: openssl pkcs12 -in identity.p12 -nokeys -out cert.pem, then -nocerts -nodes -out key.pem. This engine does not open PKCS#12.",
    );
  }
  const certs = blocks.filter((b) => b.label === "CERTIFICATE" || b.label === "TRUSTED CERTIFICATE").map((b) => parseCert(b.der));
  const keys = blocks.filter((b) => b.label === "PRIVATE KEY" || b.label === "RSA PRIVATE KEY" || b.label === "EC PRIVATE KEY");
  if (certs.length === 0) throw new KhatmError("no-cert", "PEM has no certificate (BEGIN CERTIFICATE).");
  if (keys.length === 0) throw new KhatmError("no-key", "PEM has no private key.");
  if (keys.length > 1) throw new KhatmError("pem-only", "Put exactly one private key in the file.");

  const keyBlock = keys[0];
  const pkcs8 = toPkcs8(keyBlock.label, keyBlock.der, certs);
  const kind = detectKind(keyBlock.label, keyBlock.der, pkcs8);
  const curve = kind === "ECDSA" ? detectCurve(keyBlock.label, keyBlock.der, pkcs8, certs) : null;
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    ownedBuffer(pkcs8),
    kind === "RSA" ? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } : { name: "ECDSA", namedCurve: curve ?? "P-256" },
    false,
    ["sign"],
  );

  const probe = utf8("khatm-probe");
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      kind === "RSA" ? { name: "RSASSA-PKCS1-v1_5" } : { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      ownedBuffer(probe),
    ),
  );
  let leafIndex = -1;
  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i];
    if (kind === "RSA" ? !cert.rsaModulusBytes : cert.curve !== curve) continue;
    const pub = await crypto.subtle.importKey(
      "spki",
      ownedBuffer(cert.spki),
      kind === "RSA" ? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } : { name: "ECDSA", namedCurve: curve! },
      false,
      ["verify"],
    );
    const ok = await crypto.subtle.verify(
      kind === "RSA" ? { name: "RSASSA-PKCS1-v1_5" } : { name: "ECDSA", hash: "SHA-256" },
      pub,
      ownedBuffer(sig),
      ownedBuffer(probe),
    );
    if (ok) {
      leafIndex = i;
      break;
    }
  }
  if (leafIndex < 0) throw new KhatmError("key-mismatch", "Private key matches no certificate in the PEM.");
  const leaf = certs[leafIndex];
  const chain = [leaf, ...certs.filter((_, i) => i !== leafIndex)];
  const signatureDerLength = kind === "RSA" ? (leaf.rsaModulusBytes ?? sig.length) : curve === "P-384" ? 104 : 72;
  return { leaf, chain, privateKey, kind, curve, signatureDerLength };
}

function detectKind(label: string, der: Uint8Array, pkcs8: Uint8Array): KeyKind {
  if (label === "RSA PRIVATE KEY") return "RSA";
  if (label === "EC PRIVATE KEY") return "ECDSA";
  const seq = sequenceItems(pkcs8);
  const alg = sequenceItems(seq[1].raw);
  if (oidEquals(alg[0].raw, OID.rsaEncryption)) return "RSA";
  if (oidEquals(alg[0].raw, OID.ecPublicKey)) return "ECDSA";
  throw new KhatmError("unsupported-key", "Key is not RSA or ECDSA P-256/P-384.");
}

function detectCurve(
  label: string,
  keyDer: Uint8Array,
  pkcs8: Uint8Array,
  certs: ParsedCert[],
): "P-256" | "P-384" {
  const oid = label === "EC PRIVATE KEY" ? curveOidFromSec1(keyDer) : curveOidFromPkcs8(pkcs8);
  const curve = curveName(oid);
  if (curve) return curve;
  if (oid) throw new KhatmError("unsupported-key", "Unsupported ECDSA curve. Only P-256 and P-384 are accepted.");
  const certificateCurves = [...new Set(certs.map((cert) => cert.curve).filter((value): value is "P-256" | "P-384" => !!value))];
  if (certificateCurves.length === 1) return certificateCurves[0];
  throw new KhatmError("unsupported-key", "ECDSA curve must be P-256 or P-384 and stated in the key or the certificate.");
}

function curveName(oid: Uint8Array | null): "P-256" | "P-384" | null {
  if (oid && oidEquals(oid, OID.prime256v1)) return "P-256";
  if (oid && oidEquals(oid, OID.secp384r1)) return "P-384";
  return null;
}

function toPkcs8(label: string, der: Uint8Array, certs: ParsedCert[]): Uint8Array {
  if (label === "PRIVATE KEY") return der;
  if (label === "RSA PRIVATE KEY") {
    return derSeq(derSmallInt(0), derSeq(OID.rsaEncryption, derNull()), tlv(0x04, der));
  }
  if (label === "EC PRIVATE KEY") {
    const curve = curveOidFromSec1(der) ?? (certs.find((c) => c.curve)?.curve === "P-384" ? OID.secp384r1 : OID.prime256v1);
    return derSeq(derSmallInt(0), derSeq(OID.ecPublicKey, curve), tlv(0x04, der));
  }
  throw new KhatmError("pem-only", `Unsupported PEM block: ${label}`);
}

function curveOidFromSec1(der: Uint8Array): Uint8Array | null {
  const items = sequenceItems(der);
  for (const item of items) {
    if (item.tag === 0xa0) {
      const inner = readTlv(item.content, 0);
      if (inner.tag === 0x06) return inner.raw;
    }
  }
  return null;
}

function curveOidFromPkcs8(der: Uint8Array): Uint8Array | null {
  const items = sequenceItems(der);
  if (items.length < 2) return null;
  const alg = sequenceItems(items[1].raw);
  if (!oidEquals(alg[0].raw, OID.ecPublicKey)) return null;
  return alg[1]?.raw ?? null;
}

export function parseCert(der: Uint8Array): ParsedCert {
  const top = sequenceItems(der);
  if (top.length < 3) throw new KhatmError("cert", "Incomplete X.509 certificate.");
  const tbs = sequenceItems(top[0].raw);
  let i = 0;
  if (tbs[0].tag === 0xa0) i++;
  const serialDer = tbs[i++].raw;
  i++; // signature algorithm
  const issuerDer = tbs[i++].raw;
  const validity = sequenceItems(tbs[i++].raw);
  const subject = tbs[i++].raw;
  const spki = tbs[i].raw;
  const subjectNames = parseName(subject);
  const issuerNames = parseName(issuerDer);
  const cn = subjectNames.cn[0] ?? "";
  const issuerCn = issuerNames.cn[0] ?? "";
  const issuerO = issuerNames.o[0] ?? "";
  const appleIssued = /apple/i.test(issuerCn) || /apple/i.test(issuerO);
  const { rsaModulusBytes, curve } = parseSpki(spki);
  return {
    raw: der,
    spki,
    issuerDer,
    serialDer,
    serialHex: hexOfInteger(serialDer),
    subjectCn: cn,
    subjectOu: subjectNames.ou,
    subjectO: subjectNames.o[0] ?? "",
    issuerCn,
    issuerO,
    notBefore: parseTime(validity[0]),
    notAfter: parseTime(validity[1]),
    appleIssued,
    rsaModulusBytes,
    curve,
  };
}

function hexOfInteger(integerTlv: Uint8Array): string {
  const t = readTlv(integerTlv, 0);
  let s = "";
  for (const b of t.content) s += b.toString(16).padStart(2, "0");
  return s.replace(/^0+/, "") || "0";
}

function parseTime(node: Tlv): Date {
  const text = new TextDecoder().decode(node.content);
  const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
  if (m) {
    const yy = Number(m[1]);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return new Date(Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])));
  }
  const g = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
  if (!g) throw new KhatmError("cert", "Certificate date is not understood.");
  return new Date(Date.UTC(Number(g[1]), Number(g[2]) - 1, Number(g[3]), Number(g[4]), Number(g[5]), Number(g[6])));
}

type NameParts = { cn: string[]; ou: string[]; o: string[] };

function parseName(nameDer: Uint8Array): NameParts {
  const out: NameParts = { cn: [], ou: [], o: [] };
  const rdns = sequenceItems(nameDer);
  for (const rdn of rdns) {
    if (rdn.tag !== 0x31) continue;
    let o = rdn.contentStart;
    while (o < rdn.contentEnd) {
      const atv = readTlv(nameDer, o);
      const pair = sequenceItems(atv.raw);
      const oid = pair[0].raw;
      const value = decodeDirectoryString(pair[1]);
      if (oidEquals(oid, OID.cn)) out.cn.push(value);
      else if (oidEquals(oid, OID.ou)) out.ou.push(value);
      else if (oidEquals(oid, OID.o)) out.o.push(value);
      o = atv.end;
    }
  }
  return out;
}

function decodeDirectoryString(node: Tlv): string {
  if (node.tag === 0x1e) return new TextDecoder("utf-16be").decode(node.content);
  return new TextDecoder().decode(node.content);
}

function parseSpki(spki: Uint8Array): { rsaModulusBytes: number | null; curve: "P-256" | "P-384" | null } {
  const items = sequenceItems(spki);
  const alg = sequenceItems(items[0].raw);
  const bit = items[1];
  if (oidEquals(alg[0].raw, OID.rsaEncryption)) {
    const keySeq = readTlv(bit.content.subarray(1), 0);
    const n = sequenceItems(keySeq.raw)[0];
    const content = readTlv(n.raw, 0).content;
    const rsaModulusBytes = content[0] === 0x00 ? content.length - 1 : content.length;
    return { rsaModulusBytes, curve: null };
  }
  if (oidEquals(alg[0].raw, OID.ecPublicKey)) {
    return { rsaModulusBytes: null, curve: curveName(alg[1]?.raw ?? null) };
  }
  return { rsaModulusBytes: null, curve: null };
}

export function teamIdOf(cert: ParsedCert, override?: string): string {
  if (override && override.trim()) return override.trim();
  return cert.subjectOu.find((ou) => /^[A-Za-z0-9]{10}$/.test(ou)) ?? cert.subjectOu[0] ?? "";
}

export async function createSampleIdentity(): Promise<{ pem: string; material: PemMaterial }> {
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const subject = directoryName([
    [OID.cn, "Khatm Sample"],
    [OID.ou, "SAMPLETEAM"],
    [OID.o, "Khatm"],
  ]);
  const serial = derSmallInt(0x4b481001);
  const notBefore = new Date(Date.UTC(2026, 0, 1));
  const notAfter = new Date(Date.UTC(2035, 0, 1));
  const algId = derSeq(OID.sha256WithRsa, derNull());
  const tbs = derSeq(
    tlv(0xa0, derSmallInt(2)),
    serial,
    algId,
    subject,
    derSeq(derUtcTime(notBefore), derUtcTime(notAfter)),
    subject,
    spki,
  );
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, pair.privateKey, ownedBuffer(tbs)));
  const cert = derSeq(tbs, algId, derBitString(signature));
  const pem = pemArmor("CERTIFICATE", cert) + pemArmor("PRIVATE KEY", pkcs8);
  const material = await loadPem(pem);
  if (material.leaf.subjectCn !== "Khatm Sample" || teamIdOf(material.leaf) !== "SAMPLETEAM") {
    throw new KhatmError("sample", "Sample certificate did not parse as written.");
  }
  if (!bytesEqual(material.leaf.spki, spki)) throw new KhatmError("sample", "Sample SPKI drifted.");
  return { pem, material };
}

function directoryName(attrs: [Uint8Array, string][]): Uint8Array {
  const rdns = attrs.map(([oid, value]) => tlv(0x31, derSeq(oid, derUtf8(value))));
  return derSeq(...rdns);
}
