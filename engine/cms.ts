import {
  KhatmError,
  OID,
  b64,
  bytesEqual,
  concat,
  derIntegerBytes,
  derNull,
  derOctet,
  derSeq,
  derSet,
  derSmallInt,
  derUtcTime,
  hex,
  oidEquals,
  ownedBuffer,
  readTlv,
  sequenceItems,
  sha256,
  tlv,
  utf8,
} from "./bytes.ts";
import { parseCert, type PemMaterial } from "./pem.ts";

/**
 * Detached CMS SignedData over the CodeDirectory blob.
 * Signed attributes: content-type, message-digest, signing-time,
 * 1.2.840.113635.100.9.1 (plist of 20-byte cdhashes),
 * 1.2.840.113635.100.9.2 (algorithm + full digest).
 * The private key signs the DER SET of those attributes (tag 0x31), per RFC 5652.
 */

export type CmsInput = {
  material: PemMaterial;
  codeDirectory: Uint8Array;
  /** Extra code directories, primary first is implied by `codeDirectory`. */
  alternateDirectories?: Uint8Array[];
  signingDate: Date;
  /** When set, skip the private-key operation and embed this signature value. */
  signatureOverride?: Uint8Array;
};

export async function buildCms(input: CmsInput): Promise<Uint8Array> {
  const cdHash = await sha256(input.codeDirectory);
  const allHashes = [cdHash];
  for (const alt of input.alternateDirectories ?? []) allHashes.push(await sha256(alt));
  const attrsSet = await signedAttributesSet(allHashes, cdHash, input.signingDate);
  const signature = input.signatureOverride ?? (await signAttributes(input.material, attrsSet));
  return wrapSignedData(input.material, attrsSet, signature);
}

export function cmsUpperBound(material: PemMaterial): number {
  const dummyCd = new Uint8Array(32);
  const date = new Date(Date.UTC(2026, 0, 1));
  const hashes = [dummyCd];
  const attrs = signedAttributesSetSync(hashes, dummyCd, date);
  const dummySig = new Uint8Array(material.signatureDerLength);
  return wrapSignedData(material, attrs, dummySig).length;
}

async function signAttributes(material: PemMaterial, attrsSet: Uint8Array): Promise<Uint8Array> {
  if (material.kind === "RSA") {
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, material.privateKey, ownedBuffer(attrsSet)));
    if (sig.length !== material.signatureDerLength) {
      throw new KhatmError("cms", `RSA signature length ${sig.length} does not match modulus ${material.signatureDerLength}.`);
    }
    return sig;
  }
  const raw = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, material.privateKey, ownedBuffer(attrsSet)),
  );
  const der = ecdsaRawToDer(raw);
  if (der.length > material.signatureDerLength) {
    throw new KhatmError("cms", "ECDSA signature exceeds the computed maximum.");
  }
  return der;
}

function ecdsaRawToDer(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  return derSeq(derIntegerBytes(raw.subarray(0, half)), derIntegerBytes(raw.subarray(half)));
}

function ecdsaDerToRaw(der: Uint8Array, coord: number): Uint8Array {
  const parts = sequenceItems(der);
  const raw = new Uint8Array(coord * 2);
  raw.set(unsignedFixed(readTlv(parts[0].raw, 0).content, coord), 0);
  raw.set(unsignedFixed(readTlv(parts[1].raw, 0).content, coord), coord);
  return raw;
}

function unsignedFixed(content: Uint8Array, size: number): Uint8Array {
  let body = content;
  if (body[0] === 0x00) body = body.subarray(1);
  if (body.length > size) throw new KhatmError("cms", "ECDSA coordinate is longer than the curve.");
  const out = new Uint8Array(size);
  out.set(body, size - body.length);
  return out;
}

export function signedAttributesSetSync(fullHashes: Uint8Array[], primaryHash: Uint8Array, date: Date): Uint8Array {
  const plist = cdhashPlist(fullHashes.map((h) => h.subarray(0, 20)));
  const attrs = [
    derSeq(OID.attrContentType, derSet([OID.idData])),
    derSeq(OID.attrMessageDigest, derSet([derOctet(primaryHash)])),
    derSeq(OID.attrSigningTime, derSet([derUtcTime(date)])),
    derSeq(OID.attrAppleCdhashPlist, derSet([derOctet(utf8(plist))])),
    derSeq(
      OID.attrAppleCdhashes,
      derSet(fullHashes.map((hash) => derSeq(OID.sha256, derOctet(hash)))),
    ),
  ];
  return derSet(attrs);
}

async function signedAttributesSet(fullHashes: Uint8Array[], primaryHash: Uint8Array, date: Date): Promise<Uint8Array> {
  return signedAttributesSetSync(fullHashes, primaryHash, date);
}

function cdhashPlist(truncated: Uint8Array[]): string {
  const rows = truncated.map((h) => `\t\t<data>${b64(h)}</data>`).join("\n");
  return (
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
    `<plist version="1.0">\n<dict>\n\t<key>cdhashes</key>\n\t<array>\n${rows}\n\t</array>\n</dict>\n</plist>\n`
  );
}

function wrapSignedData(material: PemMaterial, attrsSet: Uint8Array, signature: Uint8Array): Uint8Array {
  const implicitAttrs = new Uint8Array(attrsSet);
  implicitAttrs[0] = 0xa0;
  const digestAlg = derSeq(OID.sha256, derNull());
  const sigAlg =
    material.kind === "RSA" ? derSeq(OID.sha256WithRsa, derNull()) : tlv(0x30, OID.ecdsaWithSha256);
  const signer = derSeq(
    derSmallInt(1),
    derSeq(material.leaf.issuerDer, material.leaf.serialDer),
    digestAlg,
    implicitAttrs,
    sigAlg,
    derOctet(signature),
  );
  const certs = tlv(0xa0, concat(...material.chain.map((c) => c.raw)));
  const signedData = derSeq(
    derSmallInt(1),
    derSet([digestAlg]),
    derSeq(OID.idData),
    certs,
    derSet([signer]),
  );
  return derSeq(OID.idSignedData, tlv(0xa0, signedData));
}

export type CmsCheck = {
  ok: boolean;
  digestMatches: boolean;
  signerMatchesKey: boolean;
  cdhashFull: string;
};

export async function verifyCms(cms: Uint8Array, codeDirectory: Uint8Array): Promise<CmsCheck> {
  const contentInfo = sequenceItems(cms);
  if (!oidEquals(contentInfo[0].raw, OID.idSignedData)) throw new KhatmError("cms", "Content is not SignedData.");
  const explicit = readTlv(cms, contentInfo[1].headerStart);
  if (explicit.tag !== 0xa0) throw new KhatmError("cms", "SignedData has no explicit wrapper.");
  const signedData = sequenceItems(explicit.content);
  let signerParts: ReturnType<typeof sequenceItems> | null = null;
  let leafDer: Uint8Array | null = null;
  for (const part of signedData) {
    if (part.tag === 0xa0 && !leafDer) {
      leafDer = readTlv(part.content, 0).raw;
    } else if (part.tag === 0x31 && part.content.length > 40) {
      const first = readTlv(part.content, 0);
      if (first.tag === 0x30) signerParts = sequenceItems(first.raw);
    }
  }
  if (!signerParts || !leafDer) throw new KhatmError("cms", "SignerInfo or the certificate is missing.");
  const attrsField = signerParts.find((p) => p.tag === 0xa0);
  const sigField = [...signerParts].reverse().find((p) => p.tag === 0x04);
  if (!attrsField || !sigField) throw new KhatmError("cms", "Signed attributes or the signature value is missing.");
  const setForVerify = new Uint8Array(attrsField.raw);
  setForVerify[0] = 0x31;
  const cdHash = await sha256(codeDirectory);
  let digestMatches = false;
  let cursor = 0;
  while (cursor < attrsField.content.length) {
    const attr = readTlv(attrsField.content, cursor);
    const items = sequenceItems(attr.raw);
    if (oidEquals(items[0].raw, OID.attrMessageDigest)) {
      const valueSet = readTlv(attr.raw, items[1].headerStart);
      const oct = readTlv(valueSet.content, 0);
      digestMatches = bytesEqual(oct.content, cdHash);
    }
    cursor = attr.end;
  }
  const parsed = parseCert(leafDer);
  const pub = await crypto.subtle.importKey(
    "spki",
    ownedBuffer(parsed.spki),
    parsed.rsaModulusBytes
      ? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }
      : { name: "ECDSA", namedCurve: parsed.curve ?? "P-256" },
    false,
    ["verify"],
  );
  const signature = parsed.rsaModulusBytes ? sigField.content : ecdsaDerToRaw(sigField.content, parsed.curve === "P-384" ? 48 : 32);
  const signerMatchesKey = await crypto.subtle.verify(
    parsed.rsaModulusBytes ? { name: "RSASSA-PKCS1-v1_5" } : { name: "ECDSA", hash: "SHA-256" },
    pub,
    ownedBuffer(signature),
    ownedBuffer(setForVerify),
  );
  return { ok: digestMatches && signerMatchesKey, digestMatches, signerMatchesKey, cdhashFull: hex(cdHash) };
}
