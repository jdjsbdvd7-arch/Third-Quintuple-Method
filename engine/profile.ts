/**
 * Profile chain and app alignment are separate gates.
 * The profile CMS is never rebuilt here. Callers embed the original bytes.
 */
import { OID, bytesEqual, fromB64, oidEquals, ownedBuffer, readTlv, sequenceItems, sha256, type Tlv } from "./bytes.ts";
import { unzip, zip, type ZipEntry } from "./ipa.ts";
import { parseCert, type ParsedCert } from "./pem.ts";
import { appleAnchors } from "./anchors.ts";

export type Gate = { id: string; ok: boolean; detail: string };

export type ProfileView = {
  ok: boolean;
  gates: Gate[];
  signerCn: string;
  teamId: string;
  bundleId: string;
  wildcard: boolean;
  devices: string[];
  provisionsAllDevices: boolean;
  developerCerts: Uint8Array[];
  entitlements: Record<string, string | boolean>;
  entitlementsXml: string;
  separated: boolean;
};

export type AlignmentInput = {
  appCertificateDer?: Uint8Array | null;
  teamId?: string;
  bundleId?: string;
  udid?: string;
  entitlements?: Record<string, string | boolean>;
};

const PLIST_HEAD = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
`;

export type TrustStore = { roots: Uint8Array[]; intermediates?: Uint8Array[] };

export async function assessProfile(bytes: Uint8Array, app: AlignmentInput = {}, trust?: TrustStore): Promise<ProfileView> {
  const gates: Gate[] = [];
  const cms = await readCms(bytes);
  gates.push({ id: "PF-CMS-01", ok: cms.ok, detail: cms.ok ? "SignedData" : cms.reason });
  const payload = cms.payload;
  const xml = payload ? new TextDecoder().decode(payload) : "";
  const plist = xml.includes("<plist") && xml.includes("<dict>");
  gates.push({ id: "PF-PAYLOAD-01", ok: plist, detail: plist ? "plist" : "no plist payload" });
  const digestOk = cms.ok && payload ? bytesEqual(cms.digest, await sha256(payload)) : false;
  gates.push({ id: "PF-CMS-02", ok: digestOk, detail: digestOk ? "message-digest" : "digest does not match the payload" });
  const signer = cms.signer;
  gates.push({ id: "PF-CERT-01", ok: !!signer, detail: signer?.subjectCn || "signer certificate missing" });
  const signed = signer && cms.signatureOk ? true : false;
  gates.push({ id: "PF-CMS-03", ok: signed, detail: signed ? "signature matches the profile signer key" : "signature does not match" });

  const developerCerts = plist ? dataValues(xml, "DeveloperCertificates").map((item) => fromB64(item)) : [];
  const teamId = plist ? firstString(xml, "TeamIdentifier") : "";
  const entitlements = plist ? flatDict(dictAfter(xml, "Entitlements") ?? "") : {};
  const appId = typeof entitlements["application-identifier"] === "string" ? entitlements["application-identifier"] : "";
  const wildcard = appId.endsWith(".*");
  const bundleId = teamId && appId.startsWith(`${teamId}.`) ? appId.slice(teamId.length + 1) : "";
  const devices = plist ? stringsIn(xml, "ProvisionedDevices") : [];
  const provisionsAllDevices = plist && tagAfter(xml, "ProvisionsAllDevices") === "true";
  const signerHash = signer ? await sha256(signer.raw) : new Uint8Array();
  const devHashes = await Promise.all(developerCerts.map((cert) => sha256(cert)));
  const separated = !!signer && devHashes.length > 0 && devHashes.every((hash) => !bytesEqual(hash, signerHash));
  gates.push({
    id: "PF-PROFILE-01",
    ok: separated,
    detail: separated ? "developer certificate is not the profile signer" : "CMS signer and DeveloperCertificates are the same key",
  });

  const chain = signer ? await walkChain(signer, cms.certificates, trust) : { issuerOk: false, anchorOk: false, detail: "no signer" };
  gates.push({ id: "PF-CHAIN-01", ok: chain.issuerOk, detail: chain.detail });
  gates.push({ id: "PF-CHAIN-02", ok: chain.anchorOk, detail: chain.anchorOk ? "trust anchor" : "trust anchor not reached" });

  const alignment = alignmentGates(
    { teamId, bundleId, wildcard, devices, provisionsAllDevices, developerCerts, entitlements },
    app,
  );
  gates.push(...alignment);

  const entitlementsXml = Object.keys(entitlements).length ? `${PLIST_HEAD}${dictXml(entitlements)}</plist>\n` : "";
  return {
    ok: gates.every((gate) => gate.ok),
    gates,
    signerCn: signer?.subjectCn ?? "",
    teamId,
    bundleId,
    wildcard,
    devices,
    provisionsAllDevices,
    developerCerts,
    entitlements,
    entitlementsXml,
    separated,
  };
}

export async function embedProfile(ipa: Uint8Array, profile: Uint8Array): Promise<Uint8Array> {
  const entries = await unzip(ipa);
  const info = [...entries.keys()].find((path) => /Payload\/[^/]+\.app\/Info\.plist$/.test(path));
  if (!info) return ipa;
  const root = info.slice(0, info.lastIndexOf("/") + 1);
  const next = new Map<string, ZipEntry>(entries);
  next.set(`${root}embedded.mobileprovision`, { data: profile, mode: 0o100644 });
  return zip(next, { directories: true, deflate: true });
}

function alignmentGates(
  profile: {
    teamId: string;
    bundleId: string;
    wildcard: boolean;
    devices: string[];
    provisionsAllDevices: boolean;
    developerCerts: Uint8Array[];
    entitlements: Record<string, string | boolean>;
  },
  app: AlignmentInput,
): Gate[] {
  const gates: Gate[] = [];
  if (app.appCertificateDer && app.appCertificateDer.length) {
    const match = profile.developerCerts.some((cert) => bytesEqual(cert, app.appCertificateDer!));
    gates.push({ id: "AL-CERT-01", ok: match, detail: match ? "certificate is listed" : "certificate is not in DeveloperCertificates" });
  }
  if (app.teamId) {
    const ok = app.teamId === profile.teamId;
    gates.push({ id: "AL-ID-01", ok, detail: ok ? profile.teamId : `${app.teamId} ≠ ${profile.teamId || "—"}` });
  }
  if (app.bundleId && profile.bundleId && !profile.wildcard) {
    const ok = app.bundleId === profile.bundleId;
    gates.push({ id: "AL-ID-02", ok, detail: ok ? profile.bundleId : `${app.bundleId} ≠ ${profile.bundleId}` });
  }
  if (app.udid) {
    const ok = profile.provisionsAllDevices || profile.devices.includes(app.udid);
    gates.push({ id: "AL-DEVICE-01", ok, detail: ok ? "device allowed" : "UDID is not listed" });
  }
  if (app.entitlements) {
    const extra = Object.keys(app.entitlements).filter((key) => profile.entitlements[key] === undefined);
    const changed = Object.keys(app.entitlements).filter((key) => {
      const have = profile.entitlements[key];
      return have !== undefined && have !== app.entitlements![key];
    });
    const ok = extra.length === 0 && changed.length === 0;
    gates.push({
      id: "AL-ENT-01",
      ok,
      detail: ok ? "entitlements are inside the profile" : `not granted: ${[...extra, ...changed].join(", ")}`,
    });
  }
  return gates;
}

async function walkChain(signer: ParsedCert, bag: ParsedCert[], trust?: TrustStore): Promise<{ issuerOk: boolean; anchorOk: boolean; detail: string }> {
  const roots = (trust?.roots ?? appleAnchors.roots).map((der) => parseCert(der));
  const extras = (trust ? (trust.intermediates ?? []) : appleAnchors.intermediates).map((der) => parseCert(der));
  const pool = [...bag, ...extras, ...roots];
  let current = signer;
  for (let hop = 0; hop < 6; hop++) {
    if (roots.some((root) => bytesEqual(root.spki, current.spki))) {
      return { issuerOk: true, anchorOk: true, detail: current.subjectCn };
    }
    const subject = nameField(current.raw, "subject");
    const selfSigned = bytesEqual(subject, current.issuerDer);
    const issuer = pool.find((cert) => bytesEqual(nameField(cert.raw, "subject"), current.issuerDer) && !bytesEqual(cert.raw, current.raw));
    if (!issuer) {
      return { issuerOk: false, anchorOk: false, detail: `no valid issuer for ${current.subjectCn}` };
    }
    if (!(await issuedBy(current, issuer))) {
      return { issuerOk: false, anchorOk: false, detail: `issuer signature failed for ${current.subjectCn}` };
    }
    if (selfSigned) return { issuerOk: false, anchorOk: false, detail: `self-signed ${current.subjectCn}` };
    current = issuer;
  }
  return { issuerOk: false, anchorOk: false, detail: "chain too long" };
}

async function issuedBy(child: ParsedCert, issuer: ParsedCert): Promise<boolean> {
  if (!child.rsaModulusBytes || !issuer.rsaModulusBytes) return false;
  const hash = signatureHash(child.raw);
  if (!hash) return false;
  const top = sequenceItems(child.raw);
  const signature = top[2].content.subarray(1);
  const key = await crypto.subtle.importKey("spki", ownedBuffer(issuer.spki), { name: "RSASSA-PKCS1-v1_5", hash }, false, ["verify"]);
  return crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, ownedBuffer(signature), ownedBuffer(top[0].raw));
}

function signatureHash(cert: Uint8Array): "SHA-1" | "SHA-256" | null {
  const alg = sequenceItems(sequenceItems(cert)[1].raw)[0].content;
  if (bytesEqual(alg, new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]))) return "SHA-256";
  if (bytesEqual(alg, new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05]))) return "SHA-1";
  return null;
}

function nameField(cert: Uint8Array, which: "issuer" | "subject"): Uint8Array {
  const tbs = sequenceItems(sequenceItems(cert)[0].raw);
  let index = tbs[0].tag === 0xa0 ? 1 : 0;
  index += 2;
  if (which === "issuer") return tbs[index].raw;
  return tbs[index + 2].raw;
}

type CmsRead = {
  ok: boolean;
  reason: string;
  payload: Uint8Array | null;
  digest: Uint8Array;
  signer: ParsedCert | null;
  certificates: ParsedCert[];
  signatureOk: boolean;
};

async function readCms(bytes: Uint8Array): Promise<CmsRead> {
  const empty: CmsRead = { ok: false, reason: "not SignedData", payload: null, digest: new Uint8Array(), signer: null, certificates: [], signatureOk: false };
  try {
    const contentInfo = sequenceItems(bytes);
    if (!oidEquals(contentInfo[0].raw, OID.idSignedData)) return empty;
    const explicit = readTlv(bytes, contentInfo[1].headerStart);
    const signedData = sequenceItems(explicit.content);
    const encap = signedData.find((part) => part.tag === 0x30);
    const payload = encap ? eContent(encap) : null;
    const certificates = certificatesOf(signedData);
    const signerInfo = signerInfoOf(signedData);
    if (!signerInfo) return { ...empty, ok: true, reason: "no signer", payload, certificates };
    const signer = matchSigner(signerInfo, certificates);
    const digest = digestOf(signerInfo) ?? new Uint8Array();
    const signatureOk = signer ? await signatureMatches(signerInfo, signer) : false;
    return { ok: true, reason: "SignedData", payload, digest, signer, certificates, signatureOk };
  } catch (error) {
    return { ...empty, reason: error instanceof Error ? error.message : "unreadable" };
  }
}

async function signatureMatches(parts: Tlv[], signer: ParsedCert): Promise<boolean> {
  const attrs = parts.find((part) => part.tag === 0xa0);
  const sig = [...parts].reverse().find((part) => part.tag === 0x04);
  if (!attrs || !sig || !signer.rsaModulusBytes) return false;
  const set = new Uint8Array(attrs.raw);
  set[0] = 0x31;
  const key = await crypto.subtle.importKey(
    "spki",
    ownedBuffer(signer.spki),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, ownedBuffer(sig.content), ownedBuffer(set));
}

function eContent(encap: Tlv): Uint8Array | null {
  const inner = sequenceItems(encap.raw);
  const explicit = inner.find((part) => part.tag === 0xa0);
  if (!explicit) return null;
  const octet = readTlv(explicit.content, 0);
  return octet.tag === 0x04 ? octet.content : null;
}

function certificatesOf(signedData: Tlv[]): ParsedCert[] {
  const bag = signedData.find((part) => part.tag === 0xa0);
  if (!bag) return [];
  const certs: ParsedCert[] = [];
  let at = 0;
  while (at + 2 < bag.content.length) {
    const cert = readTlv(bag.content, at);
    if (cert.tag !== 0x30) break;
    certs.push(parseCert(cert.raw));
    at += cert.totalLength;
  }
  return certs;
}

function signerInfoOf(signedData: Tlv[]): Tlv[] | null {
  for (const part of signedData) {
    if (part.tag !== 0x31 || part.content.length < 40) continue;
    const first = readTlv(part.content, 0);
    if (first.tag === 0x30 && first.raw.length > 40) return sequenceItems(first.raw);
  }
  return null;
}

function matchSigner(parts: Tlv[], certs: ParsedCert[]): ParsedCert | null {
  const name = sequenceItems(parts[1]?.raw ?? new Uint8Array());
  if (name.length < 2) return certs[0] ?? null;
  return certs.find((cert) => bytesEqual(cert.issuerDer, name[0].raw) && bytesEqual(cert.serialDer, name[1].raw)) ?? certs[0] ?? null;
}

function digestOf(parts: Tlv[]): Uint8Array | null {
  const attrs = parts.find((part) => part.tag === 0xa0);
  if (!attrs) return null;
  let at = 0;
  while (at < attrs.content.length) {
    const attr = readTlv(attrs.content, at);
    at = attr.end;
    const body = sequenceItems(attr.raw);
    if (body.length < 2 || !oidEquals(body[0].raw, OID.attrMessageDigest)) continue;
    const set = readTlv(attr.raw, body[1].headerStart);
    const oct = readTlv(set.content, 0);
    return oct.content;
  }
  return null;
}

function dictAfter(xml: string, key: string): string | null {
  const at = xml.indexOf(`<key>${key}</key>`);
  if (at < 0) return null;
  const start = xml.indexOf("<dict>", at);
  if (start < 0) return null;
  let depth = 0;
  for (let i = start; i < xml.length; ) {
    if (xml.startsWith("<dict>", i)) {
      depth++;
      i += 6;
      continue;
    }
    if (xml.startsWith("</dict>", i)) {
      depth--;
      i += 7;
      if (depth === 0) return xml.slice(start, i);
      continue;
    }
    i++;
  }
  return null;
}

function flatDict(dictXml: string): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  const re = /<key>([^<]+)<\/key>\s*(?:<string>([^<]*)<\/string>|<(true|false)\/>)/g;
  for (const match of dictXml.matchAll(re)) {
    out[match[1]] = match[3] ? match[3] === "true" : match[2];
  }
  return out;
}

function dataValues(xml: string, key: string): string[] {
  const at = xml.indexOf(`<key>${key}</key>`);
  if (at < 0) return [];
  const end = xml.indexOf("</array>", at);
  const slice = xml.slice(at, end < 0 ? at + 20000 : end);
  return [...slice.matchAll(/<data>([\s\S]*?)<\/data>/g)].map((match) => match[1].replace(/\s+/g, ""));
}

function stringsIn(xml: string, key: string): string[] {
  const at = xml.indexOf(`<key>${key}</key>`);
  if (at < 0) return [];
  const end = xml.indexOf("</array>", at);
  return [...xml.slice(at, end < 0 ? at : end).matchAll(/<string>([^<]*)<\/string>/g)].map((match) => match[1]);
}

function firstString(xml: string, key: string): string {
  return stringsIn(xml, key)[0] ?? "";
}

function tagAfter(xml: string, key: string): string {
  const at = xml.indexOf(`<key>${key}</key>`);
  if (at < 0) return "";
  const next = xml.slice(at, at + 80);
  if (next.includes("<true/>")) return "true";
  if (next.includes("<false/>")) return "false";
  return "";
}

function dictXml(dict: Record<string, string | boolean>): string {
  const rows = Object.keys(dict)
    .sort()
    .map((key) => {
      const value = dict[key];
      const body = typeof value === "boolean" ? (value ? "<true/>" : "<false/>") : `<string>${value}</string>`;
      return `<key>${key}</key>${body}`;
    });
  return `<dict>${rows.join("")}</dict>\n`;
}
