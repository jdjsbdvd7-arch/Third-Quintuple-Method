/**
 * In-browser copy of the synthetic lab.
 * The root is ours. It is not an Apple trust anchor.
 */
import { b64, derBitString, derNull, derSeq, derSmallInt, derUtcTime, derUtf8, ownedBuffer, pemArmor, tlv } from "./bytes.ts";
import { OID } from "./bytes.ts";
import { buildAttachedCms } from "./cms.ts";
import { loadPem, type PemMaterial } from "./pem.ts";

export type LabChain = {
  developer: PemMaterial;
  profile: Uint8Array;
  rootDer: Uint8Array;
  intermediateDer: Uint8Array;
  developerDer: Uint8Array;
};

const NOT_BEFORE = new Date(Date.UTC(2026, 0, 1));
const NOT_AFTER = new Date(Date.UTC(2035, 0, 1));

export async function issueLab(): Promise<LabChain> {
  const root = await makeKey();
  const rootName = directoryName([
    [OID.c, "US"],
    [OID.o, "Khatm Test Authority"],
    [OID.ou, "Certification Authority"],
    [OID.cn, "Khatm Synthetic Root CA"],
  ]);
  const rootDer = await signCert(rootName, rootName, root.spki, root.privateKey, 1);
  const mid = await makeKey();
  const midName = directoryName([
    [OID.c, "US"],
    [OID.o, "Khatm Test Authority"],
    [OID.ou, "Developer Relations"],
    [OID.cn, "Khatm Synthetic Developer Relations CA"],
  ]);
  const intermediateDer = await signCert(midName, rootName, mid.spki, root.privateKey, 2);
  const leaf = await makeKey();
  const leafName = directoryName([
    [OID.c, "US"],
    [OID.o, "Khatm Owned Demo"],
    [OID.ou, "SAMPLETEAM"],
    [OID.cn, "Khatm Synthetic Development"],
  ]);
  const developerDer = await signCert(leafName, midName, leaf.spki, mid.privateKey, 3);
  const signer = await makeKey();
  const signerName = directoryName([
    [OID.c, "US"],
    [OID.o, "Khatm Test Authority"],
    [OID.ou, "Provisioning"],
    [OID.cn, "Khatm Synthetic Profile Signing"],
  ]);
  const signerDer = await signCert(signerName, midName, signer.spki, mid.privateKey, 4);
  const developer = await loadPem(
    pemArmor("CERTIFICATE", developerDer) + pemArmor("CERTIFICATE", intermediateDer) + pemArmor("PRIVATE KEY", leaf.pkcs8),
  );
  const profileSigner = await loadPem(
    pemArmor("CERTIFICATE", signerDer) + pemArmor("CERTIFICATE", intermediateDer) + pemArmor("PRIVATE KEY", signer.pkcs8),
  );
  const xml = new TextEncoder().encode(
    `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>TeamIdentifier</key><array><string>SAMPLETEAM</string></array><key>DeveloperCertificates</key><array><data>${b64(developerDer)}</data></array><key>Entitlements</key><dict><key>application-identifier</key><string>SAMPLETEAM.demo.khatm</string><key>com.apple.developer.team-identifier</key><string>SAMPLETEAM</string><key>get-task-allow</key><true/></dict><key>ProvisionedDevices</key><array><string>00008110-001965E62213801E</string></array></dict></plist>\n`,
  );
  const profile = await buildAttachedCms(profileSigner, xml, NOT_BEFORE);
  return { developer, profile, rootDer, intermediateDer, developerDer };
}

async function makeKey(): Promise<{ privateKey: CryptoKey; spki: Uint8Array; pkcs8: Uint8Array }> {
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  return {
    privateKey: pair.privateKey,
    spki: new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)),
    pkcs8: new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)),
  };
}

async function signCert(subject: Uint8Array, issuer: Uint8Array, spki: Uint8Array, key: CryptoKey, serial: number): Promise<Uint8Array> {
  const algId = derSeq(OID.sha256WithRsa, derNull());
  const tbs = derSeq(tlv(0xa0, derSmallInt(2)), derSmallInt(serial), algId, issuer, derSeq(derUtcTime(NOT_BEFORE), derUtcTime(NOT_AFTER)), subject, spki);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, ownedBuffer(tbs)));
  return derSeq(tbs, algId, derBitString(signature));
}

function directoryName(attrs: [Uint8Array, string][]): Uint8Array {
  return derSeq(...attrs.map(([oid, value]) => tlv(0x31, derSeq(oid, derUtf8(value)))));
}
