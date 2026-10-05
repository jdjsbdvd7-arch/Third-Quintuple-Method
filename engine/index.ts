import { KhatmError, hex, ownedBuffer, pemArmor } from "./bytes.ts";
import { signIpa, unzip, inspectPackage, type IpaOptions, type IpaSeal, type PackageInfo } from "./ipa.ts";
import { classify, signMachO, synthesizeMachO, verifyMachO, machoSummary, type Check, type MachOSignOptions, type SignedMachO, type SliceSeal } from "./macho.ts";
import { runOracle, type OracleReport } from "./oracle.ts";
import { createSampleIdentity, inspectCertificates, loadPem, teamIdOf, type ParsedCert, type PemMaterial } from "./pem.ts";
import { sealEntitlementsXml } from "./plist.ts";

export { KhatmError, createSampleIdentity, inspectCertificates, inspectPackage, loadPem, ownedBuffer, pemArmor, runOracle, synthesizeMachO, teamIdOf, unzip };
export type { Check, IpaSeal, OracleReport, PackageInfo, PemMaterial, SliceSeal, SignedMachO };

export type SealOptions = {
  identifier?: string;
  bundleId?: string;
  teamId?: string;
  entitlementsXml?: string;
  /** Remove embedded provisioning profiles only when the selected distribution policy permits it. */
  removeProvisioningProfiles?: boolean;
  signingDate?: Date;
  hardenedRuntime?: boolean;
};

export type SealResult = {
  bytes: Uint8Array;
  format: "macho" | "ipa";
  cdhash: string;
  slices: SliceSeal[];
  removedProfiles: string[];
  bundles: { path: string; identifier: string; cdhash: string }[];
  checks: Check[];
};

function entitlementsOf(xml: string | undefined) {
  if (!xml || !xml.trim()) return null;
  return sealEntitlementsXml(xml);
}

export async function seal(input: Uint8Array, material: PemMaterial, opts: SealOptions = {}): Promise<SealResult> {
  const kind = classify(input);
  const teamId = teamIdOf(material.leaf, opts.teamId);
  if (kind === "macho64" || kind === "fat" || kind === "fat64") {
    const identifier = opts.identifier || opts.bundleId || "a.out";
    const signed: SignedMachO = await signMachO(input, material, machoOptions(identifier, teamId, opts));
    const slices = await verifyMachO(signed.bytes);
    return {
      bytes: signed.bytes,
      format: "macho",
      cdhash: signed.slices[0]?.cdhash ?? "",
      slices: signed.slices.map((slice, i) => ({ ...slice, checks: slices[i]?.checks ?? slice.checks })),
      removedProfiles: [],
      bundles: [],
      checks: slices[0]?.checks ?? signed.slices[0]?.checks ?? [],
    };
  }
  if (input.length >= 4 && input[0] === 0x50 && input[1] === 0x4b) {
    const ipaOpts: IpaOptions = {
      bundleId: opts.bundleId,
      entitlementsXml: opts.entitlementsXml,
      removeProvisioningProfiles: opts.removeProvisioningProfiles,
      teamId,
      signingDate: opts.signingDate,
      hardenedRuntime: opts.hardenedRuntime,
    };
    const sealed: IpaSeal = await signIpa(input, material, ipaOpts);
    const app = sealed.bundles.filter((b) => b.path.endsWith(".app/") || b.path.includes(".app/")).sort((a, b) => a.path.length - b.path.length)[0];
    return {
      bytes: sealed.bytes,
      format: "ipa",
      cdhash: app?.cdhash ?? sealed.slices[0]?.cdhash ?? "",
      slices: sealed.slices,
      removedProfiles: sealed.removedProfiles,
      bundles: sealed.bundles,
      checks: sealed.slices[0]?.checks ?? [],
    };
  }
  throw new KhatmError("input", "Not a Mach-O and not an IPA.");
}

function machoOptions(identifier: string, teamId: string, opts: SealOptions): MachOSignOptions {
  return {
    identifier,
    teamId,
    entitlements: entitlementsOf(opts.entitlementsXml),
    signingDate: opts.signingDate,
    hardenedRuntime: opts.hardenedRuntime,
  };
}

export function describeMaterial(material: PemMaterial): {
  cn: string;
  teamId: string;
  issuer: string;
  serial: string;
  notAfter: string;
  kind: string;
} {
  const leaf = material.leaf;
  return {
    cn: leaf.subjectCn,
    teamId: teamIdOf(leaf),
    issuer: leaf.issuerCn || leaf.issuerO,
    serial: leaf.serialHex,
    notAfter: leaf.notAfter.toISOString().slice(0, 10),
    kind: material.kind === "RSA" ? `RSA ${material.signatureDerLength * 8}` : `ECDSA ${material.curve}`,
  };
}

export function describeCert(cert: ParsedCert): {
  cn: string;
  teamId: string;
  issuer: string;
  serial: string;
  notAfter: string;
  kind: string;
} {
  return {
    cn: cert.subjectCn,
    teamId: teamIdOf(cert),
    issuer: cert.issuerCn || cert.issuerO,
    serial: cert.serialHex,
    notAfter: cert.notAfter.toISOString().slice(0, 10),
    kind: cert.rsaModulusBytes ? `RSA ${cert.rsaModulusBytes * 8}` : cert.curve ? `ECDSA ${cert.curve}` : "certificate",
  };
}

export function cdhashOf(checks: Check[]): string {
  return checks.find((c) => c.id === "cdhash")?.detail ?? "";
}

export { hex, machoSummary };
