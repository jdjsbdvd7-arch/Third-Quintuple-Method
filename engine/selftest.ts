import { bytesEqual, sha256 } from "./bytes.ts";
import { derEntitlements, emitEntitlements } from "./plist.ts";
import { createSampleIdentity, describeCert, inspectCertificates, loadPem, runOracle, seal, synthesizeMachO } from "./index.ts";
import { inspectPackage, unzip, zip, type ZipEntry } from "./ipa.ts";
import { KhatmError } from "./bytes.ts";

function assert(cond: unknown, message: string): asserts cond {
  if (!cond) throw new Error(message);
}

async function main() {
  const { pem, material } = await createSampleIdentity();
  assert(pem.includes("BEGIN CERTIFICATE"), "sample pem missing cert");
  assert(pem.includes("BEGIN PRIVATE KEY"), "sample pem missing key");
  assert(material.leaf.subjectCn === "Khatm Sample", "cn");
  assert(material.kind === "RSA", "kind");

  let rejected = false;
  try {
    await loadPem("-----BEGIN PKCS12-----\nAAAA\n-----END PKCS12-----\n");
  } catch (error) {
    rejected = error instanceof KhatmError && error.code === "pem-only";
  }
  assert(rejected, "pkcs12 pem was accepted");

  rejected = false;
  try {
    await loadPem("not a pem and not a certificate");
  } catch (error) {
    rejected = error instanceof KhatmError && error.code === "not-pem";
  }
  assert(rejected, "binary junk was accepted");

  const certOnly = pem.replace(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/, "").trim();
  const inspected = inspectCertificates(certOnly);
  assert(inspected.length === 1 && inspected[0].subjectCn === "Khatm Sample", "cert-only pem");
  const described = describeCert(inspected[0]);
  assert(described.teamId === "SAMPLETEAM" && described.kind.startsWith("RSA"), `describeCert ${described.kind}`);
  assert(inspectCertificates(inspected[0].raw)[0]?.serialHex === material.leaf.serialHex, "der cer");
  rejected = false;
  try {
    await loadPem(certOnly);
  } catch (error) {
    rejected = error instanceof KhatmError && error.code === "no-key";
  }
  assert(rejected, "certificate without a private key was accepted for sealing");

  const date = new Date(Date.UTC(2026, 9, 5, 12, 0, 0));
  const entitlements = emitEntitlements({
    "application-identifier": "SAMPLETEAM.demo.khatm",
    "com.apple.developer.team-identifier": "SAMPLETEAM",
    "get-task-allow": true,
    "keychain-access-groups": ["SAMPLETEAM.*"],
  });
  const macho = synthesizeMachO();
  const sealed = await seal(macho, material, {
    identifier: "demo.khatm",
    teamId: "SAMPLETEAM",
    entitlementsXml: entitlements,
    signingDate: date,
  });
  assert(sealed.checks.every((c) => c.ok), `padded macho checks failed: ${sealed.checks.filter((c) => !c.ok).map((c) => c.id).join(",")}`);
  assert(sealed.cdhash.length === 40, `cdhash ${sealed.cdhash}`);
  assert(!sealed.slices[0]?.requirement.includes("apple generic"), sealed.slices[0]?.requirement ?? "");
  assert((sealed.slices[0]?.flags ?? 1) === 0, "adhoc or runtime flag leaked");

  const tampered = sealed.bytes.slice();
  tampered[0x4000] ^= 0xff;
  const bad = (await import("./macho.ts")).verifyMachO(tampered);
  const pageCheck = (await bad)[0]?.checks.find((c) => c.id === "pages");
  assert(pageCheck && !pageCheck.ok, "tamper was not detected");
  const oracle = await runOracle(sealed.bytes);
  assert(oracle.notADevice && oracle.phantom === "khatm-oracle", "oracle identity");
  assert(oracle.gates.every((gate) => gate.ok), `oracle failed: ${oracle.gates.filter((gate) => !gate.ok).map((gate) => gate.id).join(",")}`);
  assert(oracle.gates.some((gate) => gate.id === "KH-G07" && gate.detail === sealed.cdhash), "oracle cdhash diverged");
  const oracleBad = await runOracle(tampered);
  assert(oracleBad.gates.some((gate) => gate.id === "KH-G06" && !gate.ok), "oracle missed a page tamper");
  assert(oracleBad.gates.some((gate) => gate.id === "KH-G08" && gate.ok), "content tamper should not be reported as a CMS failure");

  const tight = await seal(synthesizeMachO({ tight: true }), material, {
    identifier: "demo.khatm.tight",
    teamId: "SAMPLETEAM",
    signingDate: date,
  });
  assert(tight.checks.every((c) => c.ok), `tight slide failed: ${tight.checks.filter((c) => !c.ok).map((c) => `${c.id}:${c.detail}`).join(" | ")}`);

  const { zip: zipFn } = { zip };
  const fatParts = new Map<string, Uint8Array>();
  void fatParts;
  const left = (await seal(synthesizeMachO(), material, { identifier: "demo.fat", signingDate: date })).bytes;
  void left;
  const rawA = synthesizeMachO();
  const rawB = synthesizeMachO();
  const fat = packTwo(rawA, rawB);
  const fatSealed = await seal(fat, material, { identifier: "demo.fat", signingDate: date });
  assert(fatSealed.slices.length === 2, "fat slices");
  assert(fatSealed.slices.every((s) => s.checks.every((c) => c.ok)), "fat checks");

  const fat64 = packTwo64(rawA, rawB);
  const fat64Sealed = await seal(fat64, material, { identifier: "demo.fat64", signingDate: date });
  assert(new DataView(fat64Sealed.bytes.buffer, fat64Sealed.bytes.byteOffset, 4).getUint32(0, false) === 0xcafebabf, "fat64 header changed");
  assert(fat64Sealed.slices.length === 2, "fat64 slices");
  assert(fat64Sealed.slices.every((s) => s.checks.every((c) => c.ok)), "fat64 checks");

  const crcSample = await zip(new Map<string, ZipEntry>([["Payload/Test.app/file.txt", { data: new TextEncoder().encode("ok"), mode: 0o100644 }]]));
  const crcNameLength = new DataView(crcSample.buffer).getUint16(26, true);
  crcSample[30 + crcNameLength] ^= 0xff;
  rejected = false;
  try {
    await unzip(crcSample);
  } catch (error) {
    rejected = error instanceof KhatmError && error.code === "zip";
  }
  assert(rejected, "zip CRC corruption was accepted");

  const traversal = await zip(new Map<string, ZipEntry>([["evil", { data: new Uint8Array([1]), mode: 0o100644 }]]));
  const traversalLocalName = 30;
  const traversalCentralName = 35 + 46;
  traversal.set(new TextEncoder().encode("../x"), traversalLocalName);
  traversal.set(new TextEncoder().encode("../x"), traversalCentralName);
  rejected = false;
  try {
    await unzip(traversal);
  } catch (error) {
    rejected = error instanceof KhatmError && error.code === "zip";
  }
  assert(rejected, "zip traversal path was accepted");

  const trailing = await zip(new Map<string, ZipEntry>([["Payload/Test.app/file.txt", { data: new TextEncoder().encode("ok"), mode: 0o100644 }]]));
  const trailed = new Uint8Array(trailing.length + 1);
  trailed.set(trailing);
  rejected = false;
  try {
    await unzip(trailed);
  } catch (error) {
    rejected = error instanceof KhatmError && error.code === "zip";
  }
  assert(rejected, "bytes after the ZIP end record were accepted");

  const overlapped = packTwo(rawA, rawB);
  new DataView(overlapped.buffer).setUint32(28 + 8, 0x4000, false);
  rejected = false;
  try {
    await seal(overlapped, material, { identifier: "demo.overlap", signingDate: date });
  } catch (error) {
    rejected = error instanceof KhatmError && error.code === "macho";
  }
  assert(rejected, "overlapping FAT slices were accepted");

  const ipa = await sampleIpa();
  const ipaPreserved = await seal(ipa, material, { signingDate: date });
  assert(ipaPreserved.removedProfiles.length === 0, "profile should be preserved by default");
  const preservedEntries = await unzip(ipaPreserved.bytes);
  assert(!!preservedEntries.get("Payload/KhatmDemo.app/embedded.mobileprovision"), "profile was removed without an explicit option");
  const keptProfile = preservedEntries.get("Payload/KhatmDemo.app/embedded.mobileprovision")!.data;
  const keptResources = new TextDecoder().decode(preservedEntries.get("Payload/KhatmDemo.app/_CodeSignature/CodeResources")!.data);
  assert(!keptResources.includes(b64(await sha256(keptProfile))), "preserved profile was hashed into CodeResources");
  assert(keptResources.includes("embedded\\.mobileprovision"), "codesign omit rule for the profile is missing");
  const ipaSealed = await seal(ipa, material, {
    entitlementsXml: entitlements,
    signingDate: date,
    removeProvisioningProfiles: true,
  });
  assert(ipaSealed.removedProfiles.length === 1, "profile was not stripped");
  const packed = await unzip(ipaSealed.bytes);
  assert(![...packed.keys()].some((k) => k.endsWith("embedded.mobileprovision")), "profile came back");
  const exe = packed.get("Payload/KhatmDemo.app/KhatmDemo");
  const resources = packed.get("Payload/KhatmDemo.app/_CodeSignature/CodeResources");
  const readme = packed.get("Payload/KhatmDemo.app/readme.txt");
  const helper = packed.get("Payload/KhatmDemo.app/Frameworks/Helper.framework/Helper");
  assert(exe && resources && readme && helper, "ipa members missing");
  const note = new TextDecoder().decode(resources.data);
  const readmeHash = await sha256(readme.data);
  assert(note.includes(b64(readmeHash)), "resource hash missing from CodeResources");
  assert(new TextDecoder().decode(exe.data).includes("SAMPLETEAM"), "team id was not sealed into the executable");
  const exeVerify = await (await import("./macho.ts")).verifyMachO(exe.data, {
    infoPlist: packed.get("Payload/KhatmDemo.app/Info.plist")?.data,
    codeResources: resources.data,
  });
  assert(exeVerify[0]?.checks.every((c) => c.ok), `app exe ${exeVerify[0]?.checks.filter((c) => !c.ok).map((c) => c.id).join(",")}`);
  const helperVerify = await (await import("./macho.ts")).verifyMachO(helper.data, {
    infoPlist: packed.get("Payload/KhatmDemo.app/Frameworks/Helper.framework/Info.plist")?.data,
    codeResources: packed.get("Payload/KhatmDemo.app/Frameworks/Helper.framework/_CodeSignature/CodeResources")?.data,
  });
  assert(helperVerify[0]?.checks.every((c) => c.ok), `helper ${helperVerify[0]?.checks.filter((c) => !c.ok).map((c) => c.id).join(",")}`);
  assert(!new TextDecoder().decode(helper.data).includes("application-identifier"), "framework must not carry entitlements");
  assert(zipNames(ipaSealed.bytes).includes("Payload/KhatmDemo.app/"), "sealed IPA is missing the .app directory entry");
  const seen = await inspectPackage(ipa);
  assert(seen.bundleId === "demo.khatm" && seen.appPath === "Payload/KhatmDemo.app/", "package inspect");
  let bare = false;
  try {
    await inspectPackage(await zip(new Map([["readme.txt", { data: new TextEncoder().encode("x"), mode: 0o100644 }]])));
  } catch (error) {
    bare = error instanceof KhatmError && error.code === "ipa";
  }
  assert(bare, "a zip with no .app was accepted as an IPA");
  await phantomUnsignedApp();

  const der = derEntitlements({
    "application-identifier": "SAMPLETEAM.demo.khatm",
    "get-task-allow": true,
  });
  assert(der[0] === 0x70, "DER entitlements missing APPLICATION 16");
  const key = new TextEncoder().encode("get-task-allow");
  assert(includes(der, key), "DER missing key");
  assert(includes(der, new Uint8Array([0x01, 0x01, 0xff])), "DER missing true");

  const again = await seal(macho, material, {
    identifier: "demo.khatm",
    teamId: "SAMPLETEAM",
    entitlementsXml: entitlements,
    signingDate: date,
  });
  assert(again.cdhash === sealed.cdhash, "RSA seal was not deterministic");
  assert(bytesEqual(again.bytes, sealed.bytes), "signed bytes drifted");
  void zipFn;
  console.log("SELFTEST_OK", sealed.cdhash);
}

async function phantomUnsignedApp() {
  const id = "com.apple.mobile.MobileHouseArrest";
  const info = new TextEncoder().encode(
    `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${id}</string><key>CFBundleExecutable</key><string>3105</string><key>CFBundleShortVersionString</key><string>2.0</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>\n`,
  );
  const unsigned = await zip(
    new Map<string, ZipEntry>([
      ["Payload/3105.app/Info.plist", { data: info, mode: 0o100644 }],
      ["Payload/3105.app/3105", { data: synthesizeMachO(), mode: 0o100755 }],
    ]),
    { directories: true },
  );
  const seen = await inspectPackage(unsigned);
  assert(seen.bundleId === id && seen.appPath === "Payload/3105.app/" && seen.version === "2.0", "phantom inspect");
  const { material } = await createSampleIdentity();
  const wrong = `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>application-identifier</key><string>SAMPLETEAM.demo.khatm</string><key>com.apple.developer.team-identifier</key><string>SAMPLETEAM</string><key>get-task-allow</key><true/></dict></plist>\n`;
  const sealed = await seal(unsigned, material, { entitlementsXml: wrong, signingDate: new Date("2026-01-01T00:00:00Z") });
  assert(sealed.format === "ipa", "phantom format");
  const again = await inspectPackage(sealed.bytes);
  assert(again.bundleId === id, "seal rewrote the bundle id");
  const packed = await unzip(sealed.bytes);
  const exe = new TextDecoder().decode(packed.get("Payload/3105.app/3105")!.data);
  assert(exe.includes(`SAMPLETEAM.${id}`), "entitlement was left on demo.khatm");
  assert(!exe.includes("SAMPLETEAM.demo.khatm"), "stale demo entitlement survived");
  assert(zipNames(sealed.bytes).includes("Payload/3105.app/"), "sealed phantom lost the .app directory");
}

function zipNames(buffer: Uint8Array): string[] {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let eocd = -1;
  for (let i = buffer.length - 22; i >= 0; i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return [];
  const count = view.getUint16(eocd + 10, true);
  let at = view.getUint32(eocd + 16, true);
  const names: string[] = [];
  for (let n = 0; n < count; n++) {
    const nameLen = view.getUint16(at + 28, true);
    const extraLen = view.getUint16(at + 30, true);
    const commentLen = view.getUint16(at + 32, true);
    names.push(new TextDecoder().decode(buffer.subarray(at + 46, at + 46 + nameLen)));
    at += 46 + nameLen + extraLen + commentLen;
  }
  return names;
}

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function includes(hay: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}

function packTwo(a: Uint8Array, b: Uint8Array): Uint8Array {
  const align = 0x4000;
  const offA = align;
  const offB = align * 2 + align * Math.ceil(a.length / align);
  const out = new Uint8Array(offB + b.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, 0xcafebabe, false);
  view.setUint32(4, 2, false);
  const writeArch = (o: number, offset: number, size: number) => {
    view.setUint32(o, 0x0100000c, false);
    view.setUint32(o + 4, 0, false);
    view.setUint32(o + 8, offset, false);
    view.setUint32(o + 12, size, false);
    view.setUint32(o + 16, 14, false);
  };
  writeArch(8, offA, a.length);
  writeArch(28, offB, b.length);
  out.set(a, offA);
  out.set(b, offB);
  return out;
}

function packTwo64(a: Uint8Array, b: Uint8Array): Uint8Array {
  const align = 0x4000;
  const offA = align;
  const offB = align * 2 + align * Math.ceil(a.length / align);
  const out = new Uint8Array(offB + b.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, 0xcafebabf, false);
  view.setUint32(4, 2, false);
  const writeArch = (o: number, offset: number, size: number) => {
    view.setUint32(o, 0x0100000c, false);
    view.setUint32(o + 4, 0, false);
    view.setBigUint64(o + 8, BigInt(offset), false);
    view.setBigUint64(o + 16, BigInt(size), false);
    view.setUint32(o + 24, 14, false);
    view.setUint32(o + 28, 0, false);
  };
  writeArch(8, offA, a.length);
  writeArch(40, offB, b.length);
  out.set(a, offA);
  out.set(b, offB);
  return out;
}

async function sampleIpa(): Promise<Uint8Array> {
  const macho = synthesizeMachO();
  const helper = synthesizeMachO();
  const info = (id: string, exe: string, pkg: string) =>
    new TextEncoder().encode(
      `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${id}</string><key>CFBundleExecutable</key><string>${exe}</string><key>CFBundlePackageType</key><string>${pkg}</string></dict></plist>\n`,
    );
  const entries = new Map<string, ZipEntry>([
    ["Payload/KhatmDemo.app/Info.plist", { data: info("demo.khatm", "KhatmDemo", "APPL"), mode: 0o100644 }],
    ["Payload/KhatmDemo.app/KhatmDemo", { data: macho, mode: 0o100755 }],
    ["Payload/KhatmDemo.app/readme.txt", { data: new TextEncoder().encode("khatm\n"), mode: 0o100644 }],
    ["Payload/KhatmDemo.app/embedded.mobileprovision", { data: new Uint8Array([0x30, 0x03, 0x01, 0x01, 0xff]), mode: 0o100644 }],
    ["Payload/KhatmDemo.app/Frameworks/Helper.framework/Info.plist", { data: info("demo.khatm.helper", "Helper", "FMWK"), mode: 0o100644 }],
    ["Payload/KhatmDemo.app/Frameworks/Helper.framework/Helper", { data: helper, mode: 0o100755 }],
  ]);
  return zip(entries);
}

void main().then(
  () => undefined,
  (error) => {
    console.error(error);
    process.exit(1);
  },
);
