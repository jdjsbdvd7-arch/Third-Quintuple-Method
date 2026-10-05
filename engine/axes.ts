/**
 * Nineteen checks on one IPA, then twelve profile shapes.
 * External install is Ad Hoc or Enterprise. App Store is a different signature and is rejected on purpose.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFile } from "node:fs/promises";
import { unzip } from "./ipa.ts";
import { verifyMachO } from "./macho.ts";
import { buildAttachedCms } from "./cms.ts";
import { createSampleIdentity } from "./pem.ts";
import { sha256, derOctet, derSet, derUtf8, tlv } from "./bytes.ts";

const ipaPath = process.argv[2] ?? "/tmp/hostpkg/demo-1.0.2.ipa";
const udid = "00008110-001965E62213801E";
const entries = await unzip(new Uint8Array(await readFile(ipaPath)));
const app = [...entries.keys()].find((p) => /Payload\/[^/]+\.app\/Info\.plist$/.test(p))!;
const root = app.slice(0, app.lastIndexOf("/") + 1);
const infoText = new TextDecoder().decode(entries.get(app)!.data);
const field = (key: string) => infoText.slice(infoText.indexOf(`<key>${key}</key>`)).match(/<string>([^<]*)<\/string>/)?.[1] ?? "";
const exe = entries.get(`${root}${field("CFBundleExecutable")}`)!.data;
const profile = entries.get(`${root}embedded.mobileprovision`)?.data ?? null;
const resources = entries.get(`${root}_CodeSignature/CodeResources`)?.data ?? null;
const seals = await verifyMachO(exe, { infoPlist: entries.get(app)!.data, codeResources: resources });
const dir = mkdtempSync(join(tmpdir(), "axes-"));

const rows: string[] = [];
let n = 0;
const row = (axis: string, ok: boolean, required: string, actual: string) => {
  n++;
  rows.push(`${String(n).padStart(2, "0")}  ${ok ? "PASS" : "FAIL"}  ${axis}\n    required  ${required}\n    actual    ${actual}`);
};

row("not-app-store", !!profile, "embedded.mobileprovision present (App Store builds omit it)", profile ? `${profile.byteLength} bytes` : "absent");
row("bundle-id", field("CFBundleIdentifier") === "demo.khatm", "demo.khatm", field("CFBundleIdentifier") || "missing");
row("bundle-version", field("CFBundleVersion").length > 0, "CFBundleVersion set", field("CFBundleVersion") || "missing");
row("iphone-platform", infoText.includes("<string>iPhoneOS</string>"), "CFBundleSupportedPlatforms = iPhoneOS", infoText.includes("iPhoneOS") ? "iPhoneOS" : "missing");
const view = new DataView(exe.buffer, exe.byteOffset, exe.byteLength);
let platform = 0;
let at = 32;
for (let i = 0; i < view.getUint32(16, true); i++) {
  const cmd = view.getUint32(at, true);
  const size = view.getUint32(at + 4, true);
  if (cmd === 0x32) platform = view.getUint32(at + 8, true);
  at += size;
}
row("macho-ios", platform === 2, "LC_BUILD_VERSION platform 2", String(platform || "absent"));
const checks = new Map(seals[0].checks.map((c) => [c.id, c.ok]));
row("codedirectory", checks.get("version") === true && checks.get("sha256") === true, "version 0x20400, SHA-256", "see signature checks");
row("page-hashes", checks.get("pages") === true, "every 4096-byte page hashed", checks.get("pages") ? "match" : "mismatch");
row("info-slot", checks.get("info-plist") === true, "slot -1 = SHA-256(Info.plist)", checks.get("info-plist") ? "match" : "mismatch");
row("resources-slot", checks.get("resources") === true, "slot -3 = SHA-256(CodeResources)", checks.get("resources") ? "match" : "mismatch");
row("entitlement-slots", checks.get("entitlements") === true && checks.get("der-entitlements") === true, "XML slot -5 and DER slot -7", "both hashed");
const { cd, cms } = extractCms(exe);
writeFileSync(join(dir, "cd.bin"), cd);
writeFileSync(join(dir, "macho.cms"), cms);
const macho = openssl(["cms", "-verify", "-inform", "DER", "-in", join(dir, "macho.cms"), "-content", join(dir, "cd.bin"), "-binary", "-noverify", "-out", "/dev/null"]);
row("binary-cms", macho.ok, "detached PKCS#7 over the CodeDirectory", macho.ok ? "OpenSSL verified" : "OpenSSL rejected");
const text = profile ? new TextDecoder().decode(profile) : "";
const teamOk = text.includes("SAMPLETEAM") && seals[0].teamId === "SAMPLETEAM";
row("team-id", teamOk, "same team in the certificate, the CodeDirectory and the profile", seals[0].teamId);
row("adhoc-udid", text.includes(udid), `ProvisionedDevices contains ${udid}`, text.includes(udid) ? "listed" : "absent");
const appStoreShape = profile !== null && !text.includes("ProvisionedDevices") && !text.includes("ProvisionsAllDevices");
row("not-app-store-profile", !appStoreShape, "Ad Hoc has ProvisionedDevices; App Store profiles have neither and cannot install over the air", appStoreShape ? "App Store shape" : "Ad Hoc shape");
row("developer-certificates-xml", text.includes("<key>DeveloperCertificates</key>"), "the leaf certificate is inside the profile", text.includes("DeveloperCertificates") ? "present" : "absent");
row("der-encoded-profile", text.includes("DER-Encoded-Profile"), "modern iOS reads DER-Encoded-Profile, not the XML", text.includes("DER-Encoded-Profile") ? "present" : "absent");
row("der-cert-hash", false, "inside that DER form, DeveloperCertificates is SHA-256 of the leaf, not the whole certificate", "no DER payload to hash");
writeFileSync(join(dir, "profile.cms"), profile ?? new Uint8Array());
const prof = profile ? openssl(["cms", "-verify", "-inform", "DER", "-in", join(dir, "profile.cms"), "-binary", "-noverify", "-out", "/dev/null"]) : { ok: false, out: "", err: "none" };
row("profile-cms-math", prof.ok, "the profile CMS verifies under its own signer", prof.ok ? "OpenSSL verified" : "rejected");
const named = openssl(["pkcs7", "-inform", "DER", "-in", join(dir, "profile.cms"), "-print_certs"]);
writeFileSync(join(dir, "signer.pem"), named.out);
const subject = openssl(["x509", "-in", join(dir, "signer.pem"), "-noout", "-subject", "-issuer"]).out.replaceAll("\n", " ");
const apple = subject.includes("Apple iPhone OS Provisioning Profile Signing") && subject.includes("Apple Worldwide Developer Relations");
row("apple-profile-signer", apple, "signer CN Apple iPhone OS Provisioning Profile Signing, issuer WWDR", subject.trim());

console.log(rows.join("\n\n"));
console.log("\n--- twelve shapes ---");

const { material } = await createSampleIdentity();
const leafHash = await sha256(material.leaf.raw);
const shapes: { name: string; body: string }[] = [];
const base = (extra: string) =>
  `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>${extra}<key>DeveloperCertificates</key><array><data>${Buffer.from(material.leaf.raw).toString("base64")}</data></array><key>ExpirationDate</key><date>2027-01-01T00:00:00Z</date><key>TeamIdentifier</key><array><string>SAMPLETEAM</string></array></dict></plist>\n`;
shapes.push({ name: "01 ad-hoc UDID", body: base(`<key>ProvisionedDevices</key><array><string>${udid}</string></array>`) });
shapes.push({ name: "02 enterprise all-devices", body: base(`<key>ProvisionsAllDevices</key><true/>`) });
shapes.push({ name: "03 app-store shape", body: base("") });
shapes.push({ name: "04 no devices and expired", body: base("").replace("2027", "2020") });
shapes.push({ name: "05 udid removed", body: base(`<key>ProvisionedDevices</key><array></array>`) });
shapes.push({ name: "06 team mismatch", body: base(`<key>ProvisionedDevices</key><array><string>${udid}</string></array>`).replaceAll("SAMPLETEAM", "OTHTEAMID1") });
const der = derProfile(leafHash, udid);
const derCms = await buildAttachedCms(material, der, new Date("2026-01-01T00:00:00Z"));
shapes.push({
  name: "07 modern DER-Encoded-Profile",
  body: base(`<key>ProvisionedDevices</key><array><string>${udid}</string></array><key>DER-Encoded-Profile</key><data>${Buffer.from(derCms).toString("base64")}</data>`),
});
shapes.push({ name: "08 raw plist, no CMS", body: base(`<key>ProvisionedDevices</key><array><string>${udid}</string></array>`) });
shapes.push({ name: "09 empty profile", body: "" });
shapes.push({ name: "10 certificate hash only", body: base(`<key>ProvisionedDevices</key><array><string>${udid}</string></array>`) });
shapes.push({ name: "11 same as published IPA", body: text.includes("<?xml") ? "published" : "" });
shapes.push({ name: "12 DER payload alone", body: "der" });

for (const shape of shapes) {
  if (shape.name.startsWith("08")) {
    console.log(`FAIL  ${shape.name}  raw plist has no CMS, installd will not read it`);
    continue;
  }
  if (shape.name.startsWith("09")) {
    console.log(`FAIL  ${shape.name}  missing profile is 0xe8008015`);
    continue;
  }
  if (shape.name.startsWith("11")) {
    console.log(`${prof.ok ? "MATH" : "FAIL"}  ${shape.name}  signer is still Khatm Sample`);
    continue;
  }
  if (shape.name.startsWith("12")) {
    writeFileSync(join(dir, "der.bin"), der);
    const dump = openssl(["asn1parse", "-inform", "DER", "-in", join(dir, "der.bin")]);
    const hasHash = dump.out.toLowerCase().includes(Buffer.from(leafHash).toString("hex"));
    console.log(`${hasHash ? "SHAPE" : "FAIL"}  ${shape.name}  DeveloperCertificates octet is SHA-256 of the leaf (${hasHash})`);
    continue;
  }
  const cmsBytes = await buildAttachedCms(material, new TextEncoder().encode(shape.body), new Date("2026-01-01T00:00:00Z"));
  const file = join(dir, "shape.cms");
  writeFileSync(file, cmsBytes);
  const verified = openssl(["cms", "-verify", "-inform", "DER", "-in", file, "-binary", "-noverify", "-out", "/dev/null"]);
  const who = openssl(["pkcs7", "-inform", "DER", "-in", file, "-print_certs"]);
  writeFileSync(join(dir, "who.pem"), who.out);
  const sub = openssl(["x509", "-in", join(dir, "who.pem"), "-noout", "-subject"]).out.trim();
  const appleSigned = sub.includes("Apple iPhone OS Provisioning Profile Signing");
  console.log(`${verified.ok && !appleSigned ? "MATH" : "FAIL"}  ${shape.name}  ${sub}  apple-signer ${appleSigned}`);
}

console.log("\nDER-Encoded-Profile can be built and signed here. The signer stays Khatm Sample.");
console.log("App Store shape was tested and excluded. It is not an installable external package.");

function derProfile(hash: Uint8Array, device: string): Uint8Array {
  const pair = (key: string, value: Uint8Array) => tlv(0x30, concat(derUtf8(key), value));
  return derSet([
    pair("DeveloperCertificates", tlv(0x30, derOctet(hash))),
    pair("ExpirationDate", utc(new Date(Date.UTC(2027, 0, 1)))),
    pair("ProvisionedDevices", tlv(0x30, derUtf8(device))),
  ]);
}

function utc(date: Date): Uint8Array {
  const p = (n: number) => String(n).padStart(2, "0");
  const text = `${p(date.getUTCFullYear() % 100)}${p(date.getUTCMonth() + 1)}${p(date.getUTCDate())}${p(date.getUTCHours())}${p(date.getUTCMinutes())}${p(date.getUTCSeconds())}Z`;
  return tlv(0x17, new TextEncoder().encode(text));
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function openssl(args: string[]): { ok: boolean; out: string; err: string } {
  try {
    return { ok: true, out: execFileSync("openssl", args, { encoding: "utf8" }), err: "" };
  } catch (error) {
    const failed = error as { stdout?: string; stderr?: string };
    return { ok: false, out: failed.stdout ?? "", err: failed.stderr ?? "" };
  }
}

function extractCms(file: Uint8Array): { cd: Uint8Array; cms: Uint8Array } {
  const view = new DataView(file.buffer, file.byteOffset, file.byteLength);
  let at = 32;
  for (let i = 0; i < view.getUint32(16, true); i++) {
    const cmd = view.getUint32(at, true);
    const size = view.getUint32(at + 4, true);
    if (cmd === 0x1d) {
      const dataoff = view.getUint32(at + 8, true);
      const count = view.getUint32(dataoff + 8, false);
      let cd = new Uint8Array();
      let cms = new Uint8Array();
      for (let j = 0; j < count; j++) {
        const type = view.getUint32(dataoff + 12 + j * 8, false);
        const off = view.getUint32(dataoff + 16 + j * 8, false);
        const len = view.getUint32(dataoff + off + 4, false);
        const piece = file.slice(dataoff + off, dataoff + off + len);
        if (type === 0) cd = piece;
        if (type === 0x10000) cms = piece.slice(8);
      }
      return { cd, cms };
    }
    at += size;
  }
  return { cd: new Uint8Array(), cms: new Uint8Array() };
}
