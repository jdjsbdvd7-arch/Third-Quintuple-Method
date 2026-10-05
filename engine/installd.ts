/**
 * installd's order, after the itms-services download.
 * OpenSSL checks the CMS mathematics. Trust is a separate line.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFile } from "node:fs/promises";
import { unzip } from "./ipa.ts";
import { verifyMachO } from "./macho.ts";

const ipaPath = process.argv[2];
if (!ipaPath) throw new Error("usage: installd.ts <ipa> [udid]");
const udid = process.argv[3] ?? "00008110-001965E62213801E";
const entries = await unzip(new Uint8Array(await readFile(ipaPath)));
const lines: string[] = [];
const fail: string[] = [];
const note = (layer: string, ok: boolean, detail: string) => {
  lines.push(`${ok ? "PASS" : "FAIL"}  ${layer}  ${detail}`);
  if (!ok) fail.push(layer);
};

const app = [...entries.keys()].find((path) => /Payload\/[^/]+\.app\/Info\.plist$/.test(path));
note("bundle", !!app, app ?? "no Payload/*.app/Info.plist");
if (!app) throw new Error(lines.join("\n"));
const root = app.slice(0, app.lastIndexOf("/") + 1);
const info = entries.get(app)!.data;
const infoText = new TextDecoder().decode(info);
const value = (key: string) => infoText.slice(infoText.indexOf(`<key>${key}</key>`)).match(/<string>([^<]*)<\/string>/)?.[1] ?? "";
const bundleId = value("CFBundleIdentifier");
const executable = value("CFBundleExecutable");
const version = value("CFBundleVersion");
note("identifier", !!bundleId, bundleId || "missing");
note("executable-name", !!executable, executable || "missing");
note("bundle-version", !!version, version || "CFBundleVersion missing");
const exe = entries.get(`${root}${executable}`)?.data;
note("executable-bytes", !!exe, exe ? `${exe.byteLength} bytes` : "missing");
if (!exe) throw new Error(lines.join("\n"));
const view = new DataView(exe.buffer, exe.byteOffset, exe.byteLength);
note("macho64", view.getUint32(0, true) === 0xfeedfacf, `magic 0x${view.getUint32(0, true).toString(16)}`);
let platform = 0;
let offset = 32;
const ncmds = view.getUint32(16, true);
for (let i = 0; i < ncmds; i++) {
  const cmd = view.getUint32(offset, true);
  const size = view.getUint32(offset + 4, true);
  if (cmd === 0x32) platform = view.getUint32(offset + 8, true);
  offset += size;
}
note("ios-platform", platform === 2, `LC_BUILD_VERSION platform ${platform || "absent"}`);
const resources = entries.get(`${root}_CodeSignature/CodeResources`)?.data ?? null;
const seals = await verifyMachO(exe, { infoPlist: info, codeResources: resources });
for (const seal of seals) {
  for (const check of seal.checks) note(`signature.${check.id}`, check.ok, check.detail);
}

const dir = mkdtempSync(join(tmpdir(), "installd-"));
const profile = entries.get(`${root}embedded.mobileprovision`)?.data;
note("profile-present", !!profile, profile ? `${profile.byteLength} bytes` : "0xe8008015, no profile");
if (profile && exe) {
  const { cd, cms } = extractCms(exe);
  writeFileSync(join(dir, "cd.bin"), cd);
  writeFileSync(join(dir, "macho.cms"), cms);
  writeFileSync(join(dir, "profile.cms"), profile);
  const macho = openssl(["cms", "-verify", "-inform", "DER", "-in", join(dir, "macho.cms"), "-content", join(dir, "cd.bin"), "-binary", "-noverify", "-out", "/dev/null"]);
  note("openssl-macho-cms", macho.ok, macho.ok ? "digest matches the CodeDirectory" : macho.err.split("\n").at(-1) || "verify failed");
  const prof = openssl(["cms", "-verify", "-inform", "DER", "-in", join(dir, "profile.cms"), "-binary", "-noverify", "-out", join(dir, "profile.xml")]);
  note("openssl-profile-cms", prof.ok, prof.ok ? "plist signature is mathematically valid" : prof.err.split("\n").at(-1) || "verify failed");
  const xml = prof.ok ? readFileSync(join(dir, "profile.xml"), "utf8") : "";
  note("udid-listed", xml.includes(udid), udid);
  const identity = openssl(["pkcs7", "-inform", "DER", "-in", join(dir, "profile.cms"), "-print_certs"]);
  writeFileSync(join(dir, "signer.pem"), identity.out);
  const named = openssl(["x509", "-in", join(dir, "signer.pem"), "-noout", "-subject", "-issuer"]);
  const subject = named.out.replaceAll("\n", " | ").trim();
  const apple = subject.includes("Apple iPhone OS Provisioning Profile Signing");
  const wwdr = subject.includes("Apple Worldwide Developer Relations");
  note("profile-apple-signer", apple, subject || named.err);
  note("wwdr-issuer", wwdr, wwdr ? "WWDR" : "zsign stops here: no WWDR intermediate matches the issuer");
}

console.log(lines.join("\n"));
console.log(fail.length ? `\nSTOP  ${fail.join(", ")}` : "\nSTOP  none");

function openssl(args: string[]): { ok: boolean; out: string; err: string } {
  try {
    const out = execFileSync("openssl", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return { ok: true, out, err: "" };
  } catch (error) {
    const failed = error as { stdout?: string; stderr?: string };
    return { ok: false, out: failed.stdout ?? "", err: (failed.stderr ?? "").trim() };
  }
}

function extractCms(file: Uint8Array): { cd: Uint8Array; cms: Uint8Array } {
  const view = new DataView(file.buffer, file.byteOffset, file.byteLength);
  let at = 32;
  const ncmds = view.getUint32(16, true);
  for (let i = 0; i < ncmds; i++) {
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
