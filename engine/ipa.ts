import { KhatmError, concat, digest, ownedBuffer, sha256, utf8 } from "./bytes.ts";
import { signMachO, type SliceSeal } from "./macho.ts";
import type { PemMaterial } from "./pem.ts";
import { emitEntitlements, infoKeys, replaceBundleId, sealEntitlementsXml, type PlistDict } from "./plist.ts";

export type ZipEntry = { data: Uint8Array; mode: number };

export type IpaOptions = {
  /** Override the outermost .app bundle identifier. */
  bundleId?: string;
  /** Entitlements plist for the outermost app. Undefined synthesizes team + application-identifier. "" seals none. */
  entitlementsXml?: string;
  /** Remove embedded provisioning profiles only when the selected distribution policy permits it. */
  removeProvisioningProfiles?: boolean;
  teamId?: string;
  signingDate?: Date;
  hardenedRuntime?: boolean;
};

export type IpaSeal = {
  bytes: Uint8Array;
  slices: SliceSeal[];
  removedProfiles: string[];
  bundles: { path: string; identifier: string; cdhash: string }[];
};

const BUNDLE_RE = /(?:^|\/)([^/]+\.(?:app|framework|appex|xpc|bundle))\/$/;

export async function signIpa(input: Uint8Array, material: PemMaterial, opts: IpaOptions = {}): Promise<IpaSeal> {
  const entries = await unzip(input);
  const removedProfiles: string[] = [];
  if (opts.removeProvisioningProfiles) {
    for (const path of [...entries.keys()]) {
      if (path.endsWith("embedded.mobileprovision") || path.endsWith("embedded.provisionprofile")) {
        entries.delete(path);
        removedProfiles.push(path);
      }
    }
  }
  const roots = bundleRoots(entries).sort((a, b) => b.split("/").length - a.split("/").length);
  const apps = roots.filter((root) => root.endsWith(".app/"));
  if (apps.length === 0) {
    throw new KhatmError("ipa", "No .app bundle. iOS installs Payload/Name.app inside the IPA, not the zip by itself.");
  }
  const main = apps.sort((a, b) => a.length - b.length)[0];
  const seals = new Map<string, { cdhash: Uint8Array; identifier: string; slices: SliceSeal[] }>();
  const bundles: IpaSeal["bundles"] = [];
  for (const root of roots) {
    const seal = await signOneBundle(entries, root, roots, seals, material, opts, root === main);
    seals.set(root, seal);
    bundles.push({ path: root, identifier: seal.identifier, cdhash: hexOf(seal.cdhash) });
  }
  const mainSeal = seals.get(main);
  return {
    bytes: await zip(entries, { directories: true, deflate: true }),
    slices: mainSeal?.slices ?? [],
    removedProfiles,
    bundles,
  };
}

async function signOneBundle(
  entries: Map<string, ZipEntry>,
  root: string,
  roots: string[],
  seals: Map<string, { cdhash: Uint8Array; identifier: string; slices: SliceSeal[] }>,
  material: PemMaterial,
  opts: IpaOptions,
  isMain: boolean,
): Promise<{ cdhash: Uint8Array; identifier: string; slices: SliceSeal[] }> {
  const infoPath = `${root}Info.plist`;
  const infoEntry = entries.get(infoPath);
  if (!infoEntry) throw new KhatmError("ipa", `No Info.plist in ${root}`);
  if (isMain && opts.bundleId) infoEntry.data = replaceBundleId(infoEntry.data, opts.bundleId);
  const info = infoKeys(infoEntry.data);
  const teamId = opts.teamId?.trim() || material.leaf.subjectOu.find((ou) => /^[A-Za-z0-9]{10}$/.test(ou)) || material.leaf.subjectOu[0] || "";
  const children = directChildren(root, roots);
  const files = [...entries.keys()].filter((path) => path.startsWith(root) && !path.endsWith("/"));
  const insideChild = (path: string) => children.some((child) => path.startsWith(child));
  const executablePath = `${root}${info.executable}`;
  for (const path of files) {
    if (path === executablePath || path === infoPath || insideChild(path)) continue;
    if (path.slice(root.length).startsWith("_CodeSignature/")) continue;
    const entry = entries.get(path);
    if (!entry) continue;
    if (isMachO(entry.data)) {
      const rel = path.slice(root.length);
      const signed = await signMachO(entry.data, material, {
        identifier: rel.split("/").pop() || info.bundleId,
        teamId,
        signingDate: opts.signingDate,
        hardenedRuntime: opts.hardenedRuntime,
        entitlements: null,
      });
      entry.data = signed.bytes;
      entry.mode = 0o100755;
      seals.set(path, {
        cdhash: fromHex(signed.slices[0]?.cdhash ?? ""),
        identifier: rel,
        slices: signed.slices,
      });
    }
  }
  const resources = await buildCodeResources(root, entries, children, seals, executablePath);
  const resourcesPath = `${root}_CodeSignature/CodeResources`;
  entries.set(resourcesPath, { data: utf8(resources), mode: 0o100644 });
  const exe = entries.get(executablePath);
  if (!exe) throw new KhatmError("ipa", `Executable ${info.executable} is missing from ${root}`);
  const raw = bundleWantsEntitlements(root)
    ? isMain
      ? mainEntitlements(opts.entitlementsXml, teamId, info.bundleId)
      : nestedEntitlements(teamId, info.bundleId)
    : null;
  const entitlements = bindEntitlements(raw, teamId, info.bundleId);
  const signed = await signMachO(exe.data, material, {
    identifier: info.bundleId,
    teamId,
    infoPlist: entries.get(infoPath)?.data ?? null,
    codeResources: entries.get(resourcesPath)?.data ?? null,
    entitlements,
    signingDate: opts.signingDate,
    hardenedRuntime: opts.hardenedRuntime,
  });
  exe.data = signed.bytes;
  exe.mode = 0o100755;
  const cd = fromHex(signed.slices[0]?.cdhash ?? "");
  return { cdhash: cd, identifier: info.bundleId, slices: signed.slices };
}

function bindEntitlements(
  ent: { dict: PlistDict; xml: Uint8Array } | null,
  teamId: string,
  bundleId: string,
): { dict: PlistDict; xml: Uint8Array } | null {
  if (!ent || !teamId || !bundleId) return ent;
  const dict: PlistDict = {
    ...ent.dict,
    "application-identifier": `${teamId}.${bundleId}`,
    "com.apple.developer.team-identifier": teamId,
  };
  return { dict, xml: utf8(emitEntitlements(dict)) };
}

function bundleWantsEntitlements(root: string): boolean {
  return root.endsWith(".app/") || root.endsWith(".appex/");
}

export type PackageInfo = { bundleId: string; version: string; title: string; appPath: string };

/** Read the outermost .app. Does not sign and does not require a private key. */
export async function inspectPackage(input: Uint8Array): Promise<PackageInfo> {
  const entries = await unzip(input);
  const apps = bundleRoots(entries).filter((root) => root.endsWith(".app/")).sort((a, b) => a.length - b.length);
  if (apps.length === 0) {
    throw new KhatmError("ipa", "No .app bundle. iOS installs Payload/Name.app inside the IPA, not the zip by itself.");
  }
  const info = infoKeys(entries.get(`${apps[0]}Info.plist`)!.data);
  return { bundleId: info.bundleId, version: info.version, title: info.title, appPath: apps[0] };
}

function mainEntitlements(xml: string | undefined, teamId: string, bundleId: string): { dict: PlistDict; xml: Uint8Array } | null {
  if (xml === "") return null;
  if (xml && xml.trim()) return sealEntitlementsXml(xml);
  if (!teamId) return null;
  const dict: PlistDict = {
    "application-identifier": `${teamId}.${bundleId}`,
    "com.apple.developer.team-identifier": teamId,
  };
  const text = emitEntitlements(dict);
  return { dict, xml: utf8(text) };
}

function nestedEntitlements(teamId: string, id: string): { dict: PlistDict; xml: Uint8Array } | null {
  if (!teamId) return null;
  const dict: PlistDict = {
    "application-identifier": `${teamId}.${id}`,
    "com.apple.developer.team-identifier": teamId,
  };
  return { dict, xml: utf8(emitEntitlements(dict)) };
}

type Rule = { pattern: string; re: RegExp; omit?: boolean; weight: number };

const RULES_V1: Rule[] = [
  { pattern: "^.*", re: /^.*$/, weight: 1 },
  { pattern: "^Info\\.plist$", re: /^Info\.plist$/, omit: true, weight: 20 },
  { pattern: "^PkgInfo$", re: /^PkgInfo$/, omit: true, weight: 20 },
  { pattern: "^embedded\\.provisionprofile$", re: /^embedded\.provisionprofile$/, omit: true, weight: 20 },
  { pattern: "^embedded\\.mobileprovision$", re: /^embedded\.mobileprovision$/, omit: true, weight: 20 },
  { pattern: "^version\\.plist$", re: /^version\.plist$/, omit: true, weight: 20 },
];

const RULES_V2: Rule[] = [
  { pattern: "^.*", re: /^.*$/, weight: 1 },
  { pattern: ".*\\.lproj/", re: /.*\.lproj\//, weight: 1000 },
  { pattern: ".*\\.lproj/locversion.plist$", re: /.*\.lproj\/locversion\.plist$/, omit: true, weight: 1100 },
  { pattern: "^Base\\.lproj/", re: /^Base\.lproj\//, weight: 1010 },
  { pattern: "^version\\.plist$", re: /^version\.plist$/, weight: 20 },
  { pattern: "^Info\\.plist$", re: /^Info\.plist$/, omit: true, weight: 20 },
  { pattern: "^PkgInfo$", re: /^PkgInfo$/, omit: true, weight: 20 },
  { pattern: "^embedded\\.provisionprofile$", re: /^embedded\.provisionprofile$/, omit: true, weight: 20 },
  { pattern: "^embedded\\.mobileprovision$", re: /^embedded\.mobileprovision$/, omit: true, weight: 20 },
];

function best(path: string, rules: Rule[]): Rule {
  let winner = rules[0];
  for (const rule of rules) {
    if (rule.re.test(path) && rule.weight >= winner.weight) winner = rule;
  }
  return winner;
}

async function buildCodeResources(
  root: string,
  entries: Map<string, ZipEntry>,
  children: string[],
  seals: Map<string, { cdhash: Uint8Array; identifier: string }>,
  executablePath: string,
): Promise<string> {
  const files = [...entries.keys()].filter((path) => path.startsWith(root) && !path.endsWith("/"));
  const rows1: string[] = [];
  const rows2: string[] = [];
  const rels: string[] = [];
  for (const path of files) {
    if (path === executablePath) continue;
    if (path.slice(root.length).startsWith("_CodeSignature/")) continue;
    if (children.some((child) => path.startsWith(child))) continue;
    rels.push(path.slice(root.length));
  }
  rels.sort();
  for (const rel of rels) {
    const data = entries.get(root + rel)?.data;
    if (!data || isMachO(data)) continue;
    if (!best(rel, RULES_V1).omit) {
      const sum = await digest("SHA-1", data);
      rows1.push(`\t\t<key>${escapeXml(rel)}</key>\n\t\t<data>${b64(sum)}</data>`);
    }
    if (!best(rel, RULES_V2).omit) {
      const sum = await sha256(data);
      rows2.push(
        `\t\t<key>${escapeXml(rel)}</key>\n\t\t<dict>\n\t\t\t<key>hash2</key>\n\t\t\t<data>${b64(sum)}</data>\n\t\t</dict>`,
      );
    }
  }
  const nestedRels = children
    .map((child) => ({ rel: child.slice(root.length).replace(/\/$/, ""), seal: seals.get(child) }))
    .filter((item) => item.seal)
    .sort((a, b) => a.rel.localeCompare(b.rel));
  for (const item of nestedRels) {
    rows2.push(nestedXml(item.rel, item.seal!.cdhash, item.seal!.identifier));
  }
  for (const rel of rels) {
    const seal = seals.get(root + rel);
    if (!seal) continue;
    rows2.push(nestedXml(rel, seal.cdhash, seal.identifier));
  }
  rows2.sort();
  return (
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
    `<plist version="1.0">\n<dict>\n` +
    `\t<key>files</key>\n\t<dict>\n${rows1.join("\n")}\n\t</dict>\n` +
    `\t<key>files2</key>\n\t<dict>\n${rows2.join("\n")}\n\t</dict>\n` +
    `\t<key>rules</key>\n\t<dict>\n${rulesXml(RULES_V1)}\n\t</dict>\n` +
    `\t<key>rules2</key>\n\t<dict>\n${rulesXml(RULES_V2)}\n\t</dict>\n` +
    `</dict>\n</plist>\n`
  );
}

function rulesXml(rules: Rule[]): string {
  return rules
    .map((rule) => {
      const key = `\t\t<key>${escapeXml(rule.pattern)}</key>`;
      if (!rule.omit && rule.weight === 1) return `${key}\n\t\t<true/>`;
      const bits = [
        rule.omit ? `\t\t\t<key>omit</key>\n\t\t\t<true/>` : "",
        `\t\t\t<key>weight</key>\n\t\t\t<integer>${rule.weight}</integer>`,
      ].filter(Boolean);
      return `${key}\n\t\t<dict>\n${bits.join("\n")}\n\t\t</dict>`;
    })
    .join("\n");
}

function nestedXml(rel: string, cdhash: Uint8Array, identifier: string): string {
  return (
    `\t\t<key>${escapeXml(rel)}</key>\n\t\t<dict>\n` +
    `\t\t\t<key>cdhash</key>\n\t\t\t<data>${b64(cdhash.subarray(0, 20))}</data>\n` +
    `\t\t\t<key>requirement</key>\n\t\t\t<string>${escapeXml(`identifier "${identifier}"`)}</string>\n` +
    `\t\t</dict>`
  );
}

function escapeXml(s: string): string {
  return s
    .replaceAll("\u0026", "\u0026amp;")
    .replaceAll("<", "\u0026lt;")
    .replaceAll(">", "\u0026gt;")
    .replaceAll('"', "\u0026quot;");
}

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function bundleRoots(entries: Map<string, ZipEntry>): string[] {
  const roots = new Set<string>();
  for (const path of entries.keys()) {
    const idx = path.indexOf("Info.plist");
    if (idx <= 0 || !path.endsWith("Info.plist")) continue;
    const root = path.slice(0, idx);
    if (BUNDLE_RE.test(root)) roots.add(root);
  }
  return [...roots];
}

function directChildren(root: string, roots: string[]): string[] {
  return roots.filter((candidate) => {
    if (candidate === root || !candidate.startsWith(root)) return false;
    return !roots.some((mid) => mid !== root && mid !== candidate && candidate.startsWith(mid) && mid.startsWith(root));
  });
}

function isMachO(data: Uint8Array): boolean {
  if (data.length < 4) return false;
  const u = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
  const le = (data[3] << 24) | (data[2] << 16) | (data[1] << 8) | data[0];
  return u === 0xcafebabe || u === 0xcafebabf || le === 0xfeedfacf || le === 0xfeedface;
}

function hexOf(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export async function unzip(buffer: Uint8Array): Promise<Map<string, ZipEntry>> {
  if (buffer.length < 22) throw new KhatmError("zip", "Archive is shorter than a ZIP end record.");
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let eocd = -1;
  const start = Math.max(0, buffer.length - 22 - 0xffff);
  for (let i = buffer.length - 22; i >= start; i--) {
    if (view.getUint32(i, true) !== 0x06054b50) continue;
    const comment = view.getUint16(i + 20, true);
    if (i + 22 + comment === buffer.length) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new KhatmError("zip", "Archive is not a valid ZIP.");
  const count = view.getUint16(eocd + 10, true);
  let cdOffset = view.getUint32(eocd + 16, true);
  const cdSize = view.getUint32(eocd + 12, true);
  if (count === 0xffff || cdOffset === 0xffffffff || cdSize === 0xffffffff) {
    throw new KhatmError("zip", "ZIP64 is not supported.");
  }
  const cdEnd = cdOffset + cdSize;
  if (!Number.isSafeInteger(cdEnd) || cdOffset > eocd || cdEnd > eocd) {
    throw new KhatmError("zip", "ZIP central directory is out of bounds.");
  }
  const cdStart = cdOffset;
  const entries = new Map<string, ZipEntry>();
  for (let n = 0; n < count; n++) {
    if (cdOffset > cdEnd - 46 || view.getUint32(cdOffset, true) !== 0x02014b50) {
      throw new KhatmError("zip", "ZIP central directory is corrupt.");
    }
    const flags = view.getUint16(cdOffset + 8, true);
    const method = view.getUint16(cdOffset + 10, true);
    const crc = view.getUint32(cdOffset + 16, true);
    const compSize = view.getUint32(cdOffset + 20, true);
    const uncompressedSize = view.getUint32(cdOffset + 24, true);
    const nameLen = view.getUint16(cdOffset + 28, true);
    const extraLen = view.getUint16(cdOffset + 30, true);
    const commentLen = view.getUint16(cdOffset + 32, true);
    const mode = view.getUint32(cdOffset + 38, true) >>> 16;
    const local = view.getUint32(cdOffset + 42, true);
    const nextCentral = cdOffset + 46 + nameLen + extraLen + commentLen;
    if (!Number.isSafeInteger(nextCentral) || nextCentral > cdEnd) throw new KhatmError("zip", "ZIP name or extra field is truncated.");
    const name = new TextDecoder().decode(buffer.subarray(cdOffset + 46, cdOffset + 46 + nameLen));
    cdOffset = nextCentral;
    assertZipPath(name);
    if (entries.has(name)) throw new KhatmError("zip", `Duplicate ZIP name: ${name}`);
    if (flags & 0x1) throw new KhatmError("zip", "Encrypted ZIP is rejected.");
    if (compSize === 0xffffffff || uncompressedSize === 0xffffffff) throw new KhatmError("zip", "ZIP64 entry is not supported.");
    if (uncompressedSize > 256 * 1024 * 1024) throw new KhatmError("zip", "ZIP entry exceeds the size cap.");
    if (local >= cdStart || local > buffer.length - 30 || view.getUint32(local, true) !== 0x04034b50) {
      throw new KhatmError("zip", "ZIP local header is corrupt.");
    }
    const localName = view.getUint16(local + 26, true);
    const localExtra = view.getUint16(local + 28, true);
    const dataStart = local + 30 + localName + localExtra;
    const dataEnd = dataStart + compSize;
    if (!Number.isSafeInteger(dataEnd) || dataStart > buffer.length || dataEnd > cdStart) {
      throw new KhatmError("zip", "ZIP entry data overlaps the central directory or the archive end.");
    }
    const localNameText = new TextDecoder().decode(buffer.subarray(local + 30, local + 30 + localName));
    if (localNameText !== name) throw new KhatmError("zip", "Local header name does not match the central directory.");
    const compressed = buffer.subarray(dataStart, dataStart + compSize);
    let data: Uint8Array;
    if (method === 0) {
      if (compSize !== uncompressedSize) throw new KhatmError("zip", "Stored ZIP entry size is inconsistent.");
      data = compressed.slice();
    }
    else if (method === 8) data = await inflate(compressed);
    else throw new KhatmError("zip", `Unsupported ZIP method ${method}.`);
    if (data.length !== uncompressedSize) throw new KhatmError("zip", "Inflated ZIP entry size is inconsistent.");
    if (crc32(data) !== crc) throw new KhatmError("zip", `ZIP CRC failed: ${name}`);
    if (name.endsWith("/")) continue;
    entries.set(name, { data, mode: mode || 0o100644 });
  }
  return entries;
}

function assertZipPath(name: string) {
  if (!name || name.includes("\0") || name.startsWith("/") || name.startsWith("\\")) {
    throw new KhatmError("zip", "Unsafe ZIP entry name.");
  }
  const parts = name.split(/[\\/]/);
  if (parts.some((part) => part === "." || part === "..")) {
    throw new KhatmError("zip", "ZIP entry name escapes the package.");
  }
}

export async function zip(entries: Map<string, ZipEntry>, opts: { directories?: boolean; deflate?: boolean } = {}): Promise<Uint8Array> {
  const files = [...entries.keys()].sort();
  const names = opts.directories ? withDirectories(files) : files.map((name) => ({ name, dir: false }));
  if (names.length > 0xffff) throw new KhatmError("zip", "ZIP entry count requires ZIP64.");
  const locals: Uint8Array[] = [];
  const centrals: Uint8Array[] = [];
  let offset = 0;
  for (const item of names) {
    assertZipPath(item.name);
    const entry = item.dir ? { data: new Uint8Array(), mode: 0o040755 } : entries.get(item.name)!;
    const nameBytes = utf8(item.name);
    let payload = entry.data;
    let method = 0;
    if (!item.dir && opts.deflate && entry.data.length >= 256) {
      const packed = await deflateRaw(entry.data);
      if (packed.length < entry.data.length) {
        payload = packed;
        method = 8;
      }
    }
    if (payload.length > 0xffffffff || nameBytes.length > 0xffff || offset > 0xffffffff) {
      throw new KhatmError("zip", "ZIP entry requires ZIP64.");
    }
    const crc = item.dir ? 0 : crc32(entry.data);
    const local = new Uint8Array(30 + nameBytes.length + payload.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, 0x800, true);
    lv.setUint16(8, method, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, payload.length, true);
    lv.setUint32(22, entry.data.length, true);
    lv.setUint16(26, nameBytes.length, true);
    local.set(nameBytes, 30);
    local.set(payload, 30 + nameBytes.length);
    locals.push(local);
    const central = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 0x031e, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, 0x800, true);
    cv.setUint16(10, method, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, payload.length, true);
    cv.setUint32(24, entry.data.length, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint32(38, (entry.mode || (item.dir ? 0o040755 : 0o100644)) << 16, true);
    cv.setUint32(42, offset, true);
    central.set(nameBytes, 46);
    centrals.push(central);
    offset += local.length;
  }
  const cd = concat(...centrals);
  if (offset > 0xffffffff || cd.length > 0xffffffff) throw new KhatmError("zip", "ZIP archive requires ZIP64.");
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, names.length, true);
  ev.setUint16(10, names.length, true);
  ev.setUint32(12, cd.length, true);
  ev.setUint32(16, offset, true);
  return concat(...locals, cd, eocd);
}

function withDirectories(files: string[]): { name: string; dir: boolean }[] {
  const dirs = new Set<string>();
  for (const name of files) {
    const parts = name.split("/");
    for (let i = 1; i < parts.length; i++) dirs.add(`${parts.slice(0, i).join("/")}/`);
  }
  return [...[...dirs].map((name) => ({ name, dir: true })), ...files.map((name) => ({ name, dir: false }))].sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  );
}

async function deflateRaw(data: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([ownedBuffer(data)]).stream().pipeThrough(new CompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function inflate(data: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([ownedBuffer(data)]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

let crcTable: Uint32Array | null = null;
function crc32(data: Uint8Array): number {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i++) c = crcTable[(c ^ data[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
