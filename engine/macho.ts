import {
  KhatmError,
  align,
  bytesEqual,
  concat,
  hex,
  sha256,
  utf8,
} from "./bytes.ts";
import {
  CD_HEADER,
  CS_ADHOC,
  CS_EXECSEG_ALLOW_UNSIGNED,
  CS_EXECSEG_MAIN_BINARY,
  CS_HASH_SIZE,
  CS_PAGE,
  CS_RUNTIME,
  CS_VERSION,
  CSSLOT_CODEDIRECTORY,
  CSSLOT_DER_ENTITLEMENTS,
  CSSLOT_ENTITLEMENTS,
  CSSLOT_REQUIREMENTS,
  CSSLOT_SIGNATURESLOT,
  CSMAGIC_BLOBWRAPPER,
  CSMAGIC_CODEDIRECTORY,
  CSMAGIC_EMBEDDED_SIGNATURE,
  MH_EXECUTE,
  assembleSignature,
  blob,
  buildCodeDirectory,
  buildRequirements,
  entitlementsBlobs,
  hashPages,
  superblob,
} from "./blobs.ts";
import { cmsUpperBound, buildCms, verifyCms } from "./cms.ts";
import type { PemMaterial } from "./pem.ts";
import type { PlistDict } from "./plist.ts";

const MH_MAGIC_64 = 0xfeedfacf;
const FAT_MAGIC = 0xcafebabe;
const FAT_MAGIC_64 = 0xcafebabf;
const LC_SYMTAB = 0x2;
const LC_UNIXTHREAD = 0x5;
const LC_THREAD = 0x4;
const LC_DYSYMTAB = 0xb;
const LC_LOAD_DYLIB = 0xc;
const LC_ID_DYLIB = 0xd;
const LC_LOAD_DYLINKER = 0xe;
const LC_SEGMENT_64 = 0x19;
const LC_UUID = 0x1b;
const LC_CODE_SIGNATURE = 0x1d;
const LC_SEGMENT_SPLIT_INFO = 0x1e;
const LC_ENCRYPTION_INFO_64 = 0x2c;
const LC_DYLD_INFO = 0x22;
const LC_DYLD_INFO_ONLY = 0x80000022;
const LC_VERSION_MIN_MACOSX = 0x24;
const LC_VERSION_MIN_IPHONEOS = 0x25;
const LC_FUNCTION_STARTS = 0x26;
const LC_DYLD_ENVIRONMENT = 0x27;
const LC_MAIN = 0x80000028;
const LC_DATA_IN_CODE = 0x29;
const LC_SOURCE_VERSION = 0x2a;
const LC_DYLIB_CODE_SIGN_DRS = 0x2b;
const LC_LINKER_OPTIMIZATION_HINT = 0x2e;
const LC_BUILD_VERSION = 0x32;
const LC_DYLD_EXPORTS_TRIE = 0x80000033;
const LC_DYLD_CHAINED_FIXUPS = 0x80000034;
const LC_LOAD_WEAK_DYLIB = 0x80000018;
const LC_RPATH = 0x8000001c;
const LC_REEXPORT_DYLIB = 0x8000001f;
const LC_LOAD_UPWARD_DYLIB = 0x80000035;

const LINKEDIT_DATA = new Set([
  LC_CODE_SIGNATURE,
  LC_SEGMENT_SPLIT_INFO,
  LC_FUNCTION_STARTS,
  LC_DATA_IN_CODE,
  LC_DYLIB_CODE_SIGN_DRS,
  LC_LINKER_OPTIMIZATION_HINT,
  LC_DYLD_EXPORTS_TRIE,
  LC_DYLD_CHAINED_FIXUPS,
]);

const NO_FILE_OFFSET = new Set([
  LC_UUID,
  LC_LOAD_DYLIB,
  LC_ID_DYLIB,
  LC_LOAD_DYLINKER,
  LC_LOAD_WEAK_DYLIB,
  LC_REEXPORT_DYLIB,
  LC_LOAD_UPWARD_DYLIB,
  LC_RPATH,
  LC_DYLD_ENVIRONMENT,
  LC_SOURCE_VERSION,
  LC_BUILD_VERSION,
  LC_VERSION_MIN_IPHONEOS,
  LC_VERSION_MIN_MACOSX,
]);

export type Check = { id: string; ok: boolean; detail: string };

export type MachOSignOptions = {
  identifier: string;
  teamId: string;
  infoPlist?: Uint8Array | null;
  codeResources?: Uint8Array | null;
  entitlements?: { dict: PlistDict; xml: Uint8Array } | null;
  signingDate?: Date;
  hardenedRuntime?: boolean;
};

export type SliceSeal = {
  arch: string;
  cdhash: string;
  cdhashFull: string;
  identifier: string;
  teamId: string;
  requirement: string;
  pages: number;
  flags: number;
  checks: Check[];
};

export type SignedMachO = {
  bytes: Uint8Array;
  slices: SliceSeal[];
};

function view(b: Uint8Array): DataView {
  return new DataView(b.buffer, b.byteOffset, b.byteLength);
}

function ru32(b: Uint8Array, o: number, le: boolean): number {
  return view(b).getUint32(o, le);
}
function wu32(b: Uint8Array, o: number, v: number, le: boolean) {
  view(b).setUint32(o, v >>> 0, le);
}
function ru64(b: Uint8Array, o: number, le: boolean): number {
  const v = view(b).getBigUint64(o, le);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new KhatmError("macho", "64-bit offset is out of range.");
  return Number(v);
}
function wu64(b: Uint8Array, o: number, v: number, le: boolean) {
  view(b).setBigUint64(o, BigInt(v), le);
}

function cstring(b: Uint8Array, o: number, n: number): string {
  let s = "";
  for (let i = 0; i < n && b[o + i]; i++) s += String.fromCharCode(b[o + i]);
  return s;
}

export function classify(bytes: Uint8Array): "macho64" | "fat" | "fat64" | "other" {
  if (bytes.length < 4) return "other";
  const le = ru32(bytes, 0, true);
  const be = ru32(bytes, 0, false);
  if (le === MH_MAGIC_64) return "macho64";
  if (be === FAT_MAGIC) return "fat";
  if (be === FAT_MAGIC_64) return "fat64";
  return "other";
}

type Arch = { cputype: number; subtype: number; offset: number; size: number; align: number; reserved: number };

function parseFat(file: Uint8Array, fat64: boolean): Arch[] {
  const entrySize = fat64 ? 32 : 20;
  if (file.length < 8) throw new KhatmError("macho", "Truncated FAT header.");
  const n = ru32(file, 4, false);
  const tableEnd = 8 + n * entrySize;
  if (!Number.isSafeInteger(tableEnd) || tableEnd > file.length) {
    throw new KhatmError("macho", "FAT architecture table runs past the file.");
  }
  const archs: Arch[] = [];
  let o = 8;
  for (let i = 0; i < n; i++) {
    const cputype = ru32(file, o, false);
    const subtype = ru32(file, o + 4, false);
    const offset = fat64 ? ru64(file, o + 8, false) : ru32(file, o + 8, false);
    const size = fat64 ? ru64(file, o + 16, false) : ru32(file, o + 12, false);
    const alignment = ru32(file, o + (fat64 ? 24 : 16), false);
    if (alignment > 30) throw new KhatmError("macho", `Unsupported FAT alignment: 2^${alignment}.`);
    const end = offset + size;
    if (!Number.isSafeInteger(end) || offset < tableEnd || end > file.length) {
      throw new KhatmError("macho", `FAT slice ${i} is outside the file.`);
    }
    if (fat64) {
      archs.push({
        cputype,
        subtype,
        offset,
        size,
        align: alignment,
        reserved: ru32(file, o + 28, false),
      });
      o += 32;
    } else {
      archs.push({
        cputype,
        subtype,
        offset,
        size,
        align: alignment,
        reserved: 0,
      });
      o += 20;
    }
  }
  const ordered = [...archs].sort((a, b) => a.offset - b.offset || a.size - b.size);
  for (let i = 0; i < ordered.length; i++) {
    const arch = ordered[i];
    if (arch.size <= 0) throw new KhatmError("macho", "FAT slice is empty.");
    const step = 2 ** arch.align;
    if (arch.offset % step !== 0) throw new KhatmError("macho", "FAT slice offset is not aligned.");
    if (i > 0 && arch.offset < ordered[i - 1].offset + ordered[i - 1].size) {
      throw new KhatmError("macho", "FAT slices overlap.");
    }
  }
  return archs;
}

function packFat(parts: { arch: Arch; bytes: Uint8Array }[], fat64: boolean): Uint8Array {
  const n = parts.length;
  const entrySize = fat64 ? 32 : 20;
  let cursor = 8 + n * entrySize;
  const placed: { arch: Arch; bytes: Uint8Array; offset: number }[] = [];
  for (const part of parts) {
    const alignment = part.arch.align;
    if (alignment > 30) throw new KhatmError("macho", `Unsupported FAT alignment: 2^${alignment}.`);
    const al = 2 ** alignment;
    cursor = Math.ceil(cursor / al) * al;
    if (!Number.isSafeInteger(cursor) || !Number.isSafeInteger(cursor + part.bytes.length)) {
      throw new KhatmError("macho", "FAT binary exceeds the safe offset range.");
    }
    if (!fat64 && (cursor > 0xffffffff || part.bytes.length > 0xffffffff)) {
      throw new KhatmError("macho", "FAT32 cannot hold the signed slice. Use FAT64.");
    }
    placed.push({ ...part, offset: cursor });
    cursor += part.bytes.length;
  }
  const out = new Uint8Array(cursor);
  wu32(out, 0, fat64 ? FAT_MAGIC_64 : FAT_MAGIC, false);
  wu32(out, 4, n, false);
  let o = 8;
  for (const p of placed) {
    wu32(out, o, p.arch.cputype, false);
    wu32(out, o + 4, p.arch.subtype, false);
    if (fat64) {
      wu64(out, o + 8, p.offset, false);
      wu64(out, o + 16, p.bytes.length, false);
      wu32(out, o + 24, p.arch.align, false);
      wu32(out, o + 28, p.arch.reserved, false);
    } else {
      wu32(out, o + 8, p.offset, false);
      wu32(out, o + 12, p.bytes.length, false);
      wu32(out, o + 16, p.arch.align, false);
    }
    out.set(p.bytes, p.offset);
    o += entrySize;
  }
  return out;
}

export function archName(cputype: number): string {
  if (cputype === 0x0100000c) return "arm64";
  if (cputype === 0x01000007) return "x86_64";
  if ((cputype & 0xff) === 12) return "arm";
  if ((cputype & 0xff) === 7) return "x86_64";
  return `cpu-0x${(cputype >>> 0).toString(16)}`;
}

type Seg = {
  name: string;
  cmd: number;
  fileoff: number;
  filesize: number;
  vmaddr: number;
  vmsize: number;
  nsects: number;
  header: number;
};

function segments(file: Uint8Array): Seg[] {
  const ncmds = ru32(file, 16, true);
  const out: Seg[] = [];
  let o = 32;
  for (let i = 0; i < ncmds; i++) {
    const cmd = ru32(file, o, true);
    const cmdsize = ru32(file, o + 4, true);
    if (cmd === LC_SEGMENT_64) {
      out.push({
        name: cstring(file, o + 8, 16),
        cmd,
        vmaddr: ru64(file, o + 24, true),
        vmsize: ru64(file, o + 32, true),
        fileoff: ru64(file, o + 40, true),
        filesize: ru64(file, o + 48, true),
        nsects: ru32(file, o + 64, true),
        header: o,
      });
    }
    o += cmdsize;
  }
  return out;
}

function findCmd(file: Uint8Array, want: number): number {
  const ncmds = ru32(file, 16, true);
  let o = 32;
  for (let i = 0; i < ncmds; i++) {
    const cmd = ru32(file, o, true);
    const cmdsize = ru32(file, o + 4, true);
    if (cmd === want) return o;
    o += cmdsize;
  }
  return -1;
}

function assertNotEncrypted(file: Uint8Array) {
  const at = findCmd(file, LC_ENCRYPTION_INFO_64);
  if (at < 0) return;
  const cryptid = ru32(file, at + 16, true);
  if (cryptid !== 0) {
    throw new KhatmError(
      "encrypted",
      "Encrypted binary (LC_ENCRYPTION_INFO cryptid ≠ 0). This engine signs. It does not decrypt FairPlay.",
    );
  }
}

function stripSignature(file: Uint8Array): Uint8Array {
  const at = findCmd(file, LC_CODE_SIGNATURE);
  if (at < 0) return file;
  const dataoff = ru32(file, at + 8, true);
  const datasize = ru32(file, at + 12, true);
  if (dataoff === 0 || datasize === 0) return file;
  const end = dataoff + datasize;
  if (end > file.length) throw new KhatmError("macho", "LC_CODE_SIGNATURE points outside the file.");
  for (let i = end; i < file.length; i++) {
    if (file[i] !== 0) throw new KhatmError("macho", "Bytes follow the signature. The file will not be trimmed.");
  }
  return file.slice(0, dataoff);
}

function firstContent(file: Uint8Array): number {
  const ncmds = ru32(file, 16, true);
  let min = file.length;
  let o = 32;
  for (let i = 0; i < ncmds; i++) {
    const cmd = ru32(file, o, true);
    const cmdsize = ru32(file, o + 4, true);
    if (cmd === LC_SEGMENT_64) {
      const fileoff = ru64(file, o + 40, true);
      const filesize = ru64(file, o + 48, true);
      const nsects = ru32(file, o + 64, true);
      if (filesize > 0 && fileoff > 0) min = Math.min(min, fileoff);
      let s = o + 72;
      for (let k = 0; k < nsects; k++) {
        const size = ru64(file, s + 40, true);
        const offset = ru32(file, s + 48, true);
        if (size > 0 && offset > 0) min = Math.min(min, offset);
        s += 80;
      }
    }
    o += cmdsize;
  }
  return min;
}

function slide(file: Uint8Array, insertAt: number, delta: number): Uint8Array {
  const out = new Uint8Array(file.length + delta);
  out.set(file.subarray(0, insertAt), 0);
  out.set(file.subarray(insertAt), insertAt + delta);
  const ncmds = ru32(out, 16, true);
  let o = 32;
  for (let i = 0; i < ncmds; i++) {
    const cmd = ru32(out, o, true);
    const cmdsize = ru32(out, o + 4, true);
    if (cmd === LC_SEGMENT_64) {
      const fileoff = ru64(out, o + 40, true);
      const filesize = ru64(out, o + 48, true);
      const nsects = ru32(out, o + 64, true);
      if (fileoff === 0 && filesize >= insertAt) {
        wu64(out, o + 32, ru64(out, o + 32, true) + delta, true);
        wu64(out, o + 48, filesize + delta, true);
      } else if (fileoff >= insertAt) {
        wu64(out, o + 24, ru64(out, o + 24, true) + delta, true);
        wu64(out, o + 40, fileoff + delta, true);
      }
      let s = o + 72;
      for (let k = 0; k < nsects; k++) {
        const offset = ru32(out, s + 48, true);
        if (offset >= insertAt) {
          wu64(out, s + 32, ru64(out, s + 32, true) + delta, true);
          wu32(out, s + 48, offset + delta, true);
        }
        const reloff = ru32(out, s + 56, true);
        if (reloff >= insertAt) wu32(out, s + 56, reloff + delta, true);
        s += 80;
      }
    } else if (cmd === LC_SYMTAB) {
      bump32(out, o + 8, insertAt, delta);
      bump32(out, o + 16, insertAt, delta);
    } else if (cmd === LC_DYSYMTAB) {
      for (const off of [32, 40, 48, 56, 64, 72]) bump32(out, o + off, insertAt, delta);
    } else if (cmd === LC_DYLD_INFO || cmd === LC_DYLD_INFO_ONLY) {
      for (const off of [8, 16, 24, 32, 40]) bump32(out, o + off, insertAt, delta);
    } else if (LINKEDIT_DATA.has(cmd)) {
      bump32(out, o + 8, insertAt, delta);
    } else if (cmd === LC_MAIN) {
      const entry = ru64(out, o + 8, true);
      if (entry >= insertAt) wu64(out, o + 8, entry + delta, true);
    } else if (cmd === LC_ENCRYPTION_INFO_64) {
      bump32(out, o + 8, insertAt, delta);
    } else if (cmd === LC_UNIXTHREAD || cmd === LC_THREAD) {
      throw new KhatmError("macho", "Header has no room and contains LC_UNIXTHREAD. This engine will not slide that command.");
    } else if (!NO_FILE_OFFSET.has(cmd)) {
      throw new KhatmError("macho", `Header has no room and an unknown load command 0x${cmd.toString(16)} blocks a safe slide.`);
    }
    o += cmdsize;
  }
  return out;
}

function bump32(b: Uint8Array, field: number, insertAt: number, delta: number) {
  const v = ru32(b, field, true);
  if (v >= insertAt) wu32(b, field, v + delta, true);
}

function ensureCodeSignCommand(file: Uint8Array): Uint8Array {
  if (findCmd(file, LC_CODE_SIGNATURE) >= 0) return file;
  let cur = file;
  const cmdsEnd = 32 + ru32(cur, 20, true);
  if (firstContent(cur) < cmdsEnd + 16) cur = slide(cur, cmdsEnd, 0x4000);
  const at = 32 + ru32(cur, 20, true);
  if (at + 16 > firstContent(cur)) throw new KhatmError("macho", "No room for LC_CODE_SIGNATURE.");
  wu32(cur, at, LC_CODE_SIGNATURE, true);
  wu32(cur, at + 4, 16, true);
  wu32(cur, at + 8, 0, true);
  wu32(cur, at + 12, 0, true);
  wu32(cur, 16, ru32(cur, 16, true) + 1, true);
  wu32(cur, 20, ru32(cur, 20, true) + 16, true);
  return cur;
}

function vmPage(cputype: number): number {
  return (cputype & 0xff) === 12 ? 0x4000 : 0x1000;
}

function getTaskAllow(dict: PlistDict | null | undefined): boolean {
  return !!dict && dict["get-task-allow"] === true;
}

async function signThin(fileIn: Uint8Array, material: PemMaterial, opts: MachOSignOptions): Promise<{ bytes: Uint8Array; seal: SliceSeal }> {
  if (ru32(fileIn, 0, true) !== MH_MAGIC_64) throw new KhatmError("macho", "Slice is not 64-bit little-endian Mach-O.");
  assertNotEncrypted(fileIn);
  let file = stripSignature(fileIn.slice());
  file = ensureCodeSignCommand(file);
  if (file.length % 16 !== 0) {
    const padded = new Uint8Array(align(file.length, 16));
    padded.set(file);
    file = padded;
  }
  const codeLimit = file.length;
  const cputype = ru32(file, 4, true);
  const filetype = ru32(file, 12, true);
  const segs = segments(file);
  const text = segs.find((s) => s.name === "__TEXT");
  const link = segs.find((s) => s.name === "__LINKEDIT");
  if (!link) throw new KhatmError("macho", "No __LINKEDIT segment. This engine will not invent one.");
  const identifier = opts.identifier;
  const teamId = opts.teamId;
  const entitlements = opts.entitlements && Object.keys(opts.entitlements.dict).length > 0 ? opts.entitlements : null;
  const requirements = buildRequirements(identifier, material.leaf.subjectCn, material.leaf.appleIssued);
  const ents = entitlements ? entitlementsBlobs(entitlements.dict, entitlements.xml) : null;
  const special: (Uint8Array | null)[] = [];
  special[1] = opts.infoPlist ? await sha256(opts.infoPlist) : null;
  special[2] = await sha256(requirements.blob);
  special[3] = opts.codeResources ? await sha256(opts.codeResources) : null;
  special[5] = ents ? await sha256(ents.xmlBlob) : null;
  special[7] = ents ? await sha256(ents.derBlob) : null;
  let nSpecial = 0;
  for (let i = special.length - 1; i >= 1; i--) if (special[i]) nSpecial = Math.max(nSpecial, i);
  const nCode = Math.ceil(codeLimit / CS_PAGE);
  const identLen = utf8(identifier).length;
  const teamLen = teamId ? utf8(teamId).length : 0;
  let cursor = CD_HEADER + identLen + 1 + (teamId ? teamLen + 1 : 0);
  cursor += nSpecial * CS_HASH_SIZE;
  const cdLen = cursor + nCode * CS_HASH_SIZE;
  const fakeCd = new Uint8Array(cdLen);
  const cmsMax = cmsUpperBound(material);
  const items: { type: number; data: Uint8Array }[] = [
    { type: CSSLOT_CODEDIRECTORY, data: fakeCd },
    { type: CSSLOT_REQUIREMENTS, data: requirements.blob },
  ];
  if (ents) {
    items.push({ type: CSSLOT_ENTITLEMENTS, data: ents.xmlBlob });
    items.push({ type: CSSLOT_DER_ENTITLEMENTS, data: ents.derBlob });
  }
  items.push({ type: CSSLOT_SIGNATURESLOT, data: blob(CSMAGIC_BLOBWRAPPER, new Uint8Array(cmsMax)) });
  const reserved = align(superblob(CSMAGIC_EMBEDDED_SIGNATURE, items).length, 16);
  const at = findCmd(file, LC_CODE_SIGNATURE);
  wu32(file, at + 8, codeLimit, true);
  wu32(file, at + 12, reserved, true);
  const filesize = codeLimit + reserved - link.fileoff;
  if (filesize < 0) throw new KhatmError("macho", "__LINKEDIT extends past the signature.");
  const vmsize = align(filesize, vmPage(cputype));
  const vmEnd = link.vmaddr + vmsize;
  for (const seg of segs) {
    if (seg.header === link.header) continue;
    const otherEnd = seg.vmaddr + seg.vmsize;
    const overlap = vmEnd > seg.vmaddr && link.vmaddr < otherEnd;
    if (overlap && seg.vmsize > 0 && seg.vmaddr >= link.vmaddr) {
      throw new KhatmError("macho", `__LINKEDIT growth overlaps ${seg.name}.`);
    }
    if (seg.filesize > 0 && seg.fileoff >= link.fileoff && link.fileoff + filesize > seg.fileoff) {
      throw new KhatmError("macho", `File signature overlaps ${seg.name}.`);
    }
  }
  wu64(file, link.header + 32, vmsize, true);
  wu64(file, link.header + 48, filesize, true);
  const pageHashes = await hashPages(file, codeLimit);
  const execFlags =
    (filetype === MH_EXECUTE ? CS_EXECSEG_MAIN_BINARY : 0) + (getTaskAllow(entitlements?.dict) ? CS_EXECSEG_ALLOW_UNSIGNED : 0);
  const directory = await buildCodeDirectory({
    identifier,
    teamId,
    codeLimit,
    pageHashes,
    special,
    flags: opts.hardenedRuntime ? CS_RUNTIME : 0,
    execSegBase: text?.fileoff ?? 0,
    execSegLimit: text?.filesize ?? 0,
    execSegFlags: execFlags,
  });
  const cms = await buildCms({
    material,
    codeDirectory: directory.blob,
    signingDate: opts.signingDate ?? new Date(),
  });
  const embedded = await assembleSignature({
    codeDirectory: directory.blob,
    cdhashFull: directory.hash,
    requirements: requirements.blob,
    entitlements: ents?.xmlBlob ?? null,
    derEntitlements: ents?.derBlob ?? null,
    cms,
  });
  if (embedded.superblob.length > reserved) {
    throw new KhatmError("macho", `Signature ${embedded.superblob.length} exceeds the reserved ${reserved}.`);
  }
  const out = new Uint8Array(codeLimit + reserved);
  out.set(file.subarray(0, codeLimit), 0);
  out.set(embedded.superblob, codeLimit);
  const checks = await verifyThin(out, {
    infoPlist: opts.infoPlist ?? null,
    codeResources: opts.codeResources ?? null,
  });
  if (checks.some((c) => !c.ok)) {
    const failed = checks.filter((c) => !c.ok).map((c) => c.id).join(", ");
    throw new KhatmError("verify", `Seal failed its own check: ${failed}`);
  }
  return {
    bytes: out,
    seal: {
      arch: archName(cputype),
      cdhash: hex(embedded.cdhash),
      cdhashFull: hex(embedded.cdhashFull),
      identifier,
      teamId,
      requirement: requirements.text,
      pages: nCode,
      flags: opts.hardenedRuntime ? CS_RUNTIME : 0,
      checks,
    },
  };
}

export async function signMachO(input: Uint8Array, material: PemMaterial, opts: MachOSignOptions): Promise<SignedMachO> {
  const kind = classify(input);
  if (kind === "fat" || kind === "fat64") {
    const archs = parseFat(input, kind === "fat64");
    const parts: { arch: Arch; bytes: Uint8Array }[] = [];
    const slices: SliceSeal[] = [];
    for (const arch of archs) {
      const slice = input.slice(arch.offset, arch.offset + arch.size);
      const signed = await signThin(slice, material, opts);
      parts.push({ arch, bytes: signed.bytes });
      slices.push(signed.seal);
    }
    return { bytes: packFat(parts, kind === "fat64"), slices };
  }
  if (kind !== "macho64") throw new KhatmError("macho", "Not a 64-bit Mach-O and not a fat binary.");
  const signed = await signThin(input, material, opts);
  return { bytes: signed.bytes, slices: [signed.seal] };
}

export async function verifyMachO(
  input: Uint8Array,
  extra?: { infoPlist?: Uint8Array | null; codeResources?: Uint8Array | null },
): Promise<SliceSeal[]> {
  const kind = classify(input);
  if (kind === "fat" || kind === "fat64") {
    const archs = parseFat(input, kind === "fat64");
    const out: SliceSeal[] = [];
    for (const arch of archs) {
      const slice = input.slice(arch.offset, arch.offset + arch.size);
      out.push(await sealOf(slice, await verifyThin(slice, extra)));
    }
    return out;
  }
  if (kind !== "macho64") throw new KhatmError("macho", "Not Mach-O.");
  return [await sealOf(input, await verifyThin(input, extra))];
}

async function sealOf(file: Uint8Array, checks: Check[]): Promise<SliceSeal> {
  const parsed = readEmbedded(file);
  const full = parsed ? await sha256(parsed.codeDirectory) : new Uint8Array();
  return {
    arch: archName(ru32(file, 4, true)),
    cdhash: hex(full.subarray(0, 20)),
    cdhashFull: hex(full),
    identifier: parsed?.identifier ?? "",
    teamId: parsed?.teamId ?? "",
    requirement: "",
    pages: parsed?.nCode ?? 0,
    flags: parsed?.flags ?? 0,
    checks,
  };
}

type ParsedEmbed = {
  codeDirectory: Uint8Array;
  requirements: Uint8Array | null;
  entitlements: Uint8Array | null;
  der: Uint8Array | null;
  cms: Uint8Array | null;
  identifier: string;
  teamId: string;
  flags: number;
  hashOffset: number;
  nSpecial: number;
  nCode: number;
  codeLimit: number;
  cdhash: Uint8Array;
  cdhashFull: Uint8Array;
  dataoff: number;
  datasize: number;
};

function readEmbedded(file: Uint8Array): ParsedEmbed | null {
  if (file.length < 32 || ru32(file, 0, true) !== MH_MAGIC_64) return null;
  const at = findCmd(file, LC_CODE_SIGNATURE);
  if (at < 0) return null;
  const dataoff = ru32(file, at + 8, true);
  const datasize = ru32(file, at + 12, true);
  if (dataoff === 0 || dataoff + 12 > file.length) return null;
  const magic = ru32(file, dataoff, false);
  if (magic !== CSMAGIC_EMBEDDED_SIGNATURE) return null;
  const length = ru32(file, dataoff + 4, false);
  const count = ru32(file, dataoff + 8, false);
  const blobs = new Map<number, Uint8Array>();
  for (let i = 0; i < count; i++) {
    const type = ru32(file, dataoff + 12 + i * 8, false);
    const offset = ru32(file, dataoff + 16 + i * 8, false);
    const blobLen = ru32(file, dataoff + offset + 4, false);
    blobs.set(type, file.slice(dataoff + offset, dataoff + offset + blobLen));
  }
  const directory = blobs.get(CSSLOT_CODEDIRECTORY);
  if (!directory) return null;
  const hashOffset = ru32(directory, 16, false);
  const identOffset = ru32(directory, 20, false);
  const nSpecial = ru32(directory, 24, false);
  const nCode = ru32(directory, 28, false);
  const codeLimit32 = ru32(directory, 32, false);
  const teamOffset = directory.length >= 52 ? ru32(directory, 48, false) : 0;
  const codeLimit64 = directory.length >= 64 ? Number(view(directory).getBigUint64(56, false)) : 0;
  const codeLimit = codeLimit64 || codeLimit32;
  const identifier = cstring(directory, identOffset, 256);
  const teamId = teamOffset ? cstring(directory, teamOffset, 64) : "";
  const flags = ru32(directory, 12, false);
  const wrapper = blobs.get(CSSLOT_SIGNATURESLOT) ?? null;
  let cms: Uint8Array | null = null;
  if (wrapper && ru32(wrapper, 0, false) === CSMAGIC_BLOBWRAPPER) cms = wrapper.subarray(8);
  return {
    codeDirectory: directory,
    requirements: blobs.get(CSSLOT_REQUIREMENTS) ?? null,
    entitlements: blobs.get(CSSLOT_ENTITLEMENTS) ?? null,
    der: blobs.get(CSSLOT_DER_ENTITLEMENTS) ?? null,
    cms,
    identifier,
    teamId,
    flags,
    hashOffset,
    nSpecial,
    nCode,
    codeLimit,
    cdhash: new Uint8Array(),
    cdhashFull: new Uint8Array(),
    dataoff,
    datasize,
  };
}

function slotHash(directory: Uint8Array, hashOffset: number, index: number): Uint8Array {
  const at = hashOffset + index * CS_HASH_SIZE;
  return directory.subarray(at, at + CS_HASH_SIZE);
}

async function verifyThin(
  file: Uint8Array,
  extra?: { infoPlist?: Uint8Array | null; codeResources?: Uint8Array | null },
): Promise<Check[]> {
  const checks: Check[] = [];
  const push = (id: string, ok: boolean, detail: string) => checks.push({ id, ok, detail });
  const enc = findCmd(file, LC_ENCRYPTION_INFO_64);
  push("not-encrypted", enc < 0 || ru32(file, enc + 16, true) === 0, "cryptid = 0");
  const parsed = readEmbedded(file);
  if (!parsed) {
    push("embedded", false, "no SuperBlob");
    return checks;
  }
  push("superblob", ru32(file, parsed.dataoff, false) === CSMAGIC_EMBEDDED_SIGNATURE, "CSMAGIC_EMBEDDED_SIGNATURE");
  push("version", ru32(parsed.codeDirectory, 8, false) === CS_VERSION, `0x${ru32(parsed.codeDirectory, 8, false).toString(16)}`);
  push("sha256", parsed.codeDirectory[37] === 2 && parsed.codeDirectory[36] === 32, "hashType 2, hashSize 32");
  push("page", parsed.codeDirectory[39] === 12, "4096");
  push("not-adhoc", (parsed.flags & CS_ADHOC) === 0, `flags 0x${parsed.flags.toString(16)}`);
  push("codeLimit", parsed.codeLimit === parsed.dataoff, `codeLimit ${parsed.codeLimit} dataoff ${parsed.dataoff}`);
  push("datasize-align", parsed.datasize % 16 === 0, `datasize ${parsed.datasize}`);
  const link = segments(file).find((s) => s.name === "__LINKEDIT");
  const covered = !!link && link.fileoff <= parsed.dataoff && link.fileoff + link.filesize >= parsed.dataoff + parsed.datasize;
  push("linkedit", covered, covered ? "__LINKEDIT" : "__LINKEDIT short");
  const pages = await hashPages(file, parsed.codeLimit);
  let pagesOk = pages.length === parsed.nCode * CS_HASH_SIZE;
  if (pagesOk) pagesOk = bytesEqual(pages, slotHash(parsed.codeDirectory, parsed.hashOffset, 0).length ? parsed.codeDirectory.subarray(parsed.hashOffset, parsed.hashOffset + pages.length) : pages);
  push("pages", pagesOk, String(parsed.nCode));
  const reqOk = parsed.requirements ? bytesEqual(slotHash(parsed.codeDirectory, parsed.hashOffset, -2), await sha256(parsed.requirements)) : slotIsZero(parsed, -2);
  push("requirements", reqOk, "slot -2");
  const entOk = parsed.entitlements
    ? bytesEqual(slotHash(parsed.codeDirectory, parsed.hashOffset, -5), await sha256(parsed.entitlements))
    : parsed.nSpecial < 5 || slotIsZero(parsed, -5);
  push("entitlements", entOk, "slot -5");
  const derOk = parsed.der
    ? bytesEqual(slotHash(parsed.codeDirectory, parsed.hashOffset, -7), await sha256(parsed.der))
    : parsed.nSpecial < 7 || slotIsZero(parsed, -7);
  push("der-entitlements", derOk, "slot -7");
  if (extra?.infoPlist) {
    push("info-plist", bytesEqual(slotHash(parsed.codeDirectory, parsed.hashOffset, -1), await sha256(extra.infoPlist)), "slot -1");
  }
  if (extra?.codeResources) {
    push("resources", bytesEqual(slotHash(parsed.codeDirectory, parsed.hashOffset, -3), await sha256(extra.codeResources)), "slot -3");
  }
  if (parsed.cms) {
    const cms = await verifyCms(parsed.cms, parsed.codeDirectory);
    push("cms-digest", cms.digestMatches, "message-digest = SHA-256(CodeDirectory)");
    push("cms-signature", cms.signerMatchesKey, "PKCS#7");
    const cdhash = (await sha256(parsed.codeDirectory)).subarray(0, 20);
    push("cdhash", cms.cdhashFull.startsWith(hex(cdhash)), hex(cdhash));
  } else {
    push("cms-signature", false, "no CMS");
  }
  return checks;
}

function slotIsZero(parsed: ParsedEmbed, index: number): boolean {
  if (parsed.nSpecial < -index) return true;
  const slot = slotHash(parsed.codeDirectory, parsed.hashOffset, index);
  return slot.every((b) => b === 0);
}

export function synthesizeMachO(opts?: { tight?: boolean }): Uint8Array {
  const pagezero = seg("__PAGEZERO", 0, 0x100000000, 0, 0, 0, 0, 0);
  const textCmdSize = 72 + 80;
  const cmds = 72 + textCmdSize + 72 + 24;
  const content = opts?.tight ? 32 + cmds : 0x4000;
  const codeSize = 64;
  const textFile = content + codeSize;
  const text = seg("__TEXT", 0x100000000, opts?.tight ? align(textFile, 0x4000) : 0x8000, 0, textFile, 5, 5, 1);
  const section = section64("__text", "__TEXT", 0x100000000 + content, codeSize, content, 2);
  const linkVm = (opts?.tight ? align(textFile, 0x4000) : 0x8000) + 0x100000000;
  const link = seg("__LINKEDIT", linkVm, 0x4000, textFile, 0, 1, 1, 0);
  const main = new Uint8Array(24);
  wu32(main, 0, LC_MAIN, true);
  wu32(main, 4, 24, true);
  wu64(main, 8, content, true);
  const header = new Uint8Array(32);
  wu32(header, 0, MH_MAGIC_64, true);
  wu32(header, 4, 0x0100000c, true);
  wu32(header, 12, MH_EXECUTE, true);
  wu32(header, 16, 4, true);
  wu32(header, 20, cmds, true);
  wu32(header, 24, 0x200001, true);
  const body = concat(header, pagezero, text, section, link, main);
  const out = new Uint8Array(textFile);
  out.set(body, 0);
  for (let i = 0; i < codeSize; i += 4) {
    out[content + i] = 0xc0;
    out[content + i + 1] = 0x03;
    out[content + i + 2] = 0x5f;
    out[content + i + 3] = 0xd6;
  }
  return out;
}

/** An arm64 iOS executable. installd rejects a binary that has no platform. */
export function synthesizeIOSMachO(): Uint8Array {
  const dyld = "/usr/lib/dyld";
  const dylinker = new Uint8Array(32);
  wu32(dylinker, 0, 0x0e, true);
  wu32(dylinker, 4, 32, true);
  wu32(dylinker, 8, 12, true);
  for (let i = 0; i < dyld.length; i++) dylinker[12 + i] = dyld.charCodeAt(i);
  const build = new Uint8Array(32);
  wu32(build, 0, LC_BUILD_VERSION, true);
  wu32(build, 4, 32, true);
  wu32(build, 8, 2, true);
  wu32(build, 12, 0x000f0000, true);
  wu32(build, 16, 0x00120000, true);
  const pagezero = seg("__PAGEZERO", 0, 0x100000000, 0, 0, 0, 0, 0);
  const textCmdSize = 72 + 80;
  const cmds = 72 + textCmdSize + 72 + 24 + 32 + 32;
  const content = 0x4000;
  const codeSize = 64;
  const textFile = content + codeSize;
  const text = seg("__TEXT", 0x100000000, 0x8000, 0, textFile, 5, 5, 1);
  const section = section64("__text", "__TEXT", 0x100000000 + content, codeSize, content, 2);
  const link = seg("__LINKEDIT", 0x100000000 + 0x8000, 0x4000, textFile, 0, 1, 1, 0);
  const main = new Uint8Array(24);
  wu32(main, 0, LC_MAIN, true);
  wu32(main, 4, 24, true);
  wu64(main, 8, content, true);
  const header = new Uint8Array(32);
  wu32(header, 0, MH_MAGIC_64, true);
  wu32(header, 4, 0x0100000c, true);
  wu32(header, 12, MH_EXECUTE, true);
  wu32(header, 16, 6, true);
  wu32(header, 20, cmds, true);
  wu32(header, 24, 0x00200085, true);
  const body = concat(header, pagezero, text, section, link, main, build, dylinker);
  const out = new Uint8Array(textFile);
  out.set(body, 0);
  for (let i = 0; i < codeSize; i += 4) {
    out[content + i] = 0xc0;
    out[content + i + 1] = 0x03;
    out[content + i + 2] = 0x5f;
    out[content + i + 3] = 0xd6;
  }
  return out;
}

function seg(
  name: string,
  vmaddr: number,
  vmsize: number,
  fileoff: number,
  filesize: number,
  maxprot: number,
  initprot: number,
  nsects: number,
): Uint8Array {
  const b = new Uint8Array(72);
  wu32(b, 0, LC_SEGMENT_64, true);
  wu32(b, 4, 72 + nsects * 80, true);
  for (let i = 0; i < name.length; i++) b[8 + i] = name.charCodeAt(i);
  wu64(b, 24, vmaddr, true);
  wu64(b, 32, vmsize, true);
  wu64(b, 40, fileoff, true);
  wu64(b, 48, filesize, true);
  wu32(b, 56, maxprot, true);
  wu32(b, 60, initprot, true);
  wu32(b, 64, nsects, true);
  return b;
}

function section64(sect: string, segName: string, addr: number, size: number, offset: number, alignPow: number): Uint8Array {
  const b = new Uint8Array(80);
  const put = (at: number, s: string) => {
    for (let i = 0; i < s.length; i++) b[at + i] = s.charCodeAt(i);
  };
  put(0, sect);
  put(16, segName);
  wu64(b, 32, addr, true);
  wu64(b, 40, size, true);
  wu32(b, 48, offset, true);
  wu32(b, 52, alignPow, true);
  return b;
}

export function machoSummary(file: Uint8Array): { kind: string; archs: string[]; signed: boolean; encrypted: boolean; identifier: string } {
  const kind = classify(file);
  if (kind === "other") return { kind, archs: [], signed: false, encrypted: false, identifier: "" };
  if (kind === "fat" || kind === "fat64") {
    const archs = parseFat(file, kind === "fat64");
    return {
      kind,
      archs: archs.map((a) => archName(a.cputype)),
      signed: archs.some((a) => findCmd(file.slice(a.offset, a.offset + Math.min(a.size, 4096)).length ? file.subarray(a.offset, a.offset + a.size) : file, LC_CODE_SIGNATURE) >= 0),
      encrypted: false,
      identifier: "",
    };
  }
  const embedded = readEmbedded(file);
  const enc = findCmd(file, LC_ENCRYPTION_INFO_64);
  return {
    kind,
    archs: [archName(ru32(file, 4, true))],
    signed: !!embedded,
    encrypted: enc >= 0 && ru32(file, enc + 16, true) !== 0,
    identifier: embedded?.identifier ?? "",
  };
}
