import { KhatmError, align, ascii, concat, sha256, u32, u64, utf8 } from "./bytes.ts";
import { derEntitlements, type PlistDict } from "./plist.ts";

/** Magics and slots from xnu osfmk/kern/cs_blobs.h. All multi-byte fields are big-endian. */
export const CSMAGIC_REQUIREMENT = 0xfade0c00;
export const CSMAGIC_REQUIREMENTS = 0xfade0c01;
export const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
export const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
export const CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171;
export const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xfade7172;
export const CSMAGIC_BLOBWRAPPER = 0xfade0b01;

export const CSSLOT_CODEDIRECTORY = 0;
export const CSSLOT_REQUIREMENTS = 2;
export const CSSLOT_ENTITLEMENTS = 5;
export const CSSLOT_DER_ENTITLEMENTS = 7;
export const CSSLOT_SIGNATURESLOT = 0x10000;

/** Requirement expression opcodes. Security/libsecurity_codesigning/lib/requirement.h */
const OP_IDENT = 2;
const OP_AND = 6;
const OP_CERT_FIELD = 11;
const OP_APPLE_GENERIC_ANCHOR = 15;
const MATCH_EQUAL = 1;
const EXPR_FORM = 1;
const DESIGNATED = 3;

export const CS_PAGE_BITS = 12;
export const CS_PAGE = 1 << CS_PAGE_BITS;
export const CS_HASHTYPE_SHA256 = 2;
export const CS_HASH_SIZE = 32;
/** CS_SUPPORTSEXECSEG. Header is 88 bytes; see CS_CodeDirectory through execSegFlags. */
export const CS_VERSION = 0x20400;
export const CD_HEADER = 88;

export const CS_EXECSEG_MAIN_BINARY = 0x1;
export const CS_EXECSEG_ALLOW_UNSIGNED = 0x10;
export const CS_ADHOC = 0x2;
export const CS_RUNTIME = 0x10000;

export const MH_EXECUTE = 0x2;

export function blob(magic: number, payload: Uint8Array): Uint8Array {
  return concat(u32(magic), u32(8 + payload.length), payload);
}

export function superblob(magic: number, items: { type: number; data: Uint8Array }[]): Uint8Array {
  let offset = 12 + items.length * 8;
  const placed: { type: number; offset: number; data: Uint8Array; pad: number }[] = [];
  for (const item of items) {
    const aligned = align(offset, 4);
    placed.push({ type: item.type, offset: aligned, data: item.data, pad: aligned - offset });
    offset = aligned + item.data.length;
  }
  const index = concat(...placed.map((p) => concat(u32(p.type), u32(p.offset))));
  const body: Uint8Array[] = [];
  for (const p of placed) {
    if (p.pad) body.push(new Uint8Array(p.pad));
    body.push(p.data);
  }
  const out = concat(u32(magic), u32(offset), u32(items.length), index, ...body);
  if (out.length !== offset) throw new KhatmError("blob", `SuperBlob size drift: ${out.length} != ${offset}`);
  return out;
}

function dataOperand(bytes: Uint8Array): Uint8Array {
  const pad = (4 - (bytes.length % 4)) % 4;
  return concat(u32(bytes.length), bytes, new Uint8Array(pad));
}

export function buildRequirements(identifier: string, commonName: string, appleAnchor: boolean): {
  blob: Uint8Array;
  text: string;
} {
  const terms: Uint8Array[] = [concat(u32(OP_IDENT), dataOperand(utf8(identifier)))];
  const words = [`identifier "${identifier}"`];
  if (appleAnchor) {
    terms.push(u32(OP_APPLE_GENERIC_ANCHOR));
    words.push("anchor apple generic");
  }
  terms.push(
    concat(u32(OP_CERT_FIELD), u32(0), dataOperand(ascii("subject.CN")), u32(MATCH_EQUAL), dataOperand(utf8(commonName))),
  );
  words.push(`certificate leaf[subject.CN] = "${commonName}"`);
  let expr = terms[terms.length - 1];
  for (let i = terms.length - 2; i >= 0; i--) expr = concat(u32(OP_AND), terms[i], expr);
  const one = blob(CSMAGIC_REQUIREMENT, concat(u32(EXPR_FORM), expr));
  return {
    blob: superblob(CSMAGIC_REQUIREMENTS, [{ type: DESIGNATED, data: one }]),
    text: words.join(" and "),
  };
}

export function entitlementsBlobs(dict: PlistDict, xml: Uint8Array): { xmlBlob: Uint8Array; derBlob: Uint8Array } {
  return {
    xmlBlob: blob(CSMAGIC_EMBEDDED_ENTITLEMENTS, xml),
    derBlob: blob(CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, derEntitlements(dict)),
  };
}

export type CodeDirectoryParts = {
  blob: Uint8Array;
  hash: Uint8Array;
};

export async function buildCodeDirectory(args: {
  identifier: string;
  teamId: string;
  codeLimit: number;
  pageHashes: Uint8Array;
  special: (Uint8Array | null)[];
  flags: number;
  execSegBase: number;
  execSegLimit: number;
  execSegFlags: number;
}): Promise<CodeDirectoryParts> {
  if (args.codeLimit > 0xffffffff) throw new KhatmError("codedir", "Binary exceeds the 4 GiB codeLimit.");
  let nSpecial = 0;
  for (let i = args.special.length - 1; i >= 1; i--) {
    if (args.special[i]) {
      nSpecial = i;
      break;
    }
  }
  const ident = utf8(args.identifier);
  const team = args.teamId ? utf8(args.teamId) : null;
  let cursor = CD_HEADER;
  const identOffset = cursor;
  cursor += ident.length + 1;
  let teamOffset = 0;
  if (team) {
    teamOffset = cursor;
    cursor += team.length + 1;
  }
  const specialBytes = new Uint8Array(nSpecial * CS_HASH_SIZE);
  for (let k = 1; k <= nSpecial; k++) {
    const hash = args.special[k];
    if (hash) {
      if (hash.length !== CS_HASH_SIZE) throw new KhatmError("codedir", "Slot hash size is not 32.");
      specialBytes.set(hash, (nSpecial - k) * CS_HASH_SIZE);
    }
  }
  const hashOffset = cursor + specialBytes.length;
  const nCode = args.pageHashes.length / CS_HASH_SIZE;
  const length = hashOffset + args.pageHashes.length;
  const header = concat(
    u32(CSMAGIC_CODEDIRECTORY),
    u32(length),
    u32(CS_VERSION),
    u32(args.flags >>> 0),
    u32(hashOffset),
    u32(identOffset),
    u32(nSpecial),
    u32(nCode),
    u32(args.codeLimit >>> 0),
    new Uint8Array([CS_HASH_SIZE, CS_HASHTYPE_SHA256, 0, CS_PAGE_BITS]),
    u32(0), // spare2
    u32(0), // scatterOffset
    u32(teamOffset),
    u32(0), // spare3
    u64(args.codeLimit),
    u64(args.execSegBase),
    u64(args.execSegLimit),
    u64(args.execSegFlags),
  );
  if (header.length !== CD_HEADER) throw new KhatmError("codedir", `CodeDirectory header is ${header.length} bytes, not 88.`);
  const directory = concat(header, ident, new Uint8Array([0]), team ? concat(team, new Uint8Array([0])) : new Uint8Array(), specialBytes, args.pageHashes);
  if (directory.length !== length) throw new KhatmError("codedir", "CodeDirectory length does not match its field.");
  return { blob: directory, hash: await sha256(directory) };
}

export async function hashPages(file: Uint8Array, codeLimit: number): Promise<Uint8Array> {
  const n = Math.ceil(codeLimit / CS_PAGE);
  const out = new Uint8Array(n * CS_HASH_SIZE);
  for (let i = 0; i < n; i++) {
    const start = i * CS_PAGE;
    const end = Math.min(start + CS_PAGE, codeLimit);
    out.set(await sha256(file.subarray(start, end)), i * CS_HASH_SIZE);
  }
  return out;
}

export type Embedded = {
  superblob: Uint8Array;
  codeDirectory: Uint8Array;
  requirements: Uint8Array;
  entitlements: Uint8Array | null;
  derEntitlements: Uint8Array | null;
  cdhash: Uint8Array;
  cdhashFull: Uint8Array;
};

export async function assembleSignature(args: {
  codeDirectory: Uint8Array;
  cdhashFull: Uint8Array;
  requirements: Uint8Array;
  entitlements: Uint8Array | null;
  derEntitlements: Uint8Array | null;
  cms: Uint8Array;
}): Promise<Embedded> {
  const items: { type: number; data: Uint8Array }[] = [
    { type: CSSLOT_CODEDIRECTORY, data: args.codeDirectory },
    { type: CSSLOT_REQUIREMENTS, data: args.requirements },
  ];
  if (args.entitlements) items.push({ type: CSSLOT_ENTITLEMENTS, data: args.entitlements });
  if (args.derEntitlements) items.push({ type: CSSLOT_DER_ENTITLEMENTS, data: args.derEntitlements });
  items.push({ type: CSSLOT_SIGNATURESLOT, data: blob(CSMAGIC_BLOBWRAPPER, args.cms) });
  return {
    superblob: superblob(CSMAGIC_EMBEDDED_SIGNATURE, items),
    codeDirectory: args.codeDirectory,
    requirements: args.requirements,
    entitlements: args.entitlements,
    derEntitlements: args.derEntitlements,
    cdhash: args.cdhashFull.subarray(0, 20),
    cdhashFull: args.cdhashFull,
  };
}
