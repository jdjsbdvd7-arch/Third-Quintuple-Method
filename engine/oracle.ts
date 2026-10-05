import { bytesEqual, hex, sha256 } from "./bytes.ts";
import { verifyCms } from "./cms.ts";

/**
 * Independent structural oracle. It re-reads the sealed bytes and re-hashes
 * pages itself. It is not an iOS device, not CoreTrust, and not AMFI.
 * There is no published G01–G06 or S1–S52 iOS 27 suite; these KH-G ids exist
 * so a passing report cannot be mistaken for a device verdict.
 */
export type OracleGate = { id: string; ok: boolean; detail: string };

export type OracleReport = {
  phantom: "khatm-oracle";
  notADevice: true;
  gates: OracleGate[];
};

const MH_MAGIC_64 = 0xfeedfacf;
const FAT_MAGIC = 0xcafebabe;
const FAT_MAGIC_64 = 0xcafebabf;
const LC_CODE_SIGNATURE = 0x1d;
const LC_ENCRYPTION_INFO_64 = 0x2c;
const SUPER = 0xfade0cc0;
const CODEDIR = 0xfade0c02;
const WRAPPER = 0xfade0b01;
const DER_MAGIC = 0xfade7172;

function view(b: Uint8Array): DataView {
  return new DataView(b.buffer, b.byteOffset, b.byteLength);
}
function be32(b: Uint8Array, o: number): number {
  return view(b).getUint32(o, false);
}
function le32(b: Uint8Array, o: number): number {
  return view(b).getUint32(o, true);
}

export async function runOracle(file: Uint8Array): Promise<OracleReport> {
  if (file.length >= 4) {
    const magic = be32(file, 0);
    if (magic === FAT_MAGIC || magic === FAT_MAGIC_64) {
      const fat64 = magic === FAT_MAGIC_64;
      try {
        const slices = fatSlices(file, fat64);
        const gates: OracleGate[] = [{ id: "KH-G00", ok: true, detail: fat64 ? "FAT64 preserved" : "FAT32" }];
        for (let i = 0; i < slices.length; i++) gates.push(...(await thin(slices[i], `#${i}`)));
        return { phantom: "khatm-oracle", notADevice: true, gates };
      } catch (error) {
        return {
          phantom: "khatm-oracle",
          notADevice: true,
          gates: [{ id: "KH-G00", ok: false, detail: error instanceof Error ? error.message : "FAT" }],
        };
      }
    }
  }
  return { phantom: "khatm-oracle", notADevice: true, gates: await thin(file, "") };
}

function fatSlices(file: Uint8Array, fat64: boolean): Uint8Array[] {
  if (file.length < 8) throw new Error("truncated FAT header");
  const n = be32(file, 4);
  const entry = fat64 ? 32 : 20;
  const tableEnd = 8 + n * entry;
  if (!Number.isSafeInteger(tableEnd) || n === 0 || tableEnd > file.length) throw new Error("FAT table");
  const rows: { off: number; size: number; align: number }[] = [];
  for (let i = 0; i < n; i++) {
    const o = 8 + i * entry;
    const off = fat64 ? Number(view(file).getBigUint64(o + 8, false)) : be32(file, o + 8);
    const size = fat64 ? Number(view(file).getBigUint64(o + 16, false)) : be32(file, o + 12);
    const align = be32(file, o + (fat64 ? 24 : 16));
    if (align > 30 || !Number.isSafeInteger(off + size)) throw new Error("FAT slice");
    rows.push({ off, size, align });
  }
  const ordered = [...rows].sort((a, b) => a.off - b.off);
  for (let i = 0; i < ordered.length; i++) {
    const row = ordered[i];
    if (row.size <= 0 || row.off < tableEnd || row.off + row.size > file.length) throw new Error("FAT slice outside the file");
    if (row.off % 2 ** row.align !== 0) throw new Error("FAT alignment");
    if (i > 0 && row.off < ordered[i - 1].off + ordered[i - 1].size) throw new Error("overlapping slices");
  }
  return rows.map((row) => file.subarray(row.off, row.off + row.size));
}

async function thin(file: Uint8Array, suffix: string): Promise<OracleGate[]> {
  const id = (name: string) => name + suffix;
  const gates: OracleGate[] = [];
  const magicOk = file.length >= 32 && le32(file, 0) === MH_MAGIC_64;
  gates.push({ id: id("KH-G01"), ok: magicOk, detail: magicOk ? "MH_MAGIC_64" : "not little-endian Mach-O 64" });
  if (!magicOk) return gates;

  const ncmds = le32(file, 16);
  const sizeofcmds = le32(file, 20);
  if (ncmds > 4096 || 32 + sizeofcmds > file.length) {
    gates.push({ id: id("KH-G02"), ok: false, detail: "load commands outside the file" });
    return gates;
  }
  let encrypted = false;
  let sigOff = -1;
  let sigSize = 0;
  let cursor = 32;
  for (let i = 0; i < ncmds; i++) {
    if (cursor + 8 > 32 + sizeofcmds) {
      gates.push({ id: id("KH-G02"), ok: false, detail: "truncated load command" });
      return gates;
    }
    const cmd = le32(file, cursor);
    const cmdsize = le32(file, cursor + 4);
    if (cmdsize < 8 || cursor + cmdsize > 32 + sizeofcmds) {
      gates.push({ id: id("KH-G02"), ok: false, detail: "invalid load-command size" });
      return gates;
    }
    if (cmd === LC_ENCRYPTION_INFO_64 && cmdsize >= 20 && le32(file, cursor + 16) !== 0) encrypted = true;
    if (cmd === LC_CODE_SIGNATURE && cmdsize >= 16) {
      sigOff = le32(file, cursor + 8);
      sigSize = le32(file, cursor + 12);
    }
    cursor += cmdsize;
  }
  gates.push({ id: id("KH-G02"), ok: !encrypted, detail: encrypted ? "cryptid ≠ 0, rejected" : "cryptid = 0" });
  if (encrypted) return gates;

  const boundsOk = sigOff >= 0 && sigSize % 16 === 0 && sigOff + sigSize === file.length;
  gates.push({
    id: id("KH-G03"),
    ok: boundsOk,
    detail: boundsOk ? `dataoff=${sigOff} datasize=${sigSize}` : "signature is not at end of file or is not 16-byte aligned",
  });
  if (!boundsOk) return gates;

  const blob = file.subarray(sigOff, sigOff + sigSize);
  const count = be32(blob, 8);
  const length = be32(blob, 4);
  const superOk = be32(blob, 0) === SUPER && length >= 12 && length <= sigSize && count > 0 && count < 64 && 12 + count * 8 <= length;
  gates.push({ id: id("KH-G04"), ok: superOk, detail: superOk ? `SuperBlob slots=${count}` : "corrupt SuperBlob" });
  if (!superOk) return gates;

  const slots = new Map<number, Uint8Array>();
  for (let i = 0; i < count; i++) {
    const type = be32(blob, 12 + i * 8);
    const off = be32(blob, 16 + i * 8);
    if (off + 8 > length) {
      gates.push({ id: id("KH-G05"), ok: false, detail: "slot index outside the SuperBlob" });
      return gates;
    }
    const blen = be32(blob, off + 4);
    if (blen < 8 || off + blen > length) {
      gates.push({ id: id("KH-G05"), ok: false, detail: "slot length outside the SuperBlob" });
      return gates;
    }
    slots.set(type, blob.subarray(off, off + blen));
  }

  const cd = slots.get(0);
  const cdOk = !!cd && be32(cd, 0) === CODEDIR && cd.length >= 88 && be32(cd, 4) === cd.length;
  const version = cdOk ? be32(cd, 8) : 0;
  const flags = cdOk ? be32(cd, 12) : 0;
  const hashOffset = cdOk ? be32(cd, 16) : 0;
  const nSpecial = cdOk ? be32(cd, 24) : 0;
  const nCode = cdOk ? be32(cd, 28) : 0;
  const codeLimit = cdOk ? be32(cd, 32) : 0;
  const hashSize = cdOk ? cd[36] : 0;
  const hashType = cdOk ? cd[37] : 0;
  const pageBits = cdOk ? cd[39] : 0;
  const limit64 = cdOk ? view(cd).getBigUint64(56, false) : 0n;
  const fieldsOk =
    cdOk &&
    version >= 0x20400 &&
    hashSize === 32 &&
    hashType === 2 &&
    pageBits === 12 &&
    limit64 === BigInt(codeLimit) &&
    hashOffset >= nSpecial * 32 &&
    hashOffset + nCode * 32 <= cd.length;
  gates.push({
    id: id("KH-G05"),
    ok: fieldsOk,
    detail: fieldsOk ? `CodeDirectory 0x${version.toString(16)} pages=${nCode}` : "CodeDirectory fields do not match version 0x20400",
  });
  if (!fieldsOk) return gates;

  const page = 4096;
  let pagesOk = codeLimit <= sigOff && nCode === Math.ceil(codeLimit / page);
  if (pagesOk) {
    for (let i = 0; i < nCode; i++) {
      const start = i * page;
      const end = Math.min(start + page, codeLimit);
      const got = await sha256(file.subarray(start, end));
      const stored = cd.subarray(hashOffset + i * 32, hashOffset + (i + 1) * 32);
      if (!bytesEqual(got, stored)) {
        pagesOk = false;
        break;
      }
    }
  }
  gates.push({ id: id("KH-G06"), ok: pagesOk, detail: pagesOk ? "pages match" : "page mismatch" });

  const digest = await sha256(cd);
  gates.push({ id: id("KH-G07"), ok: digest.length === 32 && limit64 === BigInt(codeLimit), detail: hex(digest.subarray(0, 20)) });
  gates.push({ id: id("KH-G09"), ok: (flags & 0x2) === 0, detail: (flags & 0x2) === 0 ? "flags clear" : "CS_ADHOC" });

  const der = slots.get(7);
  const derOk = !der || (be32(der, 0) === DER_MAGIC && der.length > 8 && der[8] === 0x70);
  gates.push({
    id: id("KH-G10"),
    ok: derOk,
    detail: !der ? "no DER slot" : derOk ? "0xfade7172 / 0x70" : "DER shape",
  });

  const cms = slots.get(0x10000);
  let cmsOk = false;
  let cmsDetail = "CMS slot missing";
  if (cms && be32(cms, 0) === WRAPPER && cms.length > 8) {
    try {
      const check = await verifyCms(cms.subarray(8), cd);
      cmsOk = check.ok && check.digestMatches && check.signerMatchesKey;
      cmsDetail = cmsOk ? "digest and signature match the embedded cert" : "digest or signature rejected";
    } catch (error) {
      cmsDetail = error instanceof Error ? error.message : "CMS";
    }
  }
  gates.push({ id: id("KH-G08"), ok: cmsOk, detail: cmsDetail });
  return gates;
}
