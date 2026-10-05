import { writeFile } from "node:fs/promises";
import { createSampleIdentity, seal, synthesizeMachO } from "./index.ts";
import { zip } from "./ipa.ts";

const id = "demo.khatm";
const info = new TextEncoder().encode(
  `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${id}</string><key>CFBundleExecutable</key><string>Khatm</string><key>CFBundleShortVersionString</key><string>1.0</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleDisplayName</key><string>Third Quintuple Method</string></dict></plist>\n`,
);
const unsigned = await zip(
  new Map([
    ["Payload/Khatm.app/Info.plist", { data: info, mode: 0o100644 }],
    ["Payload/Khatm.app/Khatm", { data: synthesizeMachO(), mode: 0o100755 }],
  ]),
  { directories: true },
);
const { material } = await createSampleIdentity();
const entitlements = `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>application-identifier</key><string>SAMPLETEAM.${id}</string><key>com.apple.developer.team-identifier</key><string>SAMPLETEAM</string><key>get-task-allow</key><true/></dict></plist>\n`;
const sealed = await seal(unsigned, material, {
  identifier: id,
  bundleId: id,
  teamId: "SAMPLETEAM",
  entitlementsXml: entitlements,
  signingDate: new Date("2026-01-01T00:00:00Z"),
});
const out = process.argv[2] || "pkg/demo.ipa";
await writeFile(out, sealed.bytes);
console.log("IPA", sealed.bytes.byteLength, sealed.cdhash);
