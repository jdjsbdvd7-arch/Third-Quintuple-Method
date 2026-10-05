import { writeFile } from "node:fs/promises";
import { b64 } from "./bytes.ts";
import { buildAttachedCms } from "./cms.ts";
import { createSampleIdentity, seal } from "./index.ts";
import { zip } from "./ipa.ts";
import { synthesizeIOSMachO } from "./macho.ts";

const id = "demo.khatm";
const version = "1.0.2";
const team = "SAMPLETEAM";
const udid = "00008110-001965E62213801E";
const info = new TextEncoder().encode(
  `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${id}</string><key>CFBundleExecutable</key><string>Khatm</string><key>CFBundleVersion</key><string>${version}</string><key>CFBundleShortVersionString</key><string>${version}</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleName</key><string>Khatm</string><key>CFBundleDisplayName</key><string>Third Quintuple Method</string><key>CFBundleInfoDictionaryVersion</key><string>6.0</string><key>MinimumOSVersion</key><string>15.0</string><key>LSRequiresIPhoneOS</key><true/><key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array></dict></plist>\n`,
);
const { material } = await createSampleIdentity();
const entitlements = `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>application-identifier</key><string>${team}.${id}</string><key>com.apple.developer.team-identifier</key><string>${team}</string><key>get-task-allow</key><true/></dict></plist>\n`;
const profileXml = new TextEncoder().encode(
  `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>AppIDName</key><string>Khatm</string><key>ApplicationIdentifierPrefix</key><array><string>${team}</string></array><key>CreationDate</key><date>2026-01-01T00:00:00Z</date><key>Platform</key><array><string>iOS</string></array><key>IsXcodeManaged</key><false/><key>DeveloperCertificates</key><array><data>${b64(material.leaf.raw)}</data></array><key>Entitlements</key><dict><key>application-identifier</key><string>${team}.${id}</string><key>com.apple.developer.team-identifier</key><string>${team}</string><key>get-task-allow</key><true/></dict><key>ExpirationDate</key><date>2027-01-01T00:00:00Z</date><key>Name</key><string>${id}</string><key>ProvisionedDevices</key><array><string>${udid}</string></array><key>TeamIdentifier</key><array><string>${team}</string></array><key>TeamName</key><string>Sample</string><key>TimeToLive</key><integer>365</integer><key>UUID</key><string>7C3E1A20-4B55-4E91-A6D2-001965E62213</string><key>Version</key><integer>1</integer></dict></plist>\n`,
);
const profile = await buildAttachedCms(material, profileXml, new Date("2026-01-01T00:00:00Z"));
const unsigned = await zip(
  new Map([
    ["Payload/Khatm.app/Info.plist", { data: info, mode: 0o100644 }],
    ["Payload/Khatm.app/PkgInfo", { data: new TextEncoder().encode("APPL????"), mode: 0o100644 }],
    ["Payload/Khatm.app/embedded.mobileprovision", { data: profile, mode: 0o100644 }],
    ["Payload/Khatm.app/Khatm", { data: synthesizeIOSMachO(), mode: 0o100755 }],
  ]),
  { directories: true },
);
const sealed = await seal(unsigned, material, {
  identifier: id,
  bundleId: id,
  teamId: team,
  entitlementsXml: entitlements,
  signingDate: new Date("2026-01-01T00:00:00Z"),
});
const out = process.argv[2] || "pkg/demo.ipa";
await writeFile(out, sealed.bytes);
console.log("IPA", sealed.bytes.byteLength, sealed.cdhash);