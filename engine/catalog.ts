import { readdir, readFile, writeFile } from "node:fs/promises";
import { inspectPackage } from "./ipa.ts";

const PAGES = "https://jdjsbdvd7-arch.github.io/Third-Quintuple-Method";

function xmlEscape(value: string): string {
  return value
    .replaceAll("&", "\u0026amp;")
    .replaceAll("<", "\u0026lt;")
    .replaceAll(">", "\u0026gt;")
    .replaceAll('"', "\u0026quot;");
}

function manifest(ipaUrl: string, bundleId: string, title: string, version: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>items</key><array><dict><key>assets</key><array><dict><key>kind</key><string>software-package</string><key>url</key><string>${xmlEscape(ipaUrl)}</string></dict></array><key>metadata</key><dict><key>bundle-identifier</key><string>${xmlEscape(bundleId)}</string><key>bundle-version</key><string>${xmlEscape(version)}</string><key>kind</key><string>software</string><key>title</key><string>${xmlEscape(title)}</string></dict></dict></array></dict></plist>`;
}

const udid = (process.env.UDID ?? "").trim();

const names = (await readdir("pkg")).filter((name) => name.endsWith(".ipa"));
const catalog: { bundleId: string; title: string; version: string; manifest: string; ipa: string; device: string }[] = [];
for (const name of names) {
  const bytes = new Uint8Array(await readFile(`pkg/${name}`));
  try {
    const info = await inspectPackage(bytes);
    const stem = name.slice(0, -4);
    const ipa = `${PAGES}/pkg/${name}`;
    const manifestUrl = `${PAGES}/pkg/${stem}.xml`;
    await writeFile(`pkg/${stem}.xml`, manifest(ipa, info.bundleId, info.title, info.version));
    const device = udid ? (Buffer.from(bytes).includes(Buffer.from(udid)) ? "listed" : "absent") : "";
    catalog.push({ bundleId: info.bundleId, title: info.title, version: info.version, manifest: manifestUrl, ipa, device });
  } catch {
    /* A file in pkg/ that is not an application is skipped. */
  }
}
await writeFile("catalog.json", `${JSON.stringify(catalog, null, 2)}\n`);
console.log(`CATALOG ${catalog.length}`);
