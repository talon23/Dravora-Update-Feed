import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { validateInstallerDownloadChannel, verifyLocalInstallerDownloadAssets } from "./installer-download-channel-lib.mjs";

const args = process.argv.slice(2);
if (!args[0]) {
  throw new Error("usage: node scripts/validate-installer-download-channel.mjs <channel.json> [--installer-dir <directory>] [--package-dir <directory>]");
}

let installerDirectory = null;
let packageDirectory = null;
for (let index = 1; index < args.length; index += 2) {
  const flag = args[index];
  const value = args[index + 1];
  if (!value || !["--installer-dir", "--package-dir"].includes(flag)) {
    throw new Error("usage: node scripts/validate-installer-download-channel.mjs <channel.json> [--installer-dir <directory>] [--package-dir <directory>]");
  }
  if (flag === "--installer-dir") installerDirectory = resolve(value);
  if (flag === "--package-dir") packageDirectory = resolve(value);
}

const channel = validateInstallerDownloadChannel(JSON.parse(readFileSync(resolve(args[0]), "utf8")));
await verifyLocalInstallerDownloadAssets(channel, { installerDirectory, packageDirectory });
console.log(`validated ${channel.channelId} installer ${channel.installer.version} with ${channel.runtimePackages.length} runtime package record(s)`);
