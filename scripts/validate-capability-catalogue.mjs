import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { validateCatalogue, verifyLocalAssets } from "./capability-catalogue-lib.mjs";

const args = process.argv.slice(2);
if (args.length !== 1 && !(args.length === 3 && args[1] === "--assets-dir")) {
  throw new Error("usage: node scripts/validate-capability-catalogue.mjs <catalogue.json> [--assets-dir <directory>]");
}

const catalogue = JSON.parse(readFileSync(resolve(args[0]), "utf8"));
validateCatalogue(catalogue);
if (args.length === 3) await verifyLocalAssets(catalogue, resolve(args[2]));
console.log(`validated ${catalogue.packages.length} capability package record(s)`);
