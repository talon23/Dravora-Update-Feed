import { readFile } from "node:fs/promises";
import { validateAddonPackageCatalogue, validateAddonStatusRegistry } from "./addon-catalogue-lib.mjs";

const [, , kind, path] = process.argv;
if (!kind || !path || !["status", "package"].includes(kind)) {
  console.error("Usage: node scripts/validate-addon-catalogues.mjs <status|package> <json-path>");
  process.exit(2);
}

const value = JSON.parse(await readFile(path, "utf8"));
if (kind === "status") validateAddonStatusRegistry(value);
else validateAddonPackageCatalogue(value);
console.log(`Dravora add-on ${kind} catalogue contract passed.`);
