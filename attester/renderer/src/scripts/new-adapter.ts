#!/usr/bin/env node
import { mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

const [, , rawName, rawKind] = process.argv;

if (!rawName || !rawKind) {
  console.error("usage: npm run new-adapter -- <kebab-name> <action-kind>");
  process.exit(1);
}

const actionKind = Number(rawKind);
if (!Number.isInteger(actionKind) || actionKind <= 0) {
  throw new Error("action-kind must be a positive integer");
}

const kebab = rawName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
const camel = kebab.replace(/-([a-z0-9])/g, (_, c: string) => c.toUpperCase());
const constant = kebab.toUpperCase().replace(/-/g, "_");
const rendererRoot = new URL("../..", import.meta.url).pathname;
const adapterPath = join(rendererRoot, "src", "adapters", `${kebab}.ts`);

if (existsSync(adapterPath)) {
  throw new Error(`adapter already exists: ${adapterPath}`);
}

mkdirSync(dirname(adapterPath), { recursive: true });
writeFileSync(adapterPath, adapterTemplate({ camel, constant, actionKind }));

const indexPath = join(rendererRoot, "src", "adapters", "index.ts");
const index = readFileSync(indexPath, "utf8");
const importLine = `import { ${camel}Adapter } from "./${kebab}.js";\n`;
const registerLine = `registerAdapter(${camel}Adapter);\n`;
writeFileSync(indexPath, index.replace("// Built-in adapters.\n", `${importLine}// Built-in adapters.\n`).trimEnd() + `\n${registerLine}`);

console.log(`created ${adapterPath}`);
console.log("next: fill in decode/render logic, mirror it in firmware/src/render.rs, then add vectors");

function adapterTemplate(input: { camel: string; constant: string; actionKind: number }): string {
  return `// Adapter for action_kind = ${input.actionKind}, "${input.constant}".
//
// Replace this byte layout with a narrow protocol-specific action schema.

import type { Adapter } from "./index.js";
import type { CanonicalIntent, RenderedIntent } from "../schema.js";

const ACTION_KIND = ${input.actionKind};

export const ${input.camel}Adapter: Adapter = {
  actionKind: ACTION_KIND,
  actionKindName: "${input.constant}",

  decode(bytes: Uint8Array): CanonicalIntent {
    if (bytes.length !== 0) {
      throw new Error("${input.constant}: replace placeholder length check");
    }
    return {};
  },

  render(_intent: CanonicalIntent): RenderedIntent {
    return {
      actionKindName: "${input.constant}",
      lines: [],
      warning: "Placeholder adapter. Do not use in production.",
    };
  },
};
`;
}
