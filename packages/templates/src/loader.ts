import { readFileSync, readdirSync } from "node:fs";
import { join, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import type { AttackTemplate, ScanDepth } from "@nightfang/shared";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const TEMPLATES_DIR = join(__dirname, "..", "attacks");

export function loadTemplates(depth?: ScanDepth): AttackTemplate[] {
  const templates: AttackTemplate[] = [];
  const dir = TEMPLATES_DIR;

  for (const category of readdirSync(dir, { withFileTypes: true })) {
    if (!category.isDirectory()) continue;
    const categoryDir = join(dir, category.name);

    for (const file of readdirSync(categoryDir)) {
      if (extname(file) !== ".yaml" && extname(file) !== ".yml") continue;
      const raw = readFileSync(join(categoryDir, file), "utf-8");
      const parsed = parseYaml(raw) as AttackTemplate;
      if (depth && !parsed.depth.includes(depth)) continue;
      templates.push(parsed);
    }
  }

  return templates;
}

export function loadTemplateById(id: string): AttackTemplate | undefined {
  const all = loadTemplates();
  return all.find((t) => t.id === id);
}
