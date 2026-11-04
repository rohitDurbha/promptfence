// Computes scanner verdicts using the exported rules, the same way the static
// demo does in a browser. Prints JSON to stdout so check_parity.py can diff it
// against Python's verdicts. Run: node scripts/js_verdicts.mjs
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const spec = JSON.parse(readFileSync(join(root, "web", "rules.json"), "utf8"));
const compiled = spec.rules.map((r) => ({
  ...r,
  re: new RegExp(r.pattern, spec.flags),
}));

export function scan(text, boundary) {
  const matches = [];
  for (const rule of compiled) {
    if (rule.boundary !== boundary) continue;
    const found = rule.re.exec(text);
    if (found === null) continue;
    matches.push({
      rule_id: rule.rule_id,
      name: rule.name,
      severity: rule.severity,
      span: [found.index, found.index + found[0].length],
      excerpt: found[0].slice(0, 60),
    });
  }
  return { blocked: matches.length > 0, matches };
}

function readJsonl(path) {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line));
}

const out = [];
for (const [file, isAttack] of [
  ["fixtures_attack.jsonl", true],
  ["fixtures_benign.jsonl", false],
]) {
  for (const row of readJsonl(join(root, "data", file))) {
    const result = scan(row.content, "input");
    out.push({
      case_id: row.input_id,
      is_attack: isAttack,
      blocked: result.blocked,
      rule_ids: result.matches.map((m) => m.rule_id),
      spans: result.matches.map((m) => m.span),
    });
  }
}

console.log(JSON.stringify(out, null, 2));
