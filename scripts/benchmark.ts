/**
 * Score every pair of contracts in examples/mainnet and check the verdicts
 * against the family labels in manifest.json.
 *
 *   npm run benchmark
 *
 * A pair is a positive when both contracts are in the same family. The report
 * shows precision/recall across thresholds, the hardest positives and the
 * most fork-like negatives, so it's obvious where the model is weak.
 */

import { readFileSync } from "node:fs";
import { fingerprint, type Fingerprint } from "../src/fingerprint.js";
import { compare } from "../src/similarity.js";

interface Entry { file: string; name: string; family: string; chain: string }

const dir = new URL("../examples/mainnet/", import.meta.url);
const manifest: { contracts: Entry[] } = JSON.parse(readFileSync(new URL("manifest.json", dir), "utf8"));
const prints = new Map<string, Fingerprint>(
  manifest.contracts.map((c) => [c.file, fingerprint(readFileSync(new URL(c.file, dir), "utf8"))])
);

interface Pair { a: Entry; b: Entry; score: number; fork: boolean }
const pairs: Pair[] = [];
const cs = manifest.contracts;
for (let i = 0; i < cs.length; i++) {
  for (let j = i + 1; j < cs.length; j++) {
    const score = compare(prints.get(cs[i].file)!, prints.get(cs[j].file)!).total;
    pairs.push({ a: cs[i], b: cs[j], score, fork: cs[i].family === cs[j].family });
  }
}

const pos = pairs.filter((p) => p.fork);
const neg = pairs.filter((p) => !p.fork);
const label = (e: Entry) => `${e.name} (${e.chain})`;
const pct = (x: number) => `${(x * 100).toFixed(1)}%`.padStart(6);

console.log(`\n${cs.length} contracts, ${pairs.length} pairs: ${pos.length} forks, ${neg.length} unrelated\n`);
console.log("threshold  precision  recall   f1");
for (let t = 0.2; t <= 0.901; t += 0.05) {
  const tp = pos.filter((p) => p.score >= t).length;
  const fp = neg.filter((p) => p.score >= t).length;
  const precision = tp + fp ? tp / (tp + fp) : 1;
  const recall = tp / pos.length;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  console.log(`   ${t.toFixed(2)}      ${pct(precision)}   ${pct(recall)}  ${f1.toFixed(3)}`);
}

console.log("\nweakest forks");
for (const p of [...pos].sort((x, y) => x.score - y.score).slice(0, 6)) {
  console.log(`  ${pct(p.score)}  ${label(p.a)}  ~  ${label(p.b)}`);
}
console.log("\nmost fork-like unrelated pairs");
for (const p of [...neg].sort((x, y) => y.score - x.score).slice(0, 6)) {
  console.log(`  ${pct(p.score)}  ${label(p.a)}  ~  ${label(p.b)}`);
}

const minPos = Math.min(...pos.map((p) => p.score));
const maxNeg = Math.max(...neg.map((p) => p.score));
console.log(`\nweakest fork ${pct(minPos)} vs strongest unrelated ${pct(maxNeg)} — ${minPos > maxNeg ? "fully separable" : "overlap"}\n`);
