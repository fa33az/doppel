/**
 * Similarity scoring between two fingerprints.
 *
 * The main signal is function-aligned: every selector that appears in either
 * contract is compared with its namesake on the other side, and the results
 * are averaged, weighted by function size. A function one side doesn't have
 * counts as 0. Aligning by selector keeps unrelated code from diluting the
 * score and makes missing or extra functions count against it.
 *
 * It is blended with a whole-contract score (Jaccard of semantic 3-grams),
 * which also covers code outside any function (constructor leftovers,
 * fallback logic) and is the only signal when no dispatcher is found.
 *
 * Weights and verdict thresholds were calibrated on the labeled contracts in
 * examples/mainnet — run `npm run benchmark` to see how they hold up.
 */

import type { Fingerprint } from "./fingerprint.js";

export interface FunctionScore {
  selector: string;
  score: number;
}

export interface Score {
  total: number;
  /** Function-aligned similarity, or null when either side has no dispatcher. */
  functionsScore: number | null;
  code: number;
  selector: number;
  /** Shared selectors with per-function similarity, best match first. */
  functions: FunctionScore[];
  onlyInA: string[];
  onlyInB: string[];
}

export const WEIGHTS = { functions: 0.7, code: 0.3 };

export function jaccard<T>(a: Set<T>, b: Set<T>): number {
  if (a.size === 0 && b.size === 0) return 1; // nothing to disagree on
  let inter = 0;
  const [small, big] = a.size < b.size ? [a, b] : [b, a];
  for (const x of small) if (big.has(x)) inter++;
  return inter / (a.size + b.size - inter);
}

/** Similarity of one function across two contracts, or null if either lacks it. */
export function compareFunction(a: Fingerprint, b: Fingerprint, selector: string): number | null {
  const fa = a.functions.get(selector);
  const fb = b.functions.get(selector);
  if (!fa || !fb) return null;
  return jaccard(fa.grams, fb.grams);
}

function aligned(a: Fingerprint, b: Fingerprint): number | null {
  if (!a.functions.size || !b.functions.size) return null;
  let num = 0;
  let den = 0;
  for (const s of new Set([...a.functions.keys(), ...b.functions.keys()])) {
    const fa = a.functions.get(s);
    const fb = b.functions.get(s);
    const w = Math.max(fa?.size ?? 0, fb?.size ?? 0, 1);
    den += w;
    if (fa && fb) num += w * jaccard(fa.grams, fb.grams);
  }
  return num / den;
}

export function compare(a: Fingerprint, b: Fingerprint): Score {
  const functionsScore = aligned(a, b);
  const code = jaccard(a.grams, b.grams);
  const selector = jaccard(a.selectors, b.selectors);

  const functions: FunctionScore[] = [];
  const onlyInA: string[] = [];
  for (const s of a.selectors) {
    if (!b.selectors.has(s)) onlyInA.push(s);
    else functions.push({ selector: s, score: compareFunction(a, b, s) ?? 0 });
  }
  const onlyInB = [...b.selectors].filter((s) => !a.selectors.has(s));
  functions.sort((x, y) => y.score - x.score);

  const total =
    functionsScore === null
      ? code
      : WEIGHTS.functions * functionsScore + WEIGHTS.code * code;

  return { total, functionsScore, code, selector, functions, onlyInA, onlyInB };
}
