/**
 * Similarity scoring between two fingerprints.
 *
 * We blend three signals, each in [0, 1]:
 *   - cosine similarity of opcode histograms  (overall instruction mix)
 *   - Jaccard of opcode 4-grams               (control-flow shape)
 *   - Jaccard of function selectors           (ABI surface)
 *
 * The weights favor the 4-gram shape, because that is the hardest thing to
 * keep identical by accident and the easiest to keep identical in a fork.
 */

import type { Fingerprint } from "./fingerprint.js";

export interface Score {
  total: number; // blended, 0..1
  histogram: number;
  ngram: number;
  selector: number;
  sharedSelectors: string[];
}

const WEIGHTS = { histogram: 0.25, ngram: 0.55, selector: 0.2 };

function cosine(a: Record<string, number>, b: Record<string, number>): number {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (const k of keys) {
    const x = a[k] ?? 0;
    const y = b[k] ?? 0;
    dot += x * y;
    na += x * x;
    nb += y * y;
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

function jaccard<T>(a: Set<T>, b: Set<T>): number {
  if (a.size === 0 && b.size === 0) return 1; // both empty == identical (trivially)
  let inter = 0;
  for (const x of a) if (b.has(x)) inter++;
  const union = a.size + b.size - inter;
  return union === 0 ? 0 : inter / union;
}

export function compare(a: Fingerprint, b: Fingerprint): Score {
  const histogram = cosine(a.opcodeHistogram, b.opcodeHistogram);
  const ngram = jaccard(a.ngrams, b.ngrams);
  const selector = jaccard(a.selectors, b.selectors);

  const shared: string[] = [];
  for (const s of a.selectors) if (b.selectors.has(s)) shared.push(s);

  const total =
    WEIGHTS.histogram * histogram +
    WEIGHTS.ngram * ngram +
    WEIGHTS.selector * selector;

  return { total, histogram, ngram, selector, sharedSelectors: shared };
}
