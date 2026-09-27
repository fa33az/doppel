/**
 * Turn disassembled bytecode into a fingerprint that survives the cosmetic
 * differences between a contract and its forks/clones.
 *
 * A fork typically keeps the same logic but changes: metadata hash (the CBOR
 * blob Solidity appends), constructor args, embedded addresses, and constants.
 * So we fingerprint the *shape* of the code:
 *
 *   1. opcodeHistogram  - normalized frequency of each opcode (immediates dropped)
 *   2. ngrams           - set of length-4 opcode sequences (control-flow shape)
 *   3. selectors        - the 4-byte function selectors the dispatcher checks
 *
 * These three views are compared independently and blended, which makes the
 * score robust: a superficial re-deploy scores near 1.0, an unrelated contract
 * near 0.
 */

import {
  disassemble,
  normalizeHex,
  stripMetadata,
  type Instruction,
} from "./bytecode.js";

export interface Fingerprint {
  /** opcode name -> normalized frequency (sums to ~1) */
  opcodeHistogram: Record<string, number>;
  /** set of "OP|OP|OP|OP" 4-grams */
  ngrams: Set<string>;
  /** function selectors found in the dispatcher, hex without 0x */
  selectors: Set<string>;
  /** number of instructions, useful as a sanity signal */
  instructionCount: number;
}

const NGRAM_N = 4;

/**
 * Solidity's function dispatcher compares calldata's first 4 bytes against
 * each selector using `PUSH4 <selector> ... EQ`. Collecting those PUSH4
 * immediates is a cheap, reliable way to recover a contract's ABI surface
 * straight from bytecode.
 */
function extractSelectors(instrs: Instruction[]): Set<string> {
  const selectors = new Set<string>();
  for (const ins of instrs) {
    // PUSH4 with a 4-byte (8 hex char) immediate.
    if (ins.name === "PUSH4" && ins.push && ins.push.length === 8) {
      // Skip the all-zero / all-f sentinels that show up as masks, not selectors.
      if (ins.push !== "00000000" && ins.push !== "ffffffff") {
        selectors.add(ins.push);
      }
    }
  }
  return selectors;
}

export interface FingerprintOptions {
  /** Strip the Solidity CBOR metadata trailer first. Default: true. */
  stripMeta?: boolean;
}

export function fingerprint(
  bytecodeHex: string,
  opts: FingerprintOptions = {}
): Fingerprint {
  const stripMeta = opts.stripMeta ?? true;
  const clean = stripMeta
    ? stripMetadata(bytecodeHex)
    : normalizeHex(bytecodeHex);
  const instrs = disassemble(clean);

  // 1. opcode histogram (names only — immediates are ignored on purpose)
  const counts: Record<string, number> = {};
  for (const ins of instrs) counts[ins.name] = (counts[ins.name] ?? 0) + 1;
  const total = instrs.length || 1;
  const opcodeHistogram: Record<string, number> = {};
  for (const [k, v] of Object.entries(counts)) opcodeHistogram[k] = v / total;

  // 2. opcode 4-grams
  const ngrams = new Set<string>();
  for (let i = 0; i + NGRAM_N <= instrs.length; i++) {
    const gram = instrs
      .slice(i, i + NGRAM_N)
      .map((x) => x.name)
      .join("|");
    ngrams.add(gram);
  }

  // 3. function selectors
  const selectors = extractSelectors(instrs);

  return { opcodeHistogram, ngrams, selectors, instructionCount: instrs.length };
}
