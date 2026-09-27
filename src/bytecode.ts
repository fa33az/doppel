/**
 * Minimal EVM bytecode disassembler.
 *
 * We only need enough of the EVM instruction set to turn raw runtime bytecode
 * into a normalized opcode stream. That stream is the raw material every
 * fingerprint is built from, so it deliberately does NOT try to be a full
 * decompiler — just a faithful, deterministic opcode walk.
 */

// The subset of opcodes we care about naming. Anything unknown is kept as
// its hex value so two contracts using the same "unknown" byte still match.
const OPCODES: Record<number, string> = {
  0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
  0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD",
  0x0a: "EXP", 0x0b: "SIGNEXTEND",
  0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ",
  0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT",
  0x1a: "BYTE", 0x1b: "SHL", 0x1c: "SHR", 0x1d: "SAR",
  0x20: "KECCAK256",
  0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER",
  0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE",
  0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY",
  0x3a: "GASPRICE", 0x3b: "EXTCODESIZE", 0x3c: "EXTCODECOPY",
  0x3d: "RETURNDATASIZE", 0x3e: "RETURNDATACOPY", 0x3f: "EXTCODEHASH",
  0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER",
  0x44: "PREVRANDAO", 0x45: "GASLIMIT", 0x46: "CHAINID", 0x47: "SELFBALANCE",
  0x48: "BASEFEE",
  0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
  0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI",
  0x58: "PC", 0x59: "MSIZE", 0x5a: "GAS", 0x5b: "JUMPDEST", 0x5f: "PUSH0",
  0xf0: "CREATE", 0xf1: "CALL", 0xf2: "CALLCODE", 0xf3: "RETURN",
  0xf4: "DELEGATECALL", 0xf5: "CREATE2", 0xfa: "STATICCALL",
  0xfd: "REVERT", 0xfe: "INVALID", 0xff: "SELFDESTRUCT",
};

export interface Instruction {
  /** Byte offset in the bytecode. */
  offset: number;
  /** Numeric opcode. */
  op: number;
  /** Human name, e.g. "PUSH1" or the raw hex for unknown opcodes. */
  name: string;
  /** For PUSH1..PUSH32, the pushed immediate as a hex string (no 0x). */
  push?: string;
}

/** Strip a leading 0x and any surrounding whitespace. */
export function normalizeHex(hex: string): string {
  const h = hex.trim().toLowerCase();
  return h.startsWith("0x") ? h.slice(2) : h;
}

/**
 * Solidity appends a CBOR metadata blob to runtime bytecode, ending with a
 * 2-byte big-endian length of that blob. The blob holds the ipfs/bzzr hash of
 * the source and the compiler version — it changes on every recompile even
 * when the logic is byte-for-byte identical, so it's pure noise for kinship
 * matching. This removes it when present, leaving just the executable code.
 *
 * Returns the (possibly shortened) hex, without 0x.
 */
export function stripMetadata(hex: string): string {
  const clean = normalizeHex(hex);
  if (clean.length < 8) return clean;
  const byteLen = clean.length / 2;

  // Last two bytes = length L of the CBOR blob that precedes them.
  const lenWord = parseInt(clean.slice(-4), 16);
  if (!Number.isFinite(lenWord) || lenWord <= 0) return clean;

  const blobStart = byteLen - 2 - lenWord; // byte index where the blob begins
  if (blobStart <= 0) return clean;

  // Sanity: a CBOR map begins with a major-type-5 byte (0xa0..0xbf). Requiring
  // it avoids chopping code off contracts that happen to end in the right bytes.
  const marker = parseInt(clean.slice(blobStart * 2, blobStart * 2 + 2), 16);
  if (marker < 0xa0 || marker > 0xbf) return clean;

  return clean.slice(0, blobStart * 2);
}

// EIP-1167 minimal proxy, and its PUSH0 variant (ERC-7511). The whole runtime
// is a fixed 45-byte stub with the implementation address baked in, so every
// clone of every contract looks identical unless we look through it.
const MINIMAL_PROXIES: { kind: string; re: RegExp }[] = [
  {
    kind: "eip-1167",
    re: /^363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3$/,
  },
  {
    kind: "erc-7511",
    re: /^365f5f375f5f365f73([0-9a-f]{40})5af43d5f5f3e5f3d91602a57fd5bf3$/,
  },
];

/** If the bytecode is a minimal proxy stub, return the address it forwards to. */
export function minimalProxyTarget(
  hex: string
): { kind: string; target: string } | null {
  const clean = normalizeHex(hex);
  for (const { kind, re } of MINIMAL_PROXIES) {
    const m = clean.match(re);
    if (m) return { kind, target: "0x" + m[1] };
  }
  return null;
}

/**
 * Walk the bytecode and yield one Instruction per opcode. PUSH immediates are
 * consumed (not mistaken for opcodes), which is the whole reason a naive byte
 * histogram is worse than a real disassembly.
 */
export function disassemble(bytecodeHex: string): Instruction[] {
  const hex = normalizeHex(bytecodeHex);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }

  const out: Instruction[] = [];
  let i = 0;
  while (i < bytes.length) {
    const op = bytes[i];
    const offset = i;

    // PUSH1 (0x60) .. PUSH32 (0x7f)
    if (op >= 0x60 && op <= 0x7f) {
      const n = op - 0x5f; // number of immediate bytes
      const imm = hex.slice((i + 1) * 2, (i + 1 + n) * 2);
      out.push({ offset, op, name: `PUSH${n}`, push: imm });
      i += 1 + n;
      continue;
    }
    // DUP1..DUP16
    if (op >= 0x80 && op <= 0x8f) {
      out.push({ offset, op, name: `DUP${op - 0x7f}` });
      i += 1;
      continue;
    }
    // SWAP1..SWAP16
    if (op >= 0x90 && op <= 0x9f) {
      out.push({ offset, op, name: `SWAP${op - 0x8f}` });
      i += 1;
      continue;
    }
    // LOG0..LOG4
    if (op >= 0xa0 && op <= 0xa4) {
      out.push({ offset, op, name: `LOG${op - 0xa0}` });
      i += 1;
      continue;
    }

    const name = OPCODES[op] ?? `UNKNOWN_${op.toString(16).padStart(2, "0")}`;
    out.push({ offset, op, name });
    i += 1;
  }
  return out;
}
