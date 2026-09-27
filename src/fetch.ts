/**
 * Fetch on-chain runtime bytecode for an address over plain JSON-RPC, looking
 * through proxies to the code that actually runs.
 *
 * Proxies matter a lot here. Thousands of unrelated contracts share the exact
 * same EIP-1167 or ERC-1967 proxy stub, so fingerprinting the stub would call
 * all of them twins. We resolve, in order:
 *
 *   - EIP-1167 / ERC-7511 minimal proxies (address is embedded in the code)
 *   - ERC-1967 implementation slot
 *   - ERC-1967 beacon slot (then ask the beacon for its implementation)
 *   - EIP-1822 (UUPS) slot
 *   - the legacy OpenZeppelin/zeppelinos slot (e.g. USDC)
 *   - finally, any contract that DELEGATECALLs and answers `implementation()`
 *     (Compound's CErc20Delegator and friends)
 *
 * Network access is opt-in: the fingerprint/compare core never touches it.
 */

import {
  createPublicClient,
  getAddress,
  http,
  type Address,
  type Hex,
  type PublicClient,
} from "viem";
import { disassemble, minimalProxyTarget } from "./bytecode.js";

/** Friendly chain name -> default public RPC. Override with DOPPEL_RPC_<CHAIN>. */
export const CHAIN_RPCS: Record<string, string> = {
  ethereum: "https://ethereum-rpc.publicnode.com",
  base: "https://base-rpc.publicnode.com",
  arbitrum: "https://arbitrum-one-rpc.publicnode.com",
  optimism: "https://optimism-rpc.publicnode.com",
  polygon: "https://polygon-bor-rpc.publicnode.com",
  bsc: "https://bsc-rpc.publicnode.com",
  avalanche: "https://avalanche-c-chain-rpc.publicnode.com",
};

/** Resolve a chain name or raw URL to an RPC URL. */
export function resolveRpc(chainOrUrl: string): string {
  if (/^https?:\/\//.test(chainOrUrl)) return chainOrUrl;
  const name = chainOrUrl.toLowerCase();
  const fromEnv = process.env[`DOPPEL_RPC_${name.toUpperCase()}`];
  if (fromEnv) return fromEnv;
  const url = CHAIN_RPCS[name];
  if (!url) {
    throw new Error(
      `Unknown chain "${chainOrUrl}". Known: ${Object.keys(CHAIN_RPCS).join(", ")} — or pass a full RPC URL.`
    );
  }
  return url;
}

const clients = new Map<string, PublicClient>();
function clientFor(chainOrUrl: string): PublicClient {
  const url = resolveRpc(chainOrUrl);
  let c = clients.get(url);
  if (!c) {
    // batch: the slot probes for one address go out as a single HTTP request
    c = createPublicClient({ transport: http(url, { batch: true, retryCount: 2 }) });
    clients.set(url, c);
  }
  return c;
}

const SLOTS: [kind: string, slot: Hex][] = [
  ["erc-1967", "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"],
  ["erc-1967-beacon", "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"],
  ["eip-1822", "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"],
  ["zeppelinos", "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"],
];

const IMPLEMENTATION_CALL = "0x5c60da1b"; // implementation()

function wordToAddress(word: Hex | undefined): Address | null {
  if (!word || word.length < 42) return null;
  const tail = word.slice(-40);
  if (/^0+$/.test(tail)) return null;
  return getAddress("0x" + tail);
}

async function callForAddress(client: PublicClient, to: Address): Promise<Address | null> {
  try {
    const { data } = await client.call({ to, data: IMPLEMENTATION_CALL });
    return data && data.length >= 66 ? wordToAddress(data.slice(0, 66) as Hex) : null;
  } catch {
    return null; // reverted: not a proxy we can see through
  }
}

export interface ProxyHop {
  kind: string;
  proxy: Address;
  implementation: Address;
}

export interface Resolved {
  /** Address whose code was fingerprinted (the implementation, for proxies). */
  address: Address;
  bytecode: Hex;
  /** Proxy layers that were looked through, outermost first. */
  hops: ProxyHop[];
}

async function detectProxy(
  client: PublicClient,
  address: Address,
  code: Hex
): Promise<{ kind: string; implementation: Address } | null> {
  const minimal = minimalProxyTarget(code);
  if (minimal) return { kind: minimal.kind, implementation: getAddress(minimal.target) };

  const words = await Promise.all(
    SLOTS.map(([, slot]) => client.getStorageAt({ address, slot }).catch(() => undefined))
  );
  for (let i = 0; i < SLOTS.length; i++) {
    const target = wordToAddress(words[i]);
    if (!target) continue;
    const kind = SLOTS[i][0];
    if (kind === "erc-1967-beacon") {
      const impl = await callForAddress(client, target);
      if (impl) return { kind, implementation: impl };
      continue;
    }
    return { kind, implementation: target };
  }

  if (disassemble(code).some((ins) => ins.name === "DELEGATECALL")) {
    const impl = await callForAddress(client, address);
    if (impl && impl !== address) return { kind: "implementation()", implementation: impl };
  }
  return null;
}

/** Fetch the code that actually runs at `address`, following up to 4 proxy hops. */
export async function fetchResolved(
  chainOrUrl: string,
  address: string,
  opts: { followProxies?: boolean } = {}
): Promise<Resolved> {
  const client = clientFor(chainOrUrl);
  const follow = opts.followProxies ?? true;
  const hops: ProxyHop[] = [];
  let current = getAddress(address);

  for (let depth = 0; depth <= 4; depth++) {
    const code = await client.getCode({ address: current });
    if (!code || code === "0x") {
      const where = hops.length ? `implementation ${current} (behind ${address})` : current;
      throw new Error(`No bytecode at ${where} on ${chainOrUrl} (EOA, self-destructed, or wrong chain?).`);
    }
    if (!follow) return { address: current, bytecode: code, hops };

    const next = await detectProxy(client, current, code);
    if (!next) return { address: current, bytecode: code, hops };
    hops.push({ kind: next.kind, proxy: current, implementation: next.implementation });
    current = next.implementation;
  }
  throw new Error(`Gave up after 4 proxy hops starting at ${address}.`);
}
