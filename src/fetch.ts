/**
 * Fetch on-chain runtime bytecode for an address, over a plain JSON-RPC
 * endpoint. viem is used only as a thin transport so the tool works against
 * any EVM chain the user points it at (mainnet, L2s, BSC, etc.).
 *
 * A registry of common public RPCs is provided for convenience, but any custom
 * URL works too. Network access is entirely opt-in: the fingerprint/compare
 * core never touches the network.
 */

import { createPublicClient, http, type Address } from "viem";

/** Friendly chain name -> a default public RPC URL. */
export const CHAIN_RPCS: Record<string, string> = {
  ethereum: "https://eth.llamarpc.com",
  base: "https://mainnet.base.org",
  arbitrum: "https://arb1.arbitrum.io/rpc",
  optimism: "https://mainnet.optimism.io",
  polygon: "https://polygon-rpc.com",
  bsc: "https://bsc-dataseed.binance.org",
  avalanche: "https://api.avax.network/ext/bc/C/rpc",
};

/** Resolve a chain name or raw URL to an RPC URL. */
export function resolveRpc(chainOrUrl: string): string {
  if (chainOrUrl.startsWith("http://") || chainOrUrl.startsWith("https://")) {
    return chainOrUrl;
  }
  const url = CHAIN_RPCS[chainOrUrl.toLowerCase()];
  if (!url) {
    throw new Error(
      `Unknown chain "${chainOrUrl}". Known: ${Object.keys(CHAIN_RPCS).join(
        ", "
      )} — or pass a full RPC URL.`
    );
  }
  return url;
}

/** Fetch the deployed runtime bytecode at `address`. */
export async function fetchBytecode(
  chainOrUrl: string,
  address: string
): Promise<string> {
  const client = createPublicClient({ transport: http(resolveRpc(chainOrUrl)) });
  const code = await client.getCode({ address: address as Address });
  if (!code || code === "0x") {
    throw new Error(
      `No bytecode at ${address} on ${chainOrUrl} (EOA, or wrong chain?).`
    );
  }
  return code;
}
