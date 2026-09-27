/**
 * A small offline table of common function signatures, so reports can say
 * `withdraw(uint256)` instead of `0x2e1a7d4d`. Selectors are computed from the
 * signature strings at load time, so the table can't drift out of sync.
 *
 * Unknown selectors are simply shown as hex.
 */

import { toFunctionSelector } from "viem";

const SIGNATURES = [
  // ERC20 / permit
  "totalSupply()", "balanceOf(address)", "transfer(address,uint256)",
  "transferFrom(address,address,uint256)", "approve(address,uint256)",
  "allowance(address,address)", "name()", "symbol()", "decimals()",
  "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
  "nonces(address)", "DOMAIN_SEPARATOR()", "PERMIT_TYPEHASH()",
  "increaseAllowance(address,uint256)", "decreaseAllowance(address,uint256)",
  "mint(address,uint256)", "burn(uint256)", "burnFrom(address,uint256)",
  // WETH / simple vaults
  "deposit()", "deposit(uint256)", "withdraw(uint256)", "withdrawAll()",
  "emergencyWithdraw(uint256)", "claim()", "harvest()", "stake(uint256)",
  "unstake(uint256)", "getReward()", "earned(address)",
  // ownership / pause
  "owner()", "transferOwnership(address)", "renounceOwnership()",
  "pendingOwner()", "acceptOwnership()", "paused()", "pause()", "unpause()",
  // Uniswap V2 pair / factory / router
  "getReserves()", "token0()", "token1()", "factory()", "mint(address)",
  "burn(address)", "swap(uint256,uint256,address,bytes)", "skim(address)",
  "sync()", "initialize(address,address)", "kLast()",
  "price0CumulativeLast()", "price1CumulativeLast()", "MINIMUM_LIQUIDITY()",
  "createPair(address,address)", "getPair(address,address)",
  "allPairs(uint256)", "allPairsLength()", "feeTo()", "feeToSetter()",
  "setFeeTo(address)", "setFeeToSetter(address)", "WETH()",
  "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
  "swapTokensForExactTokens(uint256,uint256,address[],address,uint256)",
  "swapExactETHForTokens(uint256,address[],address,uint256)",
  "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
  "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
  "addLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
  "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
  "removeLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
  "getAmountsOut(uint256,address[])", "getAmountsIn(uint256,address[])",
  "getAmountOut(uint256,uint256,uint256)", "getAmountIn(uint256,uint256,uint256)",
  "quote(uint256,uint256,uint256)",
  // Compound-style money markets
  "mint(uint256)", "redeem(uint256)", "redeemUnderlying(uint256)",
  "borrow(uint256)", "repayBorrow(uint256)",
  "liquidateBorrow(address,uint256,address)", "exchangeRateStored()",
  "exchangeRateCurrent()", "accrueInterest()", "getCash()", "totalBorrows()",
  "totalReserves()", "borrowBalanceStored(address)", "underlying()",
  "comptroller()",
  // ERC4626
  "asset()", "totalAssets()", "deposit(uint256,address)", "mint(uint256,address)",
  "withdraw(uint256,address,address)", "redeem(uint256,address,address)",
  "convertToShares(uint256)", "convertToAssets(uint256)",
  "previewDeposit(uint256)", "previewRedeem(uint256)", "maxWithdraw(address)",
  // ERC721 / ERC165
  "ownerOf(uint256)", "safeTransferFrom(address,address,uint256)",
  "setApprovalForAll(address,bool)", "isApprovedForAll(address,address)",
  "getApproved(uint256)", "tokenURI(uint256)", "supportsInterface(bytes4)",
  // proxies / misc
  "implementation()", "upgradeTo(address)", "upgradeToAndCall(address,bytes)",
  "admin()", "changeAdmin(address)", "multicall(bytes[])",
];

const BY_SELECTOR = new Map<string, string>();
for (const sig of SIGNATURES) {
  BY_SELECTOR.set(toFunctionSelector(sig).slice(2), sig);
}

/** Human label for a selector (hex, no 0x): the signature if known, else hex. */
export function labelFor(selector: string): string {
  return BY_SELECTOR.get(selector) ?? `0x${selector}`;
}

/** Accept `withdraw(uint256)` or `0x2e1a7d4d`; return the selector hex without 0x. */
export function parseFunction(input: string): string {
  const s = input.trim();
  if (/^0x[0-9a-fA-F]{8}$/.test(s)) return s.slice(2).toLowerCase();
  if (/^[A-Za-z_$][\w$]*\(.*\)$/.test(s)) return toFunctionSelector(s).slice(2);
  throw new Error(
    `--fn expects a signature like "withdraw(uint256)" or a selector like 0x2e1a7d4d, got "${input}"`
  );
}
