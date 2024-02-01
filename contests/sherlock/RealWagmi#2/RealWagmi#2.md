## Contest details
[https://audits.sherlock.xyz/contests/118](https://audits.sherlock.xyz/contests/118)

## Findings
High severity:<br>
[Malicious liquidity provider can prevent liquidation of loan and loss of funds to other liquidity providers](#h-1-malicious-liquidity-provider-can-prevent-liquidation-of-loan-and-loss-of-funds-to-other-liquidity-providers)<br>
Medium severity:<br>
[If loan is not liquidated in time, underflow may prevent loan from being liquidated using emergency mode](#m-1-if-loan-is-not-liquidated-in-time-underflow-may-prevent-loan-from-being-liquidated-using-emergency-mode)


## H-1 Malicious liquidity provider can prevent liquidation of loan and loss of funds to other liquidity providers
### Summary
By supplying a loan and burning the Univswap V3 position after, a malicious liquidity provider can cause DOS to real wagmi and prevent liquidation of loan(s) and loss of funds to other liquidity providers.

### Vulnerability Detail
A malicious liquidity provider could approve real wagmi to use his position for loans. After supplying the loan, the malicious actor could then burn their Uniswap V3 position NFT. This prevents repayment or liquidation of a loan, even through the emergency mode.

In the regular repayment/liquidation process, when _upRestoreLiquidityCache() is called, this external call :
underlyingPositionManager.positions(loan.tokenId); reverts with 'Invalid Token Id".

In the emergency process, when _calculateEmergencyLoanClosure() is called, this external call :
address creditor = underlyingPositionManager.ownerOf(loan.tokenId);reverts with 'ERC721: owner query for nonexistent token'.

### Proof of Concept
In WagmiLeverageTests.ts, bob provides a WETH_USDT loan with tokenId 512099. As all liquidity is used for loans, by inserting await nonfungiblePositionManager.connect(bob).burn(nftpos[1].tokenId); before repay is called, these tests will fail :

it("emergency repay will be successful for PosManNFT owner if the collateral is depleted") (L990)
it("Loan liquidation will be successful for anyone if the collateral is depleted") (L1071)
Impact
As a result of the DOS,

Liquidation of the loan not possible, significant funds loss/stuck
Honest liquidity providers are unable to recover funds supplied to the loan (up to 7 per position)
An honest borrower is unable to repay, close the loan and recover collateral
### Code Snippet
https://github.com/sherlock-audit/2023-10-real-wagmi/blob/main/wagmi-leverage/contracts/abstract/LiquidityManager.sol#L494

https://github.com/sherlock-audit/2023-10-real-wagmi/blob/main/wagmi-leverage/contracts/abstract/LiquidityManager.sol#L494

### Tool used
Manual Review

### Recommendation
Suggest to wrap external calls to underlyingPositionManager in try/catch and handle reverts by writing off loan from that specific liquidity position which has been burned.


## M-1 If loan is not liquidated in time, underflow may prevent loan from being liquidated using emergency mode
### Summary
If roughly 500_000 seconds (~5 days) has passed and loan is not liquidated, emergency repayment will fail due to underflow causing repay function to revert

### Vulnerability Detail
borrowingStorage.accLoanRatePerSeconds =
holdTokenRateInfo.accLoanRatePerSeconds -
FullMath.mulDiv(
uint256(-collateralBalance),
Constants.BP,
borrowing.borrowedAmount // new amount
);

When collateralBalance grows large enough, this part of the repay function will revert

### POC
In line 421 of WagmiLeverageTests.ts, if time is increased to 500_000, the next test that repays will fail with Arithmetic operation underflowed or overflowed outside of an unchecked block.

### Impact
Prevention of liquidity providers from recovering their funds from a loan under liquidation. May also have impact on regular liquidation but did not have time to check due submission close to end of contest

### Code Snippet
https://github.com/sherlock-audit/2023-10-real-wagmi/blob/main/wagmi-leverage/contracts/LiquidityBorrowingManager.sol#L612C17-L618C23

### Tool used
Manual Review

### Recommendation
Handle possible underflow with additional checks before the calculation
