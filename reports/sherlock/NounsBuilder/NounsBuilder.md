# Contest Details
[https://audits.sherlock.xyz/contests/111](https://audits.sherlock.xyz/contests/111)

# Findings
High severity: <br>
[First Founder unable to mint token due to tokenId incorrectly set to reservedUntilTokenId](#h1-first-founder-unable-to-mint-token-due-to-tokenid-incorrectly-set-to-reserveduntiltokenid)

Medium severity: <br>
[Malicious DOS by pausing contract](#m1-malicious-dos-by-pausing-contract)


## H1-First Founder unable to mint token due to tokenId incorrectly set to reservedUntilTokenId

## Summary
When adding founders during `Token.sol` initialization, the first founder will have his first tokenId set to reservedUntilTokenId. This has two consequences 1) the first founder cannot mint his first token using `mintFromReserveTo`, and 2) reservedUntilTokenId will incorrectly point to a reserved token.
## Vulnerability Detail

By design, the`reservedUntilTokenId` should be the first tokenId that the DAO's auctions will use. If it was set to 100 then it means that tokenIds 0 to 99 are reserved.
```solidity
/// @param _reservedUntilTokenId The tokenId that a DAO's auctions will start at
```

The error lies in the function `_addFounders`. Unlike subsequent tokens, this first reserved token does not go through `% 100` and therefore is set to be equal to `reservedUntilTokenId`. E.g. if `reservedUntilTokenId = 100`, the first founder's first reserved token will be id `100`.

```solidity
function _addFounders() internal {
	...
	// @audit first founder's first tokenId set to reservedUntiltokenId
	uint256 baseTokenId = reservedUntilTokenId;

	for (uint256 j; j < founderPct; ++j) {
		// @audit tokenId is unchanged by _getNextTokenId since token is unassigned
		baseTokenId = _getNextTokenId(baseTokenId);
		tokenRecipient[baseTokenId] = newFounder;

		emit MintScheduled(baseTokenId, founderId, newFounder);

		// @audit only subsequent tokenIds have the % 100 treatment
		baseTokenId = (baseTokenId + schedule) % 100;
	}
}

function _getNextTokenId(uint256 _tokenId) internal view returns (uint256) {
	unchecked {
		while (tokenRecipient[_tokenId].wallet != address(0)) {
		_tokenId = (++_tokenId) % 100;
		}

		return _tokenId;
	}
}
```

## Impact
The first founder is unable to mint his first token through `mintFromReserveTo`as it would fail the check:

```solidity
 if (tokenId >= reservedUntilTokenId) revert TOKEN_NOT_RESERVED();
```

Consider this proof-of-concept:
- Assume `reservedUntilTokenId = 100`
- After adding founders, it is checked that tokenId 100 belongs to the first founder
- If minter tries to mint tokenId 100 to founder, it will revert with "TOKEN_NOT_RESERVED"

Add this foundry test to `Token.t.sol`
```solidity
function test_cannotMintFirstToken() public {
	uint256 _reservedUntilTokenId = 100;
	deployAltMock(_reservedUntilTokenId);

	(address wallet100,,) = token.tokenRecipient(100);
	assertTrue(wallet100 == address(founder));

	address _minter = vm.addr(0x1234);
	TokenTypesV2.MinterParams[] memory minters = new TokenTypesV2.MinterParams[](1);
	TokenTypesV2.MinterParams memory p1 = TokenTypesV2.MinterParams({ minter: _minter, allowed: true });
	minters[0] = p1;

	vm.prank(address(founder));
	token.updateMinters(minters);

	vm.startPrank(minters[0].minter);

	bytes4 selector = bytes4(keccak256(abi.encodePacked("TOKEN_NOT_RESERVED()")));

	vm.expectRevert(selector);
	// First founder cannot mint first tokenId
	token.mintFromReserveTo(founder, 100);
}
```

A secondary impact happens when the first auction is held which will mint tokenId 0 to the first founder and tokenId 100 to the auction winner. So id 100 was reserved for founder, but he received id 0, and the auction winner receives id 100.  The reason is because in `mintWithVesting()` and `_isForFounder()` correctly applies `% 100` to `reservedForTokenId` before minting to the first founder.

Considering that the first founder is very likely an important person in the DAO, losing some ownership due to failure to mint a token is quite impactful. The likelihood is also high or even bound to occur due to the very first reserved tokenId being incorrectly set to `reservedForTokenId`.
## Code Snippet
[https://github.com/sherlock-audit/2023-09-nounsbuilder-giraffe0x/blob/main/nouns-protocol/src/token/Token.sol#L161](https://github.com/sherlock-audit/2023-09-nounsbuilder-giraffe0x/blob/main/nouns-protocol/src/token/Token.sol#L161)

## Tool used
Manual Review

## Recommendation
Consider changing `_addFounders()` from:

`uint256 baseTokenId = reservedUntilTokenId;`
to
`uint256 baseTokenId = reservedUntilTokenId % 100;


## M1-Malicious DOS by pausing contract
## Summary
Due to [EIP150](https://eips.ethereum.org/EIPS/eip-150) introduction of the 63/64 gas rule, it is possible to DOS the `Auction.sol` by repeatedly pausing it. This is done through providing the correct amount of gas when calling `settleCurrentAndCreateNewAuction()` that would cause `_createAuction -> token.mint()` to fail.
## Vulnerability Detail
Same bug from previous contest remains unfixed, and is not listed as a known issue:
[https://code4rena.com/reports/2022-09-nouns-builder#m-15-malicious-pausing-the-contract](https://code4rena.com/reports/2022-09-nouns-builder#m-15-malicious-pausing-the-contract)
Essentially,  `_createAuction` does a `try-catch` to call `token.mint()`. If the `try` call fails due to insufficient gas, the `catch` block is triggered which pauses the contract.

The bug is exploitable if `token.mint()` uses more than 1.5 mil of gas because 1.5mil / 64 is > 20,000 which is the amount of gas needed to pause the contract. This is achievable when roughly 20 tokens are being minted to founders.
## Impact
As `settleCurrentAndCreateNewAuction()` can be called by anyone, an attacker can potentially keep pausing the auction contract, which requires a DAO vote to call `unpause()` causing major inconvenience and possibly permanent DOS of the auction.

## Code Snippet
[https://github.com/sherlock-audit/2023-09-nounsbuilder-giraffe0x/blob/main/nouns-protocol/src/auction/Auction.sol#L294](https://github.com/sherlock-audit/2023-09-nounsbuilder-giraffe0x/blob/main/nouns-protocol/src/auction/Auction.sol#L294)

## Tool used
Manual Review

## Recommendation
Before calling `token.mint()` check that sufficient gas being forwarded so that the mint will not fail due to a lack of gas. This could be stored in a `minGas` variable.
