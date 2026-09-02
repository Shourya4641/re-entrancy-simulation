// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title Vault  (VULNERABLE CONTRACT)
/// @notice A minimal ETH vault that contains the reentrancy bug:
///         it makes the external call (sending ETH) BEFORE it updates state.
///         This is a checks-effects-interactions violation.
contract Vault {
    /// @notice How much ETH each address has deposited.
    mapping(address => uint256) public balances;

    /// @notice Deposit ETH; credits the sender's balance.
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice Withdraw the caller's full balance.
    /// @dev The ETH is sent (an external call, which hands
    ///      control to the recipient) BEFORE balances is zeroed.
    ///      A malicious contract can re-enter withdraw() from its receive()
    ///      hook while its recorded balance is still non-zero, and repeat until
    ///      the vault is empty.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");

        // ---- INTERACTION (external call) — happens BEFORE the effect ----
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        // ---- EFFECT (state update) — happens too late to matter ----
        balances[msg.sender] = 0;
    }

    /// @notice Total ETH currently held by the vault.
    function totalBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
