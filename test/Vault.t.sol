// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {Vault} from "../src/Vault.sol";
import {Attacker} from "../src/Attacker.sol";

contract VaultReentrancyTest is Test {
    Vault vault;

    address honest = makeAddr("honest");
    address attackerEOA = makeAddr("attacker");

    function setUp() public {
        vault = new Vault();

        // An honest user deposits 5 ETH into the vault.
        vm.deal(honest, 5 ether);
        vm.prank(honest);
        vault.deposit{value: 5 ether}();
    }

    /// @notice DEMONSTRATES THE EXPLOIT.
    /// Against the vulnerable Vault this test PASSES: the attacker seeds 1 ETH,
    /// re-enters withdraw() repeatedly, and walks away with the honest user's
    /// 5 ETH too — leaving the vault empty.
    function test_ReentrancyDrainsVault() public {
        vm.deal(attackerEOA, 1 ether);

        vm.prank(attackerEOA);
        Attacker attacker = new Attacker(address(vault));

        vm.prank(attackerEOA);
        attacker.attack{value: 1 ether}();

        // The vault has been fully drained...
        assertEq(vault.totalBalance(), 0, "vault should be drained by the exploit");

        // ...and the attacker now holds its 1 ETH seed plus the stolen 5.
        assertEq(address(attacker).balance, 6 ether, "attacker should hold seed + stolen funds");
    }

    /// @notice SECURITY / REGRESSION PROPERTY.
    /// An honest depositor must always be able to withdraw their own funds.
    function test_HonestUserCanWithdraw() public {
        uint256 before = honest.balance; // 0 — they deposited all 5 in setUp

        vm.prank(honest);
        vault.withdraw();

        assertEq(honest.balance, before + 5 ether, "honest user should get their 5 ETH back");
    }
}
