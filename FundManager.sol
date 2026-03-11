// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
//  CONTRACT 5: FundManager.sol
//  Deploy this FIFTH (after RoleAccess and SchemeConfig).
//  Project: Blockchain-Based Widow Pension Administration
//  Group:   IBC07 | CSE 542 | Prof. Sanjay Chaudhary
// ============================================================

import "./RoleAccess.sol";
import "./SchemeConfig.sol";

contract FundManager is RoleAccess {

    // ── State ─────────────────────────────────────────────────
    bool public paused = false;

    // schemeId => total Wei deposited for that scheme
    mapping(uint256 => uint256) public schemeBalances;

    // applicationId => amount paid out
    mapping(uint256 => uint256) public paymentRecord;

    // applicationId => has already been paid (prevent double payment)
    mapping(uint256 => bool) public isPaid;

    SchemeConfig public schemeConfig;

    // ── Events ────────────────────────────────────────────────
    event FundsDeposited(
        uint256 indexed schemeId,
        address indexed by,
        uint256 amount,
        uint256 timestamp
    );

    event PaymentReleased(
        uint256 indexed applicationId,
        uint256 indexed schemeId,
        address indexed beneficiary,
        uint256 amount,
        uint256 timestamp
    );

    event ContractPaused(address by, uint256 timestamp);
    event ContractUnpaused(address by, uint256 timestamp);

    // ── Modifiers ─────────────────────────────────────────────
    modifier notPaused() {
        require(!paused, "FundManager: contract is paused");
        _;
    }

    // ── Constructor ───────────────────────────────────────────
    /// @param schemeConfigAddress Address of the already-deployed SchemeConfig contract
    constructor(address schemeConfigAddress) {
        require(schemeConfigAddress != address(0), "FundManager: invalid SchemeConfig address");
        schemeConfig = SchemeConfig(schemeConfigAddress);
    }

    // ── Treasury Functions ────────────────────────────────────

    /// @notice Deposit ETH into a scheme's fund pool (TREASURY_ROLE only)
    /// @param schemeId The scheme to fund
    function depositFunds(uint256 schemeId) external payable onlyRole(TREASURY_ROLE) notPaused {
        require(msg.value > 0,                           "FundManager: deposit must be > 0");
        require(schemeConfig.isSchemeActive(schemeId),   "FundManager: scheme is not active");

        schemeBalances[schemeId] += msg.value;
        emit FundsDeposited(schemeId, msg.sender, msg.value, block.timestamp);
    }

    /// @notice Disburse pension payment to a beneficiary (REGISTRY_ROLE only)
    /// @dev Only PensionRegistry contract can call this after on-chain approval
    /// @param applicationId  The approved application ID
    /// @param schemeId       The pension scheme
    /// @param beneficiary    The beneficiary's wallet address to receive payment
    function disbursePayment(
        uint256 applicationId,
        uint256 schemeId,
        address payable beneficiary
    ) external onlyRole(REGISTRY_ROLE) notPaused {
        require(!isPaid[applicationId],              "FundManager: application already paid");
        require(beneficiary != address(0),           "FundManager: invalid beneficiary address");
        require(schemeConfig.isSchemeActive(schemeId), "FundManager: scheme is not active");

        uint256 amount = schemeConfig.getMonthlyAmount(schemeId);
        require(amount > 0,                          "FundManager: scheme amount is 0");
        require(
            schemeBalances[schemeId] >= amount,
            "FundManager: insufficient scheme balance"
        );

        // Mark as paid before transfer (re-entrancy guard pattern)
        isPaid[applicationId]      = true;
        paymentRecord[applicationId] = amount;
        schemeBalances[schemeId]   -= amount;

        // Transfer ETH to beneficiary
        (bool success, ) = beneficiary.call{value: amount}("");
        require(success, "FundManager: ETH transfer failed");

        emit PaymentReleased(applicationId, schemeId, beneficiary, amount, block.timestamp);
    }

    // ── Admin Controls ────────────────────────────────────────

    /// @notice Pause all fund operations (admin only — emergency use)
    function pause() external onlyAdmin {
        require(!paused, "FundManager: already paused");
        paused = true;
        emit ContractPaused(msg.sender, block.timestamp);
    }

    /// @notice Unpause fund operations (admin only)
    function unpause() external onlyAdmin {
        require(paused, "FundManager: not paused");
        paused = false;
        emit ContractUnpaused(msg.sender, block.timestamp);
    }

    // ── View Functions ────────────────────────────────────────

    /// @notice Get current balance of a scheme's fund pool
    function getSchemeBalance(uint256 schemeId) external view returns (uint256) {
        return schemeBalances[schemeId];
    }

    /// @notice Get the total ETH held across all schemes
    function totalFundsHeld() external view returns (uint256) {
        return address(this).balance;
    }

    /// @notice Check if a specific application has been paid
    function checkPaymentStatus(uint256 applicationId)
        external view returns (bool paid, uint256 amount)
    {
        paid   = isPaid[applicationId];
        amount = paymentRecord[applicationId];
    }

    // ── Receive ETH ───────────────────────────────────────────
    receive() external payable {
        // Direct ETH sends go to scheme 1 by default (admin can redirect)
        schemeBalances[1] += msg.value;
    }
}
