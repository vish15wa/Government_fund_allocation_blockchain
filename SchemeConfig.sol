// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
//  CONTRACT 2: SchemeConfig.sol
//  Deploy this SECOND (after RoleAccess).
//  Project: Blockchain-Based Widow Pension Administration
//  Group:   IBC07 | CSE 542 | Prof. Sanjay Chaudhary
// ============================================================

import "./RoleAccess.sol";

contract SchemeConfig is RoleAccess {

    // ── Struct ────────────────────────────────────────────────
    struct Scheme {
        uint256 schemeId;
        string  name;               // e.g. "IGNWPS" (Indira Gandhi National Widow Pension Scheme)
        uint256 monthlyAmount;      // pension amount in Wei
        uint256 minAgeLimit;        // minimum age for eligibility (years)
        uint256 maxAgeLimit;        // maximum age for eligibility (years)
        uint256 maxProcessingDays;  // SLA: max working days allowed for decision (e.g. 20)
        bool    active;             // scheme is open for applications
        uint256 createdAt;          // timestamp of creation
        uint256 updatedAt;          // timestamp of last update
    }

    // ── Storage ───────────────────────────────────────────────
    mapping(uint256 => Scheme) private schemes;
    uint256[] public schemeIds;
    uint256 private nextSchemeId = 1;

    // ── Events ────────────────────────────────────────────────
    event SchemeAdded(uint256 indexed schemeId, string name, uint256 monthlyAmount, address by);
    event SchemeUpdated(uint256 indexed schemeId, string name, address by);
    event SchemeToggled(uint256 indexed schemeId, bool active, address by);

    // ── Constructor ───────────────────────────────────────────
    constructor() {
        // Pre-load: Indira Gandhi National Widow Pension Scheme
        _addScheme(
            "IGNWPS - Indira Gandhi National Widow Pension Scheme",
            300 ether,   // 300 Wei (symbolic; use actual amount in production)
            18,          // min age 18
            60,          // max age 60
            20           // 20 working days SLA
        );
    }

    // ── Internal ──────────────────────────────────────────────
    function _addScheme(
        string memory name,
        uint256 monthlyAmount,
        uint256 minAge,
        uint256 maxAge,
        uint256 maxDays
    ) internal returns (uint256) {
        uint256 sid = nextSchemeId++;
        schemes[sid] = Scheme({
            schemeId:         sid,
            name:             name,
            monthlyAmount:    monthlyAmount,
            minAgeLimit:      minAge,
            maxAgeLimit:      maxAge,
            maxProcessingDays: maxDays,
            active:           true,
            createdAt:        block.timestamp,
            updatedAt:        block.timestamp
        });
        schemeIds.push(sid);
        return sid;
    }

    // ── Admin Functions ───────────────────────────────────────

    /// @notice Add a new pension scheme (admin only)
    function addScheme(
        string calldata name,
        uint256 monthlyAmount,
        uint256 minAge,
        uint256 maxAge,
        uint256 maxDays
    ) external onlyAdmin returns (uint256 schemeId) {
        require(bytes(name).length > 0,  "SchemeConfig: name cannot be empty");
        require(monthlyAmount > 0,       "SchemeConfig: amount must be > 0");
        require(minAge < maxAge,         "SchemeConfig: minAge must be < maxAge");
        schemeId = _addScheme(name, monthlyAmount, minAge, maxAge, maxDays);
        emit SchemeAdded(schemeId, name, monthlyAmount, msg.sender);
    }

    /// @notice Update scheme parameters (admin only)
    function updateScheme(
        uint256 schemeId,
        string calldata name,
        uint256 monthlyAmount,
        uint256 minAge,
        uint256 maxAge,
        uint256 maxDays
    ) external onlyAdmin {
        require(schemes[schemeId].schemeId == schemeId, "SchemeConfig: scheme does not exist");
        Scheme storage s = schemes[schemeId];
        s.name             = name;
        s.monthlyAmount    = monthlyAmount;
        s.minAgeLimit      = minAge;
        s.maxAgeLimit      = maxAge;
        s.maxProcessingDays = maxDays;
        s.updatedAt        = block.timestamp;
        emit SchemeUpdated(schemeId, name, msg.sender);
    }

    /// @notice Toggle scheme active/inactive (admin only)
    function toggleScheme(uint256 schemeId) external onlyAdmin {
        require(schemes[schemeId].schemeId == schemeId, "SchemeConfig: scheme does not exist");
        schemes[schemeId].active = !schemes[schemeId].active;
        schemes[schemeId].updatedAt = block.timestamp;
        emit SchemeToggled(schemeId, schemes[schemeId].active, msg.sender);
    }

    // ── View Functions ────────────────────────────────────────

    /// @notice Get full scheme details
    function getScheme(uint256 schemeId) external view returns (Scheme memory) {
        require(schemes[schemeId].schemeId == schemeId, "SchemeConfig: scheme does not exist");
        return schemes[schemeId];
    }

    /// @notice Check if a scheme exists and is active
    function isSchemeActive(uint256 schemeId) external view returns (bool) {
        return schemes[schemeId].active;
    }

    /// @notice Get monthly pension amount for a scheme
    function getMonthlyAmount(uint256 schemeId) external view returns (uint256) {
        require(schemes[schemeId].schemeId == schemeId, "SchemeConfig: scheme does not exist");
        return schemes[schemeId].monthlyAmount;
    }

    /// @notice Get all registered scheme IDs
    function getAllSchemeIds() external view returns (uint256[] memory) {
        return schemeIds;
    }

    /// @notice Get total number of schemes
    function totalSchemes() external view returns (uint256) {
        return schemeIds.length;
    }
}
