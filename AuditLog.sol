// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
//  CONTRACT 3: AuditLog.sol
//  Deploy this THIRD (after RoleAccess).
//  APPEND-ONLY — no update or delete functions exist.
//  Project: Blockchain-Based Widow Pension Administration
//  Group:   IBC07 | CSE 542 | Prof. Sanjay Chaudhary
// ============================================================

import "./RoleAccess.sol";

contract AuditLog is RoleAccess {

    // ── Enums ─────────────────────────────────────────────────
    enum ActionType {
        SUBMITTED,       // 0 - Application submitted by beneficiary
        REVIEW_STARTED,  // 1 - Official began reviewing
        APPROVED,        // 2 - Application approved
        REJECTED,        // 3 - Application rejected (reason mandatory)
        PAYMENT_SENT,    // 4 - Pension payment disbursed
        DISPUTE_RAISED,  // 5 - Beneficiary raised a dispute
        DISPUTE_RESOLVED // 6 - Dispute resolved by committee
    }

    // ── Struct ────────────────────────────────────────────────
    struct AuditEntry {
        uint256    applicationId;  // which application this event belongs to
        address    actor;          // wallet address of who performed the action
        ActionType action;         // what action was taken
        string     details;        // human-readable detail / mandatory rejection reason
        uint256    timestamp;      // block.timestamp at time of action
        uint256    blockNumber;    // block.number — for independent on-chain verification
    }

    // ── Storage ───────────────────────────────────────────────
    // applicationId => list of audit entries (append-only)
    mapping(uint256 => AuditEntry[]) private auditTrails;

    // Global log index for full system audit
    AuditEntry[] private globalLog;

    // ── Events ────────────────────────────────────────────────
    event AuditEventLogged(
        uint256 indexed applicationId,
        address indexed actor,
        ActionType      action,
        string          details,
        uint256         timestamp,
        uint256         blockNumber
    );

    // ── Write Function (LOGGER_ROLE only) ─────────────────────

    /// @notice Log an audit event — called by PensionRegistry only
    /// @param applicationId The application this event belongs to
    /// @param actor         The wallet address of the actor
    /// @param action        The action type enum value
    /// @param details       Human-readable description or rejection reason
    function logEvent(
        uint256    applicationId,
        address    actor,
        ActionType action,
        string calldata details
    ) external onlyRole(LOGGER_ROLE) {
        // REJECTION must include a non-empty reason
        if (action == ActionType.REJECTED) {
            require(bytes(details).length > 0, "AuditLog: rejection reason cannot be empty");
        }

        AuditEntry memory entry = AuditEntry({
            applicationId: applicationId,
            actor:         actor,
            action:        action,
            details:       details,
            timestamp:     block.timestamp,
            blockNumber:   block.number
        });

        auditTrails[applicationId].push(entry);
        globalLog.push(entry);

        emit AuditEventLogged(
            applicationId,
            actor,
            action,
            details,
            block.timestamp,
            block.number
        );
    }

    // ── Read Functions (public / auditor) ─────────────────────

    /// @notice Get the complete audit trail for one application
    function getAuditTrail(uint256 applicationId)
        external view returns (AuditEntry[] memory)
    {
        return auditTrails[applicationId];
    }

    /// @notice Get a specific audit entry for an application
    function getEntry(uint256 applicationId, uint256 entryIndex)
        external view returns (AuditEntry memory)
    {
        require(
            entryIndex < auditTrails[applicationId].length,
            "AuditLog: entry index out of bounds"
        );
        return auditTrails[applicationId][entryIndex];
    }

    /// @notice Get total number of events logged for an application
    function getEntryCount(uint256 applicationId) external view returns (uint256) {
        return auditTrails[applicationId].length;
    }

    /// @notice Get total events in the global system log
    function globalLogCount() external view returns (uint256) {
        return globalLog.length;
    }

    /// @notice Get a slice of the global log (for auditors paginating)
    function getGlobalLog(uint256 from, uint256 count)
        external view returns (AuditEntry[] memory result)
    {
        require(from < globalLog.length, "AuditLog: from index out of bounds");
        uint256 end = from + count;
        if (end > globalLog.length) end = globalLog.length;
        result = new AuditEntry[](end - from);
        for (uint256 i = from; i < end; i++) {
            result[i - from] = globalLog[i];
        }
    }

    /// @notice Verify if a specific entry hash matches expected values
    /// @dev Useful for citizens verifying a specific decision
    function verifyEntry(
        uint256 applicationId,
        uint256 entryIndex,
        address expectedActor,
        ActionType expectedAction
    ) external view returns (bool isValid) {
        if (entryIndex >= auditTrails[applicationId].length) return false;
        AuditEntry memory e = auditTrails[applicationId][entryIndex];
        return (e.actor == expectedActor && e.action == expectedAction);
    }
}
