// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
//  CONTRACT 4: IPFSVerifier.sol
//  Deploy this FOURTH (after RoleAccess).
//  Project: Blockchain-Based Widow Pension Administration
//  Group:   IBC07 | CSE 542 | Prof. Sanjay Chaudhary
// ============================================================

import "./RoleAccess.sol";

contract IPFSVerifier is RoleAccess {

    // ── Struct ────────────────────────────────────────────────
    struct DocumentRecord {
        string  ipfsCID;       // IPFS Content Identifier (CID) of the document
        bytes32 sha256Hash;    // SHA-256 hash of original file (computed off-chain)
        string  docType;       // e.g. "death_certificate", "marriage_certificate"
        uint256 anchoredAt;    // block.timestamp when CID was anchored on-chain
        bool    exists;        // guard flag
    }

    // ── Storage ───────────────────────────────────────────────
    // applicationId => list of document records
    mapping(uint256 => DocumentRecord[]) private documents;

    // CID => applicationId (reverse lookup to prevent CID reuse)
    mapping(string => uint256) private cidToAppId;

    // ── Events ────────────────────────────────────────────────
    event DocumentAnchored(
        uint256 indexed applicationId,
        string  ipfsCID,
        bytes32 sha256Hash,
        string  docType,
        uint256 timestamp
    );

    event VerificationResult(
        uint256 indexed applicationId,
        bytes32 claimedHash,
        bool    isValid,
        address verifier
    );

    // ── Write Functions (REGISTRY_ROLE only) ──────────────────

    /// @notice Anchor an IPFS CID to a specific application on-chain
    /// @param applicationId The application this document belongs to
    /// @param ipfsCID       The IPFS CID returned after upload
    /// @param sha256Hash    SHA-256 hash of the original file (bytes32)
    /// @param docType       Document category string
    function anchorDocument(
        uint256 applicationId,
        string  calldata ipfsCID,
        bytes32 sha256Hash,
        string  calldata docType
    ) external onlyRole(REGISTRY_ROLE) {
        require(bytes(ipfsCID).length > 0,   "IPFSVerifier: CID cannot be empty");
        require(sha256Hash != bytes32(0),     "IPFSVerifier: hash cannot be zero");
        require(bytes(docType).length > 0,   "IPFSVerifier: docType cannot be empty");
        require(cidToAppId[ipfsCID] == 0,    "IPFSVerifier: CID already anchored");

        documents[applicationId].push(DocumentRecord({
            ipfsCID:    ipfsCID,
            sha256Hash: sha256Hash,
            docType:    docType,
            anchoredAt: block.timestamp,
            exists:     true
        }));

        cidToAppId[ipfsCID] = applicationId;

        emit DocumentAnchored(applicationId, ipfsCID, sha256Hash, docType, block.timestamp);
    }

    // ── Read / Verify Functions ───────────────────────────────

    /// @notice Verify a document's integrity by comparing hash to stored hash
    /// @param applicationId The application to check against
    /// @param docIndex      Index of the document in the application's list
    /// @param claimedHash   SHA-256 hash of the document being verified
    /// @return isValid      True if the hash matches the stored record
    /// @return storedCID    The original IPFS CID stored on-chain
    function verifyDocument(
        uint256 applicationId,
        uint256 docIndex,
        bytes32 claimedHash
    ) external returns (bool isValid, string memory storedCID) {
        require(
            docIndex < documents[applicationId].length,
            "IPFSVerifier: document index out of bounds"
        );
        DocumentRecord memory doc = documents[applicationId][docIndex];
        isValid   = (doc.sha256Hash == claimedHash);
        storedCID = doc.ipfsCID;

        emit VerificationResult(applicationId, claimedHash, isValid, msg.sender);
    }

    /// @notice Get all document records for an application
    function getDocumentManifest(uint256 applicationId)
        external view returns (DocumentRecord[] memory)
    {
        return documents[applicationId];
    }

    /// @notice Get a specific document record
    function getDocument(uint256 applicationId, uint256 docIndex)
        external view returns (DocumentRecord memory)
    {
        require(
            docIndex < documents[applicationId].length,
            "IPFSVerifier: document index out of bounds"
        );
        return documents[applicationId][docIndex];
    }

    /// @notice Get total documents submitted for an application
    function documentCount(uint256 applicationId) external view returns (uint256) {
        return documents[applicationId].length;
    }

    /// @notice Find which application a CID belongs to (reverse lookup)
    function getAppIdByCID(string calldata cid) external view returns (uint256) {
        return cidToAppId[cid];
    }
}
