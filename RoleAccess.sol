// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
//  CONTRACT 1: RoleAccess.sol
//  Deploy this FIRST — all other contracts depend on it.
//  Project: Blockchain-Based Widow Pension Administration
//  Group:   IBC07 | CSE 542 | Prof. Sanjay Chaudhary
// ============================================================

contract RoleAccess {

    // ── Role Identifiers ──────────────────────────────────────
    bytes32 public constant DEFAULT_ADMIN_ROLE  = keccak256("DEFAULT_ADMIN_ROLE");
    bytes32 public constant REVIEWER_ROLE       = keccak256("REVIEWER_ROLE");
    bytes32 public constant APPROVER_ROLE       = keccak256("APPROVER_ROLE");
    bytes32 public constant TREASURY_ROLE       = keccak256("TREASURY_ROLE");
    bytes32 public constant AUDITOR_ROLE        = keccak256("AUDITOR_ROLE");
    bytes32 public constant LOGGER_ROLE         = keccak256("LOGGER_ROLE");
    bytes32 public constant REGISTRY_ROLE       = keccak256("REGISTRY_ROLE");

    // ── Storage ───────────────────────────────────────────────
    // role => account => hasRole
    mapping(bytes32 => mapping(address => bool)) private _roles;

    // ── Events ────────────────────────────────────────────────
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    // ── Constructor ───────────────────────────────────────────
    constructor() {
        // Deployer gets admin role automatically
        _roles[DEFAULT_ADMIN_ROLE][msg.sender] = true;
        emit RoleGranted(DEFAULT_ADMIN_ROLE, msg.sender, msg.sender);
    }

    // ── Modifiers ─────────────────────────────────────────────
    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "RoleAccess: caller does not have required role");
        _;
    }

    modifier onlyAdmin() {
        require(_roles[DEFAULT_ADMIN_ROLE][msg.sender], "RoleAccess: caller is not admin");
        _;
    }

    // ── External Functions ────────────────────────────────────

    /// @notice Check if an account has a specific role
    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    /// @notice Grant a role to an account (admin only)
    function grantRole(bytes32 role, address account) external onlyAdmin {
        require(account != address(0), "RoleAccess: cannot grant role to zero address");
        require(!_roles[role][account], "RoleAccess: account already has this role");
        _roles[role][account] = true;
        emit RoleGranted(role, account, msg.sender);
    }

    /// @notice Revoke a role from an account (admin only)
    function revokeRole(bytes32 role, address account) external onlyAdmin {
        require(_roles[role][account], "RoleAccess: account does not have this role");
        _roles[role][account] = false;
        emit RoleRevoked(role, account, msg.sender);
    }

    /// @notice An account can voluntarily renounce their own role
    function renounceRole(bytes32 role) external {
        require(_roles[role][msg.sender], "RoleAccess: caller does not have this role");
        _roles[role][msg.sender] = false;
        emit RoleRevoked(role, msg.sender, msg.sender);
    }

    /// @notice Convenience: grant multiple roles to one account (admin only)
    function grantMultipleRoles(bytes32[] calldata roles, address account) external onlyAdmin {
        for (uint256 i = 0; i < roles.length; i++) {
            if (!_roles[roles[i]][account]) {
                _roles[roles[i]][account] = true;
                emit RoleGranted(roles[i], account, msg.sender);
            }
        }
    }
}
