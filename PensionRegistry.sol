// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
//  CONTRACT 6: PensionRegistry.sol
//  Deploy this LAST - it depends on all other contracts.
//  This is the MAIN contract that orchestrates everything.
//  Project: Blockchain-Based Widow Pension Administration
//  Group:   IBC07 | CSE 542 | Prof. Sanjay Chaudhary
// ============================================================

import "./RoleAccess.sol";
import "./AuditLog.sol";
import "./FundManager.sol";
import "./SchemeConfig.sol";
import "./IPFSVerifier.sol";

contract PensionRegistry is RoleAccess {

    // -- Application State Machine -----------------------------
    enum ApplicationState {
        NONE,           // 0 - Does not exist
        SUBMITTED,      // 1 - Application submitted by beneficiary
        UNDER_REVIEW,   // 2 - Official has picked up for review
        APPROVED,       // 3 - Approved by welfare dept
        REJECTED,       // 4 - Rejected with mandatory reason
        PAID,           // 5 - Pension disbursed - terminal state
        DISPUTED        // 6 - Beneficiary raised a dispute
    }

    // -- Application Struct ------------------------------------
    struct Application {
        uint256          applicationId;
        address          applicant;           // beneficiary's wallet address
        bytes32          aadhaarHash;         // SHA-256(AadhaarNo + SchemeID + Salt) - privacy preserved
        string           ipfsCID;             // IPFS CID of encrypted document bundle
        uint256          schemeId;            // which pension scheme
        ApplicationState state;               // current state
        string           rejectionReason;     // mandatory if REJECTED
        address          reviewer;            // who started the review
        address          auditor;             // who approved/rejected
        uint256          submittedAt;         // block.timestamp of submission
        uint256          decidedAt;           // block.timestamp of approval/rejection
        uint256          paidAt;              // block.timestamp of payment
    }

    // -- Storage -----------------------------------------------
    mapping(uint256 => Application) public applications;
    mapping(bytes32 => bool)        public aadhaarRegistered;   // prevents duplicate applications
    mapping(address => uint256[])   public walletApplications;  // applicant => their app IDs

    uint256 private nextApplicationId = 1;
    uint256 public  totalApplications = 0;

    // External contracts
    AuditLog      public auditLog;
    FundManager   public fundManager;
    SchemeConfig  public schemeConfig;
    IPFSVerifier  public ipfsVerifier;

    // -- Events ------------------------------------------------
    event ApplicationSubmitted(
        uint256 indexed applicationId,
        address indexed applicant,
        uint256 indexed schemeId,
        string  ipfsCID,
        uint256 timestamp
    );

    event ReviewStarted(
        uint256 indexed applicationId,
        address indexed reviewer,
        uint256 timestamp
    );

    event ApplicationApproved(
        uint256 indexed applicationId,
        address indexed auditor,
        uint256 timestamp
    );

    event ApplicationRejected(
        uint256 indexed applicationId,
        address indexed auditor,
        string  reason,
        uint256 timestamp
    );

    event PaymentTriggered(
        uint256 indexed applicationId,
        address indexed beneficiary,
        uint256 amount,
        uint256 timestamp
    );

    event DisputeRaised(
        uint256 indexed applicationId,
        address indexed applicant,
        uint256 timestamp
    );

    // -- Constructor -------------------------------------------
    /// @param auditLogAddr     Address of deployed AuditLog contract
    /// @param fundManagerAddr  Address of deployed FundManager contract
    /// @param schemeConfigAddr Address of deployed SchemeConfig contract
    /// @param ipfsVerifierAddr Address of deployed IPFSVerifier contract
    constructor(
        address auditLogAddr,
        address fundManagerAddr,
        address schemeConfigAddr,
        address ipfsVerifierAddr
    ) {
        require(auditLogAddr     != address(0), "PensionRegistry: invalid AuditLog address");
        require(fundManagerAddr  != address(0), "PensionRegistry: invalid FundManager address");
        require(schemeConfigAddr != address(0), "PensionRegistry: invalid SchemeConfig address");
        require(ipfsVerifierAddr != address(0), "PensionRegistry: invalid IPFSVerifier address");

        auditLog     = AuditLog(auditLogAddr);
        fundManager  = FundManager(payable(fundManagerAddr));
        schemeConfig = SchemeConfig(schemeConfigAddr);
        ipfsVerifier = IPFSVerifier(ipfsVerifierAddr);
    }

    // -- Modifiers ---------------------------------------------
    modifier applicationExists(uint256 appId) {
        require(
            applications[appId].state != ApplicationState.NONE,
            "PensionRegistry: application does not exist"
        );
        _;
    }

    // ---------------------------------------------------------
    //  STEP 1 - BENEFICIARY SUBMITS APPLICATION
    // ---------------------------------------------------------

    /// @notice Submit a pension application
    /// @param aadhaarHash  SHA-256 hash of (AadhaarNo + SchemeID + Salt) - computed off-chain
    /// @param ipfsCID      IPFS CID of the encrypted document bundle
    /// @param schemeId     ID of the pension scheme to apply under
    /// @return applicationId The unique ID assigned to this application
    function submitApplication(
        bytes32 aadhaarHash,
        string  calldata ipfsCID,
        uint256 schemeId
    ) external returns (uint256 applicationId) {

        // Validations
        require(aadhaarHash != bytes32(0),            "PensionRegistry: invalid Aadhaar hash");
        require(bytes(ipfsCID).length > 0,            "PensionRegistry: IPFS CID cannot be empty");
        require(schemeConfig.isSchemeActive(schemeId),"PensionRegistry: scheme is not active");
        require(
            !aadhaarRegistered[aadhaarHash],
            "PensionRegistry: Aadhaar already has an active application - duplicate prevented"
        );

        // Assign ID
        applicationId = nextApplicationId++;
        totalApplications++;

        // Record on-chain
        applications[applicationId] = Application({
            applicationId:   applicationId,
            applicant:       msg.sender,
            aadhaarHash:     aadhaarHash,
            ipfsCID:         ipfsCID,
            schemeId:        schemeId,
            state:           ApplicationState.SUBMITTED,
            rejectionReason: "",
            reviewer:        address(0),
            auditor:         address(0),
            submittedAt:     block.timestamp,
            decidedAt:       0,
            paidAt:          0
        });

        // Mark Aadhaar hash as used (duplicate prevention)
        aadhaarRegistered[aadhaarHash] = true;
        walletApplications[msg.sender].push(applicationId);

        // Emit audit log event
        auditLog.logEvent(
            applicationId,
            msg.sender,
            AuditLog.ActionType.SUBMITTED,
            string(abi.encodePacked("Application submitted. Scheme ID: ", _uint2str(schemeId), ". IPFS CID: ", ipfsCID))
        );

        emit ApplicationSubmitted(applicationId, msg.sender, schemeId, ipfsCID, block.timestamp);
    }

    // ---------------------------------------------------------
    //  STEP 2a - OFFICIAL STARTS REVIEW
    // ---------------------------------------------------------

    /// @notice Local government official begins reviewing an application
    /// @param appId The application ID to review
    function beginReview(uint256 appId)
        external
        onlyRole(REVIEWER_ROLE)
        applicationExists(appId)
    {
        Application storage app = applications[appId];
        require(
            app.state == ApplicationState.SUBMITTED,
            "PensionRegistry: application must be in SUBMITTED state"
        );

        app.state    = ApplicationState.UNDER_REVIEW;
        app.reviewer = msg.sender;

        auditLog.logEvent(
            appId,
            msg.sender,
            AuditLog.ActionType.REVIEW_STARTED,
            "Review started by government official"
        );

        emit ReviewStarted(appId, msg.sender, block.timestamp);
    }

    // ---------------------------------------------------------
    //  STEP 2b - WELFARE DEPT APPROVES APPLICATION
    // ---------------------------------------------------------

    /// @notice State welfare department approves an application
    /// @param appId The application ID to approve
    function approveApplication(uint256 appId)
        external
        onlyRole(APPROVER_ROLE)
        applicationExists(appId)
    {
        Application storage app = applications[appId];
        require(
            app.state == ApplicationState.UNDER_REVIEW ||
            app.state == ApplicationState.SUBMITTED,
            "PensionRegistry: application is not ready for approval"
        );

        app.state     = ApplicationState.APPROVED;
        app.auditor   = msg.sender;
        app.decidedAt = block.timestamp;

        auditLog.logEvent(
            appId,
            msg.sender,
            AuditLog.ActionType.APPROVED,
            "Application approved by State Welfare Department"
        );

        emit ApplicationApproved(appId, msg.sender, block.timestamp);

        // Automatically trigger payment after approval
        _triggerPayment(appId);
    }

    // ---------------------------------------------------------
    //  STEP 2c - WELFARE DEPT REJECTS APPLICATION
    // ---------------------------------------------------------

    /// @notice State welfare department rejects an application (reason is MANDATORY)
    /// @param appId  The application ID to reject
    /// @param reason A non-empty explanation for rejection - stored permanently on-chain
    function rejectApplication(
        uint256 appId,
        string calldata reason
    )
        external
        onlyRole(APPROVER_ROLE)
        applicationExists(appId)
    {
        require(bytes(reason).length > 0, "PensionRegistry: rejection reason is mandatory");

        Application storage app = applications[appId];
        require(
            app.state == ApplicationState.UNDER_REVIEW ||
            app.state == ApplicationState.SUBMITTED,
            "PensionRegistry: application is not ready for rejection"
        );

        app.state           = ApplicationState.REJECTED;
        app.auditor         = msg.sender;
        app.rejectionReason = reason;
        app.decidedAt       = block.timestamp;

        auditLog.logEvent(
            appId,
            msg.sender,
            AuditLog.ActionType.REJECTED,
            reason   // mandatory rejection reason stored immutably
        );

        emit ApplicationRejected(appId, msg.sender, reason, block.timestamp);
    }

    // ---------------------------------------------------------
    //  STEP 3 - PAYMENT (AUTO-TRIGGERED ON APPROVAL)
    // ---------------------------------------------------------

    /// @dev Internal: trigger pension payment via FundManager after approval
    function _triggerPayment(uint256 appId) internal {
        Application storage app = applications[appId];
        require(app.state == ApplicationState.APPROVED, "PensionRegistry: not approved");

        app.state  = ApplicationState.PAID;
        app.paidAt = block.timestamp;

        uint256 amount = schemeConfig.getMonthlyAmount(app.schemeId);

        fundManager.disbursePayment(appId, app.schemeId, payable(app.applicant));

        auditLog.logEvent(
            appId,
            address(this),
            AuditLog.ActionType.PAYMENT_SENT,
            string(abi.encodePacked("Pension payment of ", _uint2str(amount), " Wei disbursed to beneficiary"))
        );

        emit PaymentTriggered(appId, app.applicant, amount, block.timestamp);
    }

    // ---------------------------------------------------------
    //  DISPUTE - BENEFICIARY RAISES A DISPUTE ON REJECTION
    // ---------------------------------------------------------

    /// @notice Beneficiary can raise a dispute within 30 days of rejection
    /// @param appId The rejected application ID
    function raiseDispute(uint256 appId) external applicationExists(appId) {
        Application storage app = applications[appId];

        require(app.applicant == msg.sender,            "PensionRegistry: only applicant can raise dispute");
        require(app.state == ApplicationState.REJECTED, "PensionRegistry: can only dispute a rejection");
        require(
            block.timestamp <= app.decidedAt + 30 days,
            "PensionRegistry: dispute window of 30 days has passed"
        );

        app.state = ApplicationState.DISPUTED;

        auditLog.logEvent(
            appId,
            msg.sender,
            AuditLog.ActionType.DISPUTE_RAISED,
            "Beneficiary raised a dispute against the rejection decision"
        );

        emit DisputeRaised(appId, msg.sender, block.timestamp);
    }

    /// @notice Admin resolves a dispute - re-opens for review or keeps rejected
    /// @param appId   The disputed application
    /// @param reopen  If true, reset to SUBMITTED for fresh review
    function resolveDispute(uint256 appId, bool reopen)
        external
        onlyAdmin
        applicationExists(appId)
    {
        Application storage app = applications[appId];
        require(app.state == ApplicationState.DISPUTED, "PensionRegistry: not in disputed state");

        if (reopen) {
            app.state = ApplicationState.SUBMITTED;
            // Release the Aadhaar lock so re-review can proceed
        }
        // If reopen=false, status stays rejected (admin confirmed rejection)

        string memory disputeOutcome = reopen
            ? "Dispute resolved: application re-opened for fresh review"
            : "Dispute resolved: original rejection upheld by committee";

        auditLog.logEvent(
            appId,
            msg.sender,
            AuditLog.ActionType.DISPUTE_RESOLVED,
            disputeOutcome
        );
    }

    // ---------------------------------------------------------
    //  SLA BREACH CHECKER
    // ---------------------------------------------------------

    /// @notice Check if an application has breached the SLA processing time
    /// @param appId The application to check
    /// @return breached  True if SLA has been exceeded
    /// @return daysElapsed Number of days since submission
    function checkSLABreach(uint256 appId)
        external
        view
        applicationExists(appId)
        returns (bool breached, uint256 daysElapsed)
    {
        Application storage app = applications[appId];
        if (
            app.state == ApplicationState.SUBMITTED ||
            app.state == ApplicationState.UNDER_REVIEW
        ) {
            daysElapsed = (block.timestamp - app.submittedAt) / 1 days;
            uint256 sla = schemeConfig.getScheme(app.schemeId).maxProcessingDays;
            breached = daysElapsed > sla;
        }
    }

    // ---------------------------------------------------------
    //  VIEW FUNCTIONS
    // ---------------------------------------------------------

    /// @notice Get complete application details (public)
    function getApplication(uint256 appId)
        external
        view
        applicationExists(appId)
        returns (Application memory)
    {
        return applications[appId];
    }

    /// @notice Get application status and rejection reason in one call (beneficiary-friendly)
    function getApplicationStatus(uint256 appId)
        external
        view
        applicationExists(appId)
        returns (
            ApplicationState state,
            string memory    rejectionReason,
            address          auditor,
            uint256          decidedAt
        )
    {
        Application storage app = applications[appId];
        return (app.state, app.rejectionReason, app.auditor, app.decidedAt);
    }

    /// @notice Get all application IDs submitted by a wallet address
    function getApplicationsByWallet(address wallet)
        external
        view
        returns (uint256[] memory)
    {
        return walletApplications[wallet];
    }

    /// @notice Check if an Aadhaar hash is already registered
    function isAadhaarRegistered(bytes32 aadhaarHash) external view returns (bool) {
        return aadhaarRegistered[aadhaarHash];
    }

    // -- Utility -----------------------------------------------
    function _uint2str(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 temp = v;
        uint256 digits;
        while (temp != 0) { digits++; temp /= 10; }
        bytes memory buf = new bytes(digits);
        while (v != 0) { digits--; buf[digits] = bytes1(uint8(48 + (v % 10))); v /= 10; }
        return string(buf);
    }
}
