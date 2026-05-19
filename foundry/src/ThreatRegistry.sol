// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ThreatRegistry
 * @author James Kabingu -- OCTIO
 * @notice On-chain threat intelligence registry for Web2 attack indicators
 * @dev Stores verified threat indicators submitted by the OCTIO monitoring layer
 */
contract ThreatRegistry {

    // Indicator types matching the OCTIO monitoring layer schema
    enum IndicatorType { PHISHING, MALWARE, SCAM, DNS_HIJACK, SUPPLY_CHAIN, BGP_ANOMALY }
    enum Severity { LOW, MEDIUM, HIGH, CRITICAL }
    enum Status { PENDING, VALIDATED, DISPUTED, REJECTED }

    struct Indicator {
        uint256 id;
        bytes32 targetHash;       // keccak256 of domain or address
        IndicatorType indicatorType;
        Severity severity;
        bytes32 evidenceHash;     // keccak256 of raw evidence stored on IPFS
        uint256 timestamp;
        address submitter;
        Status status;
        string reasoning;
    }

    // Storage
    uint256 public indicatorCount;
    mapping(uint256 => Indicator) public indicators;
    mapping(bytes32 => uint256[]) public indicatorsByTarget;
    mapping(bytes32 => bool) public flaggedTargets;
    mapping(bytes32 => Severity) public maxSeverityByTarget;

    // Access control
    address public owner;
    mapping(address => bool) public authorisedSubmitters;

    // Events
    event IndicatorSubmitted(
        uint256 indexed id,
        bytes32 indexed targetHash,
        IndicatorType indicatorType,
        Severity severity,
        address submitter
    );
    event IndicatorValidated(uint256 indexed id);
    event IndicatorRejected(uint256 indexed id);
    event TargetFlagged(bytes32 indexed targetHash, Severity severity);
    event QueryExecuted(bytes32 indexed targetHash, bool flagged, address querier);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAuthorised() {
        require(authorisedSubmitters[msg.sender] || msg.sender == owner, "Not authorised");
        _;
    }

    constructor() {
        owner = msg.sender;
        authorisedSubmitters[msg.sender] = true;
    }

    /**
     * @notice Authorise a new submitter address
     */
    function authoriseSubmitter(address submitter) external onlyOwner {
        authorisedSubmitters[submitter] = true;
    }

    /**
     * @notice Submit a new threat indicator
     * @param targetHash keccak256 hash of the target domain or address
     * @param indicatorType Type of threat indicator
     * @param severity Assessed severity level
     * @param evidenceHash keccak256 hash of evidence data stored on IPFS
     * @param reasoning Human-readable explanation from Gemma 4 analysis
     */
    function submitIndicator(
        bytes32 targetHash,
        IndicatorType indicatorType,
        Severity severity,
        bytes32 evidenceHash,
        string calldata reasoning
    ) external onlyAuthorised returns (uint256) {
        indicatorCount++;

        indicators[indicatorCount] = Indicator({
            id: indicatorCount,
            targetHash: targetHash,
            indicatorType: indicatorType,
            severity: severity,
            evidenceHash: evidenceHash,
            timestamp: block.timestamp,
            submitter: msg.sender,
            status: Status.VALIDATED,
            reasoning: reasoning
        });

        indicatorsByTarget[targetHash].push(indicatorCount);

        // Update flagged status
        flaggedTargets[targetHash] = true;

        // Update max severity
        if (uint8(severity) > uint8(maxSeverityByTarget[targetHash])) {
            maxSeverityByTarget[targetHash] = severity;
        }

        emit IndicatorSubmitted(indicatorCount, targetHash, indicatorType, severity, msg.sender);
        emit TargetFlagged(targetHash, severity);

        return indicatorCount;
    }

    /**
     * @notice Check if a target is flagged -- primary query interface for DeFi protocols
     * @param targetHash keccak256 hash of the target to check
     * @return flagged Whether the target has been flagged
     * @return severity Maximum severity level across all indicators for this target
     * @return count Number of indicators for this target
     */
    function isFlagged(bytes32 targetHash)
        external
        view
        returns (bool flagged, Severity severity, uint256 count)
    {
        return (
            flaggedTargets[targetHash],
            maxSeverityByTarget[targetHash],
            indicatorsByTarget[targetHash].length
        );
    }

    function logQuery(bytes32 targetHash) external {
        emit QueryExecuted(targetHash, flaggedTargets[targetHash], msg.sender);
    }

    /**
     * @notice Get indicator details by ID
     */
    function getIndicator(uint256 id) external view returns (Indicator memory) {
        require(id > 0 && id <= indicatorCount, "Invalid indicator ID");
        return indicators[id];
    }

    /**
     * @notice Get all indicator IDs for a target
     */
    function getIndicatorsForTarget(bytes32 targetHash)
        external
        view
        returns (uint256[] memory)
    {
        return indicatorsByTarget[targetHash];
    }

    /**
     * @notice Get total number of validated indicators
     */
    function getTotalIndicators() external view returns (uint256) {
        return indicatorCount;
    }
}
