// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AttackEvidenceStorage  (v2 – Honeyport Phase 4)
 * @notice Stores immutable forensic records for every captured attacker.
 *
 * Each record contains:
 *   attackerIP   – source IP that was funnelled into the honeypot
 *   timestamp    – Unix epoch of the attack session (set by the contract)
 *   osintScore   – AbuseIPDB / Shodan combined threat score (0–100)
 *   attackType   – XGBoost classification label ("BruteForce", "DDoS", …)
 *   ipfsCID      – IPFS CID of the zip file (Zeek logs + PCAPs + malware)
 *   reporter     – Ethereum address that submitted the transaction
 *
 * Deployed on Sepolia testnet.  Use scripts/deploy.js (Hardhat) or Remix IDE.
 */
contract AttackEvidenceStorage {

    // ── Data structures ───────────────────────────────────────────────────────

    struct AttackRecord {
        string  attackerIP;
        uint256 capturedAt;    // block.timestamp
        uint8   osintScore;    // 0–100
        string  attackType;
        string  ipfsCID;
        address reporter;
        bool    exists;
    }

    mapping(uint256 => AttackRecord) public records;
    uint256 public recordCount;

    // Per-IP history  (quick lookup for repeated attackers)
    mapping(string => uint256[]) private _ipToRecordIds;

    // ── Events ────────────────────────────────────────────────────────────────

    event RecordStored(
        uint256 indexed recordId,
        string  indexed attackerIP,
        uint256 capturedAt,
        uint8   osintScore,
        string  attackType,
        string  ipfsCID,
        address reporter
    );

    // ── Write ─────────────────────────────────────────────────────────────────

    /**
     * @notice Store a new attack forensic record.
     * @param _attackerIP  The attacker's IP address string.
     * @param _osintScore  Threat score from AbuseIPDB/Shodan (0–100).
     * @param _attackType  XGBoost classification result.
     * @param _ipfsCID     IPFS content identifier of the forensic bundle.
     * @return recordId    Sequential ID of this record (starts at 1).
     */
    function storeRecord(
        string  calldata _attackerIP,
        uint8            _osintScore,
        string  calldata _attackType,
        string  calldata _ipfsCID
    ) external returns (uint256 recordId) {
        recordCount++;
        recordId = recordCount;

        records[recordId] = AttackRecord({
            attackerIP: _attackerIP,
            capturedAt: block.timestamp,
            osintScore: _osintScore,
            attackType: _attackType,
            ipfsCID:    _ipfsCID,
            reporter:   msg.sender,
            exists:     true
        });

        _ipToRecordIds[_attackerIP].push(recordId);

        emit RecordStored(
            recordId,
            _attackerIP,
            block.timestamp,
            _osintScore,
            _attackType,
            _ipfsCID,
            msg.sender
        );
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    /**
     * @notice Retrieve a full forensic record by ID.
     */
    function getRecord(uint256 _id) external view returns (
        string  memory attackerIP,
        uint256 capturedAt,
        uint8   osintScore,
        string  memory attackType,
        string  memory ipfsCID,
        address reporter
    ) {
        require(records[_id].exists, "Record not found");
        AttackRecord storage r = records[_id];
        return (r.attackerIP, r.capturedAt, r.osintScore, r.attackType, r.ipfsCID, r.reporter);
    }

    /**
     * @notice Return all record IDs for a specific attacker IP.
     */
    function getRecordsByIP(string calldata _ip) external view
        returns (uint256[] memory)
    {
        return _ipToRecordIds[_ip];
    }

    /**
     * @notice Return the latest N record IDs (descending).
     */
    function getLatestRecords(uint256 _n) external view returns (uint256[] memory) {
        uint256 total = recordCount;
        uint256 count = _n > total ? total : _n;
        uint256[] memory ids = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            ids[i] = total - i;
        }
        return ids;
    }
}
