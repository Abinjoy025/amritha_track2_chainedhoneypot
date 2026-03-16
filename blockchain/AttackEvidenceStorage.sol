// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AttackEvidenceStorage
 * @dev Store immutable evidence of honeypot attacks on the blockchain
 * Stores the SHA256 hash and IPFS CID of attack logs
 */
contract AttackEvidenceStorage {
    
    struct Evidence {
        string ipfsCID;           // IPFS Content Identifier
        bytes32 dataHash;         // SHA256 hash of the data
        uint256 timestamp;        // When the attack was logged
        address reporter;         // Who reported this attack
        string severity;          // Attack severity (LOW, MEDIUM, HIGH)
        bool exists;              // Check if evidence exists
    }
    
    // Mapping from evidence ID to Evidence struct
    mapping(uint256 => Evidence) public evidenceStore;
    
    // Counter for evidence entries
    uint256 public evidenceCount;
    
    // Events for logging
    event EvidenceStored(
        uint256 indexed evidenceId,
        string ipfsCID,
        bytes32 dataHash,
        uint256 timestamp,
        address reporter,
        string severity
    );
    
    event EvidenceVerified(
        uint256 indexed evidenceId,
        bool isValid
    );
    
    /**
     * @dev Store new attack evidence
     * @param _ipfsCID The IPFS content identifier
     * @param _dataHash The SHA256 hash of the attack data
     * @param _severity The severity level of the attack
     */
    function storeEvidence(
        string memory _ipfsCID,
        bytes32 _dataHash,
        string memory _severity
    ) public returns (uint256) {
        evidenceCount++;
        
        evidenceStore[evidenceCount] = Evidence({
            ipfsCID: _ipfsCID,
            dataHash: _dataHash,
            timestamp: block.timestamp,
            reporter: msg.sender,
            severity: _severity,
            exists: true
        });
        
        emit EvidenceStored(
            evidenceCount,
            _ipfsCID,
            _dataHash,
            block.timestamp,
            msg.sender,
            _severity
        );
        
        return evidenceCount;
    }
    
    /**
     * @dev Verify evidence by checking if hash matches
     * @param _evidenceId The ID of the evidence to verify
     * @param _dataHash The hash to verify against
     */
    function verifyEvidence(
        uint256 _evidenceId,
        bytes32 _dataHash
    ) public returns (bool) {
        require(evidenceStore[_evidenceId].exists, "Evidence does not exist");
        
        bool isValid = (evidenceStore[_evidenceId].dataHash == _dataHash);
        
        emit EvidenceVerified(_evidenceId, isValid);
        
        return isValid;
    }
    
    /**
     * @dev Get evidence details
     * @param _evidenceId The ID of the evidence
     */
    function getEvidence(uint256 _evidenceId) public view returns (
        string memory ipfsCID,
        bytes32 dataHash,
        uint256 timestamp,
        address reporter,
        string memory severity
    ) {
        require(evidenceStore[_evidenceId].exists, "Evidence does not exist");
        
        Evidence memory evidence = evidenceStore[_evidenceId];
        
        return (
            evidence.ipfsCID,
            evidence.dataHash,
            evidence.timestamp,
            evidence.reporter,
            evidence.severity
        );
    }
    
    /**
     * @dev Get total number of stored evidences
     */
    function getTotalEvidence() public view returns (uint256) {
        return evidenceCount;
    }
}
