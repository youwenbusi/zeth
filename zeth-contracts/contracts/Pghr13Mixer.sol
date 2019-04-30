pragma solidity ^0.5.0;

import "./MerkleTreeSha256.sol";
import "./Pghr13Verifier.sol";
import "./Mixer.sol";

contract Pghr13Mixer is Mixer {
    // Smart contract responsible of on-chain verification of proofs
    Pghr13Verifier public _zksnark_verifier;

    // Constructor
    constructor(address _zksnark_verify, uint depth, address token) Mixer(depth, token) public {
        _zksnark_verifier = Pghr13Verifier(_zksnark_verify);
    }

    // This function allows to mix coins and execute payments in zero knowledge
    function mix (
        string memory ciphertext1,
        string memory ciphertext2, // Nb of ciphertexts depends on the JS description (Here 2 inputs)
        uint[2] memory a,
        uint[2] memory a_p,
        uint[2][2] memory b,
        uint[2] memory b_p,
        uint[2] memory c,
        uint[2] memory c_p,
        uint[2] memory h,
        uint[2] memory k,
        uint[] memory input
    ) public payable {
        // 1. Check the root and the nullifiers
        assemble_root_and_nullifiers_and_append_to_state(input);

        // 2. Verify the proof
        require(
            _zksnark_verifier.verifyTx(a, a_p, b, b_p, c, c_p, h, k, input),
            "Invalid proof: Unable to verify the proof correctly"
        );

        // 3. Append the commitments to the tree
        assemble_commitments_and_append_to_state(input);

        // 4. get the public values in Wei and modify the state depending on their values
        process_public_values(input);

        // 5. Add the new root to the list of existing roots and emit it
        bytes32 currentRoot = getRoot();
        add_and_emit_merkle_root(currentRoot);

        // Emit the all the coins' secret data encrypted with the recipients' respective keys
        emit_ciphertexts(ciphertext1, ciphertext2);
    }
}
