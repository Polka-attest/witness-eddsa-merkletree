pragma circom 2.0.0;
include "./merkletree.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";



// Aggregate signatures and verify the signers public key are is in the merkle root
//The template has the same parameters as the VerifySignature, but the confirmations are  the amount of witnesses that need to confirm a valid stuff
template AggregateCheckWitnessSignatures(levels,confirmations){
    //Public
    signal input msgslots[4];

    signal input origin;

    signal input destination;

    signal input nonce;

    signal input root;
    // Private

    //This needs to be private because there won't be enough space in calldata for all the addresses
    signal input witnessAddresses[confirmations];

    signal input Ax[confirmations];
    signal input Ay[confirmations];
    signal input S[confirmations];
    signal input R8x[confirmations];
    signal input R8y[confirmations];


    //Merkle proofs for each witness confirmation, to verify the witnessAddress is in the merkle tree
    signal input pathElements[confirmations][levels]; // The merkle proof which is fixed size, pathElements contains the hashes
    signal input pathIndices[confirmations][levels]; // Indices encode if we hash left or right
    
    component messageHasher = Poseidon(7);
    
    messageHasher.inputs[0] <== msgslots[0];
    messageHasher.inputs[1] <== msgslots[1];
    messageHasher.inputs[2] <== msgslots[2];
    messageHasher.inputs[3] <== msgslots[3];

    messageHasher.inputs[4] <== origin;
    messageHasher.inputs[5] <== destination;
    messageHasher.inputs[6] <== nonce;


    component witnessAddrPoseidon[confirmations];
    component tree[confirmations];
    component eddsa[confirmations];

    // Inside the forloop check if the valid signature's address is in the merkle tree
    for(var i = 0; i < confirmations; i++){
        // Check if the Ax and Ay mathches the witness address
        witnessAddrPoseidon[i] = Poseidon(2);
        witnessAddrPoseidon[i].inputs[0] <== Ax[i];
        witnessAddrPoseidon[i].inputs[1] <== Ay[i];

        witnessAddresses[i] === witnessAddrPoseidon[i].out;

        // Check if the witnessAddress is in the merkle tree
        tree[i] = MerkleTreeChecker(levels);
        tree[i].leaf <== witnessAddresses[i];
        tree[i].root <== root;

        for (var j =0; j < levels; j++){
            tree[i].pathElements[j] <== pathElements[i][j];
            tree[i].pathIndices[j] <== pathIndices[i][j];
        }

         eddsa[i] = EdDSAPoseidonVerifier();
         eddsa[i].enabled <== 1;
         eddsa[i].Ax <== Ax[i];
         eddsa[i].Ay <== Ay[i];
         eddsa[i].S <== S[i];
         eddsa[i].R8x <== R8x[i];
         eddsa[i].R8y <== R8y[i];
         eddsa[i].M <== messageHasher.out;


    }
}

component main {public [msgslots,origin,destination,nonce,root]} = AggregateCheckWitnessSignatures(20,10);
