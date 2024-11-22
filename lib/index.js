
import { utils } from "ffjavascript";
import crypto from "crypto";
import { buildPoseidon, buildEddsa } from "circomlibjs";
import { groth16 } from "snarkjs";
import assert from "assert"


/**
 * @returns {bigint} Returns a random bigint
 */
export function rbigint() { return utils.leBuff2int(crypto.randomBytes(31)) };

/**
 * @returns {Buffer} - Returns a random 32 bit buffer
 */
export function rbytes() { return crypto.randomBytes(32) }

/**
* @param args {Array<bigint>} - A list of bigint to compute the hash
* @returns {bigint} Returns the poseidon hash
*/
export async function poseidon(args) {
    const hasher = await buildPoseidon();
    const hashBytes = hasher(args);
    const hash = hasher.F.toString(hashBytes);
    return BigInt(hash);
}

/**
 * @param {string} str - The string to convert to bigint
 * @returns {bigint} - Returns the string as a bigint
 */
export function stringToBigint(str) {
    const buff = Buffer.from(str, "utf8");
    return utils.leBuff2int(buff);
}

/**
 * 
 * @param {bigint} big  - The bigint to convert to string
 * @returns {string}
 */

export function bigintToString(big) {
    const uint8arr = utils.leInt2Buff(big);
    return Buffer.from(uint8arr.buffer).toString("utf8")
}

/**
 * 
 * @param messageSlots {Array<string | bigint>} - The messages signed by the witness
 * @param origin {string | bigint} - The identifier for the message origin
 * @param destination {string | bigint} - The identifier for the message destination
 * @param nullifier {string | bigint} - The nonce is used for making message hashes unique, useful for nullification
 * @returns {bigint} Returns a poseidon hash
 */
export async function computeMessageHash(messageSlots, origin, destination, nonce) {
    return await poseidon(
        [
            BigInt(messageSlots[0]),
            BigInt(messageSlots[1]),
            BigInt(messageSlots[2]),
            BigInt(messageSlots[3]),
            BigInt(origin),
            BigInt(destination),
            BigInt(nonce)
        ])
}

export async function getEDDSA() {
    return await buildEddsa();
}

export function generateAccount(eddsa) {
    const prvKey = rbytes();
    const pubKey = eddsa.prv2pub(prvKey);
    return {
        prvKey,
        pubKey
    }
}

export function importAccount(eddsa, prvKey) {
    return {
        prvKey,
        pubKey: eddsa.prv2pub(prvKey)
    }
}

export async function getAddressFromPubkey(pubKey) {
    return poseidon(pubKey);
}

/**
 * @param {any} eddsa - the built EDDSA
 * @param {bigint} messagehash - The poseidon hash of the message
 * @param {Buffer} prvKey - The private key used to sign the message 
 * @returns Signature
 */
export function signMessage(eddsa, messageHash, prvKey) {
    const signature = eddsa.signPoseidon(prvKey, eddsa.F.e(messageHash));
    const pubKey = eddsa.prv2pub(prvKey);
    assert(eddsa.verifyPoseidon(eddsa.F.e(messageHash), signature, pubKey))

    return {
        signature,
        pubKey
    }
}

/**
 * @typedef {Object} SignatureParameters
 * @property {any} Ax
 * @property {any} Ay
 * @property {any} R8x
 * @property {any} R8y
 * @property {any} S
 */


/**
 * @param eddsa
 * @param pubKey
 * @param signature
 * @returns {SignatureParameters} - The signature parameters ready to use for the circuit
 */
export function getSignatureParameters(eddsa, pubKey, signature) {
    return {
        Ax: eddsa.F.toObject(pubKey[0]),
        Ay: eddsa.F.toObject(pubKey[1]),
        R8x: eddsa.F.toObject(signature.R8[0]),
        R8y: eddsa.F.toObject(signature.R8[1]),
        S: signature.S
    }
}


/** Hashes the leaves of a merkle tree from left to right
 * @param left {bigint} - The left leaf node
 * @param right {bigint} - The right leaf node
 * @returns {bigint} - Returns the poseidon hash
 */
export async function hashLeaves(left, right) {
    return await poseidon([BigInt(left), BigInt(right)]);
}

/**
 * @param {Object} options - The arguments for the compute proof
 * @param {Array<bigint>} options.Ax - The Ax parameter from the signature
 * @param {Array<bigint>} options.Ay - The Ay parameter from the signature
 * @param {Array<bigint>} options.S - The S parameter from the signature
 * @param {Array<bigint>} options.R8x - The R8x parameter from the signature
 * @param {Array<bigint>} options.R8y - The R8y parameter from the signature
 * @param {Array<bigint> | Array<string>} options.pathElements
 * @param {Array<number>} options.pathIndices
 * @param {Array<bigint>} options.publicInputs.witnessAddresses - The address of the witness
 * @param {Object} options.publicInputs
 * @param {Array<bigint | number> } options.publicInputs.msgslots - The message slots contain the signed message 
 * @param {bigint} options.publicInputs.origin - The identifier of the message origin
 * @param {bigint} options.publicInputs.destination - The identifier of the message destination
 * @param {bigint} options.publicInputs.nonce - A random nonce to make messages unique 
 * @param {bigint | string} options.publicInputs.root - The root hash of the merkle tree

 * @param {Object | undefined} options.snarkArtifacts - Paths to the artifacts used for generating the proof. If undefined, default values will be used. It allows for file system paths and urls.
 * @param {string} options.snarkArtifacts.wasmFilePath - Path to the generated witness file
 * @param {string} options.snarkArtifacts.zkeyFilePath - Path to the generated zKey file
 */
export async function computeProof({ Ax, Ay, S, R8x, R8y, witnessAddresses, pathElements, pathIndices, publicInputs, snarkArtifacts }) {
    const input = {
        //Private inputs
        Ax, Ay, S, R8x, R8y,
        pathElements, pathIndices,
        witnessAddresses,
        //Public inputs
        ...publicInputs
    }

    if (!snarkArtifacts) {
        snarkArtifacts = {
            wasmFilePath: "circuits/compiled/circuit_js/circuit.wasm",
            zkeyFilePath: "circuits/compiled/zkeys/circuit_final.zkey",
        }
    }

    const { proof, publicSignals } = await groth16.fullProve(
        input,
        snarkArtifacts.wasmFilePath,
        snarkArtifacts.zkeyFilePath
    )

    return { proof, publicSignals }
}
/**
* Verifies a SnarkJS proof.
* @param verificationKey The zero-knowledge verification key.
* @param fullProof The SnarkJS full proof.
* @returns {boolean} True if the proof is valid, false otherwise.
*/

export function verifyProof({ verificationKey, proof, publicSignals }) {
    return groth16.verify(
        verificationKey,
        publicSignals,
        proof,
    );
}
