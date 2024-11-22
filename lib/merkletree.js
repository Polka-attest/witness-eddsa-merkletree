
import { hashLeaves } from "./index.js";

/**
 * The TREELEVELS constant specifies the size of the tree and it's levels and merkle proof size.
 * This variable is required to be a constant by the circom circuit
 * If you adjust this variable, make sure to change the levels in the circuit
 */
const TREELEVELS = 20;

const HashDirection = {
    LEFT: 0,
    RIGHT: 1

}

/**
 * @typedef {Object} MerkleProofParams
 * @property {bigint} hash
 * @property {number} direction
 */

/**
 * @typedef {Array<MerkleProofParams>} MerkleProof 
 */

/**
 * Generate a merkle root using recursion and write the tree in to the tree argument object
 * @param {Array<bigint>} leaves - The bottom leaves of the merkle tree
 * @param {Object} tree - The whole tree is stored in this object and written per layer
 * @param {Array<Array<bigint>>} leaves.layer

 * @returns {Array<bigint>} - The merkle root, which is an array with a single element
 */
export async function generateMerkleRoot(leaves, tree) {
    if (leaves.length === 0) {
        return [];
    }
    // Duplicate the last leaf if the tree is uneven
    ensureEven(leaves);
    const combinedHashes = [];
    for (let i = 0; i < leaves.length; i += 2) {
        const newHash = await hashLeaves(leaves[i], leaves[i + 1])
        combinedHashes.push(newHash)

    }
    tree.layers.push(combinedHashes);
    // if the combined hashes length is 1 then we have the merkle root
    if (combinedHashes.length === 1) {
        return combinedHashes;
    }
    return await generateMerkleRoot(combinedHashes, tree);
}

/**
 * Computes the merkle tree using the leaves
 * @param {Array<bigint>} leaves - The merkle tree leaves

 * @returns - The merkle tree and the root
 */
export async function generateMerkleTree(leaves) {
    const tree = { layers: [leaves] }
    await generateMerkleRoot(leaves, tree);
    // Padding the tree here so we can use it in circom with a hard coded 20 level tree
    return await padTree(tree);
}



/**
 * Compute the merkle proof using a leaf and the leaves
 * @param {bigint} leaf - The leaf we compute proof for
 * @param {Array<bigint>} leaves - The leaf nodes of the merkle tree
 * @param {Array<Array<bigint>> | null} cachedTree - The cached merkle tree

 * @returns {MerkleProof | null} - Returns the valid merkle proof or returns null if the leaves are empty
 */

export async function generateMerkleProof(leaf, leaves, cachedTree) {
    if (!leaf || !leaves || leaves.length === 0) {
        return null;
    }
    const { tree } = cachedTree !== null ? { tree: cachedTree } : await generateMerkleTree(leaves);

    const merkleProof = [{
        hash: leaf,
        direction: getLeafNodeDirectionInMerkleTree(leaf, tree.layers)
    }];
    let hashIndex = tree.layers[0].findIndex(h => h === leaf);
    for (let level = 0; level < tree.layers.length - 1; level++) {
        const isLeftChild = hashIndex % 2 === 0;
        const siblingDirection = isLeftChild ? HashDirection.RIGHT : HashDirection.LEFT;
        const siblingIndex = isLeftChild ? hashIndex + 1 : hashIndex - 1;
        const siblingNode = {
            hash: tree.layers[level][siblingIndex],
            direction: siblingDirection
        };
        merkleProof.push(siblingNode);
        hashIndex = Math.floor(hashIndex / 2);
    }
    return merkleProof;
}

/**
 * Reduces the merkle proof to a root
 * @param {MerkleProof} merkleProof

 * @returns The merkle root
 */

// Reduce the merkle proof to a root by hashing the leaves and determining direction!
export async function getMerkleRootFromMerkleProof(merkleProof) {
    let accumulator = { hash: merkleProof[0].hash };
    for (let i = 1; i < merkleProof.length; i++) {
        const node = merkleProof[i];
        if (node.direction === HashDirection.RIGHT) {
            const hash = await hashLeaves(accumulator.hash, node.hash);
            accumulator = { hash }
        } else {
            const hash = await hashLeaves(node.hash, accumulator.hash);
            accumulator = { hash }
        }
    }
    return accumulator.hash;
}

/**
 * @typedef {Object} EncodedForCircuit
 * @property {Array<bigint>} pathElements
 * @property {Array<number>} pathIndices
 */


/**
 * Encode the merkle proof to a format used by the circom circuit
 * @param {MerkleProof} merkleProof
 * @returns {EncodedForCircuit}
 */

export function encodeForCircuit(merkleProof) {
    let pathElements = [];
    let pathIndices = [];
    for (let i = 0; i < merkleProof.length; i++) {
        let path = merkleProof[i];
        pathElements.push(path.hash);
        pathIndices.push(path.direction);

    }

    return { pathElements, pathIndices }
}

/**
 * Internal function, gets the leaf node's direction in the tree
 * @param {bigint} leaf 
 * @param {bigint[][]} merkleTree 
 * @returns 
 */

const getLeafNodeDirectionInMerkleTree = (leaf, merkleTree) => {
    const hashIndex = merkleTree[0].findIndex(h => h === leaf);
    return hashIndex % 2 === 0 ? HashDirection.LEFT : HashDirection.RIGHT;
};

/**
 * Pads the merkle tree as needed to fit the circuit. The padding is determined by TREELEVELS an will duplicate the last root
 * @param {Object} tree - The merkle tree
 * @param {bigint[][]} tree.layers - The layers of the tree

 * @returns - The merkle tree and the root
 */
async function padTree(tree) {
    for (let i = tree.layers.length - 1; i < TREELEVELS - 1; i++) {
        const lastRoot = tree.layers[i][0];
        tree.layers[i].push(lastRoot);
        const newRoot = await hashLeaves(lastRoot, lastRoot);
        tree.layers.push([newRoot]);
    }

    return {
        tree,
        root: tree.layers[tree.layers.length - 1][0]
    };
}

/**
 * Ensures the merkle tree layer is of even size and will duplicate the last leaf if need
 * @param {Array<bigint>} leaves 
 */
function ensureEven(leaves) {
    if (leaves.length % 2 !== 0) {
        leaves.push(leaves[leaves.length - 1]);
    }
}



export function serializeMerkleTree(tree) {
    return JSON.stringify(tree, (_, v) => typeof v === "bigint" ? v.toString() : v);
}

/**
 * @typedef {Object} TreeSecrets
 * @property {Array<BigInt>} secrets
 * @property {Array<BigInt>} nullifiers
 * @property {Array<BigInt>} commitments
 * @property {Array<Bigint>} nullifierHashes
 */

