
import assert from "assert";
import { signMessage, computeProof, verifyProof, rbigint, getEDDSA, generateAccount, getAddressFromPubkey, getSignatureParameters, stringToBigint, poseidon, computeMessageHash } from "../lib/index";
import fs from "fs";
import { encodeForCircuit, generateMerkleProof, generateMerkleTree, getMerkleRootFromMerkleProof } from "../lib/merkletree";

it("should sign bulk messages and make a merkle tree, verify a proof and test the circuit", async function () {
    const eddsa = await getEDDSA();

    const nonce = rbigint();
    const msgslots = [stringToBigint("mint"), 123121212, stringToBigint("toAddress"), stringToBigint("extraParameter")]

    const origin = await poseidon([stringToBigint("origin")])
    const destination = await poseidon([stringToBigint("destination")])

    const messageHash = await computeMessageHash(msgslots, origin, destination, nonce);


    let accounts = [];
    let witnessAddresses = [];
    let Ax = [];
    let Ay = [];
    let S = [];
    let R8x = [];
    let R8y = [];


    for (let i = 0; i < 10; i++) {
        const account = generateAccount(eddsa);
        const witnessAddr = await getAddressFromPubkey(account.pubKey);
        const signedMessage = signMessage(eddsa, messageHash, account.prvKey);
        const sigPar = getSignatureParameters(eddsa, account.pubKey, signedMessage.signature);


        accounts.push(account);
        witnessAddresses.push(witnessAddr)

        Ax.push(sigPar.Ax);
        Ay.push(sigPar.Ay);
        S.push(sigPar.S);
        R8x.push(sigPar.R8x);
        R8y.push(sigPar.R8y);


    }

    const merkleTree = await generateMerkleTree(witnessAddresses)


    let pathElements = [];
    let pathIndices = [];
    for (let i = 0; i < 10; i++) {
        const merkleProof = await generateMerkleProof(witnessAddresses[i], structuredClone(witnessAddresses), merkleTree.tree)
        const encodedProof = encodeForCircuit(merkleProof);
        pathElements.push(encodedProof.pathElements)
        pathIndices.push(encodedProof.pathIndices);
    }

    const zkeyPath = fs.readFileSync("circuits/compiled/vk_meta.txt", "utf-8")
    const { proof, publicSignals } = await computeProof({
        Ax, Ay, S, R8x, R8y,
        pathElements,
        pathIndices,
        witnessAddresses,
        publicInputs: {
            root: merkleTree.root,
            msgslots,
            origin,
            destination,
            nonce

        },
        snarkArtifacts: {
            wasmFilePath: "circuits/compiled/circuit_js/circuit.wasm",
            zkeyFilePath: zkeyPath,
        }
    });

    const verificationKeyFile = fs.readFileSync("circuits/compiled/verification_key.json", "utf-8");
    const verificationKey = JSON.parse(verificationKeyFile);
    const result = await verifyProof({ verificationKey, proof, publicSignals })
    assert.equal(result, true)

    //Write the tested proof, publicSignals and verificationKey to a file. This will be used for generating tests for the cosmwasm verifier contracts.
    fs.writeFileSync("./circuits/compiled/test_proof.json", JSON.stringify({ proof, publicSignals, verificationKey }))

}, 50000)


it("verification should fail because witness addresses  are not distinct", async function () {
    const eddsa = await getEDDSA();

    const nonce = rbigint();
    const msgslots = [stringToBigint("mint"), 123121212, stringToBigint("toAddress"), stringToBigint("extraParameter")]

    const origin = await poseidon([stringToBigint("origin")])
    const destination = await poseidon([stringToBigint("destination")])

    const messageHash = await computeMessageHash(msgslots, origin, destination, nonce);


    let accounts = [];
    let witnessAddresses = [];
    let Ax = [];
    let Ay = [];
    let S = [];
    let R8x = [];
    let R8y = [];


    for (let i = 0; i < 10; i++) {
        const account = generateAccount(eddsa);
        const witnessAddr = await getAddressFromPubkey(account.pubKey);
        const signedMessage = signMessage(eddsa, messageHash, account.prvKey);
        const sigPar = getSignatureParameters(eddsa, account.pubKey, signedMessage.signature);


        accounts.push(account);
        witnessAddresses.push(witnessAddr)

        Ax.push(sigPar.Ax);
        Ay.push(sigPar.Ay);
        S.push(sigPar.S);
        R8x.push(sigPar.R8x);
        R8y.push(sigPar.R8y);

    }

    //I PUT THE ERROR HERE, THE LAST ACCOUNT IS CHANGED AND THE FIRST ONE IS DUPLICATED
    accounts[9] = accounts[0];
    witnessAddresses[9] = witnessAddresses[0];
    Ax[9] = Ax[0];
    Ay[9] = Ay[0];
    S[9] = S[0];
    R8x[9] = R8x[0];
    R8y[9] = R8y[0];


    const merkleTree = await generateMerkleTree(witnessAddresses)


    let pathElements = [];
    let pathIndices = [];
    for (let i = 0; i < 10; i++) {
        const merkleProof = await generateMerkleProof(witnessAddresses[i], structuredClone(witnessAddresses), merkleTree.tree)
        const encodedProof = encodeForCircuit(merkleProof);
        pathElements.push(encodedProof.pathElements)
        pathIndices.push(encodedProof.pathIndices);
    }

    const zkeyPath = fs.readFileSync("circuits/compiled/vk_meta.txt", "utf-8");
    let errorOccured = false;
    let errorMessage = "";
    try {
        const { proof, publicSignals } = await computeProof({
            Ax, Ay, S, R8x, R8y,
            pathElements,
            pathIndices,
            witnessAddresses,
            publicInputs: {
                root: merkleTree.root,
                msgslots,
                origin,
                destination,
                nonce

            },
            snarkArtifacts: {
                wasmFilePath: "circuits/compiled/circuit_js/circuit.wasm",
                zkeyFilePath: zkeyPath,
            }
        });
    } catch (err) {
        console.log(err);
        errorMessage = err.message;
    }

    assert.equal(errorOccured, true);
    assert.equal(errorMessage.includes("Error: Assert Failed. Error in template AssertDistinct"), true);
}, 50000)
