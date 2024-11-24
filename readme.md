# Polka attest EDDSA signature aggregation

This circom project verifies bulk EdDSA signatures, checks for public keys in a merkle tree, verifies the public keys are distinct.

## Assertations
The signed message must be `hash(msgslots[0],msgslots[1],msgslots[2],msgslots[3],origin,destination,nonce);

All signatures must be signing the same message and must be valid.

There are 10 confirmations. That means 10 signatures must sign the message for the proof to be valid.

The signatures must have distinct public keys. The same key can't sign a message twice.

A witnessAddresses must match the public keys in the signature parameters, calculated as poseidonhash(Ax,Ay);

The merkle tree is fixed size, 20 levels. Every public key must be inside the merkle tree.


## Message
| Field      | MaxSize      | Description |
| ------------- | ------------- | ------------- |
| msgSlot 0 | 20 bytes | The first message slot for arbitrary data |
| msgSlot 1 | 20 bytes | The second message slot for arbitrary data |
| msgSlot 2 | 20 bytes | The third message slot for arbitrary data |
| msgSlot 3 | 20 bytes | The fourth message slot for arbitrary data |
| origin | 20 bytes | The identifier of the origin, poseidon hash |
| destination | 20 bytes | The identifier of the destination, poseidon hash |
| nonce | 20 bytes | Random nonce, unique for each message |

