import { secp256k1 } from '@noble/curves/secp256k1.js'

import { getRandomBytes } from './random.mjs'

import { sha256 } from '@noble/hashes/sha2.js'


let privateKey
let publicKey
let seed


// TODO: returns a JavaScript object containing the random seed and public
// key pub. The private key pri is kept unexported within the module.
export function initializeVRF() {
    const keyPair = secp256k1.keygen()

    privateKey = keyPair.secretKey
    publicKey = keyPair.publicKey

    seed = getRandomBytes(32)

    return {
        seed,
        pub: publicKey
    }
}

// TODO: receives a parameter i and returns r_i and π_i as defined above
export function generate(i) {
    const iBytes = new TextEncoder().encode(i.toString())

    const message = new Uint8Array(seed.length + iBytes.length)

    message.set(seed, 0)
    message.set(iBytes, seed.length)

    const pi = secp256k1.sign(message, privateKey)  // 64-byte secp256k1 signature
    const ri = sha256(pi)

    console.log("Proof:", pi)
    console.log("Random number:", ri)
}

// TOOD: returns true only if the verification passes as described above.
export function verify(ri, pi) {

}