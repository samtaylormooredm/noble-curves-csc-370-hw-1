import { secp256k1 } from '@noble/curves/secp256k1.js'

import { getRandomBytes } from './random.mjs'


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

}

// TOOD: returns true only if the verification passes as described above.
export function verify(ri, pi) {

}