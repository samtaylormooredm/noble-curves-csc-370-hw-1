import { secp256k1 } from '@noble/curves/secp256k1.js'
import { getRandomBytes } from './random.mjs'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'


let privateKey
let publicKey
let seed


/**
 * Initializes the verifiable random function.
 *
 * Generates a secp256k1 public-private key pair and a random 32-byte seed.
 * The private key is stored within the module and is not returned.
 *
 * @returns {{seed: Uint8Array, pub: Uint8Array}}
 *   The random seed and public key.
 */

export function initializeVRF() {
    const keyPair = secp256k1.keygen()

    privateKey = keyPair.secretKey
    publicKey = keyPair.publicKey

    // Use a 32-byte random seed for the lottery
    seed = getRandomBytes(32)

    return {
        seed,
        pub: publicKey
    }
}

/**
 * Generates a verifiable random value for the given index.
 *
 * Concatenates the seed with the index, signs the resulting message with
 * the private key to produce the proof pi, and hashes the proof to produce ri.
 *
 * @param {number} i
 *   The index used to generate the random value.
 * @returns {{ri: Uint8Array, pi: Uint8Array}}
 *   The random value ri and its associated proof pi.
 */
export function generate(i) {
    const iBytes = new TextEncoder().encode(i.toString())

    const message = new Uint8Array(seed.length + iBytes.length)

    // Store the seed first, followed immediately by the encoded index
    message.set(seed, 0)
    message.set(iBytes, seed.length)

    const pi = secp256k1.sign(message, privateKey)
    const ri = sha256(pi)

    // console.log("Proof:", pi)
    // console.log("Random number:", ri)

    return {
        ri,
        pi
    }
}


/**
 * Verifies a generated random value and its proof.
 *
 * Checks that the supplied random value is the SHA-256 hash of the proof,
 * and that the proof is a valid signature on the seed concatenated with
 * the given index.
 *
 * @param {Uint8Array} ri
 *   The random value to verify.
 * @param {Uint8Array} pi
 *   The proof associated with the random value.
 * @param {number} i
 *   The index associated with the generated value.
 * @returns {boolean}
 *   True if both the hash and signature verification succeed.
 */
export function verify(ri, pi, i) {
    const calculatedRi = sha256(pi)

    // Check that ri is the hash of the supplied proof.
    const validHash =
        bytesToHex(calculatedRi) === bytesToHex(ri)

    // Reconstruct s | i.
    const iBytes = new TextEncoder().encode(i.toString())
    const message = new Uint8Array(seed.length + iBytes.length)

    message.set(seed, 0)
    message.set(iBytes, seed.length)

    // Check that pi is actually a valid signature on s | i.
    const validSignature = secp256k1.verify(pi, message, publicKey)

    return validHash && validSignature
}