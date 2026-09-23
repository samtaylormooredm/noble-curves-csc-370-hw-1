// Documentation in https://nodejs.org/api/crypto.htm
// ST: To run, in terminal: node index.mjs

import * as crypto from 'crypto'
import { encrypt, encrypt2, decrypt, decrypt2 } from './symmetric.mjs'
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { initializeVRF, generate, verify } from './vrf.mjs'
import {
    calculateHash,
    timestamp,
    verify as verifyTimestamp
} from './timestamp.mjs'


// Generates random bytes
function testRandom() {
    // ST: 32 bytes = 256 bits
    // When displayed in hex, each byte is represented by 2 hex characters,
    // so 32 random bytes are shown as 64 hex characters.

    let random = crypto.randomBytes(32)

    console.log("Random numbers:", random.toString('hex'))
}


// Hashes
function testHashing() {
    let message = "I'm going to the Taylor Swift show"

    const hasher = crypto.createHash('sha256')
        .update(message)
        .digest()

    const hashed = hasher.toString('hex')

    console.log("Hashed message:", hashed)
}


// Symmetric encryption
function testSymmetric() {
    let key = "TaylorSwift"

    let encrypted = encrypt(key, "And I'm going to buy a T-shirt")
    console.log("Encrypted message:", encrypted)

    let decrypted = decrypt(key, encrypted)
    console.log("Decrypted message:", decrypted)
}

function testSymmetric2() {
    let key = "TaylorSwift"

    let encrypted = encrypt2(key, "And I'm going to buy a T-shirt")
    console.log("Encrypted message:", encrypted)

    let decrypted = decrypt2(key, encrypted)
    console.log("Decrypted message:", decrypted)
}

function testSymmetricAuthenticated() {
    let key = "TaylorSwift"

    let encrypted = encrypt2(key, "And I'm going to buy a T-shirt")
    console.log("Encrypted message:", encrypted)

    let decrypted = decrypt2(key, encrypted)
    console.log("Decrypted message:", decrypted)
}


// Verifiable Random Function
function testVRF() {
    const vrf = initializeVRF()
    const i = 1
    const result = generate(i)

    console.log("VRF setup:", vrf)
    console.log("Proof:", result.pi)
    console.log("Random number:", result.ri)

    console.log("Verified:", verify(result.ri, result.pi, i))
    console.log("Verified with wrong i:", verify(result.ri, result.pi, 2))
}

function testTimestamp() {
    const hash = calculateHash('test.txt')
    const result = timestamp(hash)

    console.log("Timestamp:", result)
    console.log("Timestamp verified:", verifyTimestamp(hash, result))

    const wrongHash = crypto.createHash('sha256')
        .update("different contents")
        .digest()

    console.log(
        "Timestamp verified with wrong hash:",
        verifyTimestamp(wrongHash, result)
    )
}

// Run tests

testRandom()
testHashing()
testSymmetric()
testSymmetric2()
testSymmetricAuthenticated()
testVRF()
testTimestamp()
