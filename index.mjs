// Documentation in https://nodejs.org/api/crypto.htm

// ST: To run, in terminal: node index.mjs
import * as crypto from 'crypto'

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';

// Generates random bytes

// ST: 32 bytes = 256 bits
// When displayed in hex, each byte is represented by 2 hex characters,
// so 32 random bytes are shown as 64 hex characters.
function testRandom() {
	// ** ST: Random number changes every time, hashed message remains the same
	let random = crypto.randomBytes(32)

	console.log("Random numbers:", random.toString('hex'))
}

function testRandom2() {
}

testRandom()
// testRandom2()

// Hashes

function testHashing() {
	// ST: this message gets converted into a hash.
	// Hashing is one-way, so we cannot directly reverse the hash to recover the original message.

	// Hashing creates a one-way fingerprint of a message.
	// Used to represent/verify data, not to recover the original message.
	let message = "I'm going to the Taylor Swift show"

	// Choose the algorithm
	// Use "openssl list -digest-algorithms" to see hash algorithms available
	// sha256, blake2s256 are most common

	// Create the hash once, update multiple times before calling digest()
	const hasher = crypto.createHash('sha256')
		.update(message)
		.digest()

	const hashed = hasher.toString('hex')

	console.log("Hashed message:", hashed)
}

function testHashing2() {
}

testHashing()
// testHashing2()

// Symmetric encryption

// ST: ivString (initialization vector) adds randomness to our 
// cyphertext, so we get dif values each time we run
import { encrypt, encrypt2, decrypt, decrypt2} from './symmetric.mjs'

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

testSymmetric()
testSymmetric2()
testSymmetricAuthenticated()

// Next chapters: asymetric cryptography, Diffie-Hellman


import { initializeVRF } from './vrf.mjs'

const vrf1 = initializeVRF()
const vrf2 = initializeVRF()

console.log(vrf1)
console.log(vrf2)