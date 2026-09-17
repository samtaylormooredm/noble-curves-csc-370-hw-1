// Documentation in https://nodejs.org/api/crypto.htm
import * as crypto from 'crypto'

import { deriveKey } from './kdf.mjs'
import { getRandomBytes } from './random.mjs'

// Use "openssl list -cipher-algorithms" to see symmetric algorithms available

/**
 * Encrypts a plaintext message using AES-256-CBC with Node Crypto.
 *
 * @param {string} userKey - User-provided key used to derive the encryption key.
 * @param {string} message - Plaintext message to encrypt.
 * @returns {Object} The ciphertext and IV as hex strings.
 */
export function encrypt(userKey, message) {
	// Make an initialization vector of 16B
	// (256b -- same size as required by the algorithm)
	let iv = getRandomBytes(16)

	let key = deriveKey(userKey)

	// Algorithm, key, initialization vector
	const symmetricCipher = crypto.createCipheriv('aes-256-cbc', key, iv)

	// If you input strings, you have to provide input and output encodings otherwise they're optional (default to Buffer)

	// ST: ivString (initialization vector) adds randomness to our 
	// cyphertext, so we get dif values each time we run

	// Create the cypher object once, update multiple times before calling final()
	let cyphertext = symmetricCipher.update(message, 'utf8', 'hex')
	// Final returns leftover encrypted data, so make sure to use +=
	cyphertext += symmetricCipher.final('hex')

	let ivString = iv.toString('hex')
	return { cyphertext, ivString }
}

/**
 * Decrypts an AES-256-CBC encrypted package using Node Crypto.
 *
 * @param {string} userKey - User-provided key used to derive the decryption key.
 * @param {Object} encryptedPackage - Object containing the ciphertext and IV.
 * @returns {string} The decrypted plaintext message.
 */
export function decrypt(userKey, encryptedPackage) {
	let { cyphertext, ivString } = encryptedPackage

	let iv = Buffer.from(ivString, 'hex')

	let key = deriveKey(userKey)

	// Algorithm, key, initialization vector
	const symmetricDecipher = crypto.createDecipheriv('aes-256-cbc', key, iv)

	// If you input strings, you have to provide input and output encodings otherwise they're optional (default to Buffer)

	// Create the decypher object once, update multiple times before calling final()
	let plaintext = symmetricDecipher.update(cyphertext, 'hex', 'utf8')
	// Final returns leftover encrypted data, so make sure to use +=
	plaintext += symmetricDecipher.final('utf8')

	return plaintext
}

import { cbc } from '@noble/ciphers/aes.js';
import { hmac } from '@noble/hashes/hmac.js'; 	// used for our authenticated encryption funcs
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { bytesToHex, hexToBytes } from '@noble/ciphers/utils.js';

import { deriveKey2 } from './kdf.mjs';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ST

/**
 * Encrypts a plaintext message using AES-CBC with the Noble library.
 *
 * @param {string} userKey - User-provided key used to derive the encryption key.
 * @param {string} message - Plaintext message to encrypt.
 * @returns {Object} The ciphertext and IV as hex strings.
 */
export function encrypt2(userKey, message) {
	// 16-byte IV for AES-CBC
	const iv = randomBytes(16)

	// 32-byte key for AES-256
	const key = deriveKey2(userKey)

	// Convert plaintext string → bytes
	const plaintext = encoder.encode(message)

	const cyphertextBytes = cbc(key, iv).encrypt(plaintext)

	// Convert bytes → hex strings
	const cyphertext = bytesToHex(cyphertextBytes)
	const ivString = bytesToHex(iv)

	return { cyphertext, ivString }
}

// ST

/**
 * Decrypts an AES-CBC encrypted package using the Noble library.
 *
 * @param {string} userKey - User-provided key used to derive the decryption key.
 * @param {Object} encryptedPackage - Object containing the ciphertext and IV.
 * @returns {string} The decrypted plaintext message.
 */
export function decrypt2(userKey, encryptedPackage) {
	const { cyphertext, ivString } = encryptedPackage

	// Convert hex strings → bytes
	const iv = hexToBytes(ivString)
	const cyphertextBytes = hexToBytes(cyphertext)

	const key = deriveKey2(userKey) // ST: need to use same derivation func (deriveKey2, not deriveKey)

	const plaintextBytes = cbc(key, iv).decrypt(cyphertextBytes)

	// Convert bytes → plaintext string
	const plaintext = decoder.decode(plaintextBytes)

	return plaintext
}

// ST: Authenticated Encryption

// "Manual" means:
// 1) You are doing it manually
// 2) Never do anything manually

/**
 * Encrypts a message and creates an HMAC authentication tag.
 *
 * @param {string} userKey - User-provided key used to derive separate encryption and authentication keys.
 * @param {string} message - Plaintext message to encrypt.
 * @returns {Object} The ciphertext, IV, and authentication tag.
 */
export function encryptAuthenticatedManual(userKey, message) {
	// In order to make the encryption key and authentication key different,
	// derive them from the user key with different prefixes.
	const encryptionKey = deriveKey2("encryption" + userKey)
	const authenticationKey = deriveKey2("authentication" + userKey)

	const {cyphertext, ivString} = encrypt2(encryptionKey, message)

	// Hash-based MAC = keyed hash → hmac
	const authenticationTag = bytesToHex(hmac(sha256, authenticationKey, encoder.encode(cyphertext + ivString)))

	return {cyphertext, ivString, authenticationTag}

}

/**
 * Authenticates and decrypts an encrypted message.
 *
 * @param {string} userKey - User-provided key used to derive separate encryption and authentication keys.
 * @param {Object} encryptedPackage - Object containing the ciphertext, IV, and authentication tag.
 * @returns {string} The decrypted plaintext message.
 */
export function decryptAuthenticatedManual(userKey, encryptedPackage) {
	const encryptionKey = deriveKey2("encryption" + userKey)
	const authenticationKey = deriveKey2("authentication" + userKey)

	const { cyphertext, ivString, authenticationTag } = encryptedPackage

	// Recompute the authentication tag from the received ciphertext + IV
	const expectedTag = hmac(
		sha256,
		authenticationKey,
		encoder.encode(cyphertext + ivString)
	)
	
	// Convert the received hex tag back to bytes
	const receivedTag = hexToBytes(authenticationTag)

	// Check authentication before decrypting
	if (!crypto.timingSafeEqual(
		Buffer.from(expectedTag),
		Buffer.from(receivedTag)
	)) {
		throw new Error("Authentication failed")
	}

	// Authentication succeeded, so decrypt
	return decrypt2(encryptionKey, { cyphertext, ivString })
} 

/**
 * Encrypts a plaintext message using AES-GCM authenticated encryption.
 */
export function encryptAuthenticatedProper(userKey, message) {
	// AES-GCM uses a 12-byte nonce
	const nonce = getRandomBytes(12);

	// AES-256 requires a 32-byte key
	const key = deriveKey2(userKey);

	const plaintext = encoder.encode(message);

	// Explicitly specify empty additional authenticated data
	const additionalAuthenticatedData = new Uint8Array(0);

	const symmetricCipher = gcm(
		key,
		nonce,
		additionalAuthenticatedData
	);

	// Noble returns:
	// ciphertext || 16-byte authentication tag
	const ciphertext = symmetricCipher.encrypt(plaintext);

	return {
		ciphertext: bytesToHex(ciphertext),
		nonceString: bytesToHex(nonce)
	};
}

/**
 * Authenticates and decrypts an AES-GCM encrypted message.
 */
export function decryptAuthenticatedProper(userKey, encryptedPackage) {
	const {
		ciphertext,
		nonceString
	} = encryptedPackage;

	const nonce = hexToBytes(nonceString);
	const encryptedBytes = hexToBytes(ciphertext);

	const key = deriveKey2(userKey);

	const additionalAuthenticatedData = new Uint8Array(0);

	const symmetricDecipher = gcm(
		key,
		nonce,
		additionalAuthenticatedData
	);

	// decrypt() verifies the 16-byte GCM authentication tag.
	// It throws if authentication fails.
	const plaintext = symmetricDecipher.decrypt(encryptedBytes);

	return decoder.decode(plaintext);
}