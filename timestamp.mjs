import fs from 'fs'
import * as crypto from 'crypto'

/**
 * Calculates the SHA-256 hash of a file.
 *
 * @param {string} filename
 *   The path to the file to hash.
 * @returns {Buffer}
 *   The SHA-256 hash of the file contents.
 */
export function calculateHash(filename) {
    const fileContents = fs.readFileSync(filename)

    return crypto.createHash('sha256')
        .update(fileContents)
        .digest()
}

/**
 * Creates a signed timestamp for a document hash.
 *
 * Combines the document hash with the current time, hashes the result to
 * produce Tpre, then signs Tpre concatenated with the time using the
 * timestamp authority's private key.
 *
 * @param {Buffer} hash
 *   The SHA-256 hash of the document.
 * @returns {{tPre: Buffer, time: string, signature: Buffer}}
 *   The timestamp data containing Tpre, the time, and the signature.
 */
export function timestamp(hash) {
    const time = new Date().toISOString()

    const tPre = crypto.createHash('sha256')
        .update(hash)
        .update(time)
        .digest()

    const message = Buffer.concat([
        tPre,
        Buffer.from(time)
    ])

    const privateKey = {
        key: fs.readFileSync('timestamp_authority_private.pem'),

        // Set TIMESTAMP_KEY_PASSPHRASE manually in the terminal before running.
        passphrase: process.env.TIMESTAMP_KEY_PASSPHRASE
    }

    const signature = crypto.sign(
        'sha256',
        message,
        privateKey
    )

    return {
        tPre,
        time,
        signature
    }
}

/**
 * Verifies a signed timestamp for a document hash.
 *
 * Recomputes Tpre from the provided hash and timestamp, checks that it
 * matches the stored Tpre value, and verifies the signature using the
 * timestamp authority's certificate.
 *
 * @param {Buffer} hash
 *   The SHA-256 hash of the document being verified.
 * @param {{tPre: Buffer, time: string, signature: Buffer}} timestamp
 *   The timestamp data to verify.
 * @returns {boolean}
 *   True if both Tpre and the signature are valid; otherwise, false.
 */
export function verify(hash, timestamp) {
    const calculatedTPre = crypto.createHash('sha256')
        .update(hash)
        .update(timestamp.time)
        .digest()

    if (!calculatedTPre.equals(timestamp.tPre)) {
        return false
    }

    const message = Buffer.concat([
        timestamp.tPre,
        Buffer.from(timestamp.time)
    ])

    const certificate = fs.readFileSync(
        'timestamp_authority_certificate.pem'
    )

    const publicKey = crypto.createPublicKey(certificate)

    return crypto.verify(
        'sha256',
        message,
        publicKey,
        timestamp.signature
    )
}