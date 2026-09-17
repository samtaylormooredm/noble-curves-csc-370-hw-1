import fs from 'fs'
import * as crypto from 'crypto'

export function calculateHash(filename) {
    const fileContents = fs.readFileSync(filename)

    return crypto.createHash('sha256')
        .update(fileContents)
        .digest()
}

export function timestamp(hash) {
    // TODO
}

export function verify(hash, timestamp) {
    // TODO
}