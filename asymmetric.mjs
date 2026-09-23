// 9/23/26 
// See notes on ipad for how this plays out

// ECDSA - Digital Signatures

import { ed25519 } from "@noble/curves/ed25519";

export function demoSignature(message) {
    const privateKey = ed25519.utils.randomSecretKey()
    const publicKey = ed25519.getPublicKey(privateKey)

    // encodedMessage = original message
    const encodedMessage = new TextEncoder().encode(message)

    const signature = ed25519.sign(encodedMessage, privateKey) // Alice signing from notes

    console.log("Signature: ", signature.toString())

    const checked = ed25519.verify(signature, encodedMessage, publicKey)

    console.log("Signature checked? ", checked)
}