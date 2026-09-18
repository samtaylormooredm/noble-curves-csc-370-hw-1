// 9/18/26
// See "Elliptic Curves, ECDH, and ECIES" Worksheet from 9/16/26

import { x25519 } from "@noble/curves/ed25519.js"


// Making private keys for Alice and Bob

// my private key will somehow be combined with a public key

// Have our noble curve, need to pick one of the points for the
// Generator --> the Generator will be well known (see section 4.1 of Elliptic Curves handout)
export function demoDiffieHellman() {
    const privateAlice = x25519.utils.randomSecretKey() // generate a random 32-byte X25519 private key
    const publicAlice = x25519.getPublicKey(privateAlice)// get the public key from the private key

    const privateBob = x25519.utils.randomSecretKey()
    const publicBob = x25519.getPublicKey(privateBob)

    // get shared secret key by using private key of Alice and public key of Bob
        // (a * B)
    const keyAtAlice = x25519.getSharedSecret(privateAlice, publicBob)
    // Reverse order for Bobs:
        // (A * b)
    const keyAtBob = x25519.getSharedSecret(privateBob, publicAlice)

    // JavaScript supports functional programming, so we can pass a function into .every()
    if (keyAtAlice.every((val, pos) => keyAtBob[pos] == val)) {
        console.log("The keys match")
    }
    else {
        console.log("The keys do not match")
    }
}
