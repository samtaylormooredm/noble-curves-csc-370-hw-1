# CSC 354 Homework 1

Implementation of selected cryptographic concepts from CSC 354 Applied Cryptography.

## Features

- Random byte generation and SHA-256 hashing
- Symmetric encryption
- Verifiable Random Function (VRF)
  - Generates a secp256k1 key pair
  - Generates a random seed
  - Signs `seed | i` to produce a proof
  - Hashes the proof to produce the random value
  - Verifies that the proof hashes to the expected value

## Setup

Install dependencies:

```bash
npm install
```

Run the program:

```bash
node index.mjs
```

## Dependencies

- `@noble/ciphers`
- `@noble/curves`
- `@noble/hashes`
