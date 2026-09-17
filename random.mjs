import * as crypto from 'crypto'

export function getRandomBytes(amount) {
	return crypto.randomBytes(amount)
}