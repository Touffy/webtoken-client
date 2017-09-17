import { JWA, matchAlgKty } from './jwa'


/**
 * Attempts to find a JWK with the specified ID in a JWKs fetched from the specified URL.
 * Non-HTTPS URLs will be rejected.
 */
export function fetchJWK(kid: string, jku: string) {
	const url = new URL(jku)
	if (url.protocol !== "https:") throw new URIError("Keys should be fetched only over HTTPS.")
	return fetch(jku).then(res => res.json())
	.then(res => {
		if (!Array.isArray(res)) throw new TypeError("The specified JWKs is not an Array.")
		const key = res.find(k => k.kid === kid)
		if (!key) throw new Error(`The JWKs at ${jku} did not contain the key with kid = ${kid}.`)
		return validJsonWebKey(key)
	})
}


/**
 * Checks that an object looks like a genuine JWK with the "sig" use and a supported algorithm
 */
export function validJsonWebKey(key) {
	if (!key.kid) throw new Error("The key ID (kid) is missing from the JWK.")
	if (!key.kty) throw new Error("The key type (kty) is missing from the JWK.")
	if (!key.alg) throw new Error("The key algorithm (alg) is missing from the JWK.")
	if (!/^(?:EC|RSA|oct)$/.test(key.kty)) throw new Error(`Unsupported non-standard key type: ${key.kty}.`)
	if (!(key.alg in JWA)) throw new Error(`Unsupported key algorithm: ${key.alg}.`)
	if (!matchAlgKty(key.alg, key.kty)) throw new Error(`The key type (${key.kty}) does not match its algorithm (${key.alg}).`)
	if (!/\bsig\b/.test(key.use)) throw new Error("The key does not allow signing/verification.")
	return key as JsonWebKey
}



interface HashKeyAlgorithm extends KeyAlgorithm {
	hash: KeyAlgorithm
	namedCurve?: string
}

/**
 * Checks that a CryptoKey has acceptable properties for verifying JWT signatures
 */
export function validCryptoKey(key: CryptoKey) {
	if (!key.usages.includes("verify")) throw new Error("Cannot use this key for signature verification.")
	const keyAlg = key.algorithm as HashKeyAlgorithm
	const jwa = Object.values(JWA).find(alg => alg.name === keyAlg.name && alg.hash === keyAlg.hash.name) as HashKeyAlgorithm
	if (!jwa) throw new Error("The key uses a combination of algorithm and hash that isn't listed in JWA.")
	if (jwa.namedCurve && keyAlg.namedCurve !== jwa.namedCurve) throw new Error(`The key's elliptic curve is not the one specified in JWA for ${jwa.hash}.`)
	return key
}


/**
 * Imports a verification JWK with the Web Crypto API, saving it in a key dictionary if provided
 */
export function loadJWK(jkw: JsonWebKey, collect?: {[kid: string]: CryptoKey | Promise<CryptoKey>}) {
	const promise = crypto.subtle.importKey("jwk", jkw, JWA[jkw.alg], false, ["verify"]) as Promise<CryptoKey>
	if (collect) {
		collect[jkw.kid] = promise
		promise.then(key => collect[jkw.kid] = key).catch(err => delete collect[jkw.kid])
	}
	return promise
}
