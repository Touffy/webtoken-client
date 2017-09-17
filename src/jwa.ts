// correspondence between JWA name ("alg" in JOSE header and JWK) and Web Crypto algorithm
export const JWA = {
	HS256: {name: "HMAC", hash: "SHA-256"},
	HS384: {name: "HMAC", hash: "SHA-384"},
	HS512: {name: "HMAC", hash: "SHA-512"},

	RS256: {name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"},
	RS384: {name: "RSASSA-PKCS1-v1_5", hash: "SHA-384"},
	RS512: {name: "RSASSA-PKCS1-v1_5", hash: "SHA-512"},

	ES256: {name: "ECDSA", namedCurve: "P-256", hash: "SHA-256"},
	ES384: {name: "ECDSA", namedCurve: "P-384", hash: "SHA-384"},
	ES512: {name: "ECDSA", namedCurve: "P-521", hash: "SHA-512"},

	PS256: {name: "RSA-PSS", saltLength: 128, hash: "SHA-256"},
	PS384: {name: "RSA-PSS", saltLength: 384, hash: "SHA-384"},
	PS512: {name: "RSA-PSS", saltLength: 512, hash: "SHA-512"}
}


/**
 * Check that the key is the right type for its algorithm
 */
export function matchAlgKty(alg: string, kty: string) {
	switch (alg[0]) {
		case 'H': return kty === "oct"
		case 'R': case 'P': return kty === "RSA"
		case 'E': return kty === "EC"
	}
}

/**
 * Returns the Set of the algorithms supported by the browser
 */
export function supported() {
	const tests = Object.keys(JWA).map(alg =>
		test(Object.assign({}, JWA[alg], matchAlgKty(alg, "RSA") ? rsaParams : {}))
		.catch(err => false).then(res => res && alg)
	)
	return Promise.all(tests).then(results => new Set(results.filter(Boolean)))
}

const message = new Uint8Array([1, 2, 3, 4])
const rsaParams = {modulusLength: 1024, publicExponent: new Uint8Array([0x01, 0x00, 0x01])}

async function test(algorithm) {
	const key = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]) as any
	const [pub, priv] = [key.publicKey || key, key.privateKey || key]
	const signature = await crypto.subtle.sign(algorithm, priv, message)
	return crypto.subtle.verify(algorithm, pub, signature, message)
}
