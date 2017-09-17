import { decodeBase64url, stringToBuffer } from './encoding'
import { JWA } from './jwa'
import { fetchJWK, validJsonWebKey, validCryptoKey, loadJWK } from './jwk'

export interface JWKParserOptions {
	/** unless true, tokens without a signature (alg=none) will be rejected */
	allowInsecure?: boolean
	/** unless true, will reject verification keys provided by the token itself (in 'jwk') */
	allowTokenKey?: boolean
	/** will only fetch keys from matching hosts (domain:port, as per url.spec.whatwg.org/#dom-url-host) when specified in 'jku' */
	trustKeySetOrigins?: RegExp
}

interface JOSE {
	alg: keyof typeof JWA
	kid?: string
	jwk?: JsonWebKey
	jku?: string
}

/**
 * Configure a parser that can validate signed JSON Web Tokens (JWS only for now) and manage verification keys.
 * Unsigned (insecure) JWTs are disallowed by default.
 * The parser can automatically fetch additional keys from the tokens' JOSE header (also disabled by default).
 */
export default class JWTParser {
	readonly allowInsecure: boolean
	readonly allowTokenKey: boolean
	readonly trustKeySetOrigins: RegExp | false
	private readonly _keys: {[kid: string]: CryptoKey | Promise<CryptoKey>} = {}

	/** You won't get another chance to set the parser's options */
	constructor(options: JWKParserOptions = {}) {
		for (const opt of ["allowInsecure", "allowTokenKey", "trustKeySetOrigins"]) Object.defineProperty(this, opt, {
			value: options[opt] || false,
			enumerable: true, writable: false, configurable: false // runtime readonly!
		})
	}

	/** Add a key to the parser by importing a JSON Web Key */
	addKey(key: JsonWebKey): Promise<CryptoKey>
	/** Add an already imported CryptoKey to the parser with a given Key ID so it can be referenced by the tokens */
	addKey(key: CryptoKey, kid: string): CryptoKey
	addKey(key, kid?) {
		if (key instanceof CryptoKey) {
			if (!kid || typeof kid !== "string") throw new TypeError("How would a token reference this key without a key ID?")
			return this._keys[kid] = validCryptoKey(key)
		}
		return loadJWK(validJsonWebKey(key), this._keys)
	}

	/**
	 * Validate a JSON Web Token [RFC 7519] and eventualy returns its Claims object (or rejects if something dosn't check out).
	 * Checks the well-formedness and signature of the token, with some extra implementation-specific constraints.
	 */
	async validate(token: string) {
		// validate basic token structure

		if (typeof token !== "string") throw new TypeError("The token is not a string.")
		const split = token.split(".")
		switch(split.length) {
			case 2: if (!this.allowInsecure) throw new Error("The token is not signed and we can't have that.")
			case 3: break
			default: throw new Error("The token doesn't have an acceptable number of segments.")
		}
		const [header, payload, encodedSign] = split

		// validate JOSE header

		try {var jose = JSON.parse(decodeBase64url(header))}
		catch(err) {throw new Error("Could not decode JOSE header as base64url-encoded JSON.")}

		if (!jose || typeof jose !== "object"	|| (jose.typ && !/^jwt$/i.test(jose.typ))|| !jose.alg) throw new Error("Malformed JOSE header.")

		if (encodedSign) {
			if (!(jose.alg in JWA)) throw new Error("Unsupported signing algorithm: " + jose.alg)
			// try to get the key (this may also fail validation in several ways)
			var key = this._getKey(jose)
		} else {
			if (jose.alg !== "none") throw new Error("A signing algorithm is declared but there is no signature.")
		}

		// validate Claims

		try {var claims = JSON.parse(decodeBase64url(payload))}
		catch(err) {throw new Error("Could not decode Claims payload as base64url-encoded JSON.")}

		if (!claims || typeof claims !== "object"
		|| (claims.iss && typeof claims.iss !== "string")
		|| (claims.sub && typeof claims.sub !== "string")
		|| (claims.aud && typeof claims.aud !== "string")
		|| (claims.exp && typeof claims.exp !== "number")
		|| (claims.nbf && typeof claims.nbf !== "number")
		|| (claims.iat && typeof claims.iat !== "number")
		|| (claims.jti && typeof claims.jti !== "string")) throw new Error("Malformed Claims payload.")

		// validate signature

		var signLength = +jose.alg.slice(-3)
		if (signLength === 256) signLength = 128

		try {var signature = decodeBase64url(encodedSign)}
		catch(err) {throw new Error("Could not decode Signature as base64url.")}

		if (signature.length !== signLength) throw new Error(`The signature for ${jose.alg} should be ${signLength} bytes long, but it was ${signature.length} bytes in the token.`)

		// verify signature

		if (await crypto.subtle.verify(JWA[jose.alg], await key, stringToBuffer(signature), stringToBuffer([header, payload].join("."))))
			return claims
		throw new Error("Signature verification failed.")
	}


	/**
	 * Attempt to get the key specified by the header's "kid", "jku" or "jwk" fields, fetching if needed (and if allowed).
	 */
	private async _getKey(jose: JOSE) {
		var key: JsonWebKey
		if (jose.kid in this._keys) {
			if (this._keys[jose.kid] instanceof Promise) return await this._keys[jose.kid]
			return this._keys[jose.kid]
		} else if (jose.jwk) {
			if (!this.allowTokenKey) throw new Error("The token bears its own verification key, but we don't trust that.")
			key = validJsonWebKey(jose.jwk)
			if (jose.kid && jose.kid !== key.kid) throw new Error("The supplied JWK has a different key ID than the JWT.")
		} else if (jose.kid && jose.jku) {
			if (!this.trustKeySetOrigins || !this.trustKeySetOrigins.test(new URL(jose.jku).host))
				throw new Error(`The token points to a JWK set at ${jose.jku}, but we don't trust the network to get them.`)
			key = await fetchJWK(jose.kid, jose.jku)
		} else throw new Error("The token doesn't have a JWK and doesn't say where it can be found, so we can't verify it.")

		if (key.alg !== jose.alg) throw new Error("The key has a different algorithm than specified by the header.")

		return await loadJWK(key, this._keys)
	}
}
