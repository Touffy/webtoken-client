var JWTParser = (function () {
'use strict';

/**
 * Decodes a base64url-encoded string (which differs from base64 at digits 62 and 63)
 */
function decodeBase64url(str) {
    return atob(str.replace(/-/g, "+").replace(/_/g, "/"));
}
/**
 * Turns a string (its characters should have a Unicode value below 256) into a Uint8Array
 * for use with APIs like Crypto that require an ArrayBuffer
 */
function stringToBuffer(str) {
    return new Uint8Array([...str].map(c => c.charCodeAt(0)));
}

// correspondence between JWA name ("alg" in JOSE header and JWK) and Web Crypto algorithm
const JWA = {
    HS256: { name: "HMAC", hash: "SHA-256" },
    HS384: { name: "HMAC", hash: "SHA-384" },
    HS512: { name: "HMAC", hash: "SHA-512" },
    RS256: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    RS384: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
    RS512: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
    ES256: { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" },
    ES384: { name: "ECDSA", namedCurve: "P-384", hash: "SHA-384" },
    ES512: { name: "ECDSA", namedCurve: "P-521", hash: "SHA-512" },
    PS256: { name: "RSA-PSS", saltLength: 128, hash: "SHA-256" },
    PS384: { name: "RSA-PSS", saltLength: 384, hash: "SHA-384" },
    PS512: { name: "RSA-PSS", saltLength: 512, hash: "SHA-512" }
};
/**
 * Check that the key is the right type for its algorithm
 */
function matchAlgKty(alg, kty) {
    switch (alg[0]) {
        case 'H': return kty === "oct";
        case 'R':
        case 'P': return kty === "RSA";
        case 'E': return kty === "EC";
    }
}
/**
 * Returns the Set of the algorithms supported by the browser
 */

/**
 * Attempts to find a JWK with the specified ID in a JWKs fetched from the specified URL.
 * Non-HTTPS URLs will be rejected.
 */
function fetchJWK(kid, jku) {
    const url = new URL(jku);
    if (url.protocol !== "https:")
        throw new URIError("Keys should be fetched only over HTTPS.");
    return fetch(jku).then(res => res.json())
        .then(res => {
        if (!Array.isArray(res))
            throw new TypeError("The specified JWKs is not an Array.");
        const key = res.find(k => k.kid === kid);
        if (!key)
            throw new Error(`The JWKs at ${jku} did not contain the key with kid = ${kid}.`);
        return validJsonWebKey(key);
    });
}
/**
 * Checks that an object looks like a genuine JWK with the "sig" use and a supported algorithm
 */
function validJsonWebKey(key) {
    if (!key.kid)
        throw new Error("The key ID (kid) is missing from the JWK.");
    if (!key.kty)
        throw new Error("The key type (kty) is missing from the JWK.");
    if (!key.alg)
        throw new Error("The key algorithm (alg) is missing from the JWK.");
    if (!/^(?:EC|RSA|oct)$/.test(key.kty))
        throw new Error(`Unsupported non-standard key type: ${key.kty}.`);
    if (!(key.alg in JWA))
        throw new Error(`Unsupported key algorithm: ${key.alg}.`);
    if (!matchAlgKty(key.alg, key.kty))
        throw new Error(`The key type (${key.kty}) does not match its algorithm (${key.alg}).`);
    if (!/\bsig\b/.test(key.use))
        throw new Error("The key does not allow signing/verification.");
    return key;
}
/**
 * Checks that a CryptoKey has acceptable properties for verifying JWT signatures
 */
function validCryptoKey(key) {
    if (!key.usages.includes("verify"))
        throw new Error("Cannot use this key for signature verification.");
    const keyAlg = key.algorithm;
    const jwa = Object.values(JWA).find(alg => alg.name === keyAlg.name && alg.hash === keyAlg.hash.name);
    if (!jwa)
        throw new Error("The key uses a combination of algorithm and hash that isn't listed in JWA.");
    if (jwa.namedCurve && keyAlg.namedCurve !== jwa.namedCurve)
        throw new Error(`The key's elliptic curve is not the one specified in JWA for ${jwa.hash}.`);
    return key;
}
/**
 * Imports a verification JWK with the Web Crypto API, saving it in a key dictionary if provided
 */
function loadJWK(jkw, collect) {
    const promise = crypto.subtle.importKey("jwk", jkw, JWA[jkw.alg], false, ["verify"]);
    if (collect) {
        collect[jkw.kid] = promise;
        promise.then(key => collect[jkw.kid] = key).catch(err => delete collect[jkw.kid]);
    }
    return promise;
}

/**
 * Configure a parser that can validate signed JSON Web Tokens (JWS only for now) and manage verification keys.
 * Unsigned (insecure) JWTs are disallowed by default.
 * The parser can automatically fetch additional keys from the tokens' JOSE header (also disabled by default).
 */
class JWTParser {
    /** You won't get another chance to set the parser's options */
    constructor(options = {}) {
        this._keys = {};
        for (const opt of ["allowInsecure", "allowTokenKey", "trustKeySetOrigins"])
            Object.defineProperty(this, opt, {
                value: options[opt] || false,
                enumerable: true, writable: false, configurable: false // runtime readonly!
            });
    }
    addKey(key, kid) {
        if (key instanceof CryptoKey) {
            if (!kid || typeof kid !== "string")
                throw new TypeError("How would a token reference this key without a key ID?");
            return this._keys[kid] = validCryptoKey(key);
        }
        return loadJWK(validJsonWebKey(key), this._keys);
    }
    /**
     * Validate a JSON Web Token [RFC 7519] and eventualy returns its Claims object (or rejects if something dosn't check out).
     * Checks the well-formedness and signature of the token, with some extra implementation-specific constraints.
     */
    async validate(token) {
        // validate basic token structure
        if (typeof token !== "string")
            throw new TypeError("The token is not a string.");
        const split = token.split(".");
        switch (split.length) {
            case 2: if (!this.allowInsecure)
                throw new Error("The token is not signed and we can't have that.");
            case 3: break;
            default: throw new Error("The token doesn't have an acceptable number of segments.");
        }
        const [header, payload, encodedSign] = split;
        // validate JOSE header
        try {
            var jose = JSON.parse(decodeBase64url(header));
        }
        catch (err) {
            throw new Error("Could not decode JOSE header as base64url-encoded JSON.");
        }
        if (!jose || typeof jose !== "object" || (jose.typ && !/^jwt$/i.test(jose.typ)) || !jose.alg)
            throw new Error("Malformed JOSE header.");
        if (encodedSign) {
            if (!(jose.alg in JWA))
                throw new Error("Unsupported signing algorithm: " + jose.alg);
            // try to get the key (this may also fail validation in several ways)
            var key = this._getKey(jose);
        }
        else {
            if (jose.alg !== "none")
                throw new Error("A signing algorithm is declared but there is no signature.");
        }
        // validate Claims
        try {
            var claims = JSON.parse(decodeBase64url(payload));
        }
        catch (err) {
            throw new Error("Could not decode Claims payload as base64url-encoded JSON.");
        }
        if (!claims || typeof claims !== "object"
            || (claims.iss && typeof claims.iss !== "string")
            || (claims.sub && typeof claims.sub !== "string")
            || (claims.aud && typeof claims.aud !== "string")
            || (claims.exp && typeof claims.exp !== "number")
            || (claims.nbf && typeof claims.nbf !== "number")
            || (claims.iat && typeof claims.iat !== "number")
            || (claims.jti && typeof claims.jti !== "string"))
            throw new Error("Malformed Claims payload.");
        // validate signature
        var signLength = +jose.alg.slice(-3);
        if (signLength === 256)
            signLength = 128;
        try {
            var signature = decodeBase64url(encodedSign);
        }
        catch (err) {
            throw new Error("Could not decode Signature as base64url.");
        }
        if (signature.length !== signLength)
            throw new Error(`The signature for ${jose.alg} should be ${signLength} bytes long, but it was ${signature.length} bytes in the token.`);
        // verify signature
        if (await crypto.subtle.verify(JWA[jose.alg], await key, stringToBuffer(signature), stringToBuffer([header, payload].join("."))))
            return claims;
        throw new Error("Signature verification failed.");
    }
    /**
     * Attempt to get the key specified by the header's "kid", "jku" or "jwk" fields, fetching if needed (and if allowed).
     */
    async _getKey(jose) {
        var key;
        if (jose.kid in this._keys) {
            if (this._keys[jose.kid] instanceof Promise)
                return await this._keys[jose.kid];
            return this._keys[jose.kid];
        }
        else if (jose.jwk) {
            if (!this.allowTokenKey)
                throw new Error("The token bears its own verification key, but we don't trust that.");
            key = validJsonWebKey(jose.jwk);
            if (jose.kid && jose.kid !== key.kid)
                throw new Error("The supplied JWK has a different key ID than the JWT.");
        }
        else if (jose.kid && jose.jku) {
            if (!this.trustKeySetOrigins || !this.trustKeySetOrigins.test(new URL(jose.jku).host))
                throw new Error(`The token points to a JWK set at ${jose.jku}, but we don't trust the network to get them.`);
            key = await fetchJWK(jose.kid, jose.jku);
        }
        else
            throw new Error("The token doesn't have a JWK and doesn't say where it can be found, so we can't verify it.");
        if (key.alg !== jose.alg)
            throw new Error("The key has a different algorithm than specified by the header.");
        return await loadJWK(key, this._keys);
    }
}

return JWTParser;

}());
