export interface JWKParserOptions {
    /** unless true, tokens without a signature (alg=none) will be rejected */
    allowInsecure?: boolean;
    /** unless true, will reject verification keys provided by the token itself (in 'jwk') */
    allowTokenKey?: boolean;
    /** will only fetch keys from matching hosts (domain:port, as per url.spec.whatwg.org/#dom-url-host) when specified in 'jku' */
    trustKeySetOrigins?: RegExp;
}
/**
 * Configure a parser that can validate signed JSON Web Tokens (JWS only for now) and manage verification keys.
 * Unsigned (insecure) JWTs are disallowed by default.
 * The parser can automatically fetch additional keys from the tokens' JOSE header (also disabled by default).
 */
export default class JWTParser {
    readonly allowInsecure: boolean;
    readonly allowTokenKey: boolean;
    readonly trustKeySetOrigins: RegExp | false;
    private readonly _keys;
    /** You won't get another chance to set the parser's options */
    constructor(options?: JWKParserOptions);
    /** Add a key to the parser by importing a JSON Web Key */
    addKey(key: JsonWebKey): Promise<CryptoKey>;
    /** Add an already imported CryptoKey to the parser with a given Key ID so it can be referenced by the tokens */
    addKey(key: CryptoKey, kid: string): CryptoKey;
    /**
     * Validate a JSON Web Token [RFC 7519] and eventualy returns its Claims object (or rejects if something dosn't check out).
     * Checks the well-formedness and signature of the token, with some extra implementation-specific constraints.
     */
    validate(token: string): Promise<any>;
    /**
     * Attempt to get the key specified by the header's "kid", "jku" or "jwk" fields, fetching if needed (and if allowed).
     */
    private _getKey(jose);
}
