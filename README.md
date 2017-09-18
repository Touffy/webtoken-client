# JWT client

Decode and validate [JSON Web Tokens](https://tools.ietf.org/html/rfc7519) (JWT) on the client-side, using the native [Web Crypto API](https://www.w3.org/TR/WebCryptoAPI/#subtlecrypto-interface) for JWS signature verification.

webtoken-client is only 5kB minified and has no dependencies.

## Getting started

```
npm install webtoken-client
```

```javascript
const jwtParser = new JWTParser()
jwtParser.addKey(/* insert your JWK here */)

oAuthLoginAndGetTheTokenSomehow
.then(token => jwtParser.validate(token))
.then(claims => /* now it's up to you! */)
```

The `claims` object promised in the example above by the `validate` method is the decoded payload of the token. The promise will only resolve when JWTParser has checked the well-formedness and coherence of the token, and verified the signature. It will reject if anything goes wrong.

## What does it do?

JWTParser manages cryptographic keys (see below). The most secure option is to have them hard-coded or otherwise obtain the keys locally rather than over an untrusted network. However, JWTParser is able to interpret the token headers to automatically obtain its verification key if you allow it.

The other thing JWTParser can do, and the reason you want to use it in the first place, is decode, validate and verify signed tokens. Some OAuth applications *can* treat JWTs as opaque strings on the client-side. In many other cases, the tokens contain useful information, such as a user's name and email in the case of OpenID tokens.

## Key management options

By default, you have to add all verification keys manually by calling `addKey()` on the parser. Keys can be passed as:
* a JWK object
* an already imported public (or symmetric for HMAC) CryptoKey with a Key ID as a second argument

You can pass an object to the JWKParser constructor to enable these options (all off by default):
* *allowInsecure*: accept tokens without a signature `(alg=none)`
* *allowTokenKey*: accept verification keys provided by the token itself (in the `jwk` header)
* *trustKeySetOrigins*: a `RegExp` whitelist of [hosts (domain:port)](url.spec.whatwg.org/#dom-url-host) from which keys may be fetched when specified in `jku`; the full origin is implied because only HTTPS is allowed for those requests.

For example, if you trust the network between your client and https://jwks.example.org on any port, but you fear the tokens themselves may be hijacked, you could specify:

```javascript
const parser = new JWKParser({
	trustKeySetOrigins: /^jwks\.example\.org(:\d+)?$/
})
```

Of course, it may be convenient (**for testing only!**) to relax security as much as possible:

```javascript
const parser = new JWKParser({
	allowInsecure: true,
	allowTokenKey: true,
	trustKeySetOrigins: /.*/
})
```

Anyway, **none of those options can be changed after instantiating the parser**.

## Platform support

*tl;dr: it works on modern browsers over HTTPS, stick to RSA or HMAC signatures for now.*

webtoken-client relies on the Web Crypto API in modern browsers to do its job much faster, with much less code, and with better security, than what can be accomplished with JavaScript cryptographic libraries.

Therefore, you can forget running it in node.js, or Internet Explorer. Also, the API is only exposed on HTTPS pages in some browsers, so testing on localhost may require some adjustments.

Obviously, only the cryptographic algorithms supported natively by the browser will work. Currently that means only RSASSA-PKCS1-v1_5 and HMAC for the widest compatibility. ECDSA if you can wait for Safari 11.

Since it was going to require modern browsers anyway, I went forward and picked a target of ES7 for the transpiled and rolled-up JavaScript lib. That will exclude some midly old versions of browsers that did already support WebCrypto, so if those are an important audience for your need, you'll have to recompile.

## License and credits

webtoken-client is distributed under the [X11 license](http://www.gnu.org/licenses/license-list.html#X11License).

This was developped in part during my work hours at STIME — Les Mousquetaires. That is why there is a version of this documentation in French.
