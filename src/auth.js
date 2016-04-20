
/**
 * Return a JWT header base64url encoded. The keyId is stored in the header
 * and used when verifying the signature.
 *
 * @param {keyId} string
 * @returns {string}
 * @private
 */
function jwtHeader(keyId) {
    var data = {
        typ: 'JWT',
        alg: 'CUSTOM-BITCOIN-SIGN',
        kid: keyId
    };

    return base64url.encode(stringify(data));
}


/**
 * Return a signed JWT message. By default the expiration claim (exp) is
 * set to one hour in the future and the issued at claim (iat) is the current
 * unix timestamp * 1000.
 *
 * @example
 * ```javascript
 * var bitws = require('bitws-js');
 *
 * var data = bitws.keys.deriveKeys('my username', 'my password');
 *
 * var payload = {data: data.payload};
 * var audience = 'https://example.com';
 * var raw = bitws.auth.signSerialize(audience, payload, data.key.sign, 3600);
 * ```
 *
 * @param {string} url - Used as the audience (aud) in the JWT claims.
 * @param {object} payload - Arbitrary data to be added to the JWT payload.
 * @param {object} sign - An object that contains at least "address" and "key".
 * @returns {string}
 */
function signSerialize(url, payload, sign, expTime) {
    var msg;
    var rawPayload;
    var signature;
    var claims = {};

    /* JWT claims. */
    /* Expiration time (exp) is used to disallow considering the payload
    * if it's received too late. Default to now + 1 hour. */
    if (expTime && expTime > 0)
        claims.exp = (new Date().getTime() / 1000) + expTime;
    else
        claims.exp = (new Date().getTime() / 1000) + 3600;
    /* Issued at (iat) is used as an increasing nonce. */
    claims.iat = new Date().getTime();
    /* Audience (aud) is specified so the signature takes into account
    * the expected receiver. */
    claims.aud = url;

    rawPayload = base64url.encode(stringify(assign(claims, payload)));
    msg = jwtHeader(sign.address) + '.' + rawPayload;

    return msg + '.' + base64url.encode(new Message(msg).sign(bitcore.PrivateKey(sign.key)));;
}


/**
 * Verify a signed JWT message and return its header and payload if
 * the signature matches.
 *
 * @param {string} url - Used as the audience (aud) in the JWT claims.
 * @param {string} raw - signed JWT message received.
 * @returns {object}
 */
function validateDeserialize(url, raw, checkExpiration) {
    var rawHeader, rawPayload, signature;
    var key, header, payload;
    var pieces = raw.split('.');

    if (pieces.length != 3) {
        throw new TypeError("Invalid raw data");
    }
    rawHeader = pieces[0];
    rawPayload = pieces[1];
    signature = base64url.decode(pieces[2]);
    console.log(pieces);
    header = JSON.parse(base64url.decode(rawHeader));
    key = header.kid;
    if (!key) {
        throw new TypeError("Invalid header, missing key id");
    }
    if (!(new Message(rawHeader + '.' + rawPayload).verify(key, signature))) {
        throw new Error("Signature does not match");
    }

    payload = JSON.parse(base64url.decode(rawPayload));
    if (payload.aud !== url) {
        throw new Error("Audience mismatch (" + payload.aud + " != " + url + ")");
    } else if (checkExpiration && ((new Date().getTime() / 1000) > payload.exp)) {
        throw new Error("Payload expired");
    }

    return {header: header, payload: payload};
}
