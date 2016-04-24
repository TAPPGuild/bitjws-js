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
 * Return a signed bitcore.message. By default the expiration claim (exp) is
 * set to one hour in the future and the issued at claim (iat) is the current
 * unix timestamp * 1000.
 *
 * @param {string} url - Used as the audience (aud) in the bitcore.message claims.
 * @param {object} payload - Arbitrary data to be added to the bitcore.message payload.
 * @param {object} sign - An object that contains at least "address" and "key".
 * @returns {string}
 */
function signSerialize(url, data, sign, expTime) {

    var exp = (new Date().getTime() / 1000) + 3600;
    if (expTime && expTime > 0)
        exp = (new Date().getTime() / 1000) + expTime;

    var payload = {
        aud : url,
        data : data,
        exp : exp,
        iat : new Date().getTime()
    }

    var rawPayload = base64url.encode(stringify(payload));
    var msg = jwtHeader(sign.address) + '.' + rawPayload;
    var signature = base64url.encode(new Message(msg).sign(sign.key));

    return msg + '.' + signature;

}


/**
 * Verify a signed signed message and return its address and payload if
 * the signature matches.
 *
 * @param {string} url - Used as the audience (aud) in the JWT claims.
 * @param {string} raw - signed bittcore.message received.
 * @returns {object}
 */
function validateDeserialize(url, raw, checkExpiration) {

    var pieces = raw.split('.');

    if (pieces.length != 3) {
        throw new TypeError("Invalid raw data");
    }

    rawHeader = pieces[0];
    rawPayload = pieces[1];
    signature = base64url.decode(pieces[2]);

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
