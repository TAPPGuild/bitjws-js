var sjcl = require('sjcl');
var bitcore = require('bitcore-lib');
var Mnemonic = require('bitcore-mnemonic');
var assign = require('object-assign');
var Message = require('bitcore-message');
var base64url = require('base64-url');
var stringify = require('json-stable-stringify');

/*
    Here it will concatenate the rest of the files on src/lib
    The build task includes concatenation and uglify, it runs everytime you change a file on /src
    To activate teh automatic build on everychange you need to have grunt running
    To run the task build automatically you need to run: grunt build

    To make changes and develop do them with grunt dev running with teh command: grunt dev

    Order of the concatenated files:
        dependencies
        auth, keys, etc..
        index
*/
;
var WORDSIZE = 4;  /* 32 bits. */
var ITERCOUNT = 10000;

/**
 * Generate a salt and derive keys based on the username and password given.
 * PBKDF2-HMAC-SHA256 is used for key stretching with a default iteration
 * count of 10000.
 *
 * @param {string} username
 * @param {string} password
 * @param {number} [iters=10000] - Number of iterations for PBKDF2.
 * @param {string} [salt] - Salt as hexadecimal digits.
 * @returns {object}
 */
function deriveKeys(username, password, iters, salt) {
  var saltHex, rawSalt, iterCount;
  var data = username + password;
  var check = checkBytes(data);

  if (salt) {
    rawSalt = sjcl.codec.hex.toBits(salt);
    saltHex = salt;
  } else {
    rawSalt = sjcl.random.randomWords(16 / WORDSIZE);
    saltHex = sjcl.codec.hex.fromBits(rawSalt);
  }

  /* Use PBKDF2-HMAC-SHA256 to generate a base key for usage with BIP39. */
  if (!iters) {
    iterCount = ITERCOUNT + Math.abs(sjcl.random.randomWords(1)[0] % 1024);
  } else {
    iterCount = Math.max(iters, 5000);
  }
  var baseKey = sjcl.misc.pbkdf2(data, rawSalt, iterCount);
  var words = Mnemonic.fromSeed(keyToBuffer(baseKey), Mnemonic.Words.ENGLISH);

  var keys = recoverKeys(words);

  return {
    payload: {
      username: username,
      check: check,
      salt: saltHex,
      iterations: iterCount
    },
    key: keys,
    mnemonic: words.toString()
  };
}


/**
 * Produce keys for encrypting, signing requests, and generating wallets
 * from the given words using BIP39.
 *
 * The encrypting key corresponds to the key derived at m/0', the
 * signing key (and the respective public address) at m/1', and
 * m/2' for the wallet gen key which is expected to be further derived
 * for each wallet belonging to the same user.
 *
 * @param {string} mnemonic - a string of words or an instance of Mnemonic.
 * @returns {object}
 */
function recoverKeys(mnemonic) {
  var words = (mnemonic instanceof Mnemonic) ? mnemonic : Mnemonic(mnemonic);
  var hdkey = words.toHDPrivateKey();
  var rawEncKey = hdkey.derive(0, true);
  var rawSignKey = hdkey.derive(1, true);
  var rawGenKey = hdkey.derive(2, true);

  var encKey = sjcl.codec.hex.toBits(rawEncKey.privateKey.bn.toJSON());
  var signKey = rawSignKey.privateKey;
  var signAddress = rawSignKey.publicKey.toAddress().toString();

  return {
    sign: {
      key: signKey,
      address: signAddress,
      raw: rawSignKey
    },
    encrypt: encKey,
    genWallet: rawGenKey
  };
}


/**
 * Convert data stored as a sequence of 8 elements composed of
 * 4 bytes each to a sequence of bytes as a Buffer.
 *
 * @example
 * ```javascript
 * var bitws = require('bitws-js');
 *
 * var data = bitws.keys.deriveKeys('my username', 'my password');
 * var buffer = bitws.keys.keyToBuffer(data.key.encrypt);
 * ```
 *
 * @param {array} key - array of length 8
 * @returns {object}
 */
function keyToBuffer(key) {
  var abuffer = new ArrayBuffer(32);  /* 256 bits. */
  var iview = new Int32Array(abuffer);
  var bview = new Uint8Array(abuffer);

  if (iview.length != key.length) {
    throw new Error("Unexpected length");
  }

  for (var i = 0; i < iview.length; i++) {
    iview[i] = key[i];
  }

  return new Buffer(bview);
}


/**
 * Return the last 6 hexadecimal digits from SHA256(data).
 *
 * @param {string} data
 * @returns {string}
 */
function checkBytes(data) {
  var hash = sjcl.hash.sha256.hash(data);
  var hex = sjcl.codec.hex.fromBits(hash);
  var check = hex.slice(-6);
  return check;
}

/**
 * Returns in wif format the privateKey provided.
 *
 * @param {string} priv
 * @returns {string}
 */
function privToWif(priv) {
    return bitcore.PrivateKey(priv).toWIF();
}

/**
 * Returns a PrivateKey object from the wif format privateKey provided.
 *
 * @param {string} wif
 * @returns {String}
 */
function wifToPriv(wif) {
    var privateKey = new bitcore.PrivateKey(wif);
    return privateKey.toString();
}
;
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
 * var raw = bitws.auth.signSerialize(audience, payload, data.key.sign);
 * ```
 *
 * @param {string} url - Used as the audience (aud) in the JWT claims.
 * @param {object} payload - Arbitrary data to be added to the JWT payload.
 * @param {object} sign - An object that contains at least "address" and "key".
 * @returns {string}
 */
function signSerialize(url, payload, sign) {
  var msg;
  var rawPayload;
  var signature;
  var claims = {};

  /* JWT claims. */
  /* Expiration time (exp) is used to disallow considering the payload
   * if it's received too late. Default to now + 1 hour. */
  claims.exp = (new Date().getTime() / 1000) + 3600;
  /* Issued at (iat) is used as an increasing nonce. */
  claims.iat = new Date().getTime();
  /* Audience (aud) is specified so the signature takes into account
   * the expected receiver. */
  claims.aud = url;

  rawPayload = base64url.encode(stringify(assign(claims, payload)));
  msg = jwtHeader(sign.address) + '.' + rawPayload;
  signature = base64url.encode(new Message(msg).sign(sign.key));

  return msg + '.' + signature;
}


/**
 * Verify a signed JWT message and return its header and payload if
 * the signature matches.
 *
 * @param {string} url - Used as the audience (aud) in the JWT claims.
 * @param {string} raw - signed JWT message received.
 * @returns {object}
 */
function validateDeserialize(url, raw) {
  var rawHeader, rawPayload, signature;
  var key, header, payload;
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
  } else if (new Date().getTime() / 1000 > payload.exp) {
    throw new Error("Payload expired");
  }

  return {header: header, payload: payload};
}
;
module.exports = {
    signSerialize : signSerialize,
    validateDeserialize : validateDeserialize,
    deriveKeys : deriveKeys,
    recoverKeys : recoverKeys,
    keyToBuffer : keyToBuffer,
    checkBytes : checkBytes,
    privToWif : privToWif,
    wifToPriv : wifToPriv
}
