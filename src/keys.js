
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
    var wifKey = rawSignKey.privateKey.toWIF();

    return {
        sign: {
            key: signKey,
            wif : wifKey,
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
    return {
        key: privateKey.toString(),
        address: privateKey.publicKey.toAddress().toString(),
        raw: privateKey
    }
}
