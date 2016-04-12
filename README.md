# bitws-js
A javascript library for bitws
[![Coverage Status](https://coveralls.io/repos/github/deginner/bitjws-js/badge.svg?branch=master)](https://coveralls.io/github/deginner/bitjws-js?branch=master)

## Install

Run: `bower install bitws-js`

## Methdos

### signSerialize(url, payload, sign)
Return a signed JWT message. By default the expiration claim (exp) is set to one hour in the future and the issued at claim (iat) is the current unix timestamp * 1000.

### validateDeserialize(url, raw)
Verify a signed JWT message and return its header and payload if the signature matches.

### deriveKeys(username, password, iters, salt)
Generate a salt and derive keys based on the username and password given. PBKDF2-HMAC-SHA256 is used for key stretching with a default iteration count of 10000.

### recoverKeys(mnemonic)
Produce keys for encrypting, signing requests, and generating wallets from the given words using BIP39. The encrypting key corresponds to the key derived at m/0', the signing key (and the respective public address) at m/1', and m/2' for the wallet gen key which is expected to be further derived for each wallet belonging to the same user.

### keyToBuffer(key)
Convert data stored as a sequence of 8 elements composed of 4 bytes each to a sequence of bytes as a Buffer.

### checkBytes(data)
Return the last 6 hexadecimal digits from SHA256(data).

### wifToPriv(wif)
Convert a wif string address to a private key string.

### privToWif(priv)
Convert a private key string to a wif string address.

## Develop
Run: `grunt dev` and do your stuff.

## Build
Run: `grunt build`

## Test
Run: `npm test` and the test will run over the dist files.
