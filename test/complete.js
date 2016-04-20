var expect = require('chai').expect;
var bitws = require('../dist/bitws-js.js');
var bitwsMin = require('../dist/bitws-js.min.js');
var bitcore = require('bitcore-lib');

describe('Complete Test', function() {

    it("should create a JWS message and validate it", function() {
        var data = bitws.deriveKeys('some user', 'some pwd');
        expect(data).to.have.property('key');
        expect(data).to.have.property('payload');

        var payload = {data: data.payload};
        var raw = bitws.signSerialize(null, payload, data.key.sign);

        var decoded = bitws.validateDeserialize(null, raw, true);
        expect(decoded).to.have.property("header");
        expect(decoded).to.have.property("payload");
        expect(decoded.header).to.have.property("kid");
        expect(decoded.header.kid).to.be.equal(data.key.sign.address);
        expect(decoded.payload).to.have.property("aud");
        expect(decoded.payload.aud).to.be.null;

        raw = bitws.signSerialize(null, payload, data.key.sign, 1800);
        decoded = bitws.validateDeserialize(null, raw, false);
        expect(decoded).to.have.property("header");
        expect(decoded).to.have.property("payload");
        expect(decoded.header).to.have.property("kid");
        expect(decoded.header.kid).to.be.equal(data.key.sign.address);
        expect(decoded.payload).to.have.property("aud");
        expect(decoded.payload.aud).to.be.null;

    });

    it("should provide the same keys", function() {
        var data = bitws.deriveKeys('some user', 'some pwd');
        var data2 = bitws.deriveKeys('some user', 'some pwd', data.payload.iterations, data.payload.salt);

        expect(data2.payload.salt).to.be.equal(data.payload.salt);
        expect(data2.key.address).to.be.equal(data.key.address);
        expect(data2.key.encKey).to.be.equal(data.key.encKey);
    });

    it("should return a string wif address", function() {
        var wif = bitws.privToWif("bcc993177bec48f94cb0e617980a320f028f8cfa0f7a914d44ec84e017dc7cc6");
        expect(wif).to.be.equal("L3Ygumw9tv8Y7nP8y3cM164pMYugne5B9SPdf6jix1Rve4e91yTd");
    });

    it("should signSerialize using a privKey form a wif", function() {

        var payload = { data: { something : "some data goes here"} };

        var wif = "KxZUqanyzZEGptbauar66cQo8bfGHwDauHogkxCaqTeMGY1stH6E"
        var priv = bitws.wifToPriv(wif);

        var raw = bitws.signSerialize(null, payload, priv);
        console.log(raw);
        decoded = bitws.validateDeserialize(null, raw, false);
        expect(decoded).to.have.property("header");
        expect(decoded).to.have.property("payload");
        expect(decoded.header).to.have.property("kid");
        expect(decoded.header.kid).to.be.equal(priv.address);
        expect(decoded.payload).to.have.property("aud");
        expect(decoded.payload.aud).to.be.null;
    });

});

describe('Complete Test on .min file', function() {

    it("should create a JWS message and validate it", function() {
        var data = bitwsMin.deriveKeys('some user', 'some pwd');
        expect(data).to.have.property('key');
        expect(data).to.have.property('payload');

        var payload = {data: data.payload};
        var raw = bitwsMin.signSerialize(null, payload, data.key.sign);

        var decoded = bitwsMin.validateDeserialize(null, raw, true);
        expect(decoded).to.have.property("header");
        expect(decoded).to.have.property("payload");
        expect(decoded.header).to.have.property("kid");
        expect(decoded.header.kid).to.be.equal(data.key.sign.address);
        expect(decoded.payload).to.have.property("aud");
        expect(decoded.payload.aud).to.be.null;

        raw = bitwsMin.signSerialize(null, payload, data.key.sign, 1800);
        decoded = bitwsMin.validateDeserialize(null, raw, false);
        expect(decoded).to.have.property("header");
        expect(decoded).to.have.property("payload");
        expect(decoded.header).to.have.property("kid");
        expect(decoded.header.kid).to.be.equal(data.key.sign.address);
        expect(decoded.payload).to.have.property("aud");
        expect(decoded.payload.aud).to.be.null;
    });

    it("should provide the same keys", function() {
        var data = bitwsMin.deriveKeys('some user', 'some pwd');
        var data2 = bitwsMin.deriveKeys('some user', 'some pwd', data.payload.iterations, data.payload.salt);

        expect(data2.payload.salt).to.be.equal(data.payload.salt);
        expect(data2.key.address).to.be.equal(data.key.address);
        expect(data2.key.encKey).to.be.equal(data.key.encKey);
    });

    it("should return a string wif address", function() {
        var wif = bitwsMin.privToWif("bcc993177bec48f94cb0e617980a320f028f8cfa0f7a914d44ec84e017dc7cc6");
        expect(wif).to.be.equal("L3Ygumw9tv8Y7nP8y3cM164pMYugne5B9SPdf6jix1Rve4e91yTd");
    });

});
