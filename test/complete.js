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

        var decoded = bitws.validateDeserialize(null, raw);
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
        var wif1 = bitws.privToWif("bcc993177bec48f94cb0e617980a320f028f8cfa0f7a914d44ec84e017dc7cc6");
        expect(wif1).to.be.equal("L3Ygumw9tv8Y7nP8y3cM164pMYugne5B9SPdf6jix1Rve4e91yTd");
    });

    it("should return a string private key address", function() {
        var priv1 = bitws.wifToPriv("L3Ygumw9tv8Y7nP8y3cM164pMYugne5B9SPdf6jix1Rve4e91yTd");
        expect(priv1).to.be.equal("bcc993177bec48f94cb0e617980a320f028f8cfa0f7a914d44ec84e017dc7cc6");
    });

});

describe('Complete Test on .min file', function() {

    it("should create a JWS message and validate it", function() {
        var data = bitwsMin.deriveKeys('some user', 'some pwd');
        expect(data).to.have.property('key');
        expect(data).to.have.property('payload');

        var payload = {data: data.payload};
        var raw = bitwsMin.signSerialize(null, payload, data.key.sign);

        var decoded = bitwsMin.validateDeserialize(null, raw);
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
        var wif1 = bitwsMin.privToWif("bcc993177bec48f94cb0e617980a320f028f8cfa0f7a914d44ec84e017dc7cc6");
        expect(wif1).to.be.equal("L3Ygumw9tv8Y7nP8y3cM164pMYugne5B9SPdf6jix1Rve4e91yTd");
    });

    it("should return a string private key address", function() {
        var priv1 = bitwsMin.wifToPriv("L3Ygumw9tv8Y7nP8y3cM164pMYugne5B9SPdf6jix1Rve4e91yTd");
        expect(priv1).to.be.equal("bcc993177bec48f94cb0e617980a320f028f8cfa0f7a914d44ec84e017dc7cc6");
    });

});
