var expect = require('chai').expect;
var bitws = require('../dist/bitws-js.js');
var bitwsMin = require('../dist/bitws-js.min.js');
var bitcore = require('bitcore-lib');

describe('Complete Test', function() {

    var genKey = null;
    var derivedKey = null;

    it("Should generate a pvkey and add his wif key", function(done) {
        genKey = bitws.newKeys();
        expect(genKey).to.have.property("address");
        expect(genKey).to.have.property("key");
        expect(genKey).to.have.property("wif");
        done();
    });

    it("Should derive a new signature using a username and password", function(done) {
        derivedKey = bitws.deriveKeys('username1', '123456');
        expect(derivedKey).to.have.property('payload');
        expect(derivedKey).to.have.property('key');
        done();
    });

    it("Should create a signature using the generated pvkey (without url and expiration) and validate it", function(done) {

        var payload = { something : "some data here" }

        var signature = bitws.signSerialize(null, payload, genKey, null);
        expect(signature.split('.').length).to.be.equal(3);

        var decoded = bitws.validateDeserialize(null, signature, true);
        expect(decoded).to.have.property("header");
        expect(decoded).to.have.property("payload");
        expect(decoded.header).to.have.property("kid");
        expect(decoded.header.kid).to.be.equal(genKey.address);
        expect(decoded.payload).to.have.property("aud");
        expect(decoded.payload.aud).to.be.null;
        expect(decoded.payload).to.have.property("data");
        expect(decoded.payload.data).to.have.property("something");
        expect(decoded.payload.data.something).to.be.equal("some data here");
        done();

    });

    it("Should create a signature using the generated pvkey (with url and expiration) and validate it", function(done) {

        var payload = { something : "some data here" }

        var signature = bitws.signSerialize("bitwsjsisawesome.com", payload, genKey, 1800);
        expect(signature.split('.').length).to.be.equal(3);

        var decoded = bitws.validateDeserialize("bitwsjsisawesome.com", signature, true);
        expect(decoded).to.have.property("header");
        expect(decoded).to.have.property("payload");
        expect(decoded.header).to.have.property("kid");
        expect(decoded.header.kid).to.be.equal(genKey.address);
        expect(decoded.payload).to.have.property("aud");
        expect(decoded.payload.aud).to.be.equal("bitwsjsisawesome.com");
        expect(decoded.payload).to.have.property("data");
        expect(decoded.payload.data).to.have.property("something");
        expect(decoded.payload.data.something).to.be.equal("some data here");
        done();

    });

    it("Should create a signature using the generated pvkey (with url and expiration) and fail in validation because the timeout", function(done) {

        this.timeout(15000);

        var payload = { something : "some data here" }

        var signature = bitws.signSerialize('bitwsjsisawesome.com', payload, genKey, 10);
        expect(signature.split('.').length).to.be.equal(3);

        setTimeout(function(){
            try {
                bitws.validateDeserialize('bitwsjsisawesome.com', signature, true);
            } catch(e){
                expect(e.toString()).to.be.equal("Error: Payload expired");
                done();
            }
        },11000);

    });

    it("Should create a signature using the derived pvkey (without url and expiration) and validate it", function(done) {

        var payload = { something : "some data here" }

        var signature = bitws.signSerialize(null, payload, derivedKey.key.sign, null);
        expect(signature.split('.').length).to.be.equal(3);

        var decoded = bitws.validateDeserialize(null, signature, true);
        expect(decoded).to.have.property("header");
        expect(decoded).to.have.property("payload");
        expect(decoded.header).to.have.property("kid");
        expect(decoded.header.kid).to.be.equal(derivedKey.key.sign.address);
        expect(decoded.payload).to.have.property("aud");
        expect(decoded.payload.aud).to.be.null;
        expect(decoded.payload).to.have.property("data");
        expect(decoded.payload.data).to.have.property("something");
        expect(decoded.payload.data.something).to.be.equal("some data here");
        done();

    });

    it("Should create a signature using the derived pvkey (with url and expiration) and validate it", function(done) {

        var payload = { something : "some data here" }

        var signature = bitws.signSerialize("bitwsjsisawesome.com", payload, derivedKey.key.sign, 1800);
        expect(signature.split('.').length).to.be.equal(3);

        var decoded = bitws.validateDeserialize("bitwsjsisawesome.com", signature, true);
        expect(decoded).to.have.property("header");
        expect(decoded).to.have.property("payload");
        expect(decoded.header).to.have.property("kid");
        expect(decoded.header.kid).to.be.equal(derivedKey.key.sign.address);
        expect(decoded.payload).to.have.property("aud");
        expect(decoded.payload.aud).to.be.equal("bitwsjsisawesome.com");
        expect(decoded.payload).to.have.property("data");
        expect(decoded.payload.data).to.have.property("something");
        expect(decoded.payload.data.something).to.be.equal("some data here");
        done();

    });

    it("Should create a signature using the derived pvkey (with url and expiration) and fail in validation because the timeout", function(done) {

        this.timeout(15000);

        var payload = { something : "some data here" }

        var signature = bitws.signSerialize('bitwsjsisawesome.com', payload, derivedKey.key.sign, 10);
        expect(signature.split('.').length).to.be.equal(3);

        setTimeout(function(){
            try {
                bitws.validateDeserialize('bitwsjsisawesome.com', signature, true);
            } catch(e){
                expect(e.toString()).to.be.equal("Error: Payload expired");
                done();
            }
        },11000);

    });

});
