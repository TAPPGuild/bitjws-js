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
