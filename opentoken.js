/**
 * OpenToken for Node.JS
 * http://tools.ietf.org/html/draft-smith-opentoken-02
 */

var decode  = require('./lib/decode');
var encode = require('./lib/encode');
var doxli  = require('doxli');

// Some other utility functions that might get modularized later.

/**
 * OpenToken constructor
 * @param {number} cipherSuite Cipher Suite ID (see ciphers.js)
 * @param {string} password    Encrypt/Decrypt password
 */
function OpenToken(cipherSuite, password) {
  this.cipherSuite = cipherSuite;
  this.password = password;
}

OpenToken.prototype.parseToken = function (payload, cb) {
  decode(payload, this.cipherSuite, this.password, processPayload);
  function processPayload(err, data) {
    if (err) {
      return cb(err);
    }
    console.log("opentoken.js::parseToken: got " + data);
    return cb(null, data);
  }
};


/**
 * Parse an OpenToken and validate the minimum key-value pairs
 * it should contain: subject, not-before, not-on-or-after and
 * renew-until.
 */
function parseToken(otk) {
  return null;
}

exports.OpenToken = OpenToken;
exports.decode = decode;
exports.encode = encode;

doxli(this);
