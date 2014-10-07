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
function OpenTokenAPI(cipherSuite, password) {
  this.cipherSuite = cipherSuite;
  this.password = password;
}

/**
 * Parse an OpenToken and apply basic validation checks
 * @param {string} token The raw token basd64 encoded string
 * @param {function} cb Callback function
 * @return {object} Key-value pairs from token, returned via callback
 */
OpenTokenAPI.prototype.parseToken = function (token, cb) {
  decode(token, this.cipherSuite, this.password, processPayload);
  function processPayload(err, data) {
    if (err) {
      return cb(err);
    }

    // Parse data string into key/value pairs
    var kvps = data.split("\n");
    kvps.forEach(function(x,i,arr) {
      arr[i] = x.split("=");
    });
    var pairs = {};
    var index;
    for (index in kvps) {
      pairs[kvps[index][0]] = kvps[index][1];
    }
    
    // Check the minimum required key/value pairs.
    if (!pairs.subject) {
      return cb(new Error("OpenToken missing 'subject'"));
    }
    // TODO else validate

    if (!pairs['not-before']) {
      return cb(new Error("OpenToken missing 'not-before'"));
    }
    // TODO else validate
 
    if (!pairs['not-on-or-after']) {
      return cb(new Error("OpenToken missing 'renew-until'"));
    }
    // TODO else validate

    return cb(null, pairs);
  }
};


exports.OpenTokenAPI = OpenTokenAPI;
exports.decode = decode;
exports.encode = encode;

// Add help function to exports
doxli(this);
