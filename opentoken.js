/**
 * OpenToken for Node.JS
 * http://tools.ietf.org/html/draft-smith-opentoken-02
 */

var decode  = require('./lib/decode');
var encode = require('./lib/encode');
var doxli  = require('doxli');


/**
 * OpenTokenAPI constructor
 * OpenTokenAPI is an object with utility methods for reading
 * and writing OpenTokens with some automatic validation, etc.
 *
 * @param {number} cipherSuite Cipher Suite ID (see ciphers.js)
 * @param {string} password    Encrypt/Decrypt password
 */
function OpenTokenAPI(cipherSuite, password) {
  this.cipherSuite = cipherSuite;
  this.password = password;
}

/**
 * Parse an OpenToken and apply basic validation checks
 *
 * @param {string} token The raw token basd64 encoded string
 * @param {function} cb Callback function
 * @return {object} Key-value pairs from token, returned via callback
 */
OpenTokenAPI.prototype.parseToken = function (token, cb) {
  if (!token || !cb) {
    return null;
  }
  decode(token, this.cipherSuite, this.password, processPayload);
  function processPayload(err, data) {
    if (err) {
      return cb(err);
    }

    // Parse data string into key/value pairs
    var index;
    var pairs = {};
    var kvps = data.split("\n");
    kvps.forEach(function (x,i,arr) {
      arr[i] = x.split("=");
    });

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
      return cb(new Error("OpenToken missing 'not-on-or-after'"));
    }
    // TODO else validate

    if (!pairs['renew-until']) {
      return cb(new Error("OpenToken missing 'renew-until'"));
    }
    // TODO else validate

    return cb(null, pairs);
  }
};

/**
 * Create a token from an object of key-value pairs to encode.
 * @param {object} data Object with key:value pairs to encode
 * @param {function} cb Callback
 * @return {string} base64-encoded token 
 */
OpenTokenAPI.prototype.createToken = function (pairs, cb) {
  if (!pairs || !cb) {
    return null;
  }
  console.log(pairs);
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
    return cb(new Error("OpenToken missing 'not-on-or-after'"));
  }
  // TODO else validate

  if (!pairs['renew-until']) {
    return cb(new Error("OpenToken missing 'renew-until'"));
  }
  // TODO else validate

  // probably parse the data into a 2D array [ [key, val], ...]
  // then Array.join into [k=v, k2=v2] and k=v\nk2=v2 etc
  var item;
  var keyValues = [];
  for (item in data) {
    if (data.hasOwnProperty(item)) {
      console.log("Process " + item + ":" + data[item]);
      keyValues.push(item + "=" + data[item]);
    }
  }
  keyValues = keyValues.join("\n"); // collapse to string
  console.log(pairs);
};


exports.OpenTokenAPI = OpenTokenAPI;
exports.decode = decode;
exports.encode = encode;

// Add help function to exports
doxli(this);
