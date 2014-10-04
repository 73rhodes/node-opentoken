/**
 * OpenToken decode function (separate module for easier debugging)
 * http://tools.ietf.org/html/draft-smith-opentoken-02
 */

var crypto  = require('crypto');
var zlib    = require('zlib');
var ciphers = require('./ciphersuites');


/**
 * Decode an OpenToken 
 * Invokes callback(err, result) where result is a Buffer object.
 *
 * @param {String}   otk  Base64 encoded OpenToken with "*" padding chars
 * @param {String}   key  Base64 encoded key
 * @param {function} cb   Callback function (Error, Buffer)
 */

function decode(otk, key, cb) {

  if (!otk || !key || 'function' !== typeof cb) {
    return cb(new Error("Must give token, key, callback"));
  }

  // Replace trailing "*" pad characters with standard Base64 "=" characters
  otk = otk.replace(/\*{2}$/, "==");
  otk = otk.replace(/\*$/, "=");

  // Base64 decode the otk
  var buffer = new Buffer(otk, 'base64');
  var index = 0;
  
  // Validate the OTK header literal and version
  var otkHeader  = buffer.toString('utf8', index, index += 3);
  var otkVersion = buffer.readUInt8(index++);
  if (otkHeader !== 'OTK') {
    return cb(new Error('Invalid token header literal ' + otkHeader));
  }
  if (otkVersion !== 1) {
    return cb(new Error('Invalid version ' + otkVersion + '. Must be 1.'));
  }

  // Extract cipher, mac and iv information.
  var cipherId   = buffer.readUInt8(index++);
  var cipher     = ciphers[cipherId].name;
  var hmac       = buffer.slice(index, index += 20);
  var ivLength   = buffer.readUInt8(index++);
  var iv         = null;
  if (ivLength > 0) {
    iv = buffer.slice(index, index += ivLength);
  }

  // Extract the Key Info (if present) and select a key for decryption.
  var keyInfo = null;
  var keyInfoLen = buffer.readUInt8(index++);
  if (keyInfoLen) {
    keyInfo = buffer.slice(index, index += keyInfoLen);
  }
  // Convert base64 encoded key to binary buffer
  // TODO pass in an ascii / utf8 password instead then generate key from it
  var decryptionKey = new Buffer(key, 'base64');

  // Decrypt the payload cipher-text using the selected cipher suite
  var payloadCipherText = null;
  var payloadLength = buffer.readUInt16BE(index += 2);
  payloadCipherText = buffer.slice(index, index += payloadLength);
  var decipher = crypto.createDecipheriv(cipher, decryptionKey, iv);
  var zippedData = Buffer.concat(
    [
      decipher.update(payloadCipherText),
      decipher.final()
    ]
  );

  // Remove PKCS-5 padding
  var padChar = zippedData[zippedData.length - 1];
  var trimmedData = zippedData;
  if (padChar && padChar < 32) {
    trimmedData = Buffer.slice(zippedData, 0, zippedData.length - padChar);
  }

  // Decompress the decrypted payload in accordance with RFC1950 and RFC1951
  var hmacTest;
  var payload;
  zlib.unzip(zippedData, function (err, buf) {
    if (err) {
      cb(err);
    } else {
      payload = buf;
      initializeHmac();
    }
  });

  // Initialize an HMAC using the SHA-1 algorithm and the following data 
  // OTK Version, Cipher Suite Value, IV value, Key info value (if present)
  function initializeHmac() {
    if(cipherId == 0) {
      hmacTest = crypto.createHash("sha1");
    } else {
      hmacTest = crypto.createHmac("sha1", decryptionKey);
    }
    hmacTest.update(new Buffer([otkVersion]));    // OTK Version
    hmacTest.update(new Buffer([cipherId]));      // Cipher Suite
    if (iv) {
      hmacTest.update(iv);                        // IV Value
    }
    if (keyInfo) {
      hmacTest.update(keyInfo);                   // Key Info
    }
    hmacTest.update(payload);                     // cleartext payload 

    // Compare reconstructed HMAC with original HMAC
    var hmacTestDigest = hmacTest.digest();
    if (hmacTestDigest.toString('hex') !== hmac.toString('hex')) {
      return cb(new Error("HMAC does not match."));
    }

    cb(null, payload);
  }
}

module.exports = decode;

