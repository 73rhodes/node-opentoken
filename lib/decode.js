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
 * @param {String}   key  Base64 encoded key for decrypting payload
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
  console.log("decode: token 0x" + buffer.toString('hex'));
  var index = 0;
  
  // Validate the OTK header literal and version
  var otkHeader  = buffer.toString('utf8', index, index + 3);
  index += 3;
  var otkVersion = buffer.readUInt8(index++);
  if (otkHeader !== 'OTK') {
    return cb(new Error('Invalid token header literal ' + otkHeader));
  }
  if (otkVersion !== 1) {
    return cb(new Error('Invalid version ' + otkVersion + '. Must be 1.'));
  }
  console.log("decode: otkVersion = " + otkVersion);

  // Extract cipher, mac and iv information.
  var cipherId   = buffer.readUInt8(index++);
  console.log("decode: cipherId = " + cipherId);
  var cipher     = ciphers[cipherId].name;
  var hmac       = buffer.slice(index, index + 20);
  index += 20;
  console.log('decode: hmac = 0x' + hmac.toString('hex'));
  var ivLength   = buffer.readUInt8(index++);
  console.log('decode: ivLength = ' + ivLength);
  var iv         = null;
  if (ivLength > 0) {
    iv = buffer.slice(index, index + ivLength);
    index += ivLength;
  }
  console.log("decode: iv = 0x" + iv.toString('hex'));

  // Extract the Key Info (if present) and select a key for decryption.
  var keyInfo = null;
  var keyInfoLen = buffer.readUInt8(index++);
  console.log("decode: keyInfoLen = " + keyInfoLen);
  if (keyInfoLen) {
    keyInfo = buffer.slice(index, index + keyInfoLen);
    index += keyInfoLen;
    console.log("decode: keyInfo = 0x" + keyInfo.toString('hex'));
  }
  // Convert base64 encoded key to binary buffer
  // TODO pass in an ascii / utf8 password instead then generate key from it
  var decryptionKey = new Buffer(key, 'base64');

  // Decrypt the payload cipher-text using the selected cipher suite
  var payloadCipherText = null;
  var payloadLength = buffer.readUInt16BE(index);
  console.log("decode: payloadLength = 0x" + buffer.slice(index, index+2).toString('hex'));
  index += 2;
  console.log("decode: payloadLength = " + payloadLength);
  // TODO this is yeilding wrong ciphertext length on encoded tokens which use payload length of original payload not encrypted payload
  payloadCipherText = buffer.slice(index, index + payloadLength);
  //payloadCipherText = buffer.slice(index, buffer.length);
  index += payloadLength;
  console.log("decode: cipherText = 0x%s (%d bytes)", payloadCipherText.toString('hex'), payloadCipherText.length);
  var decipher = crypto.createDecipheriv(cipher, decryptionKey, iv);
  var zd1 = decipher.update(payloadCipherText);
  var zd2 = decipher.final();
  var zdb = [zd1];
  if (zd2) zdb.push(zd2);
  var zippedData = Buffer.concat(zdb);
  /*
  var zippedData = Buffer.concat(
    [
      decipher.update(payloadCipherText),
      decipher.final()
    ]
  );
  */

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
    console.log('decode: payload =\n%s\n(%d bytes) which payload length is to be used in the header ', payload, payload.length);
    cb(null, payload);
  }
}

module.exports = decode;

