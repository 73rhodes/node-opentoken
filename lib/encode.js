/**
 * OpenToken for Node.JS
 * http://tools.ietf.org/html/draft-smith-opentoken-02
 */

var crypto  = require('crypto');
var zlib    = require('zlib');
var ciphers = require('./ciphersuites');


/**
 * Generate an OpenToken from payload
 
 * @param {string}   payload The payload to encrypt
 * @param {string}   key     Base 64 encoded key of appropriate length for cipher
 * @param {object}   options Object with optional parameters. May be null.
 *        {string}   options.keyInfo 
 *        {number}   options.cipherId The cipher suite to use (see ciphers.js0
 * @param {function} cb      Callback
 */

function encode(payload, key, options, cb) {

  // Generate the payload
  if (!cb) {
    console.error("Must give payload, key, [options], cb");
    return null;
  }
  if (!payload || !key) {
    return cb(new Error("Must give payload, key, [options], cb")); 
  }

  options = options || {};
  var ivLength;
  var iv;
  var cipherId;
  var cipherName;
  var keyInfo = options.keyInfo || null;
  var keyInfoLength = keyInfo ? keyInfo.length : 0;
  var zippedData;
  var hmac;
  var hmacDigest;

  // Select a cipher suite and generate a corresponding IV
  otkVersion = 1;
  cipherId   = options.cipherId || 2;
  console.log("encode: otkVersion = " + otkVersion);
  if (cipherId < 0 || cipherId >= ciphers.length) {
    return cb(new Error("Invalid cipher suite value " + cipherId + 
      ". Must be between 0 and " + ciphers.length));
  }
  cipherName = ciphers[cipherId].name;
  ivLength = ciphers[cipherId].ivlength;
  crypto.randomBytes(ivLength, function (err, buffer){
    if (err) {
      return cb(err);
    }
    iv = buffer;
    initializeHMAC();
  });

  // Initialize an HMAC using SHA-1 and the following data
  // OTK version, Cipher suite value, IV value (if present)
  // Key Info value (if present), clear-text payload
  // TODO: use password and generate appropriate key instead
  var encryptionKey = new Buffer(key, 'base64');
  function initializeHMAC() {
    if(cipherId == 0) {
      hmac = crypto.createHash("sha1");
    } else {
      hmac = crypto.createHmac("sha1", encryptionKey);
    }
    hmac.update(new Buffer([otkVersion]));    // OTK Version
    hmac.update(new Buffer([cipherId]));      // Cipher Suite
    if (iv) {
      hmac.update(iv);                        // IV Value
    }
    if (keyInfo) {
      hmac.update(keyInfo);                   // Key Info
    }
    hmac.update(payload);                     // cleartext payload 
    hmacDigest = hmac.digest();
  }

  // Compress payload using DEFLATE specification (RFC1950, RFC1951)
  zlib.deflate(payload, function (err, buf) {
    if (err) {
      return cb(err);
    } else {
      zippedData = buf;
      encryptData();
    }
  });

  // TODO padding...

  // Encrypt the compressed payload using the selected cipher suite
  function encryptData() {

    var cipher = crypto.createCipheriv(cipherName, encryptionKey, iv);
    var payloadCipherText = Buffer.concat(
      [
        cipher.update(zippedData),
        cipher.final()
      ]
    );

    // Construct the binary structure representing the OTK; place the MAC
    // IV, key info and cipher-text within the structure
    var otkBuffers = [
      new Buffer("OTK"),                // Header literal
      new Buffer([0x01, cipherId]),     // OTK Version, Cipher Suite
      hmacDigest,
      new Buffer([ivLength])
    ];
    if (ivLength > 0) {
      otkBuffers.push(iv);
    }
    console.log("encode: cipherId = %d (%s)", cipherId, cipherName);
    console.log('encode: hmac = 0x' + hmacDigest.toString('hex'));
    console.log("encode: ivLength = " + ivLength);
    console.log("encode: iv = 0x" + iv.toString('hex'));
    otkBuffers.push(new Buffer([keyInfoLength]));
    console.log("encode: keyInfoLength = " + keyInfoLength);
    if (keyInfoLength > 0) {
      otkBuffers.push(new Buffer(keyInfo));
      console.log("encode: keyInfo = 0x" + keyInfo.toString('hex'));
    }
    var payloadLengthBuffer = new Buffer(2);
    payloadLengthBuffer.writeUInt16BE(payload.length, 0);
    otkBuffers.push(payloadLengthBuffer);
    console.log('encode: payloadLength = ' + payload.length);
    otkBuffers.push(payloadCipherText);
    console.log("encode: cipherText = 0x" + payloadCipherText.toString('hex'));

    otkBuffer = Buffer.concat(otkBuffers);

    // Base64 encode the entire binary structure, following RFC4648 and 
    // ensuring the padding bits are all set to zero
    // TODO - padding...?
    console.log("encode: token 0x" + otkBuffer.toString('hex'));
    var otk = otkBuffer.toString('base64');

    // Replace all Base64 padding characters "=" with "*" 
    otk = otk.replace(/={2}$/, "**");
    otk = otk.replace(/=$/, "*");
    
    cb(null, otk);
  }
}

module.exports = encode;

