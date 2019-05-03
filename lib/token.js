/**
 * OpenToken for Node.JS
 * http://tools.ietf.org/html/draft-smith-opentoken-02
 */

var crypto  = require('crypto');
var zlib    = require('zlib');
var ciphers = require('./ciphersuites').ciphers;
var generateKey = require('./ciphersuites').generateKey; // function


/**
 * Generate an OpenToken from payload
 
 * @param {string}   payload Data to encrypt. Newline-delimited key=value pairs.
 * @param {string}   key     Base64 encoded key of appropriate length for cipher
 * @param {function} cb      Callback
 */

function encode(payload, cipherId, password, cb) {

  if (!cb) {
    console.error("Must give payload, cipherId, password, cb");
    return null;
  }

  if (!payload) {
    return cb(new Error("Must give payload, cipherId, password, cb")); 
  }

  // Generate the payload
  // Note: typically this would involve constructing key=val\nkey2=val2 payload
  //       from a hash map of key value pairs. In JavaScript the order of object
  //       properties is not guaranteed, however, so the only option would be to
  //       pass in an Array of key/value pairs. This is more trouble than simply
  //       passing in a string already formatted as key=val\nkey2=val2 etc. So
  //       for now, payload is passed in as newline-delimited key=value pairs.

  var ivLength;
  var iv;
  var cipherName;
  var keyInfo = null; // not used in any current implementation.
  var keyInfoLength = keyInfo ? keyInfo.length : 0;
  var zippedData;
  var hmac;
  var hmacDigest;
  var encryptionKey;

  // Select a cipher suite and generate a corresponding IV
  otkVersion = 1;
  cipherId   = cipherId || 2;
  if (cipherId < 0 || cipherId >= ciphers.length) {
    return cb(new Error("Invalid cipher suite value " + cipherId + 
      ". Must be between 0 and " + ciphers.length));
  }
  cipherName = ciphers[cipherId].name;

  encryptionKey = generateKey(password, null, cipherId);
  
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
  //
  // Note: Key info never was supported, so can be removed

  function initializeHMAC() {
    if(cipherId == 0) {
      hmac = crypto.createHash("sha1");
    } else {
      hmac = crypto.createHmac("sha1", encryptionKey);
    }
    hmac.update(new Buffer([otkVersion]));    // OTK Version
    hmac.update(new Buffer([cipherId]));      // Cipher Suite
    if (ivLength > 0) {
      hmac.update(iv);                        // IV Value
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

  // Encrypt the compressed payload using the selected cipher suite
  function encryptData() {

    var cipher = crypto.createCipheriv(cipherName, encryptionKey, iv);
    cipher.setAutoPadding(true); // add PKCS padding automatically
    var payloadBuffers = [cipher.update(zippedData)];
    payloadBuffers.push(cipher.final()); 
    var payloadCipherText = Buffer.concat(payloadBuffers);

    // Construct the binary structure representing the OTK; place the MAC
    // IV, key info and cipher-text within the structure
    var otkBuffers = [
      new Buffer("OTK"),                           // Header literal 'OTK'
      new Buffer([0x01, cipherId]),                // OTK Version, Cipher Suite
      hmacDigest,                                  // SHA-1 HMAC
      new Buffer([ivLength])                       // IV length
    ];
    if (ivLength > 0) {
      otkBuffers.push(iv);                         // IV Value
    }
    otkBuffers.push(new Buffer([keyInfoLength]));  // Key info length (0)
    // Presently, keyInfoLength is always 0.
    // if (keyInfoLength > 0) {
    //   otkBuffers.push(new Buffer(keyInfo));        // Key info (never used)
    // }

    var payloadLengthBuffer = new Buffer(2);
    payloadLengthBuffer.writeUInt16BE(payloadCipherText.length, 0);
    otkBuffers.push(payloadLengthBuffer);          // Payload length

    otkBuffers.push(payloadCipherText);            // Payload

    otkBuffer = Buffer.concat(otkBuffers);

    // Base64 encode the entire binary structure, following RFC4648 and 
    // ensuring the padding bits are all set to zero 
    var otk = otkBuffer.toString('base64');

    // Replace '/' with '_' and '+' with '-' for compatability with 
    // other implementations 
    otk = otk.replace(/\//g, "_");
    otk = otk.replace(/\+/g, "-");

    // Replace all Base64 padding characters "=" with "*" 
    otk = otk.replace(/={2}$/, "**");
    otk = otk.replace(/=$/, "*");
    
    cb(null, otk);
  }
}


/**
 * Decode an OpenToken 
 * Invokes callback(err, result) where result is a Buffer object.
 *
 * @param {String}   otk  Base64 encoded OpenToken with "*" padding chars
 * @param {String}   key  Base64 encoded key for decrypting payload
 * @param {function} cb   Callback function (Error, Buffer)
 */

function decode(otk, cipherId, password, cb) {

  if (!otk || 'function' !== typeof cb) {
    return cb(new Error("Must give token, cipherId, key, callback"));
  }

  var decryptionKey = generateKey(password, null, cipherId);

  // Replace trailing "*" pad characters with standard Base64 "=" characters
  otk = otk.replace(/\*{2}$/, "==");
  otk = otk.replace(/\*$/, "=");

  // Base64 decode the otk
  var buffer = new Buffer(otk, 'base64');
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

  // Extract cipher, mac and iv information.
  var otkCipherId = buffer.readUInt8(index++);
  var cipher      = ciphers[otkCipherId].name;
  if (cipherId !== otkCipherId) {
   return cb(new Error(
      "cipherId " + cipherId + " argument doesn't match the encoding cipher " + otkCipherId
    ));
  }
  var hmac        = buffer.slice(index, index + 20);
  index += 20;
  var ivLength   = buffer.readUInt8(index++);
  var iv         = null;
  if (ivLength > 0) {
    iv = buffer.slice(index, index + ivLength);
    index += ivLength;
  }

  // Extract the Key Info (if present) and select a key for decryption.
  var keyInfo = null;
  var keyInfoLen = buffer.readUInt8(index++);
  if (keyInfoLen) {
    keyInfo = buffer.slice(index, index + keyInfoLen);
    index += keyInfoLen;
  }

  // Decrypt the payload cipher-text using the selected cipher suite
  var payloadCipherText = null;
  var payloadLength = buffer.readUInt16BE(index);
  index += 2;
  payloadCipherText = buffer.slice(index, index + payloadLength);
  // index += payloadLength;
  var decipher = crypto.createDecipheriv(cipher, decryptionKey, iv);
  decipher.setAutoPadding(true); // automatically remove PKCS padding
  var zd1 = decipher.update(payloadCipherText);
  var zdb = [zd1];
  zdb.push(decipher.final());
  var zippedData = Buffer.concat(zdb);

  // Remove PKCS-5 padding: done automatically by decipher.final()

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
    if(otkCipherId == 0) {
      hmacTest = crypto.createHash("sha1");
    } else {
      hmacTest = crypto.createHmac("sha1", decryptionKey);
    }
    hmacTest.update(new Buffer([otkVersion]));    // OTK Version
    hmacTest.update(new Buffer([otkCipherId]));      // Cipher Suite
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
    cb(null, payload.toString());
  }
}

exports.encode = encode;
exports.decode = decode;
