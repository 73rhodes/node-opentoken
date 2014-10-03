/**
 * OpenToken for Node.JS
 * http://tools.ietf.org/html/draft-smith-opentoken-02
 */

var crypto  = require('crypto');
var zlib    = require('zlib');
var ciphers = require('./ciphersuites');

/**
 *
 */

function encode(payload, key, options, cb) {


  // 1. Generate the payload
  if (!payload || !key || !cb) {
    return cb(new Error("Must give payload, key, [options], cb")); 
  }
  options = options || {};
  selectCipher();
  var ivlength;
  var iv;
  var otkversion;
  var cipherID;
  var cipher;
  var keyinfo = options.keyinfo || null;
  var keyinfolength = keyinfo ? keyinfo.length : 0;
  var payloadlength = payload.length;
  
  // 2. Select a cipher suite and generate a corresponding IV
  function selectCipher() {
    otkVersion       = options.otkVersion || 1;
    cipherID = options.cipherID || 2;
    if (cipherID < 0 || cipherID >= ciphers.length) {
      return cb(new Error("Invalid cipher suite value " + cipherID + 
        ". Must be between 0 and " + ciphers.length));
    }
    cipher           = ciphers[cipherID].name;
    console.log("cipher: " + cipher);
    // generate IV 
    ivlength = ciphers[cipherID].ivlength;
    console.log("ivlength: " + ivlength);
    crypto.randomBytes(ivlength, function (err, buffer){
      if (err) {
        return cb(err);
      }
      console.log(buffer.toString());
      iv = buffer;
      initializeHMAC();
    });
  }

  // 3. Initialize an HMAC using the SHA-1 algorithm specified in
  //    http://tools.ietf.org/html/draft-smith-opentoken-02#ref-SHA
  //    and the following data (order is significant)
  //    1. OTK version
  //    2. Cipher suite value
  //    3. IV value (if present)
  //    4. Key Info value (if present)
  //    5. Payload length (2 bytes, network byte order)
  function initializeHMAC() {
    console.log("OTK Version: " + otkVersion);
    console.log("cipher Suite Value: " + cipherID);
    console.log("IV value (hex): " + iv.toString('hex'));
    console.log("Key Info Value: " + keyinfo);
    console.log("Payload length: " + payloadlength);
    var index = 0;
  }

  // 4. Update the SHA-1 HMAC (from the previous step) using clear-text payload

  // 5. Compress the payload using the DEFLATE specification in accordance with
  //    RFC1950 and RFC1951

  // 6. Encrypt the compressed payload using the selected cipher suite

  // 7. Construct the binary structure representing the OTK; place the MAC
  //    IV, key info and cipher-text within the structure

  // 8. Base64 encode the entire binary structure, following RFC4648 and 
  //    ensuring the padding bits are all set to zero

  // 9. Replace all Base64 padding characters "=" with "*" 
}

module.exports = encode;

