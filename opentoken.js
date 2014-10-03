/**
 * OpenToken for Node.JS
 * http://tools.ietf.org/html/draft-smith-opentoken-02
 */

var crypto = require('crypto');
var zlib   = require('zlib');


/**
 * Cipher Suites supported by OpenToken specification
 * The order of these is important!
 */

var cipherSuites = [
  {
    id: 0,
    name: "Null",
    cipher: null,
    keysize: 0,
    mode: null,
    padding: null,
    ivlength: 0
  },
  {
    id: 1,
    name: "aes-256-cbc",
    cipher: "AES",
    keysize: 256,
    mode: "CBC",
    padding: "PKCS 5",
    ivlength: 16
  },
  {
    id: 2,
    name: "aes-128-cbc",
    cipher: "AES",
    keysize: 128,
    mode: "CBC",
    padding: "PKCS 5",
    ivlength: 16
  },
  {
    id: 3,
    name: "3des",
    cipher: "3DES",
    keysize: 168,
    mode: "CBC",
    padding: "PKCS 5",
    ivlength:8 
  }
];


/**
 * Decode an OpenToken 
 * Invokes callback(err, result) where result is a Buffer object.
 *
 * @param {String}   otk  Base64 encoded OpenToken with "*" padding chars
 * @param {String}   keys Base64 encoded key or array of keys (only first is used)
 * @param {function} cb   Callback function (Error, Buffer)
 */

function decode(otk, keys, cb) {

  if (!otk || !keys || 'function' !== typeof cb) {
    return cb(new Error("Must give token, keys, callback"));
  }

  if (keys && 'string' === typeof keys) {
    keys = [keys];
  }

  // 1. Replace the "*" padding characters with standard Base64 "=" characters
  otk = otk.replace("*", "=");

  // 2. Base64 decode the otk ensuring padding bits are set to 0
  var buffer = new Buffer(otk, 'base64');
  
  // 3. Validate the OTK header literal and version
  var index = 0;
  var otkHeader  = buffer.toString('ascii', index, index += 3);
  var otkVersion = buffer.readUInt8(index++);
  var cipherId   = buffer.readUInt8(index++);
  var cipher     = cipherSuites[cipherId].name;
  var hmac       = buffer.slice(index, index += 20);
  var ivLength   = buffer.readUInt8(index++);
  var iv         = null;
  if (ivLength > 0) {
    iv = buffer.slice(index, index += ivLength);
  }

  // 4. Extract the Key Info (if present) and select a key for decryption.
  var keyInfo = null;
  var keyInfoLen = buffer.readUInt8(index++);
  if (keyInfoLen) {
    keyInfo = buffer.slice(index, index += keyInfoLen);
  }

  // The key should be selected based on key info, ostensibly, but
  // for now we just use the first and probably only key provided.
  var decryptionKey = new Buffer(keys[0], 'base64');

  // 5. Decrypt the payload cipher-text using the selected cipher suite
  var payloadLength = buffer.readUInt16BE(index+=2);

  var payloadCipherText = null;
  payloadCipherText = buffer.slice(index, index += payloadLength);
  var decipher = crypto.createDecipheriv(cipher, decryptionKey, iv);
  var compressedText = decipher.update(payloadCipherText);

  // Debugging stuff
  //console.log("Token (base64): " + otk);
  //console.log("Buffer (hex): " + buffer.toString('hex'));
  //console.log("Buffer length is " + buffer.length);
  // 
  console.log("Decryption Key (hex) 0x" + decryptionKey.toString('hex'));
  //
  console.log("OTK Header: %s", otkHeader);
  console.log("Version: %d", otkVersion);
  console.log("Cipher Suite: %d (%s)", cipherId, cipher);
  console.log("SHA-1 HMAC (hex): 0x%s", hmac.toString('hex'));
  console.log("IV length: %d", ivLength);
  console.log("IV (hex): 0x%s", iv.toString('hex'));
  console.log("Key Info Length: %d", keyInfoLen);
  if (keyInfo) {
    console.log("Key Info (hex) : 0x%s", keyInfo.toString('hex'));
  }
  console.log("Payload length: %d", payloadLength);
  console.log("Payload ciphertext (hex): 0x%s", payloadCipherText.toString('hex'));
  console.log("Compressed text (hex): 0x%s" + compressedText.toString('hex'));

  // 6. Decompress the decrypted payload in accordance with RFC1950 and RFC1951
  var payload;
  zlib.inflate(compressedText, function (err, buf) {
    if (err) {
      cb(err);
    } else {
      payload = buf;
      console.log("Payload: \n%s", payload);
      initializeHmac();
    }
  });

  // 7. Initialize an HMAC using the SHA-1 algorithm and the following data 
  //    (order is important!)
  //    1. OTK Version
  //    2. Cipher Suite Value
  //    3. IV value
  //    4. Key info value (if present)
  //    5. Payload length (2 bytes, network byte order)
  function initializeHmac() {
    console.log("Initializing HMAC");
    var hmacTest = crypto.createHmac("sha1", decryptionKey);
    var tmpBuf = new Buffer(1);
    tmpBuf.writeUInt8(otkVersion, 0);
    console.log("OTK Version for HMAC test: 0x" + tmpBuf.toString('hex'));
    hmacTest.update(tmpBuf);
    tmpBuf.writeUInt8(cipherId, 0);
    console.log("Cipher ID for HMAC test: 0x" + tmpBuf.toString('hex'));
    hmacTest.update(tmpBuf);
    if (iv) {
      hmacTest.update(iv);
      console.log("IV value for HMAC test: 0x" + iv.toString('hex'));
    } else {
      console.log("IV value for HMAC test: doesn't exist");
    }
    if (keyInfo) {
      hmacTest.update(keyInfo);
      console.log("Key Info Value for HMAC test: 0x" + keyInfo.toString('hex'));
    } else {
      console.log("Key Info Value for HMAC test: doesn't exist");
    }
    var tmpBuf2 = new Buffer(2);
    //tmpBuf2.writeUInt16LE(payloadLength, 0);
    tmpBuf2.writeUInt16BE(payloadLength, 0);
    hmacTest.update(tmpBuf2);
    var hmacTestDigest = hmacTest.digest('hex');
    console.log("HMAC digest to test against: 0x" + hmacTestDigest);
    // cheating out here.. TODO the rest of the steps!
    cb(null, payload);
  }
}


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
    if (cipherID < 0 || cipherID >= cipherSuites.length) {
      return cb(new Error("Invalid cipher suite value " + cipherID + 
        ". Must be between 0 and " + cipherSuites.length));
    }
    cipher           = cipherSuites[cipherID].name;
    console.log("cipher: " + cipher);
    // generate IV 
    ivlength = cipherSuites[cipherID].ivlength;
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

exports.decode = decode;
exports.encode = encode;

