/**
 * Cipher Suites supported by OpenToken specification
 * The order of these is important!
 */
var crypto = require('crypto');

var ciphers = [
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

function generateKey(password, salt, cipherId) {
  salt = salt || new Buffer([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]);
  if (!cipherId || cipherId < 0 || cipherId >= ciphers.length) {
    return null;
  }
  var cipher = ciphers[cipherId];
  var iterations = 1000;
  console.log(
    "Generate a %d-bit key (%d bytes) from password '%s' using %s cipher",
    cipher.keysize,
    cipher.keysize / 8,
    password,
    cipher.name
  );
  var derivedKey = crypto.pbkdf2Sync(password, salt, iterations, cipher.keysize/8);
  console.log("encode:derivedKey = " + derivedKey.toString('base64'));
  return derivedKey;
}


exports.ciphers = ciphers;
exports.generateKey  = generateKey;
