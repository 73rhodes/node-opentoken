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


module.exports = cipherSuites;

