var assert = require('assert');
var otk = require('../lib/token.js');

var yesterday = new Date(Date.now() - (24 * 3600 * 1000));
var tomorrow  = new Date(Date.now() + (24 * 3600 * 1000));
var testPassword = "testPassword";
var cipherId = 2;

// Test decode (token generated from 3rd party OpenToken lib)
(function () {
  var testToken = "T1RLAQLVVgI6nfAXif1wYQz-4Hoqqjpk-RCRhrYo_A3vfozy8DwQgX_iAAAgXtSyTiGFVbQGmJ7-USFFjaZYuPueXSr8Gl2W5APuFWw*";
  var testData = "subject=foobar\nfoo=bar\nbar=baz";
  otk.decode(testToken, cipherId, testPassword, function (err, result) {
    process.stdout.write("Test decode (3rd party token)... ");
    assert.ifError(err);
    assert.equal(result.toString(), testData);
    process.stdout.write("OK\n");
  });
}());

// Test decode (self generated from 3rd party OpenToken lib)
(function () {
  var testToken = "T1RLAQIgGSTfOxeJB3DvBLmtTpeoJv4EuBDlc2cvMEYkYpWOa3Zl6WEMAAAwTJaEPU7Fh4Cud2k9M6XTFNon228y9N_-nFupGIr7tibxVLwkoGZILIb7eUlFEVxn";
  var testData = "subject=foobar\nfizz=buzz\nqux=doo";
  otk.decode(testToken, cipherId, testPassword, function (err, result) {
    process.stdout.write("Test decode (self-generated token)... ");
    assert.ifError(err);
    assert.equal(result.toString(), testData);
    process.stdout.write("OK\n");
  });
}());

// Test Encode & Decode
(function () {
  var testData = "subject=foobar\nfizz=buzz\nqux=doo";
  otk.encode(testData, cipherId, testPassword, function (err, token) {
    assert.ifError(err);
    otk.decode(token, cipherId, testPassword, function (err, data) {
      process.stdout.write("Test encode/decode... ");
      assert.equal(data, testData);
      process.stdout.write("OK\n");
    });
  });
}());

// Test Encode & Decode of array values
(function () {
  var testData = "subject=foo\ngroups=[foo,bar]";
  otk.encode(testData, cipherId, testPassword, function (err, token) {
    assert.ifError(err);
    otk.decode(token, cipherId, testPassword, function (err, data) {
      process.stdout.write("Test encode/decode of array values... ");
      assert.equal(data, testData);
      process.stdout.write("OK\n");
    });
  });
}());

// Test Decode with wrong cipherID
(function () {
  var testData = "subject=foobar\nfizz=buzz\nqux=doo";
  otk.encode(testData, cipherId, testPassword, function (err, token) {
    assert.ifError(err);
    otk.decode(token, cipherId+1, testPassword, function (err, data) {
      process.stdout.write("Test decode error... ");
      if (err) {
        assert.ok( (/doesn\'t match/).test(err.message) );
        process.stdout.write("OK\n");
      } else {
        assert.fail(null, "Error", "Expected an error");
      }
    });
  });
}());
