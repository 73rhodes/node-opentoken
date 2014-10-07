var assert = require('assert');
var otk = require('../opentoken.js');

/**
 * Test Case 1 (token generated from 3rd party OpenToken lib)
 */
var testToken = "T1RLAQLVVgI6nfAXif1wYQz-4Hoqqjpk-RCRhrYo_A3vfozy8DwQgX_iAAAgXtSyTiGFVbQGmJ7-USFFjaZYuPueXSr8Gl2W5APuFWw*";
var testData = "subject=foobar\nfoo=bar\nbar=baz";
var testPassword = "testPassword";
var cipherId = 2;
otk.decode(testToken, cipherId, testPassword, function (err, result) {
  assert.ifError(err);
  assert.equal(result.toString(), testData);
  process.stdout.write("Test 1: decode... OK\n");
});

/**
 * Test Case 2 (self generated from 3rd part OpenToken lib)
 */
var testToken2 = "T1RLAQIgGSTfOxeJB3DvBLmtTpeoJv4EuBDlc2cvMEYkYpWOa3Zl6WEMAAAwTJaEPU7Fh4Cud2k9M6XTFNon228y9N_-nFupGIr7tibxVLwkoGZILIb7eUlFEVxn";
var testData2 = "subject=foobar\nfizz=buzz\nqux=doo";
otk.decode(testToken2, cipherId, testPassword, function (err, result) {
  assert.ifError(err);
  assert.equal(result.toString(), testData2);
  process.stdout.write("Test 2: decode... OK\n");
});

/**
 * Test Case 3 Encode & Decode
 */
otk.encode(testData2, cipherId, testPassword, function (err, token) {
  assert.ifError(err);
  otk.decode(token, cipherId, testPassword, function (err, data) {
    assert.equal(data, testData2);
    process.stdout.write("Test 3: encode/decode... OK\n");
  });
});

/**
 * Test Case 4 Decode w wrong cipherID
 */
otk.encode(testData2, cipherId, testPassword, function (err, token) {
  assert.ifError(err);
  otk.decode(token, cipherId+1, testPassword, function (err, data) {
    if (err) {
      assert.ok( (/doesn\'t match/).test(err.message) );
      process.stdout.write("Test 4: decode error... OK\n");
    } else {
      assert.fail(null, "Error", "Expected an error");
    }
  });
});


/**
 *
 */
var otkapi = new otk.OpenTokenAPI(cipherId, testPassword);
// token containing minimum required keys (subject, not-before, not-on-or-after, renew-until)
var token3 = "T1RLAQJp8VBj2gcTNiHHMzf5W0xDiqMIQRA0g2wmp6U9FuwY7pj6wiuqAABQOx9-XSTI8w3uz4Jb40eb2GNoQ6K2MuJjo3ssfRboHuvRrFCHH40rPdywj-ZMmP-4chMJ1zWMC9AfBXQCwp8AQZMtOvK-podlhsI2nq1C0jU*";
otkapi.parseToken(token3, function (err, result) {
  process.stdout.write("Test 5: OpenTokenAPI::parseToken...");
  assert.ifError(err);
  assert.equal(result.subject, "foobar");
  process.stdout.write("OK\n");
});
