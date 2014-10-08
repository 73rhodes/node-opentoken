var assert = require('assert');
var otk = require('../opentoken.js');

var yesterday = new Date(Date.now() - (24 * 3600 * 1000));
var tomorrow  = new Date(Date.now() + (24 * 3600 * 1000));
var testPassword = "testPassword";
var cipherId = 2;
var otkapi = new otk.OpenTokenAPI(cipherId, testPassword);

// Test decode (token generated from 3rd party OpenToken lib)
!(function () {
  var testToken = "T1RLAQLVVgI6nfAXif1wYQz-4Hoqqjpk-RCRhrYo_A3vfozy8DwQgX_iAAAgXtSyTiGFVbQGmJ7-USFFjaZYuPueXSr8Gl2W5APuFWw*";
  var testData = "subject=foobar\nfoo=bar\nbar=baz";
  otk.decode(testToken, cipherId, testPassword, function (err, result) {
    process.stdout.write("Test decode (3rd party token)... ");
    assert.ifError(err);
    assert.equal(result.toString(), testData);
    process.stdout.write("OK\n");
  });
}());

// Test decode (self generated from 3rd part OpenToken lib)
!(function () {
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
!(function () {
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

// Test Decode w wrong cipherID
!(function () {
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


// Test OpenTokenAPI.parseToken
!(function () {
  // token w required keys (subject, not-before, not-on-or-after, renew-until)
  var token = "T1RLAQJp8VBj2gcTNiHHMzf5W0xDiqMIQRA0g2wmp6U9FuwY7pj6wiuqAABQOx9-XSTI8w3uz4Jb40eb2GNoQ6K2MuJjo3ssfRboHuvRrFCHH40rPdywj-ZMmP-4chMJ1zWMC9AfBXQCwp8AQZMtOvK-podlhsI2nq1C0jU*";
  otkapi.parseToken(token, function (err, result) {
    process.stdout.write("Test OpenTokenAPI::parseToken... ");
    assert.ifError(err);
    assert.equal(result.subject, "foobar");
    process.stdout.write("OK\n");
  });
}());

// Test OpenTokenAPI.createToken
!(function () {
  var testData = {subject: "foobar"};
  otkapi.createToken(testData, function (err, result) {
    process.stdout.write("Test OpenTokenAPI::createToken... ");
    assert.ifError(err);
    process.stdout.write("OK\n");
  });
}());

// Test OpenTokenAPI.createToken & parseToken
!(function () {
  var testData = {subject: "foobar"};
  otkapi.createToken(testData, function (err, result) {
    assert.ifError(err);
    otkapi.parseToken(result, function (err, data) {
      process.stdout.write("Test OpenTokenAPI::createToken/parseToken... ");
      assert.ifError(err);
      assert.equal(data.subject, "foobar");
      process.stdout.write("OK\n");
    });
  });
}());

// try parsing a token earlier than allowed 
!(function() {
  var testData = "subject=foobar\nnot-before=" + tomorrow.toISOString();
  otk.encode(testData, cipherId, testPassword, function (err, token) {
    assert.ifError(err);
    otkapi.parseToken(token, function (err, data) {
      process.stdout.write("Testing token prior to not-before date... ");
      if (err) {
        assert.ok( (/Must not use this token before/i).test(err.message) );
        process.stdout.write("OK\n");
      } else {
        assert.fail(data, null, "Expected error 'Must not use this token...'");
      }
    });
  });
}());

// try parsing a token that's expired
!(function () {
  var testData = "subject=fizzbuzz\nnot-on-or-after=" + yesterday.toISOString();
  otk.encode(testData, cipherId, testPassword, function (err, token) {
    assert.ifError(err);
    otkapi.parseToken(token, function (err, data) {
      process.stdout.write("Testing expired token... ");
      if (err) {
        assert.ok( (/this token has expired/i).test(err.message) );
        process.stdout.write("OK\n");
      } else {
        assert.fail(data, null, "Expected error, token expired");
      }
    });
  });
}());

// try parsing a token that's past its renewal date
!(function () {
  var testData  = "subject=foobar\nrenew-until=" + yesterday.toISOString();
  otk.encode(testData, cipherId, testPassword, function (err, token) {
    assert.ifError(err);
    otkapi.parseToken(token, function (err, data) {
      process.stdout.write("Testing token past renewal date... ");
      if (err) {
        assert.ok( (/this token is past its renewal/i).test(err.message) );
        process.stdout.write("OK\n");
      } else {
        assert.fail(data, null, "Expected error. Token is past renewal data.");
      }
    });
  });
}());

// try parsing token where not-before > not-on-or-after
!(function () {
  var testData = "subject=quxdoo\nnot-before=" + tomorrow.toISOString() +
    "\nnot-on-or-after=" + yesterday.toISOString();
  otk.encode(testData, cipherId, testPassword, function (err, token) {
    assert.ifError(err);
    otkapi.parseToken(token, function (err, data) {
      process.stdout.write("Testing invalid before/after dates... ");
      if (err) {
        assert.ok( (/should be above/i).test(err.message) );
        process.stdout.write("OK\n");
      } else {
        assert.fail(data, null, "Expected error, before/after dates invalid");
      }
    });
  });
}());
