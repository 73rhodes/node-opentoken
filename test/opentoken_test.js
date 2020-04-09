var assert = require('assert');
var crypto = require('crypto');
var token  = require('../lib/token.js');
var OpenTokenAPI = require('../opentoken.js').OpenTokenAPI;

var yesterday = new Date(Date.now() - (24 * 3600 * 1000));
var tomorrow  = new Date(Date.now() + (24 * 3600 * 1000));
var testPassword = "testPassword";
var cipherId = 2;
var otkapi = new OpenTokenAPI(cipherId, testPassword);


// Test OpenTokenAPI.parseToken
(function () {
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
(function () {
  var testData = {subject: "foobar"};
  otkapi.createToken(testData, function (err, result) {
    process.stdout.write("Test OpenTokenAPI::createToken... ");
    assert.ifError(err);
    process.stdout.write("OK\n");
  });
}());

// Test OpenTokenAPI.createToken & parseToken
(function () {
  var testData = {subject: "fooba=r"};
  otkapi.createToken(testData, function (err, result) {
    assert.ifError(err);
    otkapi.parseToken(result, function (err, data) {
      process.stdout.write("Test OpenTokenAPI::createToken/parseToken... ");
      assert.ifError(err);
      assert.equal(data.subject, "fooba=r");
      process.stdout.write("OK\n");
    });
  });
}());

// try parsing a token earlier than allowed 
(function() {
  var testData = "subject=foobar\nnot-before=" + tomorrow.toISOString();
  token.encode(testData, cipherId, testPassword, function (err, token) {
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
(function () {
  var testData = "subject=fizzbuzz\nnot-on-or-after=" + yesterday.toISOString();
  token.encode(testData, cipherId, testPassword, function (err, token) {
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
(function () {
  var testData  = "subject=foobar\nrenew-until=" + yesterday.toISOString();
  token.encode(testData, cipherId, testPassword, function (err, token) {
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
(function () {
  var testData = "subject=quxdoo\nnot-before=" + tomorrow.toISOString() +
    "\nnot-on-or-after=" + yesterday.toISOString();
  token.encode(testData, cipherId, testPassword, function (err, token) {
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

// try obfuscating and deobfuscating a fixed password using fixed key and fixed iv
(function () {
  const testKey = "Mz7BARLx2suTqhyQqbHahietYpxLl9CX";
  const testIv = "LFWiaEouIf8=";
  const testPassword = "2FederateTestPassword";
  const obfuscatedPassword = token.obfuscatePassword(testPassword, testKey, testIv);
  process.stdout.write("Test OpenTokenAPI::obfuscatePassword... ");
  assert.equal(obfuscatedPassword, "KMLP/evZZ95Lzyy7ZcnoY+igubViZyFl");
  process.stdout.write("OK\n");
  process.stdout.write("Test OpenTokenAPI::deobfuscatePassword... ");
  const deobfuscatedPassword = token.deobfuscatePassword(obfuscatedPassword, testKey, testIv);
  assert.equal(deobfuscatedPassword, testPassword);
  process.stdout.write("OK\n");
}());

// returns a base64-encoded string of "numberBytes" random bytes
function randomBytes(numberBytes) {
  return crypto.randomBytes(numberBytes).toString('base64');
}

// try obfuscating and deobfuscating a random password using a random key and a random iv
(function () {
  const testKey = randomBytes(24);
  const testIv = randomBytes(8);
  const testPassword = randomBytes(20);
  process.stdout.write("Test OpenTokenAPI::obfuscatePassword and OpenTokenAPI::deobfuscatePassword... ");
  const obfuscatedPassword = token.obfuscatePassword(testPassword, testKey, testIv);
  const deobfuscatedPassword = token.deobfuscatePassword(obfuscatedPassword, testKey, testIv);
  assert.equal(deobfuscatedPassword, testPassword);
  process.stdout.write("OK\n");
}());

// TODO try instantiating OpenTokenAPI with different options
//      and testing pass / fail cases
