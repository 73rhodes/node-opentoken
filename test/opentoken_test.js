var assert = require('assert');
var otk = require('../opentoken.js');

/**
 * Test Case 1 (IETF Draft Interop Test 1)
 * This test data in the IETF draft spec contains errors in the
 * first character, making the header literal "PTK" instead of "OTK".
 * This one has the proper 'OTK' header literal.
 */
var testToken = "T1RLAQK9THj0okLTUB663QrJFg5qA58IDhAb93ondvcx7sY6s44eszNqAAAga5W8Dc4XZwtsZ4qV3_lDI-Zn2_yadHHIhkGqNV5J9kw*"
var testData = "foo=bar\nbar=baz";
var testKey = "a66C9MvM8eY4qJKyCXKW+w=="; // from passwd generator function
otk.decode(testToken, testKey, function (err, result) {
  process.stdout.write("Testing decode...");
  assert.ifError(err);
  assert.equal(result.toString(), testData);
  process.stdout.write("OK\n");
});

/**
 * Test Case 2 (self generated from 3rd part OpenToken lib)
 */
var testToken2 = "T1RLAQLjjQ5X5syQ07anq_1m99BnDNTJexCNX35CAIIbj5A1kFp6vgn5AAAgyCcWB_xAGsUqiON2Sh4Yix5Ql8NV44MeWG4mbUKlRnE*";
var testKey2 = "c2JvSUgMTn1OqAeAjT0wgA=="; // from passwd generator function
var testData2 = "subject=foobar\nfoo=bar\nbar=baz";
otk.decode(testToken2, testKey2, function (err, result) {
  process.stdout.write("Testing decode 2...");
  assert.ifError(err);
  assert.equal(result.toString(), testData2);
  process.stdout.write("OK\n");
});

/**
 * Test Case 3 (Encode)
 */
var options = null;
otk.encode(testData2, testKey2, options, function (err, result) {
  process.stdout.write("Testing encode...");
  assert.ifError(err);
  assert.ok(result);
  process.stdout.write("OK\n");
});
