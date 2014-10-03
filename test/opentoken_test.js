var assert = require('assert');
var otk = require('../opentoken.js');

var testData = "foo=bar\nbar=baz";
var testKey = "a66C9MvM8eY4qJKyCXKW+w==";
var testToken = "UFRLAQK9THj0okLTUB663QrJFg5qA58IDhAb93ondvcx7sY6s44eszNqAAAga5W8Dc4XZwtsZ4qV3_lDI-Zn2_yadHHIhkGqNV5J9kw*"

otk.decode(testToken, testKey, function (err, result) {
  process.stdout.write("Testing decode...");
  assert.ifError(err);
  assert.equal(result.toString(), testData);
  process.stdout.write("OK\n");
});

/*
otk.encode(testData, testKey, null, function (err, result) {
  console.log(err);
  console.log(result);
});
*/
