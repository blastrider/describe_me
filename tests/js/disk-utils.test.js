#!/usr/bin/env node
const assert = require('assert');
const { usagePercentFromBytes, widthFromBytes } = require('../../src/application/web/assets/js/disk-utils.js');

assert.strictEqual(usagePercentFromBytes(1_000, 250), 75);
assert.strictEqual(widthFromBytes(1_000, 250), '75.0%');
assert.strictEqual(usagePercentFromBytes(0, 0), 0);
assert.strictEqual(widthFromBytes(0, 0), '0.0%');

console.log('disk-utils tests passed');
