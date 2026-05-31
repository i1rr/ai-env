// Tiny self-contained smoke test for the Node fixture. Uses only the
// Node standard library (assert) so the fixture stays dependency-free
// and can be exercised by `node test.js` inside a sandbox that has no
// network access.
"use strict";

const assert = require("assert");
const { greet } = require("./index");

assert.strictEqual(greet("ai"), "hello, ai");
assert.strictEqual(greet(""), "hello, world");
assert.strictEqual(greet(undefined), "hello, world");

// eslint-disable-next-line no-console
console.log("node-app fixture: ok");
