// Minimal entry point for the Node.js fixture used by ai-env acceptance
// tests. It deliberately avoids any runtime dependency so the fixture
// tree can be checked into the repository without a node_modules/
// directory and without a lockfile that depends on the registry.
"use strict";

function greet(name) {
  if (typeof name !== "string" || name.length === 0) {
    return "hello, world";
  }
  return "hello, " + name;
}

function main() {
  const who = process.argv[2] || "world";
  // eslint-disable-next-line no-console
  console.log(greet(who));
}

if (require.main === module) {
  main();
}

module.exports = { greet };
