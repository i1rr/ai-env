# node-app fixture

Minimal Node.js project used by ai-env acceptance tests.

This tree intentionally has no runtime dependencies, no `node_modules/`,
and no lockfile so that:

1. It can be committed in full to the ai-env repository.
2. Tests can `git init` it on demand without touching a package registry.
3. It exercises the language detector's "node" classification by
   carrying a real `package.json` plus an `index.js` entry point.

Run locally with:

```bash
node index.js
node test.js
```
