# tests/fixtures

Static fixture repositories used by ai-env acceptance tests.

Each subdirectory is a minimal source tree for a single language. The
trees are intentionally committed without a `.git/` directory so they
can be `git init`-ed by tests on demand. This keeps the fixtures
portable across machines, avoids checking in submodules, and lets the
test harness pin the initial branch name and commit identity.

| Directory     | Language | Markers                                  |
|---------------|----------|------------------------------------------|
| `node-app/`   | Node.js  | `package.json`, `index.js`               |
| `python-app/` | Python   | `pyproject.toml`, `requirements.txt`, `main.py` |

Constraints intentionally enforced on every fixture:

1. No runtime dependencies. Tests must work in a sandbox with no
   network access, so neither `node_modules/` nor a virtualenv is
   required to exercise the fixture's smoke test.
2. No absolute paths anywhere in the tree.
3. Smoke tests use only the language's standard library and exit
   non-zero on failure so they double as CI sanity checks.
