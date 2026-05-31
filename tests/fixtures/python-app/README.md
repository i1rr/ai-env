# python-app fixture

Minimal Python project used by ai-env acceptance tests.

This tree intentionally has no runtime dependencies, no virtualenv, and
an empty `requirements.txt` so that:

1. It can be committed in full to the ai-env repository.
2. Tests can `git init` it on demand without touching PyPI.
3. It exercises the language detector's "python" classification by
   carrying both a real `pyproject.toml` and a `requirements.txt`
   marker alongside a `main.py` entry point.

Run locally with:

```bash
python main.py
python test_main.py
```
