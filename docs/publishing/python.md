# Publishing the Python SDK to PyPI

**Registry:** [pypi.org](https://pypi.org)
**Package:** `settled-sdk`
**Current version:** `0.2.0`

---

## One-time setup

### 1. PyPI account

Create an account at [pypi.org](https://pypi.org). Generate an API token at **Account Settings → API tokens** scoped to the `settled-sdk` project.

### 2. Configure credentials

```sh
pip install hatch twine
```

Add to `~/.pypirc`:

```ini
[pypi]
username = __token__
password = pypi-<your-token>
```

---

## Publishing a new version

### 1. Bump the version

In `sdks/python/pyproject.toml`:

```toml
version = "0.2.0"
```

### 2. Build

```sh
cd sdks/python
hatch build
```

This produces `dist/settled_sdk-0.2.0.tar.gz` and `dist/settled_sdk-0.2.0-py3-none-any.whl`.

### 3. Publish

```sh
hatch publish
```

Or with twine:

```sh
twine upload dist/settled_sdk-0.2.0*
```

### 4. Verify

```sh
pip index versions settled-sdk
```

---

## Consumer usage

```sh
pip install settled-sdk
```

```python
from settled import SettledClient
client = SettledClient('localhost:50051')
```
