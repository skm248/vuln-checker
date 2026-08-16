# Build and Install Guide (DEV / Internal Use)

This guide explains how to build the `vuln-checker` package into a wheel (`.whl`) file and how to forcefully install/reinstall it in your environment for development or internal testing.

---

## 🛠️ 1. How to Build the Wheel (`.whl`)

The project uses `setuptools` and `build` to package the codebase.

### Prerequisites
Make sure you have `build` and `wheel` installed in your Python environment:
```bash
pip install --upgrade build wheel
```

### Build Command
Run the following command from the root directory of the project (where `pyproject.toml` is located):
```bash
python -m build
```

This will compile the package and place the generated build files in the `dist/` directory:
- `dist/vuln_checker-*.whl` (The Wheel package)
- `dist/vuln-checker-*.tar.gz` (Source distribution)

---

## 🚀 2. How to Forcefully Install the Wheel

When testing changes locally, you want to force pip to reinstall the package even if the version number hasn't changed.

### Force Reinstall (Standard)
To forcefully reinstall the generated wheel and verify all dependencies:
```bash
pip install --force-reinstall dist/vuln_checker-0.5.5.3-py3-none-any.whl
```

### Force Reinstall (Fast/Offline - Skip Dependency Resolving)
If dependencies are already installed and you only want to reinstall the core code instantly without hitting PyPI:
```bash
pip install --force-reinstall --no-deps dist/vuln_checker-0.5.5.3-py3-none-any.whl
```

> [!NOTE]
> Replace `vuln_checker-0.5.5.3-py3-none-any.whl` with the actual name of the generated file in your `dist/` folder if the version has changed.

---

## 💡 3. Alternative: Editable Mode for Active Development

If you are actively making changes to the source code and don't want to rebuild and reinstall the `.whl` every time, you can install the package in **editable mode**:

```bash
pip install -e .
```

This links the active source directory to your Python environment. Any changes you make to the `.py` files take effect immediately without requiring a rebuild or reinstall.
