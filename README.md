# vuln-checker

[![PyPI version](https://img.shields.io/pypi/v/vuln-checker?color=brightgreen)](https://pypi.org/project/vuln-checker/)
[![Python version](https://img.shields.io/pypi/pyversions/vuln-checker)](https://pypi.org/project/vuln-checker/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/skm248/vuln-checker?style=social)](https://github.com/skm248/vuln-checker/stargazers)

> ✨ A CLI tool to search CVEs from the NVD API based on product/version (CPE lookup).

---

## Features

- 🎯 Interactive mode to resolve multiple CPE matches
- 📂 Batch mode to scan multiple products via CSV
- 🔍 Filter CVEs by severity
- 💾 JSON/CSV output support
- ⚡ Caches results for faster repeated queries

---

## Installation

Install via pip (after publishing):

```bash
pip install vuln-checker
```

Or from GitHub (after cloning):

```bash
git clone https://github.com/skm248/vuln-checker.git
cd vuln-checker
pip install .
```

---

## Usage

### Single Product

```bash
vuln-checker --product jquery --version 1.11.3 --severity HIGH
```

---

## License

This project is licensed under the [MIT License](LICENSE) by Sai Krishna Meda.
