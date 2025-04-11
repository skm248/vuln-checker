# vuln-checker

[![PyPI version](https://img.shields.io/pypi/v/vuln-checker?color=brightgreen)](https://pypi.org/project/vuln-checker/)
[![Python version](https://img.shields.io/pypi/pyversions/vuln-checker)](https://pypi.org/project/vuln-checker/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/skm248/vuln-checker?style=social)](https://github.com/skm248/vuln-checker/stargazers)

> ✨ A CLI tool to search CVEs from the NVD API based on product/version (CPE lookup).

---

## Features

- 🎯 Interactive mode to resolve multiple CPE matches
- 🔍 Filter CVEs by severity
- 💾 JSON/CSV/HTML output support
- ⚡ Caches results for faster repeated queries

---

## Installation

Install via pip:

```bash
pip install vuln-checker
```

Or from GitHub:

```bash
git clone https://github.com/skm248/vuln-checker.git
cd vuln-checker
pip install .
```

---

## Usage

### Single Product

```bash
vuln-checker --product tomcat --version 9.0.46 --severity HIGH --format csv
vuln-checker --product mysql --version 8.0.30 --refresh
```

---

## License

This project is licensed under the [MIT License](LICENSE) by Sai Krishna Meda.
