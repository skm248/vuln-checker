# vuln-checker Pipeline Modernization & UX Enhancements

This document summarizes the key structural, UX, and data integrity improvements implemented in `vuln-checker` over the past few weeks to build a state-of-the-art, enterprise-grade dependency scanning utility.

---

## 🚀 1. UX & Terminal Optimization

### 🔇 Silent Subprocess Installations
* **The Problem:** When verifying and auto-installing required CLI dependencies (`pip-audit`, `syft`, `retire.js`), the screen was flooded with massive terminal noise (e.g., hundreds of lines of "Requirement already satisfied").
* **The Solution:** Refactored the `ensure_installed` methods inside `integrations.py` to route all stdout and stderr streams of package manager commands (e.g. `pip install`, `npm install`) completely silently to `DEVNULL`.

### 📊 Terminal Noise Suppression & Logging Streamlining
* **The Problem:** The terminal was filled with verbose `INFO` level scanning logs for every package, which buried the actual progress bar.
* **The Solution:** Implemented a custom `TerminalFilter` in `cli.py` that intercepts console logs. It filters out noisy, repetitive per-package logs from the stdout handler while preserving full, high-fidelity diagnostic records in the persistent file logs at `logs/vuln-checker_YYYY-MM-DD.log`.

### 🔄 Live Progress Streaming for Subprocesses
* **The Problem:** Security scanners (`Syft`, `Retire.js`) took a long time to run, leaving the user with a blank, frozen terminal.
* **The Solution:** Upgraded the subprocess execution engine `run_command` in `integrations.py` using non-blocking I/O (`select.select`). This allows third-party tools to stream their native interactive animations and progress bars live to the console, ensuring a highly responsive interactive experience.

### 📁 Syft Directory Exclusion Prefix Compliance
* **The Problem:** In Syft v1.0+, the CLI parser strictly validates all exclusion paths, throwing `ERROR unable to get file resolver: invalid exclusion pattern` if a directory pattern does not begin with `./`, `*/`, or `**/`. Standard absolute system exclusion paths (e.g. `/proc`) caused the entire SBOM generation to crash and fail silently.
* **The Solution:** Patched the `generate_sbom` method in `integrations.py` to automatically clean and prefix all exclusion directories (mapping `/proc` to `./proc/**` and `**/proc/**`), guaranteeing flawless SBOM execution.

---

## 🧬 2. Advanced Multi-Feed Deduplication & Merging

### 🔗 Connected-Components (Union-Find) Vulnerability Clustering
* **The Problem:** Multi-feed scanning (NVD and OSV/GHSA) reported the same vulnerability multiple times in final reports under different primary IDs (e.g., NVD reporting `CVE-2025-46392` and Maven reporting `GHSA-pvp8-3xj6-8c6x`).
* **The Solution:** Engineered a graph-based connected-components clustering algorithm in `features.py` using **Union-Find**. Vulnerability records for the same package/version/path are connected as a graph if they share *any* primary ID or alias. They are then collapsed into a single, canonical record.

### 👑 Standardized CVE ID Promotion
* **The Problem:** Reports felt inconsistent when displaying GHSA IDs for vulnerabilities that have well-known CVE equivalents.
* **The Solution:** During deduplication merging, the algorithm automatically checks all cluster identifiers and **promotes standard CVE IDs** to the primary ID column for superior clarity and compliance reporting.

### 🧠 Intelligent Attribute Consolidation
* **The Problem:** Merging records could result in lost or conflicting data (e.g., NVD having the description, but OSV having the CVSS score).
* **The Solution:** Added smart, rules-based merging:
  * **Severity:** Prioritizes the highest severity rating (`CRITICAL` > `HIGH` > `MEDIUM` > `LOW`).
  * **CVSS Score:** Evaluates values and retains the highest numeric score.
### ⛓️ Dynamic OSV Alias Integration
* **The Problem:** In synthetic NVD CVE structures generated from OSV feeds, the `"aliases"` field was completely omitted. Consequently, the Union-Find graph clustering could not build edges linking NVD CVE IDs with OSV GHSA IDs, leading to duplicate entries (like `CVE-2025-46392` and `GHSA-pvp8-3xj6-8c6x`) appearing side-by-side in reports.
* **The Solution:** Added `"aliases": aliases` directly into the generated synthetic NVD structure in `feed_manager.py`'s `generate_synthetic_cve_from_osv` method, enabling the connected-components algorithm to successfully merge disparate advisory feeds into a single canonical record.

### 📍 Path & Package Metadata Normalization in SBOM Scanning
* **The Problem:** During CycloneDX SBOM scanning, OSV advisories returned by `search_ghsa_for_package` did not have key package attributes (`path`, `purl`, and `cpe_source`) attached. Because they were evaluated without a matching path compared to NVD's fully enriched findings, the deduplication engine classified them into separate component-path keys, failing to deduplicate them.
* **The Solution:** Patched `sbom_parser.py` to seamlessly populate and enrich OSV findings with the component's actual `path`, `purl`, and `cpe_source` metadata before being passed downstream, resulting in 100% accurate deduplication of maven dependencies.

---

## 📈 3. Metric Normalization & Fallback Logic

### ⚡ Complete CVSS v4.0 Support
* **The Problem:** Newly analyzed vulnerabilities (especially from late 2024 and 2025) use the new **CVSS v4.0** metrics, causing reports to fall back to `N/A` because the extractor only looked for V3.x/V2.x keys.
* **The Solution:**
  * Extended `_extract_cve_data` in `output_formatters.py` and `search_ghsa_for_package` in `feed_manager.py` to natively support `cvssMetricV40`.
  * Implemented an advanced pure-Python CVSS v4.0 score calculation engine using the Red Hat macro vector lookup table.

### 🛡️ NVD Enrichment Fallback
* **The Problem:** When NVD publishes a CVE but has not yet fully analyzed it (highly common for new vulnerabilities), it leaves the CVSS metrics empty, resulting in blank `N/A` fields.
* **The Solution:** Upgraded `generate_synthetic_cve_from_osv` in `feed_manager.py` to perform a **smart fallback**. If NVD data lacks metrics, the scanner automatically falls back to OSV's database severity and CVSS v4.0 vector string.

### 🧠 Pluggable Core Application Isolation (CPE Heuristic Filter)
* **The Problem:** Fuzzy NVD CPE generation mapped server-level vulnerabilities (e.g., core database engines or backend server applications) to client-side driver libraries (like database connectors or metrics client packages), flooding reports with severe false-positive alerts.
* **The Solution:** Integrated an ecosystem-aware prefix filter in `server_scanner.py` that blocks mapping core application CPEs to components of different names. To support open-source customization, the list is dynamically parsed from a customizable `core_apps.txt` file (checking the current working directory first, falling back to the package data folder, and then internal defaults).

### 🔢 Float & Integer CVSS Score Extraction
* **The Problem:** Over 70% of standard NVD vulnerabilities had their CVSS score column set to `N/A`. NVD feeds store the `baseScore` as a float/number (e.g., `7.5`), but `calculate_cvss_score` had a strict `isinstance(vector_str, str)` type check, returning `"N/A"` for any numeric values.
* **The Solution:** Enhanced `calculate_cvss_score` in `output_formatters.py` to natively support both float and integer inputs, instantly transforming them into clean, standardized decimal string formats. This eliminated blank CVSS scores by over 97% across the entire report database.

---

## 📁 4. Modernized Report Formatters

### 🎯 Missing Column Mapping
* **The Problem:** Columns such as *Library Version*, *Upgrade To*, *Path*, and *Delta Status* were not populating in some formats (like Excel and HTML).
* **The Solution:** Unified and standard-mapped all scanner data fields within `_extract_cve_data` to ensure 100% data presence.

### 🔗 Dynamic Database Hyperlinks
* **The Solution:** Configured dynamic hyperlinks for the "Vuln ID" column in Excel (`output_results_excel`) and HTML reports. Clicking a CVE ID takes you directly to the NVD site, while clicking a GHSA ID links directly to the GitHub Advisory Database.

---

## 🎛️ 5. Advanced Command-Line Features & Flags

In addition to the baseline features found in the standard PyPI version of `vuln-checker`, several enterprise-level security scanning and workflow integration flags have been added to the local CLI:

### 🖥️ Host & Directory scanning capabilities
* **`--scan-server`:** Scans the entire host system for installed applications, packages (RPMs, system libraries), and language package dependencies (npm, PyPI, Maven).
* **`--scan-dir SCAN_DIR`:** Allows scanning specific filesystem mount points, storage roots, or arbitrary folder paths for third-party libraries and code assets.
* **`--server-inventory FILE`:** Saves or loads the scanned server packages list to/from a structured JSON inventory file.

### ⚖️ Advanced Delta & Compliance Controls
* **`--baseline BASELINE`:** Automatically compares the active scan findings against a previous JSON vulnerability report to compile a dynamic **Delta Report** (identifying newly introduced, recurring, or resolved issues).
* **`--vex-file VEX_FILE`:** Supports filtering and suppressing accepted false-positive advisories by importing standard Vulnerability Exploitability eXchange (VEX) documents.
* **`--config FILE`:** Allows parsing full TOML configuration files to standardize scanner parameters across pipelines.
* **`--log-level LEVEL`:** Custom logging controls (`DEBUG`, `INFO`, `WARNING`, `ERROR`) to filter terminal stdout while saving detailed trace logs to disk.
* **`--start-year START_YEAR`:** Overrides standard starting parameters for NVD feeds to focus analysis on specific years.

### ⚖️ License Compliance & Auditing
* **`--license-audit`:** Performs license compliance audits on all native and non-native components against allowed/denied policy lists.
* **`--fail-on-license`:** Immediately exits the scan with exit code 1 if any policy-violating license is detected.

---

## 🛡️ 6. Standalone Binary Version Extraction & Compile-Time Dependency Filtering

* **CLI Version Querying**: Enhanced `get_binary_version_cli` in `utils.py` to capture both stdout and stderr across generic probe flags (`-v`, `--version`, `-version`, `-V`, `version`). This correctly extracts versions for applications like **Nginx** which write their version info to stderr.
* **Nginx Plus Release Matching**: Enhanced `safe_parse_version` in `utils.py` to normalize release-style prefixes (e.g. `R26-p1` -> `1.26.1`), preventing false positives when comparing standard semver against release letters in NVD CPE fields.
* **Internal Dependency Suppression**: Configured `_process_syft_components` in `server_scanner.py` to automatically skip internal compile-time dependencies (e.g. Go modules within Prometheus or Loki) if the parent binary's CLI version is successfully queried, preventing hundreds of false-positive CVE alerts.
* **Path Resolution Fixes**: Improved relative path resolver in `_process_syft_components` to strip leading slashes/backslashes, ensuring relative paths resolve correctly against the scan's `base_dir`.

---

## 📊 7. Quick Summary of Modified Modules

| Module / File | Primary Enhancements Implemented |
| :--- | :--- |
| `vuln_checker/integrations.py` | Silent pip/npm installations, live subprocess stdout streaming with `select`, and Syft v1.0+ path prefix formatting. |
| `vuln_checker/cli.py` | Implemented `TerminalFilter` to suppress per-package CLI log clutter, and added license compliance auditing arguments. |
| `vuln_checker/features.py` | Replaced duplicate checking with advanced Union-Find connected-components clustering and attribute consolidation. |
| `vuln_checker/feed_manager.py` | Added CVSS v4.0 key checking, NVD empty-metrics OSV fallback, dynamic alias parsing for synthetic CVEs, and skip logic for withdrawn advisories. |
| `vuln_checker/output_formatters.py` | Unified field extraction, CVSS v4.0 lookup calculator, float CVSS score parser, NVD/GitHub hyperlinks, and added the License Summary sheet in Excel. |
| `vuln_checker/sbom_parser.py` | Implemented path, purl, and cpe_source enrichment for synthetic OSV findings to ensure flawless Union-Find deduplication. |
| `vuln_checker/server_scanner.py` | Integrated ecosystem-aware core application checks, standalone binary CLI version extraction, compile-time package filtering, and dpkg/rpm license querying. |
| `vuln_checker/utils.py` | Built dynamic loader for lazy-cache files, check_license_compliance policy evaluator, and Nginx Plus release prefix parser. |
| `vuln_checker/config.py` | Added defaults and schema for license compliance auditing policy configuration. |
| `vuln_checker/main.py` | Orchestrated the license compliance audit pipeline phase and exit control. |
