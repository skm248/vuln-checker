# import requests
# import json
# import csv
# import logging
# import os
# import time
# import getpass
# import re
# import subprocess
# import sys
# import importlib.metadata
# import tempfile
# import textwrap


# from subprocess import DETACHED_PROCESS  # ✅ Needed for Windows-safe subprocess
# from argparse import ArgumentParser, RawDescriptionHelpFormatter
# from jinja2 import Environment, FileSystemLoader
# from collections import Counter
# from packaging import version
# from vuln_checker import __version__
# print(f"vuln-checker version: {__version__}")


# # Configuration
# NVD_API_BASE = "https://services.nvd.nist.gov/rest/json"
# CPE_API = f"{NVD_API_BASE}/cpes/2.0"
# CVE_API = f"{NVD_API_BASE}/cves/2.0"

# API_KEY = os.environ.get("NVD_API_KEY")  # Try to get from environment variable

# logging.basicConfig(level=logging.WARNING)

# try:
#     import tomllib  # Python 3.11+
# except ModuleNotFoundError:
#     import tomli as tomllib  # Python < 3.11

# def get_project_version():
#     toml_path = os.path.join(os.path.dirname(__file__), "../pyproject.toml")
#     try:
#         with open(toml_path, "rb") as f:
#             data = tomllib.load(f)
#             return data["project"]["version"]
#     except Exception as e:
#         print(f"⚠️ Could not read version from pyproject.toml: {e}")
#         return "unknown"

# def get_installed_version(package_name="vuln-checker"):
#     try:
#         return importlib.metadata.version(package_name)
#     except importlib.metadata.PackageNotFoundError:
#         return None

# def get_latest_version_from_pypi(package_name="vuln-checker"):
#     try:
#         response = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=5)
#         if response.status_code == 200:
#             return response.json()["info"]["version"]
#     except Exception as e:
#         print(f"⚠️ Failed to fetch version from PyPI: {e}")
#     return None

# def check_for_upgrade(package_name="vuln-checker", auto_confirm=False):
#     installed = get_installed_version(package_name)
#     latest = get_latest_version_from_pypi(package_name)

#     if not installed:
#         print(f"⚠️ '{package_name}' not installed via pip. Cannot upgrade.")
#         return

#     if not latest:
#         print("❌ Could not retrieve latest version from PyPI.")
#         return

#     v_installed = version.parse(installed)
#     v_latest = version.parse(latest)

#     if v_installed > v_latest:
#         print(f"🛑 You have a newer version ({v_installed}) than PyPI ({v_latest}). Skipping upgrade.")
#         return
#     elif v_installed == v_latest:
#         print(f"✅ You're already using the latest version: {installed}")
#         return

#     print(f"🚀 New version available: {latest} (current: {installed})")
#     if auto_confirm or input("Do you want to upgrade? [y/N]: ").strip().lower() == 'y':
#         print("🔁 Exiting and upgrading in a subprocess...")

#         upgrade_script = textwrap.dedent(f"""
#             import subprocess, time, sys
#             time.sleep(2)
#             subprocess.run([
#                 r"{sys.executable}", "-m", "pip", "install",
#                 "--upgrade", "--force-reinstall", "--no-cache-dir", "--user", "{package_name}"
#             ], check=True)
#         """)

#         # Write to a temporary .py file
#         with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as tmp:
#             tmp.write(upgrade_script)
#             script_path = tmp.name

#         # Launch the subprocess with DETACHED_PROCESS flag to allow self-upgrade
#         subprocess.Popen([sys.executable, script_path], creationflags=DETACHED_PROCESS)

#         print("✅ Upgrade process started in background. Please re-run the tool after upgrade completes.")
#         sys.exit(0)

# def search_cpe_from_user_input(product, version):
#     global API_KEY
#     headers = {"apiKey": API_KEY} if API_KEY else {}

#     # Try more intelligent query
#     query = f"{product} {version}"
#     params = {"keywordSearch": query, "resultsPerPage": 100}

#     response = requests.get(CPE_API, headers=headers, params=params)
#     if response.status_code != 200:
#         ...
    
#     products = response.json().get("products", [])
#     print(f"🔎 Matched {len(products)} CPEs for '{query}'")

#     results = []
#     for entry in products:
#         cpe = entry.get("cpe", {}).get("cpeName")
#         title = entry.get("titles", [{}])[0].get("title", cpe)
#         if cpe:
#             results.append((cpe, title))
#     return results

# def fetch_cves(cpe_uri, severity=None):
#     global API_KEY  # Declare API_KEY as global to allow reassignment
#     headers = {"apiKey": API_KEY} if API_KEY else {}
#     #print(f"Debug: Using API Key for CVE fetch: {API_KEY or 'None'}")  # Debug print
#     params = {"cpeName": cpe_uri, "resultsPerPage": 2000}
#     if severity:
#         params["cvssV3Severity"] = severity.upper()
#     all_cves = []
#     start_index = 0

#     while True:
#         params["startIndex"] = start_index
#         response = requests.get(CVE_API, headers=headers, params=params)
#         if response.status_code != 200:
#             print(f"❌ Failed to fetch CVEs: {response.status_code} - {response.text}")
#             if response.status_code == 403 and not API_KEY:
#                 print("⚠️ NVD API key is required. Set NVD_API_KEY environment variable or enter it below.")
#                 api_key_input = getpass.getpass("Enter NVD API Key: ")
#                 if api_key_input:
#                     API_KEY = api_key_input
#                     headers = {"apiKey": API_KEY}
#                     response = requests.get(CVE_API, headers=headers, params=params)
#                     if response.status_code != 200:
#                         print(f"❌ Failed with provided key: {response.status_code} - {response.text}")
#                         break
#                 else:
#                     break
#             break
#         data = response.json()
#         vulnerabilities = data.get("vulnerabilities", [])
#         all_cves.extend(vulnerabilities)
#         total_results = data.get("totalResults", 0)
#         if start_index + len(vulnerabilities) >= total_results:
#             break
#         start_index += 2000
#         time.sleep(0.5)  # Respect rate limits

#     return all_cves

# def output_results(cves, output_format="json", output_file=None):
#     if not cves:
#         print("⚠️ No CVEs found.")
#         return

#     if output_format == "json":
#         # Transform cves to include id as a dictionary with url
#         enriched_cves = []
#         for item in cves:
#             cve = item["cve"]
#             product = item.get("product", "Unknown")
#             cve_id = cve["id"]
#             url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
#             enriched_cve = {
#                 "product": product,
#                 "id": {"value": cve_id, "url": url},
#                 "published": cve.get("published"),
#                 "lastModified": cve.get("lastModified"),
#                 "cvssScore": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A"),
#                 "severity": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "N/A"),
#                 "description": cve.get("descriptions", [{}])[0].get("value", "N/A")
#             }
#             enriched_cves.append({"cve": enriched_cve})
#         with open(output_file or "output.json", "w", encoding="utf-8") as f:
#             json.dump(enriched_cves, f, indent=2)
#         print(f"✅ JSON report written to {output_file or 'output.json'}")

#     elif output_format == "csv":
#         keys = ["product", "id", "published", "lastModified", "cvssScore", "severity", "description"]
#         with open(output_file or "output.csv", "w", newline='', encoding='utf-8') as f:
#             writer = csv.DictWriter(f, fieldnames=keys)
#             writer.writeheader()
#             for item in cves:
#                 cve = item["cve"]
#                 product = item.get("product", "Unknown")
#                 cve_id = cve["id"]
#                 url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
#                 writer.writerow({
#                     "product": product,
#                     "id": f'=HYPERLINK("{url}", "{cve_id}")',
#                     "published": cve.get("published"),
#                     "lastModified": cve.get("lastModified"),
#                     "cvssScore": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A"),
#                     "severity": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "N/A"),
#                     "description": cve.get("descriptions", [{}])[0].get("value", "N/A")
#                 })
#         print(f"✅ CSV report written to {output_file or 'output.csv'}")

# def generate_html_report(cves, output_file="report.html"):
#     env = Environment(loader=FileSystemLoader("./vuln_checker/templates"))
#     template = env.get_template("template.html")

#     rows = []
#     severity_counter = Counter()
#     for item in cves:
#         cve = item["cve"]
#         product = item.get("product", "Unknown")
#         cve_id = cve["id"]
#         url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
#         metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
#         severity = metrics.get("baseSeverity", "UNKNOWN")
#         score = metrics.get("baseScore", "N/A") if metrics.get("baseScore") else "N/A"
#         description = cve.get("descriptions", [{}])[0].get("value", "N/A")
#         published = cve.get("published", "N/A")
#         severity_counter[severity] += 1

#         rows.append({
#             "product": product,
#             "id": cve_id,
#             "url": url,
#             "severity": severity,
#             "score": score,
#             "description": description,
#             "published": published
#         })

#     html = template.render(cves=rows, severity_counts=severity_counter)
#     with open(output_file, "w", encoding="utf-8") as f:
#         f.write(html)
#     print(f"📄 HTML report written to {output_file}")

# def main():
#     parser = ArgumentParser(
#         description="""\
# 🔍 vuln-checker: Search CVEs by CPE product/version

# Pre-requisite:
# Check the: https://github.com/skm248/vuln-checker/blob/main/README.md for the NVD_API_KEY section for more information.

# Features:
# - Fetch matching CPEs using product & versions
# - Batch mode to scan multiple product,versions via CSV
# - Interactive selection if multiple CPEs found
# - Pull CVEs from NVD (filter by severity)
# - Export results in JSON, CSV, or HTML
# - Auto-download & manage official CPE dictionary

# Examples:
#   vuln-checker --input-csv products.csv --severity High,Critical --format html --output report.html
#   vuln-checker --products "jquery:1.11.3,lodash:3.5.0" --format csv --output output.csv

#   A Single Product-version pair like:
#   vuln-checker --products "jquery:1.11.3" --format json

#   Multiple versions for a product like:
#   vuln-checker --products "jquery:1.11.3,1.11.5" --format json

#   Multiple products, each with single or multiple versions like:
#   vuln-checker --products "jquery:1.11.3,1.11.5 lodash:3.5.0" --format json

#   Sample csv like:
#   products,versions
#   jquery,1.11.3,1.11.5
#   lodash,3.5.0

# """,
#         formatter_class=RawDescriptionHelpFormatter
#     )

#     # Mutually exclusive group requiring one of input-csv or products
#     group = parser.add_mutually_exclusive_group()
#     group.add_argument("--input-csv", help="Path to CSV file with 'product' and 'version' columns")
#     group.add_argument("--products", help="Product/version mapping. Supports one or multiple products and versions. E.g., 'jquery:1.11.3,1.11.5 lodash:3.5.0,3.59'")    
#     parser.add_argument("--severity", help="Filter by comma-separated severities (e.g. LOW,HIGH,CRITICAL)")
#     parser.add_argument("--format", choices=["json", "csv", "html"], default="json", help="Output format")
#     parser.add_argument("--output", help="Output filename (e.g. report.html, results.csv, output.json)")
#     parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
#     parser.add_argument("--upgrade", action="store_true", help="Upgrade vuln-checker to the latest version on PyPI")
#     parser.add_argument("--yes", action="store_true", help="Auto-confirm prompts like upgrade confirmation")


#     args = parser.parse_args()

#     # Handle --upgrade early
#     if args.upgrade:
#         check_for_upgrade(auto_confirm=args.yes)
#         return

#     # Validate input only if --upgrade or --version were not used
#     if not args.input_csv and not args.products:
#         parser.error("One of --input-csv or --products is required unless using --upgrade or --version.")

#     all_cves = []

#     if args.input_csv:
#         try:
#             with open(args.input_csv, newline='', encoding='utf-8') as csvfile:
#                 reader = csv.reader(csvfile)
#                 header = next(reader)

#                 if len(header) < 2 or header[0].lower() != "products":
#                     print("❌ CSV must have a 'product' column followed by one or more versions.")
#                     return

#                 for row in reader:
#                     if len(row) < 2:
#                         print(f"⚠️ Skipping invalid row: {row}")
#                         continue

#                     product = row[0].strip()
#                     versions = [v.strip() for v in row[1:] if v.strip()]
                    
#                     if not product or not versions:
#                         print(f"⚠️ Skipping incomplete row: {row}")
#                         continue

#                     for version in versions:
#                         print(f"🔍 Searching CPE for {product} {version}")
#                         cpes = search_cpe_from_user_input(product, version)

#                         if not cpes:
#                             print(f"❌ No CPEs found for {product} {version}")
#                             continue

#                         if len(cpes) == 1:
#                             cpe_uri = cpes[0][0]
#                         else:
#                             print(f"Multiple CPEs found for {product} {version}:")
#                             for idx, (uri, title) in enumerate(cpes):
#                                 print(f"  [{idx+1}] {title} → {uri}")
#                             try:
#                                 choice = int(input(f"Select CPE [1-{len(cpes)}]: "))
#                                 cpe_uri = cpes[choice - 1][0]
#                             except (ValueError, IndexError):
#                                 print("❌ Invalid choice. Skipping.")
#                                 continue

#                         severities = [s.strip().upper() for s in args.severity.split(",")] if args.severity else [None]
#                         for sev in severities:
#                             print(f"🛡️ Fetching CVEs for {cpe_uri} (Severity: {sev or 'ALL'})")
#                             cves = fetch_cves(cpe_uri, severity=sev)
#                             for cve in cves:
#                                 cve["product"] = f"{product}:{version}"
#                             all_cves.extend(cves)

#         except FileNotFoundError:
#             print(f"❌ CSV file '{args.input_csv}' not found.")
#             return
#         except Exception as e:
#             print(f"❌ Error reading CSV: {e}")
#             return

#     # Handle --products input
#     else:
#         product_map = {}
#         for group in args.products.strip().split():
#             if ':' not in group:
#                 print(f"❌ Invalid format in: {group}. Expected 'product:version[,version,...]'")
#                 continue

#             product, version_str = group.split(":", 1)
#             versions = [v.strip() for v in version_str.split(",") if v.strip()]

#             if not versions:
#                 print(f"⚠️ No versions specified for {product}, skipping.")
#                 continue

#             if product in product_map:
#                 product_map[product].extend(versions)
#             else:
#                 product_map[product] = versions


#         for product, versions in product_map.items():
#             for version in versions:
#                 print(f"🔍 Searching CPE for {product} {version}")
#                 cpes = search_cpe_from_user_input(product, version)

#                 if not cpes:
#                     print(f"❌ No CPEs found for {product} {version}")
#                     continue

#                 if len(cpes) == 1:
#                     cpe_uri = cpes[0][0]
#                 else:
#                     print(f"Multiple CPEs found for {product} {version}:")
#                     for idx, (uri, title) in enumerate(cpes):
#                         print(f"  [{idx+1}] {title} → {uri}")
#                     try:
#                         choice = int(input(f"Select CPE [1-{len(cpes)}]: "))
#                         cpe_uri = cpes[choice - 1][0]
#                     except (ValueError, IndexError):
#                         print("❌ Invalid choice. Skipping.")
#                         continue

#                 severities = [s.strip().upper() for s in args.severity.split(",")] if args.severity else [None]
#                 for sev in severities:
#                     print(f"🛡️ Fetching CVEs for {cpe_uri} (Severity: {sev or 'ALL'})")
#                     cves = fetch_cves(cpe_uri, severity=sev)
#                     for cve in cves:
#                         cve["product"] = f"{product}:{version}"
#                     all_cves.extend(cves)

#     if args.format == "html":
#         generate_html_report(all_cves, args.output or "report.html")
#     else:
#         output_results(all_cves, args.format, args.output)

# if __name__ == "__main__":
#     main()


import platform
import requests
import json
import csv
import logging
import os
import time
import getpass
import re
import subprocess
import sys
import importlib.metadata
import tempfile
import textwrap
import pathlib

if platform.system() == "Windows":
    from subprocess import DETACHED_PROCESS  # ✅ Needed for Windows-safe subprocess
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from jinja2 import Environment, FileSystemLoader
from collections import Counter
from packaging import version
from importlib import resources
from vuln_checker import __version__
print(f"vuln-checker version: {__version__}")


# Configuration
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json"
CPE_API = f"{NVD_API_BASE}/cpes/2.0"
CVE_API = f"{NVD_API_BASE}/cves/2.0"

API_KEY = os.environ.get("NVD_API_KEY")  # Try to get from environment variable

logging.basicConfig(level=logging.WARNING)

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # Python < 3.11

def get_project_version():
    toml_path = os.path.join(os.path.dirname(__file__), "../pyproject.toml")
    try:
        with open(toml_path, "rb") as f:
            data = tomllib.load(f)
            return data["project"]["version"]
    except Exception as e:
        print(f"⚠️ Could not read version from pyproject.toml: {e}")
        return "unknown"

def get_installed_version(package_name="vuln-checker"):
    try:
        return importlib.metadata.version(package_name)
    except importlib.metadata.PackageNotFoundError:
        return None

def get_latest_version_from_pypi(package_name="vuln-checker"):
    try:
        response = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=5)
        if response.status_code == 200:
            return response.json()["info"]["version"]
    except Exception as e:
        print(f"⚠️ Failed to fetch version from PyPI: {e}")
    return None

def check_for_upgrade(package_name="vuln-checker", auto_confirm=False):
    installed = get_installed_version(package_name)
    latest = get_latest_version_from_pypi(package_name)

    if not installed:
        print(f"⚠️ '{package_name}' not installed via pip. Cannot upgrade.")
        return

    if not latest:
        print("❌ Could not retrieve latest version from PyPI.")
        return

    v_installed = version.parse(installed)
    v_latest = version.parse(latest)

    if v_installed > v_latest:
        print(f"🛑 You have a newer version ({v_installed}) than PyPI ({v_latest}). Skipping upgrade.")
        return
    elif v_installed == v_latest:
        print(f"✅ You're already using the latest version: {installed}")
        return

    print(f"🚀 New version available: {latest} (current: {installed})")
    if auto_confirm or input("Do you want to upgrade? [y/N]: ").strip().lower() == 'y':
        print("🔁 Exiting and upgrading in a subprocess...")

        upgrade_script = textwrap.dedent(f"""
            import subprocess, time, sys
            time.sleep(2)
            subprocess.run([
                r"{sys.executable}", "-m", "pip", "install",
                "--upgrade", "--force-reinstall", "--no-cache-dir", "--user", "{package_name}"
            ], check=True)
        """)

        # Write to a temporary .py file
        with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as tmp:
            tmp.write(upgrade_script)
            script_path = tmp.name

        # Launch the subprocess with DETACHED_PROCESS flag to allow self-upgrade
        subprocess.Popen([sys.executable, script_path], creationflags=DETACHED_PROCESS)

        print("✅ Upgrade process started in background. Please re-run the tool after upgrade completes.")
        sys.exit(0)

def resolve_cpes_file_path(filename):
    # Try absolute path first
    if os.path.isfile(filename):
        return filename
    
    # Try relative to main.py (installed package dir)
    pkg_dir = os.path.dirname(__file__)
    fallback = os.path.join(pkg_dir, filename)
    if os.path.isfile(fallback):
        return fallback

    # Try relative to current working directory
    cwd_fallback = os.path.join(os.getcwd(), filename)
    if os.path.isfile(cwd_fallback):
        return cwd_fallback

    return None

def lookup_cpe_from_txt(product, version, cpes_file):
    product = product.lower()
    version = version.lower()
    if not os.path.exists(cpes_file):
        return None
    with open(cpes_file, "r", encoding="utf-8") as f:
        for line in f:
            cpe = line.strip()
            if not cpe.startswith("cpe:2.3:a:"):
                continue
            parts = cpe.split(":")
            if len(parts) >= 6:
                cpe_product = parts[4].lower()
                cpe_version = parts[5].lower()
                if cpe_product == product and cpe_version == version:
                    return cpe
    return None

def search_cpe_from_user_input(product, version):
    global API_KEY
    headers = {"apiKey": API_KEY} if API_KEY else {}

    query = f"{product} {version}"
    params = {"keywordSearch": query, "resultsPerPage": 100}

    print(f"🌐 Querying NVD CPE API → {CPE_API} with {params}")
    response = requests.get(CPE_API, headers=headers, params=params)

    try:
        data = response.json()
    except ValueError:
        print(f"❌ NVD API returned non-JSON (status {response.status_code}): {response.text[:200]}")
        return []

    products = data.get("products", [])
    print(f"🔎 Matched {len(products)} CPEs for '{query}'")

    results = []
    for entry in products:
        cpe = entry.get("cpe", {}).get("cpeName")
        title = entry.get("cpe", {}).get("titles", [{}])[0].get("title", cpe)
        if cpe:
            results.append((cpe, title))
    return results

def fetch_cves(cpe_uri, severity=None):
    global API_KEY  # Declare API_KEY as global to allow reassignment
    headers = {"apiKey": API_KEY} if API_KEY else {}
    #print(f"Debug: Using API Key for CVE fetch: {API_KEY or 'None'}")  # Debug print
    params = {"cpeName": cpe_uri, "resultsPerPage": 2000}
    if severity:
        params["cvssV3Severity"] = severity.upper()
    all_cves = []
    start_index = 0

    while True:
        params["startIndex"] = start_index
        response = requests.get(CVE_API, headers=headers, params=params)
        if response.status_code != 200:
            print(f"❌ Failed to fetch CVEs: {response.status_code} - {response.text}")
            if response.status_code == 403 and not API_KEY:
                print("⚠️ NVD API key is required. Set NVD_API_KEY environment variable or enter it below.")
                api_key_input = getpass.getpass("Enter NVD API Key: ")
                if api_key_input:
                    API_KEY = api_key_input
                    headers = {"apiKey": API_KEY}
                    response = requests.get(CVE_API, headers=headers, params=params)
                    if response.status_code != 200:
                        print(f"❌ Failed with provided key: {response.status_code} - {response.text}")
                        break
                else:
                    break
            break
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        all_cves.extend(vulnerabilities)
        total_results = data.get("totalResults", 0)
        if start_index + len(vulnerabilities) >= total_results:
            break
        start_index += 2000
        time.sleep(0.5)  # Respect rate limits

    return all_cves

def output_results(cves, output_format="json", output_file=None):
    if not cves:
        print("⚠️ No CVEs found.")
        return

    if output_format == "json":
        # Transform cves to include id as a dictionary with url
        enriched_cves = []
        for item in cves:
            cve = item["cve"]
            product = item.get("product", "Unknown")
            cve_id = cve["id"]
            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            enriched_cve = {
                "product": product,
                "id": {"value": cve_id, "url": url},
                "published": cve.get("published"),
                "lastModified": cve.get("lastModified"),
                "cvssScore": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A"),
                "severity": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "N/A"),
                "description": cve.get("descriptions", [{}])[0].get("value", "N/A")
            }
            enriched_cves.append({"cve": enriched_cve})
        with open(output_file or "output.json", "w", encoding="utf-8") as f:
            json.dump(enriched_cves, f, indent=2)
        print(f"✅ JSON report written to {output_file or 'output.json'}")

    elif output_format == "csv":
        keys = ["product", "id", "published", "lastModified", "cvssScore", "severity", "description"]
        with open(output_file or "output.csv", "w", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for item in cves:
                cve = item["cve"]
                product = item.get("product", "Unknown")
                cve_id = cve["id"]
                url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                writer.writerow({
                    "product": product,
                    "id": f'=HYPERLINK("{url}", "{cve_id}")',
                    "published": cve.get("published"),
                    "lastModified": cve.get("lastModified"),
                    "cvssScore": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A"),
                    "severity": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "N/A"),
                    "description": cve.get("descriptions", [{}])[0].get("value", "N/A")
                })
        print(f"✅ CSV report written to {output_file or 'output.csv'}")

def generate_html_report(cves, output_file="report.html"):
    # env = Environment(loader=FileSystemLoader("./vuln_checker/templates"))
    # template = env.get_template("template.html")
    with resources.path("vuln_checker.templates", "template.html") as tpl_path:
        env = Environment(loader=FileSystemLoader(tpl_path.parent))
        template = env.get_template("template.html")

    rows = []
    severity_counter = Counter()
    for item in cves:
        cve = item["cve"]
        product = item.get("product", "Unknown")
        cve_id = cve["id"]
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
        severity = metrics.get("baseSeverity", "UNKNOWN")
        score = metrics.get("baseScore", "N/A") if metrics.get("baseScore") else "N/A"
        description = cve.get("descriptions", [{}])[0].get("value", "N/A")
        published = cve.get("published", "N/A")
        severity_counter[severity] += 1

        rows.append({
            "product": product,
            "id": cve_id,
            "url": url,
            "severity": severity,
            "score": score,
            "description": description,
            "published": published
        })

    html = template.render(cves=rows, severity_counts=severity_counter)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"📄 HTML report written to {output_file}")

def main():
    parser = ArgumentParser(
        description="""\
🔍 vuln-checker: Search CVEs by CPE product/version

Pre-requisite:
Check the: https://github.com/skm248/vuln-checker/blob/main/README.md for the NVD_API_KEY section for more information.

Features:
- Fetch matching CPEs using product & versions
- Batch mode to scan multiple product,versions via CSV
- Interactive selection if multiple CPEs found
- Pull CVEs from NVD (filter by severity)
- Export results in JSON, CSV, or HTML
- Auto-download & manage official CPE dictionary

Examples:
  vuln-checker --input-csv products.csv --severity High,Critical --format html --output report.html
  vuln-checker --products "jquery:1.11.3 lodash:3.5.0" --format csv --output output.csv

  A Single Product-version pair like:
  vuln-checker --products "jquery:1.11.3" --format json

  Multiple versions for a product like:
  vuln-checker --products "jquery:1.11.3,1.11.5" --format json

  Multiple products, each with single or multiple versions like:
  vuln-checker --products "jquery:1.11.3,1.11.5 lodash:3.5.0" --format json

  Sample csv like:
  products,versions
  jquery,1.11.3,1.11.5
  lodash,3.5.0

""",
        formatter_class=RawDescriptionHelpFormatter
    )

    # Mutually exclusive group requiring one of input-csv or products
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--input-csv", help="Path to CSV file with 'product' and 'version' columns")
    group.add_argument("--products", help="Product/version mapping. Supports one or multiple products and versions. E.g., 'jquery:1.11.3,1.11.5 lodash:3.5.0,3.5.9'")
    group.add_argument("--cpes-file", help="Optional path to a text file with CPEs (used to avoid NVD lookup if matched)")    
    parser.add_argument("--severity", help="Filter by comma-separated severities (e.g. LOW,HIGH,CRITICAL)")
    parser.add_argument("--format", choices=["json", "csv", "html"], default="json", help="Output format")
    parser.add_argument("--output", help="Output filename (e.g. report.html, results.csv, output.json)")
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument("--upgrade", action="store_true", help="Upgrade vuln-checker to the latest version on PyPI")
    parser.add_argument("--yes", action="store_true", help="Auto-confirm prompts like upgrade confirmation")


    args = parser.parse_args()

    # Handle --upgrade early
    if args.upgrade:
        check_for_upgrade(auto_confirm=args.yes)
        return

    # Validate input only if --upgrade or --version were not used
    if not args.input_csv and not args.products and not args.cpes_file:
        parser.error("One of --input-csv or --products or --cpes-file is required unless using --upgrade or --version.")

    all_cves = []

    if args.input_csv:
        try:
            with open(args.input_csv, newline='', encoding='utf-8') as csvfile:
                reader = csv.reader(csvfile)
                header = next(reader)

                if len(header) < 2 or header[0].lower() != "products":
                    print("❌ CSV must have a 'product' column followed by one or more versions.")
                    return

                for row in reader:
                    if len(row) < 2:
                        print(f"⚠️ Skipping invalid row: {row}")
                        continue

                    product = row[0].strip()
                    versions = [v.strip() for v in row[1:] if v.strip()]
                    
                    if not product or not versions:
                        print(f"⚠️ Skipping incomplete row: {row}")
                        continue

                    for version in versions:
                        print(f"🔍 Searching CPE for {product} {version}")
                        cpe_uri = lookup_cpe_from_txt(product, version, args.cpes_file or "cpes_list.txt")
                        if cpe_uri:
                            print(f"✅ Found in cpes.txt: {cpe_uri}")
                        else:
                            cpes = search_cpe_from_user_input(product, version)
                            if not cpes:
                                print(f"❌ No CPEs found for {product} {version}")
                                continue

                            if len(cpes) == 1:
                                cpe_uri = cpes[0][0]
                            else:
                                print(f"Multiple CPEs found for {product} {version}:")
                                for idx, (uri, title) in enumerate(cpes):
                                    print(f"  [{idx+1}] {title} → {uri}")
                                try:
                                    choice = int(input(f"Select CPE [1-{len(cpes)}]: "))
                                    cpe_uri = cpes[choice - 1][0]
                                except (ValueError, IndexError):
                                    print("❌ Invalid choice. Skipping.")
                                    continue

                        severities = [s.strip().upper() for s in args.severity.split(",")] if args.severity else [None]
                        for sev in severities:
                            print(f"🛡️ Fetching CVEs for {cpe_uri} (Severity: {sev or 'ALL'})")
                            cves = fetch_cves(cpe_uri, severity=sev)
                            for cve in cves:
                                cve["product"] = f"{product}:{version}"
                            all_cves.extend(cves)

        except FileNotFoundError:
            print(f"❌ CSV file '{args.input_csv}' not found.")
            return
        except Exception as e:
            print(f"❌ Error reading CSV: {e}")
            return

    # Handle --products input
    elif args.products:
        product_map = {}
        for group in args.products.strip().split():
            if ':' not in group:
                print(f"❌ Invalid format in: {group}. Expected 'product:version[,version,...]'")
                continue

            product, version_str = group.split(":", 1)
            versions = [v.strip() for v in version_str.split(",") if v.strip()]

            if not versions:
                print(f"⚠️ No versions specified for {product}, skipping.")
                continue

            if product in product_map:
                product_map[product].extend(versions)
            else:
                product_map[product] = versions


        for product, versions in product_map.items():
            for version in versions:
                print(f"🔍 Searching CPE for {product} {version}")
                cpe_uri = lookup_cpe_from_txt(product, version, args.cpes_file or "cpes_list.txt")
                if cpe_uri:
                    print(f"✅ Found in cpes.txt: {cpe_uri}")
                else:
                    cpes = search_cpe_from_user_input(product, version)
                    if not cpes:
                        print(f"❌ No CPEs found for {product} {version}")
                        continue

                    if len(cpes) == 1:
                        cpe_uri = cpes[0][0]
                    else:
                        print(f"Multiple CPEs found for {product} {version}:")
                        for idx, (uri, title) in enumerate(cpes):
                            print(f"  [{idx+1}] {title} → {uri}")
                        try:
                            choice = int(input(f"Select CPE [1-{len(cpes)}]: "))
                            cpe_uri = cpes[choice - 1][0]
                        except (ValueError, IndexError):
                            print("❌ Invalid choice. Skipping.")
                            continue

                severities = [s.strip().upper() for s in args.severity.split(",")] if args.severity else [None]
                for sev in severities:
                    print(f"🛡️ Fetching CVEs for {cpe_uri} (Severity: {sev or 'ALL'})")
                    cves = fetch_cves(cpe_uri, severity=sev)
                    for cve in cves:
                        cve["product"] = f"{product}:{version}"
                    all_cves.extend(cves)

    # Handle --cpes-file directly
    elif args.cpes_file:
        cpes_file_path = resolve_cpes_file_path(args.cpes_file)
        if not cpes_file_path:
            print(f"❌ File not found: {args.cpes_file}")
            return

        with open(cpes_file_path, "r", encoding="utf-8") as f:  # ✅ use the resolved path
            cpe_uris = [line.strip() for line in f if line.strip().startswith("cpe:2.3:a:")]

        if not cpe_uris:
            print("⚠️ No valid CPEs found in file.")
            return

        severities = [s.strip().upper() for s in args.severity.split(",")] if args.severity else [None]
        for cpe_uri in cpe_uris:
            for sev in severities:
                print(f"🛡️ Fetching CVEs for {cpe_uri} (Severity: {sev or 'ALL'})")
                cves = fetch_cves(cpe_uri, severity=sev)
                parts = cpe_uri.split(":")
                if len(parts) >= 6:
                    product_version = f"{parts[4]}:{parts[5]}"
                else:
                    product_version = cpe_uri  # fallback

                for cve in cves:
                    cve["product"] = product_version
                all_cves.extend(cves)


    if args.format == "html":
        generate_html_report(all_cves, args.output or "cve_report.html")
    else:
        output_results(all_cves, args.format, args.output)

if __name__ == "__main__":
    main()