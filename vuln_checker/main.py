import argparse
import requests
import json
import csv
import os
import gzip
import shutil

from pathlib import Path
from argparse import RawDescriptionHelpFormatter

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json"
CPE_API = f"{NVD_API_BASE}/cpes/2.0"
CVE_API = f"{NVD_API_BASE}/cves/2.0"

CPE_DICT_URL = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"
CPE_DICT_PATH = Path("data/official-cpe-dictionary_v2.3.xml.gz")
CPE_DICT_EXTRACTED = Path("data/official-cpe-dictionary_v2.3.xml")

def ensure_cpe_dictionary(force_refresh=False):
    os.makedirs("data", exist_ok=True)
    if force_refresh or not CPE_DICT_PATH.exists():
        print("🔄 Downloading official CPE dictionary...")
        with requests.get(CPE_DICT_URL, stream=True) as r:
            r.raise_for_status()
            with open(CPE_DICT_PATH, 'wb') as f:
                shutil.copyfileobj(r.raw, f)
        print("✅ Download complete.")

    if force_refresh or not CPE_DICT_EXTRACTED.exists():
        print("📦 Extracting CPE dictionary...")
        with gzip.open(CPE_DICT_PATH, 'rb') as f_in:
            with open(CPE_DICT_EXTRACTED, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        print("✅ Extraction complete.")

def search_cpes(product, version):
    params = {"keywordSearch": f"{product} {version}"}
    response = requests.get(CPE_API, params=params)
    results = response.json().get("products", [])
    cpe_list = []
    for product in results:
        cpe_uri = product.get("cpe", {}).get("cpeName")
        title = product.get("cpe", {}).get("title", {}).get("en", "")
        if cpe_uri:
            cpe_list.append((cpe_uri, title))
    return cpe_list

def fetch_cves(cpe_uri, severity=None):
    params = {"cpeName": cpe_uri}
    if severity:
        params["cvssV3Severity"] = severity.upper()
    response = requests.get(CVE_API, params=params)
    cve_items = response.json().get("vulnerabilities", [])
    return cve_items

def output_results(cves, output_format="json", output_file=None):
    if output_format == "json":
        formatted = []
        for cve in cves:
            data = {
                "id": cve["cve"]["id"],
                "url": f"https://nvd.nist.gov/vuln/detail/{cve['cve']['id']}",
                "published": cve["cve"]["published"],
                "lastModified": cve["cve"]["lastModified"],
                "cvssScore": cve["cve"].get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A"),
                "severity": cve["cve"].get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "N/A"),
                "description": cve["cve"]["descriptions"][0]["value"]
            }
            formatted.append(data)

        if output_file:
            with open(output_file, "w", encoding='utf-8') as f:
                json.dump(formatted, f, indent=2)
            print(f"✅ JSON results written to {output_file}")
        else:
            print(json.dumps(formatted, indent=2))

    elif output_format == "csv":
        if not cves:
            print("No CVEs found.")
            return
        keys = ["id", "published", "lastModified", "cvssScore", "severity", "description"]
        with open(output_file or "output.csv", "w", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for cve in cves:
                cve_id = cve["cve"]["id"]
                cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                cve_data = {
                    "id": f'=HYPERLINK("{cve_url}", "{cve_id}")',
                    "published": cve["cve"]["published"],
                    "lastModified": cve["cve"]["lastModified"],
                    "cvssScore": cve["cve"].get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A"),
                    "severity": cve["cve"].get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "N/A"),
                    "description": cve["cve"]["descriptions"][0]["value"]
                }
                writer.writerow(cve_data)
        print(f"✅ CSV results written to {output_file or 'output.csv'} with Excel HYPERLINK formulas.")




def main():
    # parser = argparse.ArgumentParser(
    # description=textwrap.dedent("""\
    # 🔍 vuln-checker: Search CVEs by CPE product/version

    #     Features:
    #     - Fetch matching CPEs using product & version
    #     - Interactive selection if multiple CPEs found
    #     - Pull CVEs from NVD (filter by severity)
    #     - Export results in JSON or CSV
    #     - Auto-download & manage official CPE dictionary

    #     Example:
    #       vuln-checker --product jquery --version 1.11.3 --severity HIGH --format csv
    #       vuln-checker --product lodash --version 3.5.0 --refresh
    # """)
    # )

#     parser = argparse.ArgumentParser(
#     description=(
#         "🔍 vuln-checker: Search CVEs by CPE product/version\n\n"
#         "Features:\n"
#         "- Fetch matching CPEs using product & version\n"
#         "- Interactive selection if multiple CPEs found\n"
#         "- Pull CVEs from NVD (filter by severity)\n"
#         "- Export results in JSON or CSV\n"
#         "- Auto-download & manage official CPE dictionary\n\n"
#         "Example:\n"
#         "  vuln-checker --product jquery --version 1.11.3 --severity HIGH --format csv\n"
#         "  vuln-checker --product lodash --version 3.5.0 --refresh"
#     )
# )


    parser = argparse.ArgumentParser(
    description="""\
🔍 vuln-checker: Search CVEs by CPE product/version

Features:
- Fetch matching CPEs using product & version
- Interactive selection if multiple CPEs found
- Pull CVEs from NVD (filter by severity)
- Export results in JSON or CSV
- Auto-download & manage official CPE dictionary

Example:
  vuln-checker --product tomcat --version 9.0.46 --severity HIGH --format csv
  vuln-checker --product mysql --version 8.0.30 --refresh
""",
    formatter_class=RawDescriptionHelpFormatter
)


    parser.add_argument("--product", required=True, help="Product name (e.g., jquery)")
    parser.add_argument("--version", required=True, help="Product version (e.g., 1.11.3)")
    parser.add_argument("--severity", help="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format (default: json)")
    parser.add_argument("--output", help="Output file name (default: print to terminal)")
    parser.add_argument(
        "--refresh", 
        action="store_true", 
        help="Force refresh of official CPE dictionary (re-download from NVD)"
    )


    args = parser.parse_args()

    ensure_cpe_dictionary(force_refresh=args.refresh)

    print(f"\n🔎 Searching for CPEs for {args.product} {args.version} ...")
    cpes = search_cpes(args.product, args.version)

    if not cpes:
        print("❌ No CPEs found.")
        return

    print("\nFound CPE matches:")
    for idx, (uri, title) in enumerate(cpes):
        print(f"  [{idx + 1}] {title} → {uri}")

    if len(cpes) > 1:
        choice = int(input("\nMultiple CPEs found. Select one [1 - {}]: ".format(len(cpes))))
        cpe_uri = cpes[choice - 1][0]
    else:
        cpe_uri = cpes[0][0]

    print(f"\n🛡️ Fetching CVEs for {cpe_uri} ...\n")
    cves = fetch_cves(cpe_uri, severity=args.severity)

    output_results(cves, args.format, args.output)
