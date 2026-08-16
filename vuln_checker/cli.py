import os
import sys
import logging
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from vuln_checker.config import Config

def get_version():
    """Get the package version from metadata"""
    try:
        from importlib.metadata import version
        return version("vuln-checker")
    except Exception:
        # Fallback: read from pyproject.toml for development mode
        try:
            import tomli
            pyproject_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "pyproject.toml")
            with open(pyproject_path, "rb") as f:
                pyproject = tomli.load(f)
                return pyproject.get("project", {}).get("version", "unknown")
        except Exception:
            return "unknown"

class TerminalFilter(logging.Filter):
    """Filters out granular package/CVE processing logs from the console to keep tqdm progress bar clean."""
    def filter(self, record):
        msg = record.getMessage()
        blocked_keywords = [
            "🔍 Processing:",
            "🔍 matching CPEs",
            "🔎 Detecting UI modules",
            "Running Retire.js on",
            "Running Syft discovery on",
            "⭕ ",
            "Attempt ",
            "Downloading https://",
            "Decompressed and saved feed",
            "will download",
            "will redownload",
            "is fresh, skipping download",
            "is older than 24h, refreshing",
            "Force update enabled: re-downloading",
            "missing, will download",
            "Checking for NVD feed updates",
            "Checking for OSV feed updates",
            "Year ",
            "NVD feeds into",
            "OSV feeds into",
            "OSV feed for ",
            "stale (",
            "Network error",
            "Resuming download",
            "Checking latest NVD modified",
            "Downloading latest NVD modified",
            "Non-retryable HTTP",
            "Exhausted retries",
            "Applying incremental updates",
            "Updated",
            "Incremental sync completed",
            "HTTP",
            "NVD modified delta feed",
            "delta feed",
            "Applying",
            "Decompressed and saved",
            "LOCAL & OFFLINE VULNERABILITY SCANNER"
        ]
        if any(kw in msg for kw in blocked_keywords):
            return False
        return True

def setup_logging(log_file: str, level: str = "INFO"):
    """Setup logging to file and console"""
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Use UTF-8 encoding for the file to handle emojis
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(log_level)
    
    # Console handler for real-time progress
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO) # Always show INFO in console by default
    console_handler.addFilter(TerminalFilter())
    
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger = logging.getLogger()
    logger.setLevel(log_level)
    # Remove existing handlers if any
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def validate_arguments(args):
    """Validate CLI arguments"""
    exclusive_count = sum([
        bool(args.scan_server),
        bool(args.scan_dir),
        args.sbom is not None,
        (hasattr(args, 'input_csv') and args.input_csv is not None),
        args.products is not None,
        args.cpes_file is not None,
    ])
    
    # Allow maintenance commands to run without a scan mode
    maintenance_mode = any([
        getattr(args, 'update_feeds', False),
        getattr(args, 'upgrade', False),
        getattr(args, 'migrate_cache', False)
    ])
    
    if exclusive_count == 0 and not maintenance_mode:
        raise ValueError(
            "One of --scan-server, --scan-dir, --sbom, --input-csv, "
            "--products, or --cpes-file is required."
        )
    
    if exclusive_count > 1:
        raise ValueError(
            "Only one of --scan-server, --scan-dir, --sbom, --input-csv, "
            "--products, or --cpes-file can be specified."
        )
    
    if args.sbom and not os.path.exists(args.sbom):
        raise FileNotFoundError(f"SBOM file not found: {args.sbom}")
    if args.input_csv and not os.path.exists(args.input_csv):
        raise FileNotFoundError(f"CSV file not found: {args.input_csv}")
    if args.cpes_file and not os.path.exists(args.cpes_file):
        raise FileNotFoundError(f"CPEs file not found: {args.cpes_file}")
    if args.scan_dir:
        for d in args.scan_dir:
            if not os.path.isdir(d):
                raise NotADirectoryError(f"Directory not found: {d}")
    
    os.makedirs(args.feed_dir, exist_ok=True)
    if args.output:
        output_dir = os.path.dirname(args.output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            
    # Validate format(s)
    valid_formats = {"json", "csv", "html", "excel"}
    if args.format:
        formats = [f.strip().lower() for f in args.format.split(",")]
        for f in formats:
            if f not in valid_formats:
                raise ValueError(
                    f"Invalid format '{f}'. Valid options are: json, csv, html, excel."
                )

def create_argument_parser(config: Config) -> ArgumentParser:
    """Create CLI argument parser"""
    parser = ArgumentParser(
        description="""\
🔍 vuln-checker: Search CVEs by CPE product/version with Enhanced SBOM Support

Features:
- Uses local NVD JSON feeds (no API dependency)
- Auto-updates feeds if older than 24 hours
- Parse CycloneDX-JSON SBOMs and detect vulnerabilities
- Fetch matching CPEs using product & versions
- Batch mode to scan multiple product,versions via CSV
- Export results in JSON, CSV, or HTML
- Supports excluding false-positive CPEs via an external excluded_cpes.txt file placed alongside the main script.

Examples:
    vuln-checker --update-feeds (Optional : --max-workers 5)
    vuln-checker --scan-server --format excel --output report.xlsx
    vuln-checker --scan-dir /home --format excel --output report.xlsx
    vuln-checker --input-csv products.csv --severity High,Critical --format html --output report.html
    vuln-checker --products "jquery:1.11.3 lodash:3.5.0" --format csv --output output.csv
    vuln-checker --sbom myfile.json --format html
    vuln-checker --sbom myfile.json --fast --max-workers 5 --severity Critical,High --format csv
""",
        formatter_class=RawDescriptionHelpFormatter,
    )
    
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--input-csv", help="CSV file of products and versions")
    mode_group.add_argument("--products", help="Products and versions string")
    mode_group.add_argument("--cpes-file", help="Path to file of CPEs")
    mode_group.add_argument("--sbom", help="Path to CycloneDX SBOM file (JSON)")
    mode_group.add_argument('--scan-server', action='store_true', help='Scan entire server for installed packages')    
    mode_group.add_argument("--scan-dir", nargs='+', help="Scan specific directories or mount points for packages (e.g. /mnt/rootfs /var/www)")
    
    feed_group = parser.add_argument_group("Feed Management")
    feed_group.add_argument('--update-feeds', action='store_true', help='Download the latest NVD JSON feeds')
    feed_group.add_argument('--force-update', action='store_true', help='Force re-download all feeds even if fresh')
    feed_group.add_argument('--no-update', action='store_true', help='Disable automatic downloading/updating of NVD/OSV feeds')
    feed_group.add_argument("--feed-dir", default=config.get("feed_dir", "nvd_feeds"), help=f"Directory for NVD feeds (default: {config.get('feed_dir', 'nvd_feeds')})")
    feed_group.add_argument('--start-year', type=int, help='Start year for NVD feeds (overrides NVD_FEED_START_YEAR)')
    
    perf_group = parser.add_argument_group("Performance")
    perf_group.add_argument("--fast", action="store_true", help="Fast mode: parallel processing with caching")
    
    # Calculate sensible default based on CPU cores
    cpu_cores = os.cpu_count() or 4
    suggested_workers = max(1, cpu_cores - 1)
    default_workers = config.get("max_workers", suggested_workers)
    
    perf_group.add_argument("--max-workers", type=int, default=default_workers, help=f"Number of parallel workers (default: {default_workers}, detected cores: {cpu_cores})")
    perf_group.add_argument("--max-components", type=int, help="Limit number of components to process")
    perf_group.add_argument("--no-remediation", action="store_true", help="Skip querying online registries (NPM, PyPI, APT) for remediation/upgrade versions")
    
    filter_group = parser.add_argument_group("Filtering")
    filter_group.add_argument("--severity", help="Severity filter (comma separated)")
    filter_group.add_argument("--skip-search", action="store_true", help="Skip components without existing CPEs")
    
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("--format", default="json", help="Report format(s) (comma-separated, choices: json, csv, html, excel)")
    output_group.add_argument("--output", help="Report output filename")
    
    cache_group = parser.add_argument_group("Caching")
    cache_group.add_argument("--cache-file", default=config.get("cache_file", "cve_cache.json"), help=f"CVE cache file location (default: {config.get('cache_file', 'cve_cache.json')})")
    cache_group.add_argument("--no-clear-cache", action="store_true", help="Prevent clearing the CVE cache")
    cache_group.add_argument("--migrate-cache", action="store_true", help="Migrate and normalize existing CVE cache")
    
    advanced_group = parser.add_argument_group("Advanced Vulnerability Options")
    advanced_group.add_argument("--baseline", help="Previous JSON report to generate a Delta Report")
    advanced_group.add_argument("--vex-file", help="Path to VEX document to filter out false positives")
    
    server_group = parser.add_argument_group("Server Scanning")
    server_group.add_argument('--server-inventory', default=config.get("inventory_file", "server_inventory.json"), help=f'File to store/load server inventory (default: {config.get("inventory_file", "server_inventory.json")})')
    server_group.add_argument('--exclude-dir', nargs='+', help='Directories to exclude from scanning (e.g. /proc /sys /var/log /u01/app)')
    server_group.add_argument('--native-only', action='store_true', help='Perform native scanning only, completely bypassing external tools like Syft')
    server_group.add_argument('--fast-agent', action='store_true', help='Enable high-performance agent mode featuring real-time procfs network analysis and live port exposure mapping')
    
    license_group = parser.add_argument_group("License Compliance")
    license_group.add_argument("--license-audit", action="store_true", help="Enable license compliance auditing against policies")
    license_group.add_argument("--fail-on-license", action="store_true", help="Fail the build/exit with error if a disallowed license is detected")

    sys_group = parser.add_argument_group("System")
    sys_group.add_argument("--config", metavar="FILE", help="Config file (TOML).")
    sys_group.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO", help="Set the logging level for the log file (default: INFO)")
    sys_group.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    sys_group.add_argument("--upgrade", action="store_true", help="Upgrade vuln-checker")
    sys_group.add_argument("--yes", action="store_true", help="Auto-confirm prompts")
    
    return parser
