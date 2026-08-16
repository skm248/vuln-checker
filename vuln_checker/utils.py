"""Utility functions"""
import os
import logging
import json
import re
from typing import Set
from packaging import version as pkg_version

logger = logging.getLogger(__name__)

def load_excluded_cpes(filename: str = "excluded_cpes.txt") -> Set[str]:
    """Load excluded CPEs from file, checking CWD then package dir"""
    cpes = set()
    try:
        # 1. Check current working directory (preferred for project-level config)
        file_path = os.path.join(os.getcwd(), filename)
        
        # 2. Fallback to package data directory if not in CWD
        if not os.path.exists(file_path):
            base_path = os.path.dirname(os.path.abspath(__file__))
            file_path = os.path.join(base_path, "data", filename)
        
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    cpe = line.strip()
                    if cpe and not cpe.startswith("#"):
                        cpes.add(cpe)
            logger.debug(f"✅ Loaded {len(cpes)} excluded CPEs from {file_path}")
        else:
            # Only warn if we explicitly expected it
            logger.debug(f"ℹ️ {filename} not found in CWD or package dir. Skipping exclusions.")
    except Exception as e:
        logger.error(f"❌ Error loading excluded CPEs: {e}")
    return cpes

# Use a lazy loader to ensure it's call after logging initialization
_EXCLUDED_CPES_CACHE = None

def get_excluded_cpes() -> Set[str]:
    global _EXCLUDED_CPES_CACHE
    if _EXCLUDED_CPES_CACHE is None:
        _EXCLUDED_CPES_CACHE = load_excluded_cpes()
    return _EXCLUDED_CPES_CACHE

def load_core_apps(filename: str = "core_apps.txt") -> Set[str]:
    """Load core server/application names to prevent matching client libraries, checking CWD then package dir"""
    apps = set()
    try:
        file_path = os.path.join(os.getcwd(), filename)
        if not os.path.exists(file_path):
            base_path = os.path.dirname(os.path.abspath(__file__))
            file_path = os.path.join(base_path, "data", filename)
        
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    app = line.strip()
                    if app and not app.startswith("#"):
                        apps.add(app.lower())
            logger.debug(f"✅ Loaded {len(apps)} core apps from {file_path}")
        else:
            logger.debug(f"ℹ️ {filename} not found in CWD or package dir. Using defaults.")
    except Exception as e:
        logger.error(f"❌ Error loading core apps: {e}")
    return apps

_CORE_APPS_CACHE = None

def get_core_apps() -> Set[str]:
    global _CORE_APPS_CACHE
    if _CORE_APPS_CACHE is None:
        _CORE_APPS_CACHE = load_core_apps()
        if not _CORE_APPS_CACHE:
            _CORE_APPS_CACHE = set()
    return _CORE_APPS_CACHE

def is_excluded_cpe(cpe_uri: str) -> bool:
    """Check if CPE should be excluded"""
    cpe_uri = cpe_uri.strip()
    excluded_set = get_excluded_cpes()
    
    if cpe_uri in excluded_set:
        return True
    
    for excluded in excluded_set:
        excluded = excluded.strip()
        if excluded.endswith("*"):
            prefix = excluded[:-1]
            if cpe_uri.startswith(prefix):
                return True
    return False

def normalize_severity(severity: str) -> str:
    """Normalize severity strings for consistency (e.g. MODERATE -> MEDIUM)"""
    if not severity:
        return "UNKNOWN"
    s = severity.upper().strip()
    if s == "MODERATE":
        return "MEDIUM"
    return s

def load_ui_signatures(filename: str = "ui_signatures.json") -> dict:
    """Load UI library signatures from file, checking CWD then package dir"""
    default_signatures = {
        "libraries": {},
        "default_excludes": []
    }
    
    try:
        file_path = os.path.join(os.getcwd(), filename)
        if not os.path.exists(file_path):
            base_path = os.path.dirname(os.path.abspath(__file__))
            file_path = os.path.join(base_path, "data", filename)
            
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                logger.debug(f"✅ Loaded {len(data.get('libraries', {}))} UI library signatures from {file_path}")
                if "libraries" in data and "default_excludes" in data:
                    return data
        logger.debug(f"ℹ️ {filename} not found or invalid in CWD or package dir. Using defaults.")
    except Exception as e:
        logger.error(f"❌ Error loading UI signatures: {e}")
        
    return default_signatures

_UI_SIGNATURES_CACHE = None

def get_ui_signatures() -> dict:
    global _UI_SIGNATURES_CACHE
    if _UI_SIGNATURES_CACHE is None:
        _UI_SIGNATURES_CACHE = load_ui_signatures()
    return _UI_SIGNATURES_CACHE

def load_vendor_aliases(filename: str = "vendor_aliases.json") -> dict:
    """Load vendor aliases from file, checking CWD then package dir"""
    default_config = {
        "aliases": {},
        "common_tlds": [],
        "common_prefixes": [],
        "spring_boot_vendors": [],
        "subproject_exceptions": {},
        "prefix_strip_exclusions": [],
        "standalone_apps": []
    }
    try:
        file_path = os.path.join(os.getcwd(), filename)
        if not os.path.exists(file_path):
            base_path = os.path.dirname(os.path.abspath(__file__))
            file_path = os.path.join(base_path, "data", filename)
            
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                logger.debug(f"✅ Loaded vendor aliases database from {file_path}")
                if "aliases" in data:
                    return data
        logger.debug(f"ℹ️ {filename} not found or invalid in CWD or package dir. Using defaults.")
    except Exception as e:
        logger.error(f"❌ Error loading vendor aliases: {e}")
    return default_config

_VENDOR_ALIASES_CACHE = None

def get_vendor_aliases() -> dict:
    global _VENDOR_ALIASES_CACHE
    if _VENDOR_ALIASES_CACHE is None:
        _VENDOR_ALIASES_CACHE = load_vendor_aliases()
    return _VENDOR_ALIASES_CACHE


def get_listening_ports():
    """Extract open TCP & UDP listening ports and process information using:
    1. Direct /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6 parsing
    2. Fallback CLI tools (ss -tulpn, lsof -i -P -n, netstat -tulpn)
    3. Live socket banner grabbing for unidentified listening services
    4. Well-known port mapping table
    """
    listening_ports = []
    if os.name == 'nt':
        return listening_ports

    def parse_hex_ip_port(s):
        parts = s.split(':')
        if len(parts) != 2:
            return None, None
        ip_hex, port_hex = parts
        try:
            port = int(port_hex, 16)
            if len(ip_hex) == 8: # IPv4
                ip_bytes = [int(ip_hex[i:i+2], 16) for i in range(0, 8, 2)]
                ip = ".".join(str(b) for b in reversed(ip_bytes))
            else: # IPv6
                ip = ip_hex
            return ip, port
        except Exception:
            return None, None

    inodes = {}
    # Scan both TCP and UDP listening sockets
    for proc_file, proto in [
        ("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp"),
        ("/proc/net/udp", "udp"), ("/proc/net/udp6", "udp")
    ]:
        if not os.path.exists(proc_file):
            continue
        try:
            with open(proc_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                local_addr = parts[1]
                state = parts[3]
                inode = parts[9]
                # state 0A is TCP_LISTEN, state 07 is UDP established/listening
                if state in ["0A", "07"]:
                    ip, port = parse_hex_ip_port(local_addr)
                    if ip and port:
                        inodes[inode] = {"ip": ip, "port": port, "proto": proto, "pid": None, "service": "unknown"}
        except Exception:
            pass

    # Map sockets to PIDs via /proc filesystem
    if os.path.exists("/proc"):
        try:
            for pid_entry in os.listdir("/proc"):
                if not pid_entry.isdigit():
                    continue
                fd_dir = f"/proc/{pid_entry}/fd"
                if not os.path.isdir(fd_dir):
                    continue
                try:
                    for fd in os.listdir(fd_dir):
                        link_path = os.path.join(fd_dir, fd)
                        try:
                            target = os.readlink(link_path)
                            if target.startswith("socket:["):
                                inode_val = target[8:-1]
                                if inode_val in inodes:
                                    inodes[inode_val]["pid"] = int(pid_entry)
                                    cmdline_file = f"/proc/{pid_entry}/cmdline"
                                    comm_file = f"/proc/{pid_entry}/comm"
                                    service_name = ""
                                    if os.path.exists(cmdline_file):
                                        with open(cmdline_file, 'r', encoding='utf-8', errors='ignore') as cf:
                                            cmd = cf.read().replace('\x00', ' ').strip()
                                            if cmd:
                                                service_name = cmd.split()[0].split('/')[-1]
                                    if not service_name and os.path.exists(comm_file):
                                        with open(comm_file, 'r', encoding='utf-8') as comf:
                                            service_name = comf.read().strip()
                                    inodes[inode_val]["service"] = service_name or "unknown"
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception:
            pass

    # CLI Tool Fallback if /proc was incomplete (e.g. ss, lsof, netstat)
    try:
        import subprocess
        for cli_cmd in ["ss -tulpn", "lsof -i -P -n", "netstat -tulpn"]:
            try:
                res = subprocess.run(cli_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
                if res.returncode == 0 and res.stdout:
                    for line in res.stdout.splitlines():
                        line_lower = line.lower()
                        for port_key, data in inodes.items():
                            if data.get("service") == "unknown":
                                port_str = f":{data['port']}"
                                if port_str in line:
                                    # Extract process name from quote or slash
                                    match = re.search(r'users:\(\("([^"]+)"|([a-zA-Z0-9_-]+)/', line)
                                    if match:
                                        svc = match.group(1) or match.group(2)
                                        if svc:
                                            data["service"] = svc
            except Exception:
                pass
    except Exception:
        pass

    # Well-known port mapping table fallback
    WELL_KNOWN_PORTS = {
        3100: "loki", 3306: "mysql", 33060: "mysql", 5432: "postgres", 6379: "redis",
        27017: "mongodb", 22: "ssh", 80: "nginx", 443: "nginx", 8443: "nginx",
        8889: "nginx", 9090: "prometheus", 9099: "prometheus", 6002: "python3", 6003: "python3"
    }

    # Live Socket Banner Grabbing fallback for unresolved HTTP/SSH/MySQL ports
    import socket
    for item in inodes.values():
        if item.get("service") == "unknown":
            port = item.get("port")
            ip = item.get("ip") or "127.0.0.1"
            if port in WELL_KNOWN_PORTS:
                item["service"] = WELL_KNOWN_PORTS[port]
            else:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    target_ip = "127.0.0.1" if ip in ["0.0.0.0", "::", "127.0.0.1"] else ip
                    s.connect((target_ip, port))
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(512).decode('utf-8', errors='ignore').lower()
                    s.close()
                    if "nginx" in banner: item["service"] = "nginx"
                    elif "apache" in banner: item["service"] = "httpd"
                    elif "ssh" in banner: item["service"] = "ssh"
                    elif "mysql" in banner: item["service"] = "mysql"
                except Exception:
                    pass

    return list(inodes.values())


def get_binary_version_cli(binary_path: str) -> str:
    """Executes a standalone binary with --version or -v to discover its version string."""
    if not binary_path or not os.path.exists(binary_path):
        return None
    import subprocess
    import re
    # General sequence of flags to probe version. We prioritize -v and --version to handle Nginx/Redis and standard tools efficiently.
    flags = ["-v", "--version", "-version", "-V", "version"]

    for flag in flags:
        try:
            res = subprocess.run([binary_path, flag], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
            out = f"{res.stdout or ''}\n{res.stderr or ''}".strip()
            if out:
                version_match = re.search(r'\b(?:version\s+)?v?(\d+\.\d+\.[\d\.\w_-]+)', out, re.IGNORECASE)
                if version_match:
                    return version_match.group(1)
        except Exception:
            continue
    return None


def extract_cve_severity_and_score(cve_obj: dict):
    """
    Extracts the best severity and CVSS score from the cve object metrics
    by prioritizing:
    1. nvd@nist.gov source
    2. Primary metric type
    3. Newer CVSS versions (V40 > V31 > V30 > V2)
    """
    if not isinstance(cve_obj, dict):
        return "UNKNOWN", "N/A"
    metrics = cve_obj.get("metrics", {}) if cve_obj else {}
    if not isinstance(metrics, dict) or not metrics:
        # Fallback to top-level if present (e.g. for non-NVD/OSV feeds directly)
        base_sev = cve_obj.get("baseSeverity") or cve_obj.get("severity") or "UNKNOWN"
        base_score = cve_obj.get("baseScore") or "N/A"
        return normalize_severity(base_sev), base_score
        
    all_metrics = []
    version_weights = {
        "cvssMetricV40": 4.0,
        "cvssMetricV31": 3.1,
        "cvssMetricV30": 3.0,
        "cvssMetricV2": 2.0
    }
    
    for m_key, weight in version_weights.items():
        m_list = metrics.get(m_key, [])
        if isinstance(m_list, list):
            for metric in m_list:
                if isinstance(metric, dict):
                    all_metrics.append((metric, weight))
            
    if not all_metrics:
        base_sev = cve_obj.get("baseSeverity") or cve_obj.get("severity") or "UNKNOWN"
        base_score = cve_obj.get("baseScore") or "N/A"
        return normalize_severity(base_sev), base_score
        
    # Sort key: (-is_nvd, -is_primary, -version_weight)
    all_metrics.sort(key=lambda x: (
        -1 if str(x[0].get("source", "")).lower() == "nvd@nist.gov" else 0,
        -1 if str(x[0].get("type", "")).lower() == "primary" else 0,
        -x[1]
    ))
    
    best_metric, weight = all_metrics[0]
    cvss_data = best_metric.get("cvssData", {})
    score = cvss_data.get("baseScore", "N/A")
    
    # baseSeverity can be inside cvssData, or directly in the metric (common in cvssMetricV2)
    severity = cvss_data.get("baseSeverity") or best_metric.get("baseSeverity") or "UNKNOWN"
    
    return normalize_severity(str(severity)), score


def safe_parse_version(version_str: str, product_name: str = None):
    """Safely parse version strings, stripping common prefixes like v, vv, and release- tags."""
    if not version_str:
        raise ValueError("Empty version string")
    v = str(version_str).strip().lower()
    
    # Strip epoch prefixes (e.g. 0:8.4.11 -> 8.4.11)
    v = re.sub(r'^\d+:', '', v)
    
    # Map release/revision prefix format (e.g. R26-p1, r31) to 1.X semver format dynamically.
    # This prevents comparison mismatches when comparing standard semver against release letters.
    v = re.sub(r'^r(\d+)', r'1.\1', v)
        
    # Strip any leading non-digits (e.g. go1.24.6 -> 1.24.6, node-v20 -> 20)
    v = re.sub(r'^[^0-9]+', '', v)
    # Strip common release prefixes
    v = re.sub(r'^(release|rel|ver|version)-', '', v)
    
    # Map date-based versions (e.g. 2017-03-17) to a pre-v0.0.0 prefix (0.0.0.20170317)
    # so they compare correctly against standard semver versions like 0.1.0 or 0.54.0.
    if re.match(r'^(19\d{2}|20\d{2})([-._]?\d+)*$', v):
        clean_date = re.sub(r'[-._]', '.', v)
        v = f"0.0.0.{clean_date}"
    
    # Replace '_' with '.' to preserve patch/update components (e.g. 1.8.0_492 -> 1.8.0.492)
    v = v.replace('_', '.')
    # Replace '-' with '.' if followed by a digit (e.g. 5.14.0-611 -> 5.14.0.611)
    v = re.sub(r'-(\d)', r'.\1', v)
    
    try:
        return pkg_version.parse(v)
    except Exception:
        # Fallback: find the first sequence of numbers/dots
        match = re.match(r'^(\d+(\.\d+)*)', v)
        if match:
            try:
                return pkg_version.parse(match.group(1))
            except Exception:
                pass
        raise


def check_license_compliance(license_str: str, config: dict) -> str:
    """
    Checks if a license string complies with the defined allowed/denied policy.
    Returns: "PASS", "VIOLATED", or "REVIEW"
    """
    if not license_str or license_str.lower() == "unknown":
        return "REVIEW"
        
    policy = config.get("license_policy", {})
    if not policy or not policy.get("enabled", False):
        return "PASS" # Policy disabled, implicitly pass
        
    allowed_list = [l.lower().strip() for l in policy.get("allowed_licenses", [])]
    denied_list = [l.lower().strip() for l in policy.get("denied_licenses", [])]
    
    # Split composite/expression licenses (e.g. "MIT OR Apache-2.0" or "GPL-3.0 AND MIT")
    # For simplicity, check each part
    parts = re.split(r'\s+(?:or|and)\s+|\s*,\s*|\s*\|\s*', license_str, flags=re.IGNORECASE)
    
    overall_status = "PASS"
    for part in parts:
        part = part.strip().lower()
        if not part:
            continue
            
        # Match using exact comparison or check if part starts/ends/contains standard formats
        matched_denied = False
        for d in denied_list:
            d_clean = d.replace("-only", "").replace("-or-later", "")
            part_clean = part.replace("-only", "").replace("-or-later", "")
            if d == part or d_clean == part_clean or d_clean in part_clean or part_clean in d_clean:
                matched_denied = True
                break
                
        if matched_denied:
            return "VIOLATED" # Any denied license part violates compliance
            
        matched_allowed = False
        for a in allowed_list:
            a_clean = a.replace("-only", "").replace("-or-later", "")
            part_clean = part.replace("-only", "").replace("-or-later", "")
            if a == part or a_clean == part_clean or a_clean in part_clean or part_clean in a_clean:
                matched_allowed = True
                break
                
        if not matched_allowed:
            overall_status = "REVIEW" # Not explicitly allowed, mark for review
            
    return overall_status


def identify_license_from_text(text: str) -> str:
    t = text.lower()
    if "apache license" in t and "2.0" in t:
        return "Apache-2.0"
    if "mit license" in t or "permission is hereby granted" in t:
        return "MIT"
    if "gnu general public" in t:
        if "version 3" in t:
            return "GPL-3.0"
        return "GPL-2.0"
    if "bsd 3-clause" in t or "3-clause bsd" in t or "redistribution and use in source and binary forms" in t:
        return "BSD-3-Clause"
    if "bsd 2-clause" in t or "2-clause bsd" in t:
        return "BSD-2-Clause"
    if "mozilla public" in t:
        return "MPL-2.0"
    if "eclipse public" in t:
        return "EPL-2.0"
    return "unknown"


def fetch_online_package_license(name: str, vendor: str, version: str, type_str: str, purl: str = "") -> str:
    """Attempts to query public registries to find package licenses."""
    import urllib.request
    import urllib.parse
    import json
    import re
    
    type_str = str(type_str or "").lower()
    purl = str(purl or "")
    
    # 1. NPM Registry Lookup
    if "npm" in type_str or "pkg:npm" in purl:
        try:
            url = f"https://registry.npmjs.org/{urllib.parse.quote(name)}/latest"
            req = urllib.request.Request(url, headers={'User-Agent': 'vuln-checker-license-fetcher'})
            with urllib.request.urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode('utf-8'))
                license_data = data.get("license")
                if isinstance(license_data, dict):
                    return license_data.get("type", "unknown")
                elif isinstance(license_data, str):
                    return license_data
        except Exception:
            pass

    # 2. PyPI Registry Lookup
    elif "pypi" in type_str or "python" in type_str or "pkg:pypi" in purl:
        try:
            url = f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json"
            req = urllib.request.Request(url, headers={'User-Agent': 'vuln-checker-license-fetcher'})
            with urllib.request.urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode('utf-8'))
                info = data.get("info", {})
                license_str = info.get("license")
                if license_str and len(license_str) < 50:
                    return license_str.strip()
                classifiers = info.get("classifiers", [])
                for classifier in classifiers:
                    if classifier.startswith("License ::"):
                        parts = classifier.split("::")
                        if len(parts) > 1:
                            return parts[-1].strip()
        except Exception:
            pass

    # 3. Go Module Lookup (usually hosted on GitHub)
    elif "golang" in type_str or "go" in type_str or "pkg:golang" in purl:
        try:
            repo_path = name
            if purl and purl.startswith("pkg:golang/"):
                purl_body = purl.split("?")[0]
                repo_path = purl_body.replace("pkg:golang/", "").split("@")[0]
            
            if repo_path.startswith("github.com/"):
                parts = repo_path.split("/")
                if len(parts) >= 3:
                    owner = parts[1]
                    repo = parts[2]
                    
                    # Bypass rate-limited REST API: try downloading raw LICENSE files directly
                    for branch in ["master", "main"]:
                        for filename in ["LICENSE", "LICENSE.txt", "LICENSE.md", "license", "COPYING"]:
                            try:
                                url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{filename}"
                                req = urllib.request.Request(url, headers={'User-Agent': 'vuln-checker-license-fetcher'})
                                with urllib.request.urlopen(req, timeout=1.5) as response:
                                    lic_text = response.read().decode('utf-8', errors='ignore')
                                    detected = identify_license_from_text(lic_text)
                                    if detected != "unknown":
                                        return detected
                            except Exception:
                                pass
        except Exception:
            pass

    # 4. Maven / Java POM Lookup
    elif "maven" in type_str or "java" in type_str or "jar" in type_str or "pkg:maven" in purl or "sbom_scan" in type_str:
        try:
            group = vendor or name
            artifact = name
            
            # Extract Maven Group & Artifact from PURL if available
            if purl and purl.startswith("pkg:maven/"):
                purl_body = purl.split("?")[0] # strip query parameters
                parts = purl_body.replace("pkg:maven/", "").split("/")
                if len(parts) > 1:
                    group = "/".join(parts[:-1]) # Handles nested namespace/group
                    artifact = parts[-1].split("@")[0]
            
            group_path = group.replace(".", "/")
            if "(" in artifact and ")" in artifact:
                match = re.search(r'\((.*?)\)', artifact)
                if match:
                    artifact = match.group(1)
            
            url = f"https://repo1.maven.org/maven2/{group_path}/{artifact}/{version}/{artifact}-{version}.pom"
            req = urllib.request.Request(url, headers={'User-Agent': 'vuln-checker-license-fetcher'})
            with urllib.request.urlopen(req, timeout=3) as response:
                pom_content = response.read().decode('utf-8', errors='ignore')
                
                def fetch_pom_license(content: str, depth=0) -> str:
                    if depth > 3:
                        return "unknown"
                    lic_match = re.search(r'<license>\s*<name>(.*?)</name>', content, re.DOTALL | re.IGNORECASE)
                    if lic_match:
                        return lic_match.group(1).strip()
                    
                    par_match = re.search(r'<parent>(.*?)</parent>', content, re.DOTALL | re.IGNORECASE)
                    if par_match:
                        par_content = par_match.group(1)
                        pg = re.search(r'<groupId>(.*?)</groupId>', par_content, re.IGNORECASE)
                        pa = re.search(r'<artifactId>(.*?)</artifactId>', par_content, re.IGNORECASE)
                        pv = re.search(r'<version>(.*?)</version>', par_content, re.IGNORECASE)
                        if pg and pa and pv:
                            pg_path = pg.group(1).strip().replace(".", "/")
                            pa_id = pa.group(1).strip()
                            pv_ver = pv.group(1).strip()
                            parent_url = f"https://repo1.maven.org/maven2/{pg_path}/{pa_id}/{pv_ver}/{pa_id}-{pv_ver}.pom"
                            try:
                                parent_req = urllib.request.Request(parent_url, headers={'User-Agent': 'vuln-checker-license-fetcher'})
                                with urllib.request.urlopen(parent_req, timeout=3) as p_resp:
                                    parent_pom = p_resp.read().decode('utf-8', errors='ignore')
                                    return fetch_pom_license(parent_pom, depth + 1)
                            except Exception:
                                pass
                    return "unknown"
                
                return fetch_pom_license(pom_content)
        except Exception:
            pass
            
    return "unknown"



