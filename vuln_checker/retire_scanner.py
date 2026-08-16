import os
import re
import json
import hashlib
import logging
from pathlib import Path
from packaging.version import parse as parse_version

from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Cache for the compiled RetireJS database
_RETIRE_DB_CACHE = None

def get_retire_db_path() -> Path:
    """Gets the path to the jsrepository.json file in data dir."""
    base_path = Path(__file__).parent
    return base_path / "data" / "jsrepository.json"

def download_retire_db(force_update=False):
    """Downloads the latest RetireJS jsrepository.json file if missing or older than 24 hours."""
    db_path = get_retire_db_path()
    if db_path.exists() and not force_update:
        file_modified_time = datetime.fromtimestamp(db_path.stat().st_mtime)
        if (datetime.now() - file_modified_time) < timedelta(hours=24):
            logger.info("✅ RetireJS database is fresh, skipping download")
            return
            
    logger.info("📥 Downloading latest RetireJS database...")
    import requests
    url = "https://raw.githubusercontent.com/retirejs/retire.js/master/repository/jsrepository.json"
    try:
        r = requests.get(url, timeout=30)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(db_path, "w", encoding="utf-8") as f:
            f.write(r.text)
        logger.info(f"✅ Successfully updated RetireJS database ({len(r.text)} bytes).")
    except Exception as e:
        logger.error(f"❌ Failed to download RetireJS database: {e}")

def to_comparable_version_list(ver_str):
    """Splits a version string into a list of ints and strings for fallback comparison."""
    return [int(x) if x.isdigit() else x for x in re.split(r'[-.b_aA]', ver_str) if x]

def version_in_range(v_str, at_or_above_str=None, below_str=None) -> bool:
    """Helper to check if a version string is between atOrAbove and below (exclusive)."""
    try:
        # standard semver comparison
        v = parse_version(v_str)
        if at_or_above_str:
            if v < parse_version(at_or_above_str):
                return False
        if below_str:
            if v >= parse_version(below_str):
                return False
        return True
    except Exception:
        # Fallback list-based version comparison
        try:
            vl = to_comparable_version_list(v_str)
            if at_or_above_str:
                if vl < to_comparable_version_list(at_or_above_str):
                    return False
            if below_str:
                if vl >= to_comparable_version_list(below_str):
                    return False
            return True
        except Exception:
            return False

def compile_regex_pattern(pat_str):
    """Converts a RetireJS regex pattern (with §§version§§) to a Python compiled regex."""
    try:
        # Replace the version placeholder with a group matching standard version formats
        # RetireJS uses (§§version§§) or §§version§§
        clean_pat = pat_str
        clean_pat = clean_pat.replace("(§§version§§)", "(?P<version>[0-9a-zA-Z\\.\\-_]+)")
        clean_pat = clean_pat.replace("§§version§§", "(?P<version>[0-9a-zA-Z\\.\\-_]+)")
        
        # If it's a javascript regex literal e.g. /pattern/i, extract pattern and flags
        flags = 0
        if clean_pat.startswith("/") and clean_pat.count("/") >= 2:
            parts = clean_pat.rsplit("/", 1)
            clean_pat = parts[0][1:]
            flag_str = parts[1]
            if "i" in flag_str:
                flags |= re.IGNORECASE
            if "m" in flag_str:
                flags |= re.MULTILINE
                
        # Unescape standard regex chars that might be double escaped
        return re.compile(clean_pat, flags)
    except Exception as e:
        logger.debug(f"Failed to compile pattern {pat_str}: {e}")
        return None

def load_retire_db():
    """Loads and compiles the RetireJS database from jsrepository.json."""
    global _RETIRE_DB_CACHE
    if _RETIRE_DB_CACHE is not None:
        return _RETIRE_DB_CACHE

    db_path = get_retire_db_path()
    if not db_path.exists():
        logger.warning(f"⚠️ RetireJS database not found at {db_path}. Native RetireJS scan will be skipped.")
        return None

    try:
        with open(db_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
            
        compiled_db = {}
        for lib_name, lib_data in raw_data.items():
            if lib_name == "retire-example":
                continue
                
            extractors = lib_data.get("extractors", {})
            compiled_extractors = {
                "filename": [],
                "filecontent": [],
                "hashes": extractors.get("hashes", {})
            }
            
            for pat in extractors.get("filename", []):
                rx = compile_regex_pattern(pat)
                if rx:
                    compiled_extractors["filename"].append(rx)
                    
            for pat in extractors.get("filecontent", []):
                rx = compile_regex_pattern(pat)
                if rx:
                    compiled_extractors["filecontent"].append(rx)
                    
            compiled_db[lib_name] = {
                "vulnerabilities": lib_data.get("vulnerabilities", []),
                "extractors": compiled_extractors
            }
            
        _RETIRE_DB_CACHE = compiled_db
        logger.debug(f"✅ Successfully compiled RetireJS database with {len(compiled_db)} libraries")
        return compiled_db
    except Exception as e:
        logger.error(f"❌ Failed to load RetireJS database: {e}")
        return None

def scan_js_file(file_path: Path, db: dict):
    """Scans a single JS file and returns (detected_library_name, version) if matched."""
    # 1. SHA-1 hash check
    try:
        sha1 = hashlib.sha1()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha1.update(chunk)
        file_hash = sha1.hexdigest()
        
        for lib_name, lib_data in db.items():
            hashes = lib_data["extractors"]["hashes"]
            if file_hash in hashes:
                return lib_name, hashes[file_hash]
    except Exception as e:
        logger.debug(f"Failed to hash file {file_path}: {e}")

    # 2. Filename regex check
    filename = file_path.name
    for lib_name, lib_data in db.items():
        for rx in lib_data["extractors"]["filename"]:
            match = rx.search(filename)
            if match:
                try:
                    version = match.group("version")
                    if version:
                        return lib_name, version
                except IndexError:
                    pass

    # 3. Content regex check
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(15000) # Read first 15KB of file content
            
        for lib_name, lib_data in db.items():
            for rx in lib_data["extractors"]["filecontent"]:
                match = rx.search(content)
                if match:
                    try:
                        version = match.group("version")
                        if version:
                            return lib_name, version
                    except IndexError:
                        pass
    except Exception as e:
        logger.debug(f"Failed to read file content {file_path}: {e}")

    return None, None

def check_js_vulnerabilities(library_name: str, version: str, db: dict) -> list:
    """Checks the detected library name and version against known vulnerabilities in the RetireJS DB."""
    lib_data = db.get(library_name)
    if not lib_data:
        return []

    findings = []
    for vuln in lib_data.get("vulnerabilities", []):
        at_or_above = vuln.get("atOrAbove")
        below = vuln.get("below")
        
        if version_in_range(version, at_or_above, below):
            findings.append(vuln)
            
    return findings

def run_native_retirejs_scan(file_paths: list, feed_manager) -> list:
    """Natively scans collected javascript file paths using the compiled RetireJS database."""
    db = load_retire_db()
    if not db:
        return []

    findings = []
    logger.info(f"🔎 Natively auditing {len(file_paths)} JavaScript files against RetireJS database...")
    
    for path_str in file_paths:
        file_path = Path(path_str)
        if not file_path.exists() or file_path.suffix != ".js":
            continue
            
        lib_name, version = scan_js_file(file_path, db)
        if lib_name and version:
            vulns = check_js_vulnerabilities(lib_name, version, db)
            for v in vulns:
                severity = v.get("severity", "medium").upper()
                cwe = v.get("cwe", [])
                
                identifiers = v.get("identifiers", {})
                summary = identifiers.get("summary", "Vulnerability found in JS library")
                cve_list = identifiers.get("CVE", [])
                ghsa_list = [identifiers.get("githubID")] if identifiers.get("githubID") else []
                
                vuln_id = cve_list[0] if cve_list else (ghsa_list[0] if ghsa_list else f"RETIRE-{lib_name}")
                info_urls = v.get("info", [])
                ref_url = info_urls[0] if info_urls else "https://github.com/RetireJS/retire.js"
                
                full_cve = None
                if vuln_id.startswith("CVE-") and feed_manager:
                    full_cve = feed_manager.get_cve_by_id(vuln_id)
                elif vuln_id.startswith("GHSA-") and feed_manager:
                    osv_data = feed_manager.get_osv_by_id(vuln_id)
                    if osv_data:
                        synthetic_cve = feed_manager.generate_synthetic_cve_from_osv(osv_data)
                        full_cve = {
                            "cve": synthetic_cve,
                            "feed_file": f"OSV - {osv_data.get('feed_ecosystem', 'unknown')}"
                        }
                        
                if full_cve:
                    finding = dict(full_cve)
                else:
                    finding = {
                        "cve": {
                            "id": vuln_id,
                            "metrics": {
                                "cvssMetricV31": [{
                                    "cvssData": {
                                        "baseScore": 5.0 if severity == "MEDIUM" else (7.5 if severity == "HIGH" else 3.0),
                                        "baseSeverity": severity
                                    }
                                }]
                            },
                            "descriptions": [{"lang": "en", "value": summary}]
                        },
                        "feed_file": "Retire.js"
                    }
                    
                finding.update({
                    "id": vuln_id,
                    "tool": "Retire.js",
                    "product": lib_name,
                    "component_name": lib_name,
                    "component_version": version,
                    "path": str(file_path),
                    "severity": severity,
                    "description": summary,
                    "url": ref_url,
                    "pkg_type": "npm_package",
                    "cpe_used": f"external:Retire.js",
                    "cpe_source": "Retire.js"
                })
                findings.append(finding)
                
    logger.info(f"✅ Native RetireJS audit completed. Found {len(findings)} JavaScript vulnerabilities.")
    return findings
