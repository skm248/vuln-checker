"""NVD Feed Management"""
import os
import time
import json
import logging
import random
import requests
import gzip
import shutil
import re
import zipfile
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
from packaging import version as pkg_version
from concurrent.futures import ThreadPoolExecutor, as_completed

from vuln_checker.utils import is_excluded_cpe, normalize_severity, extract_cve_severity_and_score, safe_parse_version

logger = logging.getLogger(__name__)

# Single canonical start year for NVD feeds
NVD_FEED_START_YEAR = 2002
# The NVD feeds exist starting 2002. Protect against lower values.
EARLIEST_NVD_YEAR = 2002

def get_project_version():
    """Get the package version from metadata"""
    try:
        from importlib.metadata import version
        return version("vuln-checker")
    except Exception:
        # Fallback: read from pyproject.toml for development mode
        try:
            import tomli
            import os
            pyproject_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "pyproject.toml")
            with open(pyproject_path, "rb") as f:
                pyproject = tomli.load(f)
                return pyproject.get("project", {}).get("version", "unknown")
        except Exception:
            return "unknown"

def check_feed_meta_changed(year, feed_dir="nvd_feeds"):
    meta_url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.meta"
    feed_path = Path(feed_dir)
    local_meta_path = feed_path / f"nvdcve-2.0-{year}.meta"
    
    json_file = feed_path / f"nvdcve-2.0-{year}.json"
    if not json_file.exists():
        return True

    try:
        session = requests.Session()
        headers = {
            "User-Agent": f"vuln-checker/{get_project_version()} (+https://github.com/skm248/vuln-checker)",
        }
        response = session.get(meta_url, headers=headers, timeout=10)
        if response.status_code == 200:
            remote_meta_content = response.text.strip()
            
            if local_meta_path.exists():
                with open(local_meta_path, "r", encoding="utf-8") as f:
                    local_meta_content = f.read().strip()
                
                if remote_meta_content == local_meta_content:
                    return False
            
            local_meta_path.parent.mkdir(parents=True, exist_ok=True)
            with open(local_meta_path, "w", encoding="utf-8") as f:
                f.write(remote_meta_content)
                
    except Exception as e:
        logger.warning(f"⚠️ Could not check NVD meta file for {year}: {e}")
        
    return True

def download_nvdcve_year(year, feed_dir="nvd_feeds", force_update=False):
    url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
    feed_path = Path(feed_dir)
    feed_path.mkdir(exist_ok=True)
    gz_file = feed_path / f"nvdcve-2.0-{year}.json.gz"
    json_file = feed_path / f"nvdcve-2.0-{year}.json"
    
    if json_file.exists() and not force_update:
        file_modified_time = datetime.fromtimestamp(json_file.stat().st_mtime)
        if (datetime.now() - file_modified_time) < timedelta(hours=24):
            logger.info(f"✅ JSON feed for {year} is fresh, skipping download")
            return True
        else:
            logger.info(f"⚠️ Feed for {year} is older than 24h, refreshing download")
    elif force_update:
        logger.info(f"⚠️ Force update enabled: re-downloading feed for {year}")

    logger.info(f"📥 Downloading {url} ...")
    session = requests.Session()
    headers = {
        "User-Agent": f"vuln-checker/{get_project_version()} (+https://github.com/skm248/vuln-checker)",
        "Accept": "application/gzip, application/octet-stream, */*",
    }

    max_attempts = 20
    backoff_factor = 1.0
    
    if force_update and gz_file.exists():
        try:
            gz_file.unlink()
        except Exception:
            pass

    downloaded_bytes = 0
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(f"   → Attempt {attempt}/{max_attempts} for year {year}")
            
            # Check current size of gzip file if it exists to resume
            if gz_file.exists() and downloaded_bytes == 0:
                downloaded_bytes = gz_file.stat().st_size
                
            request_headers = headers.copy()
            if downloaded_bytes > 0:
                request_headers["Range"] = f"bytes={downloaded_bytes}-"
                logger.info(f"     Resuming download from byte {downloaded_bytes}...")
            
            with session.get(url, headers=request_headers, stream=True, timeout=30) as response:
                status = response.status_code
                
                if status == 206 and downloaded_bytes > 0:
                    write_mode = 'ab'
                elif status == 200:
                    write_mode = 'wb'
                    downloaded_bytes = 0
                else:
                    logger.warning(f"   ✖ HTTP {status} received for {year} on attempt {attempt}")
                    if status not in (429, 500, 502, 503, 504):
                        logger.error(f"❌ Non-retryable HTTP {status} for {year}, aborting")
                        if gz_file.exists():
                            try:
                                gz_file.unlink()
                            except Exception:
                                pass
                        return False
                    raise requests.exceptions.RequestException(f"HTTP status {status}")

                with open(gz_file, write_mode) as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded_bytes += len(chunk)

            # Successfully downloaded
            with gzip.open(gz_file, 'rb') as f_in, open(json_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

            try:
                gz_file.unlink()
            except Exception:
                pass

            logger.info(f"✅ Decompressed and saved feed for {year}")
            return True

        except (requests.exceptions.RequestException, Exception) as e:
            if gz_file.exists():
                downloaded_bytes = gz_file.stat().st_size
            else:
                downloaded_bytes = 0
            logger.error(f"   ✖ Network error or incomplete read on attempt {attempt} for {year}: {e}")

        if attempt < max_attempts:
            backoff = backoff_factor * (2 ** (attempt - 1))
            jitter = random.uniform(0, 1)
            sleep_time = backoff + jitter
            time.sleep(sleep_time)
        else:
            logger.error(f"❌ Exhausted retries for {year}, giving up")
            if gz_file.exists():
                try:
                    gz_file.unlink()
                except Exception:
                    pass
            return False

def apply_modified_feed(modified_json_path, feed_dir):
    logger.info("🔄 Applying incremental updates from modified feed...")
    try:
        with open(modified_json_path, "r", encoding="utf-8", errors="replace") as f:
            modified_data = json.load(f)
    except Exception as e:
        logger.error(f"❌ Failed to parse modified feed JSON: {e}")
        return False

    modified_vulns = modified_data.get("vulnerabilities", [])
    if not modified_vulns:
        logger.info("ℹ️ No vulnerabilities found in modified feed.")
        return True

    by_year = defaultdict(list)
    for vuln in modified_vulns:
        cve_id = vuln.get("cve", {}).get("id")
        if not cve_id:
            continue
        parts = cve_id.split("-")
        if len(parts) >= 2 and parts[1].isdigit():
            year = int(parts[1])
            if year >= EARLIEST_NVD_YEAR:
                by_year[year].append(vuln)

    feed_path = Path(feed_dir)
    updated_years_count = 0
    
    try:
        from tqdm import tqdm
        iterator = tqdm(by_year.items(), desc="Applying incremental NVD updates", unit="year")
    except ImportError:
        iterator = by_year.items()

    for year, new_vulns in iterator:
        json_file = feed_path / f"nvdcve-2.0-{year}.json"
        if not json_file.exists():
            continue
            
        try:
            with open(json_file, "r", encoding="utf-8", errors="replace") as f:
                year_data = json.load(f)
        except Exception as e:
            logger.warning(f"⚠️ Failed to read {json_file.name}, skipping incremental update: {e}")
            continue

        vulns_list = year_data.get("vulnerabilities", [])
        vuln_map = {}
        for v in vulns_list:
            cid = v.get("cve", {}).get("id")
            if cid:
                vuln_map[cid] = v

        updates_count = 0
        inserts_count = 0
        for new_v in new_vulns:
            cid = new_v.get("cve", {}).get("id")
            if cid in vuln_map:
                vuln_map[cid] = new_v
                updates_count += 1
            else:
                vuln_map[cid] = new_v
                inserts_count += 1

        year_data["vulnerabilities"] = list(vuln_map.values())
        
        try:
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(year_data, f, ensure_ascii=False)
            logger.info(f"   ✓ Updated {json_file.name}: {updates_count} updated, {inserts_count} inserted")
            updated_years_count += 1
        except Exception as e:
            logger.error(f"❌ Failed to save updated {json_file.name}: {e}")

    logger.info(f"✅ Incremental sync completed. Updated {updated_years_count} year files.")
    return True

def download_all_nvd_feeds(feed_dir="nvd_feeds", start_year=None, force_update=False, show_progress=True, max_workers=1):
    if start_year is None:
        start_year = NVD_FEED_START_YEAR

    try:
        start_year = int(start_year)
    except Exception:
        start_year = NVD_FEED_START_YEAR

    if start_year < EARLIEST_NVD_YEAR:
        start_year = EARLIEST_NVD_YEAR

    current_year = datetime.now().year
    years = list(range(start_year, current_year + 1))
    feed_path = Path(feed_dir)
    feed_path.mkdir(exist_ok=True)

    missing_years = []
    stale_threshold = timedelta(days=7)
    now = datetime.now()
    for yr in years:
        json_file = feed_path / f"nvdcve-2.0-{yr}.json"
        if not json_file.exists() or force_update:
            missing_years.append(yr)
            continue
        try:
            if json_file.stat().st_size < 100:
                missing_years.append(yr)
                continue
            last_mod = datetime.fromtimestamp(json_file.stat().st_mtime)
            
            # Only apply the 7-day stale check to the current and previous year.
            # Historical archives are stable; updates to them are covered by the modified delta feed.
            is_recent_year = (yr >= now.year - 1)
            if is_recent_year and (now - last_mod > stale_threshold):
                logger.info(f"   ℹ️ Year {yr} is more than 7 days old, will re-download full archive")
                missing_years.append(yr)
        except Exception:
            missing_years.append(yr)

    if missing_years:
        logger.info(f"ℹ️ Downloading {len(missing_years)} missing/force-updated NVD feeds into '{feed_dir}' (max_workers={max_workers})")
        downloaded_count = 0
        def download_wrapper(yr):
            nonlocal downloaded_count
            success = download_nvdcve_year(yr, feed_dir, force_update=force_update)
            if success:
                downloaded_count += 1
            else:
                logger.warning(f"⚠️ Skipping {yr} due to download error")
            if max_workers == 1:
                time.sleep(random.uniform(1.0, 3.0))
            return success

        if max_workers > 1:
            if show_progress:
                try:
                    from tqdm import tqdm
                    with tqdm(total=len(missing_years), desc="Downloading NVD feeds (parallel)", unit="year") as pbar:
                        with ThreadPoolExecutor(max_workers=max_workers) as executor:
                            futures = {executor.submit(download_wrapper, yr): yr for yr in missing_years}
                            for future in as_completed(futures):
                                future.result()
                                pbar.update(1)
                except ImportError:
                    with ThreadPoolExecutor(max_workers=max_workers) as executor:
                        list(executor.map(download_wrapper, missing_years))
            else:
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    list(executor.map(download_wrapper, missing_years))
        else:
            if show_progress:
                try:
                    from tqdm import tqdm
                    iterator = tqdm(missing_years, desc="Downloading NVD feeds", unit="year")
                except ImportError:
                    iterator = missing_years
            else:
                iterator = missing_years
                
            for year in iterator:
                download_wrapper(year)

    if not force_update:
        logger.info("📥 Checking latest NVD modified delta feed metadata...")
        if not check_feed_meta_changed("modified", feed_dir):
            logger.info("✅ NVD modified delta feed is already up to date (no changes detected via META file).")
            return len(missing_years)

        logger.info("📥 Downloading latest NVD modified delta feed...")
        success = download_nvdcve_year("modified", feed_dir, force_update=True)
        if success:
            modified_json_path = feed_path / "nvdcve-2.0-modified.json"
            apply_modified_feed(modified_json_path, feed_dir)
            return len(missing_years) + 1
        else:
            logger.error("❌ Failed to download modified delta feed, skipping incremental sync.")
            
    return len(missing_years)

def nvd_feeds_need_update(feed_dir="nvd_feeds", max_age_hours=24, start_year=None):
    if start_year is None:
        start_year = NVD_FEED_START_YEAR

    try:
        start_year = int(start_year)
    except Exception:
        start_year = NVD_FEED_START_YEAR

    if start_year < EARLIEST_NVD_YEAR:
        start_year = EARLIEST_NVD_YEAR

    feed_path = Path(feed_dir)
    feed_path.mkdir(exist_ok=True)
    current_year = datetime.now().year
    now = datetime.now()

    for year in range(start_year, current_year + 1):
        json_file = feed_path / f"nvdcve-2.0-{year}.json"
        if not json_file.exists():
            return True

    # If all yearly files exist, we only need an update if the modified feed
    # doesn't exist or is older than max_age_hours
    modified_json = feed_path / "nvdcve-2.0-modified.json"
    if not modified_json.exists():
        return True

    last_mod = datetime.fromtimestamp(modified_json.stat().st_mtime)
    if now - last_mod > timedelta(hours=max_age_hours):
        return True

    return False

def download_osv_ecosystem(ecosystem, feed_dir="osv_feeds", force_update=False):
    url = f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
    feed_path = Path(feed_dir) / ecosystem
    feed_path.mkdir(parents=True, exist_ok=True)
    zip_file = feed_path / "all.zip"
    
    if zip_file.exists() and not force_update:
        file_modified_time = datetime.fromtimestamp(zip_file.stat().st_mtime)
        if (datetime.now() - file_modified_time) < timedelta(hours=24):
            logger.info(f"✅ OSV feed for {ecosystem} is fresh, skipping download")
            return True
        else:
            logger.info(f"⚠️ OSV feed for {ecosystem} is older than 24h, refreshing download")
    elif force_update:
        logger.info(f"⚠️ Force update enabled: re-downloading OSV feed for {ecosystem}")

    logger.info(f"📥 Downloading {url} ...")
    session = requests.Session()
    headers = {
        "User-Agent": f"vuln-checker/{get_project_version()} (+https://github.com/skm248/vuln-checker)",
    }

    max_attempts = 10
    
    if zip_file.exists():
        try:
            zip_file.unlink()
        except Exception:
            pass

    downloaded_bytes = 0
    for attempt in range(1, max_attempts + 1):
        try:
            # Check current size of zip file if it exists to resume
            if zip_file.exists() and downloaded_bytes == 0:
                downloaded_bytes = zip_file.stat().st_size
                
            request_headers = headers.copy()
            if downloaded_bytes > 0:
                request_headers["Range"] = f"bytes={downloaded_bytes}-"
                logger.info(f"     Resuming download from byte {downloaded_bytes}...")
                
            with session.get(url, headers=request_headers, stream=True, timeout=30) as response:
                status = response.status_code
                if status == 206 and downloaded_bytes > 0:
                    write_mode = 'ab'
                elif status == 200:
                    write_mode = 'wb'
                    downloaded_bytes = 0
                else:
                    logger.warning(f"   ✖ HTTP {status} received for {ecosystem} on attempt {attempt}")
                    if status not in (429, 500, 502, 503, 504):
                        logger.error(f"❌ Non-retryable HTTP {status} for {ecosystem}, aborting")
                        if zip_file.exists():
                            try:
                                zip_file.unlink()
                            except Exception:
                                pass
                        return False
                    raise requests.exceptions.RequestException(f"HTTP status {status}")

                with open(zip_file, write_mode) as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded_bytes += len(chunk)
                            
            logger.info(f"✅ Downloaded and saved OSV feed for {ecosystem}")
            return True
        except (requests.exceptions.RequestException, Exception) as e:
            if zip_file.exists():
                downloaded_bytes = zip_file.stat().st_size
            else:
                downloaded_bytes = 0
            logger.error(f"   ✖ Network error or incomplete read on attempt {attempt} for {ecosystem}: {e}")
            time.sleep(2)
            
    if zip_file.exists():
        try:
            zip_file.unlink()
        except Exception:
            pass
    return False

def download_all_osv_ecosystems(feed_dir="osv_feeds", force_update=False, show_progress=True, max_workers=1):
    ecosystems = ["PyPI", "npm", "Go", "Maven"]
    
    # Filter for ecosystems that actually need an update
    if not force_update:
        stale_ecosystems = []
        now = datetime.now()
        feed_base = Path(feed_dir)
        for eco in ecosystems:
            zip_file = feed_base / eco / "all.zip"
            if not zip_file.exists():
                logger.info(f"   ℹ️ Ecosystem {eco}: missing, will download")
                stale_ecosystems.append(eco)
                continue
            
            # Verify it's actually a valid ZIP file
            if not zipfile.is_zipfile(zip_file):
                logger.warning(f"   ⚠️ Ecosystem {eco}: corrupt ZIP, will redownload")
                stale_ecosystems.append(eco)
                continue

            last_mod = datetime.fromtimestamp(zip_file.stat().st_mtime)
            age = now - last_mod
            if age > timedelta(hours=24):
                logger.info(f"   ℹ️ Ecosystem {eco}: stale ({age.total_seconds() / 3600:.1f}h old), will download")
                stale_ecosystems.append(eco)
            else:
                logger.debug(f"   ℹ️ Ecosystem {eco}: fresh ({age.total_seconds() / 3600:.1f}h old)")
        ecosystems = stale_ecosystems

    if not ecosystems:
        logger.info("✅ All OSV feeds are fresh, skipping download.")
        return 0

    logger.info(f"ℹ️ Downloading {len(ecosystems)} OSV feeds into '{feed_dir}' (max_workers={max_workers})")

    downloaded_count = 0
    def download_wrapper(eco):
        nonlocal downloaded_count
        success = download_osv_ecosystem(eco, feed_dir, force_update=force_update)
        if success:
            downloaded_count += 1
        return success

    if max_workers > 1:
        if show_progress:
            try:
                from tqdm import tqdm
                with tqdm(total=len(ecosystems), desc="Downloading OSV feeds (parallel)", unit="ecosystem") as pbar:
                    with ThreadPoolExecutor(max_workers=max_workers) as executor:
                        futures = {executor.submit(download_wrapper, eco): eco for eco in ecosystems}
                        for future in as_completed(futures):
                            future.result()
                            pbar.update(1)
            except ImportError:
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    list(executor.map(download_wrapper, ecosystems))
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                list(executor.map(download_wrapper, ecosystems))
    else:
        if show_progress:
            try:
                from tqdm import tqdm
                iterator = tqdm(ecosystems, desc="Downloading OSV feeds", unit="ecosystem")
            except ImportError:
                iterator = ecosystems
        else:
            iterator = ecosystems

        for ecosystem in iterator:
            download_wrapper(ecosystem)
            
    return downloaded_count



_SUPPRESSION_RULES = None

def get_suppression_rules() -> dict:
    global _SUPPRESSION_RULES
    if _SUPPRESSION_RULES is None:
        _SUPPRESSION_RULES = {}
        try:
            file_path = os.path.join(os.getcwd(), "suppression_rules.json")
            if not os.path.exists(file_path):
                base_path = os.path.dirname(os.path.abspath(__file__))
                file_path = os.path.join(base_path, "data", "suppression_rules.json")
            
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    _SUPPRESSION_RULES = json.load(f)
                logger.debug(f"Loaded suppression rules from {file_path}")
        except Exception as e:
            logger.error(f"Error loading suppression rules: {e}")
    return _SUPPRESSION_RULES

def is_vulnerability_applicable(description: str, target_version: str, product_name: str) -> bool:
    """
    Perform description-based validation to suppress false positives dynamically
    without manually adding them to exclusions or hardcoding package-specific rules.
    """
    if not description or not target_version:
        return True
        
    desc_lower = description.lower()
    comp_lower = product_name.lower()
    if ":" in comp_lower:
        comp_lower = comp_lower.split(":", 1)[1]
    
    # 0. Suppress disputed vulnerabilities (common false positives where vendors state there is no risk)
    if any(phrase in desc_lower for phrase in ["** disputed **", "the vendor disputes", "vulnerability is disputed"]):
        logger.debug(f"ℹ️ Suppressing disputed vulnerability for {product_name}")
        return False

    rules = get_suppression_rules()

    # 0.05. Suppress standalone base app false positives matching sub-products/extensions
    # e.g., NGINX base server matching NGINX-UI or NGINX Management Suite
    standalone_extensions = rules.get("standalone_extensions", {})
    if comp_lower in standalone_extensions:
        for ext in standalone_extensions[comp_lower]:
            if ext in desc_lower:
                logger.debug(f"ℹ️ Suppressing sub-product/extension vulnerability for base component: {product_name} ({ext})")
                return False

    # 0.06. Suppress edition/package-level exclusivity false positives (e.g., NGINX Plus vs NGINX OSS)
    edition_exclusivity = rules.get("edition_exclusivity", {})
    if comp_lower in edition_exclusivity:
        ex_rule = edition_exclusivity[comp_lower]
        restricted = ex_rule.get("restricted_terms", [])
        allowed = ex_rule.get("allowed_terms", [])
        if any(term in desc_lower for term in restricted) and not any(term in desc_lower for term in allowed):
            logger.debug(f"ℹ️ Suppressing edition-restricted vulnerability for base component: {product_name}")
            return False

    # 0.1. Suppress subproject-specific vulnerabilities for generic base components (dynamic)
    subproject_mismatches = rules.get("subproject_mismatches", {})
    for base_comp, suffixes in subproject_mismatches.items():
        if base_comp == comp_lower or base_comp in comp_lower:
            for suffix in suffixes:
                subproject_indicator = f"{base_comp}-{suffix}"
                if (subproject_indicator in desc_lower or suffix in desc_lower) and suffix not in comp_lower:
                    logger.debug(f"ℹ️ Suppressing subproject vulnerability for generic component: {product_name} ({subproject_indicator})")
                    return False

    # 0.5. Suppress namespace mismatches (e.g. "vulnerability in ebookmeta.get_metadata function of lxml")
    namespace_match = re.search(r"in the\s+([a-zA-Z0-9_-]+)\.[a-zA-Z0-9_\.-]+\s+(?:function|method|class|module|interface|api|component)", desc_lower)
    if namespace_match:
        namespace = namespace_match.group(1)
        if namespace not in ["org", "com", "net", "java", "javax", "jakarta", "apache", "google", "microsoft", "apple"]:
            if namespace != comp_lower and namespace not in comp_lower and comp_lower not in namespace:
                logger.debug(f"ℹ️ Suppressing false positive due to namespace mismatch: {product_name} is not {namespace}")
                return False
                
    # 0.6. Suppress Java/Maven/npm submodule/artifact mismatches (e.g. netty-common matching netty-handler CVE)
    if "-" in comp_lower:
        parts = comp_lower.split("-")
        prefix = parts[0]
        if prefix in ["netty", "spring", "jackson", "apache", "commons", "jetty", "quarkus", "micronaut", "aws", "google", "protobuf"]:
            found_submodules = re.findall(rf"\b({prefix}-[a-z0-9-]+)\b", desc_lower)
            if found_submodules:
                if not any(sub == comp_lower or sub in comp_lower or comp_lower in sub for sub in found_submodules):
                    logger.debug(f"ℹ️ Suppressing false positive due to submodule mismatch: {product_name} is not in {found_submodules}")
                    return False
                    
    # 0.7. Suppress client library vs broker/server/cluster mismatch (e.g. kafka-clients matching broker/cluster CVEs)
    client_rules = rules.get("client_broker_mismatch", {})
    if "client" in comp_lower and client_rules:
        server_concepts = client_rules.get("server_concepts", [])
        if any(sc in desc_lower for sc in server_concepts):
            client_keywords = client_rules.get("client_keywords", ["client library", "client-side", "client configuration"])
            if not any(kw in desc_lower for kw in client_keywords):
                client_indicators = client_rules.get("client_indicators", [])
                if "client" not in desc_lower or any(kw in desc_lower for kw in client_indicators):
                    logger.debug(f"ℹ️ Suppressing broker/cluster-only vulnerability for client component: {product_name}")
                    return False
                    
    # 0.8. Suppress Spring web/security layer vulnerabilities for base core components (e.g. spring-core matching spring-mvc)
    spring_rules = rules.get("spring_base_mismatch", {})
    if spring_rules:
        spring_base = spring_rules.get("base_components", [])
        if comp_lower in spring_base:
            spring_web_layers = spring_rules.get("web_layers", [])
            if any(layer in desc_lower for layer in spring_web_layers):
                core_keywords = spring_rules.get("core_keywords", [])
                if not any(kw in desc_lower for kw in core_keywords):
                    logger.debug(f"ℹ️ Suppressing Spring web/layer vulnerability for base component: {product_name}")
                    return False

    # 0.9. Suppress Netty handler/codec/resolver vulnerabilities for utility/buffer components (e.g. netty-common matching netty-codec)
    netty_rules = rules.get("netty_module_mismatch", {})
    if comp_lower.startswith("netty-") and netty_rules:
        netty_base = netty_rules.get("base_components", [])
        if comp_lower in netty_base:
            codec_handler_terms = list(netty_rules.get("codec_handler_terms", []))
            if comp_lower in ["netty-common", "netty-buffer"]:
                resolver_terms = netty_rules.get("resolver_only_terms", [])
                codec_handler_terms.extend(resolver_terms)
                
            desc_clean = desc_lower.replace(" ", "").replace("-", "").replace("_", "")
            if any(term in desc_clean for term in codec_handler_terms):
                logger.debug(f"ℹ️ Suppressing Netty handler/codec/resolver vulnerability for utility component: {product_name}")
                return False
                
    # 0.95. Suppress Log4j Core implementation vulnerabilities on API/Bridge components (e.g. log4j-to-slf4j matching core layouts)
    log4j_rules = rules.get("log4j_module_mismatch", {})
    if comp_lower.startswith("log4j-") and log4j_rules:
        api_comps = log4j_rules.get("api_components", [])
        if comp_lower in api_comps:
            # First, check if description explicitly scopes this only to Log4j Core using configured phrases
            core_only_phrases = log4j_rules.get("core_only_phrases", [])
            api_exclusion_phrases = log4j_rules.get("api_exclusion_phrases", [])
            if core_only_phrases and any(phrase in desc_lower for phrase in core_only_phrases):
                if not any(phrase in desc_lower for phrase in api_exclusion_phrases):
                    logger.debug(f"ℹ️ Suppressing Log4j Core-only vulnerability for API/Bridge component: {product_name}")
                    return False
            
            core_keywords = log4j_rules.get("core_keywords", [])
            if any(kw in desc_lower for kw in core_keywords):
                api_indicators = log4j_rules.get("api_indicators", [])
                if not any(kw in desc_lower for kw in api_indicators):
                    logger.debug(f"ℹ️ Suppressing Log4j Core implementation vulnerability for API/Bridge component: {product_name}")
                    return False
    
    # 1. Module / Scope Validation (HTTP vs Non-HTTP)
    if any(kw in desc_lower for kw in ["http/1", "http/2", "chunked transfer", "request smuggling", "http request", "cookie", "websocket"]):
        # If the library is native-dns, resolver, common utils, etc., and does not mention http/web/codec
        if any(kw in comp_lower for kw in ["dns", "resolver", "common", "buffer", "transport", "handler"]):
            if not any(kw in comp_lower for kw in ["http", "codec", "server", "web", "api"]):
                logger.debug(f"ℹ️ Suppressed false positive: {product_name} is not applicable to HTTP vulnerability based on description.")
                return False
                
    # 2. Description-based version limit check
    try:
        target_v = safe_parse_version(target_version, product_name)
        if target_v:
            # Extract version limits from description (e.g. before 1.4.21, prior to 4.1.132)
            pattern = r"(?:before|prior to|earlier than|versions less than)\s+([0-9]+\.[0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9.]+)?)"
            limits = re.findall(pattern, desc_lower)
            if limits:
                for limit_str in limits:
                    try:
                        limit_v = safe_parse_version(limit_str, product_name)
                        if limit_v:
                            # Compare if installed version is newer or on a fixed branch
                            if target_v.major > limit_v.major:
                                logger.debug(f"ℹ️ Suppressed false positive: Installed {product_name} version {target_version} is >= described fix version {limit_str}.")
                                return False
                            elif target_v.major == limit_v.major:
                                if target_v.minor > limit_v.minor or (target_v.minor == limit_v.minor and target_v >= limit_v):
                                    logger.debug(f"ℹ️ Suppressed false positive: Installed {product_name} version {target_version} is >= described fix version {limit_str}.")
                                    return False
                    except:
                        pass
    except:
        pass
    # 2.5. Suppress build-time/compiler vulnerabilities on runtime components (e.g. kotlin-stdlib matching kotlin build cache CVEs)
    build_runtime_rules = rules.get("build_vs_runtime_exclusions", {})
    for base_comp, rule in build_runtime_rules.items():
        if base_comp == comp_lower or base_comp in comp_lower:
            runtime_components = rule.get("runtime_components", [])
            if any(rc in comp_lower for rc in runtime_components):
                build_keywords = rule.get("keywords", [])
                if any(kw in desc_lower for kw in build_keywords):
                    logger.debug(f"ℹ️ Suppressing build-time vulnerability for runtime component: {product_name}")
                    return False
        
    return True

class LocalFeedManager:
    def __init__(self, feed_dir="nvd_feeds", osv_dir="osv_feeds"):
        self.feed_dir = Path(feed_dir)
        self.osv_dir = Path(osv_dir)
        self.index = defaultdict(list)
        self.osv_index = defaultdict(list)
        self.cve_id_index = {}
        self.osv_id_index = {}
        self.loaded = False
        self._feed_files = []
    def load_feeds(self, show_progress=True):
        """Load all NVD and OSV feeds with concurrency and optimization"""
        if self.loaded:
            return
        self.index.clear()
        json_files = sorted(self.feed_dir.glob("nvdcve-2.0-*.json"))
        if not json_files:
            logger.error("❌ No NVD feed files found. Run with --update-feeds first.")
            return
        
        self._feed_files = json_files
        total_cves = 0

        # Helper to parse a single NVD JSON feed file
        def parse_nvd_file(json_file):
            file_index = defaultdict(list)
            file_cve_id_index = {}
            count = 0
            try:
                with open(json_file, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                    vulns = data.get("vulnerabilities", [])
                    for vuln in vulns:
                        # Modify in-place to avoid expensive dict copy
                        vuln['nvd_feed_file'] = json_file.name
                        cve_obj = vuln.get("cve", {})
                        cve_id = cve_obj.get("id")
                        if cve_id:
                            file_cve_id_index[cve_id] = vuln
                            
                        configs = cve_obj.get("configurations", [])
                        for config in configs:
                            for node in config.get("nodes", []):
                                for cpe_match in node.get("cpeMatch", []):
                                    if not cpe_match.get("vulnerable") or not cpe_match.get("criteria"):
                                        continue
                                    cpe_uri = cpe_match.get("criteria")
                                    cpe_parts = cpe_uri.split(":")
                                    if len(cpe_parts) >= 6:
                                        vendor = cpe_parts[3].lower()
                                        product = cpe_parts[4].lower()
                                        file_index[(vendor, product)].append({
                                            "vuln": vuln,
                                            "cpe_match": cpe_match
                                        })
                                        
                        # Parse CNA-provided "affected" block (useful for CVEs Undergoing Analysis that lack configurations)
                        affected_list = cve_obj.get("affected", []) if not configs else []
                        for affected in affected_list:
                            for data_item in affected.get("affectedData", []):
                                vendor = str(data_item.get("vendor", "")).lower().strip()
                                product = str(data_item.get("product", "")).lower().strip()
                                if not vendor or not product:
                                    continue
                                
                                # Normalize vendor/product names for CPE matching
                                prod_clean = product.lower().replace("_", " ").replace("-", " ")
                                rules = get_suppression_rules()
                                product_normalizations = rules.get("product_normalizations", {})
                                for target_name, synonyms in product_normalizations.items():
                                    if prod_clean in synonyms:
                                        product = target_name
                                        vendor = target_name
                                        break
                                
                                for ver_entry in data_item.get("versions", []):
                                    if ver_entry.get("status") != "affected":
                                        continue
                                    
                                    synthetic_match = {
                                        "vulnerable": True,
                                        "criteria": f"cpe:2.3:a:{vendor}:{product}:{ver_entry.get('version', '*')}:*:*:*:*:*:*:*"
                                    }
                                    
                                    v_start = ver_entry.get("version")
                                    v_less_than = ver_entry.get("lessThan")
                                    v_less_than_or_equal = ver_entry.get("lessThanOrEqual")
                                    
                                    is_range = bool(v_less_than or v_less_than_or_equal)
                                    if v_start and v_start != "0" and is_range:
                                        synthetic_match["versionStartIncluding"] = v_start
                                    
                                    if v_less_than:
                                        if v_less_than == "*":
                                            pass
                                        else:
                                            synthetic_match["versionEndExcluding"] = v_less_than
                                    elif v_less_than_or_equal:
                                        synthetic_match["versionEndIncluding"] = v_less_than_or_equal
                                        
                                    file_index[(vendor, product)].append({
                                        "vuln": vuln,
                                        "cpe_match": synthetic_match
                                    })
                        count += 1
            except Exception as e:
                logger.error(f"❌ Error loading {json_file}: {e}")
            return count, file_index, file_cve_id_index

        logger.info("📥 Loading NVD feeds concurrently...")
        start_nvd = time.time()
        
        # Parallel load using ThreadPoolExecutor
        max_workers = 2
        
        pbar = None
        if show_progress:
            try:
                from tqdm import tqdm
                pbar = tqdm(total=len(json_files), desc="Loading NVD feeds", unit="file")
            except ImportError:
                pass

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(parse_nvd_file, jf): jf for jf in json_files}
            for future in as_completed(futures):
                count, file_index, file_cve_id_index = future.result()
                total_cves += count
                # Merge local indexes into main memory indexes
                self.cve_id_index.update(file_cve_id_index)
                for key, val in file_index.items():
                    self.index[key].extend(val)
                if pbar:
                    pbar.update(1)
        if pbar:
            pbar.close()

        logger.info(f"✅ Loaded {total_cves} CVEs from {len(json_files)} NVD feeds in {time.time() - start_nvd:.2f}s")
        
        # --- OSV Loading ---
        osv_zips = list(self.osv_dir.rglob("all.zip")) if self.osv_dir.exists() else []
        total_osv = 0
        
        def parse_osv_zip(zip_path):
            zip_index = defaultdict(list)
            zip_id_index = {}
            count = 0
            try:
                with zipfile.ZipFile(zip_path, 'r') as z:
                    for filename in z.namelist():
                        if not filename.endswith('.json'):
                            continue
                        with z.open(filename) as f:
                            vuln_data = json.load(f)
                            
                        # Skip withdrawn advisories (withdrawn CVEs or GHSAs)
                        if "withdrawn" in vuln_data:
                            continue
                            
                        vuln_id = vuln_data.get("id")
                        if vuln_id:
                            zip_id_index[vuln_id] = vuln_data
                            
                        affected = vuln_data.get("affected", [])
                        for aff in affected:
                            pkg = aff.get("package", {})
                            eco = pkg.get("ecosystem", "").lower()
                            name = pkg.get("name", "").lower()
                            if eco and name:
                                zip_index[(eco, name)].append({
                                    "vuln": vuln_data,
                                    "affected": aff
                                })
                                # Tag the ecosystem for later fallback use
                                if "feed_ecosystem" not in vuln_data:
                                    vuln_data["feed_ecosystem"] = eco
                        count += 1
            except Exception as e:
                logger.error(f"❌ Error loading OSV zip {zip_path}: {e}")
            return count, zip_index, zip_id_index

        if osv_zips:
            logger.info("📥 Loading OSV feeds concurrently...")
            start_osv = time.time()
            
            pbar_osv = None
            if show_progress:
                try:
                    from tqdm import tqdm
                    pbar_osv = tqdm(total=len(osv_zips), desc="Loading OSV feeds", unit="ecosystem")
                except ImportError:
                    pass

            with ThreadPoolExecutor(max_workers=1) as executor:
                futures_osv = {executor.submit(parse_osv_zip, zp): zp for zp in osv_zips}
                for future in as_completed(futures_osv):
                    count, zip_index, zip_id_index = future.result()
                    total_osv += count
                    self.osv_id_index.update(zip_id_index)
                    for key, val in zip_index.items():
                        self.osv_index[key].extend(val)
                    if pbar_osv:
                        pbar_osv.update(1)
            if pbar_osv:
                pbar_osv.close()
                
            logger.info(f"✅ Loaded {total_osv} OSV advisories from {len(osv_zips)} ecosystems in {time.time() - start_osv:.2f}s")
            
        self.loaded = True

    def search_cves_for_cpe(self, target_cpe, severity=None):
        if not self.loaded:
            return []
        
        if is_excluded_cpe(target_cpe):
            logger.warning(f"⚠️ Skipping excluded CPE: {target_cpe}")
            return []
        
        matched_cves = []
        parts = target_cpe.split(":")
        if len(parts) >= 6:
            target_vendor = parts[3].lower()
            target_product = parts[4].lower()
            target_version = parts[5]
            logger.debug(f"🔍 Searching CVEs for CPE: {target_cpe}")
        else:
            logger.error(f"Invalid CPE format: {target_cpe}")
            return []

        vendor_candidates = {target_vendor}
        product_candidates = {target_product}
        try:
            from vuln_checker.utils import get_vendor_aliases
            aliases_config = get_vendor_aliases()
            vendor_aliases = aliases_config.get("aliases", {})
            product_aliases = aliases_config.get("product_aliases", {})
            
            if target_vendor in vendor_aliases:
                vendor_candidates.update(vendor_aliases[target_vendor])
            for k, v in vendor_aliases.items():
                if target_vendor in v:
                    vendor_candidates.add(k)
                    
            if target_product in product_aliases:
                product_candidates.update(product_aliases[target_product])
            for k, v in product_aliases.items():
                if target_product in v:
                    product_candidates.add(k)
        except Exception as e:
            logger.debug(f"Could not load vendor/product aliases: {e}")

        cve_entries = []
        for v_cand in vendor_candidates:
            for p_cand in product_candidates:
                cve_entries.extend(self.index.get((v_cand, p_cand), []))
        logger.debug(f"   → Found {len(cve_entries)} potential NVD records for {target_vendor}:{target_product} (including aliases)")

        rules = get_suppression_rules()
        cve_exclusions = rules.get("cve_exclusions", {})

        for entry in cve_entries:
            vuln = entry["vuln"]
            cpe_match = entry["cpe_match"]
            cve_obj = vuln.get("cve", {})
            cve_id = cve_obj.get("id", "unknown")
            
            # Check for specific CVE/version exclusions from suppression_rules.json
            if cve_id in cve_exclusions:
                excluded_versions = [v.lower() for v in cve_exclusions[cve_id]]
                if target_version.lower() in excluded_versions:
                    continue
            
            # --- DESCRIPTION-BASED APP VALIDATION ---
            description_text = ""
            descriptions = cve_obj.get("descriptions", [])
            if isinstance(descriptions, list) and descriptions:
                description_text = descriptions[0].get("value", "")
            else:
                description_text = vuln.get("details", "")
                
            if not is_vulnerability_applicable(description_text, target_version, target_product):
                continue
            
            if severity:
                # Pre-process severity input (allow comma-separated string)
                if isinstance(severity, str):
                    target_severities = [s.strip().upper() for s in severity.split(',')]
                else:
                    target_severities = [str(severity).upper()]

                resolved_severity, _ = extract_cve_severity_and_score(cve_obj)
                if "ALL" not in target_severities and resolved_severity not in target_severities:
                    continue
            
            is_vulnerable = False
            cpe_uri = cpe_match.get("criteria")
            cpe_parts = cpe_uri.split(":")
            cpe_version = cpe_parts[5] if len(cpe_parts) >= 6 else None
            
            try:
                target_v = safe_parse_version(target_version, target_product)
                
                if cpe_version and cpe_version != "*":
                    try:
                        cpe_v = safe_parse_version(cpe_version, target_product)
                        if target_v == cpe_v:
                            is_vulnerable = True
                    except:
                        continue
                
                v_start = cpe_match.get("versionStartIncluding")
                v_start_ex = cpe_match.get("versionStartExcluding")
                v_end = cpe_match.get("versionEndIncluding")
                v_end_ex = cpe_match.get("versionEndExcluding")
                
                lower_match = True
                upper_match = True
                
                if v_start:
                    lower_match = target_v >= safe_parse_version(v_start, target_product)
                elif v_start_ex:
                    lower_match = target_v > safe_parse_version(v_start_ex, target_product)
                
                if v_end:
                    upper_match = target_v <= safe_parse_version(v_end, target_product)
                elif v_end_ex:
                    upper_match = target_v < safe_parse_version(v_end_ex, target_product)
                
                if v_start or v_start_ex or v_end or v_end_ex:
                    is_vulnerable = lower_match and upper_match
                
            except:
                continue
            
            if is_vulnerable:
                vuln_copy = dict(vuln)
                v_end_ex = cpe_match.get("versionEndExcluding")
                v_end = cpe_match.get("versionEndIncluding")
                if v_end_ex:
                    vuln_copy["upgrade_to"] = v_end_ex
                    vuln_copy["fix_version"] = v_end_ex
                elif v_end:
                    vuln_copy["upgrade_to"] = f"> {v_end}"
                    vuln_copy["fix_version"] = f"> {v_end}"
                matched_cves.append(vuln_copy)
        
        if matched_cves:
            logger.debug(f"   ✅ Matched {len(matched_cves)} CVEs for {target_cpe}")
        return matched_cves

    def generate_synthetic_cve_from_osv(self, vuln: dict) -> dict:
        """Converts an OSV vulnerability dictionary into a synthetic NVD CVE format."""
        cve_id = vuln.get("id", "N/A")
        aliases = vuln.get("aliases", [])
        
        # Create a synthetic NVD-style structure
        synthetic_cve = {
            "id": cve_id,
            "published": vuln.get("published", "N/A"),
            "lastModified": vuln.get("modified", "N/A"),
            "descriptions": [{"value": vuln.get("details", "")}],
            "aliases": aliases
        }
        
        # Check for NVD enrichment via aliases
        nvd_cve = None
        for alias in aliases:
            if str(alias).startswith("CVE-"):
                nvd_cve = self.get_cve_by_id(alias)
                if nvd_cve:
                    break
                    
        has_nvd_metrics = False
        if nvd_cve:
            # Inherit published date, metrics, etc from NVD
            nvd_data = nvd_cve.get("cve", {})
            synthetic_cve["published"] = nvd_data.get("published", synthetic_cve["published"])
            synthetic_cve["lastModified"] = nvd_data.get("lastModified", synthetic_cve["lastModified"])
            if "metrics" in nvd_data and nvd_data["metrics"]:
                synthetic_cve["metrics"] = nvd_data["metrics"]
                has_nvd_metrics = True
                
        if not has_nvd_metrics:
            db_sev = vuln.get("database_specific", {}).get("severity")
            score_val = "N/A"
            # Try to get vector string from severity array
            sev_arr = vuln.get("severity", [])
            if sev_arr and isinstance(sev_arr, list):
                score_val = sev_arr[0].get("score", "N/A")
            
            if db_sev or score_val != "N/A":
                synthetic_cve["metrics"] = {
                    "cvssMetricV31": [{"cvssData": {
                        "baseSeverity": normalize_severity(db_sev) if db_sev else "UNKNOWN",
                        "baseScore": score_val
                    }}]
                }
        return synthetic_cve

    def search_ghsa_for_package(self, ecosystem, package_name, target_version, severity=None):
        """
        Search for OSV advisories affecting a specific package version.
        Returns a list of synthetic NVD-like CVE dictionaries.
        """
        matched_vulns = []
        if not self.loaded:
            return matched_vulns
            
        eco = ecosystem.lower()
        pkg = package_name.lower()
        
        cve_entries = self.osv_index.get((eco, pkg), [])
        
        if not cve_entries:
            return []
            
        try:
            target_v = safe_parse_version(target_version, pkg)
        except:
            return []
            
        rules = get_suppression_rules()
        cve_exclusions = rules.get("cve_exclusions", {})

        for entry in cve_entries:
            vuln = entry["vuln"]
            affected = entry["affected"]

            # Check for specific CVE/version exclusions from suppression_rules.json
            vuln_id = vuln.get("id")
            aliases = vuln.get("aliases", [])
            is_excluded = False
            for v_id in [vuln_id] + aliases:
                if v_id and v_id in cve_exclusions:
                    excluded_versions = [v.lower() for v in cve_exclusions[v_id]]
                    if target_version.lower() in excluded_versions:
                        is_excluded = True
                        break
            if is_excluded:
                continue
            
            # Severity handling
            if severity:
                target_sevs = []
                if isinstance(severity, str):
                    target_sevs = [normalize_severity(s) for s in severity.split(',')]
                else:
                    target_sevs = [normalize_severity(str(severity))]
                
                # Check database_specific metadata for GitHub Advisories
                db_specific = vuln.get("database_specific", {})
                vuln_sev = normalize_severity(db_specific.get("severity", "UNKNOWN"))
                
                # Also check NVD-style aliases if available
                aliases = vuln.get("aliases", [])
                for alias in aliases:
                    if str(alias).startswith("CVE-"):
                        nvd_cve = self.get_cve_by_id(alias)
                        if nvd_cve:
                            cve_obj = nvd_cve.get("cve", {})
                            base_sev, _ = extract_cve_severity_and_score(cve_obj)
                            if base_sev and base_sev != "UNKNOWN":
                                vuln_sev = base_sev
                
                if vuln_sev not in target_sevs and "ALL" not in target_sevs:
                    continue

            # Version range matching
            is_vulnerable = False
            fix_version = None
            for range_item in affected.get("ranges", []):
                r_type = str(range_item.get("type", "")).upper()
                if r_type not in ("ECOSYSTEM", "SEMVER"):
                    continue # Skip GIT ranges to prevent parsing commit hashes as release versions
                
                events = range_item.get("events", [])
                
                # Trace whether target_v falls within any active introduced interval in this range
                is_active = False
                current_fix = None
                for ev in events:
                    if "introduced" in ev:
                        intro_str = ev["introduced"]
                        if intro_str == "0":
                            is_active = True
                            current_fix = None
                        else:
                            try:
                                intro_v = safe_parse_version(intro_str)
                                if target_v >= intro_v:
                                    is_active = True
                                    current_fix = None
                                else:
                                    # Since events are chronological, target_v is strictly before this and all future intervals.
                                    break
                            except:
                                pass
                    elif "fixed" in ev:
                        fixed_str = ev["fixed"]
                        try:
                            fixed_v = safe_parse_version(fixed_str)
                            if target_v >= fixed_v:
                                is_active = False
                            else:
                                current_fix = fixed_str
                        except:
                            # If we cannot parse the fix version, err on the side of safety but do not mark vulnerable
                            # if target_v is clearly past the other ecosystem versions.
                            pass
                    elif "last_affected" in ev:
                        la_str = ev["last_affected"]
                        try:
                            la_v = safe_parse_version(la_str)
                            if target_v > la_v:
                                is_active = False
                        except:
                            pass
                
                if is_active:
                    is_vulnerable = True
                    fix_version = current_fix
                    break
            
            # Direct version match
            if not is_vulnerable and target_version in affected.get("versions", []):
                is_vulnerable = True
                
            if is_vulnerable:
                synthetic_cve = self.generate_synthetic_cve_from_osv(vuln)
                desc_list = synthetic_cve.get("descriptions", [])
                description_text = desc_list[0].get("value", "") if desc_list else (vuln.get("details", "") or vuln.get("summary", ""))
                if not is_vulnerability_applicable(description_text, target_version, package_name):
                    continue
                
                adapted = {
                    "cve": synthetic_cve,
                    "component_name": package_name,
                    "component_version": target_version,
                    "ecosystem": ecosystem,
                    "feed_file": f"OSV - {ecosystem}"
                }
                if fix_version:
                    adapted["fix_version"] = fix_version
                    adapted["upgrade_to"] = fix_version
                matched_vulns.append(adapted)
                
        return matched_vulns

    def get_cve_by_id(self, cve_id: str):
        """Search all loaded feeds for a specific CVE ID using O(1) index."""
        if not self.loaded:
            return None
        return self.cve_id_index.get(cve_id)

    def get_osv_by_id(self, osv_id: str):
        """Search loaded OSV feeds for a specific OSV ID (e.g. GHSA-...) using O(1) index."""
        if not self.loaded:
            return None
        return self.osv_id_index.get(osv_id)
