"""CVE Cache Management"""
import json
import logging
import os
import re
import time
import threading
from typing import Optional, List, Dict

logger = logging.getLogger(__name__)

def is_vulnerability_applicable_ecosystem(description: str, component_name: str, purl: str, path: str) -> bool:
    if not description:
        return True
    
    desc_lower = description.lower()
    comp_lower = (component_name or "").lower()
    purl_lower = (purl or "").lower()
    path_lower = (path or "").lower()
    
    # Identify target ecosystem based on purl and path
    is_python = "pkg:pypi" in purl_lower or "site-packages" in path_lower or "python" in path_lower or ".py" in path_lower
    is_node = "pkg:npm" in purl_lower or "node_modules" in path_lower or "package.json" in path_lower
    is_java = "pkg:maven" in purl_lower or ".jar" in path_lower or ".war" in path_lower or "pom.xml" in path_lower
    is_php = "pkg:composer" in purl_lower or "vendor/" in path_lower or "composer" in path_lower or ".php" in path_lower
    is_ruby = "pkg:gem" in purl_lower or "gems/" in path_lower or "gemfile" in path_lower or ".rb" in path_lower
    is_go = "pkg:golang" in purl_lower or "go.mod" in path_lower or "go.sum" in path_lower
    
    # PHP check (e.g. jmespath.php)
    if f"{comp_lower}.php" in desc_lower or f"{comp_lower}-php" in desc_lower or "in php" in desc_lower:
        if not is_php:
            return False
            
    # Ruby check (e.g. jmespath.rb)
    if f"{comp_lower}.rb" in desc_lower or f"{comp_lower}-ruby" in desc_lower or "for ruby" in desc_lower or "in ruby" in desc_lower:
        if not is_ruby:
            return False
            
    # Go dependency mismatch check (e.g. prometheus dependency inside loki binary)
    if is_go and path_lower:
        bin_name = os.path.basename(path_lower)
        if bin_name and bin_name != comp_lower:
            standalone_apps = set()
            try:
                from vuln_checker.utils import get_vendor_aliases
                aliases_config = get_vendor_aliases()
                standalone_apps = set(aliases_config.get("standalone_apps", []))
            except Exception:
                pass
            if comp_lower in standalone_apps:
                return False
                
    return True


class CPECache:
    def __init__(self, cache_file="cve_cache.json"):
        self.cache_file = cache_file
        self.lock = threading.Lock()
        self.cache = self.load_cache()
        self.last_saved = time.time()

    def load_cache(self):
        try:
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {}

    def save_cache(self):
        with self.lock:
            cache_copy = dict(self.cache)
            try:
                with open(self.cache_file, 'w') as f:
                    json.dump(cache_copy, f, indent=2)
                self.last_saved = time.time()
            except Exception as e:
                logger.error(f"Failed to save CVE cache: {e}")

    def get_cves(self, cpe_uri, severity=None):
        key = f"{cpe_uri}_{severity or 'ALL'}"
        return self.cache.get(key)

    def set_cves(self, cpe_uri, severity, cves):
        key = f"{cpe_uri}_{severity or 'ALL'}"
        cached_cves = []
        for cve in cves:
            cached_cve = dict(cve)
            # Extract id
            cve_obj = cached_cve.get("cve", {})
            cve_id = cve_obj.get("id") or cached_cve.get("id")
            
            # Strip large nested 'cve' data to optimize storage space by ~99%
            if "cve" in cached_cve:
                del cached_cve["cve"]
                
            cached_cve["id"] = cve_id
            if 'feed_file' not in cached_cve and 'nvd_feed_file' not in cached_cve:
                cached_cve['nvd_feed_file'] = 'unknown'
            cached_cves.append(cached_cve)
        
        with self.lock:
            self.cache[key] = {
                'cves': cached_cves,
                'timestamp': time.time(),
                'cpe': cpe_uri
            }
            # Only save to disk if at least 15 seconds have passed since the last save
            should_save = (time.time() - self.last_saved) > 15.0
            
        if should_save:
            self.save_cache()

    def is_fresh(self, entry, max_age_hours=24):
        return (time.time() - entry['timestamp']) < (max_age_hours * 3600)

GLOBAL_CACHE = CPECache()

def fetch_cves_from_local_feeds(cpe_uri, feed_manager, severity=None):
    if not feed_manager or not feed_manager.loaded:
        logger.error("❌ Local feeds not loaded.")
        return []
    return feed_manager.search_cves_for_cpe(cpe_uri, severity)

def fetch_cves_cached(cpe_uri, feed_manager, severity=None, bypass_cache=False, cache_obj=None):
    cache = cache_obj or GLOBAL_CACHE
    if not bypass_cache:
        cached_entry = cache.get_cves(cpe_uri, severity)
        if cached_entry and cache.is_fresh(cached_entry):
            logger.debug(f"[CACHE] Using cached CVEs for {cpe_uri}")
            reconstructed = []
            for entry in cached_entry['cves']:
                cve_id = entry.get("id")
                full_cve = feed_manager.get_cve_by_id(cve_id) if cve_id else None
                if not full_cve and cve_id and cve_id.startswith("GHSA-"):
                    osv_data = feed_manager.get_osv_by_id(cve_id)
                    if osv_data:
                        synthetic = feed_manager.generate_synthetic_cve_from_osv(osv_data)
                        full_cve = {"cve": synthetic, "feed_file": f"OSV - {osv_data.get('feed_ecosystem', 'unknown')}"}
                
                if full_cve:
                    item = dict(entry)
                    item["cve"] = full_cve.get("cve", full_cve)
                    item["feed_file"] = full_cve.get("feed_file") or full_cve.get("nvd_feed_file") or item.get("feed_file")
                    reconstructed.append(item)
                else:
                    reconstructed.append(entry)
            return reconstructed
    
    cves = fetch_cves_from_local_feeds(cpe_uri, feed_manager, severity)
    cache.set_cves(cpe_uri, severity, cves)
    return cves

def fetch_cves_cached_with_enrichment(cpe_uri, feed_manager, severity=None, component_name="", 
                                     component_version="", purl="", path=None, parent_jar=None, cache_obj=None):
    cache = cache_obj or GLOBAL_CACHE
    cached_entry = cache.get_cves(cpe_uri, severity)
    if cached_entry and cache.is_fresh(cached_entry):
        # Reconstruct full CVEs from feed manager indexes
        reconstructed = []
        from vuln_checker.feed_manager import is_vulnerability_applicable
        for entry in cached_entry['cves']:
            cve_id = entry.get("id")
            full_cve = feed_manager.get_cve_by_id(cve_id) if cve_id else None
            if not full_cve and cve_id and cve_id.startswith("GHSA-"):
                osv_data = feed_manager.get_osv_by_id(cve_id)
                if osv_data:
                    synthetic = feed_manager.generate_synthetic_cve_from_osv(osv_data)
                    full_cve = {"cve": synthetic, "feed_file": f"OSV - {osv_data.get('feed_ecosystem', 'unknown')}"}
            
            if full_cve:
                item = dict(entry)
                cve_data = full_cve.get("cve", full_cve)
                item["cve"] = cve_data
                item["feed_file"] = full_cve.get("feed_file") or full_cve.get("nvd_feed_file") or item.get("feed_file")
                
                # Check description-based applicability rules on cached entry
                description_text = ""
                descriptions = cve_data.get("descriptions", [])
                if isinstance(descriptions, list) and descriptions:
                    description_text = descriptions[0].get("value", "")
                else:
                    description_text = full_cve.get("details", "") or cve_data.get("details", "")
                    
                if not is_vulnerability_applicable_ecosystem(description_text, component_name, purl, path):
                    continue
                    
                if not is_vulnerability_applicable(description_text, component_version, component_name):
                    continue
                    
                reconstructed.append(item)
            else:
                reconstructed.append(entry)
        return reconstructed

    raw_cves = fetch_cves_from_local_feeds(cpe_uri, feed_manager, severity)
    final_cves = []
    for cve in raw_cves:
        cve_data = cve.get("cve", cve)
        description_text = ""
        descriptions = cve_data.get("descriptions", [])
        if isinstance(descriptions, list) and descriptions:
            description_text = descriptions[0].get("value", "")
        else:
            description_text = cve.get("details", "") or cve_data.get("details", "")
            
        if not is_vulnerability_applicable_ecosystem(description_text, component_name, purl, path):
            logger.debug(f"ℹ️ Suppressing false positive due to ecosystem mismatch: {component_name} matches {cve_data.get('id')}")
            continue

        from vuln_checker.feed_manager import is_vulnerability_applicable
        if not is_vulnerability_applicable(description_text, component_version, component_name):
            logger.debug(f"ℹ️ Suppressing false positive due to component mismatch: {component_name} matches {cve_data.get('id')}")
            continue

        product_field = f"{component_name}:{component_version}"
        if parent_jar and parent_jar not in (component_name, "", component_version):
            product_field += f" ({parent_jar})"
        
        enriched_cve = {
            "cve": cve_data,
            "product": product_field,
            "component_name": component_name,
            "component_version": component_version,
            "path": path or "N/A",
            "sbom": True,
            "purl": purl or "N/A",
            "cpe_used": cpe_uri,
            "cpe_source": "local_feeds",
            "nvd_feed_file": cve.get('nvd_feed_file', 'unknown'),
            "feed_file": cve.get('feed_file'),
            "upgrade_to": cve.get("upgrade_to") or cve.get("fix_version"),
            "fix_version": cve.get("fix_version") or cve.get("upgrade_to"),
        }
        final_cves.append(enriched_cve)
    
    cache.set_cves(cpe_uri, severity, final_cves)
    return final_cves
