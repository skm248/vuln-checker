"""SBOM Parsing & Processing"""
import json
import logging
import os
import threading
import concurrent.futures
from tqdm import tqdm
from vuln_checker.cve_cache import fetch_cves_cached_with_enrichment

logger = logging.getLogger(__name__)

def parse_cyclonedx_sbom_enhanced(sbom_file_path):
    try:
        with open(sbom_file_path, 'r', encoding='utf-8') as f:
            sbom_data = json.load(f)
        if sbom_data.get('bomFormat', '').lower() != 'cyclonedx':
            logger.error(f"❌ File {sbom_file_path} is not a valid CycloneDX SBOM")
            return []
        components_map = {} # (clean_name, version) -> tuple
        sbom_components = sbom_data.get('components', [])
        logger.info(f"📋 Found {len(sbom_components)} components in SBOM")
        
        for component in sbom_components:
            group = component.get('group', '')
            name = component.get('name', 'unknown')
            version = component.get('version', 'unknown')
            
            # Clean up the name if it's a full path
            clean_name = name.split('/')[-1].split('\\')[-1]
            if group:
                display_name = f"{group}:{clean_name}"
            else:
                display_name = clean_name
                
            # Use a unique key for deduplication
            key = (display_name, version)
            if key in components_map:
                continue

            purl = component.get('purl', '')
            primary_cpe = component.get('cpe', '')
            additional_cpes = []
            parent_jar = None
            path = None
            
            # Path extraction logic similar to server_scanner
            properties = component.get('properties', [])
            path_keys = ["syft:package:filePath", "syft:location:0:path", "syft:metadata:virtualPath", "syft:metadata:path"]
            path = next((p.get("value") for p in properties if p.get("name") in path_keys), None)
            
            if not path:
                locations = component.get("locations", [])
                if locations:
                    path = locations[0].get("path")

            for prop in properties:
                if prop.get('name') == 'syft:cpe23':
                    val = prop.get('value', '')
                    if val and val.startswith('cpe:2.3:a:'):
                        additional_cpes.append(val)
                if 'syft:metadata:virtualPath' in prop.get('name'):
                    path_val = prop.get('value', '')
                    jar_name = path_val.split("/")[-1].replace('.jar', '')
                    parent_jar = jar_name
            
            component_type = component.get('type', 'library')
            if component_type in ['library', 'application', 'framework']:
                components_map[key] = (display_name, version, primary_cpe, purl, additional_cpes, parent_jar, path)
                logger.debug(f"🚦 Parsed component: {display_name} v{version}")
        
        return list(components_map.values())
    except Exception as e:
        logger.error(f"❌ Error parsing SBOM file: {e}")
        return []

_cpe_file_cache = None

def lookup_cpe_from_txt(product, version, cpes_file):
    global _cpe_file_cache
    product = product.lower()
    version = version.lower()
    
    if _cpe_file_cache is None:
        active_path = cpes_file
        if not active_path or not os.path.exists(active_path):
            cwd_path = os.path.join(os.getcwd(), cpes_file or "cpes_list.txt")
            if os.path.exists(cwd_path):
                active_path = cwd_path
            else:
                pkg_path = os.path.join(os.path.dirname(__file__), "data", "cpes_list.txt")
                active_path = pkg_path if os.path.exists(pkg_path) else None

        if not active_path:
            _cpe_file_cache = []
        else:
            try:
                with open(active_path, "r", encoding="utf-8") as f:
                    _cpe_file_cache = [line.strip() for line in f if line.strip().startswith("cpe:2.3:a:")]
            except Exception:
                _cpe_file_cache = []

    for cpe in _cpe_file_cache:
        parts = cpe.split(":")
        if len(parts) >= 6:
            cpe_product = parts[4].lower()
            cpe_version = parts[5].lower()
            if cpe_product == product and cpe_version == version:
                return cpe
    return None

def process_single_component(component_data, args, feed_manager):
    component_name, component_version, primary_cpe, purl, additional_cpes, parent_jar, path = component_data
    logger.info(f"🔍 Processing: {component_name}, v{component_version}")
    all_component_cves = []
    severities = [s.strip().upper() for s in args.severity.split(",")] if args.severity else [None]
    
    cpe_list = [c for c in [primary_cpe] + additional_cpes if c and c.startswith('cpe:2.3:a:')]
    local_cpe = lookup_cpe_from_txt(component_name, component_version, getattr(args, 'cpes_file', None) or "cpes_list.txt")
    if local_cpe:
        cpe_list.append(local_cpe)
    
    from vuln_checker.utils import extract_cve_severity_and_score
    for cpe in cpe_list:
        cves = fetch_cves_cached_with_enrichment(
            cpe, feed_manager, severity=None, component_name=component_name, 
            component_version=component_version, purl=purl, path=path, parent_jar=parent_jar
        )
        if cves:
            filtered_cves = []
            for cve in cves:
                cve_obj = cve.get("cve", cve)
                cve_severity, _ = extract_cve_severity_and_score(cve_obj)
                if severities != [None] and cve_severity not in severities:
                    continue
                filtered_cves.append(cve)
            
            if filtered_cves:
                cve_ids = [c.get("cve", {}).get("id") for c in filtered_cves]
                logger.info(f"   ⭕ {component_name} v{component_version}: Found {len(filtered_cves)} vulnerabilities ({', '.join(cve_ids)})")
                all_component_cves.extend(filtered_cves)
            break
            
    if hasattr(feed_manager, 'search_ghsa_for_package') and purl:
        purl_parts = purl.split(':')
        if len(purl_parts) >= 2 and purl_parts[0] == 'pkg':
            eco_str = purl_parts[1].split('/')[0].lower()
            ecosystem = None
            if eco_str in ['npm', 'node']: ecosystem = "npm"
            elif eco_str in ['pypi', 'python']: ecosystem = "PyPI"
            elif eco_str in ['maven', 'java']: ecosystem = "Maven"
            elif eco_str in ['golang', 'go']: ecosystem = "Go"
            
            if ecosystem:
                # Use clean_name to search OSV (OSV Maven uses group:artifact which matches display_name)
                osv_cves = feed_manager.search_ghsa_for_package(ecosystem, component_name, component_version)
                if osv_cves:
                    for cve in osv_cves:
                        cve_obj = cve.get("cve", cve)
                        cve_severity, _ = extract_cve_severity_and_score(cve_obj)
                        if severities != [None] and cve_severity not in severities:
                            continue
                        
                        desc_text = ""
                        descriptions = cve_obj.get("descriptions", [])
                        if isinstance(descriptions, list) and descriptions:
                            desc_text = descriptions[0].get("value", "")
                        else:
                            desc_text = cve.get("details", "") or cve_obj.get("details", "")
                            
                        from vuln_checker.feed_manager import is_vulnerability_applicable, is_vulnerability_applicable_ecosystem
                        if not is_vulnerability_applicable_ecosystem(desc_text, component_name, purl, path):
                            continue
                        if not is_vulnerability_applicable(desc_text, component_version, component_name):
                            continue

                        # Enrich OSV finding with path and purl to allow matching with NVD during deduplication
                        cve["path"] = path or "N/A"
                        cve["purl"] = purl or "N/A"
                        cve["cpe_source"] = "ghsa"
                        all_component_cves.append(cve)
    
    return all_component_cves

def process_sbom_vulnerabilities_parallel(args, feed_manager, max_workers=5):
    if not args.sbom:
        return []
    components = parse_cyclonedx_sbom_enhanced(args.sbom)

    if getattr(args, "skip_search", False):
        components = [c for c in components if c[2] or c[4]]
    if getattr(args, "max_components", None):
        components = components[:args.max_components]

    logger.info(f"🚦 {len(components)} components to analyze")

    all_cves = []
    lock = threading.Lock()

    def worker(component):
        local_cves = process_single_component(component, args, feed_manager)
        with lock:
            all_cves.extend(local_cves)

    workers = max_workers if getattr(args, "fast", False) else 1
    logger.info(f"🚀 Starting processing with {workers} workers")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(worker, c) for c in components]
        for _ in tqdm(concurrent.futures.as_completed(futures), total=len(components), desc="Scanning SBOM", unit="comp"):
            pass

    return all_cves
