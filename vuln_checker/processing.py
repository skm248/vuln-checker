"""CSV/Products/CPEs Input Processing"""
import logging
import csv
import io
from tqdm import tqdm
from vuln_checker.cve_cache import fetch_cves_cached, fetch_cves_cached_with_enrichment

logger = logging.getLogger(__name__)

def process_csv_vulnerabilities(args, feed_manager):
    all_cves = []
    try:
        with open(args.input_csv, 'r', encoding='utf-8') as f:
            raw_lines = f.readlines()

        # Remove blank lines and comments starting with '#'
        useful_lines = [l for l in raw_lines if l.strip() and not l.strip().startswith('#')]
        if not useful_lines:
            logger.warning("⚠️ CSV file contains no usable lines (only comments/blank). Please add product rows under the header.")
            return []

        # First non-comment line should be the header. If there's no data rows, warn.
        header = useful_lines[0]
        data_lines = useful_lines[1:]
        if not data_lines:
            logger.warning("⚠️ CSV file contains a header but no data rows. Add product rows (product,version).")
            return []

        # Build a CSV reader from the filtered lines so progress counts reflect actual data rows
        reader_stream = io.StringIO(''.join([header] + data_lines))
        reader = csv.DictReader(reader_stream)
        rows_iter = tqdm(reader, desc="Processing CSV", unit="row", total=len(data_lines))

        for row in rows_iter:
                # Check for various header names (singular, plural, common variants)
                product_val = (row.get('products') or row.get('product') or row.get('name') or row.get('package') or '').strip()
                versions_str = (row.get('versions') or row.get('version') or '').strip()
                path_val = (row.get('path') or row.get('location') or '').strip()
                
                if not product_val: continue
                
                # If product_val is already a CPE, use it directly
                if product_val.startswith('cpe:2.3:'):
                    cpes_to_process = [(product_val, product_val, None, None)]
                else:
                    # Support vendor:product format
                    if ':' in product_val:
                        vendor, product = product_val.split(':', 1)
                    else:
                        vendor, product = product_val, product_val
                    
                    # Handle multiple versions (comma separated)
                    version_list = [v.strip() for v in versions_str.split(',') if v.strip()]
                    
                    # Handle unquoted versions (e.g., jquery,1.1.0,1.1.1 which creates extra columns)
                    # csv.DictReader stores extra columns under the None key by default
                    extra_values = row.get(None, [])
                    if isinstance(extra_values, list):
                        for val in extra_values:
                            v = val.strip()
                            if v and v not in version_list:
                                version_list.append(v)
                    elif isinstance(extra_values, str):
                        v = extra_values.strip()
                        if v and v not in version_list:
                            version_list.append(v)

                    cpes_to_process = []
                    for version in version_list:
                        cpe_str = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
                        cpes_to_process.append((cpe_str, f"{vendor}:{product} v{version}", f"{vendor}:{product}", version))
                
                for cpe, ident, name, ver in cpes_to_process:
                    # If it was a direct CPE, extract vendor:product and version if possible
                    if name is None:
                        parts = cpe.split(':')
                        if len(parts) >= 6:
                            name = f"{parts[3]}:{parts[4]}"
                            ver = parts[5]
                        else:
                            name = cpe
                            ver = "N/A"

                    logger.info(f"🔍 Processing: {ident} (from CSV)")
                    severities = [s.strip().upper() for s in args.severity.split(",")] if args.severity else [None]
                    found_for_this = 0
                    seen_cve_ids = set()

                    for sev in severities:
                        # 1. Search NVD (via CPE)
                        cves = fetch_cves_cached_with_enrichment(
                            cpe, feed_manager, severity=sev,
                            component_name=name,
                            component_version=ver,
                            path=path_val
                        )
                        for cve in cves:
                            cve["cpe_source"] = "csv_input"
                            cve_id = cve.get("cve", {}).get("id") or cve.get("id")
                            if cve_id: seen_cve_ids.add(cve_id)
                            found_for_this += 1
                            all_cves.append(cve)

                        # 2. Search OSV (GitHub Advisories) if it looks like a known ecosystem
                        if hasattr(feed_manager, 'search_ghsa_for_package'):
                            search_name = name
                            ecosystem = None
                            if ":" in name:
                                eco_prefix, pkg_name = name.split(":", 1)
                                if eco_prefix.lower() in ["npm", "node"]: 
                                    ecosystem = "npm"
                                    search_name = pkg_name
                                elif eco_prefix.lower() in ["pypi", "python"]: 
                                    ecosystem = "PyPI"
                                    search_name = pkg_name
                                elif eco_prefix.lower() in ["maven", "java"]: 
                                    ecosystem = "Maven"
                                    search_name = pkg_name
                                elif eco_prefix.lower() in ["go", "golang"]: 
                                    ecosystem = "Go"
                                    search_name = pkg_name

                            if ecosystem:
                                osv_cves = feed_manager.search_ghsa_for_package(ecosystem, search_name, ver, severity=sev)
                                for osv_cve in osv_cves:
                                    cve_id = osv_cve.get("id") or osv_cve.get("cve", {}).get("id")
                                    if cve_id and cve_id not in seen_cve_ids:
                                        seen_cve_ids.add(cve_id)
                                        osv_cve["cpe_source"] = "ghsa"
                                        osv_cve["path"] = path_val
                                        found_for_this += 1
                                        all_cves.append(osv_cve)

                    if found_for_this > 0:
                        logger.info(f"   ⭕ {ident}: Found {found_for_this} vulnerabilities")
    except Exception as e:
        logger.error(f"❌ Error processing CSV file: {e}")
    return all_cves

def process_products_vulnerabilities(args, feed_manager):
    all_cves = []
    product_groups = args.products.split()
    try:
        from tqdm import tqdm
        groups_iter = tqdm(product_groups, desc="Processing products", unit="group")
    except Exception:
        groups_iter = product_groups

    for group in groups_iter:
        if group.startswith('cpe:2.3:'):
            cpes_to_process = [(group, group, None, None)]
        else:
            parts = group.split(':')
            if len(parts) < 2: continue
            
            # Check if it's vendor:product:version,version or product:version,version
            if len(parts) >= 3:
                vendor = parts[0]
                product = parts[1]
                versions = ':'.join(parts[2:]).split(',')
            else:
                product = parts[0]
                vendor = product
                versions = parts[1].split(',')
                
            cpes_to_process = []
            for version in versions:
                version = version.strip()
                if not version: continue
                cpe_str = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
                cpes_to_process.append((cpe_str, f"{vendor}:{product} v{version}", f"{vendor}:{product}", version))
            
        for cpe, ident, name, ver in cpes_to_process:
            # Extract name and version for metadata
            parts = cpe.split(':')
            if len(parts) >= 6:
                name = f"{parts[3]}:{parts[4]}"
                ver = parts[5]
            else:
                name = ident
                ver = "N/A"

            logger.info(f"🔍 Processing: {ident} (from products string)")
            severities = [s.strip().upper() for s in args.severity.split(",")] if args.severity else [None]
            found_for_this = 0
            seen_cve_ids = set()

            for sev in severities:
                # 1. Search NVD (via CPE)
                cves = fetch_cves_cached_with_enrichment(
                    cpe, feed_manager, severity=sev,
                    component_name=name,
                    component_version=ver
                )
                for cve in cves:
                    cve["cpe_source"] = "products_input"
                    cve_id = cve.get("cve", {}).get("id") or cve.get("id")
                    if cve_id: seen_cve_ids.add(cve_id)
                    found_for_this += 1
                    all_cves.append(cve)

                # 2. Search OSV (GitHub Advisories) if it looks like a known ecosystem
                if hasattr(feed_manager, 'search_ghsa_for_package'):
                    ecosystem = None
                    # Try to guess ecosystem from vendor name or prefix
                    search_name = name
                    if ":" in name:
                        eco_prefix, pkg_name = name.split(":", 1)
                        if eco_prefix.lower() in ["npm", "node"]: 
                            ecosystem = "npm"
                            search_name = pkg_name
                        elif eco_prefix.lower() in ["pypi", "python"]: 
                            ecosystem = "PyPI"
                            search_name = pkg_name
                        elif eco_prefix.lower() in ["maven", "java"]: 
                            ecosystem = "Maven"
                            search_name = pkg_name
                        elif eco_prefix.lower() in ["go", "golang"]: 
                            ecosystem = "Go"
                            search_name = pkg_name
                    
                    # Fallback heuristics for common items
                    if not ecosystem:
                        # If a package exists in multiple, we might want to try them? 
                        # For now, let's keep it simple or use what the user provided.
                        pass

                    if ecosystem:
                        osv_cves = feed_manager.search_ghsa_for_package(ecosystem, search_name, ver, severity=sev)
                        for osv_cve in osv_cves:
                            cve_id = osv_cve.get("id") or osv_cve.get("cve", {}).get("id")
                            if cve_id and cve_id not in seen_cve_ids:
                                seen_cve_ids.add(cve_id)
                                osv_cve["cpe_source"] = "ghsa"
                                found_for_this += 1
                                all_cves.append(osv_cve)

            if found_for_this > 0:
                logger.info(f"   ⭕ {ident}: Found {found_for_this} vulnerabilities")
    return all_cves

def process_cpes_file_vulnerabilities(args, feed_manager):
    all_cves = []
    try:
        with open(args.cpes_file, 'r', encoding='utf-8') as f:
            raw_lines = f.readlines()

        # Filter out blanks and comment lines
        useful_lines = [l.strip() for l in raw_lines if l.strip() and not l.strip().startswith('#')]
        if not useful_lines:
            logger.warning("⚠️ CPEs file contains no usable CPE lines (only comments/blank). Please add one CPE per line in cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:* format.")
            return []

        try:
            from tqdm import tqdm
            lines_iter = tqdm(useful_lines, desc="Processing CPEs", unit="line", total=len(useful_lines))
        except Exception:
            lines_iter = useful_lines

        for line in lines_iter:
            cpe = line.strip()
            if not cpe or not cpe.startswith('cpe:2.3:'):
                continue
                
            parts = cpe.split(':')
            ident = cpe
            name = cpe
            ver = "N/A"
            if len(parts) >= 6:
                name = f"{parts[3]}:{parts[4]}"
                ver = parts[5]
                ident = f"{name} v{ver}"
            
            logger.info(f"🔍 Processing CPE: {cpe}")
            severities = [s.strip().upper() for s in args.severity.split(",")] if args.severity else [None]
            found_for_this = 0
            for sev in severities:
                # Use enriched caching to ensure consistency and store in cve_cache.json
                cves = fetch_cves_cached_with_enrichment(
                    cpe, feed_manager, severity=sev,
                    component_name=name,
                    component_version=ver
                )
                for cve in cves:
                    # Update source to reflect CPEs file input
                    cve["cpe_source"] = "cpe_file"
                    found_for_this += 1
                all_cves.extend(cves)
            if found_for_this > 0:
                logger.info(f"   ⭕ {ident}: Found {found_for_this} vulnerabilities")
    except Exception as e:
        logger.error(f"❌ Error processing CPEs file: {e}")
    return all_cves
