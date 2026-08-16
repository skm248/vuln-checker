import os
import sys
import time
import json
import logging
from collections import defaultdict
from vuln_checker.feed_manager import (
    LocalFeedManager, nvd_feeds_need_update, download_all_nvd_feeds, download_all_osv_ecosystems
)
from vuln_checker.server_scanner import (
    collect_server_packages, scan_server_vulnerabilities, store_server_inventory
)
from vuln_checker.sbom_parser import process_sbom_vulnerabilities_parallel
from vuln_checker.processing import (
    process_csv_vulnerabilities, process_products_vulnerabilities,
    process_cpes_file_vulnerabilities,
)
from vuln_checker.output_formatters import (
    output_results, output_results_excel, output_results_sbom_enhanced,
    generate_html_report, _extract_cve_data
)
from vuln_checker.features import apply_vex, deduplicate_findings, add_remediation_info, compute_delta, normalize_component_name, is_pseudo_version
from vuln_checker.utils import get_listening_ports

logger = logging.getLogger(__name__)

def normalize_path(path_str):
    if not path_str:
        return ""
    return str(path_str).replace("\\", "/").strip("/")


class VulnerabilityScanPipeline:
    """Orchestrates the entire vulnerability scanning, enrichment, and report generation pipeline."""

    def __init__(self, args, config):
        self.args = args
        self.config = config
        self.output_dir = config.get("output_dir", "reports")
        self.packages_info = defaultdict(list)
        os.makedirs(self.output_dir, exist_ok=True)

    def setup_feeds(self) -> LocalFeedManager:
        """Checks, downloads, and loads NVD/OSV vulnerability feeds."""
        start_year = self.args.start_year or self.config.get("start_year", 2002)
        osv_dir = os.path.join(os.path.dirname(self.args.feed_dir.rstrip("/\\")), "osv_feeds")
        
        from vuln_checker.retire_scanner import download_retire_db, get_retire_db_path
        no_update = getattr(self.args, 'no_update', False) or self.config.get("no_update", False)
        
        osv_missing = False
        for eco in ["PyPI", "npm", "Go", "Maven"]:
            if not os.path.exists(os.path.join(osv_dir, eco, "all.zip")):
                osv_missing = True
                break
                
        from datetime import datetime, timedelta
        
        # 1. NVD feeds update check
        nvd_needs_update = nvd_feeds_need_update(self.args.feed_dir, start_year=start_year)
        if no_update:
            logger.info("ℹ️ NVD feeds auto-update disabled. Skipping check.")
        elif self.args.update_feeds or nvd_needs_update:
            explicit_workers = any(arg.startswith("--max-workers") for arg in sys.argv)
            download_workers = self.args.max_workers if explicit_workers else 1
            logger.info(f"📥 Checking for NVD feed updates (workers={download_workers})...")
            nvd_count = download_all_nvd_feeds(
                feed_dir=self.args.feed_dir,
                start_year=start_year,
                force_update=self.args.force_update,
                max_workers=download_workers
            )
            if nvd_count > 0:
                logger.info(f"✅ Successfully updated {nvd_count} NVD feed files.")
        else:
            logger.info("ℹ️ Local NVD feeds are fresh (less than 24h old). Skipping download.")

        # 2. OSV feeds update check
        osv_needs_update = osv_missing
        if not osv_needs_update:
            for eco in ["PyPI", "npm", "Go", "Maven"]:
                all_zip = os.path.join(osv_dir, eco, "all.zip")
                if os.path.exists(all_zip):
                    file_modified_time = datetime.fromtimestamp(os.path.getmtime(all_zip))
                    if (datetime.now() - file_modified_time) >= timedelta(hours=24):
                        osv_needs_update = True
                        break
        
        if no_update:
            logger.info("ℹ️ OSV feeds auto-update disabled. Skipping check.")
        elif self.args.update_feeds or osv_needs_update:
            explicit_workers = any(arg.startswith("--max-workers") for arg in sys.argv)
            download_workers = self.args.max_workers if explicit_workers else 1
            logger.info(f"📥 Checking for OSV feed updates (workers={download_workers})...")
            osv_count = download_all_osv_ecosystems(
                feed_dir=osv_dir,
                force_update=self.args.force_update,
                max_workers=download_workers
            )
            if osv_count > 0:
                logger.info(f"✅ Successfully updated {osv_count} OSV feed files.")
        else:
            logger.info("ℹ️ Local OSV feeds are fresh (less than 24h old). Skipping download.")

        # 3. RetireJS DB update check
        retire_db_path = get_retire_db_path()
        retire_needs_update = not retire_db_path.exists()
        if not retire_needs_update and retire_db_path.exists():
            file_modified_time = datetime.fromtimestamp(retire_db_path.stat().st_mtime)
            if (datetime.now() - file_modified_time) >= timedelta(hours=24):
                retire_needs_update = True

        if no_update:
            logger.info("ℹ️ RetireJS database auto-update disabled. Skipping check.")
        elif self.args.update_feeds or retire_needs_update:
            logger.info("📥 Checking for RetireJS database updates...")
            download_retire_db(force_update=self.args.force_update)
        else:
            logger.info("ℹ️ Local RetireJS database is fresh (less than 24h old). Skipping download.")

        feed_manager = LocalFeedManager(feed_dir=self.args.feed_dir, osv_dir=osv_dir)
        feed_manager.load_feeds()
        
        if not feed_manager.loaded:
            logger.error("Failed to load NVD feeds.")
            return None
            
        return feed_manager

    def execute_scan(self, feed_manager: LocalFeedManager) -> list:
        """Executes the specific scan mode requested by the user and returns raw CVE findings."""
        if not any([self.args.scan_server, self.args.scan_dir, self.args.sbom, getattr(self.args, 'input_csv', None), self.args.products, self.args.cpes_file]):
            logger.info("Maintenance task completed. No scan mode specified.")
            return []
            
        all_cves = []
        
        if self.args.scan_server or self.args.scan_dir:
            scan_targets = self.args.scan_dir if self.args.scan_dir else ["/"]
            target = ", ".join(scan_targets) if self.args.scan_dir else "whole server (/)"
            logger.info(f"Scanning {target}...")
            
            packages_info = defaultdict(list)
            raw_sboms = {}
            
            exclude_list = self.args.exclude_dir if getattr(self.args, 'exclude_dir', None) else self.config.get("exclude_dirs", [])
            
            for base_dir in scan_targets:
                dir_packages, dir_sboms = collect_server_packages(
                    base_dir, 
                    parallelism=self.args.max_workers,
                    exclude_dirs=exclude_list,
                    native_only=getattr(self.args, 'native_only', False)
                )
                
                for k, v in dir_packages.items():
                    packages_info[k].extend(v)
                    
                for k, v in dir_sboms.items():
                    if k == 'directory':
                        safe_name = base_dir.replace('/', '_').strip('_') or 'root'
                        raw_sboms[f"directory_{safe_name}"] = v
                    else:
                        raw_sboms[k] = v

            # Pre-scan override: Map (normalized_name, path) to its correct running process version
            running_process_versions = {}
            for key, entries in list(packages_info.items()):
                for entry in entries:
                    if entry.get("type") == "running_process":
                        p_name = normalize_component_name(entry.get("name"))
                        p_path = normalize_path(entry.get("path"))
                        p_ver = entry.get("version")
                        if p_name and p_path and p_ver and not is_pseudo_version(p_ver):
                            running_process_versions[(p_name, p_path)] = p_ver

            # Update packages_info
            corrected_packages = defaultdict(list)
            for key, entries in list(packages_info.items()):
                for entry in entries:
                    p_name = normalize_component_name(entry.get("name"))
                    p_path = normalize_path(entry.get("path"))
                    p_ver = entry.get("version")
                    best_ver = running_process_versions.get((p_name, p_path))
                    if best_ver and is_pseudo_version(p_ver):
                        entry["version"] = best_ver
                        key = f"{entry.get('vendor', p_name)}:{entry.get('name')}:{best_ver}"
                    corrected_packages[key].append(entry)
            packages_info = corrected_packages

            # Update raw_sboms component versions
            for source_name, sbom_content in raw_sboms.items():
                for component in sbom_content.get("components", []):
                    c_name = normalize_component_name(component.get("name"))
                    c_path_val = None
                    for prop in component.get("properties", []):
                        if prop.get("name") in ["syft:location:0:path", "syft:location:path", "path"]:
                            c_path_val = prop.get("value")
                            break
                    if not c_path_val:
                        c_path_val = component.get("path")
                    best_ver = None
                    if c_path_val:
                        best_ver = running_process_versions.get((c_name, normalize_path(c_path_val)))
                    else:
                        for (name, path), ver in running_process_versions.items():
                            if name == c_name:
                                best_ver = ver
                                break
                    if best_ver and is_pseudo_version(component.get("version")):
                        component["version"] = best_ver

            self.packages_info = packages_info
            store_server_inventory(
                packages_info,
                self.args.server_inventory or self.config.get("inventory_file")
            )

            # 1. Process local NVD lookup for each SBOM individually (for JAR detection tracking)
            processed_sboms = 0
            for source_name, sbom_content in raw_sboms.items():
                has_jars = False
                for component in sbom_content.get("components", []):
                    c_name = component.get("name", "").lower()
                    if c_name.endswith((".jar", ".war", ".ear", ".aar", ".whl", ".zip", ".tar.gz", ".tgz")) or "java" in component.get("type", "").lower():
                        has_jars = True
                        break
                
                if has_jars:
                    sbom_filename = f"{source_name}_inventory_sbom.json"
                    sbom_path = os.path.join(self.output_dir, sbom_filename)
                    try:
                        with open(sbom_path, "w", encoding="utf-8") as f:
                            json.dump(sbom_content, f, indent=2)
                        logger.info(f"💾 JAR(s) detected in '{source_name}'. SBOM saved to {sbom_path}")
                        
                        # Process this SBOM for vulnerabilities
                        temp_args = type('Args', (object,), vars(self.args))() # Clone args
                        temp_args.sbom = sbom_path
                        workers = self.args.max_workers if self.args.fast else 1
                        findings = process_sbom_vulnerabilities_parallel(temp_args, feed_manager, max_workers=workers)
                        all_cves.extend(findings)
                        processed_sboms += 1
                    except Exception as e:
                        logger.error(f"Failed to process SBOM for {source_name}: {e}")

            # 2. Run supplemental system scans
            logger.info("Running supplemental scans for system-wide vulnerabilities...")
            # Do not skip native NVD scan to ensure core apps (nginx, mysql, redis, etc.) get scanned
            skip_nvd = False
            supplemental_cves = scan_server_vulnerabilities(
                packages_info, 
                feed_manager, 
                severity=self.args.severity, 
                base_dir=scan_targets,
                skip_nvd=skip_nvd,
                exclude_dirs=exclude_list,
                native_only=getattr(self.args, 'native_only', False)
            )
            all_cves.extend(supplemental_cves)
        
        elif self.args.sbom:
            logger.info(f"Processing SBOM: {self.args.sbom}")
            workers = self.args.max_workers if self.args.fast else 1
            all_cves = process_sbom_vulnerabilities_parallel(self.args, feed_manager, max_workers=workers)
            # Parse licenses from SBOM for compliance check
            try:
                with open(self.args.sbom, "r", encoding="utf-8") as f:
                    sbom_content = json.load(f)
                from vuln_checker.server_scanner import _process_syft_components
                packages_info = defaultdict(list)
                _process_syft_components(packages_info, sbom_content, label="sbom_scan")
                self.packages_info = packages_info
            except Exception as e:
                logger.debug(f"Could not extract licenses from SBOM: {e}")
        
        elif getattr(self.args, 'input_csv', None):
            logger.info(f"Processing CSV: {self.args.input_csv}")
            all_cves = process_csv_vulnerabilities(self.args, feed_manager)
        
        elif self.args.products:
            logger.info("Processing products...")
            all_cves = process_products_vulnerabilities(self.args, feed_manager)
        
        elif self.args.cpes_file:
            logger.info(f"Processing CPEs file: {self.args.cpes_file}")
            all_cves = process_cpes_file_vulnerabilities(self.args, feed_manager)
            
        return all_cves

    def enrich_and_filter(self, all_cves: list) -> list:
        """Applies VEX filtering, extracts standardized layout, deduplicates, and adds baseline/delta/remediation info."""
        if getattr(self.args, "vex_file", None):
            logger.info(f"Applying VEX filtering from {self.args.vex_file}")
            all_cves = apply_vex(all_cves, self.args.vex_file)

        # Perform network exposure mapping if fast_agent is enabled
        if getattr(self.args, 'fast_agent', False):
            listening_services = get_listening_ports()
            if listening_services:
                logger.info(f"⚡ Fast Agent active: mapping vulnerability findings against {len(listening_services)} open listening services...")
                logged_matches = set()
                for vuln in all_cves:
                    comp = str(vuln.get("component_name") or vuln.get("product") or "").lower()
                    path = str(vuln.get("path") or "").lower()
                    for service in listening_services:
                        svc_name = str(service.get("service") or "").lower()
                        port = service.get("port")
                        # Perform substring mapping on component name OR binary path
                        if svc_name and (svc_name in comp or comp in svc_name or svc_name in path):
                            vuln["exposed_port"] = port
                            vuln["exposed_service"] = service.get("service")
                            match_key = (comp, svc_name, port)
                            if match_key not in logged_matches:
                                logged_matches.add(match_key)
                                logger.info(f"   ⚠️ Vulnerable component '{comp}' matches running service '{svc_name}' listening on port {port}!")

        # Standardize format
        processed_data = [_extract_cve_data(item) for item in all_cves]
        
        # Deduplicate findings
        orig_len = len(processed_data)
        processed_data = deduplicate_findings(processed_data)
        dedup_count = orig_len - len(processed_data)
        if dedup_count > 0:
            logger.info(f"✨ Removed {dedup_count} duplicate vulnerability findings.")
        
        # Add remediation information
        if getattr(self.args, "no_remediation", False):
            logger.info("⏩ Skipping online registry lookups for remediation version upgrades.")
        else:
            processed_data = add_remediation_info(processed_data, max_workers=self.args.max_workers)
        
        # Compute delta if baseline provided
        if getattr(self.args, "baseline", None):
            logger.info(f"Computing Delta against baseline {self.args.baseline}")
            processed_data = compute_delta(processed_data, self.args.baseline)
            
        if not processed_data:
            logger.warning("⚠️ No CVEs found (or all filtered out).")
            return []
            
        return processed_data

    def execute_license_audit(self) -> list:
        """Audits licenses of all collected packages against allowed/denied policies."""
        violations = []
        if not self.packages_info:
            logger.info("ℹ️ No packages collected for license compliance auditing.")
            return violations
            
        policy = self.config.get("license_policy", {})
        policy_enabled = getattr(self.args, "license_audit", False) or policy.get("enabled", False)
        if not policy_enabled:
            return violations
            
        # Ensure policy is enabled in the config dict for compliance checks
        policy["enabled"] = True
        logger.info("⚖️ Running license compliance audit...")
        
        # 1. Collect packages that have 'unknown' licenses for online lookup
        entries_to_resolve = []
        for key, entries in self.packages_info.items():
            for entry in entries:
                lic = entry.get("license", "unknown")
                if not lic or lic.lower() == "unknown":
                    t = str(entry.get("type", "")).lower()
                    if "os_package" not in t:
                        entries_to_resolve.append(entry)
                        
        if entries_to_resolve:
            # Query online registries in parallel (capped at 10 workers)
            logger.info(f"🌐 Querying online registries to resolve unknown licenses for {len(entries_to_resolve)} packages...")
            from concurrent.futures import ThreadPoolExecutor
            from vuln_checker.utils import fetch_online_package_license
            
            import threading
            resolved_cache = {}
            cache_lock = threading.Lock()
            
            def resolve_entry(entry):
                name = entry.get("name", "")
                vendor = entry.get("vendor", "")
                version = entry.get("version", "")
                type_str = entry.get("type", "")
                cache_key = (name, vendor, version)
                
                with cache_lock:
                    if cache_key in resolved_cache:
                        if resolved_cache[cache_key] != "unknown":
                            entry["license"] = resolved_cache[cache_key]
                        return
                        
                try:
                    online_license = fetch_online_package_license(
                        name, vendor, version, type_str, entry.get("purl", "")
                    )
                    with cache_lock:
                        resolved_cache[cache_key] = online_license
                    if online_license and online_license.lower() != "unknown":
                        entry["license"] = online_license
                except Exception:
                    pass
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                list(executor.map(resolve_entry, entries_to_resolve))
        
        from vuln_checker.utils import check_license_compliance
        for key, entries in list(self.packages_info.items()):
            for entry in entries:
                license_str = entry.get("license", "unknown")
                status = check_license_compliance(license_str, self.config)
                entry["license_status"] = status
                if status == "VIOLATED":
                    violations.append({
                        "name": entry.get("name"),
                        "version": entry.get("version"),
                        "license": license_str,
                        "type": entry.get("type"),
                        "path": entry.get("path") or entry.get("name")
                    })
                    
        violation_count = len(violations)
        if violation_count > 0:
            logger.warning(f"❌ Found {violation_count} license compliance violations!")
            for v in violations:
                logger.warning(f"   - Package '{v['name']}' ({v['version']}) uses denied license: {v['license']}")
        else:
            logger.info("✅ License compliance audit passed. No violations detected.")
            
        return violations

    def generate_reports(self, processed_data: list, start_time: float) -> int:
        """Generates all requested report formats and prints severity breakdown summary."""
        requested_formats = self.args.format.split(",")
        
        for fmt in requested_formats:
            fmt = fmt.strip().lower()
            target_file = self.args.output
            if not target_file or len(requested_formats) > 1:
                defaults = {
                    "html": "cve_report.html",
                    "excel": "cve_report.xlsx",
                    "csv": "cve_report.csv",
                    "json": "cve_report.json"
                }
                filename = defaults.get(fmt, f"cve_report.{fmt}")
                target_file = os.path.join(self.output_dir, filename)
            elif not os.path.dirname(target_file):
                target_file = os.path.join(self.output_dir, target_file)
            
            has_baseline = bool(getattr(self.args, "baseline", None))
            logger.info(f"Generating {fmt} report at {target_file}...")
            if fmt == "html":
                generate_html_report(processed_data, target_file, has_baseline=has_baseline)
            elif fmt == "excel":
                output_results_excel(
                    processed_data, 
                    target_file, 
                    has_baseline=has_baseline, 
                    packages_info=getattr(self, 'packages_info', None), 
                    config=self.config
                )
            else:
                if self.args.sbom or (self.args.scan_server or self.args.scan_dir):
                    output_results_sbom_enhanced(processed_data, fmt, target_file, has_baseline=has_baseline)
                else:
                    output_results(processed_data, fmt, target_file, has_baseline=has_baseline)
        
        duration = time.time() - start_time
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = duration % 60
        
        if hours > 0:
            time_str = f"{hours}h {minutes}m {seconds:.2f}s"
        elif minutes > 0:
            time_str = f"{minutes}m {seconds:.2f}s"
        else:
            time_str = f"{seconds:.2f}s"
            
        logger.info(f"✅ Scan completed successfully in {time_str}.")
        
        # Calculate severity breakdown
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        unique_cve_ids = set()
        for item in processed_data:
            cve_id = item.get("id")
            if cve_id not in unique_cve_ids:
                unique_cve_ids.add(cve_id)
                sev = item.get("severity", "UNKNOWN").upper()
                if sev in severity_counts:
                    severity_counts[sev] += 1
                else:
                    severity_counts["UNKNOWN"] += 1
        
        summary_str = f"📊 Summary: Found {len(unique_cve_ids)} unique vulnerabilities."
        sev_parts = [f"{k}: {v}" for k, v in severity_counts.items() if v > 0]
        if sev_parts:
            summary_str += " Breakdown: " + ", ".join(sev_parts)
            
        logger.info(summary_str)
        
        # Flush any remaining CPE cache items to disk
        try:
            from vuln_checker.cve_cache import GLOBAL_CACHE
            GLOBAL_CACHE.save_cache()
        except Exception:
            pass
            
        return 0
