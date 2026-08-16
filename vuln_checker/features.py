import json
import logging
import subprocess
import os
import concurrent.futures
from vuln_checker.utils import safe_parse_version

logger = logging.getLogger(__name__)

def apply_vex(cves, vex_file_path):
    """
    Filter out vulnerabilities that are marked as 'not_affected' in the VEX document.
    """
    if not os.path.exists(vex_file_path):
        logger.error(f"VEX file not found at: {vex_file_path}")
        return cves
    
    try:
        with open(vex_file_path, "r", encoding="utf-8") as f:
            vex_data = json.load(f)
            
        not_affected_pairs = set() # Set of (cve_id, component_name)
        not_affected_cves = set() # Global CVE exclusion if component isn't strictly defined
        
        # Determine format
        if "vulnerabilities" in vex_data:
            # Maybe CycloneDX VEX format
            for vuln in vex_data["vulnerabilities"]:
                cve_id = vuln.get("id")
                analysis = vuln.get("analysis", {})
                state = analysis.get("state", "").lower()
                if state in ("not_affected", "false_positive"):
                    if "affects" in vuln and vuln["affects"]:
                        for affect in vuln["affects"]:
                            comp_ref = affect.get("ref", "")
                            # Try to extract a useful component name from purl or ref
                            comp_name = comp_ref.split("/")[-1].split("@")[0].split("?")[-1]
                            not_affected_pairs.add((cve_id, comp_name))
                    else:
                        not_affected_cves.add(cve_id)
        
        # Simple array format fallback
        elif isinstance(vex_data, list):
            for item in vex_data:
                state = item.get("state", item.get("status", "")).lower()
                cve_id = item.get("cve", item.get("id", ""))
                comp = item.get("component")
                if state in ("not_affected", "false_positive") and cve_id:
                    if comp:
                        not_affected_pairs.add((cve_id, comp))
                    else:
                        not_affected_cves.add(cve_id)
                        
        filtered_cves = []
        for cve_item in cves:
            cve_obj = cve_item.get("cve", cve_item)
            cve_id = cve_obj.get("id", "")
            comp_name = cve_item.get("component_name", "")
            
            if cve_id in not_affected_cves:
                logger.debug(f"VEX: Excluding {cve_id} completely.")
                continue
            
            # Substring match for component name just in case
            excluded = False
            for na_cve, na_comp in not_affected_pairs:
                if na_cve == cve_id and (na_comp in comp_name or comp_name in na_comp):
                    logger.debug(f"VEX: Excluding {cve_id} for component {comp_name}.")
                    excluded = True
                    break
                    
            if not excluded:
                filtered_cves.append(cve_item)
                
        return filtered_cves
    except Exception as e:
        logger.error(f"Error parsing VEX file: {e}")
        return cves

def compute_delta(current_cves, baseline_file_path):
    """
    Compare current findings against a baseline JSON report.
    Adds a 'delta_status' field ('New', 'Lingering', 'Resolved')
    """
    if not os.path.exists(baseline_file_path):
        logger.error(f"Baseline file not found at {baseline_file_path}")
        return current_cves
        
    try:
        with open(baseline_file_path, "r", encoding="utf-8") as f:
            baseline_data = json.load(f)
            
        def get_key(item):
            # Key by CVE ID + Component Name to track same vulnerability on same package
            cve_id = item.get("id", item.get("cve", {}).get("id", ""))
            comp_name = item.get("component_name", "")
            return f"{cve_id}_{comp_name}"
            
        baseline_keys = {get_key(item): item for item in baseline_data}
        current_keys = {get_key(item): item for item in current_cves}
        
        results = []
        
        # Check current against baseline
        for key, item in current_keys.items():
            if key in baseline_keys:
                item["delta_status"] = "Lingering"
            else:
                item["delta_status"] = "New"
            results.append(item)
            
        # Check for resolved
        for key, item in baseline_keys.items():
            if key not in current_keys:
                # Add it back but mark as resolved
                # the item might be in the simplified extraction format, ensure we handle properly
                item["delta_status"] = "Resolved"
                results.append(item)
                
        return results
    except Exception as e:
        logger.error(f"Error processing baseline Delta: {e}")
        return current_cves

def get_latest_version_cli(package_name, ecosystem):
    """Query package manager for the latest or available versions"""
    try:
        if ecosystem in ("npm", "node"):
            # npm view <pkg> version returns the latest version
            result = subprocess.run(["npm", "view", package_name, "version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                # Take only the first line in case of npm notices
                return result.stdout.strip().split("\n")[0].strip()
        elif ecosystem in ("pypi", "python"):
            # pip index versions is available in some pip versions
            result = subprocess.run(["pip", "index", "versions", package_name], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                result = subprocess.run(["pip3", "index", "versions", package_name], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "Available versions:" in line:
                        versions_str = line.split(":", 1)[1]
                        versions = [v.strip() for v in versions_str.split(",")]
                        # Filter out pre-releases/unstable versions
                        stable_versions = [
                            v for v in versions 
                            if not any(x in v.lower() for x in ["a", "b", "rc", "dev", "post", "pre"])
                        ]
                        if stable_versions:
                            return stable_versions[0]
                        elif versions:
                            return versions[0]
        elif ecosystem in ("deb", "apt", "ubuntu", "debian"):
            # apt-cache policy package
            result = subprocess.run(["apt-cache", "policy", package_name], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.strip().startswith("Candidate:"):
                        cand = line.split(":", 1)[1].strip()
                        if cand and cand != "(none)":
                            return cand
        elif ecosystem in ("rpm", "yum", "dnf", "rhel", "centos"):
            result = subprocess.run(["dnf", "info", package_name], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                result = subprocess.run(["yum", "info", package_name], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                version = ""
                release = ""
                for line in result.stdout.split("\n"):
                    if line.strip().startswith("Version"):
                        version = line.split(":", 1)[1].strip()
                    elif line.strip().startswith("Release"):
                        release = line.split(":", 1)[1].strip()
                if version:
                    return f"{version}-{release}" if release else version
    except Exception as e:
        logger.debug(f"Error querying {ecosystem} for {package_name}: {e}")
    return None

# Cache for version lookups to avoid redundant CLI calls
_VERSION_CACHE = {}

def add_remediation_info(cves, max_workers=5):
    """
    Enrich CVE results with an 'Upgrade To' field by querying local package managers.
    """
    logger.info("Looking up remediation versions using package managers...")
    
    def process_item(item):
        # Determine ecosystem from purl or other metadata
        purl = item.get("purl", "")
        ecosystem = item.get("ecosystem") # Might be set by OSV logic
        package_name = item.get("component_name", "")
        current_version = item.get("component_version", "")
        path = item.get("path", "")
        
        # 1. Extract from PURL
        if purl and purl.startswith("pkg:"):
            parts = purl.split("/") # e.g. pkg:npm/lodash@4.17.21
            if len(parts) > 1:
                eco_str = parts[0].replace("pkg:", "").lower()
                ecosystem = eco_str
                # Package name is usually the last part before @
                package_name = parts[-1].split("@")[0]
        
        # 2. Heuristics based on path
        if not ecosystem and path and path != "N/A":
            if "node_modules" in path: ecosystem = "npm"
            elif "site-packages" in path: ecosystem = "pypi"
            elif "/var/lib/dpkg" in path or "/usr/share/doc" in path: ecosystem = "deb"
            
        # 3. Handle vendor:product format from CPEs/Products input
        if ":" in package_name:
            # Often vendor:product. We usually want 'product' for the package manager.
            vendor_part, product_part = package_name.split(":", 1)
            package_name = product_part

        if package_name == "nextjs" and ecosystem == "npm":
            package_name = "next"

        # Force re-evaluation of upgrade_to for non-RetireJS findings to clear stale cached lookups
        tool = item.get("tool", "")
        original_upgrade = item.get("upgrade_to") or item.get("fix_version") or "N/A"
        if tool != "retire" and tool != "retirejs":
            item["upgrade_to"] = "N/A"

        if not item.get("upgrade_to") or item.get("upgrade_to") == "N/A":
            item["upgrade_to"] = "N/A"
        else:
            # If already has a value (e.g. from Retire.js), keep it and skip lookup
            return item
        
        # 4. If still no ecosystem, we can try to "guess" or try common ones
        pkg_type = item.get("pkg_type")
        if not ecosystem:
            is_generic = (purl and (purl.startswith("pkg:generic") or purl.startswith("pkg:golang")))
            from vuln_checker.feed_manager import get_suppression_rules
            rules = get_suppression_rules()
            standalone_apps = rules.get("standalone_apps", [])
            is_standalone = (package_name.lower() in standalone_apps)
            if pkg_type == "os_package" or is_generic or is_standalone:
                ecosystems_to_try = ["deb"]
            else:
                ecosystems_to_try = ["npm", "pypi", "deb"]
        else:
            ecosystems_to_try = [ecosystem]
        
        for eco in ecosystems_to_try:
            if not eco or not package_name:
                continue
                
            cache_key = (package_name, eco)
            if cache_key in _VERSION_CACHE:
                item["upgrade_to"] = _VERSION_CACHE[cache_key]
                if item["upgrade_to"] != "N/A":
                    break
                continue

            latest = get_latest_version_cli(package_name, eco)
            if latest:
                # Compare version to see if latest is indeed newer than current
                try:
                    curr_v = safe_parse_version(current_version)
                    late_v = safe_parse_version(latest)
                    if late_v > curr_v:
                        _VERSION_CACHE[cache_key] = latest
                        item["upgrade_to"] = latest
                        break
                except:
                    _VERSION_CACHE[cache_key] = latest
                    item["upgrade_to"] = latest
                    break
            else:
                _VERSION_CACHE[cache_key] = "N/A"
        
        # Fall back to original database fix_version if package manager didn't find anything better
        if item["upgrade_to"] == "N/A" and original_upgrade != "N/A":
            try:
                curr_v = safe_parse_version(current_version)
                orig_v = safe_parse_version(original_upgrade.replace(">", "").replace("=", "").strip())
                if orig_v > curr_v:
                    item["upgrade_to"] = original_upgrade
            except Exception:
                item["upgrade_to"] = original_upgrade
            
        return item

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Important: use list() to consume the iterator and wait for results
        results = list(executor.map(process_item, cves))
        
    # Consolidate upgrade versions to the maximum required safe version per component
    from collections import defaultdict
    from packaging.version import parse as parse_ver
    
    comp_upgrades = defaultdict(list)
    for item in results:
        comp_name = item.get("component_name")
        up_to = item.get("upgrade_to")
        if up_to and up_to != "N/A":
            clean_ver = up_to.replace(">", "").replace("=", "").strip()
            comp_upgrades[comp_name].append((clean_ver, up_to))
            
    best_upgrades = {}
    for comp, list_vers in comp_upgrades.items():
        highest_parsed = None
        highest_raw = None
        for clean_v, raw_v in list_vers:
            try:
                parsed = parse_ver(clean_v)
                if highest_parsed is None or parsed > highest_parsed:
                    highest_parsed = parsed
                    highest_raw = raw_v
            except Exception:
                if highest_raw is None:
                    highest_raw = raw_v
        if highest_raw:
            best_upgrades[comp] = highest_raw

    for item in results:
        comp_name = item.get("component_name")
        curr_ver = item.get("component_version")
        if comp_name in best_upgrades:
            best_up = best_upgrades[comp_name]
            if curr_ver and curr_ver != "N/A" and best_up and best_up != "N/A":
                try:
                    curr_v = safe_parse_version(curr_ver)
                    best_v = safe_parse_version(best_up.replace(">", "").replace("=", "").strip())
                    if best_v > curr_v:
                        item["upgrade_to"] = best_up
                    else:
                        item["upgrade_to"] = "N/A"
                except Exception:
                    item["upgrade_to"] = best_up
            else:
                item["upgrade_to"] = best_up
            
    return results

def normalize_component_name(name):
    import re
    name = str(name or "").lower().strip()
    if ":" in name:
        name = name.split(":")[-1]
    if name.startswith("github.com/"):
        parts = name.split("/")
        if len(parts) >= 3:
            last_part = parts[-1]
            if re.match(r'^v\d+$', last_part) and len(parts) >= 4:
                return parts[-2]
            return last_part
    return name

def is_pseudo_version(version_str):
    import re
    v = str(version_str or "").lower().strip()
    if not v or v == "unknown" or v == "n/a":
        return True
    if re.search(r'v?\d+\.\d+\.\d+-\d{8}', v):
        return True
    if v.startswith("v0.0.0") or v.startswith("0.0.0"):
        return True
    return False

def deduplicate_findings(findings):
    """
    Deduplicate findings across different feeds (e.g. NVD and OSV/GHSA) for the same component 
    and version. Uses a graph-based clustering (Union-Find) on vulnerability IDs 
    and their aliases to detect duplicates, consolidates all unique paths, resolves 
    pseudo-versions using running process version detections, and filters out false positive 
    core app dependencies mapped onto other packages.
    """
    from collections import defaultdict
    from vuln_checker.utils import get_core_apps
    import re

    core_apps = get_core_apps()

    # Step 1: Pre-process findings to normalize component names and clean false positives
    cleaned_findings = []
    
    # Track the best known running process version for each component name and path
    running_process_versions = {}
    for item in findings:
        norm_name = normalize_component_name(item.get("component_name") or item.get("product") or "")
        path = str(item.get("path") or "").strip()
        tool = str(item.get("tool") or "").lower()
        version = str(item.get("component_version") or "").strip()
        
        # Keep track if this version is derived from a running process
        if "running_process" in tool or "running" in tool:
            if not is_pseudo_version(version):
                running_process_versions[(norm_name, path)] = version

    for item in findings:
        norm_name = normalize_component_name(item.get("component_name") or item.get("product") or "")
        path = str(item.get("path") or "").strip()
        
        # Resolve pseudo-versions to the actual running process version if available for the same path
        best_ver = running_process_versions.get((norm_name, path))
        if best_ver and is_pseudo_version(item.get("component_version")):
            item["component_version"] = best_ver
            if item.get("product"):
                item["product"] = f"{norm_name}:{best_ver}"
                
        # Apply name normalization to the item
        item["component_name"] = norm_name
        cleaned_findings.append(item)

    # 2. Group findings by component name and version
    groups = defaultdict(list)
    for item in cleaned_findings:
        comp_name = str(item.get("component_name") or "").strip().lower()
        comp_version = str(item.get("component_version") or "").strip().lower()
        groups[(comp_name, comp_version)].append(item)

    deduplicated = []

    # 3. Process each component group independently
    for key, group_items in groups.items():
        n = len(group_items)
        if n == 0:
            continue
        
        # Initialize Union-Find structure for clustering within this component group
        parent = list(range(n))
        
        def find(i):
            if parent[i] == i:
                return i
            parent[i] = find(parent[i])
            return parent[i]
            
        def union(i, j):
            root_i = find(i)
            root_j = find(j)
            if root_i != root_j:
                parent[root_i] = root_j

        # Build set of all identifiers (primary ID + aliases) for each finding
        id_sets = []
        for item in group_items:
            ids = {str(item.get("id") or "").strip().upper()}
            for a in item.get("aliases", []) or []:
                if a:
                    ids.add(str(a).strip().upper())
            id_sets.append(ids)

        # Union findings that share any vulnerability identifier
        for i in range(n):
            for j in range(i + 1, n):
                if id_sets[i] & id_sets[j]:
                    union(i, j)

        # Group findings into their respective connected clusters
        clusters = defaultdict(list)
        for i in range(n):
            root = find(i)
            clusters[root].append(group_items[i])

        # Merge findings in each cluster
        for cluster in clusters.values():
            if len(cluster) == 1:
                # Consolidate path for single item cluster to normalize it
                merged_item = dict(cluster[0])
                p = str(merged_item.get("path") or "").strip()
                if p:
                    p_list = []
                    for sub_p in p.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
                        sub_p = sub_p.strip()
                        if sub_p and sub_p not in p_list:
                            p_list.append(sub_p)
                    merged_item["path"] = "\n".join(p_list)
                else:
                    merged_item["path"] = "N/A"
                deduplicated.append(merged_item)
                continue

            # Determine the best primary ID (globally recognized standard CVE IDs are preferred)
            all_candidate_ids = []
            for item in cluster:
                all_candidate_ids.append(str(item.get("id") or "").strip())
                for a in item.get("aliases", []) or []:
                    if a:
                        all_candidate_ids.append(str(a).strip())
            
            cve_ids = [cid for cid in all_candidate_ids if cid.upper().startswith("CVE-")]
            if cve_ids:
                primary_id = min(cve_ids) # Consistent selection
            else:
                non_empty = [cid for cid in all_candidate_ids if cid and cid.upper() != "N/A"]
                primary_id = non_empty[0] if non_empty else cluster[0].get("id")

            # Initialize merged finding using the primary record structure
            merged_item = dict(cluster[0])
            merged_item["id"] = primary_id
            
            # Select canonical URL based on primary ID
            if primary_id.upper().startswith("CVE-"):
                merged_item["url"] = f"https://nvd.nist.gov/vuln/detail/{primary_id}"
            elif primary_id.upper().startswith("GHSA-"):
                merged_item["url"] = f"https://github.com/advisories/{primary_id}"

            # Consolidate and sort all associated aliases across all cluster items
            merged_aliases = set()
            for item in cluster:
                merged_aliases.add(str(item.get("id") or "").strip())
                for a in item.get("aliases", []) or []:
                    if a:
                        merged_aliases.add(str(a).strip())
            merged_aliases.discard(primary_id)
            merged_item["aliases"] = sorted(list(merged_aliases))

            # Merge all other attributes from secondary findings, preferring richer data
            for item in cluster[1:]:
                fields_to_prioritize = [
                    "severity", "cvssScore", "upgrade_to", "delta_status", 
                    "published", "description", "feed_file", "cpe_used", 
                    "cpe_source", "purl", "lastModified", "tool"
                ]
                for field in fields_to_prioritize:
                    existing_val = merged_item.get(field)
                    new_val = item.get(field)
                    
                    if (existing_val is None or str(existing_val).upper() in ("", "N/A", "UNKNOWN")) and \
                       (new_val is not None and str(new_val).upper() not in ("", "N/A", "UNKNOWN")):
                        merged_item[field] = new_val
                    elif field == "description" and isinstance(existing_val, str) and isinstance(new_val, str):
                        if len(new_val) > len(existing_val):
                            merged_item[field] = new_val
                    elif field == "severity" and existing_val and new_val:
                        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0, "N/A": 0}
                        r_exist = sev_rank.get(str(existing_val).upper(), 0)
                        r_new = sev_rank.get(str(new_val).upper(), 0)
                        if r_new > r_exist:
                            merged_item[field] = new_val
                    elif field == "cvssScore" and existing_val is not None and new_val is not None:
                        try:
                            v_exist = float(existing_val)
                        except ValueError:
                            v_exist = 0.0
                        try:
                            v_new = float(new_val)
                        except ValueError:
                            v_new = 0.0
                        if v_new > v_exist:
                            merged_item[field] = str(new_val)

            # Consolidate and deduplicate paths across all items in the cluster
            all_paths = []
            for item in cluster:
                p = str(item.get("path") or "").strip()
                if p:
                    for sub_p in p.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
                        sub_p = sub_p.strip()
                        if sub_p and sub_p not in all_paths:
                            all_paths.append(sub_p)
            merged_item["path"] = "\n".join(all_paths) if all_paths else "N/A"

            deduplicated.append(merged_item)

    return deduplicated
