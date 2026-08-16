"""Server Package Discovery & Scanning"""
import os
import subprocess
import logging
import json
import csv
import re
import shutil
import sys
import zipfile
from pathlib import Path
from collections import defaultdict
from typing import Optional, List, Dict, Any

from vuln_checker.utils import is_excluded_cpe, normalize_severity, get_core_apps, get_ui_signatures, get_vendor_aliases, get_listening_ports
from vuln_checker.cve_cache import fetch_cves_cached, fetch_cves_cached_with_enrichment
from vuln_checker.integrations import SyftIntegration, run_smart_scans

logger = logging.getLogger(__name__)

def get_dpkg_package_license(package_name: str) -> str:
    """Reads /usr/share/doc/<package_name>/copyright and attempts to identify the license."""
    copyright_path = f"/usr/share/doc/{package_name}/copyright"
    if not os.path.exists(copyright_path):
        return "unknown"
    try:
        # Read the first 10KB of the copyright file
        with open(copyright_path, "r", errors="ignore", encoding="utf-8") as f:
            content = f.read(10240)
        
        # Look for standard machine-readable license names
        license_match = re.search(r"^License:\s*([a-zA-Z0-9\.\-\+]+)", content, re.MULTILINE | re.IGNORECASE)
        if license_match:
            return license_match.group(1).strip()
            
        # Common text indicators
        desc_lower = content.lower()
        for lic in ["gpl-3", "gpl-2", "agpl", "lgpl-3", "lgpl-2.1", "apache-2.0", "apache 2", "mit", "bsd", "isc", "mpl", "artistic"]:
            if lic in desc_lower:
                if "apache" in lic: return "Apache-2.0"
                if "mit" in lic: return "MIT"
                if "gpl-3" in lic: return "GPL-3.0"
                if "gpl-2" in lic: return "GPL-2.0"
                if "agpl" in lic: return "AGPL-3.0"
                if "lgpl-3" in lic: return "LGPL-3.0"
                if "lgpl-2.1" in lic: return "LGPL-2.1"
                if "bsd" in lic: return "BSD"
                if "isc" in lic: return "ISC"
                if "mpl" in lic: return "MPL"
                return lic.upper()
    except Exception:
        pass
    return "unknown"


def _collect_dpkg(packages_info):
    """Collect packages from Debian/Ubuntu systems"""
    # quick check: only attempt on Linux-like systems
    if not os.path.exists('/etc/os-release'):
        return 0
    # ensure dpkg binary is available
    if shutil.which('dpkg') is None:
        logger.debug("dpkg binary not found in PATH")
        return 0
    added = 0
    try:
        result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True, timeout=30)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == 'ii':
                package_name = parts[1]
                # dpkg packages can have arch appended (e.g. libc6:amd64)
                pkg_base = package_name.split(':')[0]
                version = parts[2]
                vendor = pkg_base.split('-')[0]
                license_str = get_dpkg_package_license(pkg_base)
                packages_info[f"{vendor}:{pkg_base}:{version}"].append({
                    "name": pkg_base,
                    "version": version,
                    "vendor": vendor,
                    "type": "os_package",
                    "license": license_str
                })
                added += 1
        logger.info(f"✅ Collected {added} OS packages from dpkg")
    except FileNotFoundError:
        logger.debug("dpkg not found (not a Debian/Ubuntu system)")
    except Exception as e:
        logger.debug(f"Could not collect dpkg packages: {e}")
    return added


def _collect_rpm(packages_info):
    """Collect packages from RPM-based systems (RHEL, CentOS, Oracle Linux, Fedora)"""
    added = 0
    try:
        # only attempt if rpm exists
        if shutil.which('rpm') is None:
            logger.debug("rpm binary not found in PATH")
            return 0
        result = subprocess.run(['rpm', '-qa', '--queryformat', '%{NAME}===%{VERSION}-%{RELEASE}===%{LICENSE}\n'],
                                capture_output=True, text=True, timeout=30)
        for line in result.stdout.splitlines():
            line = line.strip()
            if '===' not in line:
                continue
            parts = line.split('===')
            if len(parts) >= 2:
                package_name = parts[0].strip()
                version = parts[1].strip()
                license_str = parts[2].strip() if len(parts) >= 3 else "unknown"
                vendor = package_name.split('-')[0]
                packages_info[f"{vendor}:{package_name}:{version}"].append({
                    "name": package_name,
                    "version": version,
                    "vendor": vendor,
                    "type": "os_package",
                    "license": license_str
                })
                added += 1
        logger.info(f"✅ Collected {added} OS packages from rpm")
    except Exception as e:
        logger.debug(f"Could not collect rpm packages: {e}")
    return added

def _parse_site_packages_dir(packages_info, s_dir):
    """Helper to parse python packages metadata from a site-packages/dist-packages directory."""
    added = 0
    try:
        for entry in os.listdir(s_dir):
            entry_path = os.path.join(s_dir, entry)
            if not os.path.isdir(entry_path):
                continue
            if entry.endswith(".dist-info") or entry.endswith(".egg-info"):
                name, version, license_str = None, None, "unknown"
                for meta_name in ["METADATA", "PKG-INFO"]:
                    meta_file = os.path.join(entry_path, meta_name)
                    if os.path.isfile(meta_file):
                        try:
                            with open(meta_file, 'r', encoding='utf-8', errors='ignore') as f:
                                for line in f:
                                    if line.startswith("Name:"):
                                        name = line.split(":", 1)[1].strip()
                                    elif line.startswith("Version:"):
                                        version = line.split(":", 1)[1].strip()
                                    elif line.startswith("License:"):
                                        license_str = line.split(":", 1)[1].strip()
                        except Exception:
                            pass
                    if name and version:
                        break
                        
                if not name or not version:
                    base = entry[:-10]
                    if "-" in base:
                        parts = base.split("-")
                        name = parts[0]
                        version = parts[1]
                        
                if name and version:
                    vendor = name.split('-')[0] or name
                    key = f"{vendor}:{name}:{version}"
                    if key not in packages_info:
                        packages_info[key].append({
                            "name": name,
                            "version": version,
                            "vendor": vendor,
                            "type": "python_package",
                            "path": entry_path,
                            "license": license_str
                        })
                        added += 1
    except Exception:
        pass
    return added

def _collect_pip_from_filesystem(packages_info, exclude_dirs=None):
    """Discover Python packages directly from standard site-packages and dist-packages
    directories on the filesystem when pip list is unavailable.
    """
    added = 0
    site_dirs = []
    
    # 1. Ask active Python interpreter where its site-packages/dist-packages are
    for py_bin in ["python3", "python"]:
        try:
            res = subprocess.run([py_bin, "-c", "import sys; print(sys.path)"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                import ast
                paths = ast.literal_eval(res.stdout.strip())
                for p in paths:
                    if p and os.path.isdir(p) and ("site-packages" in p or "dist-packages" in p):
                        site_dirs.append(p)
        except Exception:
            pass
            
    # 2. Add current running Python process paths
    for p in sys.path:
        if p and os.path.isdir(p) and ("site-packages" in p or "dist-packages" in p):
            site_dirs.append(p)
            
    # 3. Fallback to generic system paths using wildcards
    paths_to_check = [
        "/usr/lib/python*",
        "/usr/local/lib/python*",
        "/usr/lib64/python*",
        "/usr/local/lib64/python*",
        os.path.expanduser("~/.local/lib/python*")
    ]
    import glob
    for path_pattern in paths_to_check:
        try:
            for py_dir in glob.glob(path_pattern):
                for sub in ["site-packages", "dist-packages"]:
                    d = os.path.join(py_dir, sub)
                    if os.path.isdir(d):
                        site_dirs.append(d)
        except Exception:
            pass
            
    site_dirs = list(set(os.path.normpath(d) for d in site_dirs))
    
    exclude_set = set()
    if exclude_dirs:
        for d in exclude_dirs:
            exclude_set.add(os.path.normpath(os.path.abspath(d)))

    for s_dir in site_dirs:
        if any(s_dir == d or s_dir.startswith(d + os.sep) for d in exclude_set):
            continue
        added += _parse_site_packages_dir(packages_info, s_dir)
            
    return added

def _collect_pip(packages_info, base_dir="/", exclude_dirs=None):
    """Collect Python packages. 
    If base_dir is '/', uses pip list for system-wide packages.
    Otherwise, scans the directory for requirements.txt, pyproject.toml files, and embedded site-packages.
    """
    added = 0
    if base_dir == "/":
        try:
            try:
                result = subprocess.run([sys.executable, '-m', 'pip', 'list', '--format=json'], capture_output=True, text=True, timeout=30)
            except Exception:
                if shutil.which('pip') is None:
                    logger.debug("pip binary not found in PATH")
                    raise FileNotFoundError("pip not found")
                result = subprocess.run(['pip', 'list', '--format=json'], capture_output=True, text=True, timeout=30)
            
            pip_packages = json.loads(result.stdout or "[]")
            if not pip_packages:
                raise Exception("Empty packages list returned by pip")
                
            for pkg in pip_packages:
                name = pkg.get('name', '')
                version = pkg.get('version', '')
                vendor = name.split('-')[0] or name
                packages_info[f"{vendor}:{name}:{version}"].append({
                    "name": name,
                    "version": version,
                    "vendor": vendor,
                    "type": "python_package"
                })
                added += 1
            logger.info(f"✅ Collected {added} system Python packages")
        except Exception as e:
            logger.debug(f"pip list failed or not found ({e}). Trying direct filesystem site-packages fallback...")
            fallback_added = _collect_pip_from_filesystem(packages_info, exclude_dirs=exclude_dirs)
            if fallback_added > 0:
                logger.info(f"✅ Collected {fallback_added} Python packages directly from filesystem site-packages")
    else:
        # Scan directory for manifests and virtual environments
        try:
            p = Path(base_dir)
            if not p.exists(): return 0
            
            def is_excluded(path_str):
                if not exclude_dirs:
                    return False
                path_str = os.path.normpath(path_str)
                for d in exclude_dirs:
                    d_norm = os.path.normpath(d)
                    if path_str.startswith(d_norm):
                        return True
                return False

            req_files = []
            pyproj_files = []
            site_dirs = []
            
            # Pruned fast walk!
            for root, dirs, files in os.walk(base_dir):
                if exclude_dirs:
                    dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root, d))]
                
                # Check for virtual environment site-packages
                base_name = os.path.basename(root)
                if base_name in ["site-packages", "dist-packages"]:
                    site_dirs.append(root)
                    dirs[:] = []  # Don't recurse inside site-packages/dist-packages
                    continue
                
                for file in files:
                    if file == "requirements.txt":
                        req_files.append(os.path.join(root, file))
                    elif file == "pyproject.toml":
                        pyproj_files.append(os.path.join(root, file))

            # 1. Parse found site-packages directories (virtual environments)
            for s_dir in site_dirs:
                added += _parse_site_packages_dir(packages_info, s_dir)

            # 2. requirements.txt
            for req_file in req_files:
                try:
                    with open(req_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith('#'): continue
                            # Simple parser for name==version or name>=version
                            match = re.match(r'^([a-zA-Z0-9._-]+)([=<>@!]+)([a-zA-Z0-9._*-]+)', line)
                            if match:
                                name, _, version = match.groups()
                                vendor = name.split('-')[0] or name
                                packages_info[f"{vendor}:{name}:{version}"].append({
                                    "name": name,
                                    "version": version,
                                    "vendor": vendor,
                                    "type": "python_package",
                                    "path": str(req_file)
                                })
                                added += 1
                except Exception: continue

            # 2. pyproject.toml
            for pyproj in pyproj_files:
                try:
                    # Basic parsing without tomli dependency if possible, or try to import it
                    import tomli
                    with open(pyproj, 'rb') as f:
                        data = tomli.load(f)
                    # Try to find dependencies
                    project = data.get('project', {})
                    deps = project.get('dependencies', [])
                    # Also check optional-dependencies
                    for group in project.get('optional-dependencies', {}).values():
                        deps.extend(group)
                    
                    for dep in deps:
                        # Parse dependency string (e.g. "requests>=2.25.1")
                        match = re.match(r'^([a-zA-Z0-9._-]+)([=<>@! \t]*)([a-zA-Z0-9._*-]+)?', dep)
                        if match:
                            name, _, version = match.groups()
                            version = version or "0.0.0"
                            vendor = name.split('-')[0] or name
                            packages_info[f"{vendor}:{name}:{version}"].append({
                                "name": name.strip(),
                                "version": version.strip(),
                                "vendor": vendor,
                                "type": "python_package",
                                "path": str(pyproj)
                            })
                            added += 1
                except Exception: continue
                
            if added > 0:
                logger.info(f"✅ Collected {added} Python packages from manifests in {base_dir}")
        except Exception as e:
            logger.debug(f"Could not scan directory for Python manifests: {e}")
            
    return added

def _parse_npm_dependencies(packages_info, p_path):
    added = 0
    parent_dir = os.path.dirname(p_path)
    lock_path = os.path.join(parent_dir, "package-lock.json")
    
    parsed_packages = {} # Map name -> version
    
    # 1. Try package-lock.json first as it has exact resolved versions
    if os.path.isfile(lock_path):
        try:
            with open(lock_path, 'r', encoding='utf-8') as f:
                lock_data = json.load(f)
                
            # Lockfile v2/v3 format
            if "packages" in lock_data:
                packages = lock_data.get("packages", {})
                for pkg_path, pkg_info in packages.items():
                    if pkg_path.startswith("node_modules/") and pkg_info.get("version"):
                        pkg_name = pkg_path[len("node_modules/"):]
                        parsed_packages[pkg_name] = pkg_info["version"]
                        
            # Lockfile v1 format / fallback
            if not parsed_packages and "dependencies" in lock_data:
                def parse_v1_deps(deps_dict):
                    for name, info in deps_dict.items():
                        ver = info.get("version")
                        if name and ver:
                            parsed_packages[name] = ver
                            sub_deps = info.get("dependencies", {})
                            if sub_deps:
                                parse_v1_deps(sub_deps)
                parse_v1_deps(lock_data["dependencies"])
        except Exception as e:
            logger.debug(f"Failed to parse package-lock.json at {lock_path}: {e}")
            
    # 2. Fall back to package.json direct dependencies if lockfile yielded nothing
    if not parsed_packages:
        try:
            with open(p_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})
            
            all_deps = {}
            if isinstance(deps, dict):
                all_deps.update(deps)
            if isinstance(dev_deps, dict):
                all_deps.update(dev_deps)
                
            for name, ver_range in all_deps.items():
                if not isinstance(ver_range, str):
                    continue
                # Clean version range: e.g. "^1.2.3" -> "1.2.3", ">=4.0.0" -> "4.0.0"
                clean_ver = re.sub(r'^[~^>=<|\s]+', '', ver_range)
                # Split at space or logical OR
                clean_ver = clean_ver.split()[0].split('||')[0].strip()
                if clean_ver:
                    parsed_packages[name] = clean_ver
        except Exception as e:
            logger.debug(f"Failed to parse package.json dependencies at {p_path}: {e}")
            
    # 3. Populate packages_info
    for name, version in parsed_packages.items():
        name = name.strip()
        version = version.strip()
        if not name or not version:
            continue
            
        vendor = name
        product = name
        if name.startswith('@') and '/' in name:
            parts = name[1:].split('/', 1)
            vendor = parts[0]
            product = parts[1]
            
        packages_info[f"{vendor}:{product}:{version}"].append({
            "name": product,
            "version": version,
            "vendor": vendor,
            "type": "npm_package",
            "path": p_path
        })
        added += 1
        
    return added

def _collect_npm(packages_info, base_dir="/", exclude_dirs=None):
    """Collect Node.js packages by finding package.json files"""
    added = 0
    try:
        json_paths = []
        if os.name != 'nt' and shutil.which('find') is not None:
            # Optimize find to ignore common system dirs and custom excluded dirs
            cmd = ['find', base_dir]
            
            prunes = set()
            if base_dir == "/":
                prunes.update(['/proc', '/sys', '/dev', '/run', '/boot'])
            if exclude_dirs:
                for d in exclude_dirs:
                    prunes.add(d.rstrip("/\\"))
                    
            if prunes:
                for d in sorted(list(prunes)):
                    cmd += ['-path', d, '-prune', '-o']
                    
            cmd += ['-type', 'f', '-name', 'package.json', '-print']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            json_paths = [p for p in result.stdout.splitlines() if p]
        else:
            # Windows or missing find - fast walk with pruning
            p = Path(base_dir)
            if not p.exists():
                # On Windows, if base_dir is "/" it might not exist, 
                # we should try to resolve it or skip.
                return 0
            
            def is_excluded(path_str):
                if not exclude_dirs:
                    return False
                path_str = os.path.normpath(path_str)
                for d in exclude_dirs:
                    d_norm = os.path.normpath(d)
                    if path_str.startswith(d_norm):
                        return True
                return False

            try:
                for root, dirs, files in os.walk(base_dir):
                    if exclude_dirs:
                        dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root, d))]
                    
                    for file in files:
                        if file == "package.json":
                            json_paths.append(os.path.join(root, file))
            except Exception as e:
                logger.debug(f"Error searching for package.json in {base_dir}: {e}")

        for p_path in json_paths:
            try:
                with open(p_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                name = data.get('name')
                version = data.get('version')
                
                if name and version and isinstance(name, str) and isinstance(version, str):
                    name = name.strip()
                    version = version.strip()
                    
                    # Handle scoped packages (e.g., @babel/core)
                    vendor = name
                    product = name
                    if name.startswith('@') and '/' in name:
                        parts = name[1:].split('/', 1)
                        vendor = parts[0]
                        product = parts[1]
                    
                    packages_info[f"{vendor}:{product}:{version}"].append({
                        "name": product,
                        "version": version,
                        "vendor": vendor,
                        "type": "npm_package",
                        "path": p_path
                    })
                    added += 1
                
                # Natively extract all dependencies from lockfiles/package.json
                deps_added = _parse_npm_dependencies(packages_info, p_path)
                added += deps_added
            except Exception:
                continue
                
        if added > 0:
            logger.info(f"✅ Collected {added} Node.js packages from {base_dir}")
    except Exception as e:
        logger.debug(f"Could not collect npm packages: {e}")
    return added

def _collect_java(packages_info, base_dir="/opt", exclude_dirs=None):
    """Collect Java JAR packages from specified directory with enhanced metadata extraction"""
    added = 0
    
    def _extract_jar_packages(jar_path):
        import io
        found_packages = []
        
        def _parse_pom_properties(content):
            ven, nm, ver = None, None, None
            for line in content.splitlines():
                if '=' not in line: continue
                k, v = [x.strip() for x in line.split('=', 1)]
                if k == 'groupId': ven = v
                elif k == 'artifactId': nm = v
                elif k == 'version': ver = v
            return ven, nm, ver

        def _parse_manifest(content):
            nm, ver, ven = None, None, None
            raw_lines = content.splitlines()
            merged_lines = []
            for line in raw_lines:
                if line.startswith(' ') and merged_lines:
                    merged_lines[-1] += line[1:]
                else:
                    merged_lines.append(line)
                    
            for line in merged_lines:
                if ':' not in line: continue
                k, v = [x.strip() for x in line.split(':', 1)]
                k_low = k.lower()
                if k_low in ('implementation-title', 'bundle-name', 'specification-title') and not nm:
                    nm = v
                elif k_low in ('implementation-version', 'bundle-version', 'specification-version') and not ver:
                    ver = v
                elif k_low in ('implementation-vendor', 'implementation-vendor-id', 'bundle-vendor') and not ven:
                    ven = v
            return ven, nm, ver

        def _scan_zip_stream(zip_stream, virtual_path):
            try:
                with zipfile.ZipFile(zip_stream, 'r') as zf:
                    pom_files = [n for n in zf.namelist() if n.startswith("META-INF/maven/") and n.endswith("pom.properties")]
                    for pom_path in pom_files:
                        try:
                            with zf.open(pom_path) as pf:
                                content = pf.read().decode('utf-8', errors='ignore')
                                ven, nm, ver = _parse_pom_properties(content)
                                if nm and ver:
                                    found_packages.append({
                                        "vendor": ven,
                                        "name": nm,
                                        "version": ver,
                                        "path": f"{virtual_path}::{pom_path}"
                                    })
                        except:
                            pass
                            
                    if not pom_files:
                        manifest_path = next((n for n in zf.namelist() if n.lower() == "meta-inf/manifest.mf"), None)
                        if manifest_path:
                            try:
                                with zf.open(manifest_path) as mf:
                                    content = mf.read().decode('utf-8', errors='ignore')
                                    ven, nm, ver = _parse_manifest(content)
                                    if nm and ver:
                                        found_packages.append({
                                            "vendor": ven,
                                            "name": nm,
                                            "version": ver,
                                            "path": virtual_path
                                        })
                            except:
                                pass
                                
                    for name in zf.namelist():
                        if name.endswith((".jar", ".war")) and name.lower() != "meta-inf/manifest.mf":
                            try:
                                nested_data = zf.read(name)
                                _scan_zip_stream(io.BytesIO(nested_data), f"{virtual_path}::{name}")
                            except:
                                pass
            except:
                pass

        try:
            with open(jar_path, 'rb') as f:
                _scan_zip_stream(io.BytesIO(f.read()), jar_path)
        except Exception as e:
            logger.debug(f"Failed to open JAR file {jar_path}: {e}")
            
        return found_packages

    def _normalize_cpe_part(part):
        """Clean and normalize strings for NVD compatibility."""
        if not part: return ""
        # 1. Remove URLs and domain artifacts
        p = part.lower().strip()
        p = re.sub(r'https?://[^\s]+', '', p)
        p = p.replace('http://', '').replace('https://', '')
        p = p.split('/')[0] # Take first part of path if any remains
        
        # 2. Aggressive cleaning but PRESERVE dots for vendors like org.apache
        p = p.replace(',', '').replace('(', '').replace(')', '').replace('[', '').replace(']', '')
        p = p.replace(' ', '_').replace(':', '_')
        p = p.strip('_.')
        return p

    try:
        jar_paths = []
        # On Windows, 'find' is usually the string search tool, not the file finder.
        # So we force pathlib usage on Windows, or if find is missing.
        if os.name != 'nt' and shutil.which('find') is not None:
            # Optimize find to ignore custom excluded dirs
            cmd = ['find', base_dir]
            
            prunes = set()
            if exclude_dirs:
                for d in exclude_dirs:
                    prunes.add(d.rstrip("/\\"))
                    
            if prunes:
                for d in sorted(list(prunes)):
                    cmd += ['-path', d, '-prune', '-o']
                    
            # Match .jar, .war, and .zip files
            cmd += ['-type', 'f', '(', '-name', '*.jar', '-o', '-name', '*.war', '-o', '-name', '*.zip', ')', '-print']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            jar_paths = [p for p in result.stdout.splitlines() if p]
        else:
            p = Path(base_dir)
            if not p.exists(): return 0
            
            def is_excluded(path_str):
                if not exclude_dirs:
                    return False
                path_str = os.path.normpath(path_str)
                for d in exclude_dirs:
                    d_norm = os.path.normpath(d)
                    if path_str.startswith(d_norm):
                        return True
                return False

            try:
                for root, dirs, files in os.walk(base_dir):
                    if exclude_dirs:
                        dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root, d))]
                    
                    for file in files:
                        if file.endswith((".jar", ".war", ".zip")):
                            jar_paths.append(os.path.join(root, file))
            except Exception as e:
                logger.debug(f"Error walking directories for Java archive files in {base_dir}: {e}")

        for jar_file in jar_paths:
            basename = os.path.basename(jar_file)
            extracted = _extract_jar_packages(jar_file)
            
            if not extracted:
                m_name = None
                m_version = None
                regex = r'^(?P<name>.+?)-(?P<version>\d[A-Za-z0-9\.\-\+_]*?)\.(jar|war|zip)$'
                match = re.match(regex, basename)
                if match:
                    m_name = match.group('name')
                    m_version = match.group('version')
                else:
                    m_name = os.path.splitext(basename)[0]
                    m_version = 'unknown'
                extracted.append({
                    "vendor": None,
                    "name": m_name,
                    "version": m_version,
                    "path": jar_file
                })
                
            for pkg in extracted:
                m_vendor = pkg.get("vendor")
                m_name = pkg.get("name")
                m_version = pkg.get("version")
                pkg_path = pkg.get("path")

                # Normalization and Cleaning
                if m_name and len(m_name.split()) > 5:
                    regex = r'^(?P<name>.+?)-(?P<version>\d[A-Za-z0-9\.\-\+_]*?)\.(jar|war|zip)$'
                    match = re.match(regex, basename)
                    if match:
                        final_name = match.group('name')
                    else:
                        final_name = os.path.splitext(basename)[0]
                else:
                    final_name = m_name or os.path.splitext(basename)[0]
                
                final_name = final_name.lower()
                final_name = re.sub(r'^(apache|org\.|com\.)', '', final_name)
                final_name = re.sub(r'[\[\]\(\)\,\/]', '', final_name)
                final_name = final_name.replace(' ', '-')
                
                final_version = m_version or 'unknown'
                final_version = final_version.lower().strip()

                final_vendor = _normalize_cpe_part(m_vendor)
                if not final_vendor:
                    if 'spring-' in final_name or 'pivotal' in pkg_path: final_vendor = 'pivotal_software'
                    elif 'apache' in final_name or 'commons-' in final_name: final_vendor = 'apache'
                    elif 'jackson-' in final_name: final_vendor = 'fasterxml'
                    elif 'netty' in final_name: final_vendor = 'netty'
                    elif 'hibernate' in final_name: final_vendor = 'hibernate'
                    else:
                        guess = final_name.split('-')[0]
                        final_vendor = _normalize_cpe_part(guess)

                packages_info[f"{final_vendor}:{final_name}:{final_version}"].append({
                    "name": final_name,
                    "version": final_version,
                    "vendor": final_vendor,
                    "type": "java_package",
                    "path": pkg_path
                })
                added += 1
        logger.info(f"✅ Collected {added} Java packages from {base_dir}")
    except FileNotFoundError:
        logger.debug(f"find command not found or directory {base_dir} does not exist")
    except Exception as e:
        logger.debug(f"Could not collect Java packages: {e}")
    return added

def _collect_static_ui_libraries(packages_info, base_dir, scanned_paths, exclude_dirs=None):
    """Natively scan static files for frontend UI library signatures dynamically loaded from config with generic fallback detection."""
    scan_targets = base_dir if isinstance(base_dir, list) else [base_dir]
    
    # Load configuration dynamically
    ui_sig = get_ui_signatures()
    libs_config = dict(ui_sig.get("libraries", {}))
    default_excludes_list = ui_sig.get("default_excludes", [])
    default_excludes = set(default_excludes_list)

    # Dynamically extract all npm package names found in package.json/lockfiles
    discovered_npm_names = set()
    for key, entries in packages_info.items():
        for entry in entries:
            if entry.get("type") == "npm_package":
                name = entry.get("name")
                if name:
                    discovered_npm_names.add(name.lower().strip())

    for npm_name in discovered_npm_names:
        # Ignore noisy/generic names
        if npm_name in ["min", "js", "css", "index", "main", "app", "version", "license", "copyright"]:
            continue
        if npm_name not in libs_config:
            libs_config[npm_name] = {
                "filename_pattern": rf"{re.escape(npm_name)}(?:[-.]([0-9]+\.[0-9]+\.[0-9]+))?(?:\.min)?\.js",
                "content_pattern": rf"{re.escape(npm_name)}\s*v?(([0-9]+\.){{1,3}}[0-9]+)",
                "vendor": npm_name,
                "aliases": [npm_name]
            }

    # Pre-compile regex patterns dynamically
    ui_patterns = {}
    ui_vendors = {}
    for lib_name, cfg in libs_config.items():
        fn_pat = cfg.get("filename_pattern")
        cn_pat = cfg.get("content_pattern")
        ui_patterns[lib_name] = [
            re.compile(fn_pat, re.IGNORECASE) if fn_pat else None,
            re.compile(cn_pat, re.IGNORECASE) if cn_pat else None
        ]
        ui_vendors[lib_name] = cfg.get("vendor", lib_name)

    # Generic dynamic patterns (no config needed)
    generic_filename_pattern = re.compile(
        r"^([a-zA-Z0-9\-_]+?)[-.]v?(([0-9]+\.){1,3}[0-9]+)(?:\.min)?\.(?:js|css)$", 
        re.IGNORECASE
    )
    generic_content_pattern = re.compile(
        r"(?:\*!|\*|//)\s*([a-zA-Z0-9\-_ ]+?)\s*(?:v|version)?\s*(?:v)?(([0-9]+\.){1,3}[0-9]+)",
        re.IGNORECASE
    )

    def clean_library_name(name: str) -> str:
        n = name.lower().strip()
        if n.endswith(".js"):
            n = n[:-3]
        if n.endswith("js"):
            if len(n) > 2:
                n = n[:-2]
        n = re.sub(r"[^a-z0-9\-_]", "", n)
        return n

    exclude_set = set()
    if exclude_dirs:
        for d in exclude_dirs:
            exclude_set.add(os.path.normpath(os.path.abspath(d)))

    def is_excluded(path_str):
        abs_path = os.path.abspath(path_str)
        norm_path = os.path.normpath(abs_path)
        for d in exclude_set:
            if norm_path == d or norm_path.startswith(d + os.sep):
                return True
        parts = norm_path.split(os.sep)
        if any(p in default_excludes for p in parts):
            return True
        return False

    added = 0
    for target in scan_targets:
        if not os.path.exists(target):
            continue
        
        target_abs = os.path.abspath(target)
        if is_excluded(target_abs):
            continue

        logger.info(f"🔎 Natively scanning static files in {target} for UI library signatures...")
        
        # Try to use 'find' command for performance on Linux/macOS if available
        file_paths = []
        if os.name != 'nt' and shutil.which('find') is not None:
            cmd = ['find', target]
            prunes = set()
            if target == "/":
                prunes.update(['/proc', '/sys', '/dev', '/run', '/boot', '/var/lib/docker'])
            if exclude_dirs:
                for d in exclude_dirs:
                    prunes.add(d.rstrip("/\\"))
            
            if prunes:
                for p in sorted(list(prunes)):
                    cmd += ['-path', p, '-prune', '-o']
            
            cmd += ['-type', 'f', '(', '-name', '*.js', '-o', '-name', '*.html', '-o', '-name', '*.htm', '-o', '-name', '*.css', ')', '-print']
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
                file_paths = [p for p in result.stdout.splitlines() if p]
            except Exception as e:
                logger.debug(f"find failed: {e}")
                
        if not file_paths:
            # Fallback to os.walk
            try:
                for root, dirs, files in os.walk(target_abs):
                    # Prune in-place
                    pruned_dirs = []
                    for d in dirs:
                        dir_path = os.path.join(root, d)
                        if not is_excluded(dir_path):
                            pruned_dirs.append(d)
                    dirs[:] = pruned_dirs

                    for file in files:
                        if file.endswith(('.js', '.html', '.htm', '.css')):
                            file_paths.append(os.path.join(root, file))
            except Exception as e:
                logger.debug(f"Walk failed on {target_abs}: {e}")

        for file_path in file_paths:
            norm_file_path = os.path.normpath(os.path.abspath(file_path))
            lookup_path = norm_file_path.lower() if os.name == 'nt' else norm_file_path
            
            if lookup_path in scanned_paths:
                continue

            detected_lib = None
            detected_ver = None
            filename = os.path.basename(file_path)

            # 1. Try to match configured libraries first (for exact regex matches)
            for lib_name, regex_list in ui_patterns.items():
                if regex_list[0]:
                    version_match = regex_list[0].search(filename)
                    if version_match:
                        detected_lib = lib_name
                        detected_ver = version_match.group(1)
                        break

            # 2. Try generic filename regex if no exact library matched
            if not detected_lib:
                generic_fn_match = generic_filename_pattern.search(filename)
                if generic_fn_match:
                    raw_name = generic_fn_match.group(1)
                    cleaned_name = clean_library_name(raw_name)
                    if cleaned_name and cleaned_name not in ["min", "js", "css", "index", "main", "app"]:
                        detected_lib = cleaned_name
                        detected_ver = generic_fn_match.group(2)

            # 3. Check inner file contents
            detected_libs = []
            if detected_lib and detected_ver:
                detected_libs.append((detected_lib, detected_ver))
            else:
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        # Read first 100,000 characters to detect bundled libraries
                        content = f.read(100000)
                        
                        # 3a. Try exact configured content regexes
                        for lib_name, regex_list in ui_patterns.items():
                            if regex_list[1]:
                                version_match = regex_list[1].search(content)
                                if version_match:
                                    detected_libs.append((lib_name, version_match.group(1)))
                                    
                        # 3b. Try generic content banner regex
                        if not detected_libs:
                            for match in generic_content_pattern.finditer(content):
                                raw_name = match.group(1)
                                cleaned_name = clean_library_name(raw_name)
                                if cleaned_name and cleaned_name not in ["min", "js", "css", "index", "main", "app", "version", "license", "copyright"]:
                                    detected_libs.append((cleaned_name, match.group(2)))
                                    if len(detected_libs) >= 5:
                                        break
                except Exception:
                    pass

            for d_lib, d_ver in detected_libs:
                vendor = ui_vendors.get(d_lib, d_lib)
                key = f"{vendor}:{d_lib}:{d_ver}"
                
                # Check if we already registered this component for this file
                already_exists = False
                for existing in packages_info[key]:
                    if existing.get("path") == file_path:
                        already_exists = True
                        break
                
                if not already_exists:
                    packages_info[key].append({
                        "name": d_lib,
                        "version": d_ver,
                        "vendor": vendor,
                        "type": "npm_package", # Map as npm_package for OSV compatibility
                        "path": file_path
                    })
                    scanned_paths.add(lookup_path)
                    added += 1

def _collect_running_processes(packages_info):
    """Collect packages from running processes by inspecting /proc on Linux systems"""
    if os.name == 'nt' or not os.path.exists("/proc"):
        return 0
    
    added = 0
    seen_bins = set()
    
    dpkg_available = shutil.which('dpkg') is not None
    rpm_available = shutil.which('rpm') is not None
    
    # Get PIDs of listening services
    listening_pids = set()
    try:
        for svc in get_listening_ports():
            pid = svc.get("pid")
            if pid:
                listening_pids.add(int(pid))
    except Exception as e:
        logger.debug(f"Could not fetch listening ports: {e}")
        
    try:
        for pid_entry in os.listdir("/proc"):
            if not pid_entry.isdigit():
                continue
            exe_link = f"/proc/{pid_entry}/exe"
            try:
                if not os.path.exists(exe_link):
                    continue
                exe_path = os.readlink(exe_link)
                if not exe_path or exe_path in seen_bins:
                    continue
                
                product = os.path.basename(exe_path)
                if not product:
                    continue

                # Check if running from a bin folder or contains bin/
                is_bin = False
                parts = exe_path.split(os.sep)
                if any(p in ("bin", "sbin") for p in parts) or "bin" in exe_path:
                    is_bin = True
                    
                # Relax bin/sbin restriction for listening ports
                if not is_bin:
                    try:
                        if int(pid_entry) in listening_pids:
                            is_bin = True
                    except Exception:
                        pass
                        
                # Relax bin/sbin restriction for core apps
                if not is_bin:
                    core_apps = get_core_apps()
                    prod_lower = product.lower()
                    if prod_lower in core_apps or any(name in prod_lower for name in ["nginx", "loki", "prometheus", "redis"]):
                        is_bin = True
                        
                if not is_bin:
                    continue
                    
                seen_bins.add(exe_path)
                
                version = "unknown"
                vendor = product
                resolved = False
                
                # Try to resolve package using dpkg or rpm
                if dpkg_available:
                    try:
                        res = subprocess.run(['dpkg', '-S', exe_path], capture_output=True, text=True, timeout=5)
                        if res.returncode == 0 and res.stdout:
                            pkg_part = res.stdout.split(':')[0].strip()
                            pkg_name = pkg_part.split(',')[0].strip()
                            if pkg_name:
                                v_res = subprocess.run(['dpkg-query', '-W', '-f=${Version}', pkg_name], capture_output=True, text=True, timeout=5)
                                if v_res.returncode == 0 and v_res.stdout.strip():
                                    version = v_res.stdout.strip()
                                    vendor = pkg_name.split('-')[0] or pkg_name
                                    product = pkg_name
                                    resolved = True
                    except Exception:
                        pass
                        
                if not resolved and rpm_available:
                    try:
                        res = subprocess.run(['rpm', '-qf', '--queryformat', '%{NAME}===%{VERSION}-%{RELEASE}', exe_path], capture_output=True, text=True, timeout=5)
                        if res.returncode == 0 and '===' in res.stdout:
                            parts = res.stdout.strip().split('===')
                            pkg_name = parts[0].strip()
                            version = parts[1].strip()
                            vendor = pkg_name.split('-')[0] or pkg_name
                            product = pkg_name
                            resolved = True
                    except Exception:
                        pass
                
                # Fallback version detection
                if not resolved:
                    path_match = re.search(r'[-vV]([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-zA-Z0-9\-\.]*)', exe_path)
                    if path_match:
                        version = path_match.group(1)
                    else:
                        flags = ["--version", "-version", "-v", "-V", "version"]
                        prod_lower = product.lower()
                        if "nginx" in prod_lower:
                            flags = ["-v", "-V"] + flags
                        elif "redis" in prod_lower:
                            flags = ["-v", "--version"] + flags
                        elif "prometheus" in prod_lower:
                            flags = ["--version"] + flags
                        elif "loki" in prod_lower:
                            flags = ["-version", "--version"] + flags

                        for flag in flags:
                            try:
                                v_res = subprocess.run([exe_path, flag], capture_output=True, text=True, timeout=2)
                                output = (v_res.stdout or "") + (v_res.stderr or "")
                                if output.strip():
                                    ver_match = re.search(r'\b([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[a-zA-Z0-9\-\.]*))\b', output)
                                    if ver_match:
                                        version = ver_match.group(1)
                                        break
                            except Exception:
                                pass
                
                packages_info[f"{vendor}:{product}:{version}"].append({
                    "name": product,
                    "version": version,
                    "vendor": vendor,
                    "type": "running_process",
                    "path": exe_path
                })
                added += 1
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"Could not inspect running processes: {e}")
        
    if added > 0:
        logger.info(f"✅ Collected {added} packages from running processes")
    return added

def _collect_native_container_packages(packages_info, container_id):
    """Collect packages inside an active Docker container natively by executing queries within the container."""
    added = 0
    # 1. Collect dpkg/deb packages
    try:
        result = subprocess.run(
            ['docker', 'exec', container_id, 'dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\n'],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if not line: continue
                parts = line.split('\t')
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1]
                    arch = parts[2] if len(parts) > 2 else "all"
                    vendor = "debian"
                    packages_info[f"{vendor}:{name}:{version}"].append({
                        "name": name,
                        "version": version,
                        "vendor": vendor,
                        "arch": arch,
                        "type": "os_package",
                        "path": f"docker_container:{container_id[:12]}"
                    })
                    added += 1
    except Exception as e:
        logger.debug(f"Failed to query dpkg in container {container_id}: {e}")

    # 2. Collect rpm packages
    try:
        result = subprocess.run(
            ['docker', 'exec', container_id, 'rpm', '-qa', '--qf', '%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\n'],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if not line: continue
                parts = line.split('\t')
                if len(parts) >= 3:
                    name = parts[0]
                    version = parts[1]
                    arch = parts[2]
                    vendor = parts[3].lower().replace(' ', '_') if len(parts) > 3 and parts[3] else "centos"
                    if vendor == "(none)":
                        vendor = "centos"
                    packages_info[f"{vendor}:{name}:{version}"].append({
                        "name": name,
                        "version": version,
                        "vendor": vendor,
                        "arch": arch,
                        "type": "os_package",
                        "path": f"docker_container:{container_id[:12]}"
                    })
                    added += 1
    except Exception as e:
        logger.debug(f"Failed to query rpm in container {container_id}: {e}")

    # 3. Collect pip packages
    try:
        result = subprocess.run(
            ['docker', 'exec', container_id, 'pip', 'list', '--format=json'],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            try:
                pip_packages = json.loads(result.stdout or "[]")
                for pkg in pip_packages:
                    name = pkg.get('name', '')
                    version = pkg.get('version', '')
                    vendor = name.split('-')[0] or name
                    packages_info[f"{vendor}:{name}:{version}"].append({
                        "name": name,
                        "version": version,
                        "vendor": vendor,
                        "type": "python_package",
                        "path": f"docker_container:{container_id[:12]}"
                    })
                    added += 1
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"Failed to query pip in container {container_id}: {e}")

    if added > 0:
        logger.info(f"   🐳 Collected {added} native packages from container {container_id[:12]}")
    return added


def collect_server_packages(base_dir="/", parallelism=None, exclude_dirs=None, native_only=False):
    """Collect packages from server. 
    If base_dir is '/', collect system-wide packages and active Docker containers.
    If base_dir is a specific path, only scan that path for local packages.
    """
    packages_info = defaultdict(list)
    scanned_paths = set()
    raw_sboms = {} # Map source name to its raw SBOM data
    
    # 1. Active Docker Scan (Always high priority if available)
    if base_dir == "/":
        containers = SyftIntegration.get_active_containers()
        for container_id in containers:
            logger.info(f"🐳 Scanning active Docker container: {container_id}")
            if not native_only:
                syft_sbom = SyftIntegration.generate_sbom(f"docker:{container_id}", parallelism=parallelism)
                if syft_sbom:
                    raw_sboms[f"docker_container_{container_id[:12]}"] = syft_sbom
                    _process_syft_components(packages_info, syft_sbom, label=f"docker_container:{container_id}", scanned_paths=scanned_paths, base_dir=base_dir)
            else:
                _collect_native_container_packages(packages_info, container_id)

    # 2. Syft Directory Discovery (Primary discovery tool)
    if not native_only and SyftIntegration.is_tool_available("syft"):
        syft_sbom = SyftIntegration.generate_sbom(base_dir, parallelism=parallelism, exclude_dirs=exclude_dirs)
        if syft_sbom:
            raw_sboms["base_system" if base_dir == "/" else "directory"] = syft_sbom
            _process_syft_components(packages_info, syft_sbom, label="syft_discovery", scanned_paths=scanned_paths, base_dir=base_dir)

    # 3. Traditional System/Directory Scans (Fallback/Supplementary)
    if base_dir == "/":
        _collect_dpkg(packages_info)
        _collect_rpm(packages_info)
        _collect_pip(packages_info, base_dir="/", exclude_dirs=exclude_dirs)
        _collect_running_processes(packages_info)
    
    npm_dir = base_dir if base_dir != "/" else ("/" if os.name != 'nt' else "C:\\")
    java_dir = base_dir if base_dir != "/" else ("/" if os.name != 'nt' else "C:\\")
    python_dir = base_dir if base_dir != "/" else ("/" if os.name != 'nt' else "C:\\")

    _collect_npm_dedup(packages_info, npm_dir, scanned_paths, exclude_dirs=exclude_dirs)
    _collect_java_dedup(packages_info, java_dir, scanned_paths, exclude_dirs=exclude_dirs)
    _collect_pip_dedup(packages_info, python_dir, scanned_paths, exclude_dirs=exclude_dirs)

    # Always collect static UI libraries for a complete inventory in both standard and native modes
    _collect_static_ui_libraries(packages_info, base_dir, scanned_paths, exclude_dirs=exclude_dirs)

    return dict(packages_info), raw_sboms

def _process_syft_components(packages_info, syft_sbom, label="syft", scanned_paths=None, base_dir=None):
    """Internal helper to process Syft components into packages_info."""
    added = 0
    cli_versions = {} # Cache: norm_path -> detected_version
    for component in syft_sbom.get("components", []):
        name = component.get("name")
        if name in ("linux-kernel", "linux_kernel"):
            continue
        version = component.get("version")
        vendor = component.get("group") or name.split('-')[0]
        
        # Track where syft found it (if path is provided in metadata)
        properties = component.get("properties", [])
        path_keys = ["syft:package:filePath", "syft:location:0:path", "syft:metadata:virtualPath", "syft:metadata:path"]
        path = next((p.get("value") for p in properties if p.get("name") in path_keys), None)
        
        # If no path in properties, check locations
        if not path:
            locations = component.get("locations", [])
            if locations:
                path = locations[0].get("path")

        norm_path = None
        if path:
            # Fix for Windows: Syft often returns paths starting with \ even if they are relative to scan root
            cleaned_path = path

            # Resolve relative/virtual paths against base_dir if provided
            if base_dir and base_dir != "/":
                rel_path = cleaned_path.lstrip('/\\')
                full_path = os.path.join(base_dir, rel_path)
            else:
                full_path = cleaned_path

            # Normalize path for better deduplication
            norm_path = os.path.normpath(os.path.abspath(full_path))
            if scanned_paths is not None:
                scanned_paths.add(norm_path)
                if os.name == 'nt':
                    scanned_paths.add(norm_path.lower())

        if name and version:
            core_apps = get_core_apps()
            from vuln_checker.feed_manager import get_suppression_rules
            rules = get_suppression_rules()
            standalone_apps = rules.get("standalone_apps", ["prometheus", "nginx", "mysql", "apache", "redis"])

            # Extract license metadata from component
            license_list = []
            licenses_data = component.get("licenses", [])
            if isinstance(licenses_data, list):
                for lic_entry in licenses_data:
                    if isinstance(lic_entry, dict):
                        expression = lic_entry.get("expression")
                        if expression:
                            license_list.append(expression)
                        else:
                            lic_detail = lic_entry.get("license", {})
                            if isinstance(lic_detail, dict):
                                lic_name = lic_detail.get("id") or lic_detail.get("name")
                                if lic_name:
                                    license_list.append(lic_name)
            license_str = ", ".join(license_list) if license_list else "unknown"

            # 1. Determine if this component belongs to a standalone application binary path
            if path and norm_path:
                bin_name = os.path.basename(path).lower()
                is_standalone_candidate = (
                    bin_name in core_apps or 
                    bin_name in standalone_apps
                )
                if is_standalone_candidate and os.path.exists(norm_path) and not os.path.isdir(norm_path):
                    # Check/retrieve version via CLI
                    if norm_path in cli_versions:
                        bin_ver = cli_versions[norm_path]
                    else:
                        from vuln_checker.utils import get_binary_version_cli
                        bin_ver = get_binary_version_cli(norm_path)
                        cli_versions[norm_path] = bin_ver

                    if bin_ver:
                        # Add the standalone binary package at its correct CLI-detected version
                        vendor_name = vendor if vendor and vendor != "unknown" else bin_name

                        standalone_key = f"{vendor_name}:{bin_name}:{bin_ver}"
                        if not any(e.get("path") == path and e.get("version") == bin_ver for e in packages_info[standalone_key]):
                            packages_info[standalone_key].append({
                                "name": bin_name,
                                "version": bin_ver,
                                "vendor": vendor_name,
                                "type": label,
                                "path": path,
                                "purl": f"pkg:generic/{bin_name}@{bin_ver}",
                                "license": license_str
                            })
                            added += 1

                        # Skip registering the internal compile-time dependencies or generic SBOM entry for this binary
                        continue

            # Fallback to standard component processing
            parent_binary = ""
            if path and ("/bin/" in path or "usr/local/bin" in path):
                bin_name = os.path.basename(path).lower()
                if bin_name in core_apps and bin_name not in standalone_apps and bin_name != name.lower():
                    parent_binary = bin_name
            
            display_name = f"{parent_binary} ({name})" if parent_binary and not name.lower().startswith(parent_binary) else name

            packages_info[f"{vendor}:{name}:{version}"].append({
                "name": display_name,
                "version": version,
                "vendor": vendor,
                "type": label,
                "path": path or name,
                "purl": component.get("purl") or "N/A",
                "license": license_str
            })
            added += 1
            
    if added > 0:
        logger.info(f"✅ Collected {added} components via {label}")

def _collect_npm_dedup(packages_info, base_dir, scanned_paths, exclude_dirs=None):
    temp_info = defaultdict(list)
    _collect_npm(temp_info, base_dir, exclude_dirs=exclude_dirs)
    added = 0
    for k, entries in temp_info.items():
        for e in entries:
            path = e.get("path")
            if path:
                norm_path = os.path.normpath(os.path.abspath(path))
                lookup_path = norm_path.lower() if os.name == 'nt' else norm_path
                if lookup_path not in scanned_paths:
                    packages_info[k].append(e)
                    scanned_paths.add(lookup_path)
                    added += 1
            else:
                packages_info[k].append(e)
                added += 1
    return added

def _collect_java_dedup(packages_info, base_dir, scanned_paths, exclude_dirs=None):
    temp_info = defaultdict(list)
    _collect_java(temp_info, base_dir, exclude_dirs=exclude_dirs)
    added = 0
    for k, entries in temp_info.items():
        for e in entries:
            path = e.get("path")
            if path:
                norm_path = os.path.normpath(os.path.abspath(path))
                lookup_path = norm_path.lower() if os.name == 'nt' else norm_path
                if lookup_path not in scanned_paths:
                    packages_info[k].append(e)
                    scanned_paths.add(lookup_path)
                    added += 1
            else:
                packages_info[k].append(e)
                added += 1
    return added

def _collect_pip_dedup(packages_info, base_dir, scanned_paths, exclude_dirs=None):
    temp_info = defaultdict(list)
    _collect_pip(temp_info, base_dir, exclude_dirs=exclude_dirs)
    added = 0
    for k, entries in temp_info.items():
        for e in entries:
            path = e.get("path")
            if path:
                norm_path = os.path.normpath(os.path.abspath(path))
                lookup_path = norm_path.lower() if os.name == 'nt' else norm_path
                if lookup_path not in scanned_paths:
                    packages_info[k].append(e)
                    scanned_paths.add(lookup_path)
                    added += 1
            else:
                packages_info[k].append(e)
                added += 1
    return added

def store_server_inventory(packages_info, output_file="server_inventory.csv"):
    rows = []
    for key, entries in packages_info.items():
        for e in entries:
            rows.append({
                "vendor": e.get("vendor", ""),
                "product": e.get("name", ""),
                "version": e.get("version", ""),
                "type": e.get("type", ""),
                "path": e.get("path", ""),
            })

    fieldnames = ["vendor", "product", "version", "type", "path"]
    try:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        logger.info(f"✅ Server inventory saved to {output_file}")
    except Exception as e:
        logger.error(f"❌ Failed to save inventory: {e}")

def _parse_key(key: str):
    parts = key.split(":")
    if len(parts) < 3:
        return None
    return parts[0], parts[1], parts[2]

def _build_cpe(vendor: str, product: str, version: str) -> str:
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _extract_cve_id_and_severity(vuln: dict):
    """Return (cve_id, severity) from a vuln dict in a best-effort way."""
    try:
        cve_field = vuln.get('cve')
        if isinstance(cve_field, dict):
            cve_id = cve_field.get('id', 'unknown')
            from vuln_checker.utils import extract_cve_severity_and_score
            severity, _ = extract_cve_severity_and_score(cve_field)
            return cve_id, severity
        else:
            cve_id = vuln.get('id') or (cve_field if isinstance(cve_field, str) else vuln.get('cve') or 'unknown')
            severity = vuln.get('severity') or vuln.get('baseSeverity') or 'UNKNOWN'
            return cve_id, normalize_severity(severity)
    except Exception:
        return 'unknown', 'UNKNOWN'

_CHANGELOG_CACHE = {}

def get_rpm_changelog(package_name: str) -> str:
    """Read local RPM package changelog to check for backported CVE fixes offline."""
    if package_name in _CHANGELOG_CACHE:
        return _CHANGELOG_CACHE[package_name]
    try:
        res = subprocess.run(['rpm', '-q', '--changelog', package_name], capture_output=True, text=True, timeout=5)
        changelog = res.stdout if res.returncode == 0 else ""
        _CHANGELOG_CACHE[package_name] = changelog
        return changelog
    except Exception:
        _CHANGELOG_CACHE[package_name] = ""
        return ""

def get_deb_changelog(package_name: str) -> str:
    """Read local Debian/Ubuntu package changelog to check for backported CVE fixes offline."""
    if package_name in _CHANGELOG_CACHE:
        return _CHANGELOG_CACHE[package_name]
    
    # Support WSL path translation when running on Windows
    wsl_prefix = ""
    if os.name == 'nt':
        cwd = os.getcwd()
        if cwd.startswith("\\\\wsl.localhost\\"):
            parts = cwd.split("\\")
            if len(parts) >= 4:
                wsl_prefix = "\\\\" + parts[2] + "\\" + parts[3]
        elif cwd.startswith("\\\\wsl$\\"):
            parts = cwd.split("\\")
            if len(parts) >= 4:
                wsl_prefix = "\\\\" + parts[2] + "\\" + parts[3]

    changelog_paths = [
        f"/usr/share/doc/{package_name}/changelog.Debian.gz",
        f"/usr/share/doc/{package_name}/changelog.Debian",
        f"/usr/share/doc/{package_name}/changelog.gz"
    ]
    
    if wsl_prefix:
        changelog_paths = [wsl_prefix + p.replace("/", "\\") for p in changelog_paths]
    
    import gzip
    for path in changelog_paths:
        if os.path.exists(path):
            try:
                if path.endswith(".gz"):
                    with gzip.open(path, 'rt', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                else:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                _CHANGELOG_CACHE[package_name] = content
                return content
            except Exception:
                pass
    _CHANGELOG_CACHE[package_name] = ""
    return ""

def _scan_single_package(vendor: str, product: str, version: str, 
                         feed_manager, severity: Optional[str], path: Optional[str] = None, pkg_type: Optional[str] = None, purl: Optional[str] = None):
    # Ignore TypeScript type definitions (like @types/node or other @types/* npm packages)
    if (vendor == "types" and pkg_type == "npm_package") or (product and product.startswith("@types/")) or (purl and ("pkg:npm/@types/" in purl or "pkg:npm/%40types/" in purl)):
        logger.debug(f"ℹ️ Skipping TypeScript type definitions: {vendor}/{product}")
        return []

    vendor_candidates = {vendor}
    
    # Dynamically load vendor aliases, TLDs, product prefixes and Spring Boot vendors
    aliases_config = get_vendor_aliases()
    aliases = dict(aliases_config.get("aliases", {}))
    product_aliases = dict(aliases_config.get("product_aliases", {}))
    common_tlds = list(aliases_config.get("common_tlds", ["org", "com", "io", "net", "uk", "de"]))
    common_prefixes = list(aliases_config.get("common_prefixes", ["apache-", "org-", "com-"]))
    spring_boot_vendors = list(aliases_config.get("spring_boot_vendors", ["pivotal_software", "pivotal", "spring", "vmware"]))
    
    # Dynamically inject UI library aliases from configuration
    try:
        ui_sig = get_ui_signatures()
        libs_config = ui_sig.get("libraries", {})
        for lib_name, cfg in libs_config.items():
            vendor_name = cfg.get("vendor")
            lib_aliases = cfg.get("aliases", [])
            if vendor_name and lib_aliases:
                if vendor_name in aliases:
                    aliases[vendor_name] = list(set(aliases[vendor_name] + lib_aliases))
                else:
                    aliases[vendor_name] = lib_aliases
    except Exception as e:
        logger.debug(f"Could not load UI library aliases: {e}")

    if vendor in aliases:
        vendor_candidates.update(aliases[vendor])
    
    for alias_key, alias_vals in aliases.items():
        if vendor.startswith(alias_key + ".") or vendor.startswith(alias_key + ":"):
            vendor_candidates.update(alias_vals)

    parts = vendor.split('.')
    if len(parts) >= 2:
        if parts[0] in common_tlds:
            vendor_candidates.add(parts[1])
            if parts[1] in aliases:
                vendor_candidates.update(aliases[parts[1]])
            if len(parts) > 2:
                vendor_candidates.add(parts[2])
                if parts[2] in aliases:
                    vendor_candidates.update(aliases[parts[2]])

    if vendor.startswith('org.'): vendor_candidates.add(vendor[4:])
    if vendor.startswith('com.'): vendor_candidates.add(vendor[4:])
    if '_' in vendor: vendor_candidates.add(vendor.replace('_', '-'))
    if '-' in vendor: vendor_candidates.add(vendor.replace('-', '_'))
    
    product_candidates = {product}
    if '-' in product: product_candidates.add(product.replace('-', '_'))
    if '_' in product: product_candidates.add(product.replace('_', '-'))
    if product.startswith(f"{vendor}-"):
        product_candidates.add(product[len(vendor)+1:])
    for prefix in common_prefixes:
        if product.startswith(prefix):
             product_candidates.add(product[len(prefix):])

    for vc in list(vendor_candidates):
        if not vc: continue
        if product == vc:
            continue
        if product.startswith(vc + "-") or product.startswith(vc + "_"):
            # Prevent core applications (servers/standalone products) from matching client libraries.
            # Loaded dynamically from core_apps.txt to support global open-source customization.
            core_apps = get_core_apps()
            if vc in core_apps and product != vc:
                remainder = product[len(vc)+1:].lower()
                # Allow actual server/client/core packages to match the core app CPE
                allow_core = False
                if any(x in remainder for x in ["server", "client", "common", "devel", "core", "community", "daemon"]):
                    if not any(x in remainder for x in ["connector", "driver", "java", "python", "node", "go", "ruby", "php"]):
                        allow_core = True
                
                if not allow_core:
                    if remainder:
                        product_candidates.add(remainder)
                    continue
            # Prevent stripping prefix to match core product if the prefix is a core language/runtime system
            # Configured dynamically in vendor_aliases.json
            prefix_strip_exclusions = list(aliases_config.get("prefix_strip_exclusions", ["perl", "python", "systemd", "linux", "kernel", "openssl", "golang", "go", "ruby", "php"]))
            if vc in prefix_strip_exclusions:
                continue

            remainder = product[len(vc)+1:]
            subproject_exceptions = aliases_config.get("subproject_exceptions", {})
            exceptions = subproject_exceptions.get(vc, [])
            
            if not any(exc in remainder for exc in exceptions):
                product_candidates.add(vc)
                
            if remainder:
                product_candidates.add(remainder)

    if 'spring-boot-starter' in product or product.startswith('spring-boot-'):
        product_candidates.add('spring-boot')
        product_candidates.add('spring_boot')
        if vendor not in spring_boot_vendors:
            vendor_candidates.update(spring_boot_vendors)

    # Dynamically resolve product aliases
    if product in product_aliases:
        product_candidates.update(product_aliases[product])
    for alias_key, alias_vals in product_aliases.items():
        if alias_key in product:
            product_candidates.update(alias_vals)

    known_ui_libs = []
    known_ui_vendors = []
    # Dynamically inject UI library product/vendor candidates from configuration
    try:
        ui_sig = get_ui_signatures()
        libs_config = ui_sig.get("libraries", {})
        known_ui_libs = list(libs_config.keys())
        known_ui_vendors = [cfg.get("vendor") for cfg in libs_config.values() if cfg.get("vendor")]
        for lib_name, cfg in libs_config.items():
            lib_aliases = cfg.get("aliases", [])
            if lib_name == product or product in lib_aliases:
                product_candidates.update(lib_aliases)
                product_candidates.add(lib_name)
                cfg_vendor = cfg.get("vendor")
                if cfg_vendor:
                    vendor_candidates.add(cfg_vendor)
    except Exception as e:
        logger.debug(f"Could not load UI library candidate aliases: {e}")

    # For global JS/NPM/UI package compatibility, dynamically expand candidates
    if pkg_type in ["npm_package", "static_ui_library"] or vendor == product or vendor in known_ui_libs or vendor in known_ui_vendors:
        # 1. Expand product names for scoped npm packages (e.g. @babel/core -> babel-core, core)
        current_products = list(product_candidates)
        for prod in current_products:
            if prod.startswith("@") and "/" in prod:
                parts = prod.split("/", 1)
                scope = parts[0][1:]
                name = parts[1]
                product_candidates.add(name)
                product_candidates.add(f"{scope}-{name}")
                product_candidates.add(f"{scope}_{name}")
                vendor_candidates.add(scope)
                vendor_candidates.add(f"{scope}js")

        # 2. Add product_project, productjs, and product as candidate vendors (common in NVD)
        for p_cand in list(product_candidates):
            vendor_candidates.add(p_cand)
            vendor_candidates.add(f"{p_cand}_project")
            vendor_candidates.add(f"{p_cand}js")
            if "-" in p_cand:
                norm_p = p_cand.replace("-", "_")
                vendor_candidates.add(f"{norm_p}_project")
                vendor_candidates.add(norm_p)
            if "_" in p_cand:
                norm_p = p_cand.replace("_", "-")
                vendor_candidates.add(f"{norm_p}_project")
                vendor_candidates.add(norm_p)

    candidate_cpes = []
    if pkg_type != "npm_package":
        base_cpe = _build_cpe(vendor, product, version)
        candidate_cpes.append(base_cpe)
        for v in vendor_candidates:
            for p in product_candidates:
                cpe = _build_cpe(v, p, version)
                if cpe != base_cpe:
                    candidate_cpes.append(cpe)
    # base_cpe = _build_cpe(vendor, product, version)
    # candidate_cpes.append(base_cpe)
    # for v in vendor_candidates:
    #     for p in product_candidates:
    #         cpe = _build_cpe(v, p, version)
    #         if cpe != base_cpe:
    #             candidate_cpes.append(cpe)
                
    all_found_cves = []
    seen_cve_ids = set()
    severities = [severity] if severity else [None]

    if not purl:
        if pkg_type == "python_package":
            purl = f"pkg:pypi/{product}@{version}"
        elif pkg_type == "npm_package":
            purl = f"pkg:npm/{product}@{version}"
        elif pkg_type == "java_package":
            purl = f"pkg:maven/{vendor}/{product}@{version}" if vendor and vendor != "unknown" else f"pkg:maven/{product}@{version}"
        else:
            purl = "N/A"

    for cpe in candidate_cpes:
        if is_excluded_cpe(cpe):
            continue
            
        for sev in severities:
            cves = fetch_cves_cached_with_enrichment(
                cpe, feed_manager, severity=sev, 
                component_name=product, 
                component_version=version,
                purl=purl,
                path=path
            )
            for cve in cves:
                cve_data = cve.get("cve", cve)
                cve_id = cve_data.get("id")
                if cve_id not in seen_cve_ids:
                    # --- OS Package Backport Suppression Check ---
                    if pkg_type == "os_package" and cve_id and cve_id != "unknown":
                        # Check RPM changelog
                        if shutil.which('rpm'):
                            changelog = get_rpm_changelog(product)
                            if changelog and cve_id.upper() in changelog.upper():
                                logger.debug(f"ℹ️ Suppressed false positive: OS package {product} has backported fix for {cve_id} in local RPM changelog.")
                                continue
                        # Check Debian/Ubuntu changelog
                        changelog = get_deb_changelog(product)
                        if changelog and cve_id.upper() in changelog.upper():
                            logger.debug(f"ℹ️ Suppressed false positive: OS package {product} has backported fix for {cve_id} in local Debian/Ubuntu changelog.")
                            continue

                    seen_cve_ids.add(cve_id)
                    cve["vendor"] = vendor
                    cve["pkg_type"] = pkg_type
                    all_found_cves.append(cve)
                    
    if hasattr(feed_manager, 'search_ghsa_for_package'):
        ecosystem = None
        # 1. Resolve ecosystem using PURL
        if purl and purl.startswith("pkg:"):
            purl_lower = purl.lower()
            if "pkg:npm/" in purl_lower:
                ecosystem = "npm"
            elif "pkg:pypi/" in purl_lower:
                ecosystem = "PyPI"
            elif "pkg:maven/" in purl_lower:
                ecosystem = "Maven"
            elif "pkg:golang/" in purl_lower or "pkg:go/" in purl_lower:
                ecosystem = "Go"
        
        # 2. Fallback to heuristics based on product name/path
        if not ecosystem:
            prod_lower = product.lower()
            path_lower = (path or "").lower()
            if prod_lower.startswith(("github.com/", "golang.org/", "google.golang.org/", "gopkg.in/", "cel.dev/")):
                ecosystem = "Go"
            elif "node_modules" in path_lower:
                ecosystem = "npm"
            elif "site-packages" in path_lower or "dist-packages" in path_lower:
                ecosystem = "PyPI"
                
        # 3. Fallback to package type string
        if not ecosystem and pkg_type:
            type_lower = pkg_type.lower()
            if "npm" in type_lower or "node" in type_lower:
                ecosystem = "npm"
            elif "python" in type_lower or "pip" in type_lower or "pypi" in type_lower:
                ecosystem = "PyPI"
            elif "java" in type_lower or "maven" in type_lower or "jar" in type_lower:
                ecosystem = "Maven"
            elif "go" in type_lower:
                ecosystem = "Go"
            
        if ecosystem:
            osv_cves = feed_manager.search_ghsa_for_package(ecosystem, product, version, severity=severity)
            for osv_cve in osv_cves:
                cve_id = osv_cve.get("id") or osv_cve.get("cve", {}).get("id")
                if cve_id and cve_id not in seen_cve_ids:
                    seen_cve_ids.add(cve_id)
                    osv_cve["vendor"] = vendor
                    if path:
                        osv_cve["path"] = path
                    osv_cve["cpe_source"] = "ghsa"
                    osv_cve["pkg_type"] = pkg_type
                    all_found_cves.append(osv_cve)
                    
    return all_found_cves

def scan_server_vulnerabilities(packages_info, feed_manager, severity=None, base_dir=None, skip_nvd=False, exclude_dirs=None, native_only=False):
    """Scan packages for vulnerabilities."""
    all_cves = []
    
    # 0. Native RetireJS scan
    if base_dir:
        import subprocess
        import shutil
        from vuln_checker.retire_scanner import run_native_retirejs_scan
        
        dirs_to_scan = base_dir if isinstance(base_dir, list) else [base_dir]
        js_files = []
        exclude_set = set(os.path.normpath(os.path.abspath(d)) for d in (exclude_dirs or []))
        
        def is_excluded_path(path_str):
            abs_path = os.path.abspath(path_str)
            norm_path = os.path.normpath(abs_path)
            for d in exclude_set:
                if norm_path == d or norm_path.startswith(d + os.sep):
                    return True
            return False

        for d in dirs_to_scan:
            if not os.path.exists(d):
                continue
            search_roots = [d]
                
            for root_dir in search_roots:
                if not os.path.exists(root_dir):
                    continue
                if is_excluded_path(root_dir):
                    continue
                    
                if os.name != 'nt' and shutil.which('find') is not None:
                    cmd = ['find', root_dir]
                    prunes = set(exclude_dirs or [])
                    if prunes:
                        for p in sorted(list(prunes)):
                            cmd += ['-path', p, '-prune', '-o']
                    cmd += ['-type', 'f', '-name', '*.js', '-print']
                    try:
                        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                        js_files.extend([p for p in res.stdout.splitlines() if p])
                    except Exception:
                        pass
                else:
                    for root, dirs, files in os.walk(root_dir):
                        dirs[:] = [dir_name for dir_name in dirs if not is_excluded_path(os.path.join(root, dir_name))]
                        for file in files:
                            if file.endswith('.js'):
                                file_path = os.path.join(root, file)
                                if not is_excluded_path(file_path):
                                    js_files.append(file_path)
                                    
        if js_files:
            native_retire_findings = run_native_retirejs_scan(js_files, feed_manager)
            all_cves.extend(native_retire_findings)
    
    # 1. External Smart Scans
    if base_dir and not native_only:
        dirs_to_scan = base_dir if isinstance(base_dir, list) else [base_dir]
        external_findings = []
        for d in dirs_to_scan:
            external_findings.extend(run_smart_scans(d, exclude_dirs=exclude_dirs))

        for vuln in external_findings:
            v_id = vuln.get("id")
            if v_id is not None:
                v_id = str(v_id)
            # Determine pkg_type for external tool findings
            ext_tool = str(vuln.get("tool") or "").lower()
            ext_pkg_type = ""
            if "npm" in ext_tool or "retire" in ext_tool:
                ext_pkg_type = "npm_package"
            elif "pip" in ext_tool:
                ext_pkg_type = "python_package"

            # Try to enrich from local feeds if it looks like a CVE or GHSA
            full_cve = None
            if v_id and v_id.startswith("CVE-"):
                full_cve = feed_manager.get_cve_by_id(v_id)
            elif v_id and v_id.startswith("GHSA-"):
                osv_data = feed_manager.get_osv_by_id(v_id)
                if osv_data:
                    synthetic_cve = feed_manager.generate_synthetic_cve_from_osv(osv_data)
                    full_cve = {
                        "cve": synthetic_cve,
                        "feed_file": f"OSV - {osv_data.get('feed_ecosystem', 'unknown')}"
                    }
            
            if full_cve:
                # Use full NVD data but keep component/path info from external tool
                cve_item = dict(full_cve)
                cve_item.update({
                    "product": vuln.get("package"),
                    "component_name": vuln.get("component_name") or vuln.get("package"),
                    "component_version": vuln.get("version") or "external",
                    "path": vuln.get("path") or "N/A",
                    "cpe_used": f"external:{vuln.get('tool')}",
                    "cpe_source": vuln.get("tool"),
                    "upgrade_to": vuln.get("fix_version"),
                    "pkg_type": ext_pkg_type,
                    "tool": vuln.get("tool")
                })
            else:
                # Fallback to minimal data
                cve_item = {
                    "cve": {
                        "id": v_id,
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseSeverity": vuln.get("severity", "UNKNOWN")}}]
                        },
                        "descriptions": [{"value": vuln.get("description", "")}]
                    },
                    "product": vuln.get("package"),
                    "component_name": vuln.get("component_name") or vuln.get("package"),
                    "component_version": vuln.get("version") or "external",
                    "path": vuln.get("path") or "N/A",
                    "cpe_used": f"external:{vuln.get('tool')}",
                    "cpe_source": vuln.get("tool"),
                    "vendor": "unknown",
                    "upgrade_to": vuln.get("fix_version"),
                    "pkg_type": ext_pkg_type,
                    "tool": vuln.get("tool")
                }
            all_cves.append(cve_item)
            
            
        if external_findings:
            logger.info(f"✅ Integrated {len(external_findings)} findings from specialized audit tools")

    # 2. Local NVD Scan
    if skip_nvd:
        return all_cves

    total = len(packages_info)
    logger.info(f"Scanning {total} packages for vulnerabilities against local NVD feeds")

    try:
        from tqdm import tqdm
        iterator = tqdm(list(packages_info.items()), desc="Processing", unit="pkg")
        use_tqdm = True
    except Exception:
        iterator = list(packages_info.items())
        use_tqdm = False

    for item in iterator:
        key, entries = item
        parsed = _parse_key(key)
        if not parsed:
            continue
        vendor, product, version = parsed

        path = entries[0].get("path") if entries else None
        pkg_type = entries[0].get("type") if entries else None

        logger.debug(f"🔍 Processing: {product}:{version}")
        if use_tqdm:
            try:
                iterator.set_postfix_str(f"{product}:{version}")
            except Exception:
                pass

        try:
            purl = entries[0].get("purl") if entries else None
            pkg_cves = _scan_single_package(vendor, product, version, feed_manager, severity, path=path, pkg_type=pkg_type, purl=purl)
            all_cves.extend(pkg_cves)
            if pkg_cves:
                logger.debug(f"  → Found {len(pkg_cves)} CVE(s) for {product}:{version}")
                max_show = 5
                for i, cve in enumerate(pkg_cves):
                    if i >= max_show:
                        break
                    cve_id, sev = _extract_cve_id_and_severity(cve)
                    logger.debug(f"    - {cve_id} [{sev}]")
                if len(pkg_cves) > max_show:
                    logger.debug(f"    ... and {len(pkg_cves)-max_show} more CVEs")
        except Exception as e:
            logger.error(f"Error scanning {product}:{version}: {e}")

    if use_tqdm:
        try:
            iterator.close()
        except Exception:
            pass

    return all_cves
