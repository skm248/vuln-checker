import subprocess
import json
import logging
import shutil
import os
import sys
import zipfile
import tarfile
import urllib.request
import platform
from typing import List, Dict, Any, Optional
from pathlib import Path
from .utils import normalize_severity, get_ui_signatures

logger = logging.getLogger(__name__)

# Directory for portable binaries
BIN_DIR = (Path(__file__).parent / "bin").absolute()

def find_manifest_files(base_path: str, target_names: List[str], exclude_dirs: Optional[List[str]] = None) -> List[str]:
    """Recursively search for files matching target_names under base_path,
    pruning node_modules, .git, and any paths in exclude_dirs.
    """
    found_files = []
    exclude_set = set()
    if exclude_dirs:
        for d in exclude_dirs:
            exclude_set.add(os.path.normpath(os.path.abspath(d)))
            
    # Load default excludes dynamically from configuration
    default_excludes = set(get_ui_signatures().get("default_excludes", []))

    def is_excluded(path_str):
        abs_path = os.path.abspath(path_str)
        norm_path = os.path.normpath(abs_path)
        # Check explicit exclude_dirs
        for d in exclude_set:
            if norm_path == d or norm_path.startswith(d + os.sep):
                return True
        # Check standard default excludes in path parts
        parts = norm_path.split(os.sep)
        if any(p in default_excludes for p in parts):
            return True
        return False

    base_abs = os.path.abspath(base_path)
    if is_excluded(base_abs):
        return []

    for root, dirs, files in os.walk(base_abs):
        # Prune excluded directories in-place to prevent os.walk from descending into them
        pruned_dirs = []
        for d in dirs:
            dir_path = os.path.join(root, d)
            if not is_excluded(dir_path):
                pruned_dirs.append(d)
        dirs[:] = pruned_dirs

        for f in files:
            if f in target_names:
                file_path = os.path.join(root, f)
                if not is_excluded(file_path):
                    found_files.append(file_path)

    return found_files

def translate_path_to_windows(path_str: str) -> str:
    """Translate a Linux path to a Windows path using wslpath if available."""
    if os.name == 'nt':
        return path_str
    try:
        if path_str.startswith("/") or "/" in path_str or "\\" in path_str:
            result = subprocess.run(["wslpath", "-w", path_str], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                return result.stdout.strip()
    except Exception:
        pass
    return path_str

class ExternalToolIntegration:
    """Handles discovery, installation, and execution of external security tools."""

    @staticmethod
    def is_tool_available(tool_name: str) -> bool:
        """Check if a tool is available in system PATH, virtualenv bin, or local bin."""
        if shutil.which(tool_name) is not None:
            return True
        
        # Check active virtualenv/running Python bin directory
        py_bin_dir = Path(sys.executable).parent
        if (py_bin_dir / tool_name).exists():
            return True
        if os.name == 'nt' and (py_bin_dir / f"{tool_name}.exe").exists():
            return True

        # Check portable node bin directory
        node_bin = Path(__file__).parent / "node-v20.10.0-linux-x64" / "bin"
        if (node_bin / tool_name).exists():
            return True
        if os.name == 'nt' and (node_bin / f"{tool_name}.cmd").exists():
            return True

        # Check local bin with extension-awareness
        if os.name == 'nt':
            if tool_name == "npm":
                return (BIN_DIR / "npm.cmd").exists()
            return (BIN_DIR / f"{tool_name}.exe").exists()
        else:
            return (BIN_DIR / tool_name).exists()

    @staticmethod
    def get_executable(tool_name: str) -> str:
        """Return the best executable path for a tool."""
        # Check active virtualenv/running Python bin directory
        py_bin_dir = Path(sys.executable).parent
        if (py_bin_dir / tool_name).exists():
            return str(py_bin_dir / tool_name)
        if os.name == 'nt' and (py_bin_dir / f"{tool_name}.exe").exists():
            return str(py_bin_dir / f"{tool_name}.exe")

        # Check portable node bin directory
        node_bin = Path(__file__).parent / "node-v20.10.0-linux-x64" / "bin"
        if (node_bin / tool_name).exists():
            return str(node_bin / tool_name)
        if os.name == 'nt' and (node_bin / f"{tool_name}.cmd").exists():
            return str(node_bin / f"{tool_name}.cmd")

        if os.name == 'nt':
            if tool_name == "npm" and (BIN_DIR / "npm.cmd").exists():
                return str(BIN_DIR / "npm.cmd")
            if (BIN_DIR / f"{tool_name}.exe").exists():
                return str(BIN_DIR / f"{tool_name}.exe")
        else:
            if (BIN_DIR / tool_name).exists():
                return str(BIN_DIR / tool_name)
        
        system_path = shutil.which(tool_name)
        return system_path or tool_name

    @classmethod
    def run_command(cls, command: List[str], cwd: Optional[str] = None, stream_output: bool = False) -> Optional[str]:
        """Execute a command and return its stdout. If stream_output is True, streams output live to terminal stdout/stderr."""
        try:
            exe_path = ExternalToolIntegration.get_executable(command[0])
            command[0] = exe_path

            # Translate paths if running a Windows executable from WSL/Linux
            is_win_exe = False
            if os.name != 'nt':
                is_win_exe = exe_path.endswith(".exe") or exe_path.endswith(".cmd") or exe_path.endswith(".bat") or "/mnt/" in exe_path.lower()

            if is_win_exe:
                new_command = [command[0]]
                for arg in command[1:]:
                    if "=" in arg:
                        parts = arg.split("=", 1)
                        parts[1] = translate_path_to_windows(parts[1])
                        new_command.append("=".join(parts))
                    else:
                        new_command.append(translate_path_to_windows(arg))
                command = new_command

                if cwd:
                    cwd = translate_path_to_windows(cwd)

            # Avoid shell=True on Windows by running command scripts via cmd.exe /c
            if os.name == 'nt' and command:
                exe = command[0]
                if exe.lower().endswith((".cmd", ".bat")) or not shutil.which(exe) and not shutil.which(f"{exe}.exe"):
                    command = ["cmd.exe", "/c"] + command

            # Prepare environment to include local bin
            env = os.environ.copy()
            # Add BIN_DIR to PATH so 'node' can find its peers if needed
            path_sep = ";" if os.name == 'nt' else ":"
            env["PATH"] = f"{BIN_DIR}{path_sep}{env.get('PATH', '')}"

            if stream_output:
                process = subprocess.Popen(
                    command,
                    cwd=cwd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    env=env,
                    shell=False
                )
                
                stdout_lines = []
                stderr_lines = []
                
                # Check if we can use select (Unix only)
                if os.name != 'nt':
                    import select
                    while process.poll() is None:
                        rlist, _, _ = select.select([process.stdout, process.stderr], [], [], 0.1)
                        for f in rlist:
                            line = f.readline()
                            if line:
                                if f is process.stdout:
                                    stdout_lines.append(line)
                                    sys.stdout.write(line)
                                    sys.stdout.flush()
                                else:
                                    stderr_lines.append(line)
                                    sys.stderr.write(line)
                                    sys.stderr.flush()
                    # Read final buffer lines
                    for line in process.stdout:
                        stdout_lines.append(line)
                        sys.stdout.write(line)
                        sys.stdout.flush()
                    for line in process.stderr:
                        stderr_lines.append(line)
                        sys.stderr.write(line)
                        sys.stderr.flush()
                else:
                    # Windows fallback: sequential read
                    for line in process.stdout:
                        stdout_lines.append(line)
                        sys.stdout.write(line)
                        sys.stdout.flush()
                    for line in process.stderr:
                        stderr_lines.append(line)
                        sys.stderr.write(line)
                        sys.stderr.flush()
                
                stdout = "".join(stdout_lines)
                stderr = "".join(stderr_lines)
                
                if not stdout and process.returncode != 0:
                    if stderr:
                        logger.debug(f"Command {' '.join(command)} failed: {stderr}")
                    return ""
                return stdout
            else:
                result = subprocess.run(
                    command,
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                    check=False,
                    env=env,
                    shell=False
                )
                
                # Some tools return non-zero for success (e.g. retire returns vuln count)
                if not result.stdout and result.returncode != 0:
                    if result.stderr:
                        logger.debug(f"Command {' '.join(command)} failed: {result.stderr}")
                    return ""
                return result.stdout
        except Exception as e:
            logger.debug(f"Error running external tool {' '.join(command)}: {e}")
            return None

class SyftIntegration(ExternalToolIntegration):
    """Integrates with Syft for SBOM generation and Docker scanning."""

    SYFT_VERSION = "1.32.0"
    
    @classmethod
    def verify_checksum(cls, file_path: Path, filename: str) -> bool:
        """Verify the SHA-256 checksum of the downloaded file against the official release checksums."""
        import hashlib
        try:
            checksums_url = f"https://github.com/anchore/syft/releases/download/v{cls.SYFT_VERSION}/syft_{cls.SYFT_VERSION}_checksums.txt"
            chk_path = file_path.parent / "syft_checksums.txt"
            urllib.request.urlretrieve(checksums_url, chk_path)
            
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            calc_hash = sha256.hexdigest().lower()
            
            match_found = False
            with open(chk_path, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        entry_hash = parts[0].lower()
                        entry_file = parts[1].strip().lstrip('*')
                        if entry_file == filename:
                            if calc_hash == entry_hash:
                                match_found = True
                                break
            if chk_path.exists():
                os.remove(chk_path)
            return match_found
        except Exception as e:
            logger.error(f"⚠️ Checksum verification failed: {e}")
            return False

    @classmethod
    def ensure_installed(cls):
        if cls.is_tool_available("syft"):
            return True
        
        msg = "📦 Syft not found. Installing portable version..."
        logger.info(msg)
        BIN_DIR.mkdir(parents=True, exist_ok=True)
        
        machine = platform.machine().lower()
        arch = "amd64"
        if "arm" in machine or "aarch64" in machine:
            arch = "arm64"
        
        try:
            if os.name == 'nt':
                msg_dl = "Downloading Syft for Windows..."
                logger.info(msg_dl)
                filename = f"syft_{cls.SYFT_VERSION}_windows_{arch}.zip"
                url = f"https://github.com/anchore/syft/releases/download/v{cls.SYFT_VERSION}/{filename}"
                zip_path = BIN_DIR / "syft.zip"
                urllib.request.urlretrieve(url, zip_path)
                
                # Cryptographic check
                logger.info("🔑 Verifying Syft release checksum...")
                if not cls.verify_checksum(zip_path, filename):
                    if zip_path.exists():
                        os.remove(zip_path)
                    raise ValueError(f"Integrity check failed: downloaded archive checksum mismatch!")
                
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extract("syft.exe", path=BIN_DIR)
                os.remove(zip_path)
            else:
                # Use the official installation script for Linux/macOS as requested
                msg_dl = "Using official Syft installation script..."
                logger.info(msg_dl)
                cmd = f"curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b {BIN_DIR}"
                subprocess.run(cmd, shell=True, check=True)
                if (BIN_DIR / "syft").exists():
                    os.chmod(BIN_DIR / "syft", 0o755)
            
            success_msg = "✅ Syft installed successfully."
            logger.info(success_msg)
            return True
        except Exception as e:
            error_msg = f"❌ Failed to install Syft: {e}"
            logger.error(error_msg)
            return False

    @classmethod
    def generate_sbom(cls, source: str, save_to: Optional[str] = None, parallelism: Optional[int] = None, exclude_dirs: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        if not cls.is_tool_available("syft"):
            if not cls.ensure_installed(): return None
        
        logger.info(f"Running Syft discovery on {source}...")
        
        import uuid
        tmp_path = None
        tmp_dir = os.path.join(os.getcwd(), ".tmp_vuln_checker")
        try:
            os.makedirs(tmp_dir, exist_ok=True)
            tmp_path = os.path.join(tmp_dir, f"syft_sbom_{uuid.uuid4().hex}.json")
            
            # Write CycloneDX directly to tmp_path so Syft prints status/progress bars to the terminal!
            cmd = ["syft", "scan", source, "-o", f"cyclonedx-json={tmp_path}"]
            if parallelism:
                cmd.extend(["--parallelism", str(parallelism)])
            if exclude_dirs:
                for d in exclude_dirs:
                    d_clean = d.strip("/\\")
                    if not d_clean:
                        continue
                    # Syft v1.0+ requires exclusion patterns to start with './', '*/', or '**/'
                    cmd.extend(["--exclude", f"./{d_clean}/**", "--exclude", f"**/{d_clean}/**"])
                
            # Stream the output live to terminal so they see the progress
            cls.run_command(cmd, stream_output=True)
            
            if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
                with open(tmp_path, "r", encoding="utf-8") as f:
                    output = f.read()
                
                if save_to:
                    try:
                        with open(save_to, "w", encoding="utf-8") as f:
                            f.write(output)
                        logger.info(f"💾 SBOM saved to {save_to}")
                    except Exception as e:
                        logger.error(f"Failed to save SBOM to {save_to}: {e}")

                try:
                    return json.loads(output)
                except json.JSONDecodeError:
                    logger.error("Failed to parse Syft output as JSON")
            else:
                logger.error("Syft failed to generate SBOM file.")
        except Exception as e:
            logger.error(f"Syft scan failed: {e}")
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
            if os.path.exists(tmp_dir):
                try:
                    os.rmdir(tmp_dir)
                except Exception:
                    pass
        return None

    @classmethod
    def get_active_containers(cls) -> List[str]:
        if not cls.is_tool_available("docker"):
            return []
        output = cls.run_command(["docker", "ps", "--format", "{{.ID}}"])
        return [line.strip() for line in output.splitlines() if line.strip()] if output else []

class NodeIntegration(ExternalToolIntegration):
    """Integrates with Node.js and npm for auditing."""

    NODE_VERSION = "20.10.0" # Modern LTS

    @classmethod
    def ensure_installed(cls):
        """Download and install a portable Node.js runtime."""
        if cls.is_tool_available("node") and cls.is_tool_available("npm"):
            return True
        
        msg = f"📦 Node.js/npm not found. Installing portable Node.js v{cls.NODE_VERSION}..."
        logger.info(msg)
        BIN_DIR.mkdir(parents=True, exist_ok=True)
        
        machine = platform.machine().lower()
        arch = "x64" # Node uses x64 instead of amd64
        if "arm" in machine or "aarch64" in machine:
            arch = "arm64"
            
        try:
            if os.name == 'nt':
                url = f"https://nodejs.org/dist/v{cls.NODE_VERSION}/node-v{cls.NODE_VERSION}-win-{arch}.zip"
                archive_path = BIN_DIR / "node.zip"
                msg_dl = f"Downloading Node.js for Windows ({arch})..."
                logger.info(msg_dl)
                urllib.request.urlretrieve(url, archive_path)
                
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    # Node zip contains a subfolder, we need node.exe and npm files
                    prefix = f"node-v{cls.NODE_VERSION}-win-{arch}/"
                    for member in zip_ref.namelist():
                        if member.startswith(prefix):
                            relative_path = member[len(prefix):]
                            if not relative_path: continue
                            target_path = BIN_DIR / relative_path
                            if member.endswith('/'):
                                target_path.mkdir(parents=True, exist_ok=True)
                            else:
                                with zip_ref.open(member) as source, open(target_path, "wb") as target:
                                    shutil.copyfileobj(source, target)
                os.remove(archive_path)
            else:
                # Linux uses .tar.xz (requires lzma which is standard in Python 3.3+)
                url = f"https://nodejs.org/dist/v{cls.NODE_VERSION}/node-v{cls.NODE_VERSION}-linux-{arch}.tar.xz"
                archive_path = BIN_DIR / "node.tar.xz"
                msg_dl = f"Downloading Node.js for Linux ({arch})..."
                logger.info(msg_dl)
                urllib.request.urlretrieve(url, archive_path)
                
                with tarfile.open(archive_path, "r:xz") as tar:
                    tar.extractall(path=BIN_DIR.parent)
                os.remove(archive_path)

                # Create symlinks in BIN_DIR pointing to extracted node, npm, npx
                extracted_bin = BIN_DIR.parent / f"node-v{cls.NODE_VERSION}-linux-{arch}" / "bin"
                for item in ["node", "npm", "npx"]:
                    target_sym = BIN_DIR / item
                    if target_sym.exists() or target_sym.is_symlink():
                        try:
                            target_sym.unlink()
                        except Exception:
                            try:
                                shutil.rmtree(target_sym)
                            except Exception:
                                pass
                    try:
                        target_sym.symlink_to(extracted_bin / item)
                    except Exception:
                        try:
                            shutil.copy2(extracted_bin / item, target_sym)
                        except Exception:
                            pass

            success_msg = "✅ Node.js and npm installed successfully."
            logger.info(success_msg)
            return True
        except Exception as e:
            error_msg = f"❌ Failed to install Node.js: {e}"
            logger.error(error_msg)
            return False

class NpmAuditIntegration(ExternalToolIntegration):
    """Integrates with npm audit."""

    @classmethod
    def scan(cls, path: str, exclude_dirs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        results = []
        if not cls.is_tool_available("npm"):
            if not NodeIntegration.ensure_installed(): return []

        p = Path(path)
        if not p.exists(): return []

        # Find all package.json files
        manifests = [Path(f) for f in find_manifest_files(path, ["package.json"], exclude_dirs)]
        if not manifests:
            return results

        # Process each found project
        for manifest in manifests:
            project_dir = str(manifest.parent)
            logger.info(f"Running npm audit on {project_dir}...")
            output = cls.run_command(["npm", "audit", "--json"], cwd=project_dir)
            if output:
                try:
                    data = json.loads(output)
                    vulnerabilities = data.get("vulnerabilities", {}) or data.get("advisories", {})
                    for pkg_name, info in vulnerabilities.items():
                        via = info.get("via", [])
                        if isinstance(via, list):
                            for advisory in via:
                                if isinstance(advisory, dict) and "source" in advisory:
                                    try:
                                        rel_manifest = str(manifest.relative_to(path))
                                        pkg_display = f"{pkg_name} ({rel_manifest})"
                                        path_display = rel_manifest
                                    except Exception:
                                        pkg_display = f"{pkg_name} ({manifest})"
                                        path_display = str(manifest)
                                    results.append({
                                        "id": advisory.get("source") or f"NPM-{advisory.get('id')}",
                                        "package": pkg_display,
                                        "component_name": pkg_name,
                                        "version": info.get("version", "unknown"),
                                        "path": path_display,
                                        "severity": normalize_severity(info.get("severity", "UNKNOWN")),
                                        "description": advisory.get("title") or f"Vulnerability in {pkg_name}",
                                        "tool": "npm audit"
                                    })
                except Exception: pass
        return results

class PipAuditIntegration(ExternalToolIntegration):
    """Integrates with pip-audit."""
    
    @classmethod
    def ensure_installed(cls):
        if cls.is_tool_available("pip-audit"): return True
        msg = "📦 pip-audit not found. Installing via pip..."
        logger.info(msg)
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "pip-audit"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            success_msg = "✅ pip-audit installed successfully."
            logger.info(success_msg)
            return True
        except Exception as e:
            error_msg = f"❌ Failed to install pip-audit: {e}"
            logger.error(error_msg)
            return False

    @classmethod
    def scan(cls, path: str, exclude_dirs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        results = []
        if not cls.is_tool_available("pip-audit"):
            if not cls.ensure_installed(): return []

        p = Path(path)
        if not p.exists(): return []

        triggers = ["requirements.txt", "pyproject.toml", "setup.py"]
        found_files = [Path(f) for f in find_manifest_files(path, triggers, exclude_dirs)]
        
        if not found_files:
            return results

        for found_file in found_files:
            file_name = found_file.name
            project_dir = str(found_file.parent)
            
            cmd = ["pip-audit", "--format", "json"]
            if file_name == "requirements.txt":
                cmd += ["-r", file_name]
            elif file_name == "pyproject.toml":
                cmd += ["--pyproject"]
            elif file_name == "setup.py":
                cmd += ["."]
            else:
                continue

            logger.info(f"Running pip-audit on {found_file}...")
            output = cls.run_command(cmd, cwd=project_dir)
            if output:
                try:
                    data = json.loads(output)
                    for dep in data:
                        pkg_name = dep.get("name")
                        version = dep.get("version")
                        for vuln in dep.get("vulns", []):
                            try:
                                rel_proj = os.path.relpath(str(found_file), path)
                            except Exception:
                                rel_proj = str(found_file)
                            results.append({
                                "id": vuln.get("id"),
                                "package": f"{pkg_name}:{version} ({rel_proj})",
                                "component_name": pkg_name,
                                "version": version,
                                "path": rel_proj,
                                "severity": normalize_severity(vuln.get("severity", "UNKNOWN")),
                                "description": vuln.get("description", f"Fix: {vuln.get('fix_versions')}"),
                                "tool": "pip-audit"
                            })
                except Exception: pass
        return results

class RetireJSIntegration(ExternalToolIntegration):
    """Integrates with Retire.js for UI/JavaScript vulnerability scanning."""
    
    @classmethod
    def ensure_installed(cls):
        if cls.is_tool_available("retire"): return True
        msg = "📦 Retire.js not found. Installing via npm..."
        logger.info(msg)
        try:
            if not NodeIntegration.ensure_installed(): return False
            cls.run_command(["npm", "install", "-g", "retire", "--quiet"])
            return cls.is_tool_available("retire")
        except Exception as e:
            logger.error(f"❌ Failed to install Retire.js: {e}")
            return False

    @classmethod
    def scan(cls, path: str, exclude_dirs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        results = []
        
        use_npx = False
        if cls.is_tool_available("retire"):
            use_npx = False
        elif cls.is_tool_available("npx"):
            use_npx = True
        else:
            if cls.ensure_installed():
                use_npx = False
            else:
                logger.warning("⚠️ Retire.js and npx are not available. Skipping Retire.js scan.")
                return []

        p = Path(path)
        if not p.exists(): return []

        logger.info(f"🔎 Detecting UI modules in {path}...")
        ui_modules = []
        
        exclude_set = set()
        if exclude_dirs:
            for d in exclude_dirs:
                exclude_set.add(os.path.normpath(os.path.abspath(d)))
        
        # Load default excludes dynamically from configuration
        default_excludes = set(get_ui_signatures().get("default_excludes", []))

        try:
            for entry in p.iterdir():
                try:
                    entry_abs = os.path.abspath(str(entry))
                    entry_norm = os.path.normpath(entry_abs)
                    if entry_norm in exclude_set:
                        continue
                    if entry.name in default_excludes:
                        continue
                    
                    if entry.is_dir():
                        has_js = False
                        for root, dirs, files in os.walk(entry):
                            pruned_dirs = []
                            for d in dirs:
                                dir_path = os.path.join(root, d)
                                dir_norm = os.path.normpath(os.path.abspath(dir_path))
                                if dir_norm not in exclude_set and d not in default_excludes:
                                    pruned_dirs.append(d)
                            dirs[:] = pruned_dirs
                            
                            depth = root[len(str(entry)):].count(os.sep)
                            if depth > 3: 
                                dirs[:] = [] 
                                continue
                            if any(f.endswith('.js') for f in files):
                                has_js = True
                                break
                        if has_js:
                            ui_modules.append(entry)
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f"Error detecting UI modules: {e}")

        if not ui_modules:
            return results

        import uuid
        tmp_dir = os.path.join(os.getcwd(), ".tmp_vuln_checker")
        try:
            os.makedirs(tmp_dir, exist_ok=True)
        except Exception:
            pass

        for module_dir in ui_modules:
            tmp_path = None
            try:
                tmp_path = os.path.join(tmp_dir, f"retire_{uuid.uuid4().hex}.json")
                
                logger.info(f"Running Retire.js on {module_dir}...")
                if use_npx:
                    cmd = ["npx", "--yes", "retire", "--path", str(module_dir), "--outputformat", "json", "--outputpath", tmp_path, "--nocache"]
                else:
                    cmd = ["retire", "--path", str(module_dir), "--outputformat", "json", "--outputpath", tmp_path, "--nocache"]
                
                cls.run_command(cmd, stream_output=True)
                
                if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
                    with open(tmp_path, 'r', encoding='utf-8') as f:
                        report_data = json.load(f)
                    
                    for entry in report_data.get("data", []):
                        file_path = entry.get("file", "unknown")
                        for result in entry.get("results", []):
                            component = result.get("component", "unknown")
                            version = result.get("version", "unknown")
                            for vuln in result.get("vulnerabilities", []):
                                severity = normalize_severity(vuln.get("severity", "UNKNOWN"))
                                
                                ids = []
                                identifiers = vuln.get("identifiers", {})
                                if "CVE" in identifiers:
                                    cve_val = identifiers["CVE"]
                                    ids.extend(cve_val if isinstance(cve_val, list) else [cve_val])
                                if "GHSA" in identifiers:
                                    ghsa_val = identifiers["GHSA"]
                                    ids.extend(ghsa_val if isinstance(ghsa_val, list) else [ghsa_val])
                                if "githubID" in identifiers:
                                    ids.append(identifiers["githubID"])
                                
                                primary_id = ids[0] if ids else f"RETIRE-{component}"
                                summary = identifiers.get("summary", "")
                                info_list = vuln.get("info", [])
                                info_str = info_list[0] if isinstance(info_list, list) and info_list else str(info_list)
                                
                                fix_version = vuln.get("below")
                                
                                description = f"{summary}\n\n{info_str}" if summary else info_str
                                if len(description) > 1000:
                                    description = description.split("\n\n")[0]
                                
                                retire_url = info_list[0] if isinstance(info_list, list) and info_list else "https://github.com/RetireJS/retire.js"
                                
                                try:
                                    rel_file = os.path.relpath(file_path, path)
                                except Exception:
                                    rel_file = file_path
                                    
                                results.append({
                                    "id": primary_id,
                                    "package": f"{component}:{version} ({rel_file})",
                                    "component_name": component,
                                    "version": version,
                                    "path": rel_file,
                                    "severity": severity,
                                    "description": description,
                                    "tool": "Retire.js",
                                    "aliases": list(set(ids)),
                                    "fix_version": fix_version,
                                    "url": retire_url
                                })
                else:
                    logger.debug(f"Retire.js produced no output for {module_dir}")
            except Exception as e:
                logger.debug(f"Retire.js failed for {module_dir}: {e}")
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass
        
        if os.path.exists(tmp_dir):
            try:
                os.rmdir(tmp_dir)
            except Exception:
                pass
                    
        return results

def ensure_tools():
    """Main entry point to ensure all required external tools are available."""
    SyftIntegration.ensure_installed()
    PipAuditIntegration.ensure_installed()
    NodeIntegration.ensure_installed()
    RetireJSIntegration.ensure_installed()

def run_smart_scans(path: str, exclude_dirs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    all_findings = []
    all_findings.extend(NpmAuditIntegration.scan(path, exclude_dirs=exclude_dirs))
    all_findings.extend(PipAuditIntegration.scan(path, exclude_dirs=exclude_dirs))
    all_findings.extend(RetireJSIntegration.scan(path, exclude_dirs=exclude_dirs))
    return all_findings
