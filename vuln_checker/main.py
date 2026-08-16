#!/usr/bin/env python3
"""CLI Entry Point"""
import sys
import re
import os
import time
import logging
from datetime import datetime
from vuln_checker.config import Config
from vuln_checker.integrations import ensure_tools
from vuln_checker.cli import get_version, setup_logging, validate_arguments, create_argument_parser

def main():
    """Main CLI entry point"""
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass # Python 3.6 or older
        
    BANNER = """\033[1;36m
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗         ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗ 
██║   ██║██║   ██║██║     ████╗  ██║        ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║   ██║██║   ██║██║     ██╔██╗ ██║ ██████╗██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║ ╚═════╝██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║        ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝         ╚══════╝╚═╝  ╚═╝╚══════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                           [ LOCAL & OFFLINE VULNERABILITY SCANNER ]
\033[0m"""
    if sys.stdout.isatty():
        print(BANNER)

    config_file = None
    if len(sys.argv) > 1 and "--config" in sys.argv:
        idx = sys.argv.index("--config")
        if idx + 1 < len(sys.argv):
            config_file = sys.argv[idx + 1]
    
    config = Config(config_file)
    
    # Setup logs directory and filename with timestamp
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    log_file = os.path.join(log_dir, f"vuln-checker_{date_str}.log")
    
    logger = setup_logging(log_file)
    
    parser = create_argument_parser(config)
    args = parser.parse_args()
    
    # Re-setup logging if a specific level was requested
    if args.log_level != "INFO":
        logger = setup_logging(log_file, level=args.log_level)
    
    # Log clean banner (no colors) at the start of the log file
    clean_banner = re.sub(r'\033\[[0-9;]*m', '', BANNER)
    logger.info(f"\n{clean_banner}")
    
    start_time = time.time()
    logger.info(f"Starting vuln-checker v{get_version()}")
    logger.info(f"Triggered Command: {' '.join(sys.argv)}")
    logger.debug(f"Arguments: {args}")
    
    # Safety Check: Cap workers at physical core count + 2 to avoid resource exhaustion
    cpu_cores = os.cpu_count() or 1
    if args.max_workers > (cpu_cores + 2):
        logger.warning(f"⚠️ Requested workers ({args.max_workers}) exceeds CPU cores ({cpu_cores}). Capping to {cpu_cores + 2} for stability.")
        args.max_workers = cpu_cores + 2
    
    try:
        validate_arguments(args)
        logger.info("Arguments validated successfully.")

        # Ensure external tools are available (Syft, pip-audit, Retire.js) unless native-only is selected
        if not getattr(args, 'native_only', False):
            ensure_tools()
        
        if args.upgrade:
            logger.info("Upgrade mode requested.")
            return 0
            
        if args.migrate_cache:
            logger.info("Cache migration not yet implemented.")
            return 0

        # Import and run the Object-Oriented pipeline orchestrator
        from vuln_checker.pipeline import VulnerabilityScanPipeline
        pipeline = VulnerabilityScanPipeline(args, config)
        
        # 1. Feed setup phase
        feed_manager = pipeline.setup_feeds()
        if not feed_manager:
            return 1
            
        # Exit early if no scan mode is specified (e.g. only --update-feeds was run)
        has_scan_mode = any([
            args.scan_server,
            args.scan_dir,
            args.sbom,
            getattr(args, 'input_csv', None),
            args.products,
            args.cpes_file
        ])
        if not has_scan_mode:
            logger.info("Feed setup completed. No scan mode specified; exiting.")
            return 0
            
        # 2. Vulnerability discovery phase
        all_cves = pipeline.execute_scan(feed_manager)
        
        # 3. Enrichment and filtering phase
        processed_data = pipeline.enrich_and_filter(all_cves)
        
        # 4. License compliance audit phase
        violations = pipeline.execute_license_audit()
        
        if not processed_data and not getattr(args, 'license_audit', False):
            return 0
            
        # 5. Report generation phase
        report_status = pipeline.generate_reports(processed_data, start_time)
        
        # Check fail-on-license condition
        policy = config.get("license_policy", {})
        fail_on_license = getattr(args, "fail_on_license", False) or policy.get("fail_on_violation", False)
        if fail_on_license and violations:
            logger.error("❌ Exiting with error code 1 due to license compliance violations.")
            return 1
            
        return report_status
    
    except FileNotFoundError as e:
        logger.error(f"File error: {e}")
        return 1
    except NotADirectoryError as e:
        logger.error(f"Directory error: {e}")
        return 1
    except ValueError as e:
        logger.error(f"Argument error: {e}")
        parser.print_help()
        return 1
    except KeyboardInterrupt:
        logger.warning("Scan cancelled by user (Ctrl+C).")
        return 130
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
