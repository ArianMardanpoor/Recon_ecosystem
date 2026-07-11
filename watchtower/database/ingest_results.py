#!/usr/bin/env python3
"""
ingest_results.py - Bridge Go recon pipeline results into MongoDB via db.py

Usage:
    ingest_results.py <hostname> --workdir <path>
    ingest_results.py GLOBAL --workdir <path> --global

Reads per-target temp directory structure and ingests findings into MongoDB.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict

# Add parent directory to path for db.py import
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from database.db import upsert_scan_artifacts, upsert_scan_findings


# ============================================================================
# Configuration
# ============================================================================

# Map severity from VulnerabilityReport to confidence levels
SEVERITY_MAP = {
    "confirmed": "HIGH",
    "likely": "MEDIUM",
    "possible": "LOW",
}

# Map category names to reflection_type values
CATEGORY_REFLECTION_MAP = {
    "query_parameters": "source_reflection",
    "headers": "header_injection",
    "json_body": "json_body_injection",
    "dom": "dom_sink_injection",
}


# ============================================================================
# Utility Functions
# ============================================================================

def safe_name(s: str) -> str:
    """Match Go's safeName function: replace non-alnum with underscore"""
    return re.sub(r'[^a-zA-Z0-9]', '_', s)


def extract_hostname(url: str) -> Optional[str]:
    """Extract hostname from URL for filtering"""
    try:
        # Simple extraction without full URL parsing to avoid imports
        if '://' in url:
            url = url.split('://', 1)[1]
        if '/' in url:
            url = url.split('/', 1)[0]
        if ':' in url:
            url = url.split(':', 1)[0]
        return url
    except Exception:
        return None


def parse_timestamp(ts: str) -> datetime:
    """Parse timestamp string to datetime, fallback to now()"""
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except Exception:
        return datetime.now()


def merge_findings_dedup(findings_list: List[Dict]) -> List[Dict]:
    """
    Deduplicate findings by (parameter, discovery_source, reflection_type).
    Keep highest confidence on conflict.
    This mirrors db.py's upsert_scan_findings logic.
    """
    confidence_weights = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    merged = {}
    
    for f in findings_list:
        key = (f.get('parameter', ''), f.get('discovery_source', ''), f.get('reflection_type', ''))
        if key in merged:
            existing_conf = confidence_weights.get(merged[key].get('confidence', 'LOW').upper(), 0)
            new_conf = confidence_weights.get(f.get('confidence', 'LOW').upper(), 0)
            if new_conf > existing_conf:
                merged[key] = f
        else:
            merged[key] = f
    
    return list(merged.values())


# ============================================================================
# File Reading Functions
# ============================================================================

def read_passive_urls(workdir: Path, hostname: str) -> List[str]:
    """Read passive/<hostname>.passive file"""
    filepath = workdir / 'passive' / f'{hostname}.passive'
    urls = []
    if filepath.exists():
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    urls.append(line)
    return urls


def read_crawled_urls(workdir: Path, hostname: str) -> List[str]:
    """Read katana/<safe_name>-katana.txt file"""
    safe_host = safe_name(hostname)
    filepath = workdir / 'katana' / f'{safe_host}-katana.txt'
    urls = []
    if filepath.exists():
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    urls.append(line)
    return urls


def read_discovered_params(workdir: Path, hostname: str) -> List[str]:
    """Read params/<hostname>-param.txt file"""
    filepath = workdir / 'params' / f'{hostname}-param.txt'
    params = []
    if filepath.exists():
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    params.append(line)
    return params


def read_raw_findings(workdir: Path, hostname: str, global_mode: bool) -> List[Dict]:
    """Read raw_findings.jsonl and filter by hostname"""
    filepath = workdir / 'raw_findings.jsonl'
    findings = []
    if not filepath.exists():
        return findings
    
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
                if global_mode:
                    findings.append(finding)
                else:
                    # Filter by root_domain or hostname in URL
                    root_domain = finding.get('root_domain', '')
                    url = finding.get('url', '')
                    if root_domain == hostname or hostname in url:
                        findings.append(finding)
            except json.JSONDecodeError:
                continue
    
    return findings


def read_vulnerability_files(workdir: Path, hostname: str, global_mode: bool) -> List[Dict]:
    """
    Read vulnerabilities/*.json files.
    Each file is a VulnerabilityReport with query_parameters/headers/json_body/dom.
    """
    vuln_dir = workdir / 'vulnerabilities'
    if not vuln_dir.exists():
        return []
    
    findings = []
    for filepath in vuln_dir.glob('*.json'):
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            report_url = data.get('url', '')
            
            # Filter by hostname (unless global mode)
            if not global_mode:
                if hostname not in report_url:
                    # Also check if hostname appears in the URL's host
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(report_url)
                        if parsed.hostname != hostname and not parsed.hostname.endswith('.' + hostname):
                            continue
                    except Exception:
                        # If we can't parse, use simple string containment
                        if hostname not in report_url:
                            continue
            
            # Extract timestamp from file mtime
            mtime = datetime.fromtimestamp(filepath.stat().st_mtime)
            timestamp_str = mtime.isoformat()
            
            # Process each category
            for category in ['query_parameters', 'headers', 'json_body', 'dom']:
                vulns = data.get(category, [])
                reflection_type = CATEGORY_REFLECTION_MAP.get(category, 'unknown')
                
                for vuln in vulns:
                    parameter = vuln.get('parameter', '')
                    if not parameter:
                        continue
                    
                    severity = vuln.get('severity', 'possible')
                    confidence = SEVERITY_MAP.get(severity, 'LOW')
                    
                    # If confirmed, force HIGH
                    if vuln.get('confirmed', False):
                        confidence = 'HIGH'
                    
                    payloads = vuln.get('payloads', [])
                    
                    finding = {
                        'parameter': parameter,
                        'discovery_source': 'xssniper',
                        'confidence': confidence,
                        'reflection_type': reflection_type,
                        'url': report_url,
                        'timestamp': timestamp_str,
                        'context': {
                            'allowed_chars': payloads,
                        }
                    }
                    findings.append(finding)
        except Exception as e:
            # Log but continue
            sys.stderr.write(f"[ingest] Error reading {filepath}: {e}\n")
    
    return findings


def read_triage_file(workdir: Path, hostname: str) -> Dict[str, List[str]]:
    """
    Read triage_<safe_name>.txt and extract parameter names.
    Returns dict of {source: [parameters]} for cross-check.
    """
    safe_host = safe_name(hostname)
    filepath = workdir / f'triage_{safe_host}.txt'
    result = {
        'get_params': [],
        'dom_params': [],
        'headers': [],
    }
    
    if not filepath.exists():
        return result
    
    current_section = None
    param_pattern = re.compile(r'^([a-zA-Z0-9_\-]+)\s*\|')
    
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            if line.startswith('[GET PARAMS]'):
                current_section = 'get_params'
            elif line.startswith('[DOM CANARY]'):
                current_section = 'dom_params'
            elif line.startswith('[HEADERS]'):
                current_section = 'headers'
            elif current_section and line != 'none':
                # Extract parameter name
                match = param_pattern.match(line)
                if match:
                    param = match.group(1)
                    if param and param not in result[current_section]:
                        result[current_section].append(param)
    
    return result


def normalize_finding_from_triage(param: str, source: str, refl_type: str) -> Dict:
    """Create a finding from triage summary"""
    return {
        'parameter': param,
        'discovery_source': 'triage_summary',
        'confidence': 'LOW',
        'reflection_type': refl_type,
        'context': {
            'location': source,
        }
    }


# ============================================================================
# Main Ingestion Logic
# ============================================================================

def ingest_results(hostname: str, workdir: Path, global_mode: bool) -> Tuple[Dict[str, int], Optional[str]]:
    """
    Main ingestion function.
    Returns (stats, scan_status) or (stats, None) for global mode.
    """
    stats = {
        'passive': 0,
        'crawled': 0,
        'params': 0,
        'findings_total': 0,
        'vuln_files': 0,
        'triage_only': 0,
        'findings_ingested': 0,
    }
    
    # 1. Read artifacts
    passive_urls = read_passive_urls(workdir, hostname)
    stats['passive'] = len(passive_urls)
    
    crawled_urls = read_crawled_urls(workdir, hostname)
    stats['crawled'] = len(crawled_urls)
    
    discovered_params = read_discovered_params(workdir, hostname)
    stats['params'] = len(discovered_params)
    
    # Dedupe
    passive_urls = list(set(passive_urls))
    crawled_urls = list(set(crawled_urls))
    discovered_params = list(set(discovered_params))
    
    # 2. Build findings list from all sources
    all_findings = []
    
    # Source 4: raw_findings.jsonl
    raw_findings = read_raw_findings(workdir, hostname, global_mode)
    for f in raw_findings:
        # Convert reporter.Finding to our schema
        finding = {
            'parameter': f.get('vulnerable_parameter', ''),
            'discovery_source': f.get('discovery_source', 'unknown'),
            'confidence': f.get('confidence', 'LOW').upper(),
            'reflection_type': f.get('reflection_type', 'unknown'),
            'url': f.get('url', ''),
            'timestamp': f.get('timestamp', datetime.now().isoformat()),
            'context': {
                'location': f.get('context', {}).get('location', ''),
                'allowed_chars': f.get('context', {}).get('allowed_chars', []),
                'status_code': f.get('context', {}).get('status_code', 0),
            }
        }
        if finding['parameter']:
            all_findings.append(finding)
    stats['findings_total'] += len(raw_findings)
    
    # Source 5: vulnerabilities/*.json
    vuln_findings = read_vulnerability_files(workdir, hostname, global_mode)
    stats['vuln_files'] = len(vuln_findings)
    all_findings.extend(vuln_findings)
    
    # Source 6: triage file (fallback for missed parameters)
    triage_data = read_triage_file(workdir, hostname)
    existing_params = {f.get('parameter', '') for f in all_findings}
    
    # Check GET params from triage
    for param in triage_data.get('get_params', []):
        if param not in existing_params:
            all_findings.append(normalize_finding_from_triage(
                param, 'query_parameters', 'candidate'
            ))
            stats['triage_only'] += 1
    
    # Check DOM params from triage
    for param in triage_data.get('dom_params', []):
        if param not in existing_params:
            all_findings.append(normalize_finding_from_triage(
                param, 'dom_canary', 'candidate'
            ))
            stats['triage_only'] += 1
    
    # Check Headers from triage
    for param in triage_data.get('headers', []):
        if param not in existing_params:
            all_findings.append(normalize_finding_from_triage(
                param, 'header_candidate', 'candidate'
            ))
            stats['triage_only'] += 1
    
    # Deduplicate findings
    all_findings = merge_findings_dedup(all_findings)
    stats['findings_ingested'] = len(all_findings)
    
    # 3. Global mode: just print summary
    if global_mode:
        return stats, None
    
    # 4. Normal mode: upsert to MongoDB
    if passive_urls or crawled_urls or discovered_params:
        upsert_scan_artifacts(
            hostname,
            passive_urls=passive_urls if passive_urls else None,
            crawled_urls=crawled_urls if crawled_urls else None,
            discovered_params=discovered_params if discovered_params else None
        )
    
    # Only call upsert_scan_findings if we have findings
    if all_findings:
        # The scan_status will be computed by db.py's upsert_scan_findings
        upsert_scan_findings(hostname, all_findings, scan_status="pending")
        
        # Determine scan_status for summary (simplified)
        high_count = sum(1 for f in all_findings if f.get('confidence', '').upper() == 'HIGH')
        if high_count > 0:
            scan_status = 'confirmed_vuln'
        elif all_findings:
            scan_status = 'findings'
        else:
            scan_status = 'clean'
    else:
        scan_status = 'clean'
    
    return stats, scan_status


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Ingest Go recon pipeline results into MongoDB"
    )
    parser.add_argument(
        'hostname',
        help="Target hostname (e.g., sub.example.com) or 'GLOBAL' for global mode"
    )
    parser.add_argument(
        '--workdir',
        required=True,
        help="Path to per-target temp work directory"
    )
    parser.add_argument(
        '--global',
        dest='global_mode',
        action='store_true',
        help="Global mode: skip per-hostname filtering and upsert calls"
    )
    
    args = parser.parse_args()
    
    workdir = Path(args.workdir)
    if not workdir.exists():
        sys.stderr.write(f"[ingest] Error: workdir {workdir} does not exist\n")
        sys.exit(0)  # Don't fail the pipeline
    
    try:
        stats, scan_status = ingest_results(args.hostname, workdir, args.global_mode)
        
        # Print summary line
        if args.global_mode:
            print(f"[ingest] GLOBAL: total_findings={stats['findings_total']} "
                  f"(vuln_files={stats['vuln_files']})")
        else:
            status_str = scan_status if scan_status else 'unknown'
            print(f"[ingest] {args.hostname}: "
                  f"passive={stats['passive']} "
                  f"crawled={stats['crawled']} "
                  f"params={stats['params']} "
                  f"findings={stats['findings_ingested']} "
                  f"(vuln_files={stats['vuln_files']}, "
                  f"triage_only={stats['triage_only']}) "
                  f"-> scan_status={status_str}")
        
    except Exception as e:
        # Never raise past main, just log and exit cleanly
        sys.stderr.write(f"[ingest] Error: {e}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()