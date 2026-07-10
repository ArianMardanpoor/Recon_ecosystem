#!/usr/bin/env python3
"""
Dynamic multi-level wildcard filter, built ON TOP of dnsx (no replacement).

Flow:
1. Caller already ran dnsx on real subdomains -> live_map {subdomain: [ips]}.
2. For every live subdomain, derive its exact parent zone (strip one label,
   not just root domain) -> catches nested/dynamic wildcards like
   *.oak.sellzone.com.
3. Dedupe parents (caching), generate ONE random fake sibling per unique
   parent, batch them all into a SINGLE dnsx call.
4. Any parent whose fake sibling resolved = wildcard zone -> every real
   subdomain under it gets discarded.
5. Whatever survives is genuine and safe to upsert_live.
"""

import random
import string
import json
import tempfile
import os

from utils.safe_subprocess import run_command_safe

RANDOM_LABEL_LEN = 14
DNSX_BASE_FLAGS = ["-silent", "-resp", "-json", "-r", "8.8.8.8,1.1.1.1", "-t", "50", "-rl", "100"]


def _random_label(length=RANDOM_LABEL_LEN):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _parent_zone(subdomain):
    parts = subdomain.split(".")
    if len(parts) <= 2:
        return subdomain
    return ".".join(parts[1:])


def _run_dnsx(domain_list):
    """Runs dnsx on a list of domains, returns {host: [ips]} for whatever resolved."""
    if not domain_list:
        return {}

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        for d in domain_list:
            f.write(f"{d}\n")
        temp_path = f.name

    resolved = {}
    try:
        command = ["dnsx", "-l", temp_path] + DNSX_BASE_FLAGS
        result = run_command_safe(command)
        if result:
            for line in result:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line.strip())
                    host = obj.get("host", "")
                    ips = obj.get("a", [])
                    if host:
                        resolved[host] = ips
                except json.JSONDecodeError:
                    continue
    finally:
        try:
            os.unlink(temp_path)
        except Exception:
            pass

    return resolved


def filter_wildcards(live_map):
    """
    live_map: {subdomain: [ips]} — already resolved by dnsx.
    Returns: (genuine_map, discarded_count)
    """
    if not live_map:
        return {}, 0

    subdomains = list(live_map.keys())

    # dedupe parent zones -> one fake probe per unique parent
    parent_to_fake = {}
    fake_to_parent = {}
    for sub in subdomains:
        parent = _parent_zone(sub)
        if parent not in parent_to_fake:
            fake = f"{_random_label()}.{parent}"
            parent_to_fake[parent] = fake
            fake_to_parent[fake] = parent

    fake_list = list(fake_to_parent.keys())
    fake_resolved = _run_dnsx(fake_list)  # only resolves if THAT zone is wildcard

    wildcard_parents = set()
    for fake_host in fake_resolved.keys():
        parent = fake_to_parent.get(fake_host)
        if parent:
            wildcard_parents.add(parent)

    genuine = {}
    discarded = 0
    for sub, ips in live_map.items():
        parent = _parent_zone(sub)
        if parent in wildcard_parents:
            discarded += 1
            continue
        genuine[sub] = ips

    return genuine, discarded