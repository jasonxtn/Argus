"""
Module Dependency Graph + Adaptive Scan Profiles
Defines which modules benefit from prior results and optimal execution ordering.
"""

from __future__ import annotations

from typing import Dict, List, Set


# Module dependencies: script_name (without .py) -> {benefits_from, feeds}
# "benefits_from" = these modules should run first for best results
# "feeds" = this module's output enriches these subsequent modules
MODULE_GRAPH: Dict[str, Dict[str, List[str]]] = {
    "dns_records": {
        "benefits_from": [],
        "feeds": ["subdomain_enum", "ip_info", "email_config", "dnssec"],
    },
    "dns_over_https": {
        "benefits_from": [],
        "feeds": ["dns_records"],
    },
    "domain_info": {
        "benefits_from": [],
        "feeds": ["domain_reputation_check", "passive_dns_history"],
    },
    "ip_info": {
        "benefits_from": ["dns_records"],
        "feeds": ["open_ports", "asn_lookup", "ip_reputation_check", "shodan"],
    },
    "associated_hosts": {
        "benefits_from": ["dns_records", "ip_info"],
        "feeds": ["ssl_checker", "http_headers"],
    },
    "open_ports": {
        "benefits_from": ["ip_info"],
        "feeds": ["firewall_detection", "http_security"],
    },
    "ssl_checker": {
        "benefits_from": ["dns_records", "open_ports"],
        "feeds": ["http_security", "certificate_authority_recon"],
    },
    "http_headers": {
        "benefits_from": ["dns_records"],
        "feeds": ["http_security", "cookies", "cdn_detection"],
    },
    "http_security": {
        "benefits_from": ["http_headers", "ssl_checker"],
        "feeds": ["clickjacking_test", "cors_misconfiguration_scanner"],
    },
    "technology_stack": {
        "benefits_from": ["http_headers", "crawler"],
        "feeds": ["cms_detection", "javascript_file_analyzer"],
    },
    "crawler": {
        "benefits_from": ["crawl_rules", "dns_records"],
        "feeds": ["broken_links", "content_discovery", "form_grabber"],
    },
    "email_config": {
        "benefits_from": ["dns_records"],
        "feeds": ["email_harvester"],
    },
    "virustotal_scan": {
        "benefits_from": ["dns_records", "ip_info"],
        "feeds": ["malware_phishing"],
    },
    "shodan": {
        "benefits_from": ["ip_info", "open_ports"],
        "feeds": ["passive_cve_mapper"],
    },
    "censys": {
        "benefits_from": ["ip_info"],
        "feeds": ["network_certificate_inventory"],
    },
}


# Adaptive Scan Profiles
# Inspired by MONNA's Adaptive Reasoning Selection — match scan intensity to task
SCAN_PROFILES: Dict[str, Dict] = {
    "quick": {
        "description": "Fast reconnaissance — essential modules only",
        "modules": [
            "dns_records", "ip_info", "domain_info", "http_headers",
            "ssl_checker", "open_ports",
        ],
        "parallel": True,
        "context_chaining": False,
        "timeout": 60,
    },
    "standard": {
        "description": "Thorough assessment — passive modules across categories",
        "categories": ["network", "web"],
        "parallel_within_category": True,
        "context_chaining": True,
        "timeout": 300,
    },
    "deep": {
        "description": "Comprehensive analysis — all modules with cross-referencing",
        "categories": ["network", "web", "security"],
        "multi_pass": True,
        "context_chaining": True,
        "follow_up": True,
        "timeout": 600,
    },
    "stealth": {
        "description": "Minimal footprint — passive-only modules",
        "modules": [
            "dns_records", "dns_over_https", "domain_info", "ct_log_query",
            "passive_dns_history", "archive_history", "global_ranking",
        ],
        "parallel": True,
        "context_chaining": False,
        "timeout": 120,
    },
}


def get_execution_order(module_ids: List[str]) -> List[List[str]]:
    """
    Given a list of module IDs, return them in dependency-aware execution order.
    Returns a list of "waves" — modules in the same wave can run in parallel.
    """
    from argus.core.catalog_cache import tools_mapping

    # Build script name -> module ID mapping
    id_to_script = {}
    script_to_id = {}
    for mid in module_ids:
        tool = tools_mapping.get(mid)
        if tool and tool.get("script"):
            script = tool["script"].replace(".py", "")
            id_to_script[mid] = script
            script_to_id[script] = mid

    # Build adjacency: module_id -> set of module_ids it depends on
    deps: Dict[str, Set[str]] = {mid: set() for mid in module_ids}
    for mid in module_ids:
        script = id_to_script.get(mid, "")
        graph_entry = MODULE_GRAPH.get(script, {})
        for dep_script in graph_entry.get("benefits_from", []):
            dep_id = script_to_id.get(dep_script)
            if dep_id and dep_id in deps:
                deps[mid].add(dep_id)

    # Topological sort into waves (Kahn's algorithm)
    waves: List[List[str]] = []
    remaining = dict(deps)

    while remaining:
        # Find modules with no unresolved dependencies
        wave = [mid for mid, d in remaining.items() if not d]
        if not wave:
            # Circular dependency — just dump everything remaining
            wave = list(remaining.keys())
            waves.append(wave)
            break
        waves.append(sorted(wave))
        for mid in wave:
            del remaining[mid]
        # Remove satisfied dependencies
        for d in remaining.values():
            d -= set(wave)

    return waves


def suggest_followups(completed_modules: List[str], all_findings_categories: Set[str]) -> List[str]:
    """
    Based on what modules have run and what was found,
    suggest modules that would provide valuable follow-up intelligence.
    """
    from argus.core.catalog_cache import tools_mapping

    completed_scripts = set()
    for mid in completed_modules:
        tool = tools_mapping.get(mid)
        if tool and tool.get("script"):
            completed_scripts.add(tool["script"].replace(".py", ""))

    suggestions = set()
    for script in completed_scripts:
        graph_entry = MODULE_GRAPH.get(script, {})
        for feed_script in graph_entry.get("feeds", []):
            if feed_script not in completed_scripts:
                # Check if this module exists in catalog
                for t in tools_mapping.values():
                    if t.get("script", "").replace(".py", "") == feed_script:
                        suggestions.add((t["number"], t["name"], feed_script))
                        break

    return sorted(suggestions, key=lambda x: x[2])
