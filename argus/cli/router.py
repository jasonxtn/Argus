"""
Layer 1: Command Router
Parses user intent, classifies target type, determines scan scope,
and routes to the appropriate execution strategy.
"""

from __future__ import annotations

import re
import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict
from urllib.parse import urlparse

from argus.core.catalog_cache import (
    tools,
    tools_mapping,
    SECTION_TOOL_NUMBERS,
    TOOL_TAGS,
)


class TargetType(Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    CIDR = "cidr"
    UNKNOWN = "unknown"


class ScanScope(Enum):
    SINGLE = "single"           # One module
    CHAIN = "chain"             # Explicit list of modules
    CATEGORY = "category"       # All modules in a category
    PROFILE = "profile"         # Adaptive scan profile (quick/standard/deep)
    FULL = "full"               # Everything applicable


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class TaskPlan:
    """The output of the command router — a structured execution plan."""
    target: str
    target_type: TargetType
    scan_scope: ScanScope
    module_ids: List[str]
    risk_level: RiskLevel = RiskLevel.LOW
    profile: Optional[str] = None
    options: Dict = field(default_factory=dict)
    suggested_followups: List[str] = field(default_factory=list)

    @property
    def module_count(self) -> int:
        return len(self.module_ids)


def detect_target_type(target: str) -> TargetType:
    """Classify what kind of target the user provided."""
    if not target:
        return TargetType.UNKNOWN

    # CIDR notation
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return TargetType.CIDR
        except ValueError:
            pass

    # URL with scheme
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        return TargetType.URL

    # IP address
    try:
        ipaddress.ip_address(target)
        return TargetType.IP
    except ValueError:
        pass

    # Domain — has at least one dot and valid chars
    domain_pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
        r"(\.[A-Za-z0-9-]{1,63})*"
        r"\.[A-Za-z]{2,}$"
    )
    if domain_pattern.match(target):
        return TargetType.DOMAIN

    return TargetType.UNKNOWN


def _get_modules_for_target_type(target_type: TargetType) -> List[str]:
    """Return module IDs that accept the given target type."""
    type_map = {
        TargetType.DOMAIN: {"Domain", "Domain/IP", "Domain/URL"},
        TargetType.IP: {"IP", "Domain/IP"},
        TargetType.URL: {"URL", "Domain/URL"},
        TargetType.CIDR: {"IP"},
    }
    accepted = type_map.get(target_type, set())
    return [
        t["number"] for t in tools
        if t.get("primary_input") in accepted and t.get("script")
    ]


def _assess_risk(target_type: TargetType, scope: ScanScope) -> RiskLevel:
    """Determine risk level based on target type and scope."""
    if scope in (ScanScope.FULL, ScanScope.CATEGORY):
        return RiskLevel.MEDIUM
    if target_type == TargetType.CIDR:
        return RiskLevel.HIGH
    return RiskLevel.LOW


def get_modules_for_profile(profile: str, target_type: TargetType) -> List[str]:
    """Select modules based on scan profile and target type."""
    from argus.core.dependencies import SCAN_PROFILES
    profile_def = SCAN_PROFILES.get(profile)
    if not profile_def:
        return []

    applicable = set(_get_modules_for_target_type(target_type))

    if "modules" in profile_def:
        # Explicit module list — resolve to IDs
        explicit = set()
        for mod_ref in profile_def["modules"]:
            for t in tools:
                if t.get("script", "").replace(".py", "") == mod_ref:
                    explicit.add(t["number"])
                    break
        return sorted(explicit & applicable)

    if "categories" in profile_def:
        cat_modules = set()
        cat_name_map = {
            "network": "Network & Infrastructure",
            "web": "Web Application Analysis",
            "security": "Security & Threat Intelligence",
        }
        for cat in profile_def["categories"]:
            full_name = cat_name_map.get(cat, cat)
            cat_modules.update(SECTION_TOOL_NUMBERS.get(full_name, []))
        return sorted(cat_modules & applicable)

    return sorted(applicable)


def route(
    target: str,
    module_ids: Optional[List[str]] = None,
    category: Optional[str] = None,
    profile: Optional[str] = None,
    options: Optional[Dict] = None,
) -> TaskPlan:
    """
    Main routing function. Takes user intent and produces a TaskPlan.
    """
    target_type = detect_target_type(target)
    opts = options or {}

    # Explicit module list
    if module_ids:
        return TaskPlan(
            target=target,
            target_type=target_type,
            scan_scope=ScanScope.CHAIN if len(module_ids) > 1 else ScanScope.SINGLE,
            module_ids=module_ids,
            risk_level=_assess_risk(target_type, ScanScope.CHAIN),
            options=opts,
        )

    # Category scan
    if category:
        cat_map = {
            "infrastructure": "Network & Infrastructure",
            "network": "Network & Infrastructure",
            "web": "Web Application Analysis",
            "security": "Security & Threat Intelligence",
        }
        full_cat = cat_map.get(category.lower(), category)
        cat_mods = SECTION_TOOL_NUMBERS.get(full_cat, [])
        return TaskPlan(
            target=target,
            target_type=target_type,
            scan_scope=ScanScope.CATEGORY,
            module_ids=cat_mods,
            risk_level=_assess_risk(target_type, ScanScope.CATEGORY),
            options=opts,
        )

    # Profile-based scan
    if profile:
        prof_mods = get_modules_for_profile(profile, target_type)
        return TaskPlan(
            target=target,
            target_type=target_type,
            scan_scope=ScanScope.PROFILE,
            module_ids=prof_mods,
            risk_level=_assess_risk(target_type, ScanScope.PROFILE),
            profile=profile,
            options=opts,
        )

    # Default: all applicable modules
    all_applicable = _get_modules_for_target_type(target_type)
    return TaskPlan(
        target=target,
        target_type=target_type,
        scan_scope=ScanScope.FULL,
        module_ids=all_applicable,
        risk_level=_assess_risk(target_type, ScanScope.FULL),
        options=opts,
    )
