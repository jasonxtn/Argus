"""
Layer 2: Context Engine
Manages shared intelligence across module runs within a session.
Modules no longer run in isolation — findings feed forward to subsequent modules.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class Finding:
    """A single discrete piece of intelligence from a module run."""
    module_id: str
    category: str               # dns, ssl, port, vulnerability, info, web, email
    title: str
    value: Any                  # The actual data (IP, subdomain, port, etc.)
    severity: str = "info"      # critical, high, medium, low, info
    evidence: str = ""          # Raw supporting data
    timestamp: float = field(default_factory=time.time)
    tags: Set[str] = field(default_factory=set)


@dataclass
class TargetProfile:
    """Cumulative intelligence about a target, built across module runs."""
    target: str
    subdomains: Set[str] = field(default_factory=set)
    ips: Set[str] = field(default_factory=set)
    ports: Dict[str, List[int]] = field(default_factory=dict)  # ip -> [ports]
    technologies: Set[str] = field(default_factory=set)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)  # type -> [values]
    certificates: List[Dict] = field(default_factory=list)
    emails: Set[str] = field(default_factory=set)
    services: Dict[str, str] = field(default_factory=dict)  # port -> service name
    metadata: Dict[str, Any] = field(default_factory=dict)  # whois, asn, geo, etc.

    def merge(self, other: TargetProfile) -> None:
        """Merge another profile into this one."""
        self.subdomains |= other.subdomains
        self.ips |= other.ips
        for ip, ports in other.ports.items():
            self.ports.setdefault(ip, []).extend(p for p in ports if p not in self.ports.get(ip, []))
        self.technologies |= other.technologies
        for rtype, vals in other.dns_records.items():
            self.dns_records.setdefault(rtype, []).extend(v for v in vals if v not in self.dns_records.get(rtype, []))
        self.certificates.extend(other.certificates)
        self.emails |= other.emails
        self.services.update(other.services)
        self.metadata.update(other.metadata)


@dataclass
class ReconContext:
    """Context passed to each module execution — everything the module can leverage."""
    target: str
    target_profile: TargetProfile
    run_history: List[str]                  # Module IDs already executed
    prior_findings: List[Finding]           # Findings from prior runs
    session_options: Dict[str, Any] = field(default_factory=dict)

    def get_findings_by_category(self, category: str) -> List[Finding]:
        return [f for f in self.prior_findings if f.category == category]

    def get_known_subdomains(self) -> Set[str]:
        return self.target_profile.subdomains

    def get_known_ips(self) -> Set[str]:
        return self.target_profile.ips

    def has_run(self, module_id: str) -> bool:
        return module_id in self.run_history


# --- Output Parsers ---
# These extract structured findings from raw module output text.

_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SUBDOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_PORT_PATTERN = re.compile(r"\b(\d{1,5})(?:/(?:tcp|udp))?\b.*?(?:open|listening)", re.I)
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_TECH_KEYWORDS = {
    "apache", "nginx", "iis", "cloudflare", "wordpress", "drupal", "joomla",
    "react", "angular", "vue", "django", "flask", "rails", "laravel",
    "node.js", "express", "php", "python", "java", "tomcat", "jquery",
}


def extract_findings_from_output(module_id: str, raw_output: str, target: str) -> List[Finding]:
    """Parse raw module output and extract structured findings."""
    findings: List[Finding] = []
    lines = raw_output.splitlines()

    # Extract IPs
    for ip in set(_IP_PATTERN.findall(raw_output)):
        if not ip.startswith("0.") and not ip.startswith("127."):
            findings.append(Finding(
                module_id=module_id,
                category="network",
                title="IP Address Discovered",
                value=ip,
                tags={"ip", "network"},
            ))

    # Extract subdomains
    target_base = target.split(".")[-2] + "." + target.split(".")[-1] if "." in target else target
    for sub in set(_SUBDOMAIN_PATTERN.findall(raw_output)):
        if target_base in sub and sub != target and len(sub) < 255:
            findings.append(Finding(
                module_id=module_id,
                category="dns",
                title="Subdomain Discovered",
                value=sub,
                tags={"subdomain", "dns"},
            ))

    # Extract open ports
    for match in _PORT_PATTERN.finditer(raw_output):
        port_num = int(match.group(1))
        if 1 <= port_num <= 65535:
            findings.append(Finding(
                module_id=module_id,
                category="port",
                title=f"Open Port {port_num}",
                value=port_num,
                tags={"port", "network"},
            ))

    # Extract emails
    for email in set(_EMAIL_PATTERN.findall(raw_output)):
        findings.append(Finding(
            module_id=module_id,
            category="email",
            title="Email Address Found",
            value=email,
            tags={"email", "contact"},
        ))

    # Extract technologies
    output_lower = raw_output.lower()
    for tech in _TECH_KEYWORDS:
        if tech in output_lower:
            findings.append(Finding(
                module_id=module_id,
                category="technology",
                title=f"Technology Detected: {tech.title()}",
                value=tech,
                tags={"technology", "web"},
            ))

    # Extract severity-tagged findings from output patterns
    severity_patterns = [
        (re.compile(r"(?:CRITICAL|SEVERE|EXPLOIT|COMPROMISE)", re.I), "critical"),
        (re.compile(r"(?:HIGH|ALERT|VULNERABLE|EXPIRED)", re.I), "high"),
        (re.compile(r"(?:WARNING|WARN|RISK|EXPOSED)", re.I), "medium"),
    ]
    for line in lines:
        for pattern, severity in severity_patterns:
            if pattern.search(line):
                findings.append(Finding(
                    module_id=module_id,
                    category="security",
                    title=line.strip()[:120],
                    value=line.strip(),
                    severity=severity,
                    tags={"security", severity},
                ))
                break  # Only tag once per line

    return findings


def update_profile_from_findings(profile: TargetProfile, findings: List[Finding]) -> None:
    """Feed findings back into the target profile for cross-module intelligence."""
    for f in findings:
        if f.category == "network" and isinstance(f.value, str) and "." in f.value:
            profile.ips.add(f.value)
        elif f.category == "dns" and "subdomain" in f.tags:
            profile.subdomains.add(f.value)
        elif f.category == "port" and isinstance(f.value, int):
            # Associate port with target (simplified — in practice associate with IPs)
            profile.ports.setdefault(profile.target, [])
            if f.value not in profile.ports[profile.target]:
                profile.ports[profile.target].append(f.value)
        elif f.category == "email":
            profile.emails.add(f.value)
        elif f.category == "technology":
            profile.technologies.add(f.value)


class ContextEngine:
    """
    Maintains session-wide context. Accumulates findings across module runs
    and provides enriched context to each subsequent module execution.
    """

    def __init__(self):
        self._profiles: Dict[str, TargetProfile] = {}
        self._findings: List[Finding] = []
        self._run_history: List[str] = []

    def get_or_create_profile(self, target: str) -> TargetProfile:
        if target not in self._profiles:
            self._profiles[target] = TargetProfile(target=target)
        return self._profiles[target]

    def build_context(self, target: str, options: Optional[Dict] = None) -> ReconContext:
        """Build a ReconContext for the next module execution."""
        profile = self.get_or_create_profile(target)
        return ReconContext(
            target=target,
            target_profile=profile,
            run_history=list(self._run_history),
            prior_findings=list(self._findings),
            session_options=options or {},
        )

    def ingest_results(self, module_id: str, target: str, raw_output: str) -> List[Finding]:
        """
        Process module output: extract findings, update profile, record history.
        Returns the new findings extracted.
        """
        self._run_history.append(module_id)
        findings = extract_findings_from_output(module_id, raw_output, target)
        self._findings.extend(findings)

        profile = self.get_or_create_profile(target)
        update_profile_from_findings(profile, findings)

        return findings

    @property
    def all_findings(self) -> List[Finding]:
        return list(self._findings)

    @property
    def run_history(self) -> List[str]:
        return list(self._run_history)

    def get_profile(self, target: str) -> Optional[TargetProfile]:
        return self._profiles.get(target)

    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self._findings if f.severity == severity]

    def get_critical_findings(self) -> List[Finding]:
        return [f for f in self._findings if f.severity in ("critical", "high")]

    def reset(self) -> None:
        self._profiles.clear()
        self._findings.clear()
        self._run_history.clear()
