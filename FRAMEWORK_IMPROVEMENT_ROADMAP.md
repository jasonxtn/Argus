# Argus Framework Improvement Roadmap

## Applying MONNA v5.1 Architectural Patterns to Argus

**Date**: 2026-02-12
**Current Argus Version**: 2.0
**Reference Framework**: MONNA APEX v5.1

---

## Executive Summary

Argus is a solid OSINT reconnaissance toolkit with 135 modules, but it lacks the layered architecture, adaptive intelligence, quality assurance, and context-aware design that MONNA v5.1 demonstrates. This roadmap maps MONNA's architectural patterns onto Argus to create a next-generation reconnaissance platform.

**Key insight**: MONNA's value comes from its **layered processing pipeline**, **adaptive technique selection**, **quality gates**, and **context engineering**. These same principles apply directly to reconnaissance workflows.

---

## Gap Analysis: Argus vs MONNA Patterns

| MONNA Pattern | Argus Current State | Gap |
|---------------|-------------------|-----|
| **Layered Architecture** (5 layers) | Flat CLI + subprocess execution | No processing pipeline |
| **Command Router** (Layer 1) | Basic cmd2 command parsing | No intelligent routing or task classification |
| **Context Engine** (Layer 2) | No context awareness | Modules run in isolation, no shared context |
| **Adaptive Reasoning** (Layer 3) | Static module execution | No adaptive strategy selection |
| **Style/Output Engine** (Layer 4) | Basic Rich formatting | No configurable output profiles |
| **Quality Gates** (Layer 5) | No validation | No output verification or scoring |
| **Model Optimization Matrix** | N/A | No AI integration at all |
| **Compliance Engine** | None | No output standards enforcement |
| **GSR (Self-Refinement)** | None | No iterative improvement on results |
| **Decorators/Modifiers** | Basic CLI flags | No composable behavior modifiers |
| **Persona Assignment** | None | No domain-specific analysis profiles |
| **Output Contracts** | Free-form text/CSV | No structured output guarantees |

---

## Phase 1: Layered Architecture Refactor

**Inspired by**: MONNA's 5-Layer APEX Architecture

### 1.1 — Introduce a Processing Pipeline

Argus currently goes: `CLI command → subprocess → raw output`. Refactor to:

```
User Input
    ↓
Layer 1: Command Router (parse + classify + route)
    ↓
Layer 2: Context Engine (target intel, session state, prior results)
    ↓
Layer 3: Execution Engine (adaptive module selection + orchestration)
    ↓
Layer 4: Output Engine (formatting, severity, reporting)
    ↓
Layer 5: Quality Gates (validation, correlation, scoring)
    ↓
Final Output
```

**Files to modify/create**:
- `argus/core/pipeline.py` — New orchestration pipeline
- `argus/core/runner.py` — Refactor to be Layer 3 only
- `argus/core/context.py` — New context engine
- `argus/core/quality.py` — New quality gate system

**Implementation**:

```python
# argus/core/pipeline.py
class ReconPipeline:
    def __init__(self):
        self.router = CommandRouter()
        self.context = ContextEngine()
        self.executor = ExecutionEngine()
        self.output = OutputEngine()
        self.quality = QualityGates()

    def process(self, command, target, options):
        task = self.router.classify(command, target, options)
        ctx = self.context.build(task, target)
        results = self.executor.run(task, ctx)
        formatted = self.output.render(results, ctx)
        validated = self.quality.check(formatted, ctx)
        return validated
```

### 1.2 — Command Router (Layer 1)

**Inspired by**: MONNA Layer 1 — Parse command + modifiers + route to layers

Current Argus parses commands through cmd2 mixins but doesn't classify intent. Add:

- **Task Classification**: Is this a single module run, a category scan, a targeted probe, or a full assessment?
- **Scope Detection**: Determine if target is domain, IP, URL, CIDR range
- **Strategy Suggestion**: Based on target type, suggest optimal module combinations

```python
# argus/cli/router.py
class CommandRouter:
    def classify(self, command, target, options):
        target_type = detect_target_type(target)  # domain, ip, url, cidr
        scan_scope = determine_scope(command)       # single, category, full
        risk_level = assess_risk(target_type, scan_scope)
        recommended_modules = suggest_modules(target_type, scan_scope)
        return TaskPlan(target_type, scan_scope, risk_level, recommended_modules)
```

### 1.3 — Context Engine (Layer 2)

**Inspired by**: MONNA's Context Engineering Layer — "what the model knows when you say it"

Currently, every Argus module runs in isolation. No module knows what other modules found. Add:

- **Session Context**: Persist results across module runs within a session
- **Cross-Module Intelligence**: DNS results inform subdomain enumeration, port scan results inform web analysis
- **Target Profile**: Build cumulative knowledge about a target
- **History Awareness**: Track what was already scanned to avoid redundancy

```python
# argus/core/context.py
class ContextEngine:
    def __init__(self):
        self.session = {}          # Current session state
        self.target_profile = {}   # Accumulated target intel
        self.run_history = []      # What already ran
        self.findings = []         # Cross-module findings

    def build(self, task, target):
        return ReconContext(
            target=target,
            known_info=self.target_profile.get(target, {}),
            prior_results=self.get_relevant_results(task),
            run_history=self.run_history,
        )

    def update(self, module_id, results):
        """Feed module results back into context for future modules."""
        self.findings.extend(results.findings)
        self.target_profile[results.target] = merge(
            self.target_profile.get(results.target, {}),
            results.extracted_intel
        )
```

**Key benefit**: When you run `dns_records` first, the context engine feeds discovered subdomains to `subdomain_enum`, discovered IPs to `ip_info`, discovered mail servers to `email_security` — automatically.

---

## Phase 2: Adaptive Execution Engine

**Inspired by**: MONNA's Adaptive Reasoning Selection + Model Optimization Matrix

### 2.1 — Scan Profiles (Replaces Static Execution)

MONNA selects reasoning technique by task complexity. Argus should select scan strategy by assessment type:

```
ADAPTIVE SCAN PROTOCOL:
┌─────────────────────────────────────────────┐
│ QUICK RECON (single target, fast results):  │
│ → DNS + WHOIS + SSL + HTTP headers          │
│ → 4-6 modules, parallel execution           │
│ → ~30 seconds                               │
├─────────────────────────────────────────────┤
│ STANDARD ASSESSMENT (thorough scan):        │
│ → All passive modules for target type       │
│ → Sequential categories, parallel within    │
│ → Context-fed module chaining               │
├─────────────────────────────────────────────┤
│ DEEP DIVE (comprehensive analysis):         │
│ → All applicable modules                    │
│ → Multi-pass with context refinement        │
│ → Cross-reference findings                  │
│ → Automated follow-up on discoveries        │
├─────────────────────────────────────────────┤
│ TARGETED PROBE (specific concern):          │
│ → User specifies focus area                 │
│ → Context engine selects relevant modules   │
│ → Deep analysis on narrow scope             │
└─────────────────────────────────────────────┘
```

**Implementation**: Add to `argus/config/settings.py`:

```python
SCAN_PROFILES = {
    "quick": {
        "modules": ["dns_records", "whois_lookup", "ssl_expiry", "http_headers", "ip_info"],
        "parallel": True,
        "max_threads": 10,
        "timeout": 30,
    },
    "standard": {
        "categories": ["network", "web"],
        "parallel_within_category": True,
        "context_chaining": True,
        "timeout": 300,
    },
    "deep": {
        "categories": ["network", "web", "security"],
        "multi_pass": True,
        "context_chaining": True,
        "follow_up": True,
        "timeout": 600,
    },
    "targeted": {
        "auto_select": True,  # Context engine picks modules
        "focus": None,        # Set by user
    },
}
```

### 2.2 — Module Dependency Graph

**Inspired by**: MONNA's information hierarchy — "what the model needs FIRST"

Define which modules benefit from prior results:

```python
# argus/core/dependencies.py
MODULE_DEPENDENCIES = {
    "subdomain_enum": {"benefits_from": ["dns_records"], "feeds": ["port_scan", "web_crawl"]},
    "port_scan": {"benefits_from": ["ip_info", "subdomain_enum"], "feeds": ["service_detection"]},
    "ssl_analysis": {"benefits_from": ["subdomain_enum", "port_scan"], "feeds": ["security_headers"]},
    "web_crawl": {"benefits_from": ["subdomain_enum", "robots_txt"], "feeds": ["technology_stack"]},
    # ... for all 135 modules
}
```

This enables intelligent execution ordering — run DNS first, feed results to subdomain enumeration, feed those to port scanning, etc.

---

## Phase 3: Quality Gates System

**Inspired by**: MONNA's Quality Gates v4.0 + GSR + TOV

### 3.1 — Output Validation (Gate 1: Anti-Hallucination equivalent)

For recon tools, the equivalent of "anti-hallucination" is **result validation**:

```python
# argus/core/quality.py
class QualityGates:
    def validate_results(self, results, context):
        checks = []
        checks.append(self.gate_1_data_integrity(results))
        checks.append(self.gate_2_cross_reference(results, context))
        checks.append(self.gate_3_severity_accuracy(results))
        checks.append(self.gate_4_completeness(results, context))
        checks.append(self.gate_5_scoring(results))
        return QualityReport(checks)

    def gate_1_data_integrity(self, results):
        """Verify data formats: IPs are valid, domains resolve, ports are in range."""
        ...

    def gate_2_cross_reference(self, results, context):
        """Cross-check findings against prior results. Flag contradictions."""
        ...

    def gate_3_severity_accuracy(self, results):
        """Verify severity ratings match actual findings (not just keyword matching)."""
        ...

    def gate_4_completeness(self, results, context):
        """Check if expected data was returned. Flag modules that returned nothing."""
        ...

    def gate_5_scoring(self, results):
        """Score overall assessment quality."""
        ...
```

### 3.2 — Severity Scoring (Replaces Regex-Based Detection)

Current Argus uses regex pattern matching for severity:
```python
# Current: crude keyword matching
ALERT_PATTERN = re.compile(r"(critical|severe|exploit|high|vulnerable|expired)", re.I)
```

Replace with structured severity assessment:

```python
# argus/core/severity.py
class SeverityEngine:
    """
    Scoring system inspired by MONNA's Output Quality Scoring.
    """
    def score_finding(self, finding, context):
        return {
            "impact": self.assess_impact(finding),          # /25
            "exploitability": self.assess_exploitability(finding),  # /25
            "confidence": self.assess_confidence(finding),   # /25
            "context_relevance": self.assess_relevance(finding, context),  # /25
            "total": None,  # Calculated
        }
```

### 3.3 — Assessment Report Scoring

**Inspired by**: MONNA's Quality Score (/100)

```
ASSESSMENT QUALITY SCORE:
┌─────────────────────────────────────┐
│ Coverage:        /20  (% of applicable modules run)
│ Data Quality:    /20  (valid results vs errors)
│ Cross-Reference: /20  (findings corroborated)
│ Severity Accuracy: /20  (severity ratings justified)
│ Completeness:    /20  (no obvious gaps)
├─────────────────────────────────────┤
│ TOTAL:           /100
└─────────────────────────────────────┘
Score >= 85: Assessment is thorough
Score 70-84: Suggest additional modules
Score < 70:  Flag gaps, recommend re-run
```

---

## Phase 4: Output Contract System

**Inspired by**: MONNA's Output Contracts + Template Standards

### 4.1 — Structured Output Formats

Replace free-form console output with structured contracts:

```python
# argus/core/output_contract.py
@dataclass
class ModuleOutputContract:
    module_id: str
    target: str
    timestamp: datetime
    status: Literal["success", "partial", "error"]
    findings: List[Finding]
    severity_summary: SeveritySummary
    raw_data: Dict
    metadata: Dict  # execution time, threads used, etc.

@dataclass
class Finding:
    category: str           # "dns", "ssl", "port", "vulnerability"
    title: str
    description: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    evidence: str           # Raw data supporting the finding
    remediation: Optional[str]
    references: List[str]   # CVE, OWASP, etc.
```

### 4.2 — Report Templates

**Inspired by**: MONNA's Output Templates

Create export profiles:

```python
REPORT_PROFILES = {
    "executive": {
        "format": "pdf",
        "sections": ["summary", "critical_findings", "recommendations"],
        "detail_level": "high-level",
    },
    "technical": {
        "format": "json",
        "sections": ["all_findings", "raw_data", "methodology"],
        "detail_level": "detailed",
    },
    "compliance": {
        "format": "csv",
        "sections": ["findings_by_standard", "remediation_timeline"],
        "standards": ["owasp", "nist", "pci"],
    },
}
```

**Files to create**:
- `argus/core/output_contract.py`
- `argus/utils/report_templates/`
- Update `argus/utils/report_generator.py` to support contracts

---

## Phase 5: Modifier & Decorator System

**Inspired by**: MONNA's Modifiers (`--short`, `--detailed`, `--verify`) and Decorators

### 5.1 — Scan Modifiers

Add composable modifiers to any Argus command:

```
argus> run dns_records --deep          # Extended record types
argus> run dns_records --verify        # Cross-reference results
argus> run dns_records --json          # JSON output
argus> runall --parallel               # Max parallelism
argus> runall --sequential             # Ordered execution
argus> runall --context-chain          # Feed results between modules
argus> run ssl_analysis --compliance   # Check against standards
```

### 5.2 — Behavior Decorators

```python
# argus/core/decorators.py
DECORATORS = {
    "verify": lambda results: cross_reference_findings(results),
    "score": lambda results: calculate_quality_score(results),
    "correlate": lambda results, ctx: find_correlations(results, ctx),
    "remediate": lambda results: suggest_remediations(results),
    "timeline": lambda results: build_timeline(results),
    "export": lambda results, fmt: export_to_format(results, fmt),
}
```

---

## Phase 6: Intelligent Module Discovery

**Inspired by**: MONNA's Prompt Wizard (`/new` command) + Domain Research Triggers

### 6.1 — Smart Scan Wizard

```
argus> wizard
🎯 What are you assessing?
1. 🌐 Web Application
2. 🖥️ Network Infrastructure
3. 📧 Email Security
4. 🔒 SSL/TLS Configuration
5. 🕵️ Full OSINT Profile
6. 🎯 Custom (select modules)

Select: 1

🔍 Target type?
1. Single domain
2. Multiple subdomains
3. IP range
4. URL list

Select: 1
Target: example.com

📋 Recommended scan plan:
Category: Web Application Analysis
Modules: [technology_stack, security_headers, ssl_analysis, ...]
Estimated modules: 15
Profile: standard

Proceed? (Y / modify)
```

### 6.2 — Auto-Suggest Follow-ups

After each module run, suggest next steps based on findings:

```python
# argus/core/suggestions.py
class SuggestionEngine:
    def suggest_next(self, results, context):
        suggestions = []
        if results.has_finding("open_ports"):
            suggestions.append(("service_detection", "Open ports found — identify services"))
        if results.has_finding("subdomains"):
            suggestions.append(("ssl_analysis", "New subdomains — check SSL certificates"))
        if results.has_finding("outdated_software"):
            suggestions.append(("cve_lookup", "Outdated software — check for known CVEs"))
        return suggestions
```

---

## Phase 7: Session & State Management

**Inspired by**: MONNA's Context Engineering — State Awareness, Memory Design

### 7.1 — Persistent Session State

```python
# argus/core/session.py
class Session:
    def __init__(self, session_id=None):
        self.id = session_id or generate_id()
        self.targets = {}           # target → TargetProfile
        self.run_log = []           # Ordered execution history
        self.findings_db = []       # All findings, searchable
        self.notes = []             # User annotations
        self.created_at = datetime.now()

    def save(self, path="~/.argus/sessions/"):
        """Persist session to disk for later resumption."""
        ...

    def load(self, session_id):
        """Resume a previous session with full context."""
        ...

    def export_report(self, profile="technical"):
        """Generate report from accumulated session data."""
        ...
```

### 7.2 — Target Intelligence Profile

```python
# argus/core/target_profile.py
class TargetProfile:
    """Cumulative intelligence about a target, built across module runs."""
    def __init__(self, target):
        self.target = target
        self.dns = {}               # DNS records
        self.subdomains = []        # Discovered subdomains
        self.ips = []               # Associated IPs
        self.ports = {}             # Open ports + services
        self.technologies = []     # Detected tech stack
        self.certificates = []     # SSL/TLS certs
        self.vulnerabilities = []  # Identified vulns
        self.metadata = {}         # WHOIS, ASN, geolocation
        self.timeline = []         # When each piece was discovered
```

---

## Phase 8: Compliance & Standards Engine

**Inspired by**: MONNA's Compliance Engine + Banned Words system

### 8.1 — Finding Classification Against Standards

```python
# argus/core/compliance.py
STANDARDS_MAP = {
    "owasp_top10": {
        "A01_broken_access": ["open_admin_panel", "directory_listing", ...],
        "A02_crypto_failures": ["weak_ssl", "expired_cert", "http_no_tls", ...],
        "A03_injection": ["sql_injection_indicators", ...],
        ...
    },
    "nist_800_53": { ... },
    "pci_dss": { ... },
    "cis_benchmarks": { ... },
}

class ComplianceEngine:
    def map_findings(self, findings, standard="owasp_top10"):
        """Map raw findings to compliance framework categories."""
        ...

    def gap_analysis(self, findings, standard):
        """Identify what wasn't tested that the standard requires."""
        ...
```

---

## Phase 9: Multi-Format Export System

**Inspired by**: MONNA's format decorators + output templates

### 9.1 — Export Formats

Expand beyond TXT/CSV to:

| Format | Use Case |
|--------|----------|
| **JSON** | API integration, programmatic consumption |
| **HTML** | Standalone report with styling |
| **PDF** | Client-facing deliverables |
| **Markdown** | Documentation, wikis |
| **SARIF** | Integration with security tools (GitHub, Azure DevOps) |
| **CSV** | Spreadsheet analysis |

### 9.2 — Implementation

```python
# argus/utils/exporters/
# ├── json_exporter.py
# ├── html_exporter.py
# ├── pdf_exporter.py
# ├── markdown_exporter.py
# ├── sarif_exporter.py
# └── csv_exporter.py

class ExportEngine:
    def export(self, session, format="json", profile="technical"):
        exporter = self.get_exporter(format)
        template = self.get_template(profile)
        return exporter.render(session, template)
```

---

## Phase 10: Optional AI Integration Layer

**Inspired by**: MONNA's entire AI-first architecture

### 10.1 — AI-Powered Analysis (Optional Module)

For users who want AI-assisted reconnaissance analysis:

```python
# argus/ai/analyzer.py (optional, behind feature flag)
class AIAnalyzer:
    """Uses LLM to analyze and correlate reconnaissance findings."""

    def analyze_findings(self, session):
        """Generate narrative analysis of all findings."""
        ...

    def suggest_attack_surface(self, target_profile):
        """Identify potential attack vectors from gathered intel."""
        ...

    def generate_executive_summary(self, session):
        """Create human-readable summary for non-technical stakeholders."""
        ...

    def correlate_across_modules(self, findings):
        """Find non-obvious connections between different module outputs."""
        ...
```

### 10.2 — Natural Language Queries

```
argus> ask "What's the most critical finding for example.com?"
argus> ask "Are there any SSL issues across all subdomains?"
argus> ask "Summarize the attack surface"
```

---

## Implementation Priority Matrix

| Phase | Effort | Impact | Priority |
|-------|--------|--------|----------|
| **Phase 1**: Pipeline Architecture | High | High | P0 — Foundation |
| **Phase 2**: Adaptive Execution | Medium | High | P0 — Core value |
| **Phase 3**: Quality Gates | Medium | High | P1 — Differentiation |
| **Phase 4**: Output Contracts | Medium | Medium | P1 — Data quality |
| **Phase 7**: Session Management | Medium | High | P1 — User experience |
| **Phase 5**: Modifiers/Decorators | Low | Medium | P2 — Power users |
| **Phase 6**: Smart Discovery | Low | Medium | P2 — Onboarding |
| **Phase 8**: Compliance Engine | Medium | Medium | P2 — Enterprise |
| **Phase 9**: Multi-Format Export | Low | Medium | P2 — Integration |
| **Phase 10**: AI Integration | High | High | P3 — Future |

---

## File Structure After Implementation

```
argus/
├── cli/                    # Existing — enhanced
│   ├── commands/           # Add wizard command
│   ├── router.py           # NEW — Command Router (Layer 1)
│   └── ...
├── core/                   # Significantly expanded
│   ├── pipeline.py         # NEW — Orchestration pipeline
│   ├── context.py          # NEW — Context Engine (Layer 2)
│   ├── runner.py           # REFACTORED — Execution only (Layer 3)
│   ├── output_engine.py    # NEW — Output Engine (Layer 4)
│   ├── quality.py          # NEW — Quality Gates (Layer 5)
│   ├── severity.py         # NEW — Structured severity scoring
│   ├── session.py          # NEW — Session state management
│   ├── target_profile.py   # NEW — Cumulative target intel
│   ├── dependencies.py     # NEW — Module dependency graph
│   ├── suggestions.py      # NEW — Follow-up suggestions
│   ├── decorators.py       # NEW — Behavior decorators
│   └── compliance.py       # NEW — Standards mapping
├── utils/
│   ├── exporters/          # NEW — Multi-format export
│   │   ├── json_exporter.py
│   │   ├── html_exporter.py
│   │   ├── sarif_exporter.py
│   │   └── ...
│   └── report_generator.py # REFACTORED — Uses output contracts
├── ai/                     # NEW — Optional AI layer
│   ├── analyzer.py
│   └── ...
└── config/
    ├── settings.py         # ENHANCED — Scan profiles, report profiles
    ├── modules.json        # ENHANCED — Add dependency metadata
    └── standards/          # NEW — Compliance standard definitions
        ├── owasp_top10.json
        ├── nist_800_53.json
        └── pci_dss.json
```

---

## Key Architectural Principles (from MONNA, applied to Argus)

1. **Layered Processing**: Every scan goes through all 5 layers, not just execution
2. **Context-Aware**: Modules share intelligence, not just run in isolation
3. **Adaptive Strategy**: Scan approach matches the assessment type, not one-size-fits-all
4. **Quality Enforced**: Every output validated, scored, and verified
5. **Composable Behavior**: Modifiers and decorators let users customize without complexity
6. **Structured Outputs**: Output contracts replace free-form text
7. **Session Persistence**: Work accumulates across runs, sessions can be resumed
8. **Standards-Mapped**: Findings map to real compliance frameworks
9. **Token/Resource Efficient**: Run only what's needed (adaptive, not exhaustive)
10. **Progressive Disclosure**: Simple by default, powerful when needed

---

## Version Targets

| Version | Includes | Codename |
|---------|----------|----------|
| **v2.1** | Phase 1 (Pipeline) + Phase 7 (Sessions) | "Foundation" |
| **v2.2** | Phase 2 (Adaptive) + Phase 3 (Quality) | "Intelligence" |
| **v2.5** | Phase 4 (Contracts) + Phase 5 (Modifiers) + Phase 9 (Export) | "Professional" |
| **v3.0** | Phase 6 (Wizard) + Phase 8 (Compliance) + Phase 10 (AI) | "APEX" |
