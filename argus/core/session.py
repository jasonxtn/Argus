"""
Session & Target Profile Management
Persistent state across module runs. Sessions can be saved and resumed.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set

from argus.core.context import ContextEngine, Finding, TargetProfile
from argus.core.output_engine import AssessmentReport, ModuleResult


SESSION_DIR = os.path.expanduser("~/.argus/sessions")


@dataclass
class SessionMeta:
    """Serializable session metadata."""
    session_id: str
    target: str
    profile: str
    created_at: float
    updated_at: float
    module_count: int
    finding_count: int
    status: str  # active, completed, paused


class Session:
    """
    Manages the lifecycle of a reconnaissance session.
    Tracks targets, findings, execution history, and can persist to disk.
    """

    def __init__(self, session_id: Optional[str] = None):
        self.id = session_id or str(uuid.uuid4())[:8]
        self.context = ContextEngine()
        self.reports: Dict[str, AssessmentReport] = {}  # target -> report
        self.notes: List[str] = []
        self.created_at = time.time()
        self.updated_at = time.time()
        self._status = "active"

    @property
    def status(self) -> str:
        return self._status

    def start_assessment(self, target: str, profile: str = "standard") -> AssessmentReport:
        """Begin a new assessment for a target."""
        import datetime
        report = AssessmentReport(
            target=target,
            profile=profile,
            started_at=datetime.datetime.now().isoformat(),
        )
        self.reports[target] = report
        self.updated_at = time.time()
        return report

    def get_report(self, target: str) -> Optional[AssessmentReport]:
        return self.reports.get(target)

    def add_note(self, note: str) -> None:
        self.notes.append(note)
        self.updated_at = time.time()

    def complete(self) -> None:
        self._status = "completed"
        self.updated_at = time.time()
        for report in self.reports.values():
            if not report.completed_at:
                report.finalize()

    def pause(self) -> None:
        self._status = "paused"
        self.updated_at = time.time()

    def resume(self) -> None:
        self._status = "active"
        self.updated_at = time.time()

    def get_meta(self) -> SessionMeta:
        total_findings = sum(r.total_findings for r in self.reports.values())
        total_modules = sum(len(r.module_results) for r in self.reports.values())
        first_target = next(iter(self.reports), "")
        first_profile = self.reports[first_target].profile if first_target else ""
        return SessionMeta(
            session_id=self.id,
            target=first_target,
            profile=first_profile,
            created_at=self.created_at,
            updated_at=self.updated_at,
            module_count=total_modules,
            finding_count=total_findings,
            status=self._status,
        )

    # --- Persistence ---

    def save(self) -> str:
        """Save session state to disk. Returns the filepath."""
        os.makedirs(SESSION_DIR, exist_ok=True)
        filepath = os.path.join(SESSION_DIR, f"{self.id}.json")

        data = {
            "session_id": self.id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self._status,
            "notes": self.notes,
            "run_history": self.context.run_history,
            "reports": {
                target: report.to_dict()
                for target, report in self.reports.items()
            },
            "profiles": {
                target: self._serialize_profile(profile)
                for target, profile in self._get_profiles().items()
            },
            "findings": [self._serialize_finding(f) for f in self.context.all_findings],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        return filepath

    @classmethod
    def load(cls, session_id: str) -> Optional[Session]:
        """Load a session from disk."""
        filepath = os.path.join(SESSION_DIR, f"{session_id}.json")
        if not os.path.exists(filepath):
            return None

        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        session = cls(session_id=data["session_id"])
        session.created_at = data.get("created_at", time.time())
        session.updated_at = data.get("updated_at", time.time())
        session._status = data.get("status", "paused")
        session.notes = data.get("notes", [])
        return session

    @classmethod
    def list_sessions(cls) -> List[Dict[str, Any]]:
        """List all saved sessions."""
        if not os.path.exists(SESSION_DIR):
            return []

        sessions = []
        for filename in os.listdir(SESSION_DIR):
            if filename.endswith(".json"):
                filepath = os.path.join(SESSION_DIR, filename)
                try:
                    with open(filepath, "r") as f:
                        data = json.load(f)
                    sessions.append({
                        "id": data.get("session_id", filename.replace(".json", "")),
                        "status": data.get("status", "unknown"),
                        "created_at": data.get("created_at"),
                        "updated_at": data.get("updated_at"),
                    })
                except (json.JSONDecodeError, IOError):
                    continue

        return sorted(sessions, key=lambda s: s.get("updated_at", 0), reverse=True)

    def _get_profiles(self) -> Dict[str, TargetProfile]:
        """Access internal profiles from context engine."""
        return self.context._profiles

    @staticmethod
    def _serialize_profile(profile: TargetProfile) -> Dict:
        return {
            "target": profile.target,
            "subdomains": list(profile.subdomains),
            "ips": list(profile.ips),
            "ports": profile.ports,
            "technologies": list(profile.technologies),
            "dns_records": profile.dns_records,
            "emails": list(profile.emails),
            "services": profile.services,
            "metadata": profile.metadata,
        }

    @staticmethod
    def _serialize_finding(finding: Finding) -> Dict:
        return {
            "module_id": finding.module_id,
            "category": finding.category,
            "title": finding.title,
            "value": str(finding.value),
            "severity": finding.severity,
            "evidence": finding.evidence,
            "timestamp": finding.timestamp,
            "tags": list(finding.tags),
        }
