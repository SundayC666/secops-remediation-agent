"""
SLA Tracker for CVE Vulnerability Management
Implements CISA BOD 22-01 compliant SLA tracking with KEV prioritization
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

# Path to SLA policy configuration
SLA_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "sla_policy.json"


class SLAStatus(Enum):
    """SLA status levels"""
    ON_TRACK = "on_track"
    DUE_SOON = "due_soon"
    OVERDUE = "overdue"
    UNKNOWN = "unknown"


@dataclass
class SLAInfo:
    """SLA information for a vulnerability"""
    sla_days: int
    deadline: Optional[datetime]
    days_remaining: Optional[int]
    hours_remaining: Optional[int]
    status: SLAStatus
    status_label: str
    priority_rank: int
    priority_label: str
    policy_reference: str
    is_kev: bool
    recommended_action: Optional[str] = None


class SLATracker:
    """
    Tracks SLA compliance for CVE vulnerabilities.

    Priority Logic (per CISA guidance):
    1. KEV status takes precedence over CVSS severity
    2. Within KEV: severity still matters
    3. Non-KEV: standard CVSS-based prioritization
    """

    def __init__(self):
        self.config = self._load_config()
        self.sla_definitions = self.config.get("sla_definitions", {})
        self.priority_order = self.config.get("priority_order", {})
        self.status_thresholds = self.config.get("status_thresholds", {})

    def _load_config(self) -> Dict[str, Any]:
        """Load SLA policy configuration"""
        try:
            if SLA_CONFIG_PATH.exists():
                with open(SLA_CONFIG_PATH, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    logger.info(f"Loaded SLA config from {SLA_CONFIG_PATH}")
                    return config
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load SLA config: {e}")

        # Return default config if file not found
        return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Default SLA configuration based on CISA BOD 22-01"""
        return {
            "sla_definitions": {
                "kev_post_2021": {"days": 14},
                "kev_pre_2021": {"days": 180},
                "critical": {"days": 15},
                "high": {"days": 30},
                "medium": {"days": 90},
                "low": {"days": 180}
            },
            "priority_order": {
                "kev_critical": 1,
                "kev_high": 2,
                "kev_medium": 3,
                "kev_low": 4,
                "critical": 5,
                "high": 6,
                "medium": 7,
                "low": 8
            },
            "status_thresholds": {
                "on_track": 50,
                "due_soon": 25,
                "overdue": 0
            }
        }

    def _parse_cve_year(self, cve_id: str) -> Optional[int]:
        """Extract year from CVE ID (e.g., CVE-2024-1234 -> 2024)"""
        if not cve_id:
            return None
        try:
            parts = cve_id.upper().replace("CVE-", "").split("-")
            if parts:
                return int(parts[0])
        except (ValueError, IndexError):
            pass
        return None

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity string to lowercase"""
        if not severity:
            return "medium"
        return severity.lower().strip()

    def _get_sla_days(self, severity: str, is_kev: bool, cve_id: str) -> tuple[int, str]:
        """
        Determine SLA days based on KEV status and severity.

        Returns: (sla_days, policy_reference)
        """
        severity = self._normalize_severity(severity)

        if is_kev:
            # KEV vulnerabilities have stricter SLA
            cve_year = self._parse_cve_year(cve_id)
            if cve_year and cve_year >= 2021:
                sla_def = self.sla_definitions.get("kev_post_2021", {"days": 14})
                return sla_def.get("days", 14), "CISA BOD 22-01: KEV (post-2021)"
            else:
                sla_def = self.sla_definitions.get("kev_pre_2021", {"days": 180})
                return sla_def.get("days", 180), "CISA BOD 22-01: KEV (pre-2021)"

        # Non-KEV: use CVSS-based SLA
        sla_def = self.sla_definitions.get(severity, {"days": 90})
        return sla_def.get("days", 90), f"Industry standard: {severity.capitalize()}"

    def _get_priority_rank(self, severity: str, is_kev: bool) -> tuple[int, str]:
        """
        Calculate priority rank (lower = higher priority).
        KEV always takes precedence over non-KEV.

        Returns: (priority_rank, priority_label)
        """
        severity = self._normalize_severity(severity)

        if is_kev:
            key = f"kev_{severity}"
            rank = self.priority_order.get(key, 4)
            label = f"P{rank} - KEV {severity.capitalize()}"
        else:
            rank = self.priority_order.get(severity, 7)
            label = f"P{rank} - {severity.capitalize()}"

        return rank, label

    def _calculate_status(
        self,
        sla_days: int,
        published_date: Optional[datetime]
    ) -> tuple[SLAStatus, Optional[datetime], Optional[int], Optional[int]]:
        """
        Calculate SLA status based on published date and SLA days.

        Returns: (status, deadline, days_remaining, hours_remaining)
        """
        if not published_date:
            return SLAStatus.UNKNOWN, None, None, None

        now = datetime.now()
        deadline = published_date + timedelta(days=sla_days)
        time_remaining = deadline - now

        days_remaining = time_remaining.days
        hours_remaining = int(time_remaining.total_seconds() // 3600)

        if days_remaining < 0:
            return SLAStatus.OVERDUE, deadline, days_remaining, hours_remaining

        # Calculate percentage remaining
        total_hours = sla_days * 24
        pct_remaining = (hours_remaining / total_hours) * 100 if total_hours > 0 else 0

        due_soon_threshold = self.status_thresholds.get("due_soon", 25)

        if pct_remaining <= due_soon_threshold:
            return SLAStatus.DUE_SOON, deadline, days_remaining, hours_remaining

        return SLAStatus.ON_TRACK, deadline, days_remaining, hours_remaining

    def _get_status_label(self, status: SLAStatus, days_remaining: Optional[int]) -> str:
        """Generate human-readable status label"""
        if status == SLAStatus.OVERDUE:
            if days_remaining is not None:
                return f"OVERDUE by {abs(days_remaining)} days"
            return "OVERDUE"
        elif status == SLAStatus.DUE_SOON:
            if days_remaining is not None:
                if days_remaining == 0:
                    return "Due TODAY"
                elif days_remaining == 1:
                    return "Due TOMORROW"
                return f"Due in {days_remaining} days"
            return "Due Soon"
        elif status == SLAStatus.ON_TRACK:
            if days_remaining is not None:
                return f"{days_remaining} days remaining"
            return "On Track"
        return "Unknown"

    def calculate_sla(
        self,
        cve_id: str,
        severity: str,
        is_kev: bool,
        published_date: Optional[str] = None
    ) -> SLAInfo:
        """
        Calculate comprehensive SLA information for a CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")
            severity: CVSS severity (critical, high, medium, low)
            is_kev: Whether this CVE is in CISA KEV catalog
            published_date: CVE publication date (ISO format or datetime)

        Returns:
            SLAInfo with all SLA details
        """
        # Parse published date
        pub_dt = None
        if published_date:
            if isinstance(published_date, datetime):
                pub_dt = published_date
            else:
                try:
                    # Try common formats
                    for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
                        try:
                            pub_dt = datetime.strptime(published_date[:19], fmt)
                            break
                        except ValueError:
                            continue
                except Exception as e:
                    logger.warning(f"Failed to parse date {published_date}: {e}")

        # Get SLA days and policy reference
        sla_days, policy_ref = self._get_sla_days(severity, is_kev, cve_id)

        # Get priority
        priority_rank, priority_label = self._get_priority_rank(severity, is_kev)

        # Calculate status
        status, deadline, days_remaining, hours_remaining = self._calculate_status(
            sla_days, pub_dt
        )

        # Generate status label
        status_label = self._get_status_label(status, days_remaining)

        # Recommended action for overdue
        recommended_action = None
        if status == SLAStatus.OVERDUE:
            recommended_action = (
                "Immediate remediation required. If patching is not possible, "
                "consider isolating the affected asset per CISA guidance."
            )
        elif status == SLAStatus.DUE_SOON:
            recommended_action = "Prioritize remediation to meet SLA deadline."

        return SLAInfo(
            sla_days=sla_days,
            deadline=deadline,
            days_remaining=days_remaining,
            hours_remaining=hours_remaining,
            status=status,
            status_label=status_label,
            priority_rank=priority_rank,
            priority_label=priority_label,
            policy_reference=policy_ref,
            is_kev=is_kev,
            recommended_action=recommended_action
        )

    def to_dict(self, sla_info: SLAInfo) -> Dict[str, Any]:
        """Convert SLAInfo to dictionary for JSON serialization"""
        return {
            "sla_days": sla_info.sla_days,
            "deadline": sla_info.deadline.isoformat() if sla_info.deadline else None,
            "days_remaining": sla_info.days_remaining,
            "hours_remaining": sla_info.hours_remaining,
            "status": sla_info.status.value,
            "status_label": sla_info.status_label,
            "priority_rank": sla_info.priority_rank,
            "priority_label": sla_info.priority_label,
            "policy_reference": sla_info.policy_reference,
            "is_kev": sla_info.is_kev,
            "recommended_action": sla_info.recommended_action
        }

    def get_sla_summary(self, cve_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate SLA compliance summary for a list of CVEs.

        Args:
            cve_list: List of CVE dictionaries with sla_info

        Returns:
            Summary statistics
        """
        summary = {
            "total": len(cve_list),
            "on_track": 0,
            "due_soon": 0,
            "overdue": 0,
            "unknown": 0,
            "kev_count": 0,
            "compliance_rate": 0.0
        }

        for cve in cve_list:
            sla = cve.get("sla_info", {})
            status = sla.get("status", "unknown")

            if status == "on_track":
                summary["on_track"] += 1
            elif status == "due_soon":
                summary["due_soon"] += 1
            elif status == "overdue":
                summary["overdue"] += 1
            else:
                summary["unknown"] += 1

            if sla.get("is_kev"):
                summary["kev_count"] += 1

        # Calculate compliance rate (non-overdue / total with known status)
        known_count = summary["total"] - summary["unknown"]
        if known_count > 0:
            compliant = summary["on_track"] + summary["due_soon"]
            summary["compliance_rate"] = round((compliant / known_count) * 100, 1)

        return summary


# Global instance
_sla_tracker: Optional[SLATracker] = None


def get_sla_tracker() -> SLATracker:
    """Get or create the global SLA tracker instance"""
    global _sla_tracker
    if _sla_tracker is None:
        _sla_tracker = SLATracker()
    return _sla_tracker
