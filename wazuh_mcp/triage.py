"""Incident triage recommendation engine.

Generates actionable response recommendations based on alert severity,
MITRE technique names, and source IPs.
"""
from __future__ import annotations


def incident_recommendations(
    techniques: list[str],
    severity: str,
    src_ips: list[str],
) -> list[str]:
    """Return a list of human-readable remediation steps for an incident.

    Args:
        techniques: List of MITRE technique names (not IDs) from the alert.
        severity:   Severity string — "CRITICAL", "HIGH", "MEDIUM", or "LOW".
        src_ips:    Source IPs observed in the incident.
    """
    recs: list[str] = []
    t = [x.lower() for x in techniques]

    if severity in ("CRITICAL", "HIGH"):
        recs.append("Isolate affected agents immediately and capture memory dumps if possible.")

    if any(k in x for x in t for k in ("brute", "credential", "password", "kerberos", "ntlm")):
        recs.append("Reset credentials for all accounts active on affected agents.")
        recs.append("Enable MFA if not already enforced.")

    if any(k in x for x in t for k in ("lateral", "remote services", "pass-the")):
        recs.append("Review SMB/RDP/WinRM connections from affected agents to peer systems.")

    if any(k in x for x in t for k in ("persist", "scheduled", "registry", "autostart", "boot")):
        recs.append("Audit startup items, scheduled tasks, and registry run keys on affected agents.")

    if any(k in x for x in t for k in ("exfiltrat", "data staged", "collection")):
        recs.append("Review outbound connections and data transfer volumes from affected agents.")
        recs.append("Check for large file transfers or unusual upload activity to external hosts.")

    if any(k in x for x in t for k in ("inject", "escalat", "token")):
        recs.append("Review running processes for injected code or unexpected privilege elevation.")

    if any(k in x for x in t for k in ("defense evasion", "impair", "indicator removal")):
        recs.append("Check for disabled logging, cleared event logs, or modified security tools.")

    if src_ips:
        recs.append(f"Block source IPs via CDB list or firewall: {', '.join(src_ips[:5])}")

    if not recs:
        recs.append("Review alerts manually and escalate if activity continues.")

    return recs
