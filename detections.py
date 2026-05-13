"""
PacketStrike — Strike Detection Engine
detections.py — The five core behavioral detections

Author  : Rayyan Umair
Date    : 2026-05-13
Purpose : Implements the five PacketStrike strike detections. Each
          detection operates on the entity state and recent flow history
          maintained by the entity engine. Detections are stateless
          functions — they receive context and return a StrikeEvent or
          None. No storage. No entity mutation. No side effects.
          The entity engine calls these after every flow is processed.

          STRIKE-001 — Port Scan
          STRIKE-002 — Beaconing
          STRIKE-003 — High Outbound Transfer
          STRIKE-004 — Internal Pivot
          STRIKE-005 — Known-Bad Destination

Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/PacketStrike

"Silence the noise, strike the signal."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import logging
import statistics
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set, Tuple

# ── Internal ──────────────────────────────────────────────────────────────────
from config import Settings
from models import (
    BehaviorFlag,
    FlowRecord,
    IPEntity,
    Protocol,
    Severity,
    StrikeEvent,
    StrikeType,
)

logger = logging.getLogger(__name__)


# ── Cooldown Tracker ──────────────────────────────────────────────────────────

class CooldownTracker:
    """
    Prevents the same strike type firing repeatedly on the same source IP
    within the cooldown window. One instance is shared across all detections.

    Key format: "{src_ip}:{strike_type}"
    """

    def __init__(self, cooldown_seconds: int) -> None:
        self._cooldown = timedelta(seconds=cooldown_seconds)
        self._last_fired: Dict[str, datetime] = {}

    def is_cooling_down(self, src_ip: str, strike_type: StrikeType) -> bool:
        key = f"{src_ip}:{strike_type.value}"
        last = self._last_fired.get(key)
        if last is None:
            return False
        return (datetime.now(timezone.utc) - last) < self._cooldown

    def record(self, src_ip: str, strike_type: StrikeType) -> None:
        key = f"{src_ip}:{strike_type.value}"
        self._last_fired[key] = datetime.now(timezone.utc)

    def clear(self, src_ip: str, strike_type: StrikeType) -> None:
        key = f"{src_ip}:{strike_type.value}"
        self._last_fired.pop(key, None)


# ── Threat Intel Store ────────────────────────────────────────────────────────

class ThreatIntelStore:
    """
    In-memory store of known-bad IPs and domains loaded from the flat-file
    threat intel feed. Reloaded on a configurable interval by the entity engine.

    File format: one IP address or domain per line. Lines starting with
    '#' are treated as comments and ignored.
    """

    def __init__(self, feed_path: str) -> None:
        self._feed_path  = feed_path
        self._bad_ips    : Set[str] = set()
        self._bad_domains: Set[str] = set()
        self._loaded_at  : Optional[datetime] = None
        self._entry_count = 0

    def load(self) -> None:
        """Load or reload the threat intel feed from disk."""
        import ipaddress
        from pathlib import Path

        path = Path(self._feed_path)
        if not path.exists():
            logger.warning(
                f"Threat intel feed not found at {self._feed_path}. "
                f"STRIKE-005 will not fire until the file exists."
            )
            return

        bad_ips: Set[str] = set()
        bad_domains: Set[str] = set()

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                entry = line.strip()
                if not entry or entry.startswith("#"):
                    continue
                try:
                    ipaddress.ip_address(entry)
                    bad_ips.add(entry)
                except ValueError:
                    # Not an IP — treat as domain
                    bad_domains.add(entry.lower())

        self._bad_ips     = bad_ips
        self._bad_domains = bad_domains
        self._loaded_at   = datetime.now(timezone.utc)
        self._entry_count = len(bad_ips) + len(bad_domains)

        logger.info(
            f"Threat intel loaded: {len(bad_ips)} IPs, "
            f"{len(bad_domains)} domains from {self._feed_path}"
        )

    def is_bad_ip(self, ip: str) -> bool:
        return ip in self._bad_ips

    def is_bad_domain(self, domain: str) -> bool:
        return domain.lower() in self._bad_domains

    @property
    def stats(self) -> dict:
        return {
            "bad_ips"     : len(self._bad_ips),
            "bad_domains" : len(self._bad_domains),
            "loaded_at"   : self._loaded_at.isoformat() if self._loaded_at else None,
            "entry_count" : self._entry_count,
        }


# ── Strike Builders ───────────────────────────────────────────────────────────

def _build_strike(
    strike_type    : StrikeType,
    severity       : Severity,
    flow           : FlowRecord,
    entity         : IPEntity,
    who            : str,
    what           : str,
    where          : str,
    when           : str,
    why            : str,
    how            : str,
    hex_offset     : Optional[int]  = None,
    evidence       : str            = "",
    related_flows  : Optional[List[str]] = None,
) -> StrikeEvent:
    """Construct a StrikeEvent from detection context."""
    return StrikeEvent(
        strike_type      = strike_type,
        severity         = severity,
        src_ip           = flow.src_ip,
        dst_ip           = flow.dst_ip,
        dst_port         = flow.dst_port,
        protocol         = flow.protocol,
        interface        = flow.interface,
        who              = who,
        what             = what,
        where            = where,
        when             = when,
        why              = why,
        how              = how,
        hex_offset       = hex_offset,
        evidence_summary = evidence,
        related_flow_ids = related_flows or [flow.flow_id],
    )


def _format_when(flow: FlowRecord) -> str:
    ts = flow.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    if flow.delta_t_ms is not None:
        return f"{ts} (Δt {flow.delta_t_ms:.1f}ms since last packet in stream)"
    return ts


def _classify_zone(ip: str) -> str:
    if ip.startswith(("10.", "172.16.", "192.168.")):
        return "INTERNAL"
    return "EXTERNAL"


# ── STRIKE-001 — Port Scan ────────────────────────────────────────────────────

def detect_port_scan(
    flow    : FlowRecord,
    entity  : IPEntity,
    settings: Settings,
    cooldown: CooldownTracker,
) -> Optional[StrikeEvent]:
    """
    STRIKE-001 — Port Scan

    Fires when a single source IP contacts more distinct destination ports
    than port_scan_threshold within the detection window.

    Indicator of:
      - Reconnaissance sweep
      - Automated vulnerability scanner
      - Worm propagation
    """
    if cooldown.is_cooling_down(flow.src_ip, StrikeType.PORT_SCAN):
        return None

    unique_ports = len(set(entity.unique_dst_ports))
    if unique_ports < settings.port_scan_threshold:
        return None

    cooldown.record(flow.src_ip, StrikeType.PORT_SCAN)

    top_ports = sorted(entity.unique_dst_ports)[:10]
    port_list = ", ".join(str(p) for p in top_ports)
    extra     = f" (+{unique_ports - 10} more)" if unique_ports > 10 else ""

    os_hint = f" [{entity.os_fingerprint}]" if entity.os_fingerprint else ""
    zone    = _classify_zone(flow.src_ip)

    logger.info(f"STRIKE-001 PORT_SCAN {flow.src_ip} → {unique_ports} ports")

    return _build_strike(
        strike_type = StrikeType.PORT_SCAN,
        severity    = Severity.HIGH,
        flow        = flow,
        entity      = entity,
        who  = f"{flow.src_ip}{os_hint} [{zone}]",
        what = (
            f"Port scan detected — {unique_ports} distinct destination ports "
            f"contacted within the {settings.detection_window_seconds}s window. "
            f"Sample ports: {port_list}{extra}."
        ),
        where = (
            f"Interface {flow.interface} | "
            f"Source zone: {zone} | "
            f"VLAN: {flow.vlan_id or 'untagged'}"
        ),
        when  = _format_when(flow),
        why   = (
            f"Threshold exceeded: {unique_ports} ports contacted "
            f"(limit: {settings.port_scan_threshold}). "
            f"Systematic multi-port contact pattern is consistent with reconnaissance."
        ),
        how   = (
            f"Isolate {flow.src_ip} at the perimeter. "
            f"Review firewall logs for the full port sweep. "
            f"Cross-reference with SIEMulate for authentication attempts post-scan."
        ),
        evidence = f"port_scan:{flow.src_ip}:{unique_ports}_ports",
    )


# ── STRIKE-002 — Beaconing ────────────────────────────────────────────────────

def detect_beaconing(
    flow             : FlowRecord,
    entity           : IPEntity,
    recent_intervals : List[float],
    settings         : Settings,
    cooldown         : CooldownTracker,
) -> Optional[StrikeEvent]:
    """
    STRIKE-002 — Beaconing

    Fires when outbound connection intervals from a source IP to a single
    destination are suspiciously regular — low coefficient of variation
    across at least beaconing_min_intervals samples.

    Indicator of:
      - C2 malware check-in
      - Implant heartbeat
      - Automated data staging
    """
    if cooldown.is_cooling_down(flow.src_ip, StrikeType.BEACONING):
        return None

    if len(recent_intervals) < settings.beaconing_min_intervals:
        return None

    mean     = statistics.mean(recent_intervals)
    if mean == 0:
        return None

    stdev    = statistics.stdev(recent_intervals) if len(recent_intervals) > 1 else 0.0
    cv       = stdev / mean          # Coefficient of variation

    if cv > settings.beaconing_jitter_tolerance:
        return None                  # Too irregular to be beaconing

    cooldown.record(flow.src_ip, StrikeType.BEACONING)

    interval_s = mean / 1000         # ms → seconds
    jitter_ms  = stdev

    zone    = _classify_zone(flow.src_ip)
    dst_zone = _classify_zone(flow.dst_ip or "0.0.0.0")
    os_hint = f" [{entity.os_fingerprint}]" if entity.os_fingerprint else ""

    logger.info(
        f"STRIKE-002 BEACONING {flow.src_ip} → {flow.dst_ip} "
        f"interval={interval_s:.1f}s jitter={jitter_ms:.1f}ms CV={cv:.3f}"
    )

    return _build_strike(
        strike_type = StrikeType.BEACONING,
        severity    = Severity.CRITICAL,
        flow        = flow,
        entity      = entity,
        who  = f"{flow.src_ip}{os_hint} [{zone}]",
        what = (
            f"Beaconing behaviour detected — {len(recent_intervals)} outbound "
            f"connections to {flow.dst_ip} [{dst_zone}] at a suspiciously regular "
            f"interval of {interval_s:.1f}s (±{jitter_ms:.1f}ms jitter). "
            f"Consistent with C2 malware heartbeat."
        ),
        where = (
            f"Interface {flow.interface} | "
            f"Source: {flow.src_ip} [{zone}] → "
            f"Destination: {flow.dst_ip} [{dst_zone}] | "
            f"VLAN: {flow.vlan_id or 'untagged'}"
        ),
        when  = _format_when(flow),
        why   = (
            f"Coefficient of variation ({cv:.3f}) is below jitter tolerance "
            f"({settings.beaconing_jitter_tolerance}). "
            f"Mean interval: {interval_s:.2f}s over {len(recent_intervals)} samples. "
            f"Natural human traffic does not exhibit this regularity."
        ),
        how   = (
            f"Immediately inspect process list on {flow.src_ip} for unknown "
            f"network-connected processes. Block {flow.dst_ip} at perimeter. "
            f"Capture full session for malware analysis. "
            f"Use STRIKE-REPLAY to reconstruct the beacon sequence."
        ),
        evidence = (
            f"beaconing:{flow.src_ip}→{flow.dst_ip}:"
            f"interval={interval_s:.1f}s:cv={cv:.3f}"
        ),
    )


# ── STRIKE-003 — High Outbound Transfer ───────────────────────────────────────

def detect_high_outbound(
    flow    : FlowRecord,
    entity  : IPEntity,
    settings: Settings,
    cooldown: CooldownTracker,
) -> Optional[StrikeEvent]:
    """
    STRIKE-003 — High Outbound Transfer

    Fires when a single session's outbound byte count exceeds the
    exfiltration_threshold_bytes setting.

    Indicator of:
      - Data exfiltration
      - Bulk upload to external host
      - Staging before ransomware deployment
    """
    if cooldown.is_cooling_down(flow.src_ip, StrikeType.HIGH_OUTBOUND):
        return None

    if flow.bytes_sent < settings.exfiltration_threshold_bytes:
        return None

    cooldown.record(flow.src_ip, StrikeType.HIGH_OUTBOUND)

    mb_sent  = flow.bytes_sent / (1024 * 1024)
    threshold_mb = settings.exfiltration_threshold_bytes / (1024 * 1024)
    zone     = _classify_zone(flow.src_ip)
    dst_zone = _classify_zone(flow.dst_ip)
    os_hint  = f" [{entity.os_fingerprint}]" if entity.os_fingerprint else ""

    duration_s = (flow.duration_ms or 0) / 1000
    rate_mbps  = (mb_sent / duration_s) if duration_s > 0 else 0.0

    logger.info(
        f"STRIKE-003 HIGH_OUTBOUND {flow.src_ip} → {flow.dst_ip} "
        f"{mb_sent:.1f} MB"
    )

    return _build_strike(
        strike_type = StrikeType.HIGH_OUTBOUND,
        severity    = Severity.CRITICAL,
        flow        = flow,
        entity      = entity,
        who  = f"{flow.src_ip}{os_hint} [{zone}]",
        what = (
            f"High outbound transfer detected — {mb_sent:.1f} MB sent from "
            f"{flow.src_ip} [{zone}] to {flow.dst_ip} [{dst_zone}] "
            f"on port {flow.dst_port} ({flow.dpi.dissected_protocol.value}). "
            f"Transfer rate: {rate_mbps:.2f} MB/s."
        ),
        where = (
            f"Interface {flow.interface} | "
            f"Source: {flow.src_ip} [{zone}] → "
            f"Destination: {flow.dst_ip} [{dst_zone}] "
            f"port {flow.dst_port} | "
            f"VLAN: {flow.vlan_id or 'untagged'}"
        ),
        when  = _format_when(flow),
        why   = (
            f"Session outbound volume ({mb_sent:.1f} MB) exceeded exfiltration "
            f"threshold ({threshold_mb:.0f} MB). "
            f"Destination is {dst_zone}. "
            f"DLP hits on this flow: {len(flow.dpi.dlp_hits)}."
        ),
        how   = (
            f"Block the session at {flow.interface} immediately if still active. "
            f"Identify the process responsible on {flow.src_ip}. "
            f"Determine what data was transferred — check DLP hits on this flow. "
            f"Use STRIKE-REPLAY to reconstruct the full transfer."
        ),
        evidence = (
            f"high_outbound:{flow.src_ip}→{flow.dst_ip}:"
            f"{mb_sent:.1f}MB:port={flow.dst_port}"
        ),
    )


# ── STRIKE-004 — Internal Pivot ───────────────────────────────────────────────

def detect_internal_pivot(
    flow    : FlowRecord,
    entity  : IPEntity,
    settings: Settings,
    cooldown: CooldownTracker,
) -> Optional[StrikeEvent]:
    """
    STRIKE-004 — Internal Pivot

    Fires when a source IP contacts more distinct internal destination
    hosts than pivot_host_threshold within the detection window.

    Indicator of:
      - Lateral movement
      - Post-exploitation host enumeration
      - Worm propagation across internal segments
    """
    if cooldown.is_cooling_down(flow.src_ip, StrikeType.INTERNAL_PIVOT):
        return None

    # Count only internal destinations
    internal_dsts = [
        ip for ip in entity.unique_dst_ips
        if ip.startswith(("10.", "172.16.", "192.168."))
    ]
    unique_internal = len(set(internal_dsts))

    if unique_internal < settings.pivot_host_threshold:
        return None

    cooldown.record(flow.src_ip, StrikeType.INTERNAL_PIVOT)

    zone    = _classify_zone(flow.src_ip)
    os_hint = f" [{entity.os_fingerprint}]" if entity.os_fingerprint else ""

    sample_hosts = list(set(internal_dsts))[:5]
    host_list    = ", ".join(sample_hosts)
    extra        = f" (+{unique_internal - 5} more)" if unique_internal > 5 else ""

    logger.info(
        f"STRIKE-004 INTERNAL_PIVOT {flow.src_ip} → "
        f"{unique_internal} internal hosts"
    )

    return _build_strike(
        strike_type = StrikeType.INTERNAL_PIVOT,
        severity    = Severity.CRITICAL,
        flow        = flow,
        entity      = entity,
        who  = f"{flow.src_ip}{os_hint} [{zone}]",
        what = (
            f"Internal pivot detected — {flow.src_ip} [{zone}] contacted "
            f"{unique_internal} distinct internal hosts within the "
            f"{settings.detection_window_seconds}s detection window. "
            f"Sample targets: {host_list}{extra}."
        ),
        where = (
            f"Interface {flow.interface} | "
            f"Pivoting host: {flow.src_ip} [{zone}] | "
            f"Internal targets: {unique_internal} hosts | "
            f"VLAN: {flow.vlan_id or 'untagged'}"
        ),
        when  = _format_when(flow),
        why   = (
            f"Internal destination count ({unique_internal}) exceeded pivot "
            f"threshold ({settings.pivot_host_threshold}). "
            f"A single host contacting this many internal targets in a short "
            f"window is consistent with lateral movement or host enumeration."
        ),
        how   = (
            f"Isolate {flow.src_ip} from the internal network immediately. "
            f"Review authentication logs for each targeted host. "
            f"Cross-reference with SIEMulate for privilege escalation events. "
            f"Treat all {unique_internal} contacted hosts as potentially compromised."
        ),
        evidence = (
            f"internal_pivot:{flow.src_ip}:"
            f"{unique_internal}_internal_hosts"
        ),
    )


# ── STRIKE-005 — Known-Bad Destination ────────────────────────────────────────

def detect_known_bad(
    flow    : FlowRecord,
    entity  : IPEntity,
    intel   : ThreatIntelStore,
    cooldown: CooldownTracker,
) -> Optional[StrikeEvent]:
    """
    STRIKE-005 — Known-Bad Destination

    Fires immediately when a destination IP matches the threat intel feed.
    No threshold. No window. Zero tolerance.

    Indicator of:
      - Active C2 communication
      - Malware download attempt
      - Known malicious infrastructure contact
    """
    if not flow.dst_ip:
        return None

    if cooldown.is_cooling_down(flow.src_ip, StrikeType.KNOWN_BAD):
        return None

    if not intel.is_bad_ip(flow.dst_ip):
        return None

    cooldown.record(flow.src_ip, StrikeType.KNOWN_BAD)

    zone     = _classify_zone(flow.src_ip)
    dst_zone = _classify_zone(flow.dst_ip)
    os_hint  = f" [{entity.os_fingerprint}]" if entity.os_fingerprint else ""

    logger.warning(
        f"STRIKE-005 KNOWN_BAD {flow.src_ip} → {flow.dst_ip} "
        f"[THREAT INTEL MATCH]"
    )

    return _build_strike(
        strike_type = StrikeType.KNOWN_BAD,
        severity    = Severity.CRITICAL,
        flow        = flow,
        entity      = entity,
        who  = f"{flow.src_ip}{os_hint} [{zone}]",
        what = (
            f"Known-bad destination contacted — {flow.src_ip} [{zone}] "
            f"established a {flow.protocol.value} connection to {flow.dst_ip} "
            f"[{dst_zone}] port {flow.dst_port}, which is listed in the "
            f"active threat intelligence feed."
        ),
        where = (
            f"Interface {flow.interface} | "
            f"Source: {flow.src_ip} [{zone}] → "
            f"Destination: {flow.dst_ip} [{dst_zone}] "
            f"port {flow.dst_port} | "
            f"VLAN: {flow.vlan_id or 'untagged'}"
        ),
        when  = _format_when(flow),
        why   = (
            f"Destination IP {flow.dst_ip} matched the threat intelligence feed "
            f"({intel.stats['entry_count']} entries loaded). "
            f"Zero-tolerance policy — no threshold required."
        ),
        how   = (
            f"Block {flow.dst_ip} at the perimeter firewall immediately. "
            f"Isolate {flow.src_ip} for forensic investigation. "
            f"Assume {flow.src_ip} is compromised until proven otherwise. "
            f"Use STRIKE-REPLAY to analyse the full session content."
        ),
        evidence = f"known_bad:{flow.src_ip}→{flow.dst_ip}:intel_match",
    )


# ── Detection Runner ──────────────────────────────────────────────────────────

class DetectionEngine:
    """
    Orchestrates all five strike detections.

    Called by the entity engine after every flow is processed and the
    entity state is updated. Passes the enriched flow and current entity
    state to each detection function and collects any strikes fired.

    Usage:
        engine = DetectionEngine(settings)
        engine.intel.load()
        strikes = engine.run(flow, entity, beacon_intervals)
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self.cooldown  = CooldownTracker(settings.strike_cooldown_seconds)
        self.intel     = ThreatIntelStore(settings.threat_intel_path)
        self._total_strikes = 0

    def run(
        self,
        flow             : FlowRecord,
        entity           : IPEntity,
        beacon_intervals : List[float],
    ) -> List[StrikeEvent]:
        """
        Run all five detections against the current flow and entity state.
        Returns a list of StrikeEvents (empty if nothing fired).
        """
        strikes: List[StrikeEvent] = []

        # ── STRIKE-001 ────────────────────────────────────────────────────────
        s = detect_port_scan(flow, entity, self._settings, self.cooldown)
        if s:
            strikes.append(s)

        # ── STRIKE-002 ────────────────────────────────────────────────────────
        s = detect_beaconing(
            flow, entity, beacon_intervals, self._settings, self.cooldown
        )
        if s:
            strikes.append(s)

        # ── STRIKE-003 ────────────────────────────────────────────────────────
        s = detect_high_outbound(flow, entity, self._settings, self.cooldown)
        if s:
            strikes.append(s)

        # ── STRIKE-004 ────────────────────────────────────────────────────────
        s = detect_internal_pivot(flow, entity, self._settings, self.cooldown)
        if s:
            strikes.append(s)

        # ── STRIKE-005 ────────────────────────────────────────────────────────
        s = detect_known_bad(flow, entity, self.intel, self.cooldown)
        if s:
            strikes.append(s)

        self._total_strikes += len(strikes)
        return strikes

    @property
    def stats(self) -> dict:
        return {
            "total_strikes_fired" : self._total_strikes,
            "intel"               : self.intel.stats,
        }