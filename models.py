"""
PacketStrike - Data Models
models.py - Pydantic schemas for all internal data structures

Author  : Rayyan Umair
Date    : 2026-05-13
Purpose : Canonical data models for PacketStrike. Every layer of the
          pipeline communicates exclusively through these schemas.
          No raw dicts. No ad-hoc structures. No exceptions.
          If data moves between layers, it is one of these models.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/PacketStrike

"Silence the noise, strike the signal."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

# ── Third Party ───────────────────────────────────────────────────────────────
from pydantic import BaseModel, Field, field_validator


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    """Always return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)

def _new_uuid() -> str:
    return str(uuid.uuid4())


# ── Enumerations ──────────────────────────────────────────────────────────────

class Protocol(str, Enum):
    TCP      = "TCP"
    UDP      = "UDP"
    ICMP     = "ICMP"
    DNS      = "DNS"
    HTTP     = "HTTP"
    HTTPS    = "HTTPS"
    FTP      = "FTP"
    SMTP     = "SMTP"
    OTHER    = "OTHER"
    UNKNOWN  = "UNKNOWN"


class StrikeType(str, Enum):
    PORT_SCAN       = "STRIKE-001"   # Systematic port sweep
    BEACONING       = "STRIKE-002"   # Regular C2-style intervals
    HIGH_OUTBOUND   = "STRIKE-003"   # Exfiltration volume threshold
    INTERNAL_PIVOT  = "STRIKE-004"   # Lateral movement across hosts
    KNOWN_BAD       = "STRIKE-005"   # Threat intel IOC match


class Severity(int, Enum):
    INFO     = 1
    LOW      = 3
    MEDIUM   = 5
    HIGH     = 7
    CRITICAL = 10


class BehaviorFlag(str, Enum):
    BEACONING      = "beaconing"
    PORT_SCAN      = "port_scan"
    INTERNAL_PIVOT = "internal_pivot"
    DATA_EXFIL     = "data_exfil"
    KNOWN_BAD_IP   = "known_bad_ip"
    DLP_HIT        = "dlp_hit"
    HIGH_ENTROPY   = "high_entropy"
    PROTOCOL_ANOMALY = "protocol_anomaly"


class CaptureMode(str, Enum):
    LIVE   = "live"
    REPLAY = "replay"


# ── DPI Sub-Models ────────────────────────────────────────────────────────────

class DLPHit(BaseModel):
    """A single cleartext sensitivity match found in a payload."""

    pattern_name : str            = Field(..., description="Human-readable name of the DLP rule that fired")
    matched_value: str            = Field(..., description="The redacted or truncated matched string")
    hex_offset   : int            = Field(..., description="Byte offset within the payload where match was found")
    regex_pattern: str            = Field(..., description="The regex pattern that produced this hit")


class DPIResult(BaseModel):
    """
    Output of the Deep Packet Inspection layer for a single flow.
    Attached to every FlowRecord before storage.
    """

    entropy_score       : float            = Field(default=0.0,   description="Shannon entropy of the inspected payload (0.0–8.0)")
    entropy_flagged     : bool             = Field(default=False,  description="True if entropy_score exceeds configured threshold")
    dlp_hits            : List[DLPHit]    = Field(default_factory=list, description="All DLP pattern matches found in this flow")
    protocol_anomaly    : bool             = Field(default=False,  description="True if traffic violates RFC expectations for its protocol/port")
    anomaly_reason      : Optional[str]   = Field(default=None,   description="Human-readable explanation of the protocol anomaly")
    dissected_protocol  : Protocol         = Field(default=Protocol.UNKNOWN, description="Protocol identified by the dissector (may differ from port-based guess)")
    os_fingerprint      : Optional[str]   = Field(default=None,   description="OS guess derived from TTL and TCP window size analysis")
    inspected_bytes     : int             = Field(default=0,       description="Number of payload bytes actually inspected by DPI")


# ── Strike Model ──────────────────────────────────────────────────────────────

class StrikeEvent(BaseModel):
    """
    A confirmed detection produced by the Strike Engine.
    One StrikeEvent is generated per detection firing.
    """

    strike_id      : str            = Field(default_factory=_new_uuid, description="Unique strike identifier")
    strike_type    : StrikeType     = Field(..., description="Which detection fired")
    severity       : Severity       = Field(..., description="Severity level of this strike")
    timestamp      : datetime       = Field(default_factory=_now_utc,  description="UTC time the strike was generated")

    # ── Source context ────────────────────────────────────────────────────────
    src_ip         : str            = Field(..., description="Source IP address that triggered the strike")
    dst_ip         : Optional[str]  = Field(default=None, description="Destination IP if applicable")
    dst_port       : Optional[int]  = Field(default=None, description="Destination port if applicable")
    protocol       : Protocol       = Field(default=Protocol.UNKNOWN)
    interface      : str            = Field(default="unknown", description="Network interface the traffic was observed on")

    # ── 5W+H Tactical Intelligence ────────────────────────────────────────────
    who            : str            = Field(..., description="WHO: Source identity - IP + OS fingerprint")
    what           : str            = Field(..., description="WHAT: What was detected and what protocol/payload evidence exists")
    where          : str            = Field(..., description="WHERE: Interface, VLAN, internal vs external classification")
    when           : str            = Field(..., description="WHEN: Timestamp + delta-T within the stream")
    why            : str            = Field(..., description="WHY: The specific evidence that triggered this strike (hex offset, pattern, interval)")
    how            : str            = Field(..., description="HOW: Recommended analyst action or STRIKE-REPLAY instruction")

    # ── Evidence ──────────────────────────────────────────────────────────────
    hex_offset     : Optional[int]  = Field(default=None, description="Byte offset of the triggering evidence in the payload")
    evidence_summary: str           = Field(default="", description="One-line machine-readable summary of the triggering evidence")
    related_flow_ids: List[str]     = Field(default_factory=list, description="Flow IDs that contributed to this strike")

    # ── AI Enrichment (optional) ──────────────────────────────────────────────
    ai_explanation : Optional[str]  = Field(default=None, description="AI-generated plain-English explanation of this strike")


# ── Flow Record ───────────────────────────────────────────────────────────────

class FlowRecord(BaseModel):
    """
    The universal unit of data in PacketStrike.
    Every captured session is normalized into a FlowRecord before
    any analysis, storage, or entity enrichment occurs.

    Raw packet structures must never leak beyond the capture layer.
    """

    flow_id        : str            = Field(default_factory=_new_uuid, description="Unique flow identifier")
    timestamp      : datetime       = Field(default_factory=_now_utc,  description="UTC time this flow was first observed")
    interface      : str            = Field(..., description="Network interface the flow was captured on")
    vlan_id        : Optional[int]  = Field(default=None, description="VLAN tag ID if present - critical for VLAN hopping detection")

    # ── Network Layer ─────────────────────────────────────────────────────────
    src_ip         : str            = Field(..., description="Source IP address")
    dst_ip         : str            = Field(..., description="Destination IP address")
    src_port       : Optional[int]  = Field(default=None, description="Source port (TCP/UDP only)")
    dst_port       : Optional[int]  = Field(default=None, description="Destination port (TCP/UDP only)")
    protocol       : Protocol       = Field(default=Protocol.UNKNOWN)
    ttl            : Optional[int]  = Field(default=None, description="IP TTL value - used for OS fingerprinting")
    tcp_window_size: Optional[int]  = Field(default=None, description="TCP window size - used for OS fingerprinting")

    # ── Volume & Timing ───────────────────────────────────────────────────────
    bytes_sent     : int            = Field(default=0, description="Bytes sent from src → dst")
    bytes_received : int            = Field(default=0, description="Bytes received from dst → src")
    packets_sent   : int            = Field(default=0, description="Packet count from src → dst")
    packets_received: int           = Field(default=0, description="Packet count from dst → src")
    start_time     : datetime       = Field(default_factory=_now_utc, description="UTC session start")
    end_time       : Optional[datetime] = Field(default=None,         description="UTC session end - None if session still open")
    duration_ms    : Optional[float]= Field(default=None,             description="Session duration in milliseconds")
    delta_t_ms     : Optional[float]= Field(default=None,             description="Time since previous packet in this TCP stream (milliseconds)")

    # ── DPI Results ───────────────────────────────────────────────────────────
    dpi            : DPIResult      = Field(default_factory=DPIResult, description="Deep packet inspection output for this flow")

    # ── Strike Reference ──────────────────────────────────────────────────────
    strike_triggered: bool          = Field(default=False, description="True if this flow contributed to a StrikeEvent")
    strike_ids     : List[str]      = Field(default_factory=list, description="IDs of strikes this flow contributed to")

    # ── Raw Payload ───────────────────────────────────────────────────────────
    raw_payload    : Optional[str]  = Field(default=None, description="Base64-encoded raw payload bytes - preserved for STRIKE-REPLAY forensics")

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received

    @property
    def is_internal_src(self) -> bool:
        """Quick check - full subnet logic lives in the entity engine."""
        return self.src_ip.startswith(("10.", "172.16.", "192.168."))

    @property
    def is_internal_dst(self) -> bool:
        return self.dst_ip.startswith(("10.", "172.16.", "192.168."))


# ── Entity Models ─────────────────────────────────────────────────────────────

class TimelineEvent(BaseModel):
    """A single entry in an entity's behavior timeline."""

    timestamp    : datetime     = Field(default_factory=_now_utc)
    event_type   : str          = Field(..., description="Short label: 'strike', 'flow', 'dlp_hit', etc.")
    description  : str          = Field(..., description="Human-readable timeline entry")
    strike_id    : Optional[str]= Field(default=None, description="Strike ID if this event is a strike")
    flow_id      : Optional[str]= Field(default=None, description="Flow ID that produced this event")
    severity     : int          = Field(default=0,    description="Severity 0–10 for timeline rendering")


class IPEntity(BaseModel):
    """
    A tracked IP address in the PacketStrike entity engine.
    Entities are living objects - they accumulate history, flags, and risk
    across multiple flows over time.

    # NetRaptor integration hook:
    # When shared entity engine is built, IPEntity maps directly to the
    # universal EntityProfile. Field names are intentionally compatible.
    """

    entity_id      : str                = Field(default_factory=_new_uuid)
    ip_address     : str                = Field(..., description="The IP address this entity represents")
    first_seen     : datetime           = Field(default_factory=_now_utc)
    last_seen      : datetime           = Field(default_factory=_now_utc)

    # ── Behavior Flags ────────────────────────────────────────────────────────
    flags          : List[BehaviorFlag] = Field(default_factory=list, description="Active behavior flags on this entity")

    # ── Traffic Statistics ────────────────────────────────────────────────────
    total_flows    : int                = Field(default=0)
    total_bytes_out: int                = Field(default=0)
    total_bytes_in : int                = Field(default=0)
    unique_dst_ips : List[str]          = Field(default_factory=list, description="Distinct destination IPs contacted")
    unique_dst_ports: List[int]         = Field(default_factory=list, description="Distinct destination ports contacted")

    # ── Fingerprinting ────────────────────────────────────────────────────────
    os_fingerprint : Optional[str]      = Field(default=None, description="Best OS guess from TTL/window analysis")
    ttl_observed   : Optional[int]      = Field(default=None)

    # ── Risk ──────────────────────────────────────────────────────────────────
    risk_score     : float              = Field(default=0.0, description="Current risk score 0.0–10.0")
    strike_count   : int                = Field(default=0,   description="Total strikes this entity has triggered")

    # ── Timeline ──────────────────────────────────────────────────────────────
    timeline       : List[TimelineEvent]= Field(default_factory=list, description="Chronological behavior timeline")

    @property
    def is_internal(self) -> bool:
        return self.ip_address.startswith(("10.", "172.16.", "192.168."))

    @property
    def is_high_risk(self) -> bool:
        return self.risk_score >= 7.0


# ── API Response Models ───────────────────────────────────────────────────────

class StrikeSummary(BaseModel):
    """Lightweight strike representation for API list endpoints."""

    strike_id   : str       = Field(...)
    strike_type : StrikeType= Field(...)
    severity    : Severity  = Field(...)
    timestamp   : datetime  = Field(...)
    src_ip      : str       = Field(...)
    dst_ip      : Optional[str] = Field(default=None)
    what        : str       = Field(...)
    why         : str       = Field(...)


class EntitySummary(BaseModel):
    """Lightweight entity representation for API list endpoints."""

    entity_id   : str               = Field(...)
    ip_address  : str               = Field(...)
    risk_score  : float             = Field(...)
    strike_count: int               = Field(...)
    flags       : List[BehaviorFlag]= Field(...)
    last_seen   : datetime          = Field(...)
    os_fingerprint: Optional[str]   = Field(default=None)


class HealthResponse(BaseModel):
    """API health check response."""

    status      : str   = Field(default="ok")
    app_name    : str   = Field(...)
    version     : str   = Field(...)
    capture_mode: str   = Field(...)
    interface   : str   = Field(...)
    ai_enabled  : bool  = Field(...)
    uptime_seconds: float = Field(...)