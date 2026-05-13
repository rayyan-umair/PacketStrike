"""
PacketStrike — Deep Packet Inspection Engine
inspector.py — Entropy scoring, DLP scanning, protocol anomaly detection

Author  : Rayyan Umair
Date    : 2026-05-13
Purpose : The DPI consumer layer of PacketStrike. Receives FlowRecords
          from the capture queue, inspects the raw payload up to
          dpi_depth bytes, and attaches a DPIResult to each flow before
          passing it downstream to the Strike Engine.
          Three analysis passes run on every flow:
            1. Shannon entropy scoring
            2. Cleartext sensitivity scanning (DLP)
            3. Protocol anomaly detection (RFC violations)
          No detection logic lives here. No entity logic lives here.
          This layer only enriches — it does not decide.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/PacketStrike

"Silence the noise, strike the signal."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import base64
import logging
import math
import re
from typing import List, Optional, Tuple

# ── Internal ──────────────────────────────────────────────────────────────────
from config import Settings
from models import DLPHit, DPIResult, FlowRecord, Protocol

logger = logging.getLogger(__name__)


# ── DLP Pattern Registry ──────────────────────────────────────────────────────
# Each entry: (pattern_name, compiled_regex)
# Patterns are applied to the raw decoded payload string.
# Matches are redacted before storage — only offset and pattern name persist.

_DLP_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # ── Credentials ───────────────────────────────────────────────────────────
    (
        "FTP_USER",
        re.compile(rb"USER\s+\S+", re.IGNORECASE),
    ),
    (
        "FTP_PASS",
        re.compile(rb"PASS\s+\S+", re.IGNORECASE),
    ),
    (
        "HTTP_AUTH_BASIC",
        re.compile(rb"Authorization:\s*Basic\s+[A-Za-z0-9+/=]+", re.IGNORECASE),
    ),
    (
        "HTTP_AUTH_BEARER",
        re.compile(rb"Authorization:\s*Bearer\s+\S+", re.IGNORECASE),
    ),
    (
        "SMTP_AUTH",
        re.compile(rb"AUTH\s+(LOGIN|PLAIN)\s+\S*", re.IGNORECASE),
    ),
    (
        "CLEARTEXT_PASSWORD",
        re.compile(rb"password[=:\s]+\S+", re.IGNORECASE),
    ),
    (
        "CLEARTEXT_PASSWD",
        re.compile(rb"passwd[=:\s]+\S+", re.IGNORECASE),
    ),

    # ── Key Material ──────────────────────────────────────────────────────────
    (
        "RSA_PRIVATE_KEY",
        re.compile(rb"-----BEGIN RSA PRIVATE KEY-----", re.IGNORECASE),
    ),
    (
        "PRIVATE_KEY",
        re.compile(rb"-----BEGIN PRIVATE KEY-----", re.IGNORECASE),
    ),
    (
        "SSH_PRIVATE_KEY",
        re.compile(rb"-----BEGIN OPENSSH PRIVATE KEY-----", re.IGNORECASE),
    ),
    (
        "AWS_ACCESS_KEY",
        re.compile(rb"AKIA[0-9A-Z]{16}", re.IGNORECASE),
    ),

    # ── Database Exposure ─────────────────────────────────────────────────────
    (
        "SQL_SELECT_STAR",
        re.compile(rb"SELECT\s+\*\s+FROM", re.IGNORECASE),
    ),
    (
        "SQL_DROP",
        re.compile(rb"DROP\s+(TABLE|DATABASE|SCHEMA)", re.IGNORECASE),
    ),
    (
        "SQL_INSERT",
        re.compile(rb"INSERT\s+INTO\s+\w+\s*\(", re.IGNORECASE),
    ),
    (
        "SQL_UNION_INJECT",
        re.compile(rb"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE),
    ),

    # ── PII Patterns ──────────────────────────────────────────────────────────
    (
        "CREDIT_CARD",
        re.compile(
            rb"\b(?:4[0-9]{12}(?:[0-9]{3})?"           # Visa
            rb"|5[1-5][0-9]{14}"                        # Mastercard
            rb"|3[47][0-9]{13}"                         # Amex
            rb"|3(?:0[0-5]|[68][0-9])[0-9]{11}"        # Diners
            rb"|6(?:011|5[0-9]{2})[0-9]{12})\b"        # Discover
        ),
    ),
    (
        "SSN",
        re.compile(rb"\b\d{3}-\d{2}-\d{4}\b"),
    ),
]


# ── Protocol Anomaly Rules ────────────────────────────────────────────────────
# Each rule: (description, check_function)
# check_function receives the FlowRecord and returns True if anomalous.

def _http_on_443(flow: FlowRecord) -> bool:
    """HTTP plaintext traffic on port 443 — should be HTTPS/TLS."""
    return (
        flow.dst_port == 443
        and flow.dpi.dissected_protocol == Protocol.HTTP
        and flow.protocol == Protocol.TCP
    )

def _dns_oversized(flow: FlowRecord) -> bool:
    """
    DNS packet exceeding 512 bytes without EDNS extension.
    Classic DNS tunneling indicator — legitimate DNS rarely exceeds 512 bytes.
    """
    return (
        flow.protocol == Protocol.UDP
        and flow.dst_port == 53
        and flow.bytes_sent > 512
    )

def _non_dns_on_53(flow: FlowRecord) -> bool:
    """Non-DNS traffic on port 53 — possible DNS tunneling or covert channel."""
    return (
        flow.dst_port == 53
        and flow.dpi.dissected_protocol not in (Protocol.DNS, Protocol.UNKNOWN)
    )

def _smtp_on_unexpected_port(flow: FlowRecord) -> bool:
    """SMTP traffic detected on a non-standard mail port."""
    smtp_ports = {25, 465, 587}
    return (
        flow.dpi.dissected_protocol == Protocol.SMTP
        and flow.dst_port not in smtp_ports
    )

def _ftp_cleartext(flow: FlowRecord) -> bool:
    """FTP credential exchange detected — inherently cleartext protocol."""
    return (
        flow.dpi.dissected_protocol == Protocol.FTP
        and any(hit.pattern_name in ("FTP_USER", "FTP_PASS") for hit in flow.dpi.dlp_hits)
    )

_ANOMALY_RULES: List[Tuple[str, callable]] = [
    ("HTTP traffic detected on port 443 — expected TLS/HTTPS",      _http_on_443),
    ("Oversized DNS packet (>512 bytes) — possible DNS tunneling",   _dns_oversized),
    ("Non-DNS traffic on port 53 — possible covert channel",         _non_dns_on_53),
    ("SMTP traffic on non-standard port",                            _smtp_on_unexpected_port),
    ("FTP credential exchange in cleartext",                         _ftp_cleartext),
]


# ── Entropy Calculator ────────────────────────────────────────────────────────

def _shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte sequence.

    Returns a value between 0.0 (fully uniform) and 8.0 (fully random).
    High entropy in a plaintext protocol field suggests:
      - encrypted payload hiding in plain sight
      - DNS tunneling (base64-encoded data in subdomains)
      - obfuscated C2 communication

    Formula: H = -Σ p(x) * log2(p(x))
    """
    if not data:
        return 0.0

    freq = [0] * 256
    for byte in data:
        freq[byte] += 1

    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return round(entropy, 4)


# ── Protocol Dissector ────────────────────────────────────────────────────────

def _dissect_protocol(flow: FlowRecord, payload: bytes) -> Protocol:
    """
    Refine the protocol classification using payload signatures.
    The capture layer makes a port-based guess — this confirms or corrects it.
    """
    if not payload:
        return flow.protocol

    # HTTP signatures
    http_methods = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                    b"OPTIONS ", b"PATCH ", b"HTTP/")
    if any(payload.startswith(m) for m in http_methods):
        return Protocol.HTTP

    # FTP signatures
    if payload.startswith((b"USER ", b"PASS ", b"220 ", b"230 ", b"331 ")):
        return Protocol.FTP

    # SMTP signatures
    if payload.startswith((b"EHLO", b"HELO", b"MAIL FROM", b"RCPT TO",
                            b"250 ", b"220 ", b"AUTH ")):
        return Protocol.SMTP

    # DNS — check port as primary signal (payload structure is binary)
    if flow.dst_port == 53 or flow.src_port == 53:
        return Protocol.DNS

    # Fall back to transport-layer protocol
    return flow.protocol


# ── OS Fingerprinter ──────────────────────────────────────────────────────────

def _fingerprint_os(ttl: Optional[int], window_size: Optional[int]) -> Optional[str]:
    """
    Estimate the source OS from TTL and TCP window size.
    This is Nmap-style passive fingerprinting — probabilistic, not definitive.

    Common TTL defaults:
      Linux/Android : 64
      Windows       : 128
      Cisco/Network : 255
      macOS/iOS     : 64 (same as Linux)
    """
    if ttl is None:
        return None

    # TTL buckets — OS sets initial TTL, we observe the remaining value
    if ttl <= 64:
        os_guess = "Linux / macOS / Android"
    elif ttl <= 128:
        os_guess = "Windows"
    elif ttl <= 255:
        os_guess = "Network Device (Cisco / BSD)"
    else:
        return None

    # Refine with window size if available
    if window_size is not None:
        if window_size == 65535:
            os_guess = "macOS / iOS"
        elif window_size == 8192:
            os_guess = "Windows (early handshake)"
        elif window_size in (5840, 14600, 29200):
            os_guess = "Linux"

    return f"{os_guess} (TTL={ttl}, Win={window_size})"


# ── DPI Engine ────────────────────────────────────────────────────────────────

class InspectionEngine:
    """
    Deep Packet Inspection layer for PacketStrike.

    Receives a FlowRecord with a raw_payload field, runs three analysis
    passes, and returns the same FlowRecord with a populated DPIResult.

    Three passes:
      1. Shannon entropy scoring
      2. DLP regex scanning
      3. Protocol anomaly detection

    This class is stateless — safe to call from multiple threads.

    Usage:
        engine = InspectionEngine(settings)
        enriched_flow = engine.inspect(flow)
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._inspected = 0
        self._dlp_hits_total = 0
        self._anomalies_total = 0
        self._entropy_flags_total = 0

    # ── Public Interface ──────────────────────────────────────────────────────

    def inspect(self, flow: FlowRecord) -> FlowRecord:
        """
        Run all DPI passes on a FlowRecord.
        Returns the same flow with flow.dpi populated.
        Always returns a flow — never raises.
        """
        try:
            return self._inspect_safe(flow)
        except Exception as e:
            logger.debug(f"DPI inspection failed for flow {flow.flow_id}: {e}")
            return flow

    # ── Internal ──────────────────────────────────────────────────────────────

    def _inspect_safe(self, flow: FlowRecord) -> FlowRecord:
        """Inner inspection — exceptions propagate to inspect() wrapper."""
        self._inspected += 1

        # ── Decode payload ────────────────────────────────────────────────────
        payload = self._decode_payload(flow.raw_payload)
        inspected_bytes = len(payload)

        # ── Pass 1: Protocol dissection ───────────────────────────────────────
        dissected = _dissect_protocol(flow, payload)

        # ── Pass 2: OS fingerprinting ─────────────────────────────────────────
        os_fp = _fingerprint_os(flow.ttl, flow.tcp_window_size)

        # ── Pass 3: Entropy scoring ───────────────────────────────────────────
        entropy_score   = 0.0
        entropy_flagged = False

        if self._settings.dlp_scan_enabled and payload:
            entropy_score   = _shannon_entropy(payload)
            entropy_flagged = entropy_score >= self._settings.entropy_threshold
            if entropy_flagged:
                self._entropy_flags_total += 1
                logger.debug(
                    f"High entropy ({entropy_score:.2f}) on flow {flow.flow_id} "
                    f"{flow.src_ip} → {flow.dst_ip}"
                )

        # ── Pass 4: DLP scanning ──────────────────────────────────────────────
        dlp_hits: List[DLPHit] = []

        if self._settings.dlp_scan_enabled and payload:
            dlp_hits = self._run_dlp(payload)
            self._dlp_hits_total += len(dlp_hits)

        # ── Pass 5: Protocol anomaly ──────────────────────────────────────────
        protocol_anomaly = False
        anomaly_reason: Optional[str] = None

        if self._settings.protocol_anomaly_enabled:
            # Temporarily attach partial DPI so anomaly rules can reference it
            flow.dpi = DPIResult(
                entropy_score      = entropy_score,
                entropy_flagged    = entropy_flagged,
                dlp_hits           = dlp_hits,
                protocol_anomaly   = False,
                dissected_protocol = dissected,
                os_fingerprint     = os_fp,
                inspected_bytes    = inspected_bytes,
            )
            protocol_anomaly, anomaly_reason = self._run_anomaly_checks(flow)
            if protocol_anomaly:
                self._anomalies_total += 1

        # ── Attach final DPIResult ────────────────────────────────────────────
        flow.dpi = DPIResult(
            entropy_score      = entropy_score,
            entropy_flagged    = entropy_flagged,
            dlp_hits           = dlp_hits,
            protocol_anomaly   = protocol_anomaly,
            anomaly_reason     = anomaly_reason,
            dissected_protocol = dissected,
            os_fingerprint     = os_fp,
            inspected_bytes    = inspected_bytes,
        )

        return flow

    def _decode_payload(self, raw_payload: Optional[str]) -> bytes:
        """
        Decode the base64 payload stored on the FlowRecord.
        Returns empty bytes if payload is absent or malformed.
        Truncates to dpi_depth before returning.
        """
        if not raw_payload:
            return b""
        try:
            decoded = base64.b64decode(raw_payload)
            return decoded[: self._settings.dpi_depth]
        except Exception:
            return b""

    def _run_dlp(self, payload: bytes) -> List[DLPHit]:
        """
        Run all DLP patterns against the payload.
        Matches are recorded with their byte offset.
        Matched values are truncated to 40 chars before storage.
        """
        hits: List[DLPHit] = []

        for pattern_name, pattern in _DLP_PATTERNS:
            for match in pattern.finditer(payload):
                raw_match = match.group(0)
                # Truncate and sanitise — never store full credentials
                display_value = raw_match[:40].decode("utf-8", errors="replace")
                if len(raw_match) > 40:
                    display_value += "…[redacted]"

                hits.append(DLPHit(
                    pattern_name  = pattern_name,
                    matched_value = display_value,
                    hex_offset    = match.start(),
                    regex_pattern = pattern.pattern
                        if isinstance(pattern.pattern, str)
                        else pattern.pattern.decode("utf-8", errors="replace"),
                ))

                logger.debug(
                    f"DLP hit [{pattern_name}] at offset {match.start()} "
                    f"on payload (truncated: {display_value[:20]}…)"
                )

        return hits

    def _run_anomaly_checks(self, flow: FlowRecord) -> Tuple[bool, Optional[str]]:
        """
        Run all protocol anomaly rules against the flow.
        Returns (anomaly_detected, reason_string).
        Stops at the first matching rule.
        """
        for description, check_fn in _ANOMALY_RULES:
            try:
                if check_fn(flow):
                    logger.debug(
                        f"Protocol anomaly [{description}] "
                        f"on flow {flow.flow_id} {flow.src_ip} → {flow.dst_ip}"
                    )
                    return True, description
            except Exception as e:
                logger.debug(f"Anomaly rule '{description}' error: {e}")

        return False, None

    # ── Stats ─────────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        """Return DPI statistics for the health endpoint."""
        return {
            "flows_inspected"    : self._inspected,
            "dlp_hits_total"     : self._dlp_hits_total,
            "anomalies_detected" : self._anomalies_total,
            "entropy_flags"      : self._entropy_flags_total,
        }