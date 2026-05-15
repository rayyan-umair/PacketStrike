"""
PacketStrike - Capture Layer
capture.py - Live interface capture and PCAP replay producer

Author  : Rayyan Umair
Date    : 2026-05-13
Purpose : The ingestion front-end of PacketStrike. Captures raw packets
          from a live network interface or replays a PCAP file, normalises
          every frame into a FlowRecord, and pushes it onto the internal
          queue for the Strike Engine to consume.
          No analysis. No storage. No intelligence lives here.
          Raw packet structures must never leak beyond this file.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/PacketStrike

"Silence the noise, strike the signal."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import asyncio
import base64
import logging
import queue
import threading
import time
from datetime import datetime, timezone
from typing import Optional

# ── Third Party ───────────────────────────────────────────────────────────────
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, Raw, Dot1Q
    from scapy.layers.dns import DNS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── Internal ──────────────────────────────────────────────────────────────────
from config import Settings
from models import FlowRecord, Protocol

logger = logging.getLogger(__name__)


# ── Protocol Resolution ───────────────────────────────────────────────────────

_PORT_PROTOCOL_MAP: dict[int, Protocol] = {
    20  : Protocol.FTP,
    21  : Protocol.FTP,
    25  : Protocol.SMTP,
    53  : Protocol.DNS,
    80  : Protocol.HTTP,
    443 : Protocol.HTTPS,
    587 : Protocol.SMTP,
    465 : Protocol.SMTP,
}

def _resolve_protocol(pkt) -> Protocol:
    """
    Guess the application protocol from port numbers and packet layers.
    This is a best-effort classification - the DPI layer refines it later.
    """
    if SCAPY_AVAILABLE:
        if pkt.haslayer(DNS):
            return Protocol.DNS
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            return _PORT_PROTOCOL_MAP.get(dport) or _PORT_PROTOCOL_MAP.get(sport) or Protocol.TCP
        if pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            return _PORT_PROTOCOL_MAP.get(dport) or Protocol.UDP
        if pkt.haslayer(ICMP):
            return Protocol.ICMP
    return Protocol.UNKNOWN


def _extract_vlan(pkt) -> Optional[int]:
    """Extract VLAN tag ID if present - critical for VLAN hopping detection."""
    if SCAPY_AVAILABLE and pkt.haslayer(Dot1Q):
        return pkt[Dot1Q].vlan
    return None


def _extract_payload(pkt, dpi_depth: int) -> Optional[str]:
    """
    Extract raw payload bytes up to dpi_depth and return as base64.
    Preserves forensic evidence for STRIKE-REPLAY.
    """
    if SCAPY_AVAILABLE and pkt.haslayer(Raw):
        raw_bytes = bytes(pkt[Raw])[:dpi_depth]
        return base64.b64encode(raw_bytes).decode("utf-8")
    return None


# ── Scapy Normaliser ──────────────────────────────────────────────────────────

def _scapy_packet_to_flow(pkt, interface: str, settings: Settings) -> Optional[FlowRecord]:
    """
    Normalise a raw Scapy packet into a FlowRecord.
    Returns None if the packet has no IP layer (ARP, etc. are ignored).
    """
    if not SCAPY_AVAILABLE:
        return None

    # ── Require IP layer ──────────────────────────────────────────────────────
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    now = datetime.now(timezone.utc)

    # ── Ports ─────────────────────────────────────────────────────────────────
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_window: Optional[int] = None

    if pkt.haslayer(TCP):
        src_port   = pkt[TCP].sport
        dst_port   = pkt[TCP].dport
        tcp_window = pkt[TCP].window
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    # ── Payload size ──────────────────────────────────────────────────────────
    payload_len = len(pkt[Raw]) if pkt.haslayer(Raw) else 0

    try:
        flow = FlowRecord(
            interface       = interface,
            vlan_id         = _extract_vlan(pkt),
            src_ip          = str(ip.src),
            dst_ip          = str(ip.dst),
            src_port        = src_port,
            dst_port        = dst_port,
            protocol        = _resolve_protocol(pkt),
            ttl             = ip.ttl,
            tcp_window_size = tcp_window,
            bytes_sent      = len(pkt),
            bytes_received  = 0,          # Single-packet view; session engine aggregates
            packets_sent    = 1,
            packets_received= 0,
            start_time      = now,
            raw_payload     = _extract_payload(pkt, settings.dpi_depth),
        )
        return flow
    except Exception as e:
        logger.debug(f"Packet normalisation failed: {e}")
        return None


# ── Capture Engine ────────────────────────────────────────────────────────────

class CaptureEngine:
    """
    Producer side of the PacketStrike pipeline.

    Captures packets from a live interface or replays a PCAP file,
    normalises each frame into a FlowRecord, and pushes it onto the
    shared internal queue for the Strike Engine to consume.

    Runs in its own daemon thread - non-blocking to the FastAPI server.

    Usage:
        engine = CaptureEngine(settings, flow_queue)
        engine.start()
        ...
        engine.stop()
    """

    def __init__(self, settings: Settings, flow_queue: queue.Queue) -> None:
        self._settings      = settings
        self._queue         = flow_queue
        self._running       = False
        self._thread        : Optional[threading.Thread] = None
        self._packets_seen  = 0
        self._packets_dropped = 0
        self._started_at    : Optional[datetime] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the capture thread."""
        if self._running:
            logger.warning("CaptureEngine is already running.")
            return

        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is not installed. Run: pip install scapy"
            )

        self._running    = True
        self._started_at = datetime.now(timezone.utc)

        target = (
            self._run_live_capture
            if self._settings.is_live_capture
            else self._run_pcap_replay
        )

        self._thread = threading.Thread(
            target=target,
            name="packetstrike-capture",
            daemon=True,
        )
        self._thread.start()

        mode = "LIVE" if self._settings.is_live_capture else "REPLAY"
        logger.info(
            f"CaptureEngine started [{mode}] "
            f"interface={self._settings.capture_interface} "
            f"filter='{self._settings.bpf_filter}'"
        )

    def stop(self) -> None:
        """Signal the capture thread to stop."""
        self._running = False
        logger.info(
            f"CaptureEngine stopping. "
            f"Seen={self._packets_seen} Dropped={self._packets_dropped}"
        )

    # ── Internal: Live Capture ────────────────────────────────────────────────

    def _run_live_capture(self) -> None:
        """
        Live capture loop using Scapy sniff().
        Runs until self._running is False.
        BPF filter is applied at the kernel level for efficiency.
        """
        logger.info(
            f"Starting live capture on {self._settings.capture_interface} "
            f"with BPF: '{self._settings.bpf_filter}'"
        )
        try:
            sniff(
                iface=self._settings.capture_interface,
                filter=self._settings.bpf_filter,
                prn=self._handle_packet,
                store=False,          # Never accumulate in memory
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            logger.error(
                "Permission denied - live capture requires root or CAP_NET_RAW. "
                "Try: sudo python main.py"
            )
            self._running = False
        except Exception as e:
            logger.error(f"Live capture error: {e}")
            self._running = False

    # ── Internal: PCAP Replay ─────────────────────────────────────────────────

    def _run_pcap_replay(self) -> None:
        """
        Replay a PCAP file through the same normalisation pipeline as live capture.
        Useful for testing, demos, and forensic re-analysis.
        """
        path = self._settings.pcap_replay_path
        if not path:
            logger.error("capture_mode=replay but PCAP_REPLAY_PATH is not set.")
            self._running = False
            return

        if not Path(path).exists():
            logger.error(f"PCAP replay file not found: {path}")
            self._running = False
            return

        logger.info(f"Replaying PCAP: {path}")
        try:
            packets = rdpcap(path)
            logger.info(f"Loaded {len(packets)} packets from {path}")
            for pkt in packets:
                if not self._running:
                    break
                self._handle_packet(pkt)
                time.sleep(0.001)       # Throttle replay - avoid instant queue flood
            logger.info("PCAP replay complete.")
        except Exception as e:
            logger.error(f"PCAP replay error: {e}")
        finally:
            self._running = False

    # ── Internal: Packet Handler ──────────────────────────────────────────────

    def _handle_packet(self, pkt) -> None:
        """
        Called for every captured or replayed packet.
        Normalises to FlowRecord and pushes to queue.
        Drops silently if the queue is full (backpressure).
        """
        self._packets_seen += 1

        flow = _scapy_packet_to_flow(
            pkt,
            interface=self._settings.capture_interface,
            settings=self._settings,
        )

        if flow is None:
            return     # Non-IP packet - ignored

        try:
            self._queue.put_nowait(flow)
        except queue.Full:
            self._packets_dropped += 1
            if self._packets_dropped % 100 == 0:
                logger.warning(
                    f"Queue full - dropped {self._packets_dropped} packets total. "
                    f"Consider increasing CAPTURE_QUEUE_MAXSIZE."
                )

    # ── Stats ─────────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        """Return capture statistics for the health endpoint."""
        uptime = 0.0
        if self._started_at:
            uptime = (datetime.now(timezone.utc) - self._started_at).total_seconds()
        return {
            "running"          : self._running,
            "mode"             : self._settings.capture_mode,
            "interface"        : self._settings.capture_interface,
            "packets_seen"     : self._packets_seen,
            "packets_dropped"  : self._packets_dropped,
            "drop_rate_pct"    : round(
                (self._packets_dropped / max(self._packets_seen, 1)) * 100, 2
            ),
            "uptime_seconds"   : round(uptime, 1),
        }