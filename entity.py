"""
PacketStrike - Entity Engine
entity.py - IP entity tracking, behavior profiling, risk scoring,
             beacon interval analysis, and timeline management

Author  : Rayyan Umair
Date    : 13 May, 2026
Purpose : The entity engine is the memory of PacketStrike. It maintains
          a live in-memory registry of every IP address observed on the
          network, accumulating behavioral evidence across flows over
          time. After each flow is processed and enriched by the DPI
          layer, the entity engine updates the relevant entity, runs
          all five detections, and returns any strikes fired.
          Entity state is persisted to DuckDB after every update.
          Risk scores decay over time - entities cool down if quiet.

          # NetRaptor integration hook:
          # IPEntity maps directly to the universal EntityProfile.
          # When the shared core is built, replace this registry with
          # the NetRaptor entity engine and keep detection calls intact.

Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/PacketStrike

"Silence the noise, strike the signal."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Deque, Dict, List, Optional, Tuple

# ── Internal ──────────────────────────────────────────────────────────────────
from config import Settings
from database import Database
from detections import DetectionEngine
from models import (
    BehaviorFlag,
    FlowRecord,
    IPEntity,
    Severity,
    StrikeEvent,
    StrikeType,
    TimelineEvent,
)

logger = logging.getLogger(__name__)


# ── Constants ─────────────────────────────────────────────────────────────────

# Risk score increments per event type
_RISK_STRIKE_CRITICAL  = 3.0
_RISK_STRIKE_HIGH      = 2.0
_RISK_STRIKE_MEDIUM    = 1.0
_RISK_DLP_HIT          = 0.5
_RISK_ENTROPY_FLAG     = 0.3
_RISK_PROTOCOL_ANOMALY = 0.2
_RISK_MAX              = 10.0
_RISK_MIN              = 0.0


# ── Beacon Interval Tracker ───────────────────────────────────────────────────

class BeaconIntervalTracker:
    """
    Tracks outbound connection timestamps per (src_ip, dst_ip) pair and
    computes the intervals between them for beaconing detection.

    Uses a sliding deque bounded by the detection window - old timestamps
    are pruned on every update so memory stays bounded.
    """

    def __init__(self, window_seconds: int, min_intervals: int) -> None:
        self._window    = timedelta(seconds=window_seconds)
        self._min       = min_intervals
        # Key: (src_ip, dst_ip) → deque of UTC datetimes
        self._timestamps: Dict[Tuple[str, str], Deque[datetime]] = defaultdict(
            lambda: deque(maxlen=200)
        )

    def record(self, src_ip: str, dst_ip: str, timestamp: datetime) -> List[float]:
        """
        Record a connection and return the list of inter-arrival intervals
        (in milliseconds) for this (src, dst) pair within the window.
        Returns an empty list if fewer than min_intervals samples exist.
        """
        key = (src_ip, dst_ip)
        dq  = self._timestamps[key]
        dq.append(timestamp)

        # Prune entries outside the sliding window
        cutoff = datetime.now(timezone.utc) - self._window
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) < self._min + 1:
            return []

        # Compute intervals between consecutive timestamps
        intervals = [
            (dq[i] - dq[i - 1]).total_seconds() * 1000   # ms
            for i in range(1, len(dq))
        ]
        return intervals

    def clear(self, src_ip: str, dst_ip: str) -> None:
        key = (src_ip, dst_ip)
        self._timestamps.pop(key, None)


# ── Entity Registry ───────────────────────────────────────────────────────────

class EntityEngine:
    """
    The memory of PacketStrike.

    Maintains a live in-memory registry of IPEntity objects, one per
    observed IP address. After the DPI layer enriches a FlowRecord,
    the entity engine:

      1. Gets or creates the entity for src_ip and dst_ip
      2. Updates traffic statistics and behavior flags
      3. Records beacon intervals for the src→dst pair
      4. Runs all five detections via DetectionEngine
      5. Applies risk scoring from DPI signals and strike results
      6. Appends timeline events
      7. Persists updated entities to DuckDB
      8. Returns any StrikeEvents fired

    Thread safety: a single lock protects the entity registry. The
    DuckDB writes happen inside the lock but are fast (single upsert).

    Usage:
        engine = EntityEngine(settings, db, detection_engine)
        engine.start()
        strikes = engine.process(flow)
        engine.stop()
    """

    def __init__(
        self,
        settings  : Settings,
        db        : Database,
        detections: DetectionEngine,
    ) -> None:
        self._settings   = settings
        self._db         = db
        self._detections = detections
        self._lock       = threading.Lock()

        # In-memory entity registry: ip_address → IPEntity
        self._entities: Dict[str, IPEntity] = {}

        # Beacon interval tracker
        self._beacon_tracker = BeaconIntervalTracker(
            window_seconds = settings.detection_window_seconds,
            min_intervals  = settings.beaconing_min_intervals,
        )

        self._flows_processed   = 0
        self._entities_created  = 0
        self._strikes_generated = 0

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Load existing entities from DuckDB into memory on startup."""
        logger.info("EntityEngine starting - loading entities from database...")
        rows = self._db.get_all_entities(limit=10_000)
        loaded = 0
        for row in rows:
            try:
                entity = self._deserialise_entity(row)
                self._entities[entity.ip_address] = entity
                loaded += 1
            except Exception as e:
                logger.debug(f"Failed to load entity row: {e}")
        logger.info(f"EntityEngine ready - {loaded} entities loaded from database.")

    def stop(self) -> None:
        """Flush all in-memory entities to DuckDB on shutdown."""
        logger.info("EntityEngine stopping - flushing entities to database...")
        with self._lock:
            for entity in self._entities.values():
                try:
                    self._db.upsert_entity(entity)
                except Exception as e:
                    logger.error(f"Failed to flush entity {entity.ip_address}: {e}")
        logger.info(f"EntityEngine stopped. {len(self._entities)} entities flushed.")

    # ── Main Pipeline Entry Point ─────────────────────────────────────────────

    def process(self, flow: FlowRecord) -> List[StrikeEvent]:
        """
        Process a DPI-enriched FlowRecord through the entity engine.
        Updates entity state, runs detections, scores risk, builds timeline.
        Returns a list of StrikeEvents (may be empty).
        """
        with self._lock:
            self._flows_processed += 1

            # ── Step 1: Get or create entities ────────────────────────────────
            src_entity = self._get_or_create(flow.src_ip)
            dst_entity = self._get_or_create(flow.dst_ip)

            # ── Step 2: Update src entity traffic stats ───────────────────────
            self._update_traffic(src_entity, flow)

            # ── Step 3: Apply DPI signals to risk ────────────────────────────
            self._apply_dpi_risk(src_entity, flow)

            # ── Step 4: Record beacon intervals ───────────────────────────────
            beacon_intervals = self._beacon_tracker.record(
                src_ip    = flow.src_ip,
                dst_ip    = flow.dst_ip,
                timestamp = flow.timestamp,
            )

            # ── Step 5: Run all five detections ───────────────────────────────
            strikes = self._detections.run(flow, src_entity, beacon_intervals)

            # ── Step 6: Apply strike results ──────────────────────────────────
            for strike in strikes:
                self._apply_strike(src_entity, strike, flow)
                self._strikes_generated += 1

            # ── Step 7: Update dst entity (lighter touch - no detection run) ──
            dst_entity.last_seen = flow.timestamp
            dst_entity.total_flows += 1

            # ── Step 8: Decay risk scores ─────────────────────────────────────
            self._decay_risk(src_entity)
            self._decay_risk(dst_entity)

            # ── Step 9: Prune timelines if too long ───────────────────────────
            self._prune_timeline(src_entity)

            # ── Step 10: Persist both entities ───────────────────────────────
            try:
                self._db.upsert_entity(src_entity)
                self._db.upsert_entity(dst_entity)
            except Exception as e:
                logger.error(f"Entity persistence failed: {e}")

            return strikes

    # ── Entity Management ─────────────────────────────────────────────────────

    def _get_or_create(self, ip: str) -> IPEntity:
        """Return existing entity or create a new one for this IP."""
        if ip not in self._entities:
            entity = IPEntity(ip_address=ip)
            self._entities[ip] = entity
            self._entities_created += 1
            logger.debug(f"New entity created: {ip}")
        return self._entities[ip]

    def get_entity(self, ip: str) -> Optional[IPEntity]:
        """Public accessor - returns entity or None if not yet observed."""
        with self._lock:
            return self._entities.get(ip)

    def get_all_entities(self) -> List[IPEntity]:
        """Return a snapshot of all in-memory entities."""
        with self._lock:
            return list(self._entities.values())

    def get_high_risk_entities(self, min_risk: float = 7.0) -> List[IPEntity]:
        """Return entities above risk threshold, sorted descending."""
        with self._lock:
            return sorted(
                [e for e in self._entities.values() if e.risk_score >= min_risk],
                key=lambda e: e.risk_score,
                reverse=True,
            )

    # ── Traffic Update ────────────────────────────────────────────────────────

    def _update_traffic(self, entity: IPEntity, flow: FlowRecord) -> None:
        """Update entity traffic statistics from this flow."""
        now = datetime.now(timezone.utc)

        entity.last_seen        = now
        entity.total_flows      += 1
        entity.total_bytes_out  += flow.bytes_sent
        entity.total_bytes_in   += flow.bytes_received

        # OS fingerprint - take best available, don't overwrite with None
        if flow.dpi.os_fingerprint and not entity.os_fingerprint:
            entity.os_fingerprint = flow.dpi.os_fingerprint
        if flow.ttl and not entity.ttl_observed:
            entity.ttl_observed = flow.ttl

        # Track unique destinations
        if flow.dst_ip and flow.dst_ip not in entity.unique_dst_ips:
            entity.unique_dst_ips.append(flow.dst_ip)

        if flow.dst_port and flow.dst_port not in entity.unique_dst_ports:
            entity.unique_dst_ports.append(flow.dst_port)

        # Add flow timeline event (lightweight - no strike reference)
        entity.timeline.append(TimelineEvent(
            timestamp   = now,
            event_type  = "flow",
            description = (
                f"Flow: {flow.src_ip}:{flow.src_port} → "
                f"{flow.dst_ip}:{flow.dst_port} "
                f"[{flow.protocol.value}] "
                f"{flow.bytes_sent}B sent"
            ),
            flow_id     = flow.flow_id,
            severity    = 0,
        ))

    # ── DPI Risk Application ──────────────────────────────────────────────────

    def _apply_dpi_risk(self, entity: IPEntity, flow: FlowRecord) -> None:
        """
        Increment entity risk score based on DPI findings.
        Also sets behavior flags where appropriate.
        """
        dpi = flow.dpi

        if dpi.entropy_flagged:
            entity.risk_score = min(
                _RISK_MAX,
                entity.risk_score + _RISK_ENTROPY_FLAG
            )
            if BehaviorFlag.HIGH_ENTROPY not in entity.flags:
                entity.flags.append(BehaviorFlag.HIGH_ENTROPY)
            entity.timeline.append(TimelineEvent(
                timestamp   = flow.timestamp,
                event_type  = "dpi_entropy",
                description = (
                    f"High entropy payload detected "
                    f"(score={dpi.entropy_score:.2f}) "
                    f"→ {flow.dst_ip}:{flow.dst_port}"
                ),
                flow_id     = flow.flow_id,
                severity    = 3,
            ))

        if dpi.dlp_hits:
            entity.risk_score = min(
                _RISK_MAX,
                entity.risk_score + _RISK_DLP_HIT * len(dpi.dlp_hits)
            )
            if BehaviorFlag.DLP_HIT not in entity.flags:
                entity.flags.append(BehaviorFlag.DLP_HIT)
            patterns = ", ".join(set(h.pattern_name for h in dpi.dlp_hits))
            entity.timeline.append(TimelineEvent(
                timestamp   = flow.timestamp,
                event_type  = "dlp_hit",
                description = (
                    f"DLP hit(s) detected: [{patterns}] "
                    f"→ {flow.dst_ip}:{flow.dst_port}"
                ),
                flow_id     = flow.flow_id,
                severity    = 5,
            ))

        if dpi.protocol_anomaly:
            entity.risk_score = min(
                _RISK_MAX,
                entity.risk_score + _RISK_PROTOCOL_ANOMALY
            )
            if BehaviorFlag.PROTOCOL_ANOMALY not in entity.flags:
                entity.flags.append(BehaviorFlag.PROTOCOL_ANOMALY)
            entity.timeline.append(TimelineEvent(
                timestamp   = flow.timestamp,
                event_type  = "protocol_anomaly",
                description = (
                    f"Protocol anomaly: {dpi.anomaly_reason} "
                    f"→ {flow.dst_ip}:{flow.dst_port}"
                ),
                flow_id     = flow.flow_id,
                severity    = 3,
            ))

    # ── Strike Application ────────────────────────────────────────────────────

    def _apply_strike(
        self,
        entity: IPEntity,
        strike: StrikeEvent,
        flow  : FlowRecord,
    ) -> None:
        """
        Apply a fired strike to the entity: increment risk, set flags,
        increment strike counter, append timeline entry.
        """
        # Risk increment by severity
        if strike.severity == Severity.CRITICAL:
            delta = _RISK_STRIKE_CRITICAL
        elif strike.severity == Severity.HIGH:
            delta = _RISK_STRIKE_HIGH
        else:
            delta = _RISK_STRIKE_MEDIUM

        entity.risk_score = min(_RISK_MAX, entity.risk_score + delta)
        entity.strike_count += 1

        # Map strike type → behavior flag
        flag_map = {
            StrikeType.PORT_SCAN      : BehaviorFlag.PORT_SCAN,
            StrikeType.BEACONING      : BehaviorFlag.BEACONING,
            StrikeType.HIGH_OUTBOUND  : BehaviorFlag.DATA_EXFIL,
            StrikeType.INTERNAL_PIVOT : BehaviorFlag.INTERNAL_PIVOT,
            StrikeType.KNOWN_BAD      : BehaviorFlag.KNOWN_BAD_IP,
        }
        flag = flag_map.get(strike.strike_type)
        if flag and flag not in entity.flags:
            entity.flags.append(flag)

        # Mark flow as strike contributor
        flow.strike_triggered = True
        if strike.strike_id not in flow.strike_ids:
            flow.strike_ids.append(strike.strike_id)

        # Timeline entry
        entity.timeline.append(TimelineEvent(
            timestamp   = strike.timestamp,
            event_type  = "strike",
            description = (
                f"⚡ {strike.strike_type.value} - {strike.what[:120]}"
            ),
            strike_id   = strike.strike_id,
            flow_id     = flow.flow_id,
            severity    = strike.severity.value,
        ))

        logger.info(
            f"Entity {entity.ip_address} - strike applied: "
            f"{strike.strike_type.value} | "
            f"risk={entity.risk_score:.1f} | "
            f"flags={[f.value for f in entity.flags]}"
        )

    # ── Risk Decay ────────────────────────────────────────────────────────────

    def _decay_risk(self, entity: IPEntity) -> None:
        """
        Gradually reduce risk score if the entity has been quiet.
        Decay begins after entity_risk_decay_hours of inactivity.
        Entities cool down at 0.1 risk points per decay cycle.
        """
        if entity.risk_score <= _RISK_MIN:
            return

        decay_threshold = timedelta(hours=self._settings.entity_risk_decay_hours)
        quiet_since     = datetime.now(timezone.utc) - entity.last_seen

        if quiet_since >= decay_threshold:
            entity.risk_score = max(
                _RISK_MIN,
                entity.risk_score - 0.1,
            )

    # ── Timeline Pruning ──────────────────────────────────────────────────────

    def _prune_timeline(self, entity: IPEntity) -> None:
        """
        Keep only the most recent entity_max_timeline_events entries.
        Oldest entries are dropped first - strikes are preserved because
        they are appended last and are therefore most recent.
        """
        max_events = self._settings.entity_max_timeline_events
        if len(entity.timeline) > max_events:
            entity.timeline = entity.timeline[-max_events:]

    # ── Deserialisation ───────────────────────────────────────────────────────

    def _deserialise_entity(self, row: dict) -> IPEntity:
        """
        Reconstruct an IPEntity from a DuckDB row dict.
        JSON fields are parsed back into typed lists.
        """
        import json

        flags = [
            BehaviorFlag(f)
            for f in json.loads(row.get("flags") or "[]")
            if f in BehaviorFlag._value2member_map_
        ]

        timeline_raw = json.loads(row.get("timeline") or "[]")
        timeline = []
        for entry in timeline_raw:
            try:
                timeline.append(TimelineEvent(**entry))
            except Exception:
                pass

        return IPEntity(
            entity_id        = row["entity_id"],
            ip_address       = row["ip_address"],
            first_seen       = row["first_seen"],
            last_seen        = row["last_seen"],
            flags            = flags,
            total_flows      = row.get("total_flows", 0),
            total_bytes_out  = row.get("total_bytes_out", 0),
            total_bytes_in   = row.get("total_bytes_in", 0),
            unique_dst_ips   = json.loads(row.get("unique_dst_ips") or "[]"),
            unique_dst_ports = json.loads(row.get("unique_dst_ports") or "[]"),
            os_fingerprint   = row.get("os_fingerprint"),
            ttl_observed     = row.get("ttl_observed"),
            risk_score       = float(row.get("risk_score", 0.0)),
            strike_count     = row.get("strike_count", 0),
            timeline         = timeline,
        )

    # ── Stats ─────────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "entities_in_memory"  : len(self._entities),
                "entities_created"    : self._entities_created,
                "flows_processed"     : self._flows_processed,
                "strikes_generated"   : self._strikes_generated,
                "high_risk_count"     : sum(
                    1 for e in self._entities.values()
                    if e.risk_score >= 7.0
                ),
            }