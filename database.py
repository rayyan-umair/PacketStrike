"""
PacketStrike - Database Layer
database.py - DuckDB packet spooler, schema management, Parquet archiving

Author  : Rayyan Umair
Date    : 2026-05-13
Purpose : All storage operations for PacketStrike. DuckDB acts as the
          live packet spooler - fast enough for real-time ingestion,
          powerful enough for SQL-based investigation queries.
          Parquet handles long-term compressed historical archives.
          Nothing outside this file touches the database directly.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/PacketStrike

"Silence the noise, strike the signal."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional

# ── Third Party ───────────────────────────────────────────────────────────────
import duckdb

# ── Internal ──────────────────────────────────────────────────────────────────
from config import Settings
from models import (
    FlowRecord,
    StrikeEvent,
    IPEntity,
    StrikeType,
    Protocol,
    Severity,
    BehaviorFlag,
    TimelineEvent,
    DPIResult,
    DLPHit,
)

logger = logging.getLogger(__name__)


# ── Schema Definitions ────────────────────────────────────────────────────────

_FLOWS_DDL = """
CREATE TABLE IF NOT EXISTS flows (
    flow_id             VARCHAR PRIMARY KEY,
    timestamp           TIMESTAMPTZ NOT NULL,
    interface           VARCHAR     NOT NULL,
    vlan_id             INTEGER,

    src_ip              VARCHAR     NOT NULL,
    dst_ip              VARCHAR     NOT NULL,
    src_port            INTEGER,
    dst_port            INTEGER,
    protocol            VARCHAR     NOT NULL,
    ttl                 INTEGER,
    tcp_window_size     INTEGER,

    bytes_sent          BIGINT      DEFAULT 0,
    bytes_received      BIGINT      DEFAULT 0,
    packets_sent        INTEGER     DEFAULT 0,
    packets_received    INTEGER     DEFAULT 0,
    start_time          TIMESTAMPTZ NOT NULL,
    end_time            TIMESTAMPTZ,
    duration_ms         DOUBLE,
    delta_t_ms          DOUBLE,

    -- DPI fields (flattened for query performance)
    entropy_score       DOUBLE      DEFAULT 0.0,
    entropy_flagged     BOOLEAN     DEFAULT FALSE,
    dlp_hits            JSON,
    protocol_anomaly    BOOLEAN     DEFAULT FALSE,
    anomaly_reason      VARCHAR,
    dissected_protocol  VARCHAR,
    os_fingerprint      VARCHAR,
    inspected_bytes     INTEGER     DEFAULT 0,

    strike_triggered    BOOLEAN     DEFAULT FALSE,
    strike_ids          JSON,
    raw_payload         TEXT
);
"""

_STRIKES_DDL = """
CREATE TABLE IF NOT EXISTS strikes (
    strike_id           VARCHAR PRIMARY KEY,
    strike_type         VARCHAR     NOT NULL,
    severity            INTEGER     NOT NULL,
    timestamp           TIMESTAMPTZ NOT NULL,

    src_ip              VARCHAR     NOT NULL,
    dst_ip              VARCHAR,
    dst_port            INTEGER,
    protocol            VARCHAR,
    interface           VARCHAR,

    who                 TEXT        NOT NULL,
    what                TEXT        NOT NULL,
    where_field         TEXT        NOT NULL,
    when_field          TEXT        NOT NULL,
    why                 TEXT        NOT NULL,
    how                 TEXT        NOT NULL,

    hex_offset          INTEGER,
    evidence_summary    TEXT,
    related_flow_ids    JSON,
    ai_explanation      TEXT
);
"""

_ENTITIES_DDL = """
CREATE TABLE IF NOT EXISTS entities (
    entity_id           VARCHAR PRIMARY KEY,
    ip_address          VARCHAR     NOT NULL UNIQUE,
    first_seen          TIMESTAMPTZ NOT NULL,
    last_seen           TIMESTAMPTZ NOT NULL,

    flags               JSON,
    total_flows         INTEGER     DEFAULT 0,
    total_bytes_out     BIGINT      DEFAULT 0,
    total_bytes_in      BIGINT      DEFAULT 0,
    unique_dst_ips      JSON,
    unique_dst_ports    JSON,

    os_fingerprint      VARCHAR,
    ttl_observed        INTEGER,
    risk_score          DOUBLE      DEFAULT 0.0,
    strike_count        INTEGER     DEFAULT 0,
    timeline            JSON
);
"""

_INDEXES_DDL = [
    "CREATE INDEX IF NOT EXISTS idx_flows_src_ip    ON flows (src_ip);",
    "CREATE INDEX IF NOT EXISTS idx_flows_dst_ip    ON flows (dst_ip);",
    "CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows (timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_flows_protocol  ON flows (protocol);",
    "CREATE INDEX IF NOT EXISTS idx_strikes_src_ip  ON strikes (src_ip);",
    "CREATE INDEX IF NOT EXISTS idx_strikes_type    ON strikes (strike_type);",
    "CREATE INDEX IF NOT EXISTS idx_strikes_ts      ON strikes (timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_entities_ip     ON entities (ip_address);",
    "CREATE INDEX IF NOT EXISTS idx_entities_risk   ON entities (risk_score);",
]


# ── Database Manager ──────────────────────────────────────────────────────────

class Database:
    """
    PacketStrike database manager.

    Wraps DuckDB for all read/write operations.
    One instance is created at startup and shared across the application.
    All methods are synchronous - DuckDB is not async-native.

    Usage:
        db = Database(settings)
        db.connect()
        db.insert_flow(flow)
        db.close()
    """

    def __init__(self, settings: Settings) -> None:
        self._settings  = settings
        self._db_path   = settings.db_path
        self._conn      : Optional[duckdb.DuckDBPyConnection] = None
        self._connected : bool = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def connect(self) -> None:
        """Open the DuckDB connection and initialise all tables."""
        logger.info(f"Connecting to DuckDB at: {self._db_path}")
        try:
            self._conn = duckdb.connect(self._db_path)
            self._init_schema()
            self._connected = True
            logger.info("Database connected and schema verified.")
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise

    def close(self) -> None:
        """Close the DuckDB connection cleanly."""
        if self._conn:
            self._conn.close()
            self._connected = False
            logger.info("Database connection closed.")

    def _init_schema(self) -> None:
        """Create all tables and indexes if they do not exist."""
        assert self._conn is not None
        self._conn.execute(_FLOWS_DDL)
        self._conn.execute(_STRIKES_DDL)
        self._conn.execute(_ENTITIES_DDL)
        for idx in _INDEXES_DDL:
            self._conn.execute(idx)
        logger.debug("Schema initialised.")

    def _require_connection(self) -> None:
        if not self._connected or self._conn is None:
            raise RuntimeError("Database.connect() must be called before any operations.")

    # ── Flow Operations ───────────────────────────────────────────────────────

    def insert_flow(self, flow: FlowRecord) -> None:
        """Insert a single FlowRecord into the flows table."""
        self._require_connection()
        assert self._conn is not None

        self._conn.execute("""
            INSERT OR REPLACE INTO flows VALUES (
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?
            )
        """, [
            flow.flow_id,
            flow.timestamp,
            flow.interface,
            flow.vlan_id,

            flow.src_ip,
            flow.dst_ip,
            flow.src_port,
            flow.dst_port,
            flow.protocol.value,
            flow.ttl,
            flow.tcp_window_size,

            flow.bytes_sent,
            flow.bytes_received,
            flow.packets_sent,
            flow.packets_received,
            flow.start_time,
            flow.end_time,
            flow.duration_ms,
            flow.delta_t_ms,

            flow.dpi.entropy_score,
            flow.dpi.entropy_flagged,
            json.dumps([h.model_dump() for h in flow.dpi.dlp_hits]),
            flow.dpi.protocol_anomaly,
            flow.dpi.anomaly_reason,
            flow.dpi.dissected_protocol.value,
            flow.dpi.os_fingerprint,
            flow.dpi.inspected_bytes,

            flow.strike_triggered,
            json.dumps(flow.strike_ids),
            flow.raw_payload,
        ])

    def get_flows_by_ip(
        self,
        ip: str,
        since: Optional[datetime] = None,
        limit: int = 500,
    ) -> List[dict]:
        """Return flows where src_ip or dst_ip matches, optionally since a timestamp."""
        self._require_connection()
        assert self._conn is not None

        query = """
            SELECT * FROM flows
            WHERE (src_ip = ? OR dst_ip = ?)
        """
        params: list = [ip, ip]

        if since:
            query += " AND timestamp >= ?"
            params.append(since)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        return self._conn.execute(query, params).fetchdf().to_dict(orient="records")

    def get_recent_flows(self, limit: int = 100) -> List[dict]:
        """Return the most recent flows across all IPs."""
        self._require_connection()
        assert self._conn is not None
        return (
            self._conn
            .execute("SELECT * FROM flows ORDER BY timestamp DESC LIMIT ?", [limit])
            .fetchdf()
            .to_dict(orient="records")
        )

    def query_flows_sql(self, sql: str) -> List[dict]:
        """
        Execute a raw SQL SELECT against the flows table.
        For analyst investigation queries - e.g.:
            SELECT * FROM flows WHERE payload LIKE '%password%'
        Read-only. Mutations are not permitted here.
        """
        self._require_connection()
        assert self._conn is not None
        if not sql.strip().upper().startswith("SELECT"):
            raise ValueError("query_flows_sql only permits SELECT statements.")
        return self._conn.execute(sql).fetchdf().to_dict(orient="records")

    # ── Strike Operations ─────────────────────────────────────────────────────

    def insert_strike(self, strike: StrikeEvent) -> None:
        """Insert a StrikeEvent into the strikes table."""
        self._require_connection()
        assert self._conn is not None

        self._conn.execute("""
            INSERT OR REPLACE INTO strikes VALUES (
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?
            )
        """, [
            strike.strike_id,
            strike.strike_type.value,
            strike.severity.value,
            strike.timestamp,

            strike.src_ip,
            strike.dst_ip,
            strike.dst_port,
            strike.protocol.value,
            strike.interface,

            strike.who,
            strike.what,
            strike.where,
            strike.when,
            strike.why,
            strike.how,

            strike.hex_offset,
            strike.evidence_summary,
            json.dumps(strike.related_flow_ids),
            strike.ai_explanation,
        ])

    def get_strikes(
        self,
        since: Optional[datetime] = None,
        src_ip: Optional[str] = None,
        strike_type: Optional[StrikeType] = None,
        limit: int = 200,
    ) -> List[dict]:
        """Fetch strikes with optional filters."""
        self._require_connection()
        assert self._conn is not None

        query  = "SELECT * FROM strikes WHERE 1=1"
        params : list = []

        if since:
            query += " AND timestamp >= ?"
            params.append(since)
        if src_ip:
            query += " AND src_ip = ?"
            params.append(src_ip)
        if strike_type:
            query += " AND strike_type = ?"
            params.append(strike_type.value)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        return self._conn.execute(query, params).fetchdf().to_dict(orient="records")

    def get_strike_count_by_type(self) -> dict:
        """Return a dict of strike_type → count for dashboard summary."""
        self._require_connection()
        assert self._conn is not None
        rows = self._conn.execute("""
            SELECT strike_type, COUNT(*) as count
            FROM strikes
            GROUP BY strike_type
            ORDER BY count DESC
        """).fetchall()
        return {row[0]: row[1] for row in rows}

    # ── Entity Operations ─────────────────────────────────────────────────────

    def upsert_entity(self, entity: IPEntity) -> None:
        """Insert or update an IPEntity. Last write wins on conflict."""
        self._require_connection()
        assert self._conn is not None

        self._conn.execute("""
            INSERT OR REPLACE INTO entities VALUES (
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?
            )
        """, [
            entity.entity_id,
            entity.ip_address,
            entity.first_seen,
            entity.last_seen,

            json.dumps([f.value for f in entity.flags]),
            entity.total_flows,
            entity.total_bytes_out,
            entity.total_bytes_in,
            json.dumps(entity.unique_dst_ips),
            json.dumps(entity.unique_dst_ports),

            entity.os_fingerprint,
            entity.ttl_observed,
            entity.risk_score,
            entity.strike_count,
            json.dumps([e.model_dump(mode="json") for e in entity.timeline]),
        ])

    def get_entity(self, ip: str) -> Optional[dict]:
        """Fetch a single entity by IP address."""
        self._require_connection()
        assert self._conn is not None
        rows = self._conn.execute(
            "SELECT * FROM entities WHERE ip_address = ?", [ip]
        ).fetchdf().to_dict(orient="records")
        return rows[0] if rows else None

    def get_high_risk_entities(self, min_risk: float = 7.0, limit: int = 50) -> List[dict]:
        """Return entities above a risk threshold, sorted by risk descending."""
        self._require_connection()
        assert self._conn is not None
        return (
            self._conn
            .execute("""
                SELECT * FROM entities
                WHERE risk_score >= ?
                ORDER BY risk_score DESC
                LIMIT ?
            """, [min_risk, limit])
            .fetchdf()
            .to_dict(orient="records")
        )

    def get_all_entities(self, limit: int = 500) -> List[dict]:
        """Return all tracked entities sorted by last_seen descending."""
        self._require_connection()
        assert self._conn is not None
        return (
            self._conn
            .execute("SELECT * FROM entities ORDER BY last_seen DESC LIMIT ?", [limit])
            .fetchdf()
            .to_dict(orient="records")
        )

    # ── Parquet Archiving ─────────────────────────────────────────────────────

    def archive_old_flows(self) -> int:
        """
        Export flows older than retention_days to Parquet and delete from DuckDB.
        Returns the number of rows archived.
        """
        self._require_connection()
        assert self._conn is not None

        cutoff = datetime.now(timezone.utc) - timedelta(days=self._settings.retention_days)
        parquet_path = self._settings.parquet_path

        archive_file = parquet_path / f"flows_{cutoff.strftime('%Y%m%d_%H%M%S')}.parquet"

        count_row = self._conn.execute(
            "SELECT COUNT(*) FROM flows WHERE timestamp < ?", [cutoff]
        ).fetchone()
        count = count_row[0] if count_row else 0

        if count == 0:
            logger.info("No flows to archive.")
            return 0

        self._conn.execute(f"""
            COPY (SELECT * FROM flows WHERE timestamp < ?)
            TO '{archive_file}' (FORMAT PARQUET)
        """, [cutoff])

        self._conn.execute("DELETE FROM flows WHERE timestamp < ?", [cutoff])

        logger.info(f"Archived {count} flows to {archive_file}")
        return count

    def archive_old_strikes(self) -> int:
        """
        Export strikes older than retention_days to Parquet and delete from DuckDB.
        Returns the number of rows archived.
        """
        self._require_connection()
        assert self._conn is not None

        cutoff = datetime.now(timezone.utc) - timedelta(days=self._settings.retention_days)
        parquet_path = self._settings.parquet_path

        archive_file = parquet_path / f"strikes_{cutoff.strftime('%Y%m%d_%H%M%S')}.parquet"

        count_row = self._conn.execute(
            "SELECT COUNT(*) FROM strikes WHERE timestamp < ?", [cutoff]
        ).fetchone()
        count = count_row[0] if count_row else 0

        if count == 0:
            logger.info("No strikes to archive.")
            return 0

        self._conn.execute(f"""
            COPY (SELECT * FROM strikes WHERE timestamp < ?)
            TO '{archive_file}' (FORMAT PARQUET)
        """, [cutoff])

        self._conn.execute("DELETE FROM strikes WHERE timestamp < ?", [cutoff])

        logger.info(f"Archived {count} strikes to {archive_file}")
        return count

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Return high-level database statistics for the health endpoint."""
        self._require_connection()
        assert self._conn is not None

        flow_count = self._conn.execute(
            "SELECT COUNT(*) FROM flows"
        ).fetchone()[0]

        strike_count = self._conn.execute(
            "SELECT COUNT(*) FROM strikes"
        ).fetchone()[0]

        entity_count = self._conn.execute(
            "SELECT COUNT(*) FROM entities"
        ).fetchone()[0]

        high_risk_count = self._conn.execute(
            "SELECT COUNT(*) FROM entities WHERE risk_score >= 7.0"
        ).fetchone()[0]

        return {
            "total_flows"       : flow_count,
            "total_strikes"     : strike_count,
            "total_entities"    : entity_count,
            "high_risk_entities": high_risk_count,
        }