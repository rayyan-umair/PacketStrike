"""
PacketStrike - Configuration
config.py - Settings, environment variables, .env file loading

Author  : Rayyan Umair
Date    : 2026-05-13
Purpose : Centralised configuration for the PacketStrike engine. All
          settings are read from environment variables with sensible
          defaults. Supports .env file for local development.
          Every setting is documented. Nothing is hardcoded anywhere
          else in the codebase - always import from here.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/PacketStrike

"Silence the noise, strike the signal."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import os
from pathlib import Path
from typing import List, Optional

# ── Third Party ───────────────────────────────────────────────────────────────
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator

# ── Base Paths ────────────────────────────────────────────────────────────────

BASE_DIR    = Path(__file__).parent
DATA_DIR    = BASE_DIR / "data"
LOGS_DIR    = BASE_DIR / "logs"
PCAP_DIR    = BASE_DIR / "pcap"
INTEL_DIR   = BASE_DIR / "intel"

# Create directories if they don't exist
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
PCAP_DIR.mkdir(exist_ok=True)
INTEL_DIR.mkdir(exist_ok=True)


# ── Settings ──────────────────────────────────────────────────────────────────

class Settings(BaseSettings):
    """
    All PacketStrike configuration.
    Values are loaded from environment variables or .env file.
    Defaults are production-safe and work out of the box.
    """

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ───────────────────────────────────────────────────────────

    app_name: str = Field(
        default="PacketStrike",
        description="Application name shown in logs and API responses",
    )
    app_version: str = Field(
        default="1.0.0",
        description="Application version",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level: DEBUG, INFO, WARNING, ERROR",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode - verbose logging, auto-reload",
    )

    # ── Server ────────────────────────────────────────────────────────────────

    host: str = Field(
        default="0.0.0.0",
        description="Host to bind the FastAPI server",
    )
    port: int = Field(
        default=8001,
        description="Port to bind the FastAPI server (8001 keeps clear of LogClaw)",
    )

    # ── Capture Layer ─────────────────────────────────────────────────────────

    capture_interface: str = Field(
        default="eth0",
        description="Network interface to capture live traffic on",
    )
    capture_mode: str = Field(
        default="live",
        description="Capture mode: live (interface) or replay (PCAP file)",
    )
    pcap_replay_path: Optional[str] = Field(
        default=None,
        description="Path to PCAP file for replay mode - only used when capture_mode=replay",
    )
    bpf_filter: str = Field(
        default="not port 22",
        description="BPF filter applied at kernel level - excludes SSH by default to prevent capture loop",
    )
    mtu_size: int = Field(
        default=1500,
        description="Maximum transmission unit - standard Ethernet frame size",
    )
    ring_buffer_size: int = Field(
        default=50000,
        description="Maximum number of raw frames held in the capture ring buffer",
    )
    capture_queue_maxsize: int = Field(
        default=10000,
        description="Maximum items in the producer→consumer internal queue before backpressure",
    )

    # ── DPI - Deep Packet Inspection ──────────────────────────────────────────

    dpi_depth: int = Field(
        default=1024,
        description="Bytes to inspect per packet payload - deeper = more accurate, higher CPU",
    )
    entropy_threshold: float = Field(
        default=4.5,
        description="Shannon entropy score above which a payload is flagged as suspicious (max 8.0)",
    )
    dlp_scan_enabled: bool = Field(
        default=True,
        description="Enable cleartext sensitivity scanning (DLP) on raw payload buffers",
    )
    protocol_anomaly_enabled: bool = Field(
        default=True,
        description="Enable RFC violation detection - flags traffic breaking protocol standards",
    )

    # ── Strike Detection ──────────────────────────────────────────────────────

    detection_window_seconds: int = Field(
        default=600,
        description="Sliding window in seconds used for all behavioral detections",
    )
    strike_cooldown_seconds: int = Field(
        default=60,
        description="Seconds before re-alerting on the same stream for the same strike type",
    )

    # STRIKE-001 - Port Scan
    port_scan_threshold: int = Field(
        default=15,
        description="Distinct destination ports from one source IP within window to trigger port scan strike",
    )

    # STRIKE-002 - Beaconing
    beaconing_min_intervals: int = Field(
        default=5,
        description="Minimum number of connection intervals required to evaluate beaconing regularity",
    )
    beaconing_jitter_tolerance: float = Field(
        default=0.1,
        description="Allowed coefficient of variation (0.0–1.0) in connection intervals before beaconing is flagged",
    )

    # STRIKE-003 - High Outbound Transfer
    exfiltration_threshold_bytes: int = Field(
        default=104_857_600,
        description="Outbound bytes in a single session above which exfiltration strike fires (default: 100 MB)",
    )

    # STRIKE-004 - Internal Pivot
    pivot_host_threshold: int = Field(
        default=3,
        description="Number of distinct internal hosts a source connects to within window to trigger pivot strike",
    )
    internal_subnets: List[str] = Field(
        default=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        description="CIDR ranges treated as internal - used for pivot and exfiltration classification",
    )

    # STRIKE-005 - Known-Bad Destination
    threat_intel_path: str = Field(
        default=str(INTEL_DIR / "known_bad.txt"),
        description="Path to plaintext threat intel feed - one IP or domain per line",
    )
    threat_intel_reload_interval: int = Field(
        default=3600,
        description="Seconds between automatic threat intel feed reloads",
    )

    # ── Entity Engine ─────────────────────────────────────────────────────────

    entity_stale_days: int = Field(
        default=90,
        description="Days of inactivity before an entity is considered stale and archived",
    )
    entity_risk_decay_hours: int = Field(
        default=24,
        description="Hours before an entity risk score begins decaying toward baseline",
    )
    entity_max_timeline_events: int = Field(
        default=1000,
        description="Maximum timeline events stored per entity before oldest are pruned",
    )

    # ── Storage ───────────────────────────────────────────────────────────────

    db_path: str = Field(
        default=str(DATA_DIR / "packetstrike.duckdb"),
        description="Path to DuckDB database file used as live packet spooler",
    )
    parquet_dir: str = Field(
        default=str(DATA_DIR / "parquet"),
        description="Directory for Parquet historical archive files",
    )
    retention_days: int = Field(
        default=90,
        description="Days to retain flow records in DuckDB before archiving to Parquet",
    )
    archive_interval_hours: int = Field(
        default=24,
        description="Hours between archiving old flow records to Parquet",
    )

    # ── WebSocket ─────────────────────────────────────────────────────────────

    ws_max_connections: int = Field(
        default=50,
        description="Maximum concurrent WebSocket connections",
    )
    ws_heartbeat_interval: int = Field(
        default=30,
        description="Seconds between WebSocket heartbeat pings",
    )

    # ── AI Layer ──────────────────────────────────────────────────────────────

    ai_provider: Optional[str] = Field(
        default=None,
        description="AI provider: anthropic | openai | gemini | groq | ollama | None",
    )
    ai_api_key: Optional[str] = Field(
        default=None,
        description="API key for the chosen AI provider",
    )
    ai_model: Optional[str] = Field(
        default=None,
        description="Model override - uses provider default if not set",
    )
    ai_enabled: bool = Field(
        default=False,
        description="Master switch for AI features - False means no AI calls at all",
    )
    ai_max_tokens: int = Field(
        default=800,
        description="Maximum tokens per AI response",
    )
    ai_timeout: int = Field(
        default=30,
        description="Seconds before an AI API call times out",
    )
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for Ollama local AI server",
    )
    ollama_model: str = Field(
        default="llama3",
        description="Ollama model name to use for local AI",
    )

    # ── Security ──────────────────────────────────────────────────────────────

    secret_key: str = Field(
        default="change-this-in-production-packetstrike-secret-key-2026",
        description="Secret key for JWT signing - MUST be changed in production",
    )
    token_expire_hours: int = Field(
        default=24,
        description="Hours before a JWT token expires",
    )
    allow_anonymous: bool = Field(
        default=True,
        description="Allow unauthenticated API access - True for local-only deployments",
    )

    # ── Validators ────────────────────────────────────────────────────────────

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v = v.upper()
        if v not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return v

    @field_validator("capture_mode")
    @classmethod
    def validate_capture_mode(cls, v: str) -> str:
        valid = {"live", "replay"}
        v = v.lower()
        if v not in valid:
            raise ValueError(f"capture_mode must be one of {valid}")
        return v

    @field_validator("ai_provider")
    @classmethod
    def validate_ai_provider(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        valid = {"anthropic", "openai", "gemini", "groq", "ollama"}
        v = v.lower()
        if v not in valid:
            raise ValueError(f"ai_provider must be one of {valid}")
        return v

    @field_validator("entropy_threshold")
    @classmethod
    def validate_entropy_threshold(cls, v: float) -> float:
        if not 0.0 <= v <= 8.0:
            raise ValueError("entropy_threshold must be between 0.0 and 8.0")
        return v

    # ── Derived Properties ────────────────────────────────────────────────────

    @property
    def parquet_path(self) -> Path:
        p = Path(self.parquet_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def is_ai_configured(self) -> bool:
        """True if AI is enabled and an API key or Ollama is configured."""
        if not self.ai_enabled:
            return False
        if self.ai_provider == "ollama":
            return True
        return bool(self.ai_api_key)

    @property
    def effective_model(self) -> Optional[str]:
        """Returns the model to use - explicit override or provider default."""
        if self.ai_model:
            return self.ai_model
        defaults = {
            "anthropic": "claude-haiku-4-5-20251001",
            "openai":    "gpt-4o",
            "gemini":    "gemini-2.0-flash",
            "groq":      "llama-3.1-8b-instant",
            "ollama":    self.ollama_model,
        }
        return defaults.get(self.ai_provider or "", None)

    @property
    def is_live_capture(self) -> bool:
        """True if capturing from a live interface."""
        return self.capture_mode == "live"


# ── .env.example Generator ────────────────────────────────────────────────────
# Run this file directly to regenerate the .env.example file.

def generate_env_example():
    """Write a .env.example file to the project root."""
    lines = [
        "# PacketStrike - Environment Configuration",
        "# Copy this file to .env and fill in your values",
        "# Built by Rayyan Umair - Silence the noise, strike the signal.",
        "",
        "# ── Application ──────────────────────────────────────",
        "LOG_LEVEL=INFO",
        "DEBUG=false",
        "",
        "# ── Server ───────────────────────────────────────────",
        "HOST=0.0.0.0",
        "PORT=8001",
        "",
        "# ── Capture ──────────────────────────────────────────",
        "# Set this to your active network interface",
        "CAPTURE_INTERFACE=eth0",
        "CAPTURE_MODE=live",
        "# PCAP_REPLAY_PATH=./pcap/sample.pcap",
        "BPF_FILTER=not port 22",
        "",
        "# ── DPI ──────────────────────────────────────────────",
        "DPI_DEPTH=1024",
        "ENTROPY_THRESHOLD=4.5",
        "DLP_SCAN_ENABLED=true",
        "PROTOCOL_ANOMALY_ENABLED=true",
        "",
        "# ── Detection ────────────────────────────────────────",
        "DETECTION_WINDOW_SECONDS=600",
        "STRIKE_COOLDOWN_SECONDS=60",
        "PORT_SCAN_THRESHOLD=15",
        "EXFILTRATION_THRESHOLD_BYTES=104857600",
        "PIVOT_HOST_THRESHOLD=3",
        "",
        "# ── Storage ──────────────────────────────────────────",
        "DB_PATH=./data/packetstrike.duckdb",
        "PARQUET_DIR=./data/parquet",
        "RETENTION_DAYS=90",
        "",
        "# ── AI Layer ─────────────────────────────────────────",
        "# Set AI_ENABLED=true and configure a provider to enable AI features",
        "AI_ENABLED=false",
        "# AI_PROVIDER=groq",
        "# AI_API_KEY=your-api-key-here",
        "# AI_MODEL=llama-3.1-8b-instant",
        "",
        "# For local AI via Ollama (no API key needed):",
        "# AI_PROVIDER=ollama",
        "# AI_ENABLED=true",
        "# OLLAMA_BASE_URL=http://localhost:11434",
        "# OLLAMA_MODEL=llama3",
        "",
        "# ── Security ─────────────────────────────────────────",
        "# CHANGE THIS in production - use a long random string",
        "SECRET_KEY=change-this-in-production-packetstrike-secret-key-2026",
        "ALLOW_ANONYMOUS=true",
        "",
    ]
    env_example = BASE_DIR / ".env.example"
    env_example.write_text("\n".join(lines))
    print(f"Written: {env_example}")


if __name__ == "__main__":
    generate_env_example()
    settings = Settings()
    print(f"\nLoaded settings:")
    print(f"  Interface   : {settings.capture_interface}")
    print(f"  Mode        : {settings.capture_mode}")
    print(f"  DB path     : {settings.db_path}")
    print(f"  DPI depth   : {settings.dpi_depth} bytes")
    print(f"  Entropy thr : {settings.entropy_threshold}")
    print(f"  AI enabled  : {settings.ai_enabled}")
    print(f"  AI provider : {settings.ai_provider}")
    print(f"  Log level   : {settings.log_level}")