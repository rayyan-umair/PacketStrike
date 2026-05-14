"""
PacketStrike — Entry Point
main.py — Application bootstrap, pipeline wiring, startup/shutdown

Author  : Rayyan Umair
Date    : 2026-05-13
Purpose : Wires every engine layer together and starts the application.
          Startup sequence:
            1. Load settings
            2. Connect database
            3. Initialise engines (inspection, detection, entity)
            4. Load threat intel feed
            5. Start capture engine (producer thread)
            6. Start pipeline worker (consumer thread)
            7. Start archive scheduler
            8. Start FastAPI server (uvicorn)
          Shutdown sequence (SIGINT / SIGTERM):
            1. Stop capture engine
            2. Stop pipeline worker
            3. Flush entity engine to database
            4. Close database connection
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/PacketStrike

"Silence the noise, strike the signal."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import asyncio
import logging
import queue
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional

# ── Third Party ───────────────────────────────────────────────────────────────
import uvicorn

# ── Internal ──────────────────────────────────────────────────────────────────
from api import ConnectionManager, create_app
from capture import CaptureEngine
from config import Settings
from database import Database
from detections import DetectionEngine
from entity import EntityEngine
from inspector import InspectionEngine
from fastapi import FastAPI

# ── Logging Setup ─────────────────────────────────────────────────────────────

def _setup_logging(settings: Settings) -> None:
    """
    Configure root logger. All modules use logging.getLogger(__name__)
    so this single call propagates to every layer.
    """
    fmt = (
        "%(asctime)s  %(levelname)-8s  %(name)-28s  %(message)s"
    )
    logging.basicConfig(
        level   = getattr(logging, settings.log_level, logging.INFO),
        format  = fmt,
        datefmt = "%Y-%m-%d %H:%M:%S",
        handlers= [
            logging.StreamHandler(sys.stdout),
        ],
    )
    # Silence noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("pyshark").setLevel(logging.WARNING)


logger = logging.getLogger(__name__)


# ── Banner ────────────────────────────────────────────────────────────────────

_BANNER = """
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗        │
│   ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝        │
│   ██████╔╝███████║██║     █████╔╝ █████╗     ██║           │
│   ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║           │
│   ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║           │
│   ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝           │
│                                                             │
│        ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗        │
│        ██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝        │
│        ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗          │
│        ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝          │
│        ███████║   ██║   ██║  ██║██║██║  ██╗███████╗        │
│        ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝        │
│                                                             │
│   "Silence the noise, strike the signal."                   │
│   Part of the NetRaptor ecosystem.                          │
│   Built by Rayyan Umair                                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
"""


# ── Pipeline Worker ───────────────────────────────────────────────────────────

class PipelineWorker:
    """
    Consumer side of the PacketStrike pipeline.

    Runs in its own daemon thread. Pulls FlowRecords from the capture
    queue, passes each through the inspection engine, then through the
    entity engine. Any strikes fired are persisted to the database and
    broadcast to WebSocket clients.

    This is the only place flows move from raw → enriched → stored.

    Flow lifecycle:
        CaptureEngine → queue → PipelineWorker
                                  → InspectionEngine  (DPI enrichment)
                                  → EntityEngine       (entity update + detections)
                                  → Database           (flow + strikes stored)
                                  → ConnectionManager  (strikes broadcast)
    """

    def __init__(
        self,
        flow_queue     : queue.Queue,
        inspector      : InspectionEngine,
        entity_engine  : EntityEngine,
        db             : Database,
        ws_manager     : ConnectionManager,
        loop           : asyncio.AbstractEventLoop,
    ) -> None:
        self._queue         = flow_queue
        self._inspector     = inspector
        self._entity_engine = entity_engine
        self._db            = db
        self._ws_manager    = ws_manager
        self._loop          = loop
        self._running       = False
        self._thread        : Optional[threading.Thread] = None
        self._flows_done    = 0
        self._errors        = 0

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(
            target = self._run,
            name   = "packetstrike-pipeline",
            daemon = True,
        )
        self._thread.start()
        logger.info("PipelineWorker started.")

    def stop(self) -> None:
        self._running = False
        logger.info(
            f"PipelineWorker stopping. "
            f"Processed={self._flows_done} Errors={self._errors}"
        )

    def _run(self) -> None:
        """Main consumer loop — runs until self._running is False."""
        while self._running:
            try:
                # Block for up to 1s so stop() is checked regularly
                flow = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                # ── Step 1: DPI enrichment ────────────────────────────────────
                flow = self._inspector.inspect(flow)

                # ── Step 2: Entity update + detections ───────────────────────
                strikes = self._entity_engine.process(flow)

                # ── Step 3: Persist flow ──────────────────────────────────────
                self._db.insert_flow(flow)

                # ── Step 4: Persist and broadcast strikes ─────────────────────
                for strike in strikes:
                    self._db.insert_strike(strike)
                    self._broadcast_strike(strike)

                self._flows_done += 1

            except Exception as e:
                self._errors += 1
                logger.error(f"Pipeline error on flow {flow.flow_id}: {e}")

            finally:
                self._queue.task_done()

    def _broadcast_strike(self, strike) -> None:
        """
        Schedule a WebSocket broadcast on the event loop.
        Called from the pipeline thread — must use run_coroutine_threadsafe.
        """
        payload = {
            "type": "strike",
            "data": strike.model_dump(mode="json"),
        }
        asyncio.run_coroutine_threadsafe(
            self._ws_manager.broadcast(payload),
            self._loop,
        )

    @property
    def stats(self) -> dict:
        return {
            "flows_processed": self._flows_done,
            "errors"         : self._errors,
            "queue_depth"    : self._queue.qsize(),
        }


# ── Archive Scheduler ─────────────────────────────────────────────────────────

class ArchiveScheduler:
    """
    Runs Parquet archiving on a background daemon thread.
    Archives old flows and strikes to Parquet on the configured interval.
    """

    def __init__(self, db: Database, settings: Settings) -> None:
        self._db       = db
        self._interval = settings.archive_interval_hours * 3600
        self._running  = False
        self._thread   : Optional[threading.Thread] = None

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(
            target = self._run,
            name   = "packetstrike-archive",
            daemon = True,
        )
        self._thread.start()
        logger.info(
            f"ArchiveScheduler started — "
            f"interval={self._interval // 3600}h"
        )

    def stop(self) -> None:
        self._running = False

    def _run(self) -> None:
        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            try:
                flows_archived   = self._db.archive_old_flows()
                strikes_archived = self._db.archive_old_strikes()
                logger.info(
                    f"Archive complete — "
                    f"flows={flows_archived} strikes={strikes_archived}"
                )
            except Exception as e:
                logger.error(f"Archive failed: {e}")


# ── Application Bootstrap ─────────────────────────────────────────────────────

class PacketStrike:
    """
    Top-level application class.
    Owns all engine instances and coordinates startup / shutdown.
    """

    def __init__(self) -> None:
        self._settings    = Settings()
        self._started_at  = datetime.now(timezone.utc)
        self._flow_queue  : queue.Queue = queue.Queue(
            maxsize=self._settings.capture_queue_maxsize
        )

        # ── Engine instances ──────────────────────────────────────────────────
        self._db              = Database(self._settings)
        self._inspector       = InspectionEngine(self._settings)
        self._detections      = DetectionEngine(self._settings)
        self._entity_engine   = EntityEngine(
            self._settings, self._db, self._detections
        )
        self._capture         = CaptureEngine(self._settings, self._flow_queue)
        self._archive         = ArchiveScheduler(self._db, self._settings)

        # ── Async event loop (shared with pipeline worker) ────────────────────
        self._loop            : Optional[asyncio.AbstractEventLoop] = None
        self._pipeline        : Optional[PipelineWorker]           = None
        self._ws_manager      : Optional[ConnectionManager]        = None

    # ── Startup ───────────────────────────────────────────────────────────────

    def startup(self) -> None:
        """
        Full startup sequence. Called before uvicorn begins serving.
        """
        print(_BANNER)

        logger.info("=" * 60)
        logger.info(f"  PacketStrike v{self._settings.app_version} starting")
        logger.info(f"  Interface : {self._settings.capture_interface}")
        logger.info(f"  Mode      : {self._settings.capture_mode}")
        logger.info(f"  DB        : {self._settings.db_path}")
        logger.info(f"  AI        : {'enabled' if self._settings.ai_enabled else 'disabled'}")
        logger.info("=" * 60)

        # 1. Database
        self._db.connect()

        # 2. Entity engine (loads from DB)
        self._entity_engine.start()

        # 3. Threat intel
        self._detections.intel.load()

        # 4. Capture engine
        self._capture.start()

        # 5. Archive scheduler
        self._archive.start()

        logger.info("Startup complete — pipeline ready.")

    def build_app(self) -> "FastAPI":
        """
        Build the FastAPI app. Called after startup() so all engines
        are live before the first request can arrive.
        """
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

        app, self._ws_manager = create_app(
            settings             = self._settings,
            db                   = self._db,
            entity_engine        = self._entity_engine,
            capture_stats_fn     = lambda: self._capture.stats,
            inspector_stats_fn   = lambda: self._inspector.stats,
            detection_stats_fn   = lambda: self._detections.stats,
            started_at           = self._started_at,
        )

        # Wire pipeline worker now that ws_manager and loop exist
        self._pipeline = PipelineWorker(
            flow_queue    = self._flow_queue,
            inspector     = self._inspector,
            entity_engine = self._entity_engine,
            db            = self._db,
            ws_manager    = self._ws_manager,
            loop          = self._loop,
        )
        self._pipeline.start()

        # Lifespan hooks
        @app.on_event("shutdown")
        async def on_shutdown() -> None:
            self.shutdown()

        return app

    # ── Shutdown ──────────────────────────────────────────────────────────────

    def shutdown(self) -> None:
        """
        Graceful shutdown sequence. Called on SIGINT / SIGTERM
        or FastAPI shutdown event.
        """
        logger.info("PacketStrike shutting down...")

        if self._capture:
            self._capture.stop()

        if self._pipeline:
            self._pipeline.stop()

        if self._archive:
            self._archive.stop()

        if self._entity_engine:
            self._entity_engine.stop()

        if self._db:
            self._db.close()

        logger.info("PacketStrike shutdown complete.")


# ── Entry Point ───────────────────────────────────────────────────────────────

def main() -> None:
    settings = Settings()
    _setup_logging(settings)

    app_instance = PacketStrike()
    app_instance.startup()
    app = app_instance.build_app()

    # Signal handlers for clean shutdown outside uvicorn lifecycle
    def _handle_signal(sig, frame):
        logger.info(f"Signal {sig} received — initiating shutdown.")
        app_instance.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    uvicorn.run(
        app,
        host      = settings.host,
        port      = settings.port,
        log_level = settings.log_level.lower(),
        reload    = False,          # Never reload in capture mode
    )


if __name__ == "__main__":
    main()