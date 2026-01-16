import logging
import threading
from datetime import datetime, timedelta
from typing import List, Optional

from app import SyncConfig, run_once
from state_manager import StateLoggingHandler, StateManager


class SyncService:
    """Manages background sync operations with state tracking."""

    def __init__(self, sync_config: SyncConfig, state_manager: StateManager, interval_seconds: int):
        self.sync_config = sync_config
        self.state_manager = state_manager
        self.interval_seconds = interval_seconds
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.sync_lock = threading.Lock()  # Prevent concurrent syncs

    def start(self):
        """Start background sync thread if interval > 0."""
        if self.interval_seconds > 0:
            self.thread = threading.Thread(target=self._run_loop, daemon=True)
            self.thread.start()
            logging.info(f"Background sync scheduler started (interval: {self.interval_seconds}s)")
        else:
            logging.info("Background sync disabled (interval: 0)")

    def stop(self):
        """Stop background sync gracefully."""
        if self.thread:
            logging.info("Stopping background sync scheduler...")
            self.stop_event.set()
            self.thread.join(timeout=5)
            logging.info("Background sync scheduler stopped")

    def trigger_sync(self, mode: Optional[str] = None) -> int:
        """Manually trigger a sync (blocking). Returns sync_id."""
        # Use provided mode or default to configured mode
        sync_mode = mode if mode else self.sync_config.mode

        # Prevent concurrent syncs
        if not self.sync_lock.acquire(blocking=False):
            raise RuntimeError("Sync already in progress")

        try:
            return self._execute_sync(sync_mode)
        finally:
            self.sync_lock.release()

    def _execute_sync(self, mode: str) -> int:
        """Execute a sync with state tracking. Returns sync_id."""
        sync_id = self.state_manager.record_sync_start(mode)
        collections_attempted: List[str] = []
        success = False
        error_message: Optional[str] = None

        # Install logging handler to capture logs
        log_handler = StateLoggingHandler(self.state_manager, sync_id)
        log_handler.setLevel(logging.DEBUG)
        root_logger = logging.getLogger()
        root_logger.addHandler(log_handler)

        try:
            logging.info(f"Manual sync triggered (mode: {mode})")

            # Determine which collections will be attempted based on mode
            if mode == "all":
                collections_attempted = [
                    "pfsense_dns_hosts",
                    "pfsense_interface_map",
                    "pfsense_filter_rule_map",
                    "pfsense_zone_subnets",
                ]
            elif mode == "dns":
                collections_attempted = ["pfsense_dns_hosts"]
            elif mode == "interfaces":
                collections_attempted = ["pfsense_interface_map"]
            elif mode == "rules":
                collections_attempted = ["pfsense_filter_rule_map"]
            elif mode == "enrichment":
                collections_attempted = ["pfsense_zone_subnets"]

            # Execute sync
            success = run_once(
                mode,
                self.sync_config.config_xml,
                self.sync_config.pfctl_file,
                self.sync_config.host,
                self.sync_config.user,
                self.sync_config.port,
                self.sync_config.password,
                self.sync_config.strict_host_key,
                self.sync_config.known_hosts_file,
                self.sync_config.kv,
                self.sync_config.chunk_size,
                self.sync_config.remove_stale,
            )

            if not success:
                error_message = "Sync completed with failures"

        except Exception as exc:
            success = False
            error_message = str(exc)
            logging.error(f"Sync failed with exception: {exc}", exc_info=True)
        finally:
            # Remove logging handler
            root_logger.removeHandler(log_handler)

            # Record completion
            self.state_manager.record_sync_complete(sync_id, success, collections_attempted, error_message)

        return sync_id

    def _run_loop(self):
        """Background thread that runs scheduled syncs."""
        while not self.stop_event.is_set():
            # Calculate next run time
            next_run = datetime.now() + timedelta(seconds=self.interval_seconds)
            self.state_manager.set_next_run(next_run.isoformat())

            try:
                # Attempt to acquire lock (non-blocking)
                if self.sync_lock.acquire(blocking=False):
                    try:
                        self._execute_sync(self.sync_config.mode)
                    finally:
                        self.sync_lock.release()
                else:
                    logging.warning("Skipping scheduled sync - manual sync in progress")

            except Exception as exc:
                logging.error(f"Error in background sync loop: {exc}", exc_info=True)

            # Sleep with interruptible wait
            self.stop_event.wait(self.interval_seconds)

        # Clear next run on shutdown
        self.state_manager.set_next_run(None)
