"""SOAR Engine - Alert Data Store

Provides the global alert_store instance used across the application.

Uses SQLite by default for persistent storage.
Set environment variable STORE_MODE=memory to use in-memory store (for testing).

Both stores expose the exact same interface (add, get, update, delete, stats, etc.)
so they are interchangeable without changing any other code.
"""

import os
import logging

logger = logging.getLogger(__name__)

# ── Store Selection ─────────────────────────────────
# Default: SQLite for persistence
# Set STORE_MODE=memory for in-memory (useful for tests)
STORE_MODE = os.getenv("STORE_MODE", "sqlite").lower()

if STORE_MODE == "memory":
    from app.db.memory_store import AlertStore
    alert_store = AlertStore()
    logger.info("Alert store: IN-MEMORY mode")
else:
    from app.db.sqlite_store import SQLiteAlertStore
    alert_store = SQLiteAlertStore()
    logger.info("Alert store: SQLite mode")
