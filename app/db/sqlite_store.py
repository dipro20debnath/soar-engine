"""SOAR Engine - SQLite Alert Data Store

Persistent alert storage using SQLite.
Drop-in replacement for the in-memory AlertStore — same interface,
but data survives server restarts.

The database file is created at ./soar_engine.db by default.
"""

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from app.models.alert import (
    NormalizedAlert,
    AlertStatus,
    AlertSeverity,
    AlertType,
    AlertStats,
    AlertSummary,
    IoC,
)

logger = logging.getLogger(__name__)

# Default database path (project root)
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "soar_engine.db"


def _adapt_datetime(val: datetime) -> str:
    """Convert datetime to ISO 8601 string for SQLite storage."""
    return val.isoformat()


def _convert_datetime(val: bytes) -> datetime:
    """Convert ISO 8601 string from SQLite back to datetime."""
    return datetime.fromisoformat(val.decode())


# Register SQLite adapters
sqlite3.register_adapter(datetime, _adapt_datetime)
sqlite3.register_converter("TIMESTAMP", _convert_datetime)


class SQLiteAlertStore:
    """SQLite-backed persistent alert store.

    Provides the exact same interface as the in-memory AlertStore,
    but stores data in a SQLite database file.

    Schema:
        alerts table — stores all NormalizedAlert fields
        Serializes complex fields (iocs, enrichment_data, response_actions, tags)
        as JSON strings.
    """

    def __init__(self, db_path: Optional[str] = None):
        """Initialize the SQLite store and create tables if needed.

        Args:
            db_path: Path to the SQLite database file.
                     Defaults to ./soar_engine.db
                     Use ":memory:" for in-memory SQLite (tests).
        """
        self._db_path = db_path or str(DEFAULT_DB_PATH)
        self._init_db()
        logger.info(f"SQLiteAlertStore initialized (db: {self._db_path})")

    def _get_conn(self) -> sqlite3.Connection:
        """Get a new database connection (one per call for thread safety)."""
        conn = sqlite3.connect(
            self._db_path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        """Create database tables if they don't exist."""
        conn = self._get_conn()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id       TEXT PRIMARY KEY,
                    timestamp      TIMESTAMP NOT NULL,
                    received_at    TIMESTAMP NOT NULL,
                    alert_type     TEXT NOT NULL DEFAULT 'unknown',
                    severity       TEXT NOT NULL DEFAULT 'medium',
                    status         TEXT NOT NULL DEFAULT 'new',
                    source_ip      TEXT,
                    dest_ip        TEXT,
                    target_host    TEXT,
                    description    TEXT DEFAULT '',
                    iocs           TEXT DEFAULT '[]',
                    risk_score     REAL,
                    enrichment_data TEXT DEFAULT '{}',
                    playbook_name  TEXT,
                    response_actions TEXT DEFAULT '[]',
                    siem_source    TEXT DEFAULT 'generic',
                    raw_payload    TEXT DEFAULT '{}',
                    tags           TEXT DEFAULT '[]'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)
            """)
            conn.commit()
        finally:
            conn.close()

    def _alert_to_row(self, alert: NormalizedAlert) -> dict:
        """Convert a NormalizedAlert to a dictionary for database insertion."""
        return {
            "alert_id": alert.alert_id,
            "timestamp": alert.timestamp.isoformat(),
            "received_at": alert.received_at.isoformat(),
            "alert_type": alert.alert_type.value,
            "severity": alert.severity.value,
            "status": alert.status.value,
            "source_ip": alert.source_ip,
            "dest_ip": alert.dest_ip,
            "target_host": alert.target_host,
            "description": alert.description,
            "iocs": json.dumps([ioc.model_dump() for ioc in alert.iocs]),
            "risk_score": alert.risk_score,
            "enrichment_data": json.dumps(alert.enrichment_data),
            "playbook_name": alert.playbook_name,
            "response_actions": json.dumps(alert.response_actions),
            "siem_source": alert.siem_source.value,
            "raw_payload": json.dumps(alert.raw_payload),
            "tags": json.dumps(alert.tags),
        }

    def _row_to_alert(self, row: sqlite3.Row) -> NormalizedAlert:
        """Convert a database row back to a NormalizedAlert."""
        data = dict(row)

        # Parse JSON fields
        data["iocs"] = [IoC(**ioc) for ioc in json.loads(data["iocs"])]
        data["enrichment_data"] = json.loads(data["enrichment_data"])
        data["response_actions"] = json.loads(data["response_actions"])
        data["raw_payload"] = json.loads(data["raw_payload"])
        data["tags"] = json.loads(data["tags"])

        # Parse timestamps (sqlite3 converter already makes these datetime objects)
        if isinstance(data["timestamp"], str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        if isinstance(data["received_at"], str):
            data["received_at"] = datetime.fromisoformat(data["received_at"])

        return NormalizedAlert(**data)

    # ── CRUD Operations ───────────────────────────────

    def add_alert(self, alert: NormalizedAlert) -> NormalizedAlert:
        """Add a new alert to the database.

        Args:
            alert: The normalized alert to store.

        Returns:
            The stored alert.
        """
        row = self._alert_to_row(alert)
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO alerts
                   (alert_id, timestamp, received_at, alert_type, severity, status,
                    source_ip, dest_ip, target_host, description, iocs, risk_score,
                    enrichment_data, playbook_name, response_actions, siem_source,
                    raw_payload, tags)
                   VALUES (:alert_id, :timestamp, :received_at, :alert_type, :severity,
                    :status, :source_ip, :dest_ip, :target_host, :description, :iocs,
                    :risk_score, :enrichment_data, :playbook_name, :response_actions,
                    :siem_source, :raw_payload, :tags)""",
                row,
            )
            conn.commit()
        finally:
            conn.close()

        logger.info(
            f"Alert stored (SQLite): {alert.alert_id} | "
            f"Type: {alert.alert_type} | Severity: {alert.severity}"
        )
        return alert

    def get_alert(self, alert_id: str) -> Optional[NormalizedAlert]:
        """Retrieve a single alert by ID."""
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
            )
            row = cursor.fetchone()
            return self._row_to_alert(row) if row else None
        finally:
            conn.close()

    def get_all_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        alert_type: Optional[AlertType] = None,
        status: Optional[AlertStatus] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[NormalizedAlert]:
        """Get alerts with optional filtering, sorted newest first."""
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity.value)
        if alert_type:
            query += " AND alert_type = ?"
            params.append(alert_type.value)
        if status:
            query += " AND status = ?"
            params.append(status.value)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        conn = self._get_conn()
        try:
            cursor = conn.execute(query, params)
            return [self._row_to_alert(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def update_alert(self, alert_or_id, **updates) -> Optional[NormalizedAlert]:
        """Update an existing alert.

        Can be called two ways:
        1. update_alert(normalized_alert) — replace with full alert object
        2. update_alert(alert_id, field1=val1, ...) — update specific fields
        """
        if isinstance(alert_or_id, NormalizedAlert):
            alert = alert_or_id
            # Re-insert (INSERT OR REPLACE)
            self.add_alert(alert)
            logger.info(f"Alert replaced (SQLite): {alert.alert_id}")
            return alert

        alert_id = alert_or_id
        existing = self.get_alert(alert_id)
        if not existing:
            logger.warning(f"Alert not found for update: {alert_id}")
            return None

        alert_dict = existing.model_dump()
        alert_dict.update(updates)
        updated = NormalizedAlert(**alert_dict)
        self.add_alert(updated)
        logger.info(f"Alert updated (SQLite): {alert_id} | Fields: {list(updates.keys())}")
        return updated

    def delete_alert(self, alert_id: str) -> bool:
        """Delete an alert from the database."""
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "DELETE FROM alerts WHERE alert_id = ?", (alert_id,)
            )
            conn.commit()
            deleted = cursor.rowcount > 0
        finally:
            conn.close()

        if deleted:
            logger.info(f"Alert deleted (SQLite): {alert_id}")
        return deleted

    def get_stats(self) -> AlertStats:
        """Calculate aggregate statistics across all stored alerts."""
        conn = self._get_conn()
        try:
            # Total count
            total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            if total == 0:
                return AlertStats()

            # By severity
            by_severity = {}
            for row in conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
            ):
                by_severity[row["severity"]] = row["cnt"]

            # By type
            by_type = {}
            for row in conn.execute(
                "SELECT alert_type, COUNT(*) as cnt FROM alerts GROUP BY alert_type"
            ):
                by_type[row["alert_type"]] = row["cnt"]

            # By status
            by_status = {}
            for row in conn.execute(
                "SELECT status, COUNT(*) as cnt FROM alerts GROUP BY status"
            ):
                by_status[row["status"]] = row["cnt"]

            # Average risk score
            avg_row = conn.execute(
                "SELECT AVG(risk_score) FROM alerts WHERE risk_score IS NOT NULL"
            ).fetchone()
            avg_risk = round(avg_row[0], 2) if avg_row[0] is not None else None

            # Last alert time
            last_row = conn.execute(
                "SELECT MAX(timestamp) FROM alerts"
            ).fetchone()
            last_time = (
                datetime.fromisoformat(last_row[0]) if last_row[0] else None
            )

            return AlertStats(
                total_alerts=total,
                by_severity=by_severity,
                by_type=by_type,
                by_status=by_status,
                avg_risk_score=avg_risk,
                last_alert_time=last_time,
            )
        finally:
            conn.close()

    def get_summaries(self, limit: int = 50) -> list[AlertSummary]:
        """Get lightweight summaries for dashboard display."""
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                """SELECT alert_id, timestamp, alert_type, severity, status,
                          source_ip, description, risk_score
                   FROM alerts ORDER BY timestamp DESC LIMIT ?""",
                (limit,),
            )
            return [
                AlertSummary(
                    alert_id=row["alert_id"],
                    timestamp=row["timestamp"] if not isinstance(row["timestamp"], str) else datetime.fromisoformat(row["timestamp"]),
                    alert_type=row["alert_type"],
                    severity=row["severity"],
                    status=row["status"],
                    source_ip=row["source_ip"],
                    description=row["description"],
                    risk_score=row["risk_score"],
                )
                for row in cursor.fetchall()
            ]
        finally:
            conn.close()

    @property
    def count(self) -> int:
        """Total number of alerts in the store."""
        conn = self._get_conn()
        try:
            return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        finally:
            conn.close()

    def clear(self) -> None:
        """Remove all alerts from the store."""
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM alerts")
            conn.commit()
        finally:
            conn.close()
        logger.info("SQLiteAlertStore cleared")

    def get_alerts_by_risk_level(
        self, min_score: float = 0, max_score: float = 100
    ) -> list[NormalizedAlert]:
        """Get alerts filtered by risk score range, sorted highest first."""
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                """SELECT * FROM alerts
                   WHERE risk_score IS NOT NULL
                   AND risk_score >= ? AND risk_score <= ?
                   ORDER BY risk_score DESC""",
                (min_score, max_score),
            )
            return [self._row_to_alert(row) for row in cursor.fetchall()]
        finally:
            conn.close()
