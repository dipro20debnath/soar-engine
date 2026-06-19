"""SOAR Engine - Webhook Receiver Router

Handles incoming SIEM alert webhooks at POST /api/alerts.
This is the entry point for all alerts into the SOAR pipeline.

Pipeline: Receive → Normalize → Enrich → Score → Playbook → Contain → Store
"""

import logging
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Any, Optional

from app.models.alert import RawAlert, NormalizedAlert, AlertStatus
from app.services.normalizer import normalize_alert
from app.services.enrichment import EnrichmentService
from app.services.risk_scorer import calculate_risk_score, get_risk_level
from app.services.playbook_engine import playbook_engine
from app.config import settings
from app.db.store import alert_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Webhooks"])

# Shared enrichment service instance
_enrichment_service = EnrichmentService()


class WebhookResponse(BaseModel):
    """Response returned after successfully receiving an alert."""
    success: bool = True
    message: str = "Alert received and processed successfully"
    alert_id: str
    alert_type: str
    severity: str
    status: str
    ioc_count: int
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    threat_level: Optional[str] = None
    playbook_name: Optional[str] = None
    response_actions: list[str] = Field(default_factory=list)
    enrichment_notes: list[str] = Field(default_factory=list)
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BulkWebhookRequest(BaseModel):
    """Request body for sending multiple alerts at once."""
    source: str = "generic"
    alerts: list[dict[str, Any]]


class BulkWebhookResponse(BaseModel):
    """Response for bulk alert ingestion."""
    success: bool = True
    total_received: int
    total_processed: int
    total_failed: int
    alert_ids: list[str]
    errors: list[str] = Field(default_factory=list)


def _process_alert(source: str, payload: dict[str, Any]) -> tuple[NormalizedAlert, Optional[float], Optional[str], list[str]]:
    """Run the full processing pipeline for a single alert.

    Steps:
        1. Normalize the raw SIEM payload into a standard schema
        2. Enrich IoCs via AbuseIPDB and VirusTotal
        3. Calculate a risk score using the weighted algorithm
        4. Update the alert with enrichment data and risk score

    Args:
        source: The SIEM source identifier (e.g., "splunk", "elastic")
        payload: The raw alert JSON payload

    Returns:
        Tuple of (normalized_alert, risk_score, threat_level, notes)
    """
    # Step 1: Normalize
    normalized = normalize_alert(source=source, payload=payload)

    risk_score = None
    threat_level = None
    notes = []
    enrichment_result = None  # Shared across pipeline steps

    # Step 2: Enrich (if enrichment is enabled)
    if settings.ENRICHMENT_ENABLED and len(normalized.iocs) > 0:
        try:
            enrichment_result = _enrichment_service.enrich(normalized)

            # Step 3: Calculate risk score
            risk_score = calculate_risk_score(normalized, enrichment_result)
            threat_level = enrichment_result.overall_threat_level
            notes = enrichment_result.notes

            # Step 4: Update the alert with enrichment data
            normalized.risk_score = risk_score
            normalized.enrichment_data = {
                "threat_level": threat_level,
                "confidence": enrichment_result.confidence,
                "ip_results_count": len(enrichment_result.ip_results),
                "hash_results_count": len(enrichment_result.hash_results),
                "notes": notes,
                "enriched_at": enrichment_result.enriched_at.isoformat(),
            }
            normalized.status = AlertStatus.ENRICHED
            normalized.tags.append(f"risk:{get_risk_level(risk_score)}")

            logger.info(
                f"Alert {normalized.alert_id} enriched: "
                f"risk_score={risk_score}, threat_level={threat_level}"
            )

        except Exception as e:
            logger.error(f"Enrichment failed for {normalized.alert_id}: {e}")
            normalized.status = AlertStatus.NORMALIZED
            notes.append(f"Enrichment failed: {str(e)}")

    # Step 5: Execute playbook (automated response)
    if normalized.risk_score is not None:
        try:
            actions = playbook_engine.execute(normalized, enrichment_result)
            logger.info(
                f"Playbook '{normalized.playbook_name}' executed for "
                f"{normalized.alert_id}: {len(actions)} actions"
            )
        except Exception as e:
            logger.error(f"Playbook execution failed for {normalized.alert_id}: {e}")

    return normalized, risk_score, threat_level, notes


@router.post(
    "/alerts",
    response_model=WebhookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Receive SIEM Alert Webhook",
    description="Receives a single SIEM alert, normalizes it, enriches it with threat intelligence, calculates risk score, and stores it.",
)
async def receive_alert(raw_alert: RawAlert) -> WebhookResponse:
    """Receive and process a single SIEM alert through the full pipeline.

    Pipeline: Normalize → Enrich (AbuseIPDB + VirusTotal) → Risk Score → Store

    Args:
        raw_alert: The raw alert with source hint and JSON payload.

    Returns:
        WebhookResponse with alert ID, classification, risk score, and enrichment notes.
    """
    try:
        logger.info(f"Received alert from source: {raw_alert.source}")

        # Run the full processing pipeline
        normalized, risk_score, threat_level, notes = _process_alert(
            source=raw_alert.source or "generic",
            payload=raw_alert.payload,
        )

        # Store the processed alert
        alert_store.add_alert(normalized)

        logger.info(
            f"Alert processed: {normalized.alert_id} | "
            f"Type: {normalized.alert_type} | "
            f"Severity: {normalized.severity} | "
            f"Risk: {risk_score} | "
            f"IoCs: {len(normalized.iocs)}"
        )

        return WebhookResponse(
            alert_id=normalized.alert_id,
            alert_type=normalized.alert_type.value,
            severity=normalized.severity.value,
            status=normalized.status.value,
            ioc_count=len(normalized.iocs),
            risk_score=risk_score,
            risk_level=get_risk_level(risk_score) if risk_score is not None else None,
            threat_level=threat_level,
            playbook_name=normalized.playbook_name,
            response_actions=normalized.response_actions,
            enrichment_notes=notes,
        )

    except Exception as e:
        logger.error(f"Failed to process alert: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to process alert: {str(e)}",
        )


@router.post(
    "/alerts/bulk",
    response_model=BulkWebhookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Receive Multiple SIEM Alerts",
    description="Receives multiple alerts in a single request for batch processing. Each alert goes through the full enrichment pipeline.",
)
async def receive_bulk_alerts(request: BulkWebhookRequest) -> BulkWebhookResponse:
    """Receive and process multiple SIEM alerts in one request.

    Each alert goes through the full pipeline independently.
    Failures don't affect other alerts in the batch.

    Args:
        request: Batch request containing source and list of alert payloads.

    Returns:
        BulkWebhookResponse with success/failure counts and alert IDs.
    """
    alert_ids = []
    errors = []

    for i, payload in enumerate(request.alerts):
        try:
            normalized, _, _, _ = _process_alert(
                source=request.source,
                payload=payload,
            )
            alert_store.add_alert(normalized)
            alert_ids.append(normalized.alert_id)
        except Exception as e:
            error_msg = f"Alert #{i + 1}: {str(e)}"
            errors.append(error_msg)
            logger.error(f"Failed to process bulk alert #{i + 1}: {str(e)}")

    logger.info(
        f"Bulk ingestion complete: {len(alert_ids)} processed, {len(errors)} failed"
    )

    return BulkWebhookResponse(
        total_received=len(request.alerts),
        total_processed=len(alert_ids),
        total_failed=len(errors),
        alert_ids=alert_ids,
        errors=errors,
    )

