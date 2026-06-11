"""SOAR Engine - Webhook Receiver Router

Handles incoming SIEM alert webhooks at POST /api/alerts.
This is the entry point for all alerts into the SOAR pipeline.
"""

import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Any, Optional

from app.models.alert import RawAlert, NormalizedAlert
from app.services.normalizer import normalize_alert
from app.db.store import alert_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Webhooks"])


class WebhookResponse(BaseModel):
    """Response returned after successfully receiving an alert."""
    success: bool = True
    message: str = "Alert received and normalized successfully"
    alert_id: str
    alert_type: str
    severity: str
    status: str
    ioc_count: int
    received_at: datetime = Field(default_factory=datetime.utcnow)


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


@router.post(
    "/alerts",
    response_model=WebhookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Receive SIEM Alert Webhook",
    description="Receives a single SIEM alert, normalizes it, and stores it for processing.",
)
async def receive_alert(raw_alert: RawAlert) -> WebhookResponse:
    """Receive and process a single SIEM alert.
    
    This endpoint accepts alerts from any SIEM system (Splunk, Elastic, etc.).
    The alert is automatically:
    1. Normalized to a standard schema
    2. IoCs (IPs, hashes, URLs) are extracted
    3. Stored for enrichment and response
    
    Args:
        raw_alert: The raw alert with source hint and JSON payload.
        
    Returns:
        WebhookResponse with the assigned alert ID and classification.
    """
    try:
        logger.info(f"Received alert from source: {raw_alert.source}")
        
        # Normalize the alert
        normalized: NormalizedAlert = normalize_alert(
            source=raw_alert.source or "generic",
            payload=raw_alert.payload,
        )
        
        # Store the normalized alert
        alert_store.add_alert(normalized)
        
        logger.info(
            f"Alert processed successfully: {normalized.alert_id} | "
            f"Type: {normalized.alert_type} | "
            f"Severity: {normalized.severity} | "
            f"IoCs: {len(normalized.iocs)}"
        )
        
        return WebhookResponse(
            alert_id=normalized.alert_id,
            alert_type=normalized.alert_type.value,
            severity=normalized.severity.value,
            status=normalized.status.value,
            ioc_count=len(normalized.iocs),
        )
        
    except Exception as e:
        logger.error(f"Failed to process alert: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to normalize alert: {str(e)}",
        )


@router.post(
    "/alerts/bulk",
    response_model=BulkWebhookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Receive Multiple SIEM Alerts",
    description="Receives multiple alerts in a single request for batch processing.",
)
async def receive_bulk_alerts(request: BulkWebhookRequest) -> BulkWebhookResponse:
    """Receive and process multiple SIEM alerts in one request.
    
    Useful for batch replay of historical alerts or high-volume SIEM integration.
    Each alert is processed independently — failures don't affect other alerts.
    
    Args:
        request: Batch request containing source and list of alert payloads.
        
    Returns:
        BulkWebhookResponse with success/failure counts and alert IDs.
    """
    alert_ids = []
    errors = []
    
    for i, payload in enumerate(request.alerts):
        try:
            normalized = normalize_alert(
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
