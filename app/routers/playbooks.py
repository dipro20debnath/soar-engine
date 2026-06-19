"""SOAR Engine - Playbook & Containment Router

Provides API endpoints for:
    - Viewing playbook execution history
    - Listing registered playbooks
    - Managing the firewall blocklist
    - Viewing isolated instances
    - Approval/rejection workflow for high-impact actions
    - Notification history
"""

import logging
from fastapi import APIRouter, HTTPException, Query

from app.services.playbook_engine import playbook_engine
from app.containment.firewall import firewall
from app.containment.aws_isolator import aws_isolator
from app.containment.notification import notification_service
from app.db.store import alert_store
from app.models.alert import AlertStatus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Playbooks & Containment"])


# ═════════════════════════════════════════════════════
# Playbook Endpoints
# ═════════════════════════════════════════════════════

@router.get(
    "/playbooks",
    summary="List Registered Playbooks",
    description="View all registered playbooks and their descriptions.",
)
async def list_playbooks() -> dict:
    """List all registered playbooks in the engine."""
    return {
        "success": True,
        "playbooks": playbook_engine.get_registered_playbooks(),
        "total": len(playbook_engine.get_registered_playbooks()),
    }


@router.get(
    "/playbooks/history",
    summary="Playbook Execution History",
    description="View recent playbook executions with actions taken.",
)
async def playbook_history(
    limit: int = Query(default=50, ge=1, le=500, description="Max records"),
) -> dict:
    """Get recent playbook execution history."""
    history = playbook_engine.get_history(limit=limit)
    return {
        "success": True,
        "total": len(history),
        "history": history,
    }


# ═════════════════════════════════════════════════════
# Approval Workflow Endpoints
# ═════════════════════════════════════════════════════

@router.get(
    "/playbooks/pending",
    summary="View Pending Approvals",
    description="View alerts waiting for human approval before high-impact containment actions are executed.",
)
async def pending_approvals() -> dict:
    """Get all alerts currently pending human approval."""
    pending = playbook_engine.get_pending_approvals()
    return {
        "success": True,
        "total": len(pending),
        "pending": pending,
    }


@router.post(
    "/playbooks/approve/{alert_id}",
    summary="Approve Pending Actions",
    description="Approve and execute high-impact containment actions that were deferred for an alert.",
)
async def approve_alert(alert_id: str) -> dict:
    """Approve pending high-impact actions for an alert.

    When a very high-risk alert (risk > 90) has high-impact actions
    like host isolation, those actions are deferred until a human analyst
    approves them. This endpoint executes the deferred actions.
    """
    result = playbook_engine.approve_alert(alert_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"No pending approval found for alert: {alert_id}",
        )

    # Update alert status in store
    alert = alert_store.get_alert(alert_id)
    if alert:
        alert.status = AlertStatus.RESPONDED
        alert.response_actions.extend(result["executed_actions"])
        alert_store.update_alert(alert)

    return {"success": True, **result}


@router.post(
    "/playbooks/reject/{alert_id}",
    summary="Reject Pending Actions",
    description="Reject and discard high-impact containment actions for an alert.",
)
async def reject_alert(alert_id: str) -> dict:
    """Reject pending high-impact actions for an alert.

    The deferred containment actions will be discarded and the alert
    will be marked as closed.
    """
    result = playbook_engine.reject_alert(alert_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"No pending approval found for alert: {alert_id}",
        )

    # Update alert status in store
    alert = alert_store.get_alert(alert_id)
    if alert:
        alert.status = AlertStatus.CLOSED
        alert.tags.append("rejected_by_analyst")
        alert_store.update_alert(alert)

    return {"success": True, **result}


# ═════════════════════════════════════════════════════
# Firewall / Blocklist Endpoints
# ═════════════════════════════════════════════════════

@router.get(
    "/containment/blocklist",
    summary="View IP Blocklist",
    description="View all currently blocked IP addresses in the firewall.",
)
async def get_blocklist() -> dict:
    """Get the full firewall blocklist."""
    blocklist = firewall.get_blocklist()
    return {
        "success": True,
        "blocked_count": firewall.blocked_count,
        "blocklist": blocklist,
    }


@router.post(
    "/containment/block/{ip_address}",
    summary="Block IP Address",
    description="Manually block an IP address in the firewall.",
)
async def block_ip(ip_address: str) -> dict:
    """Manually block an IP in the firewall."""
    was_blocked = firewall.block_ip(ip_address, reason="manual_block")
    if not was_blocked:
        return {
            "success": True,
            "message": f"IP {ip_address} is already blocked",
            "already_blocked": True,
        }
    return {
        "success": True,
        "message": f"IP {ip_address} has been blocked",
        "already_blocked": False,
    }


@router.post(
    "/containment/unblock/{ip_address}",
    summary="Unblock IP Address",
    description="Manually remove an IP address from the firewall blocklist.",
)
async def unblock_ip(ip_address: str) -> dict:
    """Manually unblock an IP from the firewall."""
    was_unblocked = firewall.unblock_ip(ip_address, reason="manual_unblock")
    if not was_unblocked:
        raise HTTPException(
            status_code=404,
            detail=f"IP {ip_address} is not in the blocklist",
        )
    return {
        "success": True,
        "message": f"IP {ip_address} has been unblocked",
    }


@router.get(
    "/containment/firewall/log",
    summary="Firewall Action Log",
    description="View recent firewall block/unblock actions.",
)
async def firewall_log(
    limit: int = Query(default=50, ge=1, le=500),
) -> dict:
    """Get the firewall action log."""
    log = firewall.get_action_log(limit=limit)
    return {
        "success": True,
        "total": len(log),
        "actions": log,
    }


# ═════════════════════════════════════════════════════
# AWS Isolator Endpoints
# ═════════════════════════════════════════════════════

@router.get(
    "/containment/isolated",
    summary="View Isolated Instances",
    description="View all currently isolated EC2 instances.",
)
async def get_isolated_instances() -> dict:
    """Get all currently isolated instances."""
    isolated = aws_isolator.get_isolated_instances()
    return {
        "success": True,
        "isolated_count": aws_isolator.isolated_count,
        "instances": isolated,
    }


@router.post(
    "/containment/restore/{instance_id}",
    summary="Restore Isolated Instance",
    description="Restore an isolated EC2 instance to its original security group.",
)
async def restore_instance(instance_id: str) -> dict:
    """Manually restore an isolated instance."""
    was_restored = aws_isolator.restore_instance(
        instance_id, reason="manual_restore"
    )
    if not was_restored:
        raise HTTPException(
            status_code=404,
            detail=f"Instance {instance_id} is not isolated",
        )
    return {
        "success": True,
        "message": f"Instance {instance_id} has been restored",
    }


# ═════════════════════════════════════════════════════
# Notification Endpoints
# ═════════════════════════════════════════════════════

@router.get(
    "/containment/notifications",
    summary="Notification History",
    description="View recent SOC notifications sent by the system.",
)
async def notification_history(
    limit: int = Query(default=50, ge=1, le=500),
) -> dict:
    """Get recent notification history."""
    history = notification_service.get_history(limit=limit)
    return {
        "success": True,
        "total_sent": notification_service.total_sent,
        "notifications": history,
    }


# ═════════════════════════════════════════════════════
# Containment Summary
# ═════════════════════════════════════════════════════

@router.get(
    "/containment/summary",
    summary="Containment Summary",
    description="Overview of all containment actions: blocked IPs, isolated instances, notifications.",
)
async def containment_summary() -> dict:
    """Get a summary of all containment status."""
    return {
        "success": True,
        "firewall": {
            "blocked_ips": firewall.blocked_count,
            "blocklist": firewall.get_blocklist(),
        },
        "isolation": {
            "isolated_instances": aws_isolator.isolated_count,
            "instances": aws_isolator.get_isolated_instances(),
        },
        "notifications": {
            "total_sent": notification_service.total_sent,
        },
        "playbooks": {
            "total_executions": playbook_engine.history_count,
            "pending_approvals": len(playbook_engine.get_pending_approvals()),
        },
    }
