from app import db
from app.models.audit import AuditLog
from flask import current_app
import logging

# FIX A09: Python standard logger for system-level events
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("securevault")


def log_event(action, user_id=None, details=None, ip_address=None, status="success"):
    """
    FIX A09: Always log security events to both database and file.
    Every login attempt, vault access, and admin action is recorded.

    Uses db.session.commit() so the audit row is immediately persisted to the
    database regardless of what the calling route does afterward. This is
    intentional — audit logs must never be silently lost because a route
    didn't happen to commit after calling log_event().
    """
    try:
        log = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=ip_address,
            status=status
        )
        db.session.add(log)
        db.session.commit()

        # Also write to the application log file / stdout
        log_msg = f"ACTION={action} USER={user_id} IP={ip_address} STATUS={status}"
        if details:
            log_msg += f" DETAILS={details}"

        if status == "failure":
            logger.warning(log_msg)
        else:
            logger.info(log_msg)

    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")