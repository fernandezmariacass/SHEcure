from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from app import db, limiter
from app.models.user import User, AllowedIP
from app.models.logs import AccessLog, ActivityLog, UnauthorizedAlert, NetworkDevice, AdminAuditLog
from app.utils.security import admin_required, _get_real_ip
from app.utils.email_utils import send_2fa_reset_email
from app.models.logs import now_pst
import secrets
from datetime import timedelta

admin_bp = Blueprint("admin", __name__)


def _audit(action, target_user=None, detail=""):
    """Write a tamper-evident AdminAuditLog entry for every destructive admin action."""
    try:
        entry = AdminAuditLog(
            actor_id=current_user.id,
            actor_username=current_user.username,
            action=action,
            target_id=target_user.id if target_user else None,
            target_username=target_user.username if target_user else None,
            ip_address=_get_real_ip(),
            user_agent=request.user_agent.string[:512],
            detail=detail[:500],
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        import logging
        logging.getLogger(__name__).error("[audit] failed to write audit log: %s", e)


@admin_bp.route("/")
@login_required
@admin_required
@limiter.limit("60 per minute")
def panel():
    from app.models.user import BlockedIP, ADMIN_LIMIT
    from app.utils.security import is_ip_allowed, _get_real_ip
    users = User.query.order_by(User.created_at.desc()).all()
    ips = AllowedIP.query.order_by(AllowedIP.created_at.desc()).all()
    pending = User.query.filter_by(is_approved=False).count()
    alerts = UnauthorizedAlert.query.filter_by(resolved=False).count()
    blocked = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    admin_count = User.query.filter_by(role="admin").count()
    ip_allowed = is_ip_allowed(_get_real_ip())
    devices = NetworkDevice.query.order_by(NetworkDevice.last_seen.desc()).all()
    return render_template("admin/panel.html", users=users, ips=ips,
                           pending=pending, alerts=alerts, blocked_ips=blocked,
                           admin_count=admin_count, admin_limit=ADMIN_LIMIT,
                           ip_allowed=ip_allowed, network_devices=devices)


@admin_bp.route("/users/<int:user_id>/approve", methods=["POST"])
@login_required
@admin_required
@limiter.limit("30 per minute")
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == "admin":
        flash("Admin accounts cannot be approved through this panel.", "danger")
        return redirect(url_for("admin.panel"))
    user.is_approved = True
    if not user.totp_enabled:
        user.require_2fa_setup = True
    db.session.commit()
    _audit("approve_user", target_user=user, detail=f"Account approved; 2FA setup required: {not user.totp_enabled}")
    flash(f"{user.username} approved.", "success")
    return redirect(url_for("admin.panel"))


@admin_bp.route("/users/<int:user_id>/revoke", methods=["POST"])
@login_required
@admin_required
@limiter.limit("30 per minute")
def revoke_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot revoke your own access.", "danger")
        return redirect(url_for("admin.panel"))
    if user.role == "admin":
        flash("Admin access cannot be revoked directly. Remove admin role first.", "danger")
        return redirect(url_for("admin.panel"))
    user.is_approved = False
    db.session.commit()
    _audit("revoke_user", target_user=user, detail="Account access revoked")
    flash(f"{user.username} access revoked.", "warning")
    return redirect(url_for("admin.panel"))


@admin_bp.route("/users/<int:user_id>/unlock", methods=["POST"])
@login_required
@admin_required
@limiter.limit("30 per minute")
def unlock_user(user_id):
    """Clear failed login logs for a user so they are no longer locked out."""
    user = User.query.get_or_404(user_id)
    AccessLog.query.filter(
        AccessLog.username_attempted == user.username,
        AccessLog.status == "failed",
    ).delete()
    db.session.commit()
    _audit("unlock_user", target_user=user, detail="Failed login lockout cleared")
    flash(f"{user.username}'s lockout cleared — they can now log in.", "success")
    return redirect(url_for("admin.panel"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
@limiter.limit("10 per minute")
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin.panel"))
    if user.role == "admin":
        flash("Admin accounts cannot be deleted. Revoke admin role first.", "danger")
        return redirect(url_for("admin.panel"))
    try:
        AllowedIP.query.filter_by(added_by=user.id).update({"added_by": None})
        AccessLog.query.filter_by(user_id=user.id).delete()
        ActivityLog.query.filter_by(user_id=user.id).delete()
        _audit("delete_user", target_user=user, detail=f"User account permanently deleted (email: {user.email})")
        db.session.delete(user)
        db.session.commit()
        flash("User deleted.", "danger")
    except Exception as e:
        db.session.rollback()
        flash(f"Could not delete user: {e}", "danger")
    return redirect(url_for("admin.panel"))


@admin_bp.route("/users/<int:user_id>/reset-2fa", methods=["POST"])
@login_required
@admin_required
@limiter.limit("10 per minute")
def reset_2fa(user_id):
    """Admin-only: send the user a confirmation email with a link to reset their 2FA."""
    from flask import request as _req
    from flask_login import current_user as _cu
    user = User.query.get_or_404(user_id)
    token = secrets.token_urlsafe(32)
    user.reset_2fa_token        = token
    user.reset_2fa_token_expiry = now_pst() + timedelta(hours=24)
    db.session.commit()
    confirm_url = _req.host_url.rstrip("/") + f"/confirm-2fa-reset/{token}"
    try:
        send_2fa_reset_email(
            user,
            admin_username=_cu.username,
            timestamp=now_pst().strftime("%Y-%m-%d %H:%M:%S"),
            confirm_url=confirm_url,
        )
        _audit("reset_2fa", target_user=user, detail="2FA reset confirmation email sent")
        flash(f"A confirmation email has been sent to {user.username}.", "info")
    except Exception:
        flash(f"Could not send email to {user.username}. Check mail settings.", "danger")
    return redirect(url_for("admin.panel"))


@admin_bp.route("/users/<int:user_id>/require-2fa", methods=["POST"])
@login_required
@admin_required
@limiter.limit("30 per minute")
def require_2fa(user_id):
    """Admin-only: mark a user as required to set up 2FA on next login."""
    user = User.query.get_or_404(user_id)
    user.require_2fa_setup = True
    db.session.commit()
    _audit("require_2fa", target_user=user, detail="Admin flagged user to set up 2FA on next login")
    flash(f"{user.username} will be prompted to set up 2FA on their next login.", "info")
    return redirect(url_for("admin.panel"))


@admin_bp.route("/ip/add", methods=["POST"])
@login_required
@admin_required
@limiter.limit("30 per minute")
def add_ip():
    from flask_login import current_user
    ip = request.form.get("ip_address", "").strip()
    label = request.form.get("label", "").strip()
    if not ip:
        flash("IP address required.", "danger")
        return redirect(url_for("admin.panel"))
    if AllowedIP.query.filter_by(ip_address=ip).first():
        flash("IP already in allow-list.", "warning")
        return redirect(url_for("admin.panel"))
    entry = AllowedIP(ip_address=ip, label=label, added_by=current_user.id)
    db.session.add(entry)
    db.session.commit()
    _audit("add_ip", detail=f"IP {ip} added to allow-list (label: {label or 'none'})")
    flash(f"IP {ip} added to allow-list.", "success")
    return redirect(url_for("admin.panel"))


@admin_bp.route("/ip/<int:ip_id>/delete", methods=["POST"])
@login_required
@admin_required
@limiter.limit("30 per minute")
def delete_ip(ip_id):
    entry = AllowedIP.query.get_or_404(ip_id)
    _audit("delete_ip", detail=f"IP {entry.ip_address} removed from allow-list (label: {entry.label or 'none'})")
    db.session.delete(entry)
    db.session.commit()
    flash("IP removed from allow-list.", "info")
    return redirect(url_for("admin.panel"))


@admin_bp.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
@login_required
@admin_required
@limiter.limit("30 per minute")
def resolve_alert(alert_id):
    alert = UnauthorizedAlert.query.get_or_404(alert_id)
    alert.resolved = True
    db.session.commit()
    return jsonify({"ok": True})


@admin_bp.route("/logs")
@login_required
@admin_required
@limiter.limit("30 per minute")
def logs():
    access = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(500).all()
    return render_template("admin/logs.html", logs=access)


@admin_bp.route("/audit-log")
@login_required
@admin_required
@limiter.limit("30 per minute")
def audit_log():
    from app.models.logs import AdminAuditLog
    logs = AdminAuditLog.query.order_by(AdminAuditLog.timestamp.desc()).limit(500).all()
    return render_template("admin/audit.html", logs=logs)


@admin_bp.route("/test-email", methods=["POST"])
@login_required
@admin_required
@limiter.limit("5 per minute")
def test_email():
    from flask_login import current_user
    from app.utils.email_utils import _send_email
    _send_email(
        current_user.email,
        "SHEcure Test Email",
        "<h2>It works!</h2><p>SMTP is configured correctly.</p>"
    )
    flash(f"Test email sent to {current_user.email} — check your inbox and Railway logs.", "info")
    return redirect(url_for("admin.panel"))


# ── Step 4: Log purge endpoint ────────────────────────────────────────────────

@admin_bp.route("/purge-logs", methods=["POST"])
@login_required
@admin_required
@limiter.limit("5 per minute")
def purge_logs():
    """Delete log entries older than 90 days."""
    from app.utils.db_cleanup import purge_old_logs
    result = purge_old_logs(days=90)
    total = result["access_logs_deleted"] + result["activity_logs_deleted"] + result["alerts_deleted"]
    if total == 0:
        flash(
            f"No old logs to delete. All logs are within the last 90 days (cutoff: {result['cutoff_date']}).",
            "info"
        )
    else:
        flash(
            f"Old logs purged successfully. "
            f"Access logs: {result['access_logs_deleted']}, "
            f"Activity logs: {result['activity_logs_deleted']}, "
            f"Alerts: {result['alerts_deleted']}. "
            f"Cutoff: {result['cutoff_date']}",
            "success"
        )
    return redirect(url_for("admin.panel"))


# ── Honeypot blocklist management ─────────────────────────────────────────────

@admin_bp.route("/blocked-ips")
@login_required
@admin_required
@limiter.limit("30 per minute")
def blocked_ips():
    from app.models.user import BlockedIP
    blocks = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    return jsonify([
        {
            "id": b.id,
            "ip": b.ip_address,
            "reason": b.reason,
            "blocked_at": b.blocked_at.strftime("%Y-%m-%d %H:%M:%S") + " PST",
            "expires_at": b.expires_at.strftime("%Y-%m-%d %H:%M:%S") + " PST" if b.expires_at else "permanent",
            "active": b.is_currently_blocked(),
        }
        for b in blocks
    ])


@admin_bp.route("/blocked-ips/<int:block_id>/unblock", methods=["POST"])
@login_required
@admin_required
@limiter.limit("30 per minute")
def unblock_ip_route(block_id):
    from app.models.user import BlockedIP
    entry = BlockedIP.query.get_or_404(block_id)
    entry.is_active = False
    db.session.commit()
    _audit("unblock_ip", detail=f"IP {entry.ip_address} manually unblocked by admin")
    flash(f"IP {entry.ip_address} has been unblocked.", "success")
    return redirect(url_for("admin.panel"))


@admin_bp.route("/blocked-ips/unblock-by-ip", methods=["POST"])
@login_required
@admin_required
@limiter.limit("30 per minute")
def unblock_by_ip_string():
    """Unblock a specific IP by value (not DB row id)."""
    from app.models.user import BlockedIP
    from app.utils.security import _INMEMORY_BANNED_IPS

    ip = request.form.get("ip_address", "").strip()
    if not ip:
        flash("No IP address provided.", "danger")
        return redirect(url_for("admin.panel"))

    entry = BlockedIP.query.filter_by(ip_address=ip).first()
    if entry:
        entry.is_active = False
        db.session.commit()
        _INMEMORY_BANNED_IPS.discard(ip)
        _audit("unblock_ip", detail=f"IP {ip} unblocked by string lookup (DB + in-memory)")
        flash(
            f"✓ IP {ip} has been unblocked. "
            f"DB record cleared and in-memory ban removed.",
            "success",
        )
    else:
        _INMEMORY_BANNED_IPS.discard(ip)
        _audit("unblock_ip", detail=f"IP {ip} cleared from in-memory ban (no DB record found)")
        flash(
            f"IP {ip} was not found in the blocklist (may have expired or "
            f"the ban was memory-only). In-memory entry cleared.",
            "warning",
        )

    return redirect(url_for("admin.panel"))
