from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required
from app import db
from app.models.user import User, AllowedIP
from app.models.logs import AccessLog, ActivityLog, UnauthorizedAlert
from app.utils.security import admin_required

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/")
@login_required
@admin_required
def panel():
    users = User.query.order_by(User.created_at.desc()).all()
    ips = AllowedIP.query.order_by(AllowedIP.created_at.desc()).all()
    pending = User.query.filter_by(is_approved=False).count()
    alerts = UnauthorizedAlert.query.filter_by(resolved=False).count()
    return render_template("admin/panel.html", users=users, ips=ips,
                           pending=pending, alerts=alerts)


@admin_bp.route("/users/<int:user_id>/approve", methods=["POST"])
@login_required
@admin_required
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_approved = True
    db.session.commit()
    flash(f"{user.username} approved.", "success")
    return redirect(url_for("admin.panel"))


@admin_bp.route("/users/<int:user_id>/revoke", methods=["POST"])
@login_required
@admin_required
def revoke_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_approved = False
    db.session.commit()
    flash(f"{user.username} access revoked.", "warning")
    return redirect(url_for("admin.panel"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f"User deleted.", "danger")
    return redirect(url_for("admin.panel"))


@admin_bp.route("/ip/add", methods=["POST"])
@login_required
@admin_required
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
    flash(f"IP {ip} added to allow-list.", "success")
    return redirect(url_for("admin.panel"))


@admin_bp.route("/ip/register-mine", methods=["POST"])
@login_required
@admin_required
def register_my_ip():
    from flask_login import current_user
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip:
        ip = ip.split(",")[0].strip()

    if not ip:
        flash("Could not detect your IP.", "danger")
        return redirect(url_for("admin.panel"))

    existing = AllowedIP.query.filter_by(ip_address=ip).first()
    if existing:
        existing.is_active = True
        existing.label = f"Auto: {current_user.username}"
        db.session.commit()
        flash(f"Your IP {ip} is already allowed (re-activated).", "info")
        return redirect(url_for("admin.panel"))

    # Deactivate previous auto-registered IPs for this admin to keep list clean
    old = AllowedIP.query.filter(
        AllowedIP.label.like(f"Auto: {current_user.username}%"),
        AllowedIP.ip_address != ip
    ).all()
    for entry in old:
        db.session.delete(entry)

    entry = AllowedIP(ip_address=ip, label=f"Auto: {current_user.username}", added_by=current_user.id)
    db.session.add(entry)
    db.session.commit()
    flash(f"Your current IP ({ip}) has been added to the allowlist.", "success")
    return redirect(url_for("admin.panel"))



@login_required
@admin_required
def delete_ip(ip_id):
    entry = AllowedIP.query.get_or_404(ip_id)
    db.session.delete(entry)
    db.session.commit()
    flash("IP removed from allow-list.", "info")
    return redirect(url_for("admin.panel"))


@admin_bp.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
@login_required
@admin_required
def resolve_alert(alert_id):
    alert = UnauthorizedAlert.query.get_or_404(alert_id)
    alert.resolved = True
    db.session.commit()
    return jsonify({"ok": True})


@admin_bp.route("/logs")
@login_required
@admin_required
def logs():
    access = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(500).all()
    return render_template("admin/logs.html", logs=access)
