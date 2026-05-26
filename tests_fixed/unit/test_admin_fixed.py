"""
Unit tests for Fixed Admin Panel — routes/admin.py
Proves: @admin_required decorator enforces 403 for non-admins (A01),
admin actions logged (A09).
"""
import pytest
from app.models.audit import AuditLog
from app.models.user import User
from app import db


class TestAdminAccessControlFixed:

    def test_admin_can_access_dashboard(self, logged_in_admin):
        """Admin user must be able to access the dashboard."""
        response = logged_in_admin.get("/admin/dashboard")
        assert response.status_code == 200
        assert b"Admin" in response.data

    def test_regular_user_gets_403_on_dashboard(self, logged_in_alice):
        """FIX A01: Regular user must get 403 on admin dashboard."""
        response = logged_in_alice.get("/admin/dashboard")
        assert response.status_code == 403

    def test_bob_gets_403_on_dashboard(self, logged_in_bob):
        """FIX A01: Bob (regular user) must get 403."""
        response = logged_in_bob.get("/admin/dashboard")
        assert response.status_code == 403

    def test_regular_user_gets_403_on_users_list(self, logged_in_alice):
        """FIX A01: Regular user must NOT see all registered users."""
        response = logged_in_alice.get("/admin/users")
        assert response.status_code == 403

    def test_regular_user_gets_403_on_logs(self, logged_in_alice):
        """FIX A01: Regular user must NOT access audit logs."""
        response = logged_in_alice.get("/admin/logs")
        assert response.status_code == 403

    def test_regular_user_cannot_toggle_accounts(self, logged_in_alice):
        """FIX A01: Regular user must NOT be able to disable other accounts."""
        bob = User.query.filter_by(username="bob").first()
        bob_id = bob.id
        original_status = bob.is_active

        response = logged_in_alice.post(
            f"/admin/users/toggle/{bob_id}",
            follow_redirects=False
        )

        bob_after = User.query.get(bob_id)
        assert response.status_code == 403
        assert bob_after.is_active == original_status

    def test_unauthenticated_redirected_from_admin(self, client):
        """Unauthenticated users must be redirected to login."""
        response = client.get("/admin/dashboard", follow_redirects=True)
        assert b"login" in response.data.lower()

    def test_admin_can_see_all_users(self, logged_in_admin):
        """Admin must see all registered users."""
        response = logged_in_admin.get("/admin/users")
        assert response.status_code == 200
        assert b"alice" in response.data
        assert b"bob" in response.data

    def test_admin_can_toggle_user(self, logged_in_admin):
        """Admin must be able to disable a user account."""
        bob = User.query.filter_by(username="bob").first()
        bob_id = bob.id
        original_status = bob.is_active

        response = logged_in_admin.post(
            f"/admin/users/toggle/{bob_id}",
            follow_redirects=True
        )

        bob_after = User.query.get(bob_id)
        assert response.status_code == 200
        assert bob_after.is_active != original_status

    def test_admin_cannot_disable_own_account(self, logged_in_admin):
        """Admin must NOT be able to disable their own account."""
        admin = User.query.filter_by(username="admin").first()
        response = logged_in_admin.post(
            f"/admin/users/toggle/{admin.id}",
            follow_redirects=True
        )
        assert b"cannot disable your own" in response.data.lower()

    def test_unauthorized_admin_access_logged(self, logged_in_alice):
        """FIX A09: Unauthorized admin access attempts must be logged."""
        logged_in_alice.get("/admin/dashboard")
        log = AuditLog.query.filter_by(
            action="admin_unauthorized_access",
            status="failure"
        ).first()
        assert log is not None

    def test_admin_dashboard_view_logged(self, logged_in_admin):
        """FIX A09: Admin dashboard view must be logged."""
        logged_in_admin.get("/admin/dashboard")
        log = AuditLog.query.filter_by(action="admin_dashboard_view").first()
        assert log is not None

    def test_admin_toggle_user_logged(self, logged_in_admin):
        """FIX A09: Admin toggling a user must be logged."""
        bob = User.query.filter_by(username="bob").first()
        logged_in_admin.post(f"/admin/users/toggle/{bob.id}", follow_redirects=True)
        log = AuditLog.query.filter_by(action="admin_toggle_user").first()
        assert log is not None


class TestAuditLogsFixed:

    def test_audit_logs_page_accessible_to_admin(self, logged_in_admin):
        """FIX A09: Admin must be able to view audit logs page."""
        logged_in_admin.get("/admin/dashboard")
        response = logged_in_admin.get("/admin/logs")
        assert response.status_code == 200

    def test_audit_logs_not_empty_after_activity(self, logged_in_admin):
        """FIX A09: Audit logs must contain entries — not empty like vulnerable version."""
        logged_in_admin.get("/admin/dashboard")
        log_count = AuditLog.query.count()
        assert log_count > 0

    def test_audit_logs_blocked_for_regular_user(self, logged_in_alice):
        """FIX A01: Regular user must not see audit logs."""
        response = logged_in_alice.get("/admin/logs")
        assert response.status_code == 403
