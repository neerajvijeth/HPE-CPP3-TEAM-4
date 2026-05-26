import os
import pytest

os.environ["SECRET_KEY"] = "test-secret-key-32-bytes-exactly!"
os.environ["VAULT_ENCRYPTION_KEY"] = "XF9BwFdxj1L7rClNczN/E7s3nkOD1MdGz0s8GV5PKQE="
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["DEBUG"] = "False"

from app import create_app, db as _db
from app.models.user import User
from app.models.vault import VaultEntry
from app.models.audit import AuditLog
from app.utils.crypto import encrypt_password


# ROOT CAUSE OF ALL FAILURES:
#
# The original conftest used a SESSION-scoped `app` fixture (one app for all 110 tests)
# with a FUNCTION-scoped `clean_db` fixture (delete+reinsert users before each test).
#
# SQLAlchemy maintains an *identity map* — a per-session cache of loaded objects keyed
# by primary key. When clean_db deleted and re-inserted admin (id=1) and alice (id=2),
# the identity map still held the OLD Python objects from the previous test. On the next
# login request, `User.query.filter_by(username='alice').first()` could return the cached
# stale object, causing `login_user()` to log in the WRONG user. The symptom was alice's
# session containing admin's user_id (1), giving her full admin access; and the `client`
# fixture receiving an admin session it never asked for.
#
# FIX: Change `app` to FUNCTION scope. Each test now gets a completely fresh Flask app,
# a brand-new SQLAlchemy engine bound to a new in-memory SQLite database, and a clean
# identity map. There is zero state leakage between tests.
#
# Trade-off: slightly slower (db.create_all runs per test) but 100% correct isolation.


@pytest.fixture(scope="function")
def app():
    """Fresh Flask app + in-memory database for every single test."""
    test_app = create_app()
    test_app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test-secret-key-32-bytes-exactly!",
        "VAULT_ENCRYPTION_KEY": "XF9BwFdxj1L7rClNczN/E7s3nkOD1MdGz0s8GV5PKQE=",
        "LOGGING_ENABLED": True,
        "MAX_LOGIN_ATTEMPTS": 5,
        "LOGIN_LOCKOUT_MINUTES": 15,
    })
    with test_app.app_context():
        _db.create_all()
        yield test_app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture(scope="function", autouse=True)
def clean_db(app):
    """Seed the fresh database before every test."""
    admin = User(username="admin", email="admin@test.com", role="admin")
    admin.set_password("Admin@Test123!")
    _db.session.add(admin)

    alice = User(username="alice", email="alice@test.com", role="user")
    alice.set_password("Alice@Test123!")
    _db.session.add(alice)

    bob = User(username="bob", email="bob@test.com", role="user")
    bob.set_password("Bob@Test456!")
    _db.session.add(bob)

    _db.session.flush()

    _db.session.add_all([
        VaultEntry(
            user_id=alice.id, site_name="Gmail",
            site_url="https://gmail.com", username="alice@gmail.com",
            password=encrypt_password("alicesecret123"), notes="Personal email"
        ),
        VaultEntry(
            user_id=alice.id, site_name="GitHub",
            site_url="https://github.com", username="alice_dev",
            password=encrypt_password("githubPass456"),
        ),
        VaultEntry(
            user_id=bob.id, site_name="Twitter",
            site_url="https://twitter.com", username="bob_tweets",
            password=encrypt_password("twitter123"),
        ),
    ])
    _db.session.commit()
    yield


@pytest.fixture(scope="function")
def client(app, clean_db):
    """Fresh unauthenticated test client."""
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess.clear()
        yield c


@pytest.fixture(scope="function")
def logged_in_alice(app, clean_db):
    """Fresh client logged in as alice."""
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess.clear()
        c.post("/login", data={
            "username": "alice", "password": "Alice@Test123!"
        }, follow_redirects=True)
        yield c


@pytest.fixture(scope="function")
def logged_in_bob(app, clean_db):
    """Fresh client logged in as bob."""
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess.clear()
        c.post("/login", data={
            "username": "bob", "password": "Bob@Test456!"
        }, follow_redirects=True)
        yield c


@pytest.fixture(scope="function")
def logged_in_admin(app, clean_db):
    """Fresh client logged in as admin."""
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess.clear()
        c.post("/login", data={
            "username": "admin", "password": "Admin@Test123!"
        }, follow_redirects=True)
        yield c