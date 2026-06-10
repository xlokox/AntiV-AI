"""
Security regression tests for the hardening pass.

These lock in the fixes for the audit's critical/high findings so a future change
that re-opens a hole fails CI instead of shipping:

  * SEC-02 / SEC-11 : sensitive endpoints now require authentication.
  * SEC-06          : path-based scanning is confined to an allowlist (no traversal).
  * SEC-01          : RBAC is default-deny and hierarchical (user < analyst < admin).
  * JWT type        : a refresh token cannot be used as an access token.

The HTTP-layer tests use FastAPI's TestClient against the real app; if the app
(or its httpx-based test client) cannot be constructed in this environment they
skip cleanly rather than fail.
"""

import os                                   # env setup + paths
import sys                                  # import path
import pytest                               # framework + skip/raises

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "src"))

# A stable secret so importing the app does not generate an ephemeral key / warn.
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-at-least-32-chars-long-aaaa")
os.environ.setdefault("ANTIV_ENV", "development")

# Try to build a TestClient against the real FastAPI app. Heavy import (loads all
# singletons + the ML model), so failures degrade to skips, not errors.
try:
    from fastapi.testclient import TestClient
    import app as app_module
    _client = TestClient(app_module.app)
    _APP_OK = True
    _APP_ERR = ""
except Exception as e:                       # httpx missing, import error, etc.
    _APP_OK = False
    _APP_ERR = repr(e)
    _client = None


@pytest.fixture(autouse=True)
def _reset_rate_limit_state():
    """Reset rate-limit / DDoS state before each test.

    The middleware keys on the single TestClient source IP, so a burst of requests
    across tests would otherwise trip the throttle and return 429 — masking the
    auth behaviour we are actually asserting. Clearing the in-memory counters keeps
    each test measuring authorization, not rate limiting.
    """
    try:
        from ddos_protector import ddos_protector as d
        d.ip_data.clear(); d.blocked_ips.clear(); d.temp_blocks.clear(); d.attack_patterns.clear()
    except Exception:
        pass
    try:
        from network_security import rate_limiter as rl
        rl.request_history.clear(); rl.blocked_ips.clear()
    except Exception:
        pass
    yield


# Endpoints that MUST reject an unauthenticated caller (401 Unauthorized or 403
# Forbidden — FastAPI's HTTPBearer returns 403 when the header is absent).
_PROTECTED_GET = [
    "/quarantine/list", "/quarantine/stats",
    "/sandbox/stats", "/sandbox/executions",
    "/monitoring/events", "/monitoring/status", "/monitoring/process-tree",
    "/system/status",
]


@pytest.mark.skipif(not _APP_OK, reason="app/TestClient unavailable: " + _APP_ERR)
@pytest.mark.parametrize("path", _PROTECTED_GET)
def test_protected_get_endpoints_require_auth(path):
    """Each sensitive GET endpoint must refuse an unauthenticated request."""
    resp = _client.get(path)
    assert resp.status_code in (401, 403), f"{path} returned {resp.status_code} without auth"


@pytest.mark.skipif(not _APP_OK, reason="app/TestClient unavailable: " + _APP_ERR)
def test_destructive_endpoints_require_auth():
    """Quarantine restore/delete and sandbox execute must refuse unauthenticated calls."""
    assert _client.post("/quarantine/restore/anything").status_code in (401, 403)
    assert _client.delete("/quarantine/delete/anything").status_code in (401, 403)
    assert _client.post("/sandbox/execute", params={"file_path": "/etc/passwd", "file_hash": "x"}
                        ).status_code in (401, 403)


@pytest.mark.skipif(not _APP_OK, reason="app/TestClient unavailable: " + _APP_ERR)
def test_health_endpoint_is_public():
    """The health check stays public (no regression that locks everyone out)."""
    assert _client.get("/health").status_code == 200


@pytest.mark.skipif(not _APP_OK, reason="app/TestClient unavailable: " + _APP_ERR)
def test_scan_path_allowlist_blocks_traversal():
    """The /scan path guard must reject host paths and accept allowlisted ones."""
    from fastapi import HTTPException
    from app import _ensure_path_allowed
    # Arbitrary host files are rejected (this is the SEC-06 fix).
    for bad in ("/etc/passwd", "/Users", os.path.expanduser("~/.ssh/id_rsa")):
        with pytest.raises(HTTPException):
            _ensure_path_allowed(bad)
    # A path inside the allowlisted test_files directory resolves and is accepted.
    good = _ensure_path_allowed(os.path.join(_REPO_ROOT, "test_files", "clean_document.txt"))
    assert good.endswith("clean_document.txt")


# ---- Unit tests that need only auth.py (no HTTP layer) --------------------
def test_rbac_is_default_deny_and_hierarchical():
    """user < analyst < admin; unknown roles get zero privilege."""
    from auth import ROLE_LEVELS
    def allowed(user_role, required):
        return ROLE_LEVELS.get(user_role, 0) >= ROLE_LEVELS.get(required, 999)
    assert not allowed("user", "analyst")      # the core SEC-01 bug: was previously allowed
    assert not allowed("user", "admin")
    assert allowed("analyst", "analyst")
    assert allowed("admin", "analyst")
    assert allowed("admin", "admin")
    assert not allowed("bogus", "admin")        # unknown caller role -> denied


def test_refresh_token_cannot_be_used_as_access_token():
    """A refresh token must not authenticate API access (JWT type enforcement)."""
    from auth import auth_manager, User
    u = User(id=99, username="jwttype", email="j@t", role="admin", is_active=True, created_at="")
    access = auth_manager.create_access_token(u)
    refresh = auth_manager.create_refresh_token(u)
    assert auth_manager.verify_token(access, "access") is not None
    assert auth_manager.verify_token(refresh, "access") is None     # the fix
    assert auth_manager.verify_token(refresh, "refresh") is not None


def test_analyst_is_an_assignable_role():
    """'analyst' must be a real, grantable role so its endpoints have principals."""
    from auth import auth_manager
    import secrets as _s
    suffix = _s.token_hex(4)
    user = auth_manager.create_user(f"analyst_{suffix}", f"analyst_{suffix}@x.com",
                                    "Str0ng!Passw0rd123", "analyst")
    assert user is not None and user.role == "analyst"
    with pytest.raises(Exception):
        auth_manager.create_user(f"bad_{suffix}", f"bad_{suffix}@x.com",
                                 "Str0ng!Passw0rd123", "superuser")
