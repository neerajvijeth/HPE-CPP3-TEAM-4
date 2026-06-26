def test_security_headers_are_applied(client):
    response = client.get("/login")

    assert response.status_code == 200
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]


def test_json_error_handler_for_api_routes(client):
    response = client.get("/secdebt/api/missing", headers={"Accept": "application/json"})

    assert response.status_code == 404
    assert response.get_json() == {"error": "Not found"}


def test_options_requests_are_rejected_when_csrf_hooks_enabled(client):
    response = client.open("/login", method="OPTIONS")

    assert response.status_code == 405


def test_csrf_rejects_state_changing_request_without_token(app, client):
    app.config["WTF_CSRF_ENABLED"] = True

    response = client.post("/login", data={
        "username": "alice",
        "password": "Alice@Test123!",
    })

    assert response.status_code == 400
    assert b"Bad request" in response.data
