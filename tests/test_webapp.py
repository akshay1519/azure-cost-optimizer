"""Tests for the Flask web application."""

import json
import pytest
from webapp.app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret"
    with app.test_client() as client:
        yield client


class TestPublicPages:
    def test_index(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"Azure Cost Optimizer" in resp.data

    def test_pricing(self, client):
        resp = client.get("/pricing")
        assert resp.status_code == 200
        assert b"Pricing" in resp.data

    def test_health_api(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"


class TestAuth:
    def test_login_page(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"Sign In" in resp.data

    def test_login_success(self, client):
        resp = client.post("/login", data={"email": "test@example.com"}, follow_redirects=True)
        assert resp.status_code == 200

    def test_login_empty_email(self, client):
        resp = client.post("/login", data={"email": ""}, follow_redirects=True)
        assert resp.status_code == 200

    def test_logout(self, client):
        # Login first
        client.post("/login", data={"email": "test@example.com"})
        resp = client.get("/logout", follow_redirects=True)
        assert resp.status_code == 200


class TestDashboard:
    def test_dashboard_requires_login(self, client):
        resp = client.get("/dashboard")
        assert resp.status_code == 302  # Redirect to login

    def test_dashboard_logged_in(self, client):
        client.post("/login", data={"email": "test@example.com"})
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        assert b"Dashboard" in resp.data


class TestAPI:
    def test_api_scan_no_key(self, client):
        resp = client.post("/api/v1/scan", json={"subscription_id": "test"})
        assert resp.status_code == 401

    def test_api_scan_no_subscription(self, client):
        resp = client.post(
            "/api/v1/scan",
            json={},
            headers={"X-API-Key": "test-key"},
        )
        assert resp.status_code == 400
