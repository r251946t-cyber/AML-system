import os
import tempfile
from queue import Queue

import pytest

import app as aml_app


@pytest.fixture()
def client():
    aml_app.app.config.update(TESTING=True, SECRET_KEY="test-secret")
    if os.path.exists(aml_app.app.config["DATABASE"]):
        try:
            os.remove(aml_app.app.config["DATABASE"])
        except PermissionError:
            pass
    with aml_app.app.test_client() as client:
        with aml_app.app.app_context():
            aml_app.init_db()
            aml_app.seed_demo_data()
        yield client


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert b"ok" in response.data.lower()


def test_register_and_login(client):
    response = client.post(
        "/register",
        data={
            "username": "newuser",
            "email": "newuser@example.com",
            "id_number": "631234567a47",
            "password": "secret123",
            "role": "customer",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"verification code" in response.data.lower()

    with client.session_transaction() as session:
        pending = session["pending_registration"]
        otp = pending["otp"]

    verified = client.post(
        "/register",
        data={"otp": otp},
        follow_redirects=True,
    )
    assert verified.status_code == 200
    assert b"Customer" in verified.data or b"Banking" in verified.data

    login = client.post(
        "/login",
        data={"email": "newuser@example.com", "id_number": "631234567a47", "password": "secret123"},
        follow_redirects=True,
    )
    assert login.status_code == 200
    assert b"Customer" in login.data or b"Banking" in login.data


def test_register_and_login_accepts_six_digit_id_body(client):
    response = client.post(
        "/register",
        data={
            "username": "sixdigit",
            "email": "sixdigit@example.com",
            "id_number": "08995728p34",
            "password": "secret123",
            "role": "customer",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"verification code" in response.data.lower()

    with client.session_transaction() as session:
        otp = session["pending_registration"]["otp"]
        assert session["pending_registration"]["id_number"] == "08-995728P34"

    client.post(
        "/register",
        data={"otp": otp},
        follow_redirects=True,
    )

    login = client.post(
        "/login",
        data={"email": "sixdigit@example.com", "id_number": "08-995728P34", "password": "secret123"},
        follow_redirects=True,
    )
    assert login.status_code == 200
    assert b"Customer" in login.data or b"Banking" in login.data


def test_register_rejects_invalid_id_format(client):
    response = client.post(
        "/register",
        data={
            "username": "badid",
            "email": "badid@example.com",
            "id_number": "123456789",
            "password": "secret123",
            "role": "customer",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"00-000000A00" in response.data


def test_high_value_transfer_creates_alert(client):
    client.post(
        "/register",
        data={"username": "sender", "email": "sender@example.com", "id_number": "63-1111111A11", "password": "secret123", "role": "customer"},
        follow_redirects=True,
    )
    with client.session_transaction() as session:
        sender_otp = session["pending_registration"]["otp"]
    client.post(
        "/register",
        data={"otp": sender_otp},
        follow_redirects=True,
    )

    client.post(
        "/register",
        data={"username": "receiver", "email": "receiver@example.com", "id_number": "63-2222222A22", "password": "secret123", "role": "customer"},
        follow_redirects=True,
    )
    with client.session_transaction() as session:
        receiver_otp = session["pending_registration"]["otp"]
    client.post(
        "/register",
        data={"otp": receiver_otp},
        follow_redirects=True,
    )

    client.post(
        "/login",
        data={"email": "sender@example.com", "id_number": "63-1111111A11", "password": "secret123"},
        follow_redirects=True,
    )

    response = client.post(
        "/customer/transaction",
        data={"type": "transfer", "recipient": "receiver", "amount": "1500"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"high risk" in response.data.lower() or b"suspicious" in response.data.lower()


def test_stream_endpoint_is_available(client):
    response = client.get("/stream")
    assert response.status_code == 200
    assert "text/event-stream" in response.content_type


def test_transaction_processing_emits_live_events(client):
    with aml_app.app.app_context():
        conn = aml_app.get_db()
        queue = Queue()
        aml_app.app.config.setdefault("STREAM_SUBSCRIBERS", []).append(queue)
        conn.execute(
            """
            INSERT INTO transactions (
                sender_account, receiver_account, amount, transaction_type,
                timestamp, status, risk_score, risk_level, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("ACC1001", "ACC1002", 1500, "transfer", "2026-06-13T00:00:00+00:00", "Completed", 0, "normal", "Test transaction"),
        )
        conn.commit()
        transaction_id = conn.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

        aml_app.process_transaction_event(
            conn,
            transaction_id,
            "ACC1001",
            "ACC1002",
            1500,
            "transfer",
            "2026-06-13T00:00:00+00:00",
            account_number="ACC1001",
        )

        event = queue.get_nowait()
        assert event["event"] == "transaction"


def test_reports_show_alert_history(client):
    client.post(
        "/register",
        data={"username": "sender2", "email": "sender2@example.com", "id_number": "63-3333333A33", "password": "secret123", "role": "customer"},
        follow_redirects=True,
    )
    with client.session_transaction() as session:
        sender2_otp = session["pending_registration"]["otp"]
    client.post(
        "/register",
        data={"otp": sender2_otp},
        follow_redirects=True,
    )

    client.post(
        "/register",
        data={"username": "receiver2", "email": "receiver2@example.com", "id_number": "63-4444444A44", "password": "secret123", "role": "customer"},
        follow_redirects=True,
    )
    with client.session_transaction() as session:
        receiver2_otp = session["pending_registration"]["otp"]
    client.post(
        "/register",
        data={"otp": receiver2_otp},
        follow_redirects=True,
    )
    client.post(
        "/login",
        data={"email": "sender2@example.com", "id_number": "63-3333333A33", "password": "secret123"},
        follow_redirects=True,
    )
    client.post(
        "/customer/transaction",
        data={"type": "transfer", "recipient": "receiver2", "amount": "1500"},
        follow_redirects=True,
    )

    client.post(
        "/logout",
        follow_redirects=True,
    )
    client.post(
        "/login",
        data={"email": "compliance@example.com", "id_number": "63-1000002A02", "password": "compliance123"},
        follow_redirects=True,
    )

    response = client.get("/reports")
    assert response.status_code == 200
    assert b"Alert history" in response.data
    assert b"Suspicious transactions" in response.data
