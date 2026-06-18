import os
import tempfile
from queue import Queue

import pytest

import app as aml_app


@pytest.fixture()
def client():
    aml_app.app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret",
        DATABASE=str(aml_app.TestingConfig.DATABASE_URL),
    )
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


def test_mysql_database_url_uses_mysql_schema():
    original_database = aml_app.app.config["DATABASE"]
    aml_app.app.config["DATABASE"] = "mysql://aml:aml123@localhost:3306/aml"
    try:
        assert aml_app.is_mysql_database_url(aml_app.app.config["DATABASE"])
        schema = aml_app.get_schema_sql()
        assert "AUTO_INCREMENT" in schema
        assert "VARCHAR(255) UNIQUE NOT NULL" in schema
    finally:
        aml_app.app.config["DATABASE"] = original_database


def test_database_adapter_translates_placeholders_for_mysql():
    adapter = aml_app.DatabaseAdapter(connection=None, engine="mysql")
    assert adapter.normalize_query("SELECT * FROM users WHERE email = ? AND id_number = ?") == (
        "SELECT * FROM users WHERE email = %s AND id_number = %s"
    )


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
    with aml_app.app.app_context():
        receiver_account = aml_app.get_user_by_username("receiver")["account_number"]

    client.post(
        "/login",
        data={"email": "sender@example.com", "id_number": "63-1111111A11", "password": "secret123"},
        follow_redirects=True,
    )

    response = client.post(
        "/customer/transaction",
        data={"type": "transfer", "recipient": receiver_account, "amount": "1500"},
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
    with aml_app.app.app_context():
        receiver2_account = aml_app.get_user_by_username("receiver2")["account_number"]
    client.post(
        "/login",
        data={"email": "sender2@example.com", "id_number": "63-3333333A33", "password": "secret123"},
        follow_redirects=True,
    )
    client.post(
        "/customer/transaction",
        data={"type": "transfer", "recipient": receiver2_account, "amount": "1500"},
        follow_redirects=True,
    )

    client.post(
        "/logout",
        follow_redirects=True,
    )
    client.post(
        "/login",
        data={"login": "Compliance", "password": "Compliance123"},
        follow_redirects=True,
    )

    response = client.get("/reports")
    assert response.status_code == 200
    assert b"Alert history" in response.data
    assert b"Suspicious transactions" in response.data


def test_staff_login_requires_reserved_username(client):
    response = client.post(
        "/login",
        data={"login": "Admin", "password": "Admin123"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Administrative Control Center" in response.data

    client.get("/logout", follow_redirects=True)
    rejected = client.post(
        "/login",
        data={"email": "admin@example.com", "id_number": "63-1000001A01", "password": "Admin123"},
        follow_redirects=True,
    )
    assert rejected.status_code == 200
    assert b"Administrative Control Center" not in rejected.data
    assert b"Invalid credentials" in rejected.data or b"All fields are required" in rejected.data


def test_registration_cannot_create_staff_role(client):
    response = client.post(
        "/register",
        data={
            "username": "fakeofficer",
            "email": "fakeofficer@example.com",
            "id_number": "63-5555555A55",
            "password": "secret123",
            "role": "admin",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    with client.session_transaction() as session:
        otp = session["pending_registration"]["otp"]

    client.post("/register", data={"otp": otp}, follow_redirects=True)
    with aml_app.app.app_context():
        user = aml_app.get_user_by_username("fakeofficer")
        assert user["role"] == "customer"
