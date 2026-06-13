import json
import logging
import os
import random
import re
import smtplib
import sqlite3
import threading
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from functools import wraps
from queue import Queue
from urllib.parse import unquote, urlparse

from dotenv import load_dotenv
from flask import Flask, Response, flash, g, redirect, render_template, request, session, url_for
from flask_socketio import SocketIO
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash, generate_password_hash

from aml_logic import analyze_transaction
from config import DevelopmentConfig, ProductionConfig, TestingConfig
from realtime import RealtimeBroker

load_dotenv()

app = Flask(__name__)
app.config.from_object(DevelopmentConfig if os.environ.get("FLASK_ENV") == "development" else ProductionConfig)
if app.config.get("TESTING"):
    app.config.from_object(TestingConfig)
app.config.setdefault("STREAM_SUBSCRIBERS", [])
app.config.setdefault("LAST_MONITORED_TRANSACTION_ID", 0)
app.config.setdefault("REALTIME_POLL_INTERVAL", 0.5)
app.config.setdefault("DATABASE", app.config.get("DATABASE_URL", os.path.join(os.path.dirname(__file__), "aml.db")))

logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

socketio = SocketIO(app, cors_allowed_origins="*")
app.extensions["realtime_broker"] = RealtimeBroker(app=app, socketio=socketio)

ID_NUMBER_PATTERN = re.compile(r"^\d{2}-\d{6,7}[A-Z]\d{2}$")
ID_NUMBER_FORMAT_MESSAGE = "ID number must use the format 00-000000A00, for example 08-995728P34."


class DatabaseAdapter:
    def __init__(self, connection, engine):
        self.connection = connection
        self.engine = engine

    @property
    def is_postgres(self):
        return self.engine == "postgres"

    @property
    def is_mysql(self):
        return self.engine == "mysql"

    def normalize_query(self, query):
        if self.is_postgres or self.is_mysql:
            return query.replace("?", "%s")
        return query

    def execute(self, query, params=()):
        query = self.normalize_query(query)
        if self.is_postgres:
            cursor = self.connection.cursor(cursor_factory=RealDictCursor)
            cursor.execute(query, params)
            return cursor
        if self.is_mysql:
            cursor = self.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(query, params)
            return cursor
        return self.connection.execute(query, params)

    def executescript(self, script):
        if self.is_postgres or self.is_mysql:
            statements = [statement.strip() for statement in script.split(";") if statement.strip()]
            for statement in statements:
                cursor = self.connection.cursor()
                try:
                    cursor.execute(self.normalize_query(statement))
                finally:
                    cursor.close()
            return None
        self.connection.executescript(script)

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()


def is_postgres_database_url(database_url):
    return bool(database_url) and database_url.startswith(("postgres://", "postgresql://"))


def is_mysql_database_url(database_url):
    return bool(database_url) and database_url.startswith(("mysql://", "mysql+mysqlconnector://"))


def connect_db():
    database_url = app.config["DATABASE"]
    if is_postgres_database_url(database_url):
        import psycopg2
        from psycopg2.extras import RealDictCursor

        conn = psycopg2.connect(database_url)
        conn.autocommit = False
        return DatabaseAdapter(conn, "postgres")

    if is_mysql_database_url(database_url):
        import mysql.connector

        parsed_url = urlparse(database_url)
        conn = mysql.connector.connect(
            host=parsed_url.hostname or "localhost",
            port=parsed_url.port or 3306,
            user=unquote(parsed_url.username or ""),
            password=unquote(parsed_url.password or ""),
            database=parsed_url.path.lstrip("/"),
            charset="utf8mb4",
            collation="utf8mb4_unicode_ci",
        )
        return DatabaseAdapter(conn, "mysql")

    conn = sqlite3.connect(database_url)
    conn.row_factory = sqlite3.Row
    return DatabaseAdapter(conn, "sqlite")


def get_db():
    if "db" not in g:
        g.db = connect_db()
    return g.db


@app.before_request
def enforce_security_headers():
    request.environ.setdefault("werkzeug.request", request)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def broadcast_event(event_name, payload):
    app.extensions["realtime_broker"].publish(event_name, payload)


def create_alert_if_needed(conn, transaction_id, account_number, risk_score, risk_level, reason, timestamp):
    existing = conn.execute("SELECT id FROM alerts WHERE transaction_id = ?", (transaction_id,)).fetchone()
    if existing is None and risk_level != "normal":
        conn.execute(
            """
            INSERT INTO alerts (transaction_id, account_number, risk_score, risk_level, reason, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (transaction_id, account_number, risk_score, risk_level, reason, timestamp),
        )
        return True
    return False


def process_transaction_event(
    conn,
    transaction_id,
    sender_account,
    receiver_account,
    amount,
    transaction_type,
    timestamp,
    account_number=None,
    emit_events=True,
):
    risk_score, risk_level, reason = analyze_transaction(
        conn,
        transaction_type,
        amount,
        sender_account,
        receiver_account,
        timestamp,
    )
    conn.execute(
        "UPDATE transactions SET risk_score = ?, risk_level = ?, description = ? WHERE id = ?",
        (risk_score, risk_level, reason, transaction_id),
    )
    created_alert = create_alert_if_needed(
        conn,
        transaction_id,
        account_number or sender_account,
        risk_score,
        risk_level,
        reason,
        timestamp,
    )
    if emit_events:
        broadcast_event(
            "transaction",
            {
                "id": transaction_id,
                "type": transaction_type,
                "amount": amount,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "timestamp": timestamp,
            },
        )
        if created_alert:
            broadcast_event(
                "alert",
                {
                    "transaction_id": transaction_id,
                    "account_number": account_number or sender_account,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "reason": reason,
                    "timestamp": timestamp,
                },
            )
    return risk_score, risk_level, reason, created_alert


def monitor_transactions():
    while not app.config.get("MONITOR_STOP", False):
        try:
            with app.app_context():
                conn = connect_db()
                last_seen_id = app.config.get("LAST_MONITORED_TRANSACTION_ID", 0)
                rows = conn.execute(
                    "SELECT id, sender_account, receiver_account, amount, transaction_type, timestamp, risk_level FROM transactions WHERE id > ? ORDER BY id ASC",
                    (last_seen_id,),
                ).fetchall()
                for row in rows:
                    process_transaction_event(
                        conn,
                        row["id"],
                        row["sender_account"],
                        row["receiver_account"],
                        row["amount"],
                        row["transaction_type"],
                        row["timestamp"],
                        account_number=row["sender_account"],
                    )
                    app.config["LAST_MONITORED_TRANSACTION_ID"] = row["id"]
                conn.commit()
                conn.close()
        except Exception:
            pass
        time.sleep(app.config.get("REALTIME_POLL_INTERVAL", 0.5))


def ensure_background_monitor():
    if app.config.get("TESTING", False) or app.config.get("MONITOR_RUNNING", False):
        return
    app.config["MONITOR_RUNNING"] = True
    thread = threading.Thread(target=monitor_transactions, daemon=True)
    thread.start()
    app.config["MONITOR_THREAD"] = thread


def get_schema_sql():
    if is_mysql_database_url(app.config["DATABASE"]):
        return """
        CREATE TABLE IF NOT EXISTS users (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            id_number VARCHAR(32) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(64) NOT NULL,
            account_number VARCHAR(64) UNIQUE NOT NULL,
            balance DOUBLE DEFAULT 0,
            created_at VARCHAR(64) NOT NULL
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            sender_account VARCHAR(64) NOT NULL,
            receiver_account VARCHAR(64) NOT NULL,
            amount DOUBLE NOT NULL,
            transaction_type VARCHAR(64) NOT NULL,
            timestamp VARCHAR(64) NOT NULL,
            status VARCHAR(64) NOT NULL,
            risk_score DOUBLE DEFAULT 0,
            risk_level VARCHAR(64) DEFAULT 'normal',
            description TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            transaction_id BIGINT NOT NULL,
            account_number VARCHAR(64) NOT NULL,
            risk_score DOUBLE NOT NULL,
            risk_level VARCHAR(64) NOT NULL,
            reason TEXT NOT NULL,
            timestamp VARCHAR(64) NOT NULL
        );

        CREATE TABLE IF NOT EXISTS activity_log (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            actor VARCHAR(255) NOT NULL,
            action VARCHAR(255) NOT NULL,
            detail TEXT NOT NULL,
            timestamp VARCHAR(64) NOT NULL
        );
        """

    if is_postgres_database_url(app.config["DATABASE"]):
        return """
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            id_number TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            account_number TEXT UNIQUE NOT NULL,
            balance DOUBLE PRECISION DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id BIGSERIAL PRIMARY KEY,
            sender_account TEXT NOT NULL,
            receiver_account TEXT NOT NULL,
            amount DOUBLE PRECISION NOT NULL,
            transaction_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_score DOUBLE PRECISION DEFAULT 0,
            risk_level TEXT DEFAULT 'normal',
            description TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id BIGSERIAL PRIMARY KEY,
            transaction_id BIGINT NOT NULL,
            account_number TEXT NOT NULL,
            risk_score DOUBLE PRECISION NOT NULL,
            risk_level TEXT NOT NULL,
            reason TEXT NOT NULL,
            timestamp TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS activity_log (
            id BIGSERIAL PRIMARY KEY,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT NOT NULL,
            timestamp TEXT NOT NULL
        );
        """

    return """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        id_number TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        account_number TEXT UNIQUE NOT NULL,
        balance REAL DEFAULT 0,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_account TEXT NOT NULL,
        receiver_account TEXT NOT NULL,
        amount REAL NOT NULL,
        transaction_type TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        status TEXT NOT NULL,
        risk_score REAL DEFAULT 0,
        risk_level TEXT DEFAULT 'normal',
        description TEXT
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_id INTEGER NOT NULL,
        account_number TEXT NOT NULL,
        risk_score REAL NOT NULL,
        risk_level TEXT NOT NULL,
        reason TEXT NOT NULL,
        timestamp TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        detail TEXT NOT NULL,
        timestamp TEXT NOT NULL
    );
    """


def init_db():
    conn = connect_db()
    conn.executescript(get_schema_sql())
    if not is_postgres_database_url(app.config["DATABASE"]) and not is_mysql_database_url(app.config["DATABASE"]):
        columns = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "email" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
        if "id_number" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN id_number TEXT")
    conn.commit()
    conn.close()


def seed_demo_data():
    conn = connect_db()
    default_users = [
        ("admin", "admin@example.com", "63-1000001A01", generate_password_hash("admin123"), "admin", "ACC1001"),
        ("compliance", "compliance@example.com", "63-1000002A02", generate_password_hash("compliance123"), "compliance", "ACC1002"),
        ("demo", "demo@example.com", "63-1000003A03", generate_password_hash("demo123"), "customer", "ACC1003"),
    ]
    for username, email, id_number, password_hash, role, account_number in default_users:
        existing = conn.execute(
            "SELECT id, id_number FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing is None:
            conn.execute(
                """
                INSERT INTO users (username, email, id_number, password_hash, role, account_number, balance, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 5000, ?)
                """,
                (username, email, id_number, password_hash, role, account_number, datetime.now(timezone.utc).isoformat()),
            )
        elif not is_valid_id_number(existing["id_number"]):
            conn.execute("UPDATE users SET id_number = ? WHERE id = ?", (id_number, existing["id"]))
    conn.commit()
    conn.close()


def get_user_by_username(username):
    return get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def get_user_by_email(email):
    return get_db().execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()


def get_user_by_id_number(id_number):
    return get_db().execute(
        "SELECT * FROM users WHERE id_number = ?", (id_number,)
    ).fetchone()


def get_user_by_account_number(account_number):
    return get_db().execute(
        "SELECT * FROM users WHERE account_number = ?", (account_number,)
    ).fetchone()


def normalize_id_number(id_number):
    compact_id = re.sub(r"[^0-9A-Za-z]", "", id_number).upper()
    if re.fullmatch(r"\d{8,9}[A-Z]\d{2}", compact_id):
        return f"{compact_id[:2]}-{compact_id[2:]}"
    return id_number.strip().upper()


def normalize_account_number(account_number):
    return account_number.strip().upper()


def is_valid_id_number(id_number):
    return bool(ID_NUMBER_PATTERN.fullmatch(id_number))


def get_user_by_id(user_id):
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def record_activity(actor, action, detail):
    get_db().execute(
        "INSERT INTO activity_log (actor, action, detail, timestamp) VALUES (?, ?, ?, ?)",
        (actor, action, detail, datetime.now(timezone.utc).isoformat()),
    )
    get_db().commit()


def get_last_insert_id(conn):
    if is_postgres_database_url(app.config["DATABASE"]):
        cursor = conn.execute("SELECT LASTVAL() as id")
        return cursor.fetchone()["id"]
    if is_mysql_database_url(app.config["DATABASE"]):
        cursor = conn.execute("SELECT LAST_INSERT_ID() as id")
        return cursor.fetchone()["id"]
    cursor = conn.execute("SELECT last_insert_rowid() as id")
    return cursor.fetchone()["id"]


def send_otp_email(recipient_email, otp):
    if app.config.get("TESTING"):
        return True

    sender_email = os.environ.get("SMTP_EMAIL", "prominancefungurayi7@gmail.com")
    sender_password = os.environ.get("SMTP_PASSWORD", "mrww ilxu nvva lhpr").replace(" ", "")
    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))

    message = EmailMessage()
    message["Subject"] = "Your AML portal verification code"
    message["From"] = sender_email
    message["To"] = recipient_email
    message.set_content(
        f"Your verification code is {otp}. Enter it in the registration form to complete your account setup."
    )

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(message)
    return True


@app.route("/stream")
def stream():
    return app.extensions["realtime_broker"].stream_response()


def login_required(*roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in to continue.")
                return redirect(url_for("login"))
            user = get_user_by_id(session["user_id"])
            if user is None:
                session.clear()
                flash("Session expired. Please log in again.")
                return redirect(url_for("login"))
            if roles and user["role"] not in roles:
                flash("You do not have access to that page.")
                return redirect(url_for("dashboard_redirect"))
            return view_func(*args, **kwargs)

        return wrapped

    return decorator


@app.context_processor
def inject_user():
    user = None
    if "user_id" in session:
        user = get_user_by_id(session["user_id"])
    return {"current_user": user}


@app.route("/")
def index():
    return redirect(url_for("dashboard_redirect"))


@app.route("/health")
def health():
    return {"status": "ok", "service": "aml-system", "timestamp": datetime.now(timezone.utc).isoformat()}, 200


@app.route("/dashboard")
def dashboard_redirect():
    if "user_id" not in session:
        return redirect(url_for("login"))
    user = get_user_by_id(session["user_id"])
    if user["role"] == "customer":
        return redirect(url_for("customer_dashboard"))
    if user["role"] == "compliance":
        return redirect(url_for("compliance_dashboard"))
    return redirect(url_for("admin_dashboard"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        if otp:
            pending_registration = session.get("pending_registration")
            if not pending_registration:
                flash("Registration session expired. Please start again.")
                return redirect(url_for("register"))
            if time.time() > pending_registration.get("expires_at", 0):
                session.pop("pending_registration", None)
                flash("The verification code has expired. Please register again.")
                return redirect(url_for("register"))
            if str(otp) != str(pending_registration.get("otp")):
                flash("The verification code is invalid.")
                return render_template("register.html", otp_step=True, email=pending_registration.get("email"))

            username = pending_registration["username"]
            email = pending_registration["email"]
            id_number = pending_registration["id_number"]
            password_hash = pending_registration["password_hash"]
            role = pending_registration["role"]
            account_number = f"ACC{1000 + get_db().execute('SELECT COUNT(*) FROM users').fetchone()[0] + 1}"
            get_db().execute(
                """
                INSERT INTO users (username, email, id_number, password_hash, role, account_number, balance, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 5000, ?)
                """,
                (username, email, id_number, password_hash, role, account_number, datetime.now(timezone.utc).isoformat()),
            )
            get_db().commit()
            session.pop("pending_registration", None)
            record_activity(username, "register", f"New {role} account created")
            user = get_user_by_username(username)
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            flash("Account created and verified. You are now logged in.")
            return redirect(url_for("customer_dashboard"))

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        id_number = normalize_id_number(request.form.get("id_number", ""))
        password = request.form.get("password", "")
        role = request.form.get("role", "customer")
        if not username or not email or not id_number or not password:
            flash("Username, email, ID number, and password are required.")
            return render_template("register.html")
        if not is_valid_id_number(id_number):
            flash(ID_NUMBER_FORMAT_MESSAGE)
            return render_template("register.html")
        if get_user_by_username(username) is not None:
            flash("That username is already taken.")
            return render_template("register.html")
        if get_user_by_email(email) is not None:
            flash("That email is already registered.")
            return render_template("register.html")
        if get_user_by_id_number(id_number) is not None:
            flash("That ID number is already registered.")
            return render_template("register.html")

        otp = f"{random.randint(100000, 999999)}"
        session["pending_registration"] = {
            "username": username,
            "email": email,
            "id_number": id_number,
            "password_hash": generate_password_hash(password),
            "role": role,
            "otp": otp,
            "expires_at": time.time() + 600,
        }
        try:
            send_otp_email(email, otp)
        except Exception:
            app.logger.exception("Unable to send registration OTP")
            session.pop("pending_registration", None)
            flash("We could not send the verification code. Please check the email address and try again.")
            return render_template("register.html")
        flash(f"A verification code has been sent to {email}.")
        return render_template("register.html", otp_step=True, email=email)
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        id_number = normalize_id_number(request.form.get("id_number", ""))
        password = request.form.get("password", "")
        if not email or not id_number or not password:
            flash("Email, ID number, and password are required.")
            return render_template("login.html")
        if not is_valid_id_number(id_number):
            flash(ID_NUMBER_FORMAT_MESSAGE)
            return render_template("login.html")

        user = get_user_by_email(email)
        if user is not None and user["id_number"] == id_number and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            record_activity(email, "login", "User logged in")
            flash("Welcome back!")
            return redirect(url_for("dashboard_redirect"))
        flash("Invalid login credentials.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))


@app.route("/customer")
@login_required("customer")
def customer_dashboard():
    user = get_user_by_id(session["user_id"])
    transactions = get_db().execute(
        "SELECT * FROM transactions WHERE sender_account = ? OR receiver_account = ? ORDER BY timestamp DESC LIMIT 20",
        (user["account_number"], user["account_number"]),
    ).fetchall()
    alerts = get_db().execute(
        "SELECT * FROM alerts WHERE account_number = ? ORDER BY timestamp DESC LIMIT 10",
        (user["account_number"],),
    ).fetchall()
    return render_template(
        "customer_dashboard.html",
        user=user,
        transactions=transactions,
        alerts=alerts,
    )


@app.route("/customer/transaction", methods=["POST"])
@login_required("customer")
def create_transaction():
    user = get_user_by_id(session["user_id"])
    tx_type = request.form.get("type")
    amount = float(request.form.get("amount", 0))
    recipient_account = normalize_account_number(request.form.get("recipient", ""))

    if amount <= 0:
        flash("Please enter a valid amount.")
        return redirect(url_for("customer_dashboard"))

    if tx_type == "withdraw" and user["balance"] < amount:
        flash("Insufficient funds for withdrawal.")
        return redirect(url_for("customer_dashboard"))

    if tx_type == "transfer":
        recipient_user = get_user_by_account_number(recipient_account)
        if recipient_user is None or recipient_user["id"] == user["id"]:
            flash("Recipient account not found.")
            return redirect(url_for("customer_dashboard"))

    if tx_type == "deposit":
        new_balance = user["balance"] + amount
        status = "Completed"
    elif tx_type == "withdraw":
        new_balance = user["balance"] - amount
        status = "Completed"
    else:
        new_balance = user["balance"] - amount
        status = "Completed"

    if new_balance < 0:
        flash("The transaction could not be completed.")
        return redirect(url_for("customer_dashboard"))

    timestamp = datetime.now(timezone.utc).isoformat()
    receiver_account = user["account_number"]
    sender_account = user["account_number"]
    if tx_type == "transfer":
        receiver_account = recipient_user["account_number"]
        sender_account = user["account_number"]

    get_db().execute(
        """
        INSERT INTO transactions (
            sender_account, receiver_account, amount, transaction_type,
            timestamp, status, risk_score, risk_level, description
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sender_account,
            receiver_account,
            amount,
            tx_type,
            timestamp,
            status,
            0,
            "normal",
            f"{tx_type.title()} initiated",
        ),
    )
    transaction_id = get_last_insert_id(get_db())

    risk_score, risk_level, reason, _ = process_transaction_event(
        get_db(),
        transaction_id,
        sender_account,
        receiver_account,
        amount,
        tx_type,
        timestamp,
        account_number=user["account_number"],
    )

    if tx_type == "deposit":
        get_db().execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, user["id"]))
    elif tx_type == "withdraw":
        get_db().execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, user["id"]))
    else:
        get_db().execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, user["id"]))
        get_db().execute(
            "UPDATE users SET balance = balance + ? WHERE id = ?",
            (amount, recipient_user["id"]),
        )

    get_db().commit()
    record_activity(user["username"], f"{tx_type} transaction", f"{tx_type} of {amount} processed")
    flash(f"Transaction recorded. Risk level: {risk_level}")
    return redirect(url_for("customer_dashboard"))


@app.route("/compliance")
@login_required("compliance", "admin")
def compliance_dashboard():
    filter_value = request.args.get("filter", "all")
    if filter_value == "flagged":
        transactions = get_db().execute(
            "SELECT * FROM transactions WHERE risk_level != 'normal' ORDER BY timestamp DESC"
        ).fetchall()
    elif filter_value == "suspicious":
        transactions = get_db().execute(
            "SELECT * FROM transactions WHERE risk_level = 'suspicious' OR risk_level = 'high risk' ORDER BY timestamp DESC"
        ).fetchall()
    else:
        transactions = get_db().execute(
            "SELECT * FROM transactions ORDER BY timestamp DESC"
        ).fetchall()
    alerts = get_db().execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20").fetchall()
    return render_template(
        "compliance_dashboard.html",
        transactions=transactions,
        alerts=alerts,
        filter_value=filter_value,
    )


@app.route("/admin", methods=["GET", "POST"])
@login_required("admin")
def admin_dashboard():
    if request.method == "POST":
        user_id = request.form.get("user_id")
        role = request.form.get("role")
        if user_id and role:
            get_db().execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
            get_db().commit()
            flash("User role updated.")
            record_activity("admin", "role_update", f"Updated role for user {user_id}")
    users = get_db().execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    activity = get_db().execute("SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT 20").fetchall()
    transactions = get_db().execute("SELECT * FROM transactions ORDER BY timestamp DESC LIMIT 20").fetchall()
    return render_template(
        "admin_dashboard.html",
        users=users,
        activity=activity,
        transactions=transactions,
    )


@app.route("/reports")
@login_required("compliance", "admin")
def reports():
    total_transactions = get_db().execute("SELECT COUNT(*) as count FROM transactions").fetchone()["count"]
    suspicious_transactions = get_db().execute(
        "SELECT COUNT(*) as count FROM transactions WHERE risk_level != 'normal'"
    ).fetchone()["count"]
    high_risk_accounts = get_db().execute(
        "SELECT account_number, COUNT(*) as count FROM alerts GROUP BY account_number ORDER BY count DESC"
    ).fetchall()
    risk_summary = get_db().execute(
        "SELECT risk_level, COUNT(*) as count FROM transactions GROUP BY risk_level ORDER BY count DESC"
    ).fetchall()
    alerts = get_db().execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20").fetchall()
    return render_template(
        "reports.html",
        total_transactions=total_transactions,
        suspicious_transactions=suspicious_transactions,
        high_risk_accounts=high_risk_accounts,
        risk_summary=risk_summary,
        alerts=alerts,
    )


@app.errorhandler(404)
def page_not_found(_):
    return render_template("error.html", message="The requested page was not found."), 404


@app.errorhandler(500)
def server_error(_):
    app.logger.exception("Unhandled server error")
    return render_template("error.html", message="A server error occurred."), 500


if __name__ == "__main__":
    init_db()
    seed_demo_data()
    ensure_background_monitor()
    socketio.run(
        app,
        debug=app.config.get("DEBUG", False),
        host="0.0.0.0",
        port=5000,
        allow_unsafe_werkzeug=True,
    )
