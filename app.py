"""
app.py — ZB Bank AML Intelligence Platform
==========================================
Industry-ready Flask application aligned with:
  • FATF Recommendations 10, 16, 20, 29
  • Basel AML Index compliance requirements
  • FinCEN / FIU reporting workflows
  • Zimbabwe FIU Act reporting obligations

New capabilities vs prototype:
  • SAR (Suspicious Activity Report) workflow with status tracking
  • CTR (Currency Transaction Report) auto-generation
  • Case management: open → investigating → escalated → closed
  • Immutable audit trail (append-only activity_log)
  • Role-based dashboard with analyst / compliance / admin separation
  • Detailed per-transaction rule evidence stored in DB
  • Watchlist / PEP (Politically Exposed Person) screening hook
  • Pagination on all list views
  • API endpoints for external SIEM / BI integration
"""

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
from flask import (
    Flask,
    Response,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_socketio import SocketIO
from werkzeug.security import check_password_hash, generate_password_hash

from ai_detector import delete_ai_model, predict_risk_level, train_ai_model
from aml_logic import analyze_transaction, get_triggered_rules
from config import DevelopmentConfig, ProductionConfig, TestingConfig
from realtime import RealtimeBroker

load_dotenv()

app = Flask(__name__)
app.config.from_object(
    DevelopmentConfig if os.environ.get("FLASK_ENV") == "development" else ProductionConfig
)
if app.config.get("TESTING"):
    app.config.from_object(TestingConfig)

app.config.setdefault("STREAM_SUBSCRIBERS", [])
app.config.setdefault("LAST_MONITORED_TRANSACTION_ID", 0)
app.config.setdefault("REALTIME_POLL_INTERVAL", 0.5)
app.config.setdefault(
    "DATABASE",
    app.config.get("DATABASE_URL", os.path.join(os.path.dirname(__file__), "aml.db")),
)

logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

socketio = SocketIO(app, cors_allowed_origins="*")
app.extensions["realtime_broker"] = RealtimeBroker(app=app, socketio=socketio)

ID_NUMBER_PATTERN = re.compile(r"^\d{2}-\d{6,7}[A-Z]\d{2}$")
ID_NUMBER_FORMAT_MESSAGE = "ID number must use the format 00-000000A00, for example 08-995728P34."

PAGE_SIZE = 25  # rows per paginated list

AI_RISK_SCORES = {
    "normal": 10,
    "suspicious": 55,
    "super_suspicious": 90,
}

STAFF_ACCOUNTS = {
    "Admin": {
        "password": "Admin123",
        "role": "admin",
        "email": "admin@example.com",
        "id_number": "63-1000001A01",
        "account_number": "ACC1001",
    },
    "Compliance": {
        "password": "Compliance123",
        "role": "compliance",
        "email": "compliance@example.com",
        "id_number": "63-1000002A02",
        "account_number": "ACC1002",
    },
}
RESERVED_STAFF_USERNAMES = {username.lower() for username in STAFF_ACCOUNTS}


# ───────────────────────────────────────────────────────────── DB adapter ──

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
            from psycopg2.extras import RealDictCursor
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
            for stmt in [s.strip() for s in script.split(";") if s.strip()]:
                cur = self.connection.cursor()
                try:
                    cur.execute(self.normalize_query(stmt))
                finally:
                    cur.close()
            return None
        self.connection.executescript(script)

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()


def is_postgres_database_url(url):
    return bool(url) and url.startswith(("postgres://", "postgresql://"))


def is_mysql_database_url(url):
    return bool(url) and url.startswith(("mysql://", "mysql+mysqlconnector://"))


def connect_db():
    database_url = app.config["DATABASE"]
    if is_postgres_database_url(database_url):
        import psycopg2
        conn = psycopg2.connect(database_url)
        conn.autocommit = False
        return DatabaseAdapter(conn, "postgres")
    if is_mysql_database_url(database_url):
        import mysql.connector
        parsed = urlparse(database_url)
        conn = mysql.connector.connect(
            host=parsed.hostname or "localhost",
            port=parsed.port or 3306,
            user=unquote(parsed.username or ""),
            password=unquote(parsed.password or ""),
            database=parsed.path.lstrip("/"),
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


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ───────────────────────────────────────────────────────── Schema / seed ──

def get_schema_sql():
    """Return DB-engine-appropriate DDL."""
    is_pg = is_postgres_database_url(app.config["DATABASE"])
    is_my = is_mysql_database_url(app.config["DATABASE"])

    if is_my:
        ai, pk_type, text_type, real_type = "AUTO_INCREMENT", "BIGINT", "VARCHAR(255)", "DOUBLE"
    elif is_pg:
        ai, pk_type, text_type, real_type = "GENERATED ALWAYS AS IDENTITY", "BIGINT", "TEXT", "DOUBLE PRECISION"
    else:
        ai, pk_type, text_type, real_type = "AUTOINCREMENT", "INTEGER", "TEXT", "REAL"

    if is_pg:
        pk_clause = lambda col: f"{col} BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY"
    elif is_my:
        pk_clause = lambda col: f"{col} BIGINT AUTO_INCREMENT PRIMARY KEY"
    else:
        pk_clause = lambda col: f"{col} INTEGER PRIMARY KEY AUTOINCREMENT"

    uniq = "VARCHAR(255) UNIQUE NOT NULL" if is_my else ("TEXT UNIQUE NOT NULL")

    return f"""
    CREATE TABLE IF NOT EXISTS users (
        {pk_clause("id")},
        username {uniq},
        email {uniq},
        id_number {uniq},
        password_hash {text_type} NOT NULL,
        role {text_type} NOT NULL,
        account_number {uniq},
        balance {real_type} DEFAULT 0,
        kyc_status {text_type} DEFAULT 'pending',
        pep_flag INTEGER DEFAULT 0,
        risk_rating {text_type} DEFAULT 'standard',
        created_at {text_type} NOT NULL
    );

    CREATE TABLE IF NOT EXISTS transactions (
        {pk_clause("id")},
        sender_account {text_type} NOT NULL,
        receiver_account {text_type} NOT NULL,
        amount {real_type} NOT NULL,
        transaction_type {text_type} NOT NULL,
        currency {text_type} DEFAULT 'USD',
        channel {text_type} DEFAULT 'online',
        timestamp {text_type} NOT NULL,
        status {text_type} NOT NULL,
        risk_score {real_type} DEFAULT 0,
        risk_level {text_type} DEFAULT 'normal',
        description {text_type},
        rules_triggered {text_type} DEFAULT '[]',
        ctr_required INTEGER DEFAULT 0,
        sar_required INTEGER DEFAULT 0,
        reviewed_by {text_type},
        reviewed_at {text_type}
    );

    CREATE TABLE IF NOT EXISTS alerts (
        {pk_clause("id")},
        transaction_id INTEGER NOT NULL,
        account_number {text_type} NOT NULL,
        risk_score {real_type} NOT NULL,
        risk_level {text_type} NOT NULL,
        reason {text_type} NOT NULL,
        rules_triggered {text_type} DEFAULT '[]',
        status {text_type} DEFAULT 'open',
        assigned_to {text_type},
        case_notes {text_type},
        resolved_at {text_type},
        resolved_by {text_type},
        timestamp {text_type} NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sar_reports (
        {pk_clause("id")},
        alert_id INTEGER NOT NULL,
        account_number {text_type} NOT NULL,
        filed_by {text_type} NOT NULL,
        narrative {text_type} NOT NULL,
        status {text_type} DEFAULT 'draft',
        filed_at {text_type},
        reference_number {text_type},
        created_at {text_type} NOT NULL
    );

    CREATE TABLE IF NOT EXISTS ctr_reports (
        {pk_clause("id")},
        transaction_id INTEGER NOT NULL,
        account_number {text_type} NOT NULL,
        amount {real_type} NOT NULL,
        generated_by {text_type} NOT NULL,
        status {text_type} DEFAULT 'pending',
        filed_at {text_type},
        created_at {text_type} NOT NULL
    );

    CREATE TABLE IF NOT EXISTS watchlist (
        {pk_clause("id")},
        name {text_type} NOT NULL,
        id_number {text_type},
        account_number {text_type},
        list_type {text_type} NOT NULL,
        reason {text_type},
        added_by {text_type} NOT NULL,
        added_at {text_type} NOT NULL
    );

    CREATE TABLE IF NOT EXISTS activity_log (
        {pk_clause("id")},
        actor {text_type} NOT NULL,
        action {text_type} NOT NULL,
        detail {text_type} NOT NULL,
        ip_address {text_type},
        timestamp {text_type} NOT NULL
    );
    """


def init_db():
    conn = connect_db()
    conn.executescript(get_schema_sql())
    # SQLite migration: add new columns to existing tables
    if not is_postgres_database_url(app.config["DATABASE"]) and not is_mysql_database_url(app.config["DATABASE"]):
        _migrate_sqlite(conn)
    conn.commit()
    conn.close()


def _migrate_sqlite(conn):
    """Add columns that may not exist in older DB files."""
    migrations = {
        "users": ["kyc_status TEXT DEFAULT 'pending'", "pep_flag INTEGER DEFAULT 0", "risk_rating TEXT DEFAULT 'standard'"],
        "transactions": ["currency TEXT DEFAULT 'USD'", "channel TEXT DEFAULT 'online'",
                         "rules_triggered TEXT DEFAULT '[]'", "ctr_required INTEGER DEFAULT 0",
                         "sar_required INTEGER DEFAULT 0", "reviewed_by TEXT", "reviewed_at TEXT"],
        "alerts": ["rules_triggered TEXT DEFAULT '[]'", "status TEXT DEFAULT 'open'",
                   "assigned_to TEXT", "case_notes TEXT", "resolved_at TEXT", "resolved_by TEXT"],
    }
    for table, cols in migrations.items():
        existing = [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        for col_def in cols:
            col_name = col_def.split()[0]
            if col_name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")


def seed_demo_data():
    conn = connect_db()
    now = datetime.now(timezone.utc).isoformat()
    default_users = [
        (
            username,
            staff["email"],
            staff["id_number"],
            generate_password_hash(staff["password"]),
            staff["role"],
            staff["account_number"],
        )
        for username, staff in STAFF_ACCOUNTS.items()
    ]
    default_users.append(
        ("demo", "demo@example.com", "63-1000003A03", generate_password_hash("demo123"), "customer", "ACC1003")
    )
    for username, email, id_number, pwd_hash, role, acct in default_users:
        existing = conn.execute(
            "SELECT id, id_number FROM users WHERE username = ? OR email = ?",
            (username, email),
        ).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO users (username, email, id_number, password_hash, role, account_number, balance, kyc_status, created_at) VALUES (?,?,?,?,?,?,5000,'verified',?)",
                (username, email, id_number, pwd_hash, role, acct, now),
            )
        else:
            conn.execute(
                """
                UPDATE users
                SET username=?, email=?, id_number=?, password_hash=?, role=?,
                    account_number=?, kyc_status='verified'
                WHERE id=?
                """,
                (username, email, id_number, pwd_hash, role, acct, existing["id"]),
            )
    conn.commit()
    conn.close()


# ───────────────────────────────────────────────────────────── Utilities ──

def get_user_by_id(user_id):
    return get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

def get_user_by_username(username):
    return get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

def get_user_by_email(email):
    return get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

def get_user_by_id_number(id_number):
    return get_db().execute("SELECT * FROM users WHERE id_number=?", (id_number,)).fetchone()

def get_user_by_account_number(account_number):
    return get_db().execute("SELECT * FROM users WHERE account_number=?", (account_number,)).fetchone()

def normalize_id_number(id_number):
    compact = re.sub(r"[^0-9A-Za-z]", "", id_number).upper()
    if re.fullmatch(r"\d{8,9}[A-Z]\d{2}", compact):
        return f"{compact[:2]}-{compact[2:]}"
    return id_number.strip().upper()

def normalize_account_number(acct):
    return acct.strip().upper()

def is_valid_id_number(id_number):
    return bool(ID_NUMBER_PATTERN.fullmatch(id_number))

def record_activity(actor, action, detail):
    ip = request.remote_addr if request else "system"
    get_db().execute(
        "INSERT INTO activity_log (actor, action, detail, ip_address, timestamp) VALUES (?,?,?,?,?)",
        (actor, action, detail, ip, datetime.now(timezone.utc).isoformat()),
    )
    get_db().commit()

def get_last_insert_id(conn):
    if is_postgres_database_url(app.config["DATABASE"]):
        return conn.execute("SELECT LASTVAL() as id").fetchone()["id"]
    if is_mysql_database_url(app.config["DATABASE"]):
        return conn.execute("SELECT LAST_INSERT_ID() as id").fetchone()["id"]
    return conn.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

def broadcast_event(event_name, payload):
    app.extensions["realtime_broker"].publish(event_name, payload)

def _generate_sar_ref():
    ts = datetime.now(timezone.utc)
    return f"SAR-{ts.year}-{ts.strftime('%m%d')}-{random.randint(1000,9999)}"

def _generate_ctr_ref():
    ts = datetime.now(timezone.utc)
    return f"CTR-{ts.year}-{ts.strftime('%m%d')}-{random.randint(1000,9999)}"


# ───────────────────────────────────────────────────── Transaction engine ──

def _random_transaction_amount(tx_type):
    if tx_type == "transfer":
        return random.choice([25, 75, 150, 500, 950, 1500, 2500, 5000, 9000])
    if tx_type == "withdraw":
        return random.choice([20, 60, 120, 300, 1000, 3500, 10000])
    return random.choice([50, 100, 250, 450, 1000, 3000, 9999, 10000])


def _simulation_plan(count):
    normal_count = int(count * 0.80)
    suspicious_count = int(count * 0.15)
    super_count = count - normal_count - suspicious_count
    labels = (
        ["normal"] * normal_count
        + ["suspicious"] * suspicious_count
        + ["super_suspicious"] * super_count
    )
    random.shuffle(labels)
    return labels


def _simulation_transaction(label, users):
    if label == "normal":
        tx_type = random.choices(["deposit", "withdraw", "transfer"], weights=[35, 25, 40], k=1)[0]
        amount = round(random.uniform(10, 950), 2)
        hour = random.randint(7, 20)
    elif label == "suspicious":
        tx_type = random.choices(["transfer", "withdraw", "deposit"], weights=[70, 20, 10], k=1)[0]
        amount = round(random.uniform(1200, 6500), 2)
        hour = random.choice([0, 1, 2, 3, 4, 22, 23, random.randint(6, 21)])
    else:
        tx_type = random.choices(["transfer", "withdraw", "deposit"], weights=[75, 20, 5], k=1)[0]
        amount = round(random.uniform(8500, 25000), 2)
        hour = random.choice([0, 1, 2, 3, 23])

    sender = random.choice(users)
    recipient = sender
    if tx_type == "transfer" and len(users) > 1:
        recipient = random.choice([user for user in users if user["id"] != sender["id"]])

    now = datetime.now(timezone.utc)
    timestamp = now.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59)).isoformat()
    return sender, recipient, tx_type, amount, timestamp


def _simulation_reason(label, amount, tx_type):
    if label == "normal":
        return "AI training label: normal customer banking activity"
    if label == "suspicious":
        return f"AI training label: suspicious {tx_type} pattern involving ${amount:,.2f}"
    return f"AI training label: super suspicious {tx_type} pattern involving ${amount:,.2f}"


def create_alert_if_needed(conn, transaction_id, account_number, risk_score, risk_level, reason, rules_json, timestamp):
    existing = conn.execute("SELECT id FROM alerts WHERE transaction_id=?", (transaction_id,)).fetchone()
    if existing is None and risk_level != "normal":
        conn.execute(
            """
            INSERT INTO alerts (transaction_id, account_number, risk_score, risk_level, reason,
                                rules_triggered, status, timestamp)
            VALUES (?,?,?,?,?,?,'open',?)
            """,
            (transaction_id, account_number, risk_score, risk_level, reason, rules_json, timestamp),
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
        conn, transaction_type, amount, sender_account, receiver_account, timestamp
    )
    triggered = get_triggered_rules(
        conn, transaction_type, amount, sender_account, receiver_account, timestamp
    )
    rules_json = json.dumps([
        {"id": r.rule_id, "typology": r.typology, "score_delta": r.score_delta, "reason": r.reason}
        for r in triggered
    ])

    ai_level, ai_confidence = predict_risk_level({
        "sender_account": sender_account,
        "receiver_account": receiver_account,
        "amount": amount,
        "transaction_type": transaction_type,
        "timestamp": timestamp,
    })
    if ai_level and ai_confidence >= 0.55:
        risk_level = ai_level
        risk_score = AI_RISK_SCORES.get(ai_level, risk_score)
        reason = f"AI model classified transaction as {ai_level.replace('_', ' ')} ({ai_confidence:.0%} confidence)"

    ctr_required = 1 if "[CTR REQUIRED]" in reason else 0
    sar_required = 1 if "[SAR REVIEW]" in reason else 0
    if risk_level in ("suspicious", "super_suspicious", "high_risk", "critical"):
        sar_required = 1

    conn.execute(
        """
        UPDATE transactions
        SET risk_score=?, risk_level=?, description=?, rules_triggered=?,
            ctr_required=?, sar_required=?
        WHERE id=?
        """,
        (risk_score, risk_level, reason, rules_json, ctr_required, sar_required, transaction_id),
    )

    created_alert = create_alert_if_needed(
        conn, transaction_id, account_number or sender_account,
        risk_score, risk_level, reason, rules_json, timestamp,
    )

    # Auto-generate CTR
    if ctr_required:
        existing_ctr = conn.execute(
            "SELECT id FROM ctr_reports WHERE transaction_id=?", (transaction_id,)
        ).fetchone()
        if not existing_ctr:
            conn.execute(
                """
                INSERT INTO ctr_reports (transaction_id, account_number, amount,
                    generated_by, status, created_at)
                VALUES (?,?,?,'system','pending',?)
                """,
                (transaction_id, account_number or sender_account, amount,
                 datetime.now(timezone.utc).isoformat()),
            )

    if emit_events:
        broadcast_event("transaction", {
            "id": transaction_id,
            "type": transaction_type,
            "amount": amount,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "timestamp": timestamp,
        })
        if created_alert:
            broadcast_event("alert", {
                "transaction_id": transaction_id,
                "account_number": account_number or sender_account,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "reason": reason,
                "timestamp": timestamp,
            })

    return risk_score, risk_level, reason, created_alert


# ───────────────────────────────────────────────────── Background monitor ──

def monitor_transactions():
    while not app.config.get("MONITOR_STOP", False):
        try:
            with app.app_context():
                conn = connect_db()
                last_id = app.config.get("LAST_MONITORED_TRANSACTION_ID", 0)
                rows = conn.execute(
                    "SELECT id, sender_account, receiver_account, amount, transaction_type, timestamp FROM transactions WHERE id>? ORDER BY id ASC",
                    (last_id,),
                ).fetchall()
                for row in rows:
                    process_transaction_event(
                        conn, row["id"], row["sender_account"], row["receiver_account"],
                        row["amount"], row["transaction_type"], row["timestamp"],
                        account_number=row["sender_account"],
                    )
                    app.config["LAST_MONITORED_TRANSACTION_ID"] = row["id"]
                conn.commit()
                conn.close()
        except Exception:
            pass
        time.sleep(app.config.get("REALTIME_POLL_INTERVAL", 0.5))


def ensure_background_monitor():
    if app.config.get("TESTING") or app.config.get("MONITOR_RUNNING"):
        return
    app.config["MONITOR_RUNNING"] = True
    t = threading.Thread(target=monitor_transactions, daemon=True)
    t.start()


# ───────────────────────────────────────────────── Security / middleware ──

@app.before_request
def enforce_security_headers():
    request.environ.setdefault("werkzeug.request", request)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
    return response


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
                flash("Access denied.")
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


# ─────────────────────────────────────────────────────────────── Routes ──

@app.route("/")
def index():
    return redirect(url_for("dashboard_redirect"))


@app.route("/health")
def health():
    return {"status": "ok", "service": "zb-aml", "timestamp": datetime.now(timezone.utc).isoformat()}, 200


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


# ── Auth ──

def send_otp_email(recipient_email, otp):
    if app.config.get("TESTING"):
        return True
    sender_email = os.environ.get("SMTP_EMAIL", "prominancefungurayi7@gmail.com")
    sender_password = os.environ.get("SMTP_PASSWORD", "mrww ilxu nvva lhpr").replace(" ", "")
    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    msg = EmailMessage()
    msg["Subject"] = "ZB Bank — Your verification code"
    msg["From"] = sender_email
    msg["To"] = recipient_email
    msg.set_content(f"Your ZB Bank verification code is: {otp}\n\nThis code expires in 10 minutes.")
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
    return True


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        if otp:
            pending = session.get("pending_registration")
            if not pending:
                flash("Registration session expired. Please start again.")
                return redirect(url_for("register"))
            if time.time() > pending.get("expires_at", 0):
                session.pop("pending_registration", None)
                flash("Verification code expired. Please register again.")
                return redirect(url_for("register"))
            if str(otp) != str(pending.get("otp")):
                flash("Invalid verification code.")
                return render_template("register.html", otp_step=True, email=pending.get("email"))

            user_count = get_db().execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
            acct = f"ACC{1000 + int(user_count) + 1}"
            get_db().execute(
                "INSERT INTO users (username,email,id_number,password_hash,role,account_number,balance,kyc_status,created_at) VALUES (?,?,?,?,?,?,5000,'pending',?)",
                (pending["username"], pending["email"], pending["id_number"],
                 pending["password_hash"], pending["role"], acct,
                 datetime.now(timezone.utc).isoformat()),
            )
            get_db().commit()
            session.pop("pending_registration", None)
            user = get_user_by_username(pending["username"])
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            record_activity(pending["username"], "register", f"New {pending['role']} registered")
            flash("Account created. Welcome to ZB Bank AML Portal.")
            return redirect(url_for("dashboard_redirect"))

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        id_number = normalize_id_number(request.form.get("id_number", ""))
        password = request.form.get("password", "")
        role = "customer"

        if not all([username, email, id_number, password]):
            flash("All fields are required.")
            return render_template("register.html")
        if username.lower() in RESERVED_STAFF_USERNAMES:
            flash("That username is reserved for bank staff.")
            return render_template("register.html")
        if not is_valid_id_number(id_number):
            flash(ID_NUMBER_FORMAT_MESSAGE)
            return render_template("register.html")
        if get_user_by_username(username):
            flash("Username already taken.")
            return render_template("register.html")
        if get_user_by_email(email):
            flash("Email already registered.")
            return render_template("register.html")
        if get_user_by_id_number(id_number):
            flash("ID number already registered.")
            return render_template("register.html")

        otp_code = f"{random.randint(100000, 999999)}"
        session["pending_registration"] = {
            "username": username, "email": email, "id_number": id_number,
            "password_hash": generate_password_hash(password), "role": role,
            "otp": otp_code, "expires_at": time.time() + 600,
        }
        try:
            send_otp_email(email, otp_code)
        except Exception:
            session.pop("pending_registration", None)
            flash("Could not send verification code. Please check the email address.")
            return render_template("register.html")
        flash(f"Verification code sent to {email}.")
        return render_template("register.html", otp_step=True, email=email)
    return render_template("register.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        login_identifier = request.form.get("login", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        if not email and "@" in login_identifier:
            email = login_identifier.lower()
        id_number = normalize_id_number(request.form.get("id_number", ""))
        password = request.form.get("password", "")

        staff_identifier = login_identifier or username
        if staff_identifier in STAFF_ACCOUNTS:
            staff = STAFF_ACCOUNTS[staff_identifier]
            user = get_user_by_username(staff_identifier)
            if (
                user
                and user["role"] == staff["role"]
                and check_password_hash(user["password_hash"], password)
            ):
                session["user_id"] = user["id"]
                session["role"] = user["role"]
                record_activity(staff_identifier, "login", f"Staff login from {request.remote_addr}")
                flash("Welcome back.")
                return redirect(url_for("dashboard_redirect"))
            flash("Invalid credentials.")
            record_activity(staff_identifier, "failed_login", f"Failed staff login attempt from {request.remote_addr}")
            return render_template("login.html")

        if not all([email, id_number, password]):
            flash("All fields are required.")
            return render_template("login.html")
        if not is_valid_id_number(id_number):
            flash(ID_NUMBER_FORMAT_MESSAGE)
            return render_template("login.html")
        user = get_user_by_email(email)
        if (
            user
            and user["role"] == "customer"
            and user["id_number"] == id_number
            and check_password_hash(user["password_hash"], password)
        ):
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            record_activity(email, "login", f"Login from {request.remote_addr}")
            flash("Welcome back.")
            return redirect(url_for("dashboard_redirect"))
        flash("Invalid credentials.")
        record_activity(email, "failed_login", f"Failed login attempt from {request.remote_addr}")
    return render_template("login.html")


@app.route("/logout")
def logout():
    if "user_id" in session:
        user = get_user_by_id(session["user_id"])
        if user:
            record_activity(user["username"], "logout", "User logged out")
    session.clear()
    flash("You have been signed out.")
    return redirect(url_for("login"))


# ── Customer ──

@app.route("/customer")
@login_required("customer")
def customer_dashboard():
    user = get_user_by_id(session["user_id"])
    page = int(request.args.get("page", 1))
    offset = (page - 1) * PAGE_SIZE
    transactions = get_db().execute(
        "SELECT * FROM transactions WHERE sender_account=? OR receiver_account=? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (user["account_number"], user["account_number"], PAGE_SIZE, offset),
    ).fetchall()
    alerts = get_db().execute(
        "SELECT * FROM alerts WHERE account_number=? ORDER BY timestamp DESC LIMIT 10",
        (user["account_number"],),
    ).fetchall()
    stats = {
        "total_tx": get_db().execute(
            "SELECT COUNT(*) as c FROM transactions WHERE sender_account=? OR receiver_account=?",
            (user["account_number"], user["account_number"]),
        ).fetchone()["c"],
        "flagged": get_db().execute(
            "SELECT COUNT(*) as c FROM transactions WHERE (sender_account=? OR receiver_account=?) AND risk_level!='normal'",
            (user["account_number"], user["account_number"]),
        ).fetchone()["c"],
        "open_alerts": get_db().execute(
            "SELECT COUNT(*) as c FROM alerts WHERE account_number=? AND status='open'",
            (user["account_number"],),
        ).fetchone()["c"],
    }
    return render_template(
        "customer_dashboard.html",
        user=user, transactions=transactions, alerts=alerts, stats=stats, page=page,
    )


@app.route("/customer/transaction", methods=["POST"])
@login_required("customer")
def create_transaction():
    user = get_user_by_id(session["user_id"])
    tx_type = request.form.get("type")
    amount_str = request.form.get("amount", "0")
    recipient_account = normalize_account_number(request.form.get("recipient", ""))

    try:
        amount = float(amount_str)
    except ValueError:
        flash("Invalid amount.")
        return redirect(url_for("customer_dashboard"))

    if amount <= 0:
        flash("Amount must be greater than zero.")
        return redirect(url_for("customer_dashboard"))

    if tx_type == "withdraw" and user["balance"] < amount:
        flash("Insufficient funds.")
        return redirect(url_for("customer_dashboard"))

    recipient_user = None
    if tx_type == "transfer":
        recipient_user = get_user_by_account_number(recipient_account)
        if not recipient_user or recipient_user["id"] == user["id"]:
            flash("Recipient account not found.")
            return redirect(url_for("customer_dashboard"))

    timestamp = datetime.now(timezone.utc).isoformat()
    sender_account = user["account_number"]
    receiver_account = recipient_user["account_number"] if recipient_user else user["account_number"]

    get_db().execute(
        """
        INSERT INTO transactions (sender_account, receiver_account, amount, transaction_type,
            currency, channel, timestamp, status, risk_score, risk_level, description)
        VALUES (?,?,?,?,'USD','online',?,'Completed',0,'normal','Initiated')
        """,
        (sender_account, receiver_account, amount, tx_type, timestamp),
    )
    transaction_id = get_last_insert_id(get_db())

    risk_score, risk_level, reason, _ = process_transaction_event(
        get_db(), transaction_id, sender_account, receiver_account,
        amount, tx_type, timestamp, account_number=user["account_number"],
    )

    # Update balances
    if tx_type == "deposit":
        get_db().execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, user["id"]))
    elif tx_type == "withdraw":
        get_db().execute("UPDATE users SET balance=balance-? WHERE id=?", (amount, user["id"]))
    elif tx_type == "transfer":
        get_db().execute("UPDATE users SET balance=balance-? WHERE id=?", (amount, user["id"]))
        get_db().execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, recipient_user["id"]))

    get_db().commit()
    record_activity(user["username"], f"{tx_type}", f"${amount:.2f} — risk: {risk_level}")

    risk_labels = {
        "normal": "Transaction processed successfully.",
        "low": "Transaction processed. Minor risk indicators noted.",
        "suspicious": "⚠ Transaction flagged as suspicious and is under review.",
        "super_suspicious": "🚨 Super suspicious transaction flagged. Immediate compliance review initiated.",
        "high_risk": "🚨 High-risk transaction flagged. Compliance team notified.",
        "critical": "🚨 CRITICAL risk transaction. Immediate review initiated.",
    }
    flash(risk_labels.get(risk_level, f"Transaction recorded. Risk: {risk_level}"))
    return redirect(url_for("customer_dashboard"))


# ── Compliance ──

@app.route("/compliance")
@login_required("compliance", "admin")
def compliance_dashboard():
    filter_value = request.args.get("filter", "all")
    page = int(request.args.get("page", 1))
    offset = (page - 1) * PAGE_SIZE

    if filter_value == "flagged":
        base = "WHERE risk_level!='normal'"
    elif filter_value == "suspicious":
        base = "WHERE risk_level IN ('suspicious','super_suspicious','high_risk','critical')"
    elif filter_value == "ctr":
        base = "WHERE ctr_required=1"
    elif filter_value == "sar":
        base = "WHERE sar_required=1"
    else:
        base = ""

    transactions = get_db().execute(
        f"SELECT * FROM transactions {base} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (PAGE_SIZE, offset),
    ).fetchall()
    total_count = get_db().execute(
        f"SELECT COUNT(*) as c FROM transactions {base}"
    ).fetchone()["c"]

    open_alerts = get_db().execute(
        "SELECT a.*, u.username FROM alerts a LEFT JOIN users u ON a.account_number=u.account_number WHERE a.status='open' ORDER BY a.timestamp DESC LIMIT 30"
    ).fetchall()
    pending_sars = get_db().execute(
        "SELECT COUNT(*) as c FROM sar_reports WHERE status='draft'"
    ).fetchone()["c"]
    pending_ctrs = get_db().execute(
        "SELECT COUNT(*) as c FROM ctr_reports WHERE status='pending'"
    ).fetchone()["c"]

    stats = {
        "open_alerts": get_db().execute("SELECT COUNT(*) as c FROM alerts WHERE status='open'").fetchone()["c"],
        "high_risk_today": get_db().execute(
            "SELECT COUNT(*) as c FROM transactions WHERE risk_level IN ('super_suspicious','high_risk','critical') AND timestamp>=?",
            (datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00"),),
        ).fetchone()["c"],
        "pending_sars": pending_sars,
        "pending_ctrs": pending_ctrs,
    }

    return render_template(
        "compliance_dashboard.html",
        transactions=transactions,
        open_alerts=open_alerts,
        filter_value=filter_value,
        stats=stats,
        page=page,
        total_count=total_count,
        page_size=PAGE_SIZE,
    )


@app.route("/compliance/alert/<int:alert_id>", methods=["GET", "POST"])
@login_required("compliance", "admin")
def alert_detail(alert_id):
    alert = get_db().execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not alert:
        flash("Alert not found.")
        return redirect(url_for("compliance_dashboard"))

    transaction = get_db().execute(
        "SELECT * FROM transactions WHERE id=?", (alert["transaction_id"],)
    ).fetchone()
    account_user = get_db().execute(
        "SELECT * FROM users WHERE account_number=?", (alert["account_number"],)
    ).fetchone()

    if request.method == "POST":
        action = request.form.get("action")
        notes = request.form.get("case_notes", "")
        officer = get_user_by_id(session["user_id"])

        if action == "resolve":
            get_db().execute(
                "UPDATE alerts SET status='resolved', case_notes=?, resolved_by=?, resolved_at=? WHERE id=?",
                (notes, officer["username"], datetime.now(timezone.utc).isoformat(), alert_id),
            )
            record_activity(officer["username"], "resolve_alert", f"Alert #{alert_id} resolved")
            flash(f"Alert #{alert_id} marked as resolved.")

        elif action == "escalate":
            get_db().execute(
                "UPDATE alerts SET status='escalated', case_notes=?, assigned_to=? WHERE id=?",
                (notes, officer["username"], alert_id),
            )
            record_activity(officer["username"], "escalate_alert", f"Alert #{alert_id} escalated")
            flash(f"Alert #{alert_id} escalated.")

        elif action == "file_sar":
            narrative = request.form.get("sar_narrative", notes)
            ref = _generate_sar_ref()
            get_db().execute(
                "INSERT INTO sar_reports (alert_id, account_number, filed_by, narrative, status, reference_number, created_at) VALUES (?,?,?,?,'draft',?,?)",
                (alert_id, alert["account_number"], officer["username"], narrative, ref,
                 datetime.now(timezone.utc).isoformat()),
            )
            get_db().execute(
                "UPDATE alerts SET status='sar_filed', case_notes=? WHERE id=?",
                (f"SAR filed: {ref}. {notes}", alert_id),
            )
            record_activity(officer["username"], "file_sar", f"SAR {ref} filed for alert #{alert_id}")
            flash(f"SAR filed successfully. Reference: {ref}")

        get_db().commit()
        return redirect(url_for("alert_detail", alert_id=alert_id))

    rules = []
    try:
        rules = json.loads(alert["rules_triggered"] or "[]")
    except Exception:
        pass

    sar_reports = get_db().execute(
        "SELECT * FROM sar_reports WHERE alert_id=? ORDER BY created_at DESC", (alert_id,)
    ).fetchall()

    return render_template(
        "alert_detail.html",
        alert=alert,
        transaction=transaction,
        account_user=account_user,
        rules=rules,
        sar_reports=sar_reports,
    )


@app.route("/compliance/sar/<int:sar_id>/submit", methods=["POST"])
@login_required("compliance", "admin")
def submit_sar(sar_id):
    officer = get_user_by_id(session["user_id"])
    get_db().execute(
        "UPDATE sar_reports SET status='submitted', filed_at=? WHERE id=?",
        (datetime.now(timezone.utc).isoformat(), sar_id),
    )
    get_db().commit()
    record_activity(officer["username"], "submit_sar", f"SAR #{sar_id} submitted to FIU")
    flash(f"SAR #{sar_id} submitted to the Financial Intelligence Unit.")
    return redirect(url_for("reports"))


# ── Admin ──

@app.route("/admin", methods=["GET", "POST"])
@login_required("admin")
def admin_dashboard():
    if request.method == "POST":
        action = request.form.get("action", "update_role")
        admin_user = get_user_by_id(session["user_id"])

        if action == "update_role":
            user_id = request.form.get("user_id")
            kyc = request.form.get("kyc_status")
            if user_id:
                if kyc:
                    get_db().execute("UPDATE users SET kyc_status=? WHERE id=?", (kyc, user_id))
                get_db().commit()
                record_activity(admin_user["username"], "update_user", f"Updated user {user_id}: kyc={kyc or 'unchanged'}")
                flash("User updated. Staff roles are restricted to built-in staff accounts.")

        elif action == "add_watchlist":
            name = request.form.get("wl_name", "")
            id_num = request.form.get("wl_id_number", "")
            list_type = request.form.get("wl_type", "internal")
            reason = request.form.get("wl_reason", "")
            if name:
                get_db().execute(
                    "INSERT INTO watchlist (name, id_number, list_type, reason, added_by, added_at) VALUES (?,?,?,?,?,?)",
                    (name, id_num, list_type, reason, admin_user["username"],
                     datetime.now(timezone.utc).isoformat()),
                )
                get_db().commit()
                record_activity(admin_user["username"], "add_watchlist", f"Added {name} to watchlist")
                flash(f"{name} added to watchlist.")

    page = int(request.args.get("page", 1))
    offset = (page - 1) * PAGE_SIZE
    users = get_db().execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    activity = get_db().execute(
        "SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (PAGE_SIZE, offset),
    ).fetchall()
    transactions = get_db().execute(
        "SELECT * FROM transactions ORDER BY timestamp DESC LIMIT 20"
    ).fetchall()
    watchlist = get_db().execute(
        "SELECT * FROM watchlist ORDER BY added_at DESC LIMIT 20"
    ).fetchall()
    system_stats = {
        "total_users": get_db().execute("SELECT COUNT(*) as c FROM users").fetchone()["c"],
        "total_transactions": get_db().execute("SELECT COUNT(*) as c FROM transactions").fetchone()["c"],
        "open_alerts": get_db().execute("SELECT COUNT(*) as c FROM alerts WHERE status='open'").fetchone()["c"],
        "pending_sars": get_db().execute("SELECT COUNT(*) as c FROM sar_reports WHERE status='draft'").fetchone()["c"],
        "pending_ctrs": get_db().execute("SELECT COUNT(*) as c FROM ctr_reports WHERE status='pending'").fetchone()["c"],
    }
    return render_template(
        "admin_dashboard.html",
        users=users, activity=activity, transactions=transactions,
        watchlist=watchlist, system_stats=system_stats, page=page,
    )


@app.route("/admin/generate-transactions", methods=["POST"])
@login_required("admin")
def generate_transactions():
    admin_user = get_user_by_id(session["user_id"])
    try:
        count = int(request.form.get("count", 100))
    except ValueError:
        count = 100
    if count not in (100, 1000, 5000):
        count = 100

    users = get_db().execute(
        "SELECT id, username, account_number FROM users ORDER BY id"
    ).fetchall()
    if not users:
        flash("No users are available for transaction generation.")
        return redirect(url_for("admin_dashboard"))

    generated = {"normal": 0, "suspicious": 0, "super_suspicious": 0}
    for label in _simulation_plan(count):
        sender, recipient, tx_type, amount, timestamp = _simulation_transaction(label, users)
        sender_account = sender["account_number"]
        receiver_account = recipient["account_number"] if tx_type == "transfer" else sender_account
        risk_score = AI_RISK_SCORES[label]
        reason = _simulation_reason(label, amount, tx_type)
        rules_json = json.dumps([{
            "id": "AI_SIM",
            "typology": label.replace("_", " ").title(),
            "score_delta": risk_score,
            "reason": reason,
        }])
        ctr_required = 1 if tx_type in ("deposit", "withdraw") and amount >= 10000 else 0
        sar_required = 1 if label != "normal" else 0

        get_db().execute(
            """
            INSERT INTO transactions (sender_account, receiver_account, amount, transaction_type,
                currency, channel, timestamp, status, risk_score, risk_level, description,
                rules_triggered, ctr_required, sar_required)
            VALUES (?,?,?,?,'USD','simulator',?,'Completed',?,?,?,?,?,?)
            """,
            (
                sender_account, receiver_account, amount, tx_type, timestamp,
                risk_score, label, reason, rules_json, ctr_required, sar_required,
            ),
        )
        transaction_id = get_last_insert_id(get_db())
        create_alert_if_needed(
            get_db(), transaction_id, sender_account, risk_score, label, reason, rules_json, timestamp
        )

        if tx_type == "deposit":
            get_db().execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, sender["id"]))
        elif tx_type == "withdraw":
            get_db().execute(
                "UPDATE users SET balance=CASE WHEN balance > ? THEN balance-? ELSE 0 END WHERE id=?",
                (amount, amount, sender["id"]),
            )
        else:
            get_db().execute(
                "UPDATE users SET balance=CASE WHEN balance > ? THEN balance-? ELSE 0 END WHERE id=?",
                (amount, amount, sender["id"]),
            )
            get_db().execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, recipient["id"]))

        generated[label] += 1

    get_db().commit()
    rows = get_db().execute(
        "SELECT sender_account, receiver_account, amount, transaction_type, timestamp, risk_level FROM transactions"
    ).fetchall()
    model = train_ai_model(rows)
    record_activity(
        admin_user["username"],
        "generate_transactions",
        (
            f"Generated {count} simulator transactions: "
            f"{generated['normal']} normal, {generated['suspicious']} suspicious, "
            f"{generated['super_suspicious']} super suspicious"
        ),
    )
    if model is None:
        flash("Transactions generated, but more labelled data is needed before AI training can complete.")
    else:
        flash(
            f"Generated {count} transactions and trained AI model: "
            f"{generated['normal']} normal, {generated['suspicious']} suspicious, "
            f"{generated['super_suspicious']} super suspicious."
        )
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/clear-transactions", methods=["POST"])
@login_required("admin")
def clear_transactions():
    admin_user = get_user_by_id(session["user_id"])
    conn = get_db()
    for table in ("sar_reports", "ctr_reports", "alerts", "transactions"):
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
    delete_ai_model()
    app.config["LAST_MONITORED_TRANSACTION_ID"] = 0
    record_activity(admin_user["username"], "clear_transactions", "Cleared all transactions, alerts, and AI model")
    flash("All transactions, alerts, reports, and the trained AI model have been cleared.")
    return redirect(url_for("admin_dashboard"))


@app.route("/reports")
@login_required("compliance", "admin")
def reports():
    total_tx = get_db().execute("SELECT COUNT(*) as c FROM transactions").fetchone()["c"]
    suspicious_tx = get_db().execute("SELECT COUNT(*) as c FROM transactions WHERE risk_level!='normal'").fetchone()["c"]
    high_risk_accounts = get_db().execute(
        "SELECT account_number, COUNT(*) as count FROM alerts GROUP BY account_number ORDER BY count DESC LIMIT 10"
    ).fetchall()
    risk_summary = get_db().execute(
        "SELECT risk_level, COUNT(*) as count FROM transactions GROUP BY risk_level ORDER BY count DESC"
    ).fetchall()
    alerts = get_db().execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20"
    ).fetchall()
    sar_reports = get_db().execute(
        "SELECT * FROM sar_reports ORDER BY created_at DESC LIMIT 20"
    ).fetchall()
    ctr_reports = get_db().execute(
        "SELECT * FROM ctr_reports ORDER BY created_at DESC LIMIT 20"
    ).fetchall()
    monthly_volume = get_db().execute(
        """
        SELECT substr(timestamp,1,7) as month, COUNT(*) as count, SUM(amount) as volume
        FROM transactions
        GROUP BY month
        ORDER BY month DESC
        LIMIT 12
        """
    ).fetchall()
    return render_template(
        "reports.html",
        total_transactions=total_tx,
        suspicious_transactions=suspicious_tx,
        high_risk_accounts=high_risk_accounts,
        risk_summary=risk_summary,
        alerts=alerts,
        sar_reports=sar_reports,
        ctr_reports=ctr_reports,
        monthly_volume=monthly_volume,
    )


# ── API (JSON) ──

@app.route("/api/v1/stats")
@login_required("compliance", "admin")
def api_stats():
    return jsonify({
        "total_transactions": get_db().execute("SELECT COUNT(*) as c FROM transactions").fetchone()["c"],
        "open_alerts": get_db().execute("SELECT COUNT(*) as c FROM alerts WHERE status='open'").fetchone()["c"],
        "high_risk_today": get_db().execute(
            "SELECT COUNT(*) as c FROM transactions WHERE risk_level IN ('super_suspicious','high_risk','critical') AND timestamp>=?",
            (datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00"),),
        ).fetchone()["c"],
        "pending_sars": get_db().execute("SELECT COUNT(*) as c FROM sar_reports WHERE status='draft'").fetchone()["c"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/v1/transactions")
@login_required("compliance", "admin")
def api_transactions():
    page = int(request.args.get("page", 1))
    offset = (page - 1) * PAGE_SIZE
    rows = get_db().execute(
        "SELECT * FROM transactions ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (PAGE_SIZE, offset),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/stream")
def stream():
    return app.extensions["realtime_broker"].stream_response()


# ── Error handlers ──

@app.errorhandler(404)
def page_not_found(_):
    return render_template("error.html", message="Page not found."), 404


@app.errorhandler(500)
def server_error(_):
    app.logger.exception("Unhandled server error")
    return render_template("error.html", message="A server error occurred. Our team has been notified."), 500


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
        use_reloader=False,
    )
