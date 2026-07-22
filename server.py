"""

server.py — StanPro Bank AML Intelligence Platform (Consolidated Web Server)

=========================================================================

Industry-ready Flask application aligned with:

  • FATF Recommendations 10, 16, 20, 29

  • Basel AML Index compliance requirements

  • FinCEN / FIU reporting workflows

  • Zimbabwe FIU Act reporting obligations

New capabilities vs prototype:

  • SAR (Suspicious Activity Report) workflow with status tracking

  • CTR (Currency Transaction Report) auto-generation

  • Case management: open → investigating → escalated → closed

  • System activity log for operational history

  • Role-based dashboard with analyst / compliance / admin separation

  • Detailed per-transaction rule evidence stored in DB

  • Watchlist / PEP (Politically Exposed Person) screening hook

  • Pagination on all list views

  • API endpoints for external SIEM / BI integration

  • Real-time event broadcasting via WebSocket/Redis/Kafka

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

import uuid

from queue import Empty, Queue

from datetime import datetime, timedelta, timezone

from decimal import Decimal

from email.message import EmailMessage

from functools import wraps

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

from typing import Optional, Dict, List, Tuple, Any



# Import from consolidated ai_core module
from ai_core import (
    MODEL_PATH,
    PROFILE_FEATURE_DEFAULTS,
    BehavioralProfiler,
    CustomerBehavioralProfile,
    TransactionAnomaly,
    behavioral_profiler,
    delete_ai_model,
    get_model_metadata,
    predict_risk_level,
    train_ai_model,
)

from config import DevelopmentConfig, ProductionConfig, TestingConfig

from screening import is_registration_blocked, screen_entity, screening_summary


# ============================================================================
# Real-time Event Broadcasting (Consolidated from realtime.py)
# ============================================================================

try:
    import redis
except ImportError:
    redis = None

try:
    from kafka import KafkaProducer
except ImportError:
    KafkaProducer = None


class RealtimeBroker:
    """Real-time event broker for WebSocket/Redis/Kafka broadcasting."""
    def __init__(self, app=None, socketio=None):
        self.app = app
        self.socketio = socketio
        self._subscribers = []
        self._redis_client = None
        self._redis_pubsub = None
        self._kafka_producer = None
        self._instance_id = str(uuid.uuid4())
        self._init_brokers()
        self._start_redis_listener()

    def _init_brokers(self):
        redis_url = os.environ.get("REDIS_URL")
        if redis_url and redis is not None:
            try:
                self._redis_client = redis.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_connect_timeout=0.5,
                    socket_timeout=0.5,
                )
                self._redis_client.ping()
            except Exception:
                self._redis_client = None

        kafka_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS")
        # Skip Kafka if not configured or set to localhost (won't work in cloud)
        if kafka_bootstrap and KafkaProducer is not None and "localhost" not in kafka_bootstrap and "127.0.0.1" not in kafka_bootstrap:
            try:
                self._kafka_producer = KafkaProducer(
                    bootstrap_servers=[server.strip() for server in kafka_bootstrap.split(",") if server.strip()],
                    api_version_auto_timeout_ms=100,
                    request_timeout_ms=200,
                    max_block_ms=200,
                    value_serializer=lambda value: json.dumps(value).encode("utf-8"),
                )
            except Exception:
                self._kafka_producer = None

    def _start_redis_listener(self):
        """Subscribe to Redis pub/sub for cross-instance event fan-out."""
        if self._redis_client is None:
            return
        try:
            self._redis_pubsub = self._redis_client.pubsub(ignore_subscribe_messages=True)
            self._redis_pubsub.subscribe("aml-events")

            def _listen():
                for raw in self._redis_pubsub.listen():
                    if raw.get("type") != "message":
                        continue
                    try:
                        message = json.loads(raw["data"])
                        if message.get("publisher") == self._instance_id:
                            continue
                        self._local_deliver(message.get("event"), message.get("data"))
                    except Exception:
                        pass

            thread = threading.Thread(target=_listen, daemon=True)
            thread.start()
        except Exception:
            self._redis_pubsub = None

    def _local_deliver(self, event_name, payload):
        if not event_name:
            return
        message = {"event": event_name, "data": payload}
        delivered = set()
        app_subscribers = self.app.config.get("STREAM_SUBSCRIBERS", []) if self.app is not None else []
        for subscriber in list(self._subscribers) + list(app_subscribers):
            subscriber_id = id(subscriber)
            if subscriber_id in delivered:
                continue
            delivered.add(subscriber_id)
            try:
                subscriber.put_nowait(message)
            except Exception:
                pass
        if self.socketio is not None:
            try:
                self.socketio.emit(event_name, payload, broadcast=True)
                if self.app:
                    self.app.logger.debug(f"SocketIO broadcast event: {event_name}")
            except Exception as e:
                if self.app:
                    self.app.logger.error(f"SocketIO broadcast failed for {event_name}: {e}")

    def set_socketio(self, socketio):
        self.socketio = socketio

    def add_subscriber(self, queue):
        self._subscribers.append(queue)
        if self.app is not None:
            app_subscribers = self.app.config.setdefault("STREAM_SUBSCRIBERS", [])
            if queue not in app_subscribers:
                app_subscribers.append(queue)
        return queue

    def publish(self, event_name, payload):
        message = {"event": event_name, "data": payload, "publisher": self._instance_id}
        self._local_deliver(event_name, payload)

        if self._redis_client is not None:
            try:
                event_key = f"aml_events:history"
                self._redis_client.lpush(event_key, json.dumps(message))
                self._redis_client.ltrim(event_key, 0, 999)
                self._redis_client.expire(event_key, 3600)
                self._redis_client.publish("aml-events", json.dumps(message))
                if self.app:
                    self.app.logger.debug(f"Published event to Redis: {event_name}")
            except Exception as e:
                if self.app:
                    self.app.logger.error(f"Failed to publish event to Redis: {e}")

        if self._kafka_producer is not None:
            try:
                self._kafka_producer.send("aml-events", message)
            except Exception:
                pass

    def stream_response(self):
        queue = Queue()
        self.add_subscriber(queue)

        def generate():
            try:
                yield ": connected\n\n"
                while True:
                    try:
                        message = queue.get(timeout=1)
                    except Empty:
                        yield ": heartbeat\n\n"
                        continue
                    yield f"event: {message['event']}\n"
                    yield f"data: {json.dumps(message['data'])}\n\n"
            finally:
                if queue in self._subscribers:
                    self._subscribers.remove(queue)
                if self.app is not None:
                    app_subscribers = self.app.config.get("STREAM_SUBSCRIBERS", [])
                    if queue in app_subscribers:
                        app_subscribers.remove(queue)

        return Response(generate(), mimetype="text/event-stream")






load_dotenv()



app = Flask(__name__)

app.config.from_object(

    DevelopmentConfig if os.environ.get("FLASK_ENV") == "development" else ProductionConfig

)

# behavioral_profiler is imported from ai_core module
# No need to reinitialize - using global instance from ai_core


def get_customer_behavioral_profile(conn, account_number: str) -> Optional[CustomerBehavioralProfile]:
    """Load customer's behavioral profile from database."""
    row = conn.execute(
        "SELECT profile_data FROM behavioral_profiles WHERE account_number=?",
        (account_number,)
    ).fetchone()
    
    if not row or not row["profile_data"]:
        return None
    
    try:
        profile_data = json.loads(row["profile_data"])
        return behavioral_profiler.dict_to_profile(profile_data)
    except (json.JSONDecodeError, TypeError):
        return None


def save_customer_behavioral_profile(conn, profile: CustomerBehavioralProfile):
    """Save customer's behavioral profile to database."""
    profile_dict = behavioral_profiler.profile_to_dict(profile)
    profile_json = json.dumps(profile_dict)
    
    existing = conn.execute(
        "SELECT account_number FROM behavioral_profiles WHERE account_number=?",
        (profile.account_number,)
    ).fetchone()
    
    if existing:
        conn.execute(
            "UPDATE behavioral_profiles SET profile_data=?, last_updated=?, total_transactions=? WHERE account_number=?",
            (profile_json, profile.last_updated, profile.total_transactions, profile.account_number)
        )
    else:
        conn.execute(
            "INSERT INTO behavioral_profiles (account_number, profile_data, last_updated, total_transactions) VALUES (?, ?, ?, ?)",
            (profile.account_number, profile_json, profile.last_updated, profile.total_transactions)
        )


def build_or_update_customer_profile(conn, account_number: str) -> Optional[CustomerBehavioralProfile]:
    """Build or update customer's behavioral profile from transaction history."""
    # Get customer's transaction history
    transactions = conn.execute(
        """
        SELECT id, amount, transaction_type, sender_account, receiver_account, 
               channel, timestamp, destination_country
        FROM transactions
        WHERE sender_account=? OR receiver_account=?
        ORDER BY timestamp DESC
        LIMIT 500
        """,
        (account_number, account_number)
    ).fetchall()
    
    if not transactions:
        return None
    
    # Convert to list of dicts
    tx_list = [dict(tx) for tx in transactions]
    
    # Extract profile (balance history not available from transactions table)
    profile = behavioral_profiler.extract_profile_from_history(
        account_number, tx_list, None
    )
    
    if profile:
        save_customer_behavioral_profile(conn, profile)
    
    return profile


def assess_transaction_behavioral_risk(
    conn,
    transaction: Dict[str, Any],
    sender_account: str
) -> Tuple[float, str, str, List[str]]:
    """
    Assess transaction risk using behavioral profiling.
    
    Engineering Constraint: No Circular Flagging
    - Behavioral scoring is based strictly on statistical anomalies (velocity, amount deviation, counterparty network)
    - Past alerts, alert counts, or historical risk ratings are NOT used in scoring
    - Cold-start grace period: Users with < 5 transactions get neutral baseline, rely on global ML model
    
    Returns:
        (risk_score, risk_level, reason, anomaly_reasons)
    """
    # Get or build customer profile
    profile = get_customer_behavioral_profile(conn, sender_account)
    
    if not profile:
        # Try to build profile from history
        profile = build_or_update_customer_profile(conn, sender_account)
    
    if not profile:
        # Insufficient data for behavioral analysis - cold start
        # Return neutral baseline to rely on global ML model (ai_core.py)
        return 0, "normal", "Cold-start: insufficient transaction history for behavioral analysis (< 5 transactions)", []
    
    # Cold-start grace period: check if user has < 5 transactions
    if profile.total_transactions < 5:
        # Return neutral baseline to rely on global ML model
        return 0, "normal", f"Cold-start: building behavioral baseline ({profile.total_transactions}/5 transactions)", []
    
    # Detect anomaly using statistical features only (velocity, amount deviation, counterparty network)
    anomaly = behavioral_profiler.detect_anomaly(profile, transaction)
    
    # Update profile with this transaction (pass anomaly score for adaptive learning)
    updated_profile = behavioral_profiler.update_profile(profile, transaction, anomaly.overall_anomaly_score)
    save_customer_behavioral_profile(conn, updated_profile)
    
    # Convert anomaly score to risk score (0-100)
    risk_score = int(anomaly.overall_anomaly_score)
    
    # Map anomaly risk level to standard risk levels
    risk_level_mapping = {
        "normal": "normal",
        "low": "low", 
        "medium": "suspicious",
        "high": "high_risk",
        "critical": "critical"
    }
    risk_level = risk_level_mapping.get(anomaly.risk_level, "normal")
    
    # Build reason
    reason = anomaly.behavioral_context
    if anomaly.anomaly_reasons:
        reason += " " + "; ".join(anomaly.anomaly_reasons)
    
    return risk_score, risk_level, reason, anomaly.anomaly_reasons

if app.config.get("TESTING"):

    app.config.from_object(TestingConfig)



app.config.setdefault("STREAM_SUBSCRIBERS", [])

app.config.setdefault("LAST_MONITORED_TRANSACTION_ID", 0)

app.config.setdefault("REALTIME_POLL_INTERVAL", 0.5)

app.config.setdefault("ACTIVE_STREAMS", {})

app.config.setdefault(

    "DATABASE",

    app.config.get("DATABASE_URL", os.path.join(os.path.dirname(__file__), "aml.db")),

)



# Ensure data directory exists for Railway

if app.config["DATABASE"].startswith("sqlite:///"):

    db_path = app.config["DATABASE"].replace("sqlite:///", "")

    db_dir = os.path.dirname(db_path)

    if db_dir and not os.path.exists(db_dir):

        os.makedirs(db_dir, exist_ok=True)



logging.basicConfig(level=logging.INFO)

app.logger.setLevel(logging.INFO)



# Configure SocketIO with Redis message queue for cross-device broadcasting
redis_url = os.environ.get("REDIS_URL")
socketio_kwargs = {
    "cors_allowed_origins": "*",
    "manage_session": False,
    "async_mode": "threading",
}

if redis_url and redis is not None:
    try:
        socketio_kwargs["message_queue"] = redis_url
        socketio_kwargs["channel"] = "aml-socketio"
        app.logger.info(f"SocketIO configured with Redis message queue: {redis_url}")
    except Exception as e:
        app.logger.warning(f"Failed to configure Redis message queue: {e}")
else:
    app.logger.warning("REDIS_URL not configured, SocketIO will work in single-instance mode")

socketio = SocketIO(app, **socketio_kwargs)

app.extensions["realtime_broker"] = RealtimeBroker(app=app, socketio=socketio)



# SocketIO authentication middleware

@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session:
        app.logger.warning("SocketIO connection rejected: no user_id in session")
        return False
    
    user_id = session.get('user_id')
    role = session.get('role', 'unknown')
    app.logger.info(f"User {user_id} (role: {role}) connected via SocketIO")
    
    # Send initial connection confirmation
    socketio.emit('connect', {'status': 'connected', 'user_id': user_id}, to=request.sid)
    
    return True



@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        user_id = session.get('user_id')
        role = session.get('role', 'unknown')
        app.logger.info(f"User {user_id} (role: {role}) disconnected from SocketIO")



ID_NUMBER_PATTERN = re.compile(r"^\d{2}-\d{6,7}[A-Z]\d{2}$")

ID_NUMBER_FORMAT_MESSAGE = "ID number must use the format 00-000000A00, for example 08-995728P34."



PAGE_SIZE = 25  # rows per paginated list

VALID_TRANSACTION_TYPES = {"deposit", "withdraw", "transfer"}



AI_RISK_SCORES = {

    "normal": 10,

    "suspicious": 55,

    "super_suspicious": 90,

}



STAFF_ACCOUNTS = {

    "Admin": {

        "password": os.environ.get("ADMIN_PASSWORD", "Admin123"),

        "role": "admin",

        "email": os.environ.get("ADMIN_EMAIL", "admin@example.com"),

        "id_number": "63-1000001A01",

        "account_number": "ACC1001",

    },

    "Compliance": {

        "password": os.environ.get("COMPLIANCE_PASSWORD", "Compliance123"),

        "role": "compliance",

        "email": os.environ.get("COMPLIANCE_EMAIL", "compliance@example.com"),

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

        ai, pk_type, text_type, long_text_type, real_type = "AUTO_INCREMENT", "BIGINT", "VARCHAR(255)", "LONGTEXT", "DOUBLE"

    elif is_pg:

        ai, pk_type, text_type, long_text_type, real_type = "GENERATED ALWAYS AS IDENTITY", "BIGINT", "TEXT", "TEXT", "DOUBLE PRECISION"

    else:

        ai, pk_type, text_type, long_text_type, real_type = "AUTOINCREMENT", "INTEGER", "TEXT", "TEXT", "REAL"



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

        wealth_segment {text_type} DEFAULT 'average',

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

        rule_score {real_type} DEFAULT 0,

        rule_level {text_type} DEFAULT 'normal',

        rule_reason {long_text_type},

        ai_risk_level {text_type},

        ai_confidence {real_type} DEFAULT 0,

        ai_reason {long_text_type},

        description {long_text_type},

        rules_triggered {long_text_type},

        ctr_required INTEGER DEFAULT 0,

        sar_required INTEGER DEFAULT 0,

        destination_country {text_type} DEFAULT 'ZW',

        screening_hits {long_text_type},

        reviewed_by {text_type},

        reviewed_at {text_type}

    );



    CREATE TABLE IF NOT EXISTS alerts (

        {pk_clause("id")},

        transaction_id INTEGER NOT NULL,

        account_number {text_type} NOT NULL,

        risk_score {real_type} NOT NULL,

        risk_level {text_type} NOT NULL,

        reason {long_text_type} NOT NULL,

        rules_triggered {long_text_type},

        status {text_type} DEFAULT 'open',

        assigned_to {text_type},

        case_notes {long_text_type},

        resolved_at {text_type},

        resolved_by {text_type},

        timestamp {text_type} NOT NULL

    );



    CREATE TABLE IF NOT EXISTS sar_reports (

        {pk_clause("id")},

        alert_id INTEGER NOT NULL,

        account_number {text_type} NOT NULL,

        filed_by {text_type} NOT NULL,

        narrative {long_text_type} NOT NULL,

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

        reason {long_text_type},

        added_by {text_type} NOT NULL,

        added_at {text_type} NOT NULL

    );



    CREATE TABLE IF NOT EXISTS activity_log (

        {pk_clause("id")},

        actor {text_type} NOT NULL,

        action {text_type} NOT NULL,

        detail {long_text_type} NOT NULL,

        ip_address {text_type},

        timestamp {text_type} NOT NULL

    );



    CREATE TABLE IF NOT EXISTS behavioral_profiles (

        account_number {text_type} PRIMARY KEY,

        profile_data {long_text_type},

        last_updated {text_type},

        total_transactions INTEGER DEFAULT 0

    );

    """





def init_db():

    conn = connect_db()

    conn.executescript(get_schema_sql())

    # SQLite migration: add new columns to existing tables

    if not is_postgres_database_url(app.config["DATABASE"]) and not is_mysql_database_url(app.config["DATABASE"]):

        _migrate_sqlite(conn)

    elif is_mysql_database_url(app.config["DATABASE"]):

        _migrate_mysql(conn)

    elif is_postgres_database_url(app.config["DATABASE"]):

        _migrate_postgres(conn)

    conn.commit()

    conn.close()





def _migrate_sqlite(conn):

    """Add columns that may not exist in older DB files."""

    migrations = {

        "users": ["kyc_status TEXT DEFAULT 'pending'", "pep_flag INTEGER DEFAULT 0", "risk_rating TEXT DEFAULT 'standard'", "wealth_segment TEXT DEFAULT 'average'"],

        "transactions": ["currency TEXT DEFAULT 'USD'", "channel TEXT DEFAULT 'online'",

                         "rule_score REAL DEFAULT 0", "rule_level TEXT DEFAULT 'normal'",

                         "rule_reason TEXT", "ai_risk_level TEXT", "ai_confidence REAL DEFAULT 0",

                         "ai_reason TEXT",

                         "rules_triggered TEXT DEFAULT '[]'", "ctr_required INTEGER DEFAULT 0",

                         "sar_required INTEGER DEFAULT 0", "destination_country TEXT DEFAULT 'ZW'",

                         "screening_hits TEXT", "reviewed_by TEXT", "reviewed_at TEXT"],

        "alerts": ["rules_triggered TEXT DEFAULT '[]'", "status TEXT DEFAULT 'open'",

                   "assigned_to TEXT", "case_notes TEXT", "resolved_at TEXT", "resolved_by TEXT"],

        "behavioral_profiles": ["account_number TEXT PRIMARY KEY", "profile_data TEXT", "last_updated TEXT", "total_transactions INTEGER DEFAULT 0"],

    }

    for table, cols in migrations.items():

        existing = [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]

        for col_def in cols:

            col_name = col_def.split()[0]

            if col_name not in existing:

                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")





def _migrate_mysql(conn):
    """Widen older MySQL VARCHAR columns that store AML evidence JSON/text."""

    column_migrations = {

        "users": [
            ("kyc_status", "VARCHAR(255) DEFAULT 'pending'"),
            ("pep_flag", "INTEGER DEFAULT 0"),
            ("risk_rating", "VARCHAR(255) DEFAULT 'standard'"),
            ("wealth_segment", "VARCHAR(255) DEFAULT 'average'"),
        ],
        "transactions": [
            ("currency", "VARCHAR(255) DEFAULT 'USD'"),
            ("channel", "VARCHAR(255) DEFAULT 'online'"),
            ("rule_score", "DOUBLE DEFAULT 0"),
            ("rule_level", "VARCHAR(255) DEFAULT 'normal'"),
            ("rule_reason", "LONGTEXT"),
            ("ai_risk_level", "VARCHAR(255)"),
            ("ai_confidence", "DOUBLE DEFAULT 0"),
            ("ai_reason", "LONGTEXT"),
            ("rules_triggered", "LONGTEXT DEFAULT '[]'"),
            ("ctr_required", "INTEGER DEFAULT 0"),
            ("sar_required", "INTEGER DEFAULT 0"),
            ("destination_country", "VARCHAR(255) DEFAULT 'ZW'"),
            ("screening_hits", "LONGTEXT"),
            ("reviewed_by", "VARCHAR(255)"),
            ("reviewed_at", "VARCHAR(255)"),
        ],
        "alerts": [
            ("rules_triggered", "LONGTEXT DEFAULT '[]'"),
            ("status", "VARCHAR(255) DEFAULT 'open'"),
            ("assigned_to", "VARCHAR(255)"),
            ("case_notes", "LONGTEXT"),
            ("resolved_at", "VARCHAR(255)"),
            ("resolved_by", "VARCHAR(255)"),
        ],
        "behavioral_profiles": [
            ("account_number", "VARCHAR(255) PRIMARY KEY"),
            ("profile_data", "LONGTEXT"),
            ("last_updated", "VARCHAR(255)"),
            ("total_transactions", "INTEGER DEFAULT 0"),
        ],
    }

    for table, columns in column_migrations.items():
        try:
            existing = {
                row["Field"]
                for row in conn.execute(f"SHOW COLUMNS FROM {table}").fetchall()
            }
            for column_name, column_def in columns:
                if column_name not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_name} {column_def}")
        except Exception as e:
            logging.error(f"Error adding columns to {table}: {e}")


def _migrate_postgres(conn):
    """Add columns for PostgreSQL databases."""
    column_migrations = {
        "users": [
            ("kyc_status", "TEXT DEFAULT 'pending'"),
            ("pep_flag", "INTEGER DEFAULT 0"),
            ("risk_rating", "TEXT DEFAULT 'standard'"),
            ("wealth_segment", "TEXT DEFAULT 'average'"),
        ],
        "transactions": [
            ("currency", "TEXT DEFAULT 'USD'"),
            ("channel", "TEXT DEFAULT 'online'"),
            ("rule_score", "DOUBLE PRECISION DEFAULT 0"),
            ("rule_level", "TEXT DEFAULT 'normal'"),
            ("rule_reason", "TEXT"),
            ("ai_risk_level", "TEXT"),
            ("ai_confidence", "DOUBLE PRECISION DEFAULT 0"),
            ("ai_reason", "TEXT"),
            ("rules_triggered", "TEXT DEFAULT '[]'"),
            ("ctr_required", "INTEGER DEFAULT 0"),
            ("sar_required", "INTEGER DEFAULT 0"),
            ("destination_country", "TEXT DEFAULT 'ZW'"),
            ("screening_hits", "TEXT"),
            ("reviewed_by", "TEXT"),
            ("reviewed_at", "TEXT"),
        ],
        "alerts": [
            ("rules_triggered", "TEXT DEFAULT '[]'"),
            ("status", "TEXT DEFAULT 'open'"),
            ("assigned_to", "TEXT"),
            ("case_notes", "TEXT"),
            ("resolved_at", "TEXT"),
            ("resolved_by", "TEXT"),
        ],
        "behavioral_profiles": [
            ("account_number", "TEXT PRIMARY KEY"),
            ("profile_data", "TEXT"),
            ("last_updated", "TEXT"),
            ("total_transactions", "INTEGER DEFAULT 0"),
        ],
    }

    for table, columns in column_migrations.items():
        try:
            # Check if table exists
            table_exists = conn.execute(
                "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = %s)",
                (table,)
            ).fetchone()[0]
            
            if not table_exists:
                # Create behavioral_profiles table if it doesn't exist
                if table == "behavioral_profiles":
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS behavioral_profiles (
                            account_number TEXT PRIMARY KEY,
                            profile_data TEXT,
                            last_updated TEXT,
                            total_transactions INTEGER DEFAULT 0
                        )
                    """)
                continue
                
            existing = {
                row["column_name"]
                for row in conn.execute(
                    "SELECT column_name FROM information_schema.columns WHERE table_name = %s",
                    (table,)
                ).fetchall()
            }
            for column_name, column_def in columns:
                if column_name not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_name} {column_def}")
        except Exception as e:
            logging.error(f"Error adding columns to {table}: {e}")





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

                "INSERT INTO users (username, email, id_number, password_hash, role, account_number, balance, kyc_status, wealth_segment, created_at) VALUES (?,?,?,?,?,?,5000,'verified','average',?)",

                (username, email, id_number, pwd_hash, role, acct, now),

            )

        else:

            conn.execute(

                """

                UPDATE users

                SET username=?, email=?, id_number=?, password_hash=?, role=?,

                    account_number=?, kyc_status='verified', wealth_segment='average'

                WHERE id=?

                """,

                (username, email, id_number, pwd_hash, role, acct, existing["id"]),

            )

    _seed_wealth_tier_users(conn, now)

    _seed_watchlist(conn)

    conn.commit()

    conn.close()


def _seed_wealth_tier_users(conn, now):
    """Seed users with different wealth tiers for realistic transaction simulation."""
    wealth_tiers = {
        "low": {"count": 5, "balance_range": (500, 5000), "transaction_range": (50, 500)},
        "average": {"count": 5, "balance_range": (10000, 50000), "transaction_range": (500, 5000)},
        "high": {"count": 3, "balance_range": (100000, 500000), "transaction_range": (5000, 50000)},
        "ultra_high": {"count": 2, "balance_range": (1000000, 10000000), "transaction_range": (50000, 500000)},
    }
    
    user_id = 1000
    for tier, config in wealth_tiers.items():
        for i in range(config["count"]):
            username = f"user_{tier}_{i+1}"
            email = f"{username}@example.com"
            id_number = f"63-{user_id:07d}A{user_id % 100:02d}"
            account_number = f"ACC{user_id}"
            balance = random.randint(*config["balance_range"])
            
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ? OR account_number = ?",
                (username, account_number),
            ).fetchone()
            
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO users (username, email, id_number, password_hash, role, account_number, balance, kyc_status, wealth_segment, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (username, email, id_number, generate_password_hash("password123"), "customer", account_number,
                     balance, "verified", tier, now),
                )
            user_id += 1





def _seed_watchlist(conn):

    """Seed industry-standard sanctions and PEP entries for demonstration screening."""

    now = datetime.now(timezone.utc).isoformat()

    defaults = [

        ("OFAC SDN — Example Entity", "99-0000001X01", None, "sanctions",

         "OFAC Specially Designated Nationals list match (demo entry)"),

        ("UN Consolidated Sanctions — Demo", "99-0000002X02", None, "sanctions",

         "UN Security Council consolidated sanctions list (demo entry)"),

        ("PEP — Senior Government Official", "88-0000001P01", None, "pep",

         "Politically Exposed Person — senior government official"),

        ("Internal Fraud Watch", None, "ACC9999", "internal",

         "Internal fraud investigation — account frozen"),

    ]

    for name, id_num, acct, list_type, reason in defaults:

        existing = conn.execute(

            "SELECT id FROM watchlist WHERE name=? AND list_type=?",

            (name, list_type),

        ).fetchone()

        if existing is None:

            conn.execute(

                """

                INSERT INTO watchlist (name, id_number, account_number, list_type, reason, added_by, added_at)

                VALUES (?,?,?,?,?,'system',?)

                """,

                (name, id_num, acct, list_type, reason, now),

            )





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

    timestamp = datetime.now(timezone.utc).isoformat()

    get_db().execute(

        "INSERT INTO activity_log (actor, action, detail, ip_address, timestamp) VALUES (?,?,?,?,?)",

        (actor, action, detail, ip, timestamp),

    )

    get_db().commit()

    broadcast_event("activity", {

        "actor": actor,

        "action": action,

        "detail": detail,

        "ip_address": ip,

        "timestamp": timestamp,

    })



def get_last_insert_id(conn):

    if is_postgres_database_url(app.config["DATABASE"]):

        return conn.execute("SELECT LASTVAL() as id").fetchone()["id"]

    if is_mysql_database_url(app.config["DATABASE"]):

        return conn.execute("SELECT LAST_INSERT_ID() as id").fetchone()["id"]

    return conn.execute("SELECT last_insert_rowid() as id").fetchone()["id"]



def broadcast_event(event_name, payload):

    app.extensions["realtime_broker"].publish(event_name, payload)





def _stats_payload(conn):

    today_start = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00")

    return {

        "total_transactions": conn.execute("SELECT COUNT(*) as c FROM transactions").fetchone()["c"],

        "suspicious_transactions": conn.execute(

            "SELECT COUNT(*) as c FROM transactions WHERE risk_level!='normal'"

        ).fetchone()["c"],

        "open_alerts": conn.execute("SELECT COUNT(*) as c FROM alerts WHERE status='open'").fetchone()["c"],

        "high_risk_today": conn.execute(

            "SELECT COUNT(*) as c FROM transactions WHERE risk_level IN ('super_suspicious','high_risk','critical') AND timestamp>=?",

            (today_start,),

        ).fetchone()["c"],

        "pending_sars": conn.execute("SELECT COUNT(*) as c FROM sar_reports WHERE status='draft'").fetchone()["c"],

        "pending_ctrs": conn.execute("SELECT COUNT(*) as c FROM ctr_reports WHERE status='pending'").fetchone()["c"],

        "timestamp": datetime.now(timezone.utc).isoformat(),

    }





def broadcast_stats(conn=None):

    conn = conn or get_db()

    broadcast_event("stats", _stats_payload(conn))





def request_page(default=1):

    try:

        page = int(request.args.get("page", 1))

    except (TypeError, ValueError):

        return default

    return max(1, page)





def _user_balance_payload(row):

    return {

        "user_id": row["id"],

        "username": row["username"],

        "account_number": row["account_number"],

        "balance": float(row["balance"] or 0),

        "kyc_status": row["kyc_status"],

        "timestamp": datetime.now(timezone.utc).isoformat(),

    }





def serialize_value(value):

    if isinstance(value, Decimal):

        return float(value)

    if isinstance(value, datetime):

        return value.isoformat()

    return value





def serialize_row(row):

    return {key: serialize_value(row[key]) for key in row.keys()}





def serialize_rows(rows):

    return [serialize_row(row) for row in rows]





def broadcast_user_balance(conn, account_number):

    row = conn.execute(

        "SELECT id, username, account_number, balance, kyc_status FROM users WHERE account_number=?",

        (account_number,),

    ).fetchone()

    if row:

        broadcast_event("balance", _user_balance_payload(row))





def broadcast_alert_update(conn, alert_id, event_name="alert_update"):

    row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()

    if row:

        broadcast_event(event_name, {

            "id": row["id"],

            "transaction_id": row["transaction_id"],

            "account_number": row["account_number"],

            "risk_score": float(row["risk_score"] or 0),

            "risk_level": row["risk_level"],

            "reason": row["reason"],

            "status": row["status"],

            "assigned_to": row["assigned_to"],

            "resolved_by": row["resolved_by"],

            "resolved_at": row["resolved_at"],

            "timestamp": row["timestamp"],

        })





def _json_safe(value):

    if value is None or isinstance(value, (str, int, float, bool)):

        return value

    try:

        return float(value)

    except (TypeError, ValueError):

        return str(value)





def broadcast_report_event(kind, row):

    broadcast_event(kind, {

        key: _json_safe(row[key])

        for key in row.keys()

    })



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

    normal_count = int(count * 0.60)

    suspicious_count = int(count * 0.30)

    super_count = count - normal_count - suspicious_count

    labels = (

        ["normal"] * normal_count

        + ["suspicious"] * suspicious_count

        + ["super_suspicious"] * super_count

    )

    random.shuffle(labels)

    return labels





def _simulation_timestamp(hour):

    now = datetime.now(timezone.utc)

    days_back = random.randint(1, 30)

    candidate = now - timedelta(

        days=days_back,

        minutes=random.randint(0, 23 * 60 + 59),

    )

    return candidate.replace(

        hour=hour,

        minute=random.randint(0, 59),

        second=random.randint(0, 59),

        microsecond=0,

    ).isoformat()





NORMAL_TRANSACTION_SCENARIOS = [

    {

        "type": "deposit",

        "amount": (850, 4200),

        "channel": "ach",

        "hours": list(range(8, 17)),

        "description": "Payroll credit from registered employer",

    },

    {

        "type": "withdraw",

        "amount": (12, 180),

        "channel": "card",

        "hours": list(range(7, 22)),

        "description": "Point-of-sale card purchase at local merchant",

    },

    {

        "type": "withdraw",

        "amount": (20, 500),

        "channel": "atm",

        "hours": list(range(6, 23)),

        "description": "ATM cash withdrawal at bank terminal",

    },

    {

        "type": "transfer",

        "amount": (35, 950),

        "channel": "mobile",

        "hours": list(range(7, 22)),

        "description": "Mobile transfer for household payment",

    },

    {

        "type": "transfer",

        "amount": (120, 1800),

        "channel": "online",

        "hours": list(range(8, 20)),

        "description": "Online bill payment to regular beneficiary",

    },

]



SUSPICIOUS_TRANSACTION_SCENARIOS = [

    {

        "type": "deposit",

        "amount": (9200, 9900),

        "channel": "branch",

        "hours": list(range(9, 16)),

        "description": "Cash deposit just below currency reporting threshold",

        "reason": "Possible structuring: cash deposit below the CTR threshold",

    },

    {

        "type": "transfer",

        "amount": (1400, 6800),

        "channel": "online",

        "hours": [0, 1, 2, 3, 22, 23],

        "description": "Unusual off-hours transfer to recently added beneficiary",

        "reason": "Off-hours transfer pattern inconsistent with normal customer activity",

    },

    {

        "type": "withdraw",

        "amount": (1500, 6500),

        "channel": "atm",

        "hours": [0, 1, 2, 3, 4, 22, 23],

        "description": "High-value ATM cash withdrawal outside normal banking hours",

        "reason": "Large cash withdrawal during unusual hours",

    },

    {

        "type": "transfer",

        "amount": (2500, 7400),

        "channel": "mobile",

        "hours": list(range(6, 23)),

        "description": "Multiple rapid mobile transfers to another customer account",

        "reason": "Potential layering through repeated customer-to-customer transfers",

    },

]



SUPER_SUSPICIOUS_TRANSACTION_SCENARIOS = [

    {

        "type": "deposit",

        "amount": (10000, 28000),

        "channel": "branch",

        "hours": list(range(9, 16)),

        "description": "Large cash deposit requiring currency transaction review",

        "reason": "Cash transaction exceeds the CTR threshold and requires enhanced review",

    },

    {

        "type": "transfer",

        "amount": (12000, 52000),

        "channel": "swift",

        "hours": [0, 1, 2, 3, 23],

        "destination_country": "IR",

        "description": "High-value SWIFT transfer to high-risk jurisdiction",

        "reason": "High-value off-hours transfer to FATF grey-list jurisdiction",

    },

    {

        "type": "withdraw",

        "amount": (10000, 24000),

        "channel": "branch",

        "hours": list(range(9, 16)),

        "description": "Large over-the-counter cash withdrawal",

        "reason": "Large cash withdrawal meets threshold for immediate compliance review",

    },

]





def _scenario_amount(low, high, label):

    amount = random.triangular(low, high, low + ((high - low) * 0.35))

    if label == "normal":

        return round(amount, 2)

    if low >= 9000:

        return round(amount / 50) * 50

    return round(amount / 10) * 10





def _simulation_segment_multiplier(segment, label):

    segment = (segment or "average").lower()

    multipliers = {

        "low": {"normal": 0.6, "suspicious": 0.75, "super_suspicious": 0.9},

        "average": {"normal": 1.0, "suspicious": 1.0, "super_suspicious": 1.0},

        "high": {"normal": 1.5, "suspicious": 1.1, "super_suspicious": 1.2},

        "ultra_high": {"normal": 2.0, "suspicious": 1.2, "super_suspicious": 1.3},

    }

    return multipliers.get(segment, multipliers["average"]).get(label, 1.0)


def _simulation_transaction(label, users):

    if label == "normal":

        scenario = random.choice(NORMAL_TRANSACTION_SCENARIOS)

    elif label == "suspicious":

        scenario = random.choice(SUSPICIOUS_TRANSACTION_SCENARIOS)

    else:

        scenario = random.choice(SUPER_SUSPICIOUS_TRANSACTION_SCENARIOS)


    tx_type = scenario["type"]

    sender = random.choice(users)

    amount = round(
        _scenario_amount(*scenario["amount"], label)
        * _simulation_segment_multiplier(sender.get("wealth_segment", "average"), label),
        2,
    )

    hour = random.choice(scenario["hours"])


    if tx_type in ("withdraw", "transfer") and sender.get("balance") is not None:

        balance = float(sender["balance"] or 0)

        if balance > 0 and amount > balance * 0.85:

            amount = round(balance * random.uniform(0.35, 0.75), 2)

            amount = max(amount, 1.0)


    recipient = sender

    if tx_type == "transfer" and len(users) > 1:

        recipient = random.choice([user for user in users if user["id"] != sender["id"]])


    timestamp = _simulation_timestamp(hour)

    dest_country = scenario.get("destination_country", "ZW")

    return (

        sender, recipient, tx_type, amount, timestamp,

        scenario["channel"], scenario["description"], scenario.get("reason"), dest_country,

    )



def _simulation_reason(label, amount, tx_type, scenario_reason=None):

    if label == "normal":

        return "Routine customer activity consistent with known banking behaviour"

    if label == "suspicious":

        return f"{scenario_reason or 'Suspicious transaction pattern'} involving a {tx_type} of ${amount:,.2f}"

    return f"{scenario_reason or 'High-risk AML pattern'} involving a {tx_type} of ${amount:,.2f}"





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

        return get_last_insert_id(conn)

    return None





def _parse_timestamp(value):

    try:

        return datetime.fromisoformat(str(value))

    except (TypeError, ValueError):

        return datetime.now(timezone.utc)





def _history_profile(amount, receiver_account, timestamp, history):

    amounts = history.get("amounts", [])

    recipients = history.get("recipients", set())

    events = history.get("events", [])

    amount = float(amount)

    avg_amount = sum(amounts) / len(amounts) if amounts else 0.0

    max_amount = max(amounts) if amounts else 0.0

    current_time = _parse_timestamp(timestamp)

    cutoff = current_time - timedelta(hours=24)

    recent_amounts = [

        float(event_amount)

        for event_time, event_amount in events

        if event_time >= cutoff

    ]

    volume_24h = sum(recent_amounts)



    profile = dict(PROFILE_FEATURE_DEFAULTS)

    profile.update({

        "sender_avg_amount": avg_amount,

        "sender_max_amount": max_amount,

        "sender_tx_count": len(amounts),

        "amount_to_sender_avg": amount / avg_amount if avg_amount > 0 else 1.0,

        "amount_to_sender_max": amount / max_amount if max_amount > 0 else 1.0,

        "sender_tx_count_24h": len(recent_amounts),

        "sender_volume_24h": volume_24h,

        "amount_to_sender_volume_24h": amount / volume_24h if volume_24h > 0 else 1.0,

        "is_new_recipient": 0.0 if receiver_account in recipients else 1.0,

    })

    return profile





def _ai_profile_for_transaction(conn, transaction_id, sender_account, receiver_account, amount, timestamp):

    cutoff = (_parse_timestamp(timestamp) - timedelta(hours=24)).isoformat()

    prior = conn.execute(

        """

        SELECT

            COUNT(*) AS tx_count,

            COALESCE(AVG(amount), 0) AS avg_amount,

            COALESCE(MAX(amount), 0) AS max_amount,

            COALESCE(u.wealth_segment, 'average') AS wealth_segment

        FROM transactions t

        LEFT JOIN users u ON t.sender_account = u.account_number

        WHERE sender_account=? AND t.id<>? AND timestamp<?

        """,

        (sender_account, transaction_id, timestamp),

    ).fetchone()

    recent = conn.execute(

        """

        SELECT COUNT(*) AS tx_count, COALESCE(SUM(amount), 0) AS volume

        FROM transactions t

        WHERE sender_account=? AND t.id<>? AND timestamp>=? AND timestamp<?

        """,

        (sender_account, transaction_id, cutoff, timestamp),

    ).fetchone()

    recipient_seen = conn.execute(

        """

        SELECT id FROM transactions t

        WHERE sender_account=? AND receiver_account=? AND t.id<>? AND timestamp<?

        LIMIT 1

        """,

        (sender_account, receiver_account, transaction_id, timestamp),

    ).fetchone()



    avg_amount = float(prior.get("avg_amount") if prior else 0)

    max_amount = float(prior.get("max_amount") if prior else 0)

    tx_count = int(prior.get("tx_count") if prior else 0)

    volume_24h = float(recent.get("volume") if recent else 0)

    amount = float(amount)



    profile = dict(PROFILE_FEATURE_DEFAULTS)

    profile.update({

        "sender_avg_amount": avg_amount,

        "sender_max_amount": max_amount,

        "sender_tx_count": tx_count,

        "amount_to_sender_avg": amount / avg_amount if avg_amount > 0 else 1.0,

        "amount_to_sender_max": amount / max_amount if max_amount > 0 else 1.0,

        "sender_tx_count_24h": int(recent.get("tx_count") if recent else 0),

        "sender_volume_24h": volume_24h,

        "amount_to_sender_volume_24h": amount / volume_24h if volume_24h > 0 else 1.0,

        "is_new_recipient": 0.0 if recipient_seen else 1.0,

        "wealth_segment": prior.get("wealth_segment") if prior and prior.get("wealth_segment") else "average",

    })

    return profile





def _ai_training_rows(rows):

    histories = {}

    enriched = []

    for row in rows:

        sender = row["sender_account"]

        history = histories.setdefault(sender, {"amounts": [], "recipients": set(), "events": []})

        profile = _history_profile(row["amount"], row["receiver_account"], row["timestamp"], history)

        item = dict(row)

        item.update(profile)

        enriched.append(item)

        history["amounts"].append(float(row["amount"]))

        history["recipients"].add(row["receiver_account"])

        history["events"].append((_parse_timestamp(row["timestamp"]), float(row["amount"])))

    return enriched





def _train_ai_model_from_db(conn, emit_events=True):

    rows = conn.execute(

        """

        SELECT t.id, t.sender_account, t.receiver_account, t.amount, t.transaction_type,

               t.timestamp, t.risk_level, t.risk_score, t.channel,

               COALESCE(u.wealth_segment, 'average') AS wealth_segment

        FROM transactions t

        LEFT JOIN users u ON t.sender_account = u.account_number

        WHERE description != 'Initiated' OR risk_score > 0

        ORDER BY t.timestamp ASC, t.id ASC

        """

    ).fetchall()

    model = train_ai_model(_ai_training_rows(rows))

    if emit_events:

        meta = get_model_metadata()

        broadcast_event("ai_model", {

            "trained": model is not None,

            "training_rows": len(rows),

            "version": meta.get("version", "unknown"),

            "cross_val_f1": meta.get("cross_val_f1_weighted"),

            "timestamp": datetime.now(timezone.utc).isoformat(),

        })

    return model





def _transaction_payload(row):

    confidence = row["ai_confidence"] if "ai_confidence" in row.keys() else 0

    ctr_required = row["ctr_required"] if "ctr_required" in row.keys() else 0

    sar_required = row["sar_required"] if "sar_required" in row.keys() else 0

    return {

        "id": row["id"],

        "sender_account": row["sender_account"],

        "receiver_account": row["receiver_account"],

        "amount": float(row["amount"]),

        "type": row["transaction_type"],

        "transaction_type": row["transaction_type"],

        "timestamp": row["timestamp"],

        "risk_level": row["risk_level"],

        "risk_score": float(row["risk_score"] or 0),

        "rule_level": row["rule_level"] or "normal",

        "rule_score": float(row["rule_score"] or 0),

        "ai_risk_level": row["ai_risk_level"] or "unavailable",

        "ai_confidence": float(confidence or 0),

        "ctr_required": bool(ctr_required),

        "sar_required": bool(sar_required),

        "channel": row["channel"] if "channel" in row.keys() else "online",

        "description": row["description"] or "",

    }





RISK_RANK = {

    "normal": 0,

    "low": 1,

    "suspicious": 2,

    "super_suspicious": 3,

    "high_risk": 3,

    "critical": 4,

}





def _risk_level_from_score(score):

    if score >= 80:

        return "critical"

    if score >= 60:

        return "high_risk"

    if score >= 40:

        return "suspicious"

    if score >= 25:

        return "low"

    return "normal"





def _combine_rule_ai_risk(rule_score, rule_level, rule_reason, triggered_rules, ai_level, ai_confidence):
    # Simplified - mandatory check now based on screening severity only
    mandatory = any(r.get("severity") == "critical" for r in triggered_rules) if triggered_rules else False

    rule_rank = RISK_RANK.get(rule_level, 0)

    ai_reason = "AI model unavailable or not confident enough to affect final risk."

    final_score = rule_score

    final_level = rule_level

    final_reason = rule_reason



    if ai_level:

        ai_reason = (

            f"AI behavior model predicted {ai_level.replace('_', ' ')} "

            f"with {ai_confidence:.0%} confidence."

        )



    if ai_level and ai_confidence >= 0.55:

        ai_score = AI_RISK_SCORES.get(ai_level, rule_score)

        ai_rank = RISK_RANK.get(ai_level, 0)



        if not mandatory:

            ai_weight = min(0.85, max(0.60, ai_confidence))

            rule_weight = 1 - ai_weight

            blended_score = round((ai_score * ai_weight) + (rule_score * rule_weight))



            if ai_level == "normal" and ai_confidence >= 0.85 and rule_rank < RISK_RANK["low"]:

                final_score = min(blended_score, 24)

                final_level = "normal"

                final_reason = (

                    f"AI-led behavior model recognized this as normal for the sender "

                    f"({ai_confidence:.0%} confidence), so non-mandatory rule risk was reduced. "

                    f"Rule review: {rule_reason}"

                )

            else:

                if ai_level == "normal" and rule_rank >= RISK_RANK["suspicious"]:

                    blended_score = max(rule_score, blended_score)

                final_score = max(0, min(100, blended_score))

                final_level = _risk_level_from_score(final_score)

                if ai_level == "normal" and rule_rank >= RISK_RANK["suspicious"]:

                    ai_direction = "reviewed but did not downgrade"

                else:

                    ai_direction = "increased" if ai_rank > rule_rank else "tempered"

                final_reason = (

                    f"AI-led behavior model {ai_direction} the behavioral risk "

                    f"({ai_confidence:.0%} confidence, {ai_weight:.0%} AI weighting). "

                    f"Rule review: {rule_reason}"

                )

        elif ai_level == "normal":

            final_reason = (

                f"Mandatory compliance rule preserved despite AI normal prediction "

                f"({ai_confidence:.0%} confidence). Rule review: {rule_reason}"

            )

        elif ai_rank > rule_rank:

            final_score = max(rule_score, ai_score)

            final_level = _risk_level_from_score(final_score)

            final_reason = (

                f"Mandatory compliance rule preserved and AI behavior model added elevated context "

                f"({ai_confidence:.0%} confidence). Rule review: {rule_reason}"

            )



    if mandatory and RISK_RANK.get(final_level, 0) < RISK_RANK.get(rule_level, 0):

        final_score = rule_score

        final_level = rule_level

        final_reason = f"Mandatory compliance rule preserved. {rule_reason}"



    return final_score, final_level, final_reason, ai_reason





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

    destination_country="ZW",

):

    sender_user = conn.execute(

        "SELECT username, id_number, pep_flag FROM users WHERE account_number=?",

        (sender_account,),

    ).fetchone()

    receiver_user = conn.execute(

        "SELECT username, id_number, pep_flag FROM users WHERE account_number=?",

        (receiver_account,),

    ).fetchone()



    screening_hits = []

    for party, user_row, acct in (

        ("sender", sender_user, sender_account),

        ("receiver", receiver_user, receiver_account),

    ):

        if user_row:

            party_hits = screen_entity(

                conn,

                name=user_row["username"],

                id_number=user_row["id_number"],

                account_number=acct,

            )

            screening_hits.extend(party_hits)



    screen_delta, screen_reason, screen_json = screening_summary(screening_hits)

    # Legacy rule-based assessment removed - using AI + Behavioral only
    # Screening hits are incorporated directly into risk assessment
    rule_score = screen_delta if screen_delta else 0
    rule_level = _risk_level_from_score(rule_score)
    rule_reason = screen_reason if screen_delta else "No screening hits"
    
    # Build triggered rules list from screening only
    triggered = []
    if screen_delta:
        triggered.append({
            "rule_id": "SCREENING",
            "triggered": True,
            "score_delta": screen_delta,
            "reason": screen_reason,
            "severity": "critical" if any(h.list_type == "sanctions" for h in screening_hits) else "warning",
            "typology": "Watchlist / PEP Screening",
        })

    rules_json = json.dumps(triggered + screen_json)



    # Build transaction dict for behavioral analysis
    transaction_dict = {
        "id": transaction_id,
        "sender_account": sender_account,
        "receiver_account": receiver_account,
        "amount": amount,
        "transaction_type": transaction_type,
        "timestamp": timestamp,
        "destination_country": destination_country,
    }
    
    tx_row = conn.execute("SELECT channel FROM transactions WHERE id=?", (transaction_id,)).fetchone()
    if tx_row and tx_row["channel"]:
        transaction_dict["channel"] = tx_row["channel"]
    
    # Primary: Behavioral-based risk assessment
    behavioral_score, behavioral_level, behavioral_reason, anomaly_reasons = assess_transaction_behavioral_risk(
        conn, transaction_dict, sender_account
    )
    
    # Combine behavioral and screening assessments
    # Behavioral assessment takes priority unless mandatory screening rules are triggered
    mandatory = any(h.list_type == "sanctions" for h in screening_hits)
    
    if mandatory:
        # Mandatory compliance rules override behavioral assessment
        risk_score = rule_score
        risk_level = rule_level
        reason = f"Mandatory compliance rule: {rule_reason}. Behavioral context: {behavioral_reason}"
    elif behavioral_score > 0:
        # Use behavioral assessment when available
        risk_score = behavioral_score
        risk_level = behavioral_level
        reason = behavioral_reason
        
        # Add rule context for high-risk transactions
        if rule_score >= 40:
            reason += f" Rule-based context: {rule_reason}"
            risk_score = max(risk_score, rule_score * 0.3)  # Blend in rule score
            risk_level = _risk_level_from_score(risk_score)
    else:
        # Fallback to rule-based when insufficient behavioral data
        risk_score = rule_score
        risk_level = rule_level
        reason = rule_reason
    
    # Set AI-related fields for database compatibility
    ai_level = behavioral_level if behavioral_score > 0 else None
    ai_confidence = min(1.0, behavioral_score / 100) if behavioral_score > 0 else 0
    ai_reason = behavioral_reason if behavioral_score > 0 else None



    ctr_required = 1 if "[CTR REQUIRED]" in rule_reason else 0

    sar_required = 1 if "[SAR REVIEW]" in rule_reason else 0

    if risk_level in ("suspicious", "super_suspicious", "high_risk", "critical"):

        sar_required = 1



    conn.execute(

        """

        UPDATE transactions

        SET risk_score=?, risk_level=?, rule_score=?, rule_level=?, rule_reason=?,

            ai_risk_level=?, ai_confidence=?, ai_reason=?, description=?, rules_triggered=?,

            ctr_required=?, sar_required=?, destination_country=?, screening_hits=?

        WHERE id=?

        """,

        (

            risk_score, risk_level, rule_score, rule_level, rule_reason,

            ai_level, ai_confidence, ai_reason, reason, rules_json,

            ctr_required, sar_required, destination_country,

            json.dumps(screen_json) if screen_json else "[]",

            transaction_id,

        ),

    )



    created_alert = create_alert_if_needed(

        conn, transaction_id, account_number or sender_account,

        risk_score, risk_level, reason, rules_json, timestamp,

    )



    # Auto-generate CTR

    ctr_id = None

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

            ctr_id = get_last_insert_id(conn)



    if emit_events:

        tx_row = conn.execute("SELECT * FROM transactions WHERE id=?", (transaction_id,)).fetchone()

        if tx_row:

            broadcast_event("transaction", _transaction_payload(tx_row))

        if created_alert:

            broadcast_event("alert", {

                "id": created_alert,

                "transaction_id": transaction_id,

                "account_number": account_number or sender_account,

                "risk_score": risk_score,

                "risk_level": risk_level,

                "reason": reason,

                "timestamp": timestamp,

            })

        if ctr_required and ctr_id:

            row = conn.execute("SELECT * FROM ctr_reports WHERE id=?", (ctr_id,)).fetchone()

            if row:

                broadcast_report_event("ctr_report", row)

        broadcast_stats(conn)



    return risk_score, risk_level, reason, created_alert





# ───────────────────────────────────────────────────── Background monitor ──



def monitor_transactions():

    while not app.config.get("MONITOR_STOP", False):

        try:

            with app.app_context():

                conn = connect_db()

                last_id = app.config.get("LAST_MONITORED_TRANSACTION_ID", 0)

                rows = conn.execute(

                    """

                    SELECT id, sender_account, receiver_account, amount, transaction_type, timestamp

                    FROM transactions

                    WHERE id>? AND risk_score=0 AND description='Initiated'

                    ORDER BY id ASC

                    """,

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

                if rows:

                    _train_ai_model_from_db(conn)

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

            if roles and user and user.get("role") not in roles:

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

    broker = app.extensions.get("realtime_broker")

    status = {

        "status": "ok",

        "service": "stanpro-aml",

        "timestamp": datetime.now(timezone.utc).isoformat(),

        "realtime": {

            "subscribers": len(broker._subscribers) if broker else 0,

            "redis_connected": broker._redis_client is not None if broker else False,

            "kafka_connected": broker._kafka_producer is not None if broker else False,

        },

        "database": app.config.get("DATABASE", "unknown"),

        "active_streams": len(app.config.get("ACTIVE_STREAMS", {})),

    }

    return status, 200





@app.route("/dashboard")

def dashboard_redirect():

    if "user_id" not in session:

        return redirect(url_for("login"))

    user = get_user_by_id(session["user_id"])

    if user is None:

        session.clear()

        flash("Session expired. Please log in again.")

        return redirect(url_for("login"))

    if user["role"] == "customer":

        return redirect(url_for("customer_dashboard"))

    if user["role"] == "compliance":

        return redirect(url_for("compliance_dashboard"))

    return redirect(url_for("admin_dashboard"))





# ── Auth ──



def send_otp_email(recipient_email, otp):

    if app.config.get("TESTING"):

        return True

    sender_email = os.environ.get("SMTP_EMAIL")

    sender_password = os.environ.get("SMTP_PASSWORD")

    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")

    smtp_port = int(os.environ.get("SMTP_PORT", "587"))

    if not sender_email or not sender_password:

        raise ValueError("SMTP credentials not configured")

    msg = EmailMessage()

    msg["Subject"] = "StanPro Bank — Your verification code"

    msg["From"] = sender_email

    msg["To"] = recipient_email

    msg.set_content(f"Your StanPro Bank verification code is: {otp}\n\nThis code expires in 10 minutes.")

    with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as server:

        server.starttls(timeout=30)

        server.login(sender_email, sender_password)

        server.send_message(msg)

    return True


def send_otp_email_async(recipient_email, otp):

    def _send():

        try:

            send_otp_email(recipient_email, otp)

        except Exception as e:

            app.logger.error(f"Failed to send OTP email to {recipient_email}: {str(e)}")

    thread = threading.Thread(target=_send, daemon=True)

    thread.start()

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



            reg_hits = screen_entity(

                get_db(),

                name=pending["username"],

                id_number=pending["id_number"],

            )

            if is_registration_blocked(reg_hits):

                session.pop("pending_registration", None)

                flash("Registration cannot proceed — sanctions screening match detected. Contact compliance.")

                record_activity("system", "registration_blocked", f"Sanctions hit for {pending['username']}")

                return redirect(url_for("register"))



            user_count = get_db().execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]

            acct = f"ACC{1000 + int(user_count or 0) + 1}"

            pep_flag = 1 if any(h.list_type == "pep" for h in reg_hits) else 0

            kyc_status = "pending_edd" if pep_flag else "pending"

            get_db().execute(

                "INSERT INTO users (username,email,id_number,password_hash,role,account_number,balance,kyc_status,pep_flag,created_at) VALUES (?,?,?,?,?,?,5000,?,?,?)",

                (pending["username"], pending["email"], pending["id_number"],

                 pending["password_hash"], pending["role"], acct, kyc_status, pep_flag,

                 datetime.now(timezone.utc).isoformat()),

            )

            get_db().commit()

            session.pop("pending_registration", None)

            user = get_user_by_username(pending["username"])

            session["user_id"] = user["id"]

            session["role"] = user["role"]

            record_activity(pending["username"], "register", f"New {pending['role']} registered")

            flash("Account created. Welcome to StanPro Bank AML Portal.")

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

            send_otp_email_async(email, otp_code)

        except Exception as e:

            session.pop("pending_registration", None)

            app.logger.error(f"OTP send failed: {str(e)}")

            flash("Could not send verification code. Please check the email address or try again later.")

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



        customer_identifier = email or login_identifier or username

        if not all([customer_identifier, id_number, password]):

            flash("All fields are required.")

            return render_template("login.html")

        if not is_valid_id_number(id_number):

            flash(ID_NUMBER_FORMAT_MESSAGE)

            return render_template("login.html")

        user = get_user_by_email(email) if email else get_user_by_username(customer_identifier)

        if (

            user

            and user["role"] == "customer"

            and user["id_number"] == id_number

            and check_password_hash(user["password_hash"], password)

        ):

            session["user_id"] = user["id"]

            session["role"] = user["role"]

            record_activity(customer_identifier, "login", f"Login from {request.remote_addr}")

            flash("Welcome back.")

            return redirect(url_for("dashboard_redirect"))

        flash("Invalid credentials.")

        record_activity(customer_identifier, "failed_login", f"Failed login attempt from {request.remote_addr}")

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

    page = request_page()

    offset = (page - 1) * PAGE_SIZE

    transactions = get_db().execute(

        "SELECT * FROM transactions WHERE sender_account=? OR receiver_account=? ORDER BY id DESC LIMIT ? OFFSET ?",

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

        dashboard_data={

            "user": serialize_row(user),

            "transactions": serialize_rows(transactions),

            "alerts": serialize_rows(alerts),

            "stats": stats,

            "page": page,

        },

        user=user, transactions=transactions, alerts=alerts, stats=stats, page=page,

    )





@app.route("/customer/transaction", methods=["POST"])

@login_required("customer")

def create_transaction():

    user = get_user_by_id(session["user_id"])

    tx_type = request.form.get("type")

    amount_str = request.form.get("amount", "0")

    recipient_account = normalize_account_number(request.form.get("recipient", ""))



    if tx_type not in VALID_TRANSACTION_TYPES:

        flash("Invalid transaction type.")

        return redirect(url_for("customer_dashboard"))



    try:

        amount = float(amount_str)

    except ValueError:

        flash("Invalid amount.")

        return redirect(url_for("customer_dashboard"))



    if amount <= 0:

        flash("Amount must be greater than zero.")

        return redirect(url_for("customer_dashboard"))



    if tx_type in ("withdraw", "transfer") and user["balance"] < amount:

        flash("Insufficient funds.")

        return redirect(url_for("customer_dashboard"))



    recipient_user = None

    if tx_type == "transfer":

        recipient_user = get_user_by_account_number(recipient_account)

        if not recipient_user or (recipient_user.get("id") is not None and recipient_user.get("id") == user["id"]) or (recipient_user.get("role") is not None and recipient_user.get("role") != "customer"):

            flash("Recipient customer account not found.")

            return redirect(url_for("customer_dashboard"))



    timestamp = datetime.now(timezone.utc).isoformat()

    sender_account = user["account_number"]

    receiver_account = recipient_user.get("account_number") if recipient_user and recipient_user.get("account_number") else user["account_number"]



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

        if recipient_user and recipient_user.get("id") is not None:
            get_db().execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, recipient_user["id"]))



    get_db().commit()

    broadcast_user_balance(get_db(), sender_account)

    if tx_type == "transfer":

        broadcast_user_balance(get_db(), receiver_account)

    broadcast_stats(get_db())

    _train_ai_model_from_db(get_db())

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

    page = request_page()

    offset = (page - 1) * PAGE_SIZE

    # Whitelist of valid filter values to prevent SQL injection
    VALID_FILTERS = {
        "all": "",
        "flagged": "WHERE risk_level!='normal'",
        "suspicious": "WHERE risk_level IN ('suspicious','super_suspicious','high_risk','critical')",
        "ctr": "WHERE ctr_required=1",
        "sar": "WHERE sar_required=1",
    }
    base = VALID_FILTERS.get(filter_value, "")



    transactions = get_db().execute(

        f"SELECT * FROM transactions {base} ORDER BY id DESC LIMIT ? OFFSET ?",

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

        dashboard_data={

            "transactions": serialize_rows(transactions),

            "open_alerts": serialize_rows(open_alerts),

            "filter_value": filter_value,

            "stats": stats,

            "page": page,

            "total_count": total_count,

            "page_size": PAGE_SIZE,

        },

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

            # Update customer risk rating
            if account_user:
                old_risk = account_user.get("risk_rating", "standard")
                new_risk = update_customer_risk_rating(get_db(), alert.get("account_number"), "resolve", old_risk)
                record_activity(officer["username"], "resolve_alert", f"Alert #{alert_id} resolved, risk rating: {old_risk} -> {new_risk}")
                flash(f"Alert #{alert_id} marked as resolved. Customer risk rating updated to {new_risk}.")
            else:
                record_activity(officer["username"], "resolve_alert", f"Alert #{alert_id} resolved (account not found)")
                flash(f"Alert #{alert_id} marked as resolved.")



        elif action == "escalate":

            get_db().execute(

                "UPDATE alerts SET status='escalated', case_notes=?, assigned_to=? WHERE id=?",

                (notes, officer["username"], alert_id),

            )

            # Update customer risk rating
            if account_user:
                old_risk = account_user.get("risk_rating", "standard")
                new_risk = update_customer_risk_rating(get_db(), alert.get("account_number"), "escalate", old_risk)
                record_activity(officer["username"], "escalate_alert", f"Alert #{alert_id} escalated, risk rating: {old_risk} -> {new_risk}")
                flash(f"Alert #{alert_id} escalated. Customer risk rating updated to {new_risk}.")
            else:
                record_activity(officer["username"], "escalate_alert", f"Alert #{alert_id} escalated (account not found)")
                flash(f"Alert #{alert_id} escalated.")



        elif action == "file_sar":

            narrative = request.form.get("sar_narrative", notes)

            ref = _generate_sar_ref()

            get_db().execute(

                "INSERT INTO sar_reports (alert_id, account_number, filed_by, narrative, status, reference_number, created_at) VALUES (?,?,?,?,'draft',?,?)",

                (alert_id, alert.get("account_number"), officer["username"], narrative, ref,

                 datetime.now(timezone.utc).isoformat()),

            )

            get_db().execute(

                "UPDATE alerts SET status='sar_filed', case_notes=? WHERE id=?",

                (f"SAR filed: {ref}. {notes}", alert_id),

            )

            # Update customer risk rating
            if account_user:
                old_risk = account_user.get("risk_rating", "standard")
                new_risk = update_customer_risk_rating(get_db(), alert["account_number"], "file_sar", old_risk)
                record_activity(officer["username"], "file_sar", f"SAR {ref} filed for alert #{alert_id}, risk rating: {old_risk} -> {new_risk}")
                flash(f"SAR filed successfully. Reference: {ref}. Customer risk rating updated to {new_risk}.")
            else:
                record_activity(officer["username"], "file_sar", f"SAR {ref} filed for alert #{alert_id} (account not found)")
                flash(f"SAR filed successfully. Reference: {ref}.")



        get_db().commit()

        broadcast_alert_update(get_db(), alert_id)

        if action == "file_sar":

            sar = get_db().execute(

                "SELECT * FROM sar_reports WHERE alert_id=? ORDER BY id DESC LIMIT 1",

                (alert_id,),

            ).fetchone()

            if sar:

                broadcast_report_event("sar_report", sar)

        broadcast_stats(get_db())

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

    filed_at = datetime.now(timezone.utc).isoformat()

    get_db().execute(

        "UPDATE sar_reports SET status='submitted', filed_at=? WHERE id=?",

        (filed_at, sar_id),

    )

    get_db().commit()

    sar = get_db().execute("SELECT * FROM sar_reports WHERE id=?", (sar_id,)).fetchone()

    if sar:

        broadcast_report_event("sar_report", sar)

    broadcast_stats(get_db())

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

                updated = get_db().execute(

                    "SELECT id, username, account_number, balance, kyc_status FROM users WHERE id=?",

                    (user_id,),

                ).fetchone()

                if updated:

                    broadcast_event("user", _user_balance_payload(updated))

                record_activity(admin_user["username"], "update_user", f"Updated user {user_id}: kyc={kyc or 'unchanged'}")

                flash("User updated.")



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

                watchlist = get_db().execute(

                    "SELECT * FROM watchlist ORDER BY id DESC LIMIT 1"

                ).fetchone()

                if watchlist:

                    broadcast_report_event("watchlist", watchlist)

                record_activity(admin_user["username"], "add_watchlist", f"Added {name} to watchlist")

                flash(f"{name} added to watchlist.")



    page = request_page()

    offset = (page - 1) * PAGE_SIZE

    users = get_db().execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()

    activity = get_db().execute(

        "SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT ? OFFSET ?",

        (PAGE_SIZE, offset),

    ).fetchall()

    transactions = get_db().execute(

        "SELECT * FROM transactions ORDER BY id DESC LIMIT 20"

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

        dashboard_data={

            "users": serialize_rows(users),

            "activity": serialize_rows(activity),

            "transactions": serialize_rows(transactions),

            "watchlist": serialize_rows(watchlist),

            "system_stats": system_stats,

            "page": page,

        },

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

    if count not in (100, 500, 1000, 2000):

        count = 100

    try:

        users = get_db().execute(

            "SELECT id, username, account_number, balance, wealth_segment FROM users WHERE role='customer' ORDER BY id"

        ).fetchall()

        if not users:

            flash("No customer accounts are available for transaction generation.")

            return redirect(url_for("admin_dashboard"))



        generated = {"normal": 0, "flagged": 0, "critical": 0}

        # Batch insert transactions first for performance
        transactions_to_process = []
        for label in _simulation_plan(count):

            (

                sender, recipient, tx_type, amount, timestamp,

                channel, description, _scenario_reason, dest_country,

            ) = _simulation_transaction(label, users)

            sender_account = sender["account_number"]

            receiver_account = recipient["account_number"] if tx_type == "transfer" else sender_account

            get_db().execute(

                """

                INSERT INTO transactions (sender_account, receiver_account, amount, transaction_type,

                    currency, channel, timestamp, status, risk_score, risk_level, description,

                    destination_country)

                VALUES (?,?,?,?,?,?,?,'Completed',0,'normal',?,?)

                """,

                (

                    sender_account, receiver_account, amount, tx_type, "USD", channel, timestamp,

                    description, dest_country,

                ),

            )

            transaction_id = get_last_insert_id(get_db())

            transactions_to_process.append((transaction_id, sender, recipient, tx_type, amount, timestamp, sender_account, receiver_account, dest_country))

            # Update balances immediately
            if tx_type == "deposit":

                get_db().execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, sender["id"]))

            elif tx_type == "withdraw":

                get_db().execute(

                    "UPDATE users SET balance=CASE WHEN balance > ? THEN balance-? ELSE 0 END WHERE id=?",

                    (amount, amount, sender["id"]),

                )

            elif tx_type == "transfer":

                get_db().execute(

                    "UPDATE users SET balance=CASE WHEN balance > ? THEN balance-? ELSE 0 END WHERE id=?",

                    (amount, amount, sender["id"]),

                )

                get_db().execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, recipient["id"]))

        get_db().commit()

        # Process transactions in batch for AML rules and AI
        for transaction_id, sender, recipient, tx_type, amount, timestamp, sender_account, receiver_account, dest_country in transactions_to_process:

            risk_score, risk_level, reason, alert_id = process_transaction_event(

                get_db(), transaction_id, sender_account, receiver_account,

                amount, tx_type, timestamp, account_number=sender_account,

                destination_country=dest_country,

            )



            if risk_level in ("normal", "low"):

                generated["normal"] += 1

            elif risk_level in ("critical", "high_risk"):

                generated["critical"] += 1

            else:

                generated["flagged"] += 1

        get_db().commit()

        for user_row in get_db().execute(

            "SELECT account_number FROM users ORDER BY id"

        ).fetchall():

            broadcast_user_balance(get_db(), user_row["account_number"])

        broadcast_event("transaction_batch", {

            "count": count,

            "normal": generated["normal"],

            "flagged": generated["flagged"],

            "critical": generated["critical"],

            "timestamp": datetime.now(timezone.utc).isoformat(),

        })

        broadcast_stats(get_db())

        model = _train_ai_model_from_db(get_db())

        record_activity(

            admin_user["username"],

            "generate_transactions",

            (

                f"Generated {count} rule-scored transactions: "

                f"{generated['normal']} normal, {generated['flagged']} flagged, "

                f"{generated['critical']} critical/high-risk"

            ),

        )

        flash(f"Generated {count} transactions: {generated['normal']} normal, {generated['flagged']} flagged, {generated['critical']} critical.")

        return redirect(url_for("admin_dashboard"))

    except Exception as e:

        get_db().rollback()

        app.logger.error(f"Transaction generation failed: {e}")

        flash(f"Transaction generation failed: {str(e)}")

        return redirect(url_for("admin_dashboard"))





@app.route("/admin/clear-transactions", methods=["POST"])

@login_required("admin")

def clear_transactions():

    admin_user = get_user_by_id(session["user_id"])

    conn = get_db()

    for table in ("sar_reports", "ctr_reports", "alerts", "transactions", "activity_log"):

        conn.execute(f"DELETE FROM {table}")

    conn.commit()

    delete_ai_model()

    app.config["LAST_MONITORED_TRANSACTION_ID"] = 0

    broadcast_event("reset", {

        "scope": "transactions",

        "timestamp": datetime.now(timezone.utc).isoformat(),

    })

    broadcast_stats(conn)

    record_activity(admin_user["username"], "clear_transactions", "Cleared all transactions, alerts, reports, recent activity, and AI model")

    flash("All transactions, alerts, reports, recent activity, and the trained AI model have been cleared.")

    return redirect(url_for("admin_dashboard"))



@app.route("/admin/clear-watchlist", methods=["POST"])

@login_required("admin")

def clear_watchlist():

    admin_user = get_user_by_id(session["user_id"])

    conn = get_db()

    conn.execute("DELETE FROM watchlist")

    conn.commit()

    record_activity(admin_user["username"], "clear_watchlist", "Cleared all watchlist entries")

    flash("All watchlist entries have been cleared.")

    return redirect(url_for("admin_dashboard"))



@app.route("/admin/migrate-database", methods=["POST"])

@login_required("admin")

def migrate_database():

    admin_user = get_user_by_id(session["user_id"])

    conn = get_db()

    try:
        if not is_postgres_database_url(app.config["DATABASE"]) and not is_mysql_database_url(app.config["DATABASE"]):

            _migrate_sqlite(conn)

        elif is_mysql_database_url(app.config["DATABASE"]):

            _migrate_mysql(conn)

        conn.commit()

        record_activity(admin_user["username"], "migrate_database", "Ran database migration")

        flash("Database migration completed successfully.")

    except Exception as e:

        conn.rollback()

        app.logger.error(f"Database migration failed: {e}")

        flash(f"Database migration failed: {str(e)}")

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

        SELECT SUBSTRING(timestamp,1,7) as month, COUNT(*) as count, SUM(amount) as volume

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



@app.route("/api/v1/ai-model")

@login_required("compliance", "admin")

def api_ai_model():

    return jsonify(get_model_metadata())





@app.route("/api/v1/stats")

@login_required("compliance", "admin")

def api_stats():

    return jsonify(_stats_payload(get_db()))





@app.route("/api/v1/transactions")

@login_required("compliance", "admin")

def api_transactions():

    page = request_page()

    offset = (page - 1) * PAGE_SIZE

    rows = get_db().execute(

        "SELECT * FROM transactions ORDER BY id DESC LIMIT ? OFFSET ?",

        (PAGE_SIZE, offset),

    ).fetchall()

    return jsonify(serialize_rows(rows))





@app.route("/stream")

@login_required("customer", "compliance", "admin")

def stream():

    # Rate limiting: check if user has too many active streams

    user_streams_key = f"stream_user_{session.get('user_id')}"

    active_streams = app.config.get("ACTIVE_STREAMS", {})

    

    if user_streams_key in active_streams:

        active_streams[user_streams_key] += 1

        if active_streams[user_streams_key] > 3:  # Max 3 concurrent streams per user

            app.logger.warning(f"User {session.get('user_id')} exceeded stream limit")

            return Response("Too many active connections", status=429)

    else:

        active_streams[user_streams_key] = 1

    

    response = app.extensions["realtime_broker"].stream_response()

    

    # Cleanup on response close

    @response.call_on_close

    def cleanup():

        if user_streams_key in active_streams:

            active_streams[user_streams_key] -= 1

            if active_streams[user_streams_key] <= 0:

                del active_streams[user_streams_key]

    

    return response





# ── Error handlers ──



@app.errorhandler(404)

def page_not_found(_):

    return render_template("error.html", message="Page not found."), 404





@app.errorhandler(500)

def server_error(_):

    app.logger.exception("Unhandled server error")

    return render_template("error.html", message="A server error occurred. Our team has been notified."), 500





def ensure_ai_model_ready():

    """Bootstrap AI model on cold start using synthetic typology data."""

    if app.config.get("TESTING"):

        return

    if os.path.exists(MODEL_PATH):

        return

    with app.app_context():

        conn = connect_db()

        try:

            train_ai_model([])

        finally:

            conn.close()





# Initialize database on startup (for gunicorn deployment)
try:
    init_db()
    seed_demo_data()
    ensure_ai_model_ready()
    ensure_background_monitor()
except Exception as e:
    logging.error(f"Error during startup initialization: {e}")


if __name__ == "__main__":

    init_db()

    seed_demo_data()

    ensure_ai_model_ready()

    ensure_background_monitor()

    socketio.run(

        app,

        debug=app.config.get("DEBUG", False),

        host="0.0.0.0",

        port=5000,

        allow_unsafe_werkzeug=True,

        use_reloader=False,

    )

