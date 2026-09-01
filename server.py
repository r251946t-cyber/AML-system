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

  • Security features: rate limiting, account lockout, secure headers

"""

import json

import logging

import os

import random

import re

import smtplib

import socket

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

from collections import defaultdict


from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Flag to prevent concurrent AI training
_ai_training_in_progress = False
_ai_training_lock = threading.Lock()

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
from aml_rules import CTR_THRESHOLD, assess_rules
from transaction_simulation import (
    _random_transaction_amount,
    _simulation_plan,
    _simulation_timestamp,
    _scenario_amount,
    _simulation_segment_multiplier,
    _simulation_transaction,
    _simulation_reason,
    _history_profile,
    _ai_profile_for_transaction,
    _parse_timestamp,
    NORMAL_TRANSACTION_SCENARIOS,
    SUSPICIOUS_TRANSACTION_SCENARIOS,
    SUPER_SUSPICIOUS_TRANSACTION_SCENARIOS,
    PROFILE_FEATURE_DEFAULTS,
)

# Import from modularized components
from database import (
    DatabaseAdapter,
    is_postgres_database_url,
    is_mysql_database_url,
    connect_db,
    get_schema_sql,
)
from security import (
    check_login_attempts,
    record_login_attempt,
    add_security_headers,
)
from behavioral_profiling import (
    get_customer_behavioral_profile,
    save_customer_behavioral_profile,
    build_or_update_customer_profile,
    assess_transaction_behavioral_risk,
)
from alerts import (
    create_alert_if_needed,
    update_customer_risk_rating,
    _generate_sar_ref,
    _generate_ctr_ref,
    get_alert_statistics,
)
from realtime import RealtimeBroker
from utils import (
    serialize_value,
    serialize_row,
    serialize_rows,
    request_page,
    _user_balance_payload,
    _transaction_payload,
    _stats_payload,
    send_email,
)
from users import (
    validate_id_number,
    is_username_reserved,
    get_staff_accounts,
    create_user,
    get_user_by_account_number,
    get_user_by_username,
    get_user_by_id,
    update_user_balance,
    update_user_kyc_status,
    update_user_risk_rating,
    get_all_users,
    get_users_by_role,
    update_user_last_login,
    verify_password,
    ID_NUMBER_PATTERN,
    ID_NUMBER_FORMAT_MESSAGE,
    STAFF_ACCOUNTS,
    RESERVED_STAFF_USERNAMES,
)
from transactions import (
    set_rule_engine_enabled,
    is_rule_engine_enabled,
    _risk_level_from_score,
    _calibrate_generated_transaction_risk,
    _combine_rule_ai_risk,
    get_transaction_by_id,
    get_transactions_by_account,
    get_all_transactions,
    get_transactions_by_risk_level,
    get_transaction_statistics,
    RISK_RANK,
    AI_RISK_SCORES,
)
from reports import (
    create_sar_report,
    create_ctr_report,
    get_sar_reports,
    get_sar_reports_by_account,
    get_sar_by_id,
    get_ctr_reports,
    get_ctr_reports_by_account,
    get_ctr_by_id,
    update_sar_status,
    update_ctr_status,
    get_report_statistics,
    log_system_activity,
    get_activity_log,
)
from messaging import (
    create_messaging_tables_sql,
    get_or_create_conversation,
    send_message,
    get_conversation_messages,
    get_user_conversations,
    get_unread_count,
    mark_conversation_as_read,
    add_unread_message,
    set_user_online,
    get_user_online_status,
    set_typing_indicator,
    can_user_message,
    mark_message_as_delivered,
    mark_message_as_read,
)


load_dotenv()



app = Flask(__name__)

app.config.from_object(

    DevelopmentConfig if os.environ.get("FLASK_ENV") == "development" else ProductionConfig

)

# Security: Add secure headers
@app.after_request
def add_security_headers_wrapper(response):
    return add_security_headers(response)


# ============================================================================
# Database Connection
# ============================================================================

def get_db():
    if "db" not in g:
        g.db = connect_db(app.config["DATABASE"])
    return g.db


def login_required(view_func=None, *roles):
    """Require a logged-in user, optionally limited to one or more roles."""
    def decorator(func):
        @wraps(func)
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

            return func(*args, **kwargs)

        return wrapped

    if callable(view_func):
        return decorator(view_func)

    if view_func is not None:
        roles = (view_func, *roles)

    return decorator


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ============================================================================
# Schema Initialization
# ============================================================================

def init_db():
    conn = connect_db(app.config["DATABASE"])
    conn.executescript(get_schema_sql(app.config["DATABASE"]))
    
    # Add messaging tables
    messaging_sql = create_messaging_tables_sql(app.config["DATABASE"])
    conn.executescript(messaging_sql)
    
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
                         "screening_hits TEXT", "reviewed_by TEXT", "reviewed_at TEXT",
                         "generated_label TEXT", "status TEXT DEFAULT 'Completed'"],
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
    
    # Create messaging tables if they don't exist
    messaging_sql = create_messaging_tables_sql(app.config["DATABASE"])
    for statement in messaging_sql.split(";"):
        statement = statement.strip()
        if statement:
            conn.execute(statement)


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
            ("generated_label", "VARCHAR(50)"),
            ("status", "VARCHAR(50) DEFAULT 'Completed'"),
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
    
    # Create messaging tables if they don't exist
    messaging_sql = create_messaging_tables_sql(app.config["DATABASE"])
    for statement in messaging_sql.split(";"):
        statement = statement.strip()
        if statement:
            try:
                conn.execute(statement)
            except Exception as e:
                logging.error(f"Error creating messaging table: {e}")


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
            ("generated_label", "VARCHAR(50)"),
            ("status", "VARCHAR(50) DEFAULT 'Completed'"),
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
            existing = {
                row["column_name"]
                for row in conn.execute(f"SELECT column_name FROM information_schema.columns WHERE table_name='{table}'").fetchall()
            }
            for column_name, column_def in columns:
                if column_name not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_name} {column_def}")
        except Exception as e:
            logging.error(f"Error adding columns to {table}: {e}")
    
    # Create messaging tables if they don't exist
    messaging_sql = create_messaging_tables_sql(app.config["DATABASE"])
    for statement in messaging_sql.split(";"):
        statement = statement.strip()
        if statement:
            try:
                conn.execute(statement)
            except Exception as e:
                logging.error(f"Error creating messaging table: {e}")


# ============================================================================
# Constants
# ============================================================================

PAGE_SIZE = 25  # rows per paginated list
VALID_TRANSACTION_TYPES = {"deposit", "withdraw", "transfer"}

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



# Configure SocketIO for cross-device broadcasting
# Note: We use RealtimeBroker with Redis for cross-instance messaging, not SocketIO's message queue
socketio_kwargs = {
    "cors_allowed_origins": "*",
    "manage_session": False,
    # The deployment uses Gunicorn's threaded worker (see Procfile/Dockerfile),
    # which is the matching and portable Socket.IO runtime for this application.
    "async_mode": "threading",
    "logger": False,
    "engineio_logger": False,
    "ping_timeout": 30,
    "ping_interval": 5,
}

app.logger.info("SocketIO configured with threading (RealtimeBroker handles cross-instance messaging)")

socketio = SocketIO(app, **socketio_kwargs)
app.logger.info(f"SocketIO initialized with async_mode: {socketio.async_mode}")

app.extensions["realtime_broker"] = RealtimeBroker(app=app, socketio=socketio)



# SocketIO authentication middleware with presence tracking

@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session:
        app.logger.warning("SocketIO connection rejected: no user_id in session")
        return False
    
    user_id = session.get('user_id')
    role = session.get('role', 'unknown')
    sid = request.sid
    
    # Rate limit connection logging to prevent log spam
    broker = app.extensions.get('realtime_broker')
    if broker and broker._redis_client:
        try:
            presence_key = f"presence:user:{user_id}"
            existing = broker._redis_client.hget(presence_key, 'sid')
            if existing and existing.decode('utf-8') == sid:
                # Same socket reconnecting, don't log
                pass
            else:
                app.logger.info(f"User {user_id} (role: {role}) connected via SocketIO, presence stored in Redis")
        except:
            app.logger.info(f"User {user_id} (role: {role}) connected via SocketIO, presence stored in Redis")
    
    # Store presence in Redis for cross-server routing
    if broker and broker._redis_client:
        try:
            presence_key = f"presence:user:{user_id}"
            broker._redis_client.hset(presence_key, mapping={
                'sid': sid,
                'server_id': broker._instance_id,
                'role': role,
                'connected_at': int(time.time())
            })
            broker._redis_client.expire(presence_key, 300)  # 5 minute TTL
            
            # Deliver queued offline messages
            offline_messages = broker.get_offline_queue(user_id)
            if offline_messages:
                app.logger.info(f"Delivering {len(offline_messages)} queued messages to user {user_id}")
                for msg in reversed(offline_messages):  # Deliver in chronological order
                    socketio.emit(msg['event'], msg['data'], to=sid)
        except Exception as e:
            app.logger.error(f"Failed to store presence in Redis: {e}")
    else:
        app.logger.warning(f"User {user_id} (role: {role}) connected via SocketIO (no Redis presence tracking)")
    
    # Send initial connection confirmation
    socketio.emit('connection_confirmed', {'status': 'connected', 'user_id': user_id}, to=sid)
    
    return True


@socketio.on('heartbeat')
def handle_heartbeat():
    """Client heartbeat to maintain connection and refresh presence TTL"""
    if 'user_id' in session:
        user_id = session.get('user_id')
        broker = app.extensions.get('realtime_broker')
        if broker and broker._redis_client:
            try:
                presence_key = f"presence:user:{user_id}"
                broker._redis_client.expire(presence_key, 300)  # Refresh TTL
                app.logger.debug(f"Heartbeat received from user {user_id}")
            except Exception as e:
                app.logger.error(f"Failed to refresh presence TTL: {e}")
    # Separate from Socket.IO transport ping/pong; confirms that the application
    # and server-side presence tracking are both still alive.
    socketio.emit("heartbeat_ack", {"timestamp": time.time()}, to=request.sid)


@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        user_id = session.get('user_id')
        role = session.get('role', 'unknown')
        
        # Remove presence from Redis
        broker = app.extensions.get('realtime_broker')
        if broker and broker._redis_client:
            try:
                presence_key = f"presence:user:{user_id}"
                broker._redis_client.delete(presence_key)
                app.logger.info(f"User {user_id} (role: {role}) disconnected, presence removed from Redis")
            except Exception as e:
                app.logger.error(f"Failed to remove presence from Redis: {e}")
        else:
            app.logger.info(f"User {user_id} (role: {role}) disconnected from SocketIO")
    
    # Mark user as offline
    try:
        conn = connect_db()
        if 'username' in session:
            set_user_online(conn, session['username'], False)
        conn.close()
    except:
        pass


# ============================================================================
# Messaging WebSocket Handlers
# ============================================================================

@socketio.on('send_message')
def handle_send_message(data):
    """Handle incoming message."""
    if 'username' not in session:
        socketio.emit('error', {'message': 'Not authenticated'})
        return
    
    sender = session['username']
    receiver = data.get('receiver')
    content = data.get('content')
    
    if not receiver or not content:
        socketio.emit('error', {'message': 'Missing receiver or content'})
        return
    
    try:
        conn = connect_db()
        
        # Check permissions
        sender_user = get_user_by_username(conn, sender)
        receiver_user = get_user_by_username(conn, receiver)
        
        if not sender_user or not receiver_user:
            socketio.emit('error', {'message': 'User not found'})
            return
        
        can_message, reason = can_user_message(sender_user['role'], receiver_user['role'])
        if not can_message:
            socketio.emit('error', {'message': reason})
            return
        
        # Get or create conversation
        conv = get_or_create_conversation(conn, sender, receiver)
        
        # Send message
        msg = send_message(conn, conv['id'], sender, receiver, content, sender_user['role'])
        
        # Mark as unread for receiver
        add_unread_message(conn, conv['id'], receiver)
        
        # Emit to both users
        message_data = {
            'id': msg['id'],
            'sender': sender,
            'receiver': receiver,
            'content': msg['content'],
            'status': 'sent',
            'timestamp': msg['created_at'],
            'conversation_id': conv['id']
        }
        
        # Broadcast to both participants
        socketio.emit('new_message', message_data, broadcast=True)
        
        # Broadcast unread badge update
        unread = get_unread_count(conn, receiver)
        socketio.emit('unread_update', unread, to=receiver)
        
        conn.close()
    except Exception as e:
        app.logger.error(f"Error sending message: {e}")
        socketio.emit('error', {'message': f'Failed to send message: {e}'})


@socketio.on('typing')
def handle_typing(data):
    """Handle typing indicator."""
    if 'username' not in session:
        return
    
    username = session['username']
    conversation_id = data.get('conversation_id')
    
    try:
        conn = connect_db()
        set_typing_indicator(conn, username, conversation_id)
        conn.close()
        
        # Broadcast typing status
        socketio.emit('user_typing', {
            'user': username,
            'conversation_id': conversation_id
        }, broadcast=True)
    except Exception as e:
        app.logger.error(f"Error handling typing: {e}")


@socketio.on('stop_typing')
def handle_stop_typing(data):
    """Handle stop typing indicator."""
    if 'username' not in session:
        return
    
    username = session['username']
    conversation_id = data.get('conversation_id')
    
    try:
        conn = connect_db()
        set_typing_indicator(conn, username, None)
        conn.close()
        
        socketio.emit('user_stop_typing', {
            'user': username,
            'conversation_id': conversation_id
        }, broadcast=True)
    except Exception as e:
        app.logger.error(f"Error handling stop typing: {e}")


@socketio.on('mark_read')
def handle_mark_read(data):
    """Mark messages as read."""
    if 'username' not in session:
        return
    
    username = session['username']
    conversation_id = data.get('conversation_id')
    
    try:
        conn = connect_db()
        mark_conversation_as_read(conn, conversation_id, username)
        conn.close()
        
        # Update unread badge
        unread = get_unread_count(conn, username)
        socketio.emit('unread_update', unread, to=username)
    except Exception as e:
        app.logger.error(f"Error marking messages as read: {e}")


# ============================================================================
# Messaging API Routes
# ============================================================================

@app.route('/api/conversations', methods=['GET'])
@login_required
def api_get_conversations():
    """Get all conversations for current user."""
    try:
        conn = connect_db()
        conversations = get_user_conversations(conn, session['username'])
        conn.close()
        
        return jsonify({
            'status': 'success',
            'conversations': conversations
        })
    except Exception as e:
        app.logger.error(f"Error fetching conversations: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/conversations/<int:conversation_id>/messages', methods=['GET'])
@login_required
def api_get_messages(conversation_id):
    """Get messages for a conversation."""
    try:
        conn = connect_db()
        messages = get_conversation_messages(conn, conversation_id, limit=50)
        conn.close()
        
        return jsonify({
            'status': 'success',
            'messages': messages
        })
    except Exception as e:
        app.logger.error(f"Error fetching messages: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/users/<username>/can-message', methods=['GET'])
@login_required
def api_can_message(username):
    """Check if current user can message target user."""
    try:
        conn = connect_db()
        
        sender_user = get_user_by_username(conn, session['username'])
        receiver_user = get_user_by_username(conn, username)
        
        if not sender_user or not receiver_user:
            return jsonify({'status': 'error', 'can_message': False, 'message': 'User not found'}), 404
        
        can_message, reason = can_user_message(sender_user['role'], receiver_user['role'])
        conn.close()
        
        return jsonify({
            'status': 'success',
            'can_message': can_message,
            'reason': reason,
            'target_user': {
                'username': username,
                'role': receiver_user['role']
            }
        })
    except Exception as e:
        app.logger.error(f"Error checking message permissions: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/unread-count', methods=['GET'])
@login_required
def api_get_unread_count():
    """Get unread message counts."""
    try:
        conn = connect_db()
        unread = get_unread_count(conn, session['username'])
        conn.close()
        
        return jsonify({
            'status': 'success',
            'unread': unread
        })
    except Exception as e:
        app.logger.error(f"Error fetching unread count: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/user-status/<username>', methods=['GET'])
@login_required
def api_get_user_status(username):
    """Get user's online status."""
    try:
        conn = connect_db()
        status = get_user_online_status(conn, username)
        conn.close()
        
        return jsonify({
            'status': 'success',
            'user_status': status
        })
    except Exception as e:
        app.logger.error(f"Error fetching user status: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/messageable-users', methods=['GET'])
@login_required
def api_get_messageable_users():
    """Get list of users current user can message."""
    try:
        conn = connect_db()
        current_user = get_user_by_username(conn, session['username'])
        
        if not current_user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Get all users and filter by messaging permissions
        all_users = get_all_users(conn)
        messageable_users = []
        
        for user in all_users:
            if user['username'] == session['username']:
                continue
            
            can_message, _ = can_user_message(current_user['role'], user['role'])
            if can_message:
                status = get_user_online_status(conn, user['username'])
                messageable_users.append({
                    'username': user['username'],
                    'role': user['role'],
                    'is_online': status['is_online'],
                    'last_seen': status['last_seen']
                })
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'users': messageable_users
        })
    except Exception as e:
        app.logger.error(f"Error fetching messageable users: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============================================================================
# Event Broadcasting Helper
# ============================================================================

def broadcast_event(event_name, payload):
    """Broadcast event using RealtimeBroker."""
    broker = app.extensions.get("realtime_broker")
    if broker:
        broker.publish(event_name, payload)


# ============================================================================
# AI Training Functions
# ============================================================================

def _ai_training_rows(rows):
    histories = {}
    enriched = []
    for row in rows:
        sender = row["sender_account"]
        history = histories.setdefault(sender, {"amounts": [], "recipients": set(), "events": [], "transactions": []})
        profile = _history_profile(row["amount"], row["receiver_account"], row["timestamp"], history)
        item = dict(row)
        item.update(profile)
        enriched.append(item)
        history["amounts"].append(float(row["amount"]))
        history["recipients"].add(row["receiver_account"])
        history["events"].append((_parse_timestamp(row["timestamp"]), float(row["amount"])))
        history["transactions"].append(dict(row))
    return enriched


def _train_ai_model_from_db(conn, emit_events=True):
    # Prevent concurrent AI training
    global _ai_training_in_progress, _ai_training_lock
    with _ai_training_lock:
        if _ai_training_in_progress:
            if app:
                app.logger.info("AI training already in progress, skipping")
            return None
        _ai_training_in_progress = True
    
    try:
        rows = conn.execute(
            """
            SELECT t.id, t.sender_account, t.receiver_account, t.amount, t.transaction_type,
                   t.timestamp, COALESCE(t.generated_label, t.risk_level) as risk_level, t.risk_score, t.channel,
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
    finally:
        with _ai_training_lock:
            _ai_training_in_progress = False


# ============================================================================
# Flask Routes
# ============================================================================


def seed_demo_data():
    conn = connect_db(app.config["DATABASE"])
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

                "INSERT INTO users (username, email, id_number, password_hash, role, account_number, balance, kyc_status, wealth_segment, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",

                (username, email, id_number, pwd_hash, role, acct, 5000, 'verified', 'average', now),

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

                VALUES (?,?,?,?,?,?,?)

                """,

                (name, id_num, acct, list_type, reason, 'system', now),

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
    if app:
        app.logger.info(f"broadcast_event called: {event_name}")
    app.extensions["realtime_broker"].publish(event_name, payload)





def _stats_payload(conn):

    today_start = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00")

    # Use a single query with subqueries for better performance
    stats_query = """
        SELECT 
            (SELECT COUNT(*) FROM transactions) as total_transactions,
            (SELECT COUNT(*) FROM transactions WHERE risk_level!='normal') as suspicious_transactions,
            (SELECT COUNT(*) FROM alerts WHERE status='open') as open_alerts,
            (SELECT COUNT(*) FROM transactions WHERE risk_level IN ('super_suspicious','high_risk','critical') AND timestamp>=?) as high_risk_today,
            (SELECT COUNT(*) FROM sar_reports WHERE status='draft') as pending_sars,
            (SELECT COUNT(*) FROM ctr_reports WHERE status='pending') as pending_ctrs
    """
    row = conn.execute(stats_query, (today_start,)).fetchone()

    return {

        "total_transactions": row["total_transactions"],

        "suspicious_transactions": row["suspicious_transactions"],

        "open_alerts": row["open_alerts"],

        "high_risk_today": row["high_risk_today"],

        "pending_sars": row["pending_sars"],

        "pending_ctrs": row["pending_ctrs"],

        "timestamp": datetime.now(timezone.utc).isoformat(),

    }





def broadcast_stats(conn=None):

    conn = conn or get_db()

    broadcast_event("stats", _stats_payload(conn))


def send_otp_email_async(email, otp_code):
    """Send OTP email using SMTP."""
    subject = "StanPro Bank - Verification Code"
    body = f"""
Your verification code is: {otp_code}

This code will expire in 10 minutes.

If you did not request this code, please ignore this email.

StanPro Bank AML Intelligence Platform
"""
    html_body = f"""
<html>
<body>
    <h2>StanPro Bank - Verification Code</h2>
    <p>Your verification code is: <strong>{otp_code}</strong></p>
    <p>This code will expire in 10 minutes.</p>
    <p>If you did not request this code, please ignore this email.</p>
    <p><em>StanPro Bank AML Intelligence Platform</em></p>
</body>
</html>
"""
    result = send_email(email, subject, body, html_body)
    
    # Always log OTP to console for debugging (fallback)
    if result:
        app.logger.info(f"OTP sent via email to {email}")
    else:
        app.logger.warning(f"OTP email failed to send to {email}. OTP for testing: {otp_code}")
    
    return result





def request_page(parameter="page", default=1):

    try:

        page = int(request.args.get(parameter, default))

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


def update_customer_risk_rating(db, account_number, action, current_risk):
    """Update customer risk rating based on alert action."""
    risk_levels = ["standard", "medium", "high", "critical"]
    
    try:
        current_idx = risk_levels.index(current_risk.lower()) if current_risk.lower() in risk_levels else 0
    except:
        current_idx = 0
    
    if action == "resolve":
        # Reduce risk level on resolve
        new_idx = max(0, current_idx - 1)
    elif action == "escalate":
        # Increase risk level on escalate
        new_idx = min(len(risk_levels) - 1, current_idx + 1)
    elif action == "file_sar":
        # Set to high or critical on SAR
        new_idx = min(len(risk_levels) - 1, current_idx + 2)
    else:
        return current_risk
    
    new_risk = risk_levels[new_idx]
    
    # Update database (caller will commit)
    db.execute("UPDATE users SET risk_rating=? WHERE account_number=?", (new_risk, account_number))
    
    return new_risk


def _generate_ctr_ref():
    ts = datetime.now(timezone.utc)
    return f"CTR-{ts.year}-{ts.strftime('%m%d')}-{random.randint(1000,9999)}"


def _ai_training_rows(rows):

    histories = {}

    enriched = []

    for row in rows:

        sender = row["sender_account"]

        history = histories.setdefault(sender, {"amounts": [], "recipients": set(), "events": [], "transactions": []})

        profile = _history_profile(row["amount"], row["receiver_account"], row["timestamp"], history)

        item = dict(row)

        item.update(profile)

        enriched.append(item)

        history["amounts"].append(float(row["amount"]))
        history["recipients"].add(row["receiver_account"])
        history["events"].append((_parse_timestamp(row["timestamp"]), float(row["amount"])))
        history["transactions"].append(dict(row))

    return enriched





def _train_ai_model_from_db(conn, emit_events=True):
    # Prevent concurrent AI training
    global _ai_training_in_progress, _ai_training_lock
    with _ai_training_lock:
        if _ai_training_in_progress:
            if app:
                app.logger.info("AI training already in progress, skipping")
            return None
        _ai_training_in_progress = True
    
    try:
        rows = conn.execute(

            """

            SELECT t.id, t.sender_account, t.receiver_account, t.amount, t.transaction_type,

                   t.timestamp, COALESCE(t.generated_label, t.risk_level) as risk_level, t.risk_score, t.channel,

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
    finally:
        with _ai_training_lock:
            _ai_training_in_progress = False





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



def _calibrate_generated_transaction_risk(label, risk_score, risk_level, reason, mandatory=False):
    """Keep synthetic generation labels aligned with the intended AML split."""
    label = (label or "normal").lower()

    if label == "normal":
        if mandatory:
            calibrated_score = max(risk_score, 35)
            calibrated_level = "high_risk" if calibrated_score >= 60 else "suspicious"
            return calibrated_score, calibrated_level, reason
        return 20, "normal", "Synthetic normal transaction preserved as normal."

    if label == "suspicious":
        calibrated_score = max(risk_score, 45)
        calibrated_level = "high_risk" if calibrated_score >= 60 else "suspicious"
        return calibrated_score, calibrated_level, reason

    calibrated_score = max(risk_score, 70)
    calibrated_level = "critical" if calibrated_score >= 80 else "high_risk"
    return calibrated_score, calibrated_level, reason



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





# Flag to disable rule-based engine for AI-only testing
_RULE_ENGINE_ENABLED = False

def set_rule_engine_enabled(enabled: bool):
    """Enable or disable the rule-based engine for AI-only testing."""
    global _RULE_ENGINE_ENABLED
    _RULE_ENGINE_ENABLED = enabled

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

    generated_label=None,

    scenario_reason=None,

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

    # Rules are evaluated before behavioural/ML blending.  They provide the
    # auditable typology evidence that a statistical model alone cannot infer.
    if _RULE_ENGINE_ENABLED:
        triggered = [rule.payload() for rule in assess_rules(
            conn, amount=amount, tx_type=transaction_type, sender=sender_account,
            receiver=receiver_account, timestamp=timestamp,
            destination_country=destination_country, exclude_transaction_id=transaction_id,
        )]
        if screen_delta:
            triggered.append({
                "rule_id": "SCREENING",
                "triggered": True,
                "score_delta": screen_delta,
                "reason": screen_reason,
                "severity": "critical" if any(h.list_type == "sanctions" for h in screening_hits) else "warning",
                "typology": "Watchlist / PEP Screening",
            })
        rule_score = min(100, sum(int(rule["score_delta"]) for rule in triggered))
        rule_level = _risk_level_from_score(rule_score)
        rule_reason = "; ".join(rule["reason"] for rule in triggered) or "No rule indicators"
        rules_json = json.dumps(triggered + screen_json)
    else:
        # Rule engine disabled - use AI-only approach
        triggered = []
        rule_score = 0
        rule_level = "normal"
        rule_reason = "Rule engine disabled - AI-only mode"
        rules_json = json.dumps([])



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
    
    # Behavioural evidence is customer-specific and is never the sole reason
    # to suppress a confirmed compliance typology.
    behavioral_score, behavioral_level, behavioral_reason, anomaly_reasons = assess_transaction_behavioral_risk(
        conn, transaction_dict, sender_account
    )
    ml_features = dict(transaction_dict)
    ml_features.update(_ai_profile_for_transaction(
        conn, transaction_id, sender_account, receiver_account, amount, timestamp
    ))
    ml_level, ml_confidence, _ = predict_risk_level(ml_features)
    
    # Adaptive confidence threshold: higher-risk levels tolerate lower confidence
    # super_suspicious: 0.55 threshold (catch risky transactions even with modest confidence)
    # suspicious: 0.65 threshold (standard AML risk threshold)
    # normal: 0.75 threshold (require high confidence to avoid false positives)
    confidence_threshold = 0.65  # default
    if ml_level == "super_suspicious":
        confidence_threshold = 0.55
    elif ml_level == "suspicious":
        confidence_threshold = 0.65
    else:
        confidence_threshold = 0.75
    
    ml_score = AI_RISK_SCORES.get(ml_level, 0) if ml_confidence >= confidence_threshold else 0

    # AI only contributes when confident.  Rules marked critical (and
    # sanctions) are non-downgradable; all other signals must independently
    # reach a material threshold before an alert is opened.
    behavioral_confidence = min(0.90, behavioral_score / 100) if behavioral_score else 0
    ai_score = round((ml_score * ml_confidence * 0.65) + (behavioral_score * behavioral_confidence * 0.35))
    mandatory = any(h.list_type == "sanctions" for h in screening_hits) or any(
        rule["severity"] == "critical" for rule in triggered
    )
    risk_score = max(rule_score, ai_score)
    if mandatory:
        risk_score = max(risk_score, rule_score)
    risk_level = _risk_level_from_score(risk_score)
    reasons = []
    if triggered:
        reasons.append(rule_reason)
    if ml_score:
        reasons.append(f"ML model: {ml_level.replace('_', ' ')} ({ml_confidence:.0%} confidence)")
    if behavioral_score >= 40:
        reasons.append(behavioral_reason)
    if scenario_reason:
        reasons.append(f"Reason: {scenario_reason}")
    reason = "; ".join(reasons) or "Routine transaction — no material AML indicators"

    if generated_label is not None:
        risk_score, risk_level, reason = _calibrate_generated_transaction_risk(
            generated_label,
            risk_score,
            risk_level,
            reason,
            mandatory=mandatory,
        )

    ai_level = ml_level or behavioral_level
    ai_confidence = max(ml_confidence or 0, behavioral_confidence)
    ai_reason = f"{behavioral_reason} ML: {ml_level or 'unavailable'} ({ml_confidence or 0:.0%})."



    ctr_required = 1 if transaction_type in ("deposit", "withdraw") and float(amount) >= CTR_THRESHOLD else 0

    sar_required = 1 if any(rule["rule_id"] == "R07" for rule in triggered) else 0

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

                VALUES (?,?,?,?,?,?)

                """,

                (transaction_id, account_number or sender_account, amount,

                 'system', 'pending', datetime.now(timezone.utc).isoformat()),

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

                    # Train AI model in background thread to avoid blocking monitor
                    def train_in_background():
                        training_conn = None
                        try:
                            # The monitor closes its connection below. Training
                            # owns an independent connection so it cannot race
                            # with that cleanup.
                            training_conn = connect_db()
                            _train_ai_model_from_db(training_conn)
                        except Exception as e:
                            if app:
                                app.logger.error(f"Background AI training in monitor failed: {e}")
                        finally:
                            if training_conn is not None:
                                training_conn.close()
                    threading.Thread(target=train_in_background, daemon=True).start()

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


@app.route("/messages")
@login_required
def messages():
    """Real-time messaging page."""
    user = get_user_by_id(session["user_id"])
    
    if not user:
        flash("User not found.")
        return redirect(url_for("login"))
    
    # Check if user can message
    if user["role"] not in ["admin", "compliance", "customer"]:
        flash("You don't have permission to access messaging.")
        return redirect(url_for("dashboard_redirect"))
    
    return render_template("messages.html", user=user)


# ── Auth ──



def send_otp_email(recipient_email, otp):

    if app.config.get("TESTING"):
        print(f"[TESTING MODE] Would send OTP to {recipient_email}: {otp}")
        return True

    sender_email = os.environ.get("SMTP_EMAIL")

    sender_password = os.environ.get("SMTP_PASSWORD")

    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")

    smtp_port = int(os.environ.get("SMTP_PORT", "587"))

    if not sender_email or not sender_password:
        print(f"ERROR: SMTP credentials not configured")
        raise ValueError("SMTP credentials not configured")

    print(f"[EMAIL] Preparing to send OTP to {recipient_email}")
    print(f"[EMAIL] From: {sender_email}, Server: {smtp_server}:{smtp_port}")

    msg = EmailMessage()

    msg["Subject"] = "StanPro Bank — Your verification code"

    msg["From"] = sender_email

    msg["To"] = recipient_email

    msg.set_content(f"Your StanPro Bank verification code is: {otp}\n\nThis code expires in 10 minutes.")

    try:
        print(f"[EMAIL] Connecting to SMTP server...")
        with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as server:
            print(f"[EMAIL] Connected, starting TLS...")
            server.starttls()
            print(f"[EMAIL] TLS started, logging in...")
            server.login(sender_email, sender_password)
            print(f"[EMAIL] Login successful, sending message...")
            server.send_message(msg)
            print(f"[EMAIL] ✓ Message sent successfully")

    except Exception as e:
        print(f"[EMAIL] ✗ Error during send: {type(e).__name__}: {e}")
        import traceback
        print(f"[EMAIL] Traceback: {traceback.format_exc()}")
        raise

    return True


def send_otp_email_async(recipient_email, otp):

    def _send():
        with app.app_context():
            try:
                print(f"[ASYNC EMAIL] Starting to send OTP to {recipient_email}...")
                send_otp_email(recipient_email, otp)
                print(f"[ASYNC EMAIL] ✓ OTP email sent successfully to {recipient_email}")

            except Exception as e:
                import traceback
                error_msg = f"Failed to send OTP email to {recipient_email}: {str(e)}"
                print(f"[ASYNC EMAIL] ✗ {error_msg}")
                print(f"[ASYNC EMAIL] Traceback: {traceback.format_exc()}")
                app.logger.error(f"{error_msg}\n{traceback.format_exc()}")

    thread = threading.Thread(target=_send, daemon=False)  # Changed to daemon=False for better visibility

    thread.start()
    # Give thread a small window to start execution
    time.sleep(0.1)

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

                "INSERT INTO users (username,email,id_number,password_hash,role,account_number,balance,kyc_status,pep_flag,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",

                (pending["username"], pending["email"], pending["id_number"],

                 pending["password_hash"], pending["role"], acct, 5000, kyc_status, pep_flag,

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



        # Generate server-side OTP
        otp_code = f"{random.randint(100000, 999999)}"
        
        # Print OTP to console for debugging
        print(f"\n{'='*60}")
        print(f"OTP GENERATED FOR {email}: {otp_code}")
        print(f"{'='*60}\n")

        session["pending_registration"] = {

            "username": username, "email": email, "id_number": id_number,

            "password_hash": generate_password_hash(password), "role": role,

            "otp": otp_code, "expires_at": time.time() + 600,

        }

        # Send OTP via SMTP
        print(f"Attempting to send OTP email to {email}...")
        try:

            result = send_otp_email_async(email, otp_code)
            print(f"Email send result: {result}")

        except Exception as e:

            session.pop("pending_registration", None)

            app.logger.error(f"OTP send failed: {str(e)}")
            print(f"ERROR sending OTP: {e}")

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
        # Security: Check rate limiting for staff login
        can_login, lockout_message = check_login_attempts(staff_identifier)
        if not can_login:
            flash(lockout_message)
            return render_template("login.html")

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
                record_login_attempt(staff_identifier, True)
                flash("Welcome back.")
                return redirect(url_for("dashboard_redirect"))
            flash("Invalid credentials.")
            record_activity(staff_identifier, "failed_login", f"Failed staff login attempt from {request.remote_addr}")
            is_locked = record_login_attempt(staff_identifier, False)
            if is_locked:
                flash("Too many failed attempts. Account locked for 15 minutes.")
            return render_template("login.html")

        customer_identifier = email or login_identifier or username
        # Security: Check rate limiting for customer login
        can_login, lockout_message = check_login_attempts(customer_identifier)
        if not can_login:
            flash(lockout_message)
            return render_template("login.html")

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
            record_login_attempt(customer_identifier, True)
            flash("Welcome back.")
            return redirect(url_for("dashboard_redirect"))
        flash("Invalid credentials.")
        record_activity(customer_identifier, "failed_login", f"Failed login attempt from {request.remote_addr}")
        is_locked = record_login_attempt(customer_identifier, False)
        if is_locked:
            flash("Too many failed attempts. Account locked for 15 minutes.")
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


@app.route("/forgot-password", methods=["GET", "POST"])

def forgot_password():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        if not email:

            flash("Email is required.")

            return render_template("forgot_password.html")

        user = get_user_by_email(email)

        if user:

            # Generate reset token
            reset_token = f"{random.randint(100000, 999999)}"
            
            # Store token in database (using a simple approach - in production, use a dedicated table)
            session["password_reset"] = {
                "user_id": user["id"],
                "token": reset_token,
                "expires_at": time.time() + 600  # 10 minutes
            }
            
            # Send email with reset token
            try:
                send_otp_email_async(email, reset_token)
                flash(f"Password reset code sent to {email}.")
                return redirect(url_for("reset_password"))
            except Exception as e:
                app.logger.error(f"Failed to send reset email: {e}")
                flash("Could not send reset code. Please try again later.")
                return render_template("forgot_password.html")
        
        # Always show same message for security (don't reveal if email exists)
        flash("If an account exists with this email, a reset code will be sent.")
        return render_template("forgot_password.html")

    return render_template("forgot_password.html")


@app.route("/reset-password", methods=["GET", "POST"])

def reset_password():

    reset_data = session.get("password_reset")
    
    if not reset_data:
        flash("Password reset session expired. Please start again.")
        return redirect(url_for("forgot_password"))
    
    if time.time() > reset_data.get("expires_at", 0):
        session.pop("password_reset", None)
        flash("Reset code expired. Please request a new one.")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        reset_code = request.form.get("reset_code", "").strip()
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not all([reset_code, new_password, confirm_password]):
            flash("All fields are required.")
            return render_template("reset_password.html")

        if str(reset_code) != str(reset_data.get("token")):
            flash("Invalid reset code.")
            return render_template("reset_password.html")

        if new_password != confirm_password:
            flash("Passwords do not match.")
            return render_template("reset_password.html")

        if len(new_password) < 6:
            flash("Password must be at least 6 characters.")
            return render_template("reset_password.html")

        # Update password
        user_id = reset_data["user_id"]
        new_hash = generate_password_hash(new_password)
        
        get_db().execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, user_id))
        get_db().commit()
        
        # Clear reset session
        session.pop("password_reset", None)
        
        user = get_user_by_id(user_id)
        if user:
            record_activity(user["username"], "password_reset", "User reset password")
        
        flash("Password reset successfully. Please log in with your new password.")
        return redirect(url_for("login"))

    return render_template("reset_password.html")





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

        if not recipient_user or (recipient_user["id"] is not None and recipient_user["id"] == user["id"]) or (recipient_user["role"] is not None and recipient_user["role"] != "customer"):

            flash("Recipient customer account not found.")

            return redirect(url_for("customer_dashboard"))



    timestamp = datetime.now(timezone.utc).isoformat()

    sender_account = user["account_number"]

    receiver_account = recipient_user["account_number"] if recipient_user and recipient_user["account_number"] else user["account_number"]



    get_db().execute(

        """

        INSERT INTO transactions (sender_account, receiver_account, amount, transaction_type,

            currency, channel, timestamp, status, risk_score, risk_level, description)

        VALUES (?,?,?,?,?,?,?,?,?,?,?)

        """,

        (sender_account, receiver_account, amount, tx_type, 'USD', 'online', timestamp, 'Completed', 0, 'normal', 'Initiated'),

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

        if recipient_user and recipient_user["id"] is not None:
            get_db().execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, recipient_user["id"]))



    get_db().commit()

    broadcast_user_balance(get_db(), sender_account)

    if tx_type == "transfer":

        broadcast_user_balance(get_db(), receiver_account)

    broadcast_stats(get_db())

    # Train AI model in background thread to avoid blocking
    import threading
    def train_in_background():
        try:
            _train_ai_model_from_db(get_db())
        except Exception as e:
            if app:
                app.logger.error(f"Background AI training failed: {e}")
    threading.Thread(target=train_in_background, daemon=True).start()

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

    alert_page = request_page("alert_page")

    offset = (page - 1) * PAGE_SIZE

    alert_offset = (alert_page - 1) * PAGE_SIZE

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

        "SELECT a.*, u.username FROM alerts a LEFT JOIN users u ON a.account_number=u.account_number WHERE a.status='open' ORDER BY a.timestamp DESC, a.id DESC LIMIT ? OFFSET ?",

        (PAGE_SIZE, alert_offset),

    ).fetchall()

    open_alert_count = get_db().execute(

        "SELECT COUNT(*) as c FROM alerts WHERE status='open'"

    ).fetchone()["c"]

    pending_sars = get_db().execute(

        "SELECT COUNT(*) as c FROM sar_reports WHERE status='draft'"

    ).fetchone()["c"]

    pending_ctrs = get_db().execute(

        "SELECT COUNT(*) as c FROM ctr_reports WHERE status='pending'"

    ).fetchone()["c"]



    stats = {

        "open_alerts": open_alert_count,

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

            "alert_page": alert_page,

            "open_alert_count": open_alert_count,

        },

        transactions=transactions,

        open_alerts=open_alerts,

        filter_value=filter_value,

        stats=stats,

        page=page,

        total_count=total_count,

        page_size=PAGE_SIZE,

        alert_page=alert_page,

        open_alert_count=open_alert_count,

    )



def _get_next_open_alert_id(conn, current_alert_id):
    next_alert = conn.execute(
        "SELECT id FROM alerts WHERE status='open' AND id != ? ORDER BY timestamp DESC, id DESC LIMIT 1",
        (current_alert_id,),
    ).fetchone()
    return next_alert["id"] if next_alert else None


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

    account_number = alert["account_number"]

    account_user = get_db().execute(

        "SELECT * FROM users WHERE account_number=?", (account_number,)

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
                old_risk = account_user["risk_rating"] or "standard"
                new_risk = update_customer_risk_rating(get_db(), account_number, "resolve", old_risk)
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
                old_risk = account_user["risk_rating"] or "standard"
                new_risk = update_customer_risk_rating(get_db(), account_number, "escalate", old_risk)
                record_activity(officer["username"], "escalate_alert", f"Alert #{alert_id} escalated, risk rating: {old_risk} -> {new_risk}")
                flash(f"Alert #{alert_id} escalated. Customer risk rating updated to {new_risk}.")
            else:
                record_activity(officer["username"], "escalate_alert", f"Alert #{alert_id} escalated (account not found)")
                flash(f"Alert #{alert_id} escalated.")



        elif action == "file_sar":

            narrative = request.form.get("sar_narrative", notes)

            ref = _generate_sar_ref()

            get_db().execute(

                "INSERT INTO sar_reports (alert_id, account_number, filed_by, narrative, status, reference_number, created_at) VALUES (?,?,?,?,?,?,?)",

                (alert_id, account_number, officer["username"], narrative, 'draft', ref,

                 datetime.now(timezone.utc).isoformat()),

            )

            get_db().execute(

                "UPDATE alerts SET status='sar_filed', case_notes=? WHERE id=?",

                (f"SAR filed: {ref}. {notes}", alert_id),

            )

            # Update customer risk rating
            if account_user:
                old_risk = account_user["risk_rating"] or "standard"
                new_risk = update_customer_risk_rating(get_db(), account_number, "file_sar", old_risk)
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

        next_alert_id = _get_next_open_alert_id(get_db(), alert_id)
        if next_alert_id is not None:
            return redirect(url_for("alert_detail", alert_id=next_alert_id))

        return redirect(url_for("compliance_dashboard"))



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
    app.logger.info("Transaction generation route called")
    admin_user = get_user_by_id(session["user_id"])

    try:

        count = int(request.form.get("count", 100))

    except ValueError:

        count = 100

    if count not in (100, 500, 1000, 2000, 5000):

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
            transactions = _simulation_transaction(label, users)
            for (
                sender, recipient, tx_type, amount, timestamp,
                channel, description, _scenario_reason, dest_country,
            ) in transactions:
                sender_account = sender["account_number"]
                receiver_account = recipient["account_number"] if tx_type == "transfer" else sender_account

                get_db().execute(
                    """
                    INSERT INTO transactions (sender_account, receiver_account, amount, transaction_type,
                        currency, channel, timestamp, status, risk_score, risk_level, description,
                        destination_country, generated_label)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        sender_account, receiver_account, amount, tx_type, "USD", channel, timestamp, 'Completed', 0, 'normal', description, dest_country, label,
                    ),
                )

                transaction_id = get_last_insert_id(get_db())
                transactions_to_process.append((transaction_id, sender, recipient, tx_type, amount, timestamp, sender_account, receiver_account, dest_country, label, _scenario_reason))

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

        # Train AI model first with existing data before processing new transactions
        # This ensures new transactions are processed with a properly trained model
        _train_ai_model_from_db(get_db(), emit_events=False)

        # Process transactions in batch for AML rules and AI
        # Evaluate chronologically so every score uses only information that
        # was available at that point in time.
        for transaction_id, sender, recipient, tx_type, amount, timestamp, sender_account, receiver_account, dest_country, label, scenario_reason in sorted(
            transactions_to_process, key=lambda item: item[5]
        ):

            risk_score, risk_level, reason, alert_id = process_transaction_event(
                get_db(), transaction_id, sender_account, receiver_account,
                amount, tx_type, timestamp, account_number=sender_account,
                destination_country=dest_country,
                generated_label=label,
                scenario_reason=scenario_reason,
            )

            if risk_level in ("normal", "low"):
                generated["normal"] += 1
            elif risk_level in ("critical", "high_risk"):
                generated["critical"] += 1
            else:
                generated["flagged"] += 1

        get_db().commit()

        # Only broadcast balances for affected accounts
        affected_accounts = set()
        for transaction_id, sender, recipient, tx_type, amount, timestamp, sender_account, receiver_account, dest_country, _label in transactions_to_process:
            affected_accounts.add(sender_account)
            if tx_type == "transfer":
                affected_accounts.add(receiver_account)
        
        for account in affected_accounts:
            broadcast_user_balance(get_db(), account)

        broadcast_event("transaction_batch", {
            "count": count,
            "normal": generated["normal"],
            "flagged": generated["flagged"],
            "critical": generated["critical"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        broadcast_stats(get_db())

        # Retrain AI model with the new transactions to include them in training
        import threading
        def train_in_background():
            try:
                _train_ai_model_from_db(get_db())
            except Exception as e:
                if app:
                    app.logger.error(f"Background AI training failed: {e}")
        threading.Thread(target=train_in_background, daemon=True).start()

        record_activity(
            admin_user["username"],
            "generate_transactions",
            (
                f"Generated {count} transactions: "
                f"{generated['normal']} normal, {generated['flagged']} flagged, "
                f"{generated['critical']} critical/high-risk"
            ),
        )

        app.logger.info(f"Transaction generation completed: {count} transactions generated")
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
        # Keep deployed databases in sync with the current application schema.
        # CREATE ... IF NOT EXISTS makes table/index creation safe to re-run.
        conn.executescript(get_schema_sql(app.config["DATABASE"]))
        conn.executescript(create_messaging_tables_sql(app.config["DATABASE"]))

        if is_postgres_database_url(app.config["DATABASE"]):
            _migrate_postgres(conn)
        elif is_mysql_database_url(app.config["DATABASE"]):
            _migrate_mysql(conn)
        else:
            _migrate_sqlite(conn)

        conn.commit()

        record_activity(admin_user["username"], "migrate_database", "Ran database migration")

        flash("Database migration completed successfully. Missing tables and columns are now up to date.")

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





def initialize_startup():
    init_db()
    seed_demo_data()
    ensure_ai_model_ready()
    ensure_background_monitor()


# Initialize database on startup when imported by a WSGI server.
if __name__ != "__main__":
    try:
        initialize_startup()
    except Exception as e:
        logging.error(f"Error during startup initialization: {e}")


if __name__ == "__main__":

    initialize_startup()

    socketio.run(

        app,

        debug=app.config.get("DEBUG", False),

        host="0.0.0.0",

        port=5000,

        allow_unsafe_werkzeug=True,

        use_reloader=False,

    )

