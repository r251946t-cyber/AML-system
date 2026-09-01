"""
database.py — Database Adapter Module

This module provides database abstraction layer for SQLite, MySQL, and PostgreSQL.
It handles connection management, query normalization, and schema generation.

Classes:
    - DatabaseAdapter: Unified interface for different database engines
Functions:
    - is_postgres_database_url: Check if URL is PostgreSQL
    - is_mysql_database_url: Check if URL is MySQL
    - connect_db: Create database connection based on URL
    - get_db: Get database connection from Flask context
    - get_schema_sql: Generate DDL based on database engine
"""

from urllib.parse import unquote, urlparse
import sqlite3


class DatabaseAdapter:
    """Unified database adapter for SQLite, MySQL, and PostgreSQL."""
    
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
        """Convert SQLite-style ? placeholders to %s for MySQL/PostgreSQL."""
        if self.is_postgres or self.is_mysql:
            return query.replace("?", "%s")
        return query

    def execute(self, query, params=()):
        """Execute a query with parameters."""
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
        """Execute multiple SQL statements."""
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
        """Commit transaction."""
        self.connection.commit()

    def rollback(self):
        """Rollback transaction."""
        self.connection.rollback()

    def close(self):
        """Close connection."""
        self.connection.close()


def is_postgres_database_url(url):
    """Check if the database URL is for PostgreSQL."""
    return bool(url) and url.startswith(("postgres://", "postgresql://"))


def is_mysql_database_url(url):
    """Check if the database URL is for MySQL."""
    return bool(url) and url.startswith(("mysql://", "mysql+mysqlconnector://"))


def connect_db(database_url):
    """
    Create a database connection based on the URL.
    
    Args:
        database_url: Database connection string (SQLite, MySQL, or PostgreSQL)
    
    Returns:
        DatabaseAdapter instance
    """
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

    # SQLite
    if database_url.startswith("sqlite:///"):
        database_url = database_url[len("sqlite:///"):]
    conn = sqlite3.connect(database_url)
    conn.row_factory = sqlite3.Row
    return DatabaseAdapter(conn, "sqlite")


def get_schema_sql(database_url):
    """
    Return database-engine-appropriate DDL for schema creation.
    
    Args:
        database_url: Database connection string
    
    Returns:
        String containing SQL DDL statements
    """
    is_pg = is_postgres_database_url(database_url)
    is_my = is_mysql_database_url(database_url)

    if is_my:
        ai, pk_type, text_type, long_text_type, real_type = "AUTO_INCREMENT", "BIGINT", "VARCHAR(255)", "LONGTEXT", "DOUBLE"
    elif is_pg:
        ai, pk_type, text_type, long_text_type, real_type = "GENERATED ALWAYS AS IDENTITY", "BIGINT", "TEXT", "TEXT", "DOUBLE PRECISION"
    else:
        ai, pk_type, text_type, long_text_type, real_type = "AUTOINCREMENT", "INTEGER", "TEXT", "TEXT", "REAL"

    schema_sql = f"""
    CREATE TABLE IF NOT EXISTS users (
        id {pk_type} PRIMARY KEY {ai},
        username {text_type} UNIQUE NOT NULL,
        password_hash {text_type} NOT NULL,
        account_number {text_type} UNIQUE NOT NULL,
        id_number {text_type},
        email {text_type},
        role {text_type} DEFAULT 'customer',
        balance REAL DEFAULT 0.0,
        kyc_status {text_type} DEFAULT 'pending',
        risk_rating {text_type} DEFAULT 'standard',
        wealth_segment {text_type} DEFAULT 'average',
        pep_flag INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS transactions (
        id {pk_type} PRIMARY KEY {ai},
        sender_account {text_type} NOT NULL,
        receiver_account {text_type} NOT NULL,
        amount {real_type} NOT NULL,
        transaction_type {text_type} NOT NULL,
        channel {text_type} DEFAULT 'online',
        description {text_type},
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        risk_level {text_type} DEFAULT 'normal',
        risk_score REAL DEFAULT 0.0,
        rule_level {text_type} DEFAULT 'normal',
        rule_score REAL DEFAULT 0.0,
        ai_risk_level {text_type},
        ai_confidence REAL,
        generated_label {text_type},
        scenario_reason {text_type},
        destination_country {text_type} DEFAULT 'ZW',
        ctr_required INTEGER DEFAULT 0,
        sar_required INTEGER DEFAULT 0,
        FOREIGN KEY (sender_account) REFERENCES users(account_number),
        FOREIGN KEY (receiver_account) REFERENCES users(account_number)
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id {pk_type} PRIMARY KEY {ai},
        transaction_id {pk_type},
        account_number {text_type} NOT NULL,
        risk_score REAL NOT NULL,
        risk_level {text_type} NOT NULL,
        reason {long_text_type},
        rules_triggered {text_type},
        status {text_type} DEFAULT 'open',
        assigned_to {text_type},
        resolved_by {text_type},
        resolved_at TIMESTAMP,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (transaction_id) REFERENCES transactions(id)
    );

    CREATE TABLE IF NOT EXISTS behavioral_profiles (
        id {pk_type} PRIMARY KEY {ai},
        account_number {text_type} UNIQUE NOT NULL,
        profile_data {long_text_type},
        last_updated TIMESTAMP,
        total_transactions INTEGER DEFAULT 0,
        FOREIGN KEY (account_number) REFERENCES users(account_number)
    );

    CREATE TABLE IF NOT EXISTS sar_reports (
        id {pk_type} PRIMARY KEY {ai},
        reference_number {text_type} UNIQUE NOT NULL,
        transaction_id {pk_type},
        account_number {text_type} NOT NULL,
        filing_reason {long_text_type},
        status {text_type} DEFAULT 'filed',
        filed_by {text_type},
        filed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (transaction_id) REFERENCES transactions(id)
    );

    CREATE TABLE IF NOT EXISTS ctr_reports (
        id {pk_type} PRIMARY KEY {ai},
        reference_number {text_type} UNIQUE NOT NULL,
        account_number {text_type} NOT NULL,
        total_amount {real_type} NOT NULL,
        transaction_count INTEGER DEFAULT 1,
        filing_date DATE,
        status {text_type} DEFAULT 'filed',
        filed_by {text_type},
        filed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS system_activity_log (
        id {pk_type} PRIMARY KEY {ai},
        user_id {text_type},
        action {text_type} NOT NULL,
        details {long_text_type},
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address {text_type}
    );

    CREATE TABLE IF NOT EXISTS activity_log (
        id {pk_type} PRIMARY KEY {ai},
        actor {text_type},
        action {text_type} NOT NULL,
        detail {long_text_type},
        ip_address {text_type},
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS watchlist (
        id {pk_type} PRIMARY KEY {ai},
        name {text_type} NOT NULL,
        id_number {text_type},
        account_number {text_type},
        list_type {text_type} NOT NULL,
        reason {long_text_type},
        added_by {text_type},
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    
    # MySQL doesn't support IF NOT EXISTS for indexes, handle separately
    if is_my:
        return schema_sql  # Indexes will be created manually or via migration
    else:
        return schema_sql + """
    CREATE INDEX IF NOT EXISTS idx_transactions_sender ON transactions(sender_account);
    CREATE INDEX IF NOT EXISTS idx_transactions_receiver ON transactions(receiver_account);
    CREATE INDEX IF NOT EXISTS idx_transactions_timestamp ON transactions(timestamp);
    CREATE INDEX IF NOT EXISTS idx_alerts_account ON alerts(account_number);
    CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
    CREATE INDEX IF NOT EXISTS idx_activity_user ON system_activity_log(user_id);
    CREATE INDEX IF NOT EXISTS idx_activity_log_actor ON activity_log(actor);
    CREATE INDEX IF NOT EXISTS idx_watchlist_type ON watchlist(list_type);
    CREATE INDEX IF NOT EXISTS idx_watchlist_id_number ON watchlist(id_number);
    """
