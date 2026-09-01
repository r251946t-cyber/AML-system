import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_MYSQL_DATABASE_URL = "mysql://aml:aml123@127.0.0.1:3306/aml"


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "aml-secret-key")
    # Railway's MySQL service exposes MYSQL_URL by default.  DATABASE_URL
    # remains preferred so other hosts can use their standard variable name.
    DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("MYSQL_URL") or DEFAULT_MYSQL_DATABASE_URL
    DEBUG = False
    TESTING = False
    JSON_SORT_KEYS = False


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
    DATABASE_URL = str(BASE_DIR / "test_aml.db")


class ProductionConfig(Config):
    DEBUG = False
