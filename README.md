# Real-Time AML System

A Flask-based AML monitoring prototype with authentication, transactions, risk scoring, alerts, compliance dashboards, and live event streaming.

## Run locally

1. Install dependencies:
   `pip install -r requirements.txt`
2. Create the local MySQL database and user:

```sql
CREATE DATABASE IF NOT EXISTS aml CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'aml'@'localhost' IDENTIFIED BY 'aml123';
CREATE USER IF NOT EXISTS 'aml'@'127.0.0.1' IDENTIFIED BY 'aml123';
GRANT ALL PRIVILEGES ON aml.* TO 'aml'@'localhost';
GRANT ALL PRIVILEGES ON aml.* TO 'aml'@'127.0.0.1';
FLUSH PRIVILEGES;
```

3. Confirm `.env` contains:
   `DATABASE_URL=mysql://aml:aml123@127.0.0.1:3306/aml`
4. Start the app; it creates the tables and seeds staff accounts automatically:
   `python app.py`
5. Open http://127.0.0.1:5000

The first app start creates the MySQL tables and seeds:

- Admin / Admin123
- Compliance / Compliance123

## Production notes

- Set a strong `SECRET_KEY`.
- Use MySQL 8+ with a dedicated database user in production.
- Run the app with Gunicorn in a container or a cloud host.
- Keep the `.env` values out of source control.

## Docker

```bash
docker build -t aml-system .
docker run -p 5000:5000 aml-system
```
