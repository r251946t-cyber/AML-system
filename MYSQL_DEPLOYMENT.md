# MySQL Deployment Guide

## Free MySQL-Compatible Deployment Platforms

### Option 1: Railway (Recommended - Free Tier Available)

**Pros:**
- Free tier with $5/month credit
- Built-in MySQL addon
- Automatic SSL
- Easy GitHub integration
- Real-time metrics

**Steps:**
1. Go to https://railway.app
2. Create new project from your GitHub repo
3. Add MySQL service (New Service → MySQL)
4. Railway provides connection string like: `mysql://root:password@host:3306/railway`
5. Set `DATABASE_URL` environment variable to the MySQL connection string
6. Deploy

**Environment Variables:**
```
DATABASE_URL=mysql://root:password@host:3306/railway
SECRET_KEY=<generate-strong-key>
FLASK_ENV=production
PORT=5000
```

### Option 2: Render (Free Tier Available)

**Pros:**
- Free tier for web services
- MySQL addon available (free tier: 90 days, then $7/month)
- Automatic SSL
- Easy deployment

**Steps:**
1. Go to https://render.com
2. Create new web service from GitHub
3. Add PostgreSQL (Render doesn't have MySQL, but your app supports PostgreSQL too)
4. Or use external MySQL provider (PlanetScale, Aiven)

### Option 3: PlanetScale (MySQL-specific, Free Tier)

**Pros:**
- MySQL-compatible
- Serverless MySQL
- Free tier: 5GB storage, 1 billion rows read/month
- Excellent for production

**Steps:**
1. Go to https://planetscale.com
2. Create database
3. Get connection string
4. Deploy app to Railway/Render and set `DATABASE_URL`

**Connection String Format:**
```
mysql://user:password@host:port/database
```

### Option 4: Aiven (Free Tier Available)

**Pros:**
- MySQL managed service
- Free tier: 1GB storage, 10k connections/month
- High availability

**Steps:**
1. Go to https://aiven.io
2. Create MySQL service
3. Get connection string
4. Deploy app and configure

### Option 5: DigitalOcean (Paid, but affordable)

**Pros:**
- Managed MySQL database
- $15/month for basic plan
- Reliable and scalable

**Steps:**
1. Create DigitalOcean account
2. Create MySQL database cluster
3. Deploy app to DigitalOcean App Platform or Droplet

## Docker Compose (Local/Self-Hosted)

If you want to deploy with MySQL using Docker:

```yaml
version: '3.8'
services:
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: aml
      MYSQL_USER: aml
      MYSQL_PASSWORD: aml123
    ports:
      - "3306:3306"
    volumes:
      - mysql_data:/var/lib/mysql

  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      DATABASE_URL: mysql://aml:aml123@mysql:3306/aml
      SECRET_KEY: your-secret-key
      FLASK_ENV: production
    depends_on:
      - mysql

volumes:
  mysql_data:
```

Run with:
```bash
docker-compose up -d
```

## Configuration for MySQL

Your `config.py` already has MySQL as default:
```python
DEFAULT_MYSQL_DATABASE_URL = "mysql://aml:aml123@127.0.0.1:3306/aml"
```

For production, set `DATABASE_URL` environment variable to your MySQL connection string.

## Recommended: Railway + MySQL

**Best free option for MySQL deployment:**

1. Deploy app to Railway
2. Add MySQL addon on Railway
3. Railway automatically provides MySQL connection string
4. Set `DATABASE_URL` in Railway dashboard
5. Your app will use Railway's MySQL automatically

This gives you:
- Free hosting for the app
- Free MySQL database
- Automatic SSL
- Built-in monitoring
- Easy scaling
