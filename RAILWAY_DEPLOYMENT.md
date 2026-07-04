# Free Deployment Guide - Railway with MySQL

## Quick Steps (5 minutes)

### 1. Push Code to GitHub (Already Done)
Your code is already at: https://github.com/prominancefungurayi7-cyber/AML_System

### 2. Create Railway Account
- Go to https://railway.app
- Sign up (free $5/month credit)
- Verify email

### 3. Deploy Application
1. Click "New Project"
2. Select "Deploy from GitHub repo"
3. Choose `AML_System` repository
4. Click "Deploy"
5. Wait 2-3 minutes for build

### 4. Add MySQL Database
1. In Railway dashboard, click "New Service"
2. Select "MySQL"
3. Wait for MySQL to initialize
4. Click on MySQL service → "Variables"
5. Copy the `DATABASE_URL` value

### 5. Configure Environment Variables
1. Go to your app service → Settings → Variables
2. Add these variables:
   - `DATABASE_URL`: Paste the MySQL connection string from step 4
   - `SECRET_KEY`: Generate one with: `python -c "import secrets; print(secrets.token_hex(32))"`
   - `FLASK_ENV`: `production`
   - `PORT`: `5000`

### 6. Redeploy
1. Click "Deploy" button in app service
2. Wait 2-3 minutes
3. Click the generated URL (e.g., https://your-app.railway.app)

## That's It!

Your AML System is now live with:
- Free hosting
- Free MySQL database
- Automatic SSL
- Real-time monitoring
- Industrial-grade features

## Cost
- **Free**: $5/month credit covers both app and MySQL
- **After credit**: ~$5-10/month for small usage

## Alternative: PlanetScale + Railway
If Railway MySQL isn't available:
1. Create free PlanetScale account (https://planetscale.com)
2. Create database
3. Get connection string
4. Use it as `DATABASE_URL` in Railway

## Using Railway PostgreSQL (Recommended for Production)

1. Add PostgreSQL service in Railway dashboard
2. Set `DATABASE_URL` environment variable to Railway's PostgreSQL connection string
3. Update `.env.example` to use PostgreSQL format

## Monitoring
- Railway provides built-in logs and metrics
- Access logs via: `railway logs`
- Monitor health at: `https://your-app-name.railway.app/health`

## Troubleshooting
- If deployment fails, check: `railway logs`
- Ensure all dependencies are in requirements.txt
- Verify Dockerfile syntax
- Check environment variables are set correctly
