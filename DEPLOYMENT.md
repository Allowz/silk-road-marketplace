# Silk Road Deployment (Linux + Nginx + Gunicorn + PostgreSQL)

## 1. Install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 2. PostgreSQL

Create database and user:

```sql
CREATE DATABASE silkroad_db;
CREATE USER silkroad_user WITH PASSWORD 'strong_password_here';
GRANT ALL PRIVILEGES ON DATABASE silkroad_db TO silkroad_user;
```

Set `DATABASE_URL` in `.env`:

```env
DATABASE_URL=postgresql+psycopg2://silkroad_user:strong_password_here@127.0.0.1:5432/silkroad_db
FLASK_SECRET_KEY=change-me
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=https://your-domain.com/auth/google/callback
```

## 3. Run with Gunicorn

```bash
gunicorn -c gunicorn.conf.py wsgi:app
```

## 4. Configure Nginx

Copy `deploy/nginx-silkroad.conf` to `/etc/nginx/sites-available/silkroad`, enable it, then reload Nginx.

## 5. Run as service

Copy `deploy/silkroad.service` to `/etc/systemd/system/silkroad.service` and run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable silkroad
sudo systemctl restart silkroad
```

## User Roles

- `admin`: full admin panel access
- `seller`: can post/manage own ads
- `buyer`: browse and purchase flows (no admin access)
