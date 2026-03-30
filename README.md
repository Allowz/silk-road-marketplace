# Silk Road Marketplace

A dark-first, modern multi-vendor marketplace built with Flask, Jinja2, and local JSON data.  
This project is designed for rapid local development, visual polish, and practical marketplace workflows.

## Highlights

- Full marketplace browsing flow: home, listings, listing detail, seller store pages
- Authentication system: register, login, logout, password reset, Google OAuth
- Seller features: post ads, seller profile/store, seller reviews, listing chat
- Buyer flow: shopping cart, checkout, orders, order detail tracking
- Payment integration scaffold: Paystack initialize + verify callback flow
- Admin control center: users, listings, moderation, settings, transactions, reports
- Responsive UI with dark/light toggle and custom marketplace styling

## Tech Stack

- `Python` + `Flask`
- `Jinja2` templates
- `Flask-Session` + `Flask-SQLAlchemy` (session and user persistence layer)
- JSON-backed marketplace data (`data/*.json`)
- Static assets in `static/`, `frontend/`, and prebuilt CSS/JS bundles

## Project Structure

```text
silk-road-marketplace/
├─ app.py
├─ requirements.txt
├─ templates/
├─ static/
├─ data/
├─ deploy/
├─ wsgi.py
└─ gunicorn.conf.py
```

## Quick Start (Local)

1. Clone the repo
2. Create and activate a virtual environment
3. Install dependencies
4. Run the app

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open: `http://127.0.0.1:5500/`

## Environment Variables

Create a `.env` file in the project root:

```env
FLASK_SECRET_KEY=change-this-secret
DATABASE_URL=sqlite:///data/app.db

# Optional Google auth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://127.0.0.1:5500/auth/google/callback

# Optional Paystack
PAYSTACK_SECRET_KEY=your-paystack-secret-key
```

## Deployment Notes

- Production server target: `gunicorn` + `nginx`
- Deployment templates included in:
  - `deploy/nginx-silkroad.conf`
  - `deploy/silkroad.service`
- WSGI entrypoint: `wsgi.py`

## Core Routes

- `/` Home
- `/listings` Listings with filters
- `/listing/<slug>` Listing detail
- `/store/<username>` Seller store
- `/cart` Cart
- `/checkout` Checkout
- `/orders` Order history
- `/admin` Admin dashboard

## Roadmap Ideas

- PostgreSQL migration for full production data durability
- WebSocket chat for real-time messaging
- Notification center (in-app + email)
- Stronger anti-fraud and dispute automation

## License

This project is provided as-is for educational and product prototyping use.
