from __future__ import annotations

import json
import os
import re
import secrets
import shutil
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from flask import Flask, abort, flash, has_app_context, redirect, render_template, request, session, url_for
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_FILE = DATA_DIR / "listings.json"
USERS_FILE = DATA_DIR / "users.json"
TRANSACTIONS_FILE = DATA_DIR / "transactions.json"
REPORTS_FILE = DATA_DIR / "reports.json"
SETTINGS_FILE = DATA_DIR / "settings.json"
CATEGORIES_FILE = DATA_DIR / "categories.json"
ANNOUNCEMENTS_FILE = DATA_DIR / "announcements.json"
PROMOTIONS_FILE = DATA_DIR / "promotions.json"
ACTIVITY_FILE = DATA_DIR / "activity_log.json"
MESSAGES_FILE = DATA_DIR / "messages.json"
REVIEWS_FILE = DATA_DIR / "reviews.json"
SELLER_PROFILES_FILE = DATA_DIR / "seller_profiles.json"
ORDERS_FILE = DATA_DIR / "orders.json"
ENV_FILE = BASE_DIR / ".env"

STATIC_DIR = BASE_DIR / "static"
UPLOADS_ROOT = STATIC_DIR / "uploads"
LISTINGS_UPLOAD_ROOT = UPLOADS_ROOT / "new" / "listings"
ADS_UPLOAD_ROOT = UPLOADS_ROOT / "new" / "ads-images"
BACKUP_DIR = BASE_DIR / "backups"

DEFAULT_IMAGE_NAME = "image.webp"
ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}

CATEGORY_ICONS = {
    "Vehicles": "car-100.png",
    "Electronics": "electronics-100.png",
    "Fashion": "fashion-100.png",
    "Property": "house-100.png",
    "Services": "labour-100.png",
    "Mobile": "mobile-100.png",
    "Food": "food-100.png",
    "Workspace": "workspace-100.png",
}

DEFAULT_CATEGORIES = list(CATEGORY_ICONS.keys())
DEFAULT_SETTINGS: dict[str, Any] = {
    "site_name": "SILK ROAD",
    "logo_path": "frontend/images/silk-road-logo.png",
    "commission_percent": 5.0,
    "escrow_enabled": True,
    "multi_vendor_payout_automation": False,
    "ai_fraud_detection": False,
    "geo_restrictions": [],
    "require_admin_2fa": False,
    "rate_limit_per_minute": 120,
    "payment_gateway": "Manual",
    "email_provider": "Local",
    "sms_provider": "Disabled",
    "api_keys": {"payments": "", "email": "", "sms": ""},
    "traffic_sources": {"Direct": 62, "Search": 25, "Social": 13},
    "blacklist_keywords": ["weapon", "drugs", "counterfeit"],
    "announcement_enabled": True,
    "newsletter_enabled": True,
    "dark_mode": True,
}


def load_env_file() -> None:
    if not ENV_FILE.exists():
        return
    for raw_line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


load_env_file()


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "silkroad-dev-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", f"sqlite:///{(DATA_DIR / 'app.db').as_posix()}")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_TYPE"] = "sqlalchemy"
app.config["SESSION_SQLALCHEMY_TABLE"] = "flask_sessions"
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
db = SQLAlchemy(app)
app.config["SESSION_SQLALCHEMY"] = db
Session(app)

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
PAYSTACK_INITIALIZE_URL = "https://api.paystack.co/transaction/initialize"
PAYSTACK_VERIFY_URL = "https://api.paystack.co/transaction/verify"
VALID_USER_ROLES = {"admin", "seller", "buyer"}


def normalize_role(role: str) -> str:
    normalized = (role or "").strip().lower()
    if normalized == "vendor":
        normalized = "seller"
    if normalized not in VALID_USER_ROLES:
        normalized = "seller"
    return normalized


class UserAccount(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=True)
    password_hash = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(20), nullable=False, default="seller")
    status = db.Column(db.String(20), nullable=False, default="active")
    seller_verified = db.Column(db.Boolean, nullable=False, default=False)
    session_version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.String(40), nullable=True)
    last_login = db.Column(db.String(40), nullable=True)
    last_ip = db.Column(db.String(80), nullable=True)
    auth_provider = db.Column(db.String(50), nullable=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "password_hash": self.password_hash,
            "role": normalize_role(self.role),
            "status": self.status,
            "seller_verified": bool(self.seller_verified),
            "session_version": int(self.session_version or 1),
            "created_at": self.created_at,
            "last_login": self.last_login,
            "last_ip": self.last_ip,
            "auth_provider": self.auth_provider,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_json(path: Path, default: Any) -> Any:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        with path.open("w", encoding="utf-8") as file:
            json.dump(default, file, indent=2)
        return default
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(value, file, indent=2)


def ensure_upload_structure() -> None:
    LISTINGS_UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    ADS_UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def ensure_data_files() -> None:
    ensure_upload_structure()
    read_json(CATEGORIES_FILE, DEFAULT_CATEGORIES)
    read_json(SETTINGS_FILE, DEFAULT_SETTINGS)
    read_json(TRANSACTIONS_FILE, [])
    read_json(REPORTS_FILE, [])
    read_json(ANNOUNCEMENTS_FILE, [])
    read_json(PROMOTIONS_FILE, [])
    read_json(ACTIVITY_FILE, [])
    read_json(MESSAGES_FILE, [])
    read_json(REVIEWS_FILE, [])
    read_json(SELLER_PROFILES_FILE, {})
    read_json(ORDERS_FILE, [])
    users = read_json(USERS_FILE, [])
    changed = False
    for user in users:
        if "role" not in user:
            user["role"] = "admin" if user.get("username", "").lower() == "admin" else "seller"
            changed = True
        else:
            normalized = normalize_role(str(user.get("role", "seller")))
            if user.get("role") != normalized:
                user["role"] = normalized
                changed = True
        if "status" not in user:
            user["status"] = "active"
            changed = True
        if "seller_verified" not in user:
            user["seller_verified"] = False
            changed = True
        if "session_version" not in user:
            user["session_version"] = 1
            changed = True
    if changed:
        write_json(USERS_FILE, users)


def seed_users_from_json() -> None:
    if UserAccount.query.count() > 0:
        return
    json_users = read_json(USERS_FILE, [])
    for item in json_users:
        username = str(item.get("username", "")).strip()
        if not username:
            continue
        db.session.add(
            UserAccount(
                id=int(item.get("id", 0) or 0) or None,
                username=username,
                email=item.get("email"),
                password_hash=str(item.get("password_hash", "")),
                role=normalize_role(str(item.get("role", "seller"))),
                status=str(item.get("status", "active")),
                seller_verified=bool(item.get("seller_verified", False)),
                session_version=int(item.get("session_version", 1) or 1),
                created_at=item.get("created_at"),
                last_login=item.get("last_login"),
                last_ip=item.get("last_ip"),
                auth_provider=item.get("auth_provider"),
            )
        )
    db.session.commit()


def initialize_database() -> None:
    with app.app_context():
        db.create_all()
        seed_users_from_json()


ensure_data_files()
initialize_database()


def load_listings() -> list[dict[str, Any]]:
    items = read_json(DATA_FILE, [])
    valid_items: list[dict[str, Any]] = []
    for item in items:
        if all(key in item for key in ("id", "slug", "title", "category", "image", "description")):
            item.setdefault("status", "approved")
            item.setdefault("featured", False)
            item.setdefault("flagged", False)
            item.setdefault("created_by", "system")
            item.setdefault("created_at", "2026-01-01T00:00:00Z")
            valid_items.append(item)
    return valid_items


def save_listings(items: list[dict[str, Any]]) -> None:
    write_json(DATA_FILE, items)


def load_users() -> list[dict[str, Any]]:
    if not has_app_context():
        with app.app_context():
            return load_users()
    users = [row.to_dict() for row in UserAccount.query.order_by(UserAccount.id.asc()).all()]
    return users


def save_users(users: list[dict[str, Any]]) -> None:
    if not has_app_context():
        with app.app_context():
            save_users(users)
            return
    existing_by_id = {int(row.id): row for row in UserAccount.query.all()}
    seen_ids: set[int] = set()
    for item in users:
        raw_id = int(item.get("id", 0) or 0)
        row = existing_by_id.get(raw_id) if raw_id else None
        if row is None:
            row = UserAccount()
            db.session.add(row)
        row.username = str(item.get("username", "")).strip()
        raw_email = item.get("email")
        email_value = str(raw_email).strip().lower() if raw_email is not None else ""
        row.email = email_value or None
        row.password_hash = str(item.get("password_hash", ""))
        row.role = normalize_role(str(item.get("role", "seller")))
        row.status = str(item.get("status", "active"))
        row.seller_verified = bool(item.get("seller_verified", False))
        row.session_version = int(item.get("session_version", 1) or 1)
        row.created_at = item.get("created_at")
        row.last_login = item.get("last_login")
        row.last_ip = item.get("last_ip")
        row.auth_provider = item.get("auth_provider")
        if raw_id:
            seen_ids.add(raw_id)
    for db_id, row in existing_by_id.items():
        if db_id not in seen_ids and seen_ids:
            db.session.delete(row)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise


def google_oauth_enabled() -> bool:
    return bool(os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"))


def google_redirect_uri() -> str:
    configured = os.environ.get("GOOGLE_REDIRECT_URI", "").strip()
    if configured:
        return configured
    return url_for("google_auth_callback", _external=True)


def safe_username_seed(email: str, name: str) -> str:
    if name and name.strip():
        seed = slugify(name).replace("-", "")
        if len(seed) >= 3:
            return seed
    local = email.split("@")[0].strip() if "@" in email else email.strip()
    seed = re.sub(r"[^a-zA-Z0-9_-]", "", local).lower()
    return seed[:24] or "user"


def unique_username(users: list[dict[str, Any]], base: str) -> str:
    taken = {str(item.get("username", "")).lower() for item in users}
    candidate = base
    if len(candidate) < 3:
        candidate = f"user{secrets.randbelow(9000) + 1000}"
    if candidate.lower() not in taken:
        return candidate
    suffix = 2
    while f"{candidate}{suffix}".lower() in taken:
        suffix += 1
    return f"{candidate}{suffix}"


def create_or_get_google_user(email: str, name: str) -> dict[str, Any]:
    users = load_users()
    normalized_email = email.strip().lower()
    existing = next((u for u in users if str(u.get("email", "")).lower() == normalized_email), None)
    if existing:
        return existing

    username = unique_username(users, safe_username_seed(email, name))
    new_user = {
        "id": next_id(users),
        "username": username,
        "email": normalized_email,
        "password_hash": generate_password_hash(secrets.token_urlsafe(24)),
        "role": "seller",
        "status": "active",
        "seller_verified": False,
        "session_version": 1,
        "created_at": utc_now(),
        "auth_provider": "google",
    }
    users.append(new_user)
    save_users(users)
    return new_user


def load_categories() -> list[str]:
    categories = read_json(CATEGORIES_FILE, DEFAULT_CATEGORIES)
    if not isinstance(categories, list):
        return DEFAULT_CATEGORIES
    return [str(item) for item in categories if str(item).strip()]


def save_categories(categories: list[str]) -> None:
    write_json(CATEGORIES_FILE, categories)


def load_transactions() -> list[dict[str, Any]]:
    return read_json(TRANSACTIONS_FILE, [])


def save_transactions(items: list[dict[str, Any]]) -> None:
    write_json(TRANSACTIONS_FILE, items)


def load_reports() -> list[dict[str, Any]]:
    return read_json(REPORTS_FILE, [])


def save_reports(items: list[dict[str, Any]]) -> None:
    write_json(REPORTS_FILE, items)


def load_settings() -> dict[str, Any]:
    settings = read_json(SETTINGS_FILE, DEFAULT_SETTINGS)
    merged = dict(DEFAULT_SETTINGS)
    merged.update(settings)
    return merged


def save_settings(settings: dict[str, Any]) -> None:
    write_json(SETTINGS_FILE, settings)


def load_announcements() -> list[dict[str, Any]]:
    return read_json(ANNOUNCEMENTS_FILE, [])


def save_announcements(items: list[dict[str, Any]]) -> None:
    write_json(ANNOUNCEMENTS_FILE, items)


def load_promotions() -> list[dict[str, Any]]:
    return read_json(PROMOTIONS_FILE, [])


def save_promotions(items: list[dict[str, Any]]) -> None:
    write_json(PROMOTIONS_FILE, items)


def load_messages() -> list[dict[str, Any]]:
    return read_json(MESSAGES_FILE, [])


def save_messages(items: list[dict[str, Any]]) -> None:
    write_json(MESSAGES_FILE, items)


def load_reviews() -> list[dict[str, Any]]:
    return read_json(REVIEWS_FILE, [])


def save_reviews(items: list[dict[str, Any]]) -> None:
    write_json(REVIEWS_FILE, items)


def load_orders() -> list[dict[str, Any]]:
    return read_json(ORDERS_FILE, [])


def save_orders(items: list[dict[str, Any]]) -> None:
    write_json(ORDERS_FILE, items)


def load_seller_profiles() -> dict[str, dict[str, Any]]:
    raw = read_json(SELLER_PROFILES_FILE, {})
    return raw if isinstance(raw, dict) else {}


def save_seller_profiles(items: dict[str, dict[str, Any]]) -> None:
    write_json(SELLER_PROFILES_FILE, items)


def load_activity_log() -> list[dict[str, Any]]:
    return read_json(ACTIVITY_FILE, [])


def save_activity_log(items: list[dict[str, Any]]) -> None:
    write_json(ACTIVITY_FILE, items[-1000:])


def append_activity(action: str, target: str, meta: dict[str, Any] | None = None) -> None:
    logs = load_activity_log()
    logs.append(
        {
            "timestamp": utc_now(),
            "actor": session.get("username", "system"),
            "action": action,
            "target": target,
            "ip": request.remote_addr or "unknown",
            "meta": meta or {},
        }
    )
    save_activity_log(logs)


def all_categories(items: list[dict[str, Any]]) -> list[str]:
    data_categories = {item["category"] for item in items}
    return sorted(set(load_categories()) | data_categories)


def find_listing_by_slug(items: list[dict[str, Any]], slug: str) -> dict[str, Any] | None:
    for item in items:
        if item["slug"] == slug:
            return item
    return None


def resolve_seller_username(listing: dict[str, Any], users: list[dict[str, Any]]) -> str:
    usernames_by_lower = {str(item.get("username", "")).lower(): str(item.get("username", "")) for item in users}
    created_by = str(listing.get("created_by", "")).strip()
    if created_by and created_by.lower() in usernames_by_lower:
        return usernames_by_lower[created_by.lower()]
    if "admin" in usernames_by_lower:
        return usernames_by_lower["admin"]
    if users:
        return str(users[0].get("username", "seller"))
    return created_by or "seller"


def seller_reviews_summary(username: str, reviews: list[dict[str, Any]]) -> dict[str, Any]:
    items = [r for r in reviews if str(r.get("seller", "")).lower() == username.lower()]
    count = len(items)
    avg = round(sum(float(r.get("rating", 0) or 0) for r in items) / count, 2) if count else 0.0
    return {"count": count, "avg": avg, "items": sorted(items, key=lambda x: str(x.get("created_at", "")), reverse=True)}


def enrich_listing_with_seller(listing: dict[str, Any], users: list[dict[str, Any]], profiles: dict[str, dict[str, Any]], reviews: list[dict[str, Any]]) -> dict[str, Any]:
    seller_username = resolve_seller_username(listing, users)
    seller_row = next((u for u in users if str(u.get("username", "")).lower() == seller_username.lower()), {})
    profile_key = seller_username.lower()
    profile = profiles.get(profile_key, {})
    summary = seller_reviews_summary(seller_username, reviews)
    enriched = dict(listing)
    enriched["seller_username"] = seller_username
    enriched["seller_profile"] = {
        "display_name": profile.get("display_name") or seller_username,
        "location": profile.get("location") or "Nigeria",
        "about": profile.get("about") or "Trusted marketplace seller.",
        "phone": profile.get("phone") or "",
        "joined_at": profile.get("joined_at") or "",
    }
    enriched["seller_rating"] = summary["avg"]
    enriched["seller_reviews_count"] = summary["count"]
    enriched["seller_verified"] = bool(seller_row.get("seller_verified", False))
    enriched["seller_role"] = normalize_role(str(seller_row.get("role", "seller")))
    return enriched


def parse_price_value(raw_price: Any) -> float | None:
    text = str(raw_price or "").strip()
    if not text:
        return None
    cleaned = re.sub(r"[^0-9.]", "", text)
    if not cleaned:
        return None
    try:
        return float(cleaned)
    except ValueError:
        return None


def parse_iso_timestamp(raw: Any) -> datetime | None:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def filter_by_date_posted(items: list[dict[str, Any]], date_posted: str) -> list[dict[str, Any]]:
    if not date_posted:
        return items
    now = datetime.now(timezone.utc)
    hours_by_filter = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30, "90d": 24 * 90}
    max_hours = hours_by_filter.get(date_posted)
    if max_hours is None:
        return items
    result: list[dict[str, Any]] = []
    for item in items:
        created_at = parse_iso_timestamp(item.get("created_at"))
        if created_at is None:
            continue
        age = now - created_at
        if age.total_seconds() <= max_hours * 3600:
            result.append(item)
    return result


def filter_listings(
    items: list[dict[str, Any]],
    query: str,
    category: str,
    location: str = "",
    min_price: str = "",
    max_price: str = "",
    date_posted: str = "",
) -> list[dict[str, Any]]:
    result = items
    if category:
        result = [item for item in result if item["category"].lower() == category.lower()]
    if location:
        result = [item for item in result if str(item.get("location", "")).lower() == location.lower()]
    if min_price.strip():
        try:
            min_val = float(min_price)
            result = [item for item in result if (parse_price_value(item.get("price")) or -1) >= min_val]
        except ValueError:
            pass
    if max_price.strip():
        try:
            max_val = float(max_price)
            result = [item for item in result if (parse_price_value(item.get("price")) or 10**18) <= max_val]
        except ValueError:
            pass
    if query:
        q = query.lower()
        result = [
            item
            for item in result
            if q in item["title"].lower()
            or q in item["description"].lower()
            or q in item.get("location", "").lower()
            or q in item["category"].lower()
        ]
    result = filter_by_date_posted(result, date_posted)
    return result


def public_path_to_file(public_path: str) -> Path:
    return (STATIC_DIR / public_path.replace("/", os.sep)).resolve()


def file_to_public_path(file_path: Path) -> str:
    rel = file_path.resolve().relative_to(STATIC_DIR.resolve())
    return str(rel).replace("\\", "/")


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9\s-]", "", value).strip().lower()
    slug = re.sub(r"[\s_-]+", "-", slug)
    return slug[:80] or "listing"


def unique_slug(items: list[dict[str, Any]], base_slug: str) -> str:
    existing = {item["slug"] for item in items}
    if base_slug not in existing:
        return base_slug
    counter = 2
    while f"{base_slug}-{counter}" in existing:
        counter += 1
    return f"{base_slug}-{counter}"


def listing_folder_for(category: str, slug: str) -> Path:
    return LISTINGS_UPLOAD_ROOT / slugify(category) / slug


def get_current_user_record() -> dict[str, Any] | None:
    username = session.get("username")
    if not username:
        return None
    row = UserAccount.query.filter(db.func.lower(UserAccount.username) == str(username).lower()).first()
    return row.to_dict() if row else None


def is_admin_user() -> bool:
    user = get_current_user_record()
    return bool(user and user.get("role") == "admin")


def login_required(view: Any) -> Any:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if not session.get("username"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        user = get_current_user_record()
        if not user:
            session.clear()
            flash("Session expired. Please log in again.", "error")
            return redirect(url_for("login"))
        if user.get("status") != "active":
            session.clear()
            flash("Your account is not active. Contact admin.", "error")
            return redirect(url_for("login"))
        if user.get("session_version", 1) != session.get("session_version", 1):
            session.clear()
            flash("You have been logged out by admin. Please log in again.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view: Any) -> Any:
    @wraps(view)
    @login_required
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if not is_admin_user():
            flash("Admin access only.", "error")
            return redirect(url_for("home"))
        return view(*args, **kwargs)

    return wrapped


def next_id(items: list[dict[str, Any]]) -> int:
    return max((int(item.get("id", 0)) for item in items), default=0) + 1


def format_naira(amount: float) -> str:
    return f"N {amount:,.2f}"


def get_cart_items() -> list[dict[str, Any]]:
    raw = session.get("cart", [])
    if not isinstance(raw, list):
        session["cart"] = []
        session.modified = True
        return []
    cleaned: list[dict[str, Any]] = []
    changed = False
    for row in raw:
        if not isinstance(row, dict):
            changed = True
            continue
        slug = str(row.get("slug", "")).strip()
        try:
            qty = int(row.get("qty", 1) or 1)
        except (TypeError, ValueError):
            qty = 1
        qty = max(1, min(99, qty))
        if not slug:
            changed = True
            continue
        normalized = {"slug": slug, "qty": qty}
        if normalized != row:
            changed = True
        cleaned.append(normalized)
    if changed:
        session["cart"] = cleaned
        session.modified = True
    return cleaned


def set_cart_items(items: list[dict[str, Any]]) -> None:
    session["cart"] = items
    session.modified = True


def cart_item_count() -> int:
    return sum(int(item.get("qty", 0) or 0) for item in get_cart_items())


def build_cart_details() -> tuple[list[dict[str, Any]], float]:
    listings = [item for item in load_listings() if item.get("status", "approved") == "approved"]
    listings_by_slug = {str(item.get("slug", "")): item for item in listings}
    users = load_users()
    profiles = load_seller_profiles()
    reviews = load_reviews()

    details: list[dict[str, Any]] = []
    subtotal = 0.0
    cleaned_cart: list[dict[str, Any]] = []
    for row in get_cart_items():
        slug = str(row.get("slug", ""))
        qty = int(row.get("qty", 1) or 1)
        listing = listings_by_slug.get(slug)
        if listing is None:
            continue
        cleaned_cart.append({"slug": slug, "qty": qty})
        enriched = enrich_listing_with_seller(listing, users, profiles, reviews)
        unit_price = parse_price_value(enriched.get("price"))
        line_total = (unit_price or 0.0) * qty if unit_price is not None else None
        if line_total is not None:
            subtotal += line_total
        details.append(
            {
                "slug": slug,
                "qty": qty,
                "listing": enriched,
                "unit_price_value": unit_price,
                "unit_price_label": format_naira(unit_price) if unit_price is not None else str(enriched.get("price", "N/A")),
                "line_total_value": line_total,
                "line_total_label": format_naira(line_total) if line_total is not None else "N/A",
            }
        )
    if cleaned_cart != get_cart_items():
        set_cart_items(cleaned_cart)
    return details, subtotal


def find_order_by_id(order_id: int, orders: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((item for item in orders if int(item.get("id", 0)) == order_id), None)


def paystack_secret_key(settings: dict[str, Any]) -> str:
    env_key = os.environ.get("PAYSTACK_SECRET_KEY", "").strip()
    if env_key:
        return env_key
    api_keys = settings.get("api_keys", {})
    if isinstance(api_keys, dict):
        return str(api_keys.get("payments", "")).strip()
    return ""


def create_backup_snapshot() -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    snapshot_dir = BACKUP_DIR / f"snapshot-{timestamp}"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    for path in DATA_DIR.glob("*.json"):
        shutil.copy2(path, snapshot_dir / path.name)
    return snapshot_dir


def restore_latest_backup() -> bool:
    backups = sorted([p for p in BACKUP_DIR.glob("snapshot-*") if p.is_dir()])
    if not backups:
        return False
    latest = backups[-1]
    for path in latest.glob("*.json"):
        shutil.copy2(path, DATA_DIR / path.name)
    return True


def migrate_existing_listing_images_to_folders() -> None:
    ensure_upload_structure()
    listings = load_listings()
    changed = False
    sample_default = ADS_UPLOAD_ROOT / "sample-default.webp"

    for item in listings:
        slug = item.get("slug", "")
        category = item.get("category", "")
        if not slug:
            continue
        listing_folder = listing_folder_for(category, slug)
        listing_folder.mkdir(parents=True, exist_ok=True)
        current_image = str(item.get("image", "")).strip()
        target_file = listing_folder / DEFAULT_IMAGE_NAME
        expected_prefix = f"uploads/new/listings/{slugify(category)}/{slug}/"
        if current_image.startswith(expected_prefix):
            continue

        src_file: Path | None = None
        if current_image.startswith("uploads/"):
            candidate = public_path_to_file(current_image)
            if candidate.exists() and candidate.is_file():
                src_file = candidate

        if src_file is not None:
            ext = src_file.suffix.lower() if src_file.suffix.lower() in ALLOWED_IMAGE_EXTENSIONS else ".webp"
            target_file = listing_folder / f"image{ext}"
            if not target_file.exists():
                shutil.copy2(src_file, target_file)
        elif not target_file.exists() and sample_default.exists():
            shutil.copy2(sample_default, target_file)

        new_public = file_to_public_path(target_file)
        if item.get("image") != new_public:
            item["image"] = new_public
            changed = True

    if changed:
        save_listings(listings)


@app.before_request
def enforce_session_integrity() -> None:
    exempt = {"static", "login", "register", "forgot_password"}
    if request.endpoint in exempt:
        return
    username = session.get("username")
    if not username:
        return
    user = get_current_user_record()
    if not user:
        session.clear()
        return
    if user.get("session_version", 1) != session.get("session_version", 1):
        session.clear()


@app.context_processor
def inject_globals() -> dict[str, Any]:
    settings = load_settings()
    user = get_current_user_record()
    return {
        "site_name": settings.get("site_name", "SILK ROAD"),
        "logo_path": settings.get("logo_path", "frontend/images/silk-road-logo.png"),
        "current_user": session.get("username"),
        "current_user_role": (user or {}).get("role", ""),
        "is_authenticated": bool(session.get("username")),
        "is_admin": bool(user and user.get("role") == "admin"),
        "google_auth_enabled": google_oauth_enabled(),
        "cart_count": cart_item_count(),
        "theme_default": "dark" if settings.get("dark_mode", True) else "light",
    }


@app.get("/")
def home() -> str:
    listings = [item for item in load_listings() if item.get("status", "approved") == "approved"]
    users = load_users()
    profiles = load_seller_profiles()
    reviews = load_reviews()
    enriched = [enrich_listing_with_seller(item, users, profiles, reviews) for item in listings]
    featured = [item for item in enriched if item.get("featured")][:8]
    categories = all_categories(listings)
    locations = sorted({str(item.get("location", "")).strip() for item in listings if str(item.get("location", "")).strip()})
    category_cards = [
        {
            "name": category,
            "icon": CATEGORY_ICONS.get(category, "workspace-100.png"),
            "count": len([item for item in listings if item["category"] == category]),
        }
        for category in categories
    ]
    return render_template(
        "home.html",
        active_page="home",
        featured=featured,
        categories=categories,
        category_cards=category_cards,
        locations=locations,
    )


@app.get("/listings")
def listings_page() -> str:
    listings = [item for item in load_listings() if item.get("status", "approved") == "approved"]
    query = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    location = request.args.get("location", "").strip()
    min_price = request.args.get("min_price", "").strip()
    max_price = request.args.get("max_price", "").strip()
    date_posted = request.args.get("date_posted", "").strip()
    filtered = filter_listings(listings, query, category, location, min_price, max_price, date_posted)
    users = load_users()
    profiles = load_seller_profiles()
    reviews = load_reviews()
    enriched_filtered = [enrich_listing_with_seller(item, users, profiles, reviews) for item in filtered]
    locations = sorted({str(item.get("location", "")).strip() for item in listings if str(item.get("location", "")).strip()})
    return render_template(
        "listings.html",
        active_page="listings",
        listings=enriched_filtered,
        categories=all_categories(listings),
        locations=locations,
        query=query,
        selected_category=category,
        selected_location=location,
        min_price=min_price,
        max_price=max_price,
        selected_date_posted=date_posted,
    )


@app.get("/listing/<slug>")
def listing_detail(slug: str) -> str:
    listings = load_listings()
    listing = find_listing_by_slug(listings, slug)
    if listing is None:
        abort(404)
    if listing.get("status", "approved") != "approved" and not is_admin_user():
        abort(404)
    users = load_users()
    profiles = load_seller_profiles()
    reviews = load_reviews()
    messages = load_messages()
    enriched = enrich_listing_with_seller(listing, users, profiles, reviews)
    seller_username = enriched["seller_username"]

    summary = seller_reviews_summary(seller_username, reviews)
    similar_ads = [
        enrich_listing_with_seller(item, users, profiles, reviews)
        for item in listings
        if item.get("slug") != slug
        and item.get("status", "approved") == "approved"
        and item.get("category") == listing.get("category")
    ][:4]

    chat_messages: list[dict[str, Any]] = []
    current = session.get("username")
    if current:
        if current.lower() == seller_username.lower():
            chat_messages = [
                msg
                for msg in messages
                if msg.get("listing_slug") == slug
                and (msg.get("sender", "").lower() == seller_username.lower() or msg.get("recipient", "").lower() == seller_username.lower())
            ]
        else:
            participants = {current.lower(), seller_username.lower()}
            chat_messages = [
                msg
                for msg in messages
                if msg.get("listing_slug") == slug
                and msg.get("sender", "").lower() in participants
                and msg.get("recipient", "").lower() in participants
            ]
    chat_messages = sorted(chat_messages, key=lambda x: str(x.get("created_at", "")))[-30:]

    return render_template(
        "detail.html",
        active_page="detail",
        listing=enriched,
        seller_reviews=summary["items"][:6],
        seller_rating=summary["avg"],
        seller_reviews_count=summary["count"],
        chat_messages=chat_messages,
        similar_ads=similar_ads,
    )


@app.post("/cart/add/<slug>")
@login_required
def cart_add(slug: str) -> Any:
    listings = [item for item in load_listings() if item.get("status", "approved") == "approved"]
    listing = find_listing_by_slug(listings, slug)
    if listing is None:
        abort(404)

    try:
        qty = int(request.form.get("qty", "1") or 1)
    except ValueError:
        qty = 1
    qty = max(1, min(99, qty))

    cart = get_cart_items()
    existing = next((item for item in cart if item.get("slug") == slug), None)
    if existing:
        existing["qty"] = max(1, min(99, int(existing.get("qty", 1) or 1) + qty))
    else:
        cart.append({"slug": slug, "qty": qty})
    set_cart_items(cart)
    append_activity("cart_add", f"listing:{slug}", {"qty": qty})
    flash("Added to cart.", "success")
    next_url = request.form.get("next", "").strip()
    if next_url:
        return redirect(next_url)
    return redirect(url_for("cart_page"))


@app.get("/cart")
@login_required
def cart_page() -> str:
    cart_lines, subtotal = build_cart_details()
    return render_template(
        "cart.html",
        active_page="cart",
        cart_lines=cart_lines,
        subtotal=subtotal,
        subtotal_label=format_naira(subtotal),
    )


@app.post("/cart/update/<slug>")
@login_required
def cart_update(slug: str) -> Any:
    cart = get_cart_items()
    row = next((item for item in cart if item.get("slug") == slug), None)
    if row is None:
        flash("Item not found in cart.", "error")
        return redirect(url_for("cart_page"))
    try:
        qty = int(request.form.get("qty", "1") or 1)
    except ValueError:
        qty = 1
    if qty <= 0:
        cart = [item for item in cart if item.get("slug") != slug]
    else:
        row["qty"] = max(1, min(99, qty))
    set_cart_items(cart)
    append_activity("cart_update", f"listing:{slug}", {"qty": qty})
    flash("Cart updated.", "success")
    return redirect(url_for("cart_page"))


@app.post("/cart/remove/<slug>")
@login_required
def cart_remove(slug: str) -> Any:
    cart = get_cart_items()
    cart = [item for item in cart if item.get("slug") != slug]
    set_cart_items(cart)
    append_activity("cart_remove", f"listing:{slug}")
    flash("Item removed from cart.", "success")
    return redirect(url_for("cart_page"))


@app.post("/cart/clear")
@login_required
def cart_clear() -> Any:
    set_cart_items([])
    append_activity("cart_clear", f"user:{session.get('username', 'unknown')}")
    flash("Cart cleared.", "success")
    return redirect(url_for("cart_page"))


@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout_page() -> Any:
    cart_lines, subtotal = build_cart_details()
    if not cart_lines:
        flash("Your cart is empty. Add products before checkout.", "error")
        return redirect(url_for("listings_page"))

    current_user = get_current_user_record() or {}
    profile_email = str(current_user.get("email", "") or "").strip()

    if request.method == "GET":
        return render_template(
            "checkout.html",
            active_page="checkout",
            cart_lines=cart_lines,
            subtotal=subtotal,
            subtotal_label=format_naira(subtotal),
            default_email=profile_email,
        )

    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").strip()
    address = request.form.get("address", "").strip()
    city = request.form.get("city", "").strip()
    notes = request.form.get("notes", "").strip()
    payment_method = request.form.get("payment_method", "paystack").strip().lower()
    allowed_methods = {"paystack", "manual"}
    if payment_method not in allowed_methods:
        payment_method = "manual"

    if len(full_name) < 3 or "@" not in email or len(phone) < 6 or len(address) < 5 or len(city) < 2:
        flash("Please complete all checkout fields correctly.", "error")
        return render_template(
            "checkout.html",
            active_page="checkout",
            cart_lines=cart_lines,
            subtotal=subtotal,
            subtotal_label=format_naira(subtotal),
            default_email=profile_email,
        )

    orders = load_orders()
    order_id = next_id(orders)
    order_ref = f"ORD-{order_id:06d}"
    lines: list[dict[str, Any]] = []
    for line in cart_lines:
        listing = line["listing"]
        lines.append(
            {
                "slug": line["slug"],
                "title": listing.get("title", ""),
                "seller_username": listing.get("seller_username", ""),
                "qty": int(line["qty"]),
                "unit_price_label": line["unit_price_label"],
                "unit_price_value": line["unit_price_value"],
                "line_total_label": line["line_total_label"],
                "line_total_value": line["line_total_value"],
                "image": listing.get("image", ""),
            }
        )
    order = {
        "id": order_id,
        "order_ref": order_ref,
        "buyer_username": session.get("username", ""),
        "customer": {
            "full_name": full_name,
            "email": email,
            "phone": phone,
            "address": address,
            "city": city,
            "notes": notes,
        },
        "items": lines,
        "subtotal": round(subtotal, 2),
        "subtotal_label": format_naira(subtotal),
        "payment_method": payment_method,
        "payment_status": "pending",
        "status": "pending_payment",
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }
    orders.append(order)
    save_orders(orders)

    transactions = load_transactions()
    transactions.append(
        {
            "id": next_id(transactions),
            "order_id": order_id,
            "order_ref": order_ref,
            "buyer": session.get("username", ""),
            "amount": round(subtotal, 2),
            "commission": round(subtotal * (float(load_settings().get("commission_percent", 5.0)) / 100), 2),
            "gateway": payment_method,
            "status": "pending",
            "risk_score": 0.1,
            "created_at": utc_now(),
        }
    )
    save_transactions(transactions)

    set_cart_items([])
    append_activity("order_created", f"order:{order_ref}", {"payment_method": payment_method, "amount": subtotal})

    if payment_method == "paystack":
        return redirect(url_for("paystack_initialize", order_id=order_id))
    flash("Order created. Awaiting manual payment confirmation.", "success")
    return redirect(url_for("order_detail", order_id=order_id))


@app.get("/orders")
@login_required
def orders_page() -> str:
    all_orders = load_orders()
    username = str(session.get("username", "")).lower()
    if is_admin_user():
        visible_orders = list(reversed(all_orders))
    else:
        visible_orders = [item for item in reversed(all_orders) if str(item.get("buyer_username", "")).lower() == username]
    return render_template("orders.html", active_page="orders", orders=visible_orders)


@app.get("/order/<int:order_id>")
@login_required
def order_detail(order_id: int) -> str:
    orders = load_orders()
    order = find_order_by_id(order_id, orders)
    if order is None:
        abort(404)
    current = str(session.get("username", "")).lower()
    if not is_admin_user() and str(order.get("buyer_username", "")).lower() != current:
        abort(404)
    return render_template("order_detail.html", active_page="orders", order=order)


@app.get("/payment/paystack/initialize/<int:order_id>")
@login_required
def paystack_initialize(order_id: int) -> Any:
    orders = load_orders()
    order = find_order_by_id(order_id, orders)
    if order is None:
        abort(404)
    current = str(session.get("username", "")).lower()
    if not is_admin_user() and str(order.get("buyer_username", "")).lower() != current:
        abort(404)
    if str(order.get("payment_method", "")).lower() != "paystack":
        flash("This order is not configured for Paystack.", "error")
        return redirect(url_for("order_detail", order_id=order_id))

    settings = load_settings()
    secret_key = paystack_secret_key(settings)
    if not secret_key:
        flash("Paystack key missing. Set PAYSTACK_SECRET_KEY or Admin payments API key.", "error")
        return redirect(url_for("order_detail", order_id=order_id))

    amount_kobo = int(round(float(order.get("subtotal", 0) or 0) * 100))
    if amount_kobo < 100:
        flash("Invalid order amount for Paystack.", "error")
        return redirect(url_for("order_detail", order_id=order_id))
    customer = order.get("customer", {}) if isinstance(order.get("customer"), dict) else {}
    email = str(customer.get("email", "")).strip().lower()
    if "@" not in email:
        flash("Customer email missing for Paystack checkout.", "error")
        return redirect(url_for("order_detail", order_id=order_id))

    metadata = {
        "order_id": order_id,
        "order_ref": order.get("order_ref", ""),
        "buyer_username": order.get("buyer_username", ""),
    }
    payload = json.dumps(
        {
            "email": email,
            "amount": amount_kobo,
            "currency": "NGN",
            "reference": f"{order.get('order_ref', 'ORD')}-{secrets.token_hex(4)}",
            "callback_url": url_for("paystack_callback", _external=True),
            "metadata": metadata,
        }
    ).encode("utf-8")
    try:
        req = Request(
            PAYSTACK_INITIALIZE_URL,
            data=payload,
            headers={"Authorization": f"Bearer {secret_key}", "Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=20) as resp:
            response_data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        flash("Could not initialize Paystack payment right now.", "error")
        return redirect(url_for("order_detail", order_id=order_id))

    if not response_data.get("status"):
        flash(str(response_data.get("message", "Paystack initialization failed.")), "error")
        return redirect(url_for("order_detail", order_id=order_id))

    data = response_data.get("data", {}) if isinstance(response_data.get("data"), dict) else {}
    auth_url = str(data.get("authorization_url", "")).strip()
    reference = str(data.get("reference", "")).strip()
    if not auth_url or not reference:
        flash("Paystack did not return a valid payment URL.", "error")
        return redirect(url_for("order_detail", order_id=order_id))

    order["paystack_reference"] = reference
    order["payment_status"] = "processing"
    order["status"] = "awaiting_gateway_confirmation"
    order["updated_at"] = utc_now()
    save_orders(orders)
    append_activity("paystack_initialized", f"order:{order.get('order_ref', order_id)}", {"reference": reference})
    return redirect(auth_url)


@app.get("/payment/paystack/callback")
def paystack_callback() -> Any:
    reference = request.args.get("reference", "").strip() or request.args.get("trxref", "").strip()
    if not reference:
        flash("Missing Paystack transaction reference.", "error")
        return redirect(url_for("orders_page"))

    settings = load_settings()
    secret_key = paystack_secret_key(settings)
    if not secret_key:
        flash("Paystack key missing. Contact admin.", "error")
        return redirect(url_for("orders_page"))

    try:
        req = Request(
            f"{PAYSTACK_VERIFY_URL}/{reference}",
            headers={"Authorization": f"Bearer {secret_key}"},
            method="GET",
        )
        with urlopen(req, timeout=20) as resp:
            verify_data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        flash("Could not verify payment right now.", "error")
        return redirect(url_for("orders_page"))

    status_ok = bool(verify_data.get("status"))
    payload = verify_data.get("data", {}) if isinstance(verify_data.get("data"), dict) else {}
    order_id = 0
    metadata = payload.get("metadata", {})
    if isinstance(metadata, dict):
        try:
            order_id = int(metadata.get("order_id", 0) or 0)
        except (TypeError, ValueError):
            order_id = 0

    orders = load_orders()
    order = find_order_by_id(order_id, orders) if order_id else next(
        (item for item in orders if str(item.get("paystack_reference", "")) == reference),
        None,
    )
    if order is None:
        flash("Order was not found for this payment reference.", "error")
        return redirect(url_for("orders_page"))

    order["paystack_reference"] = reference
    order["updated_at"] = utc_now()
    paid = status_ok and str(payload.get("status", "")).lower() == "success"
    if paid:
        order["payment_status"] = "paid"
        order["status"] = "processing"
        flash("Payment successful. Your order is confirmed.", "success")
        append_activity("paystack_payment_success", f"order:{order.get('order_ref', order.get('id'))}", {"reference": reference})
    else:
        order["payment_status"] = "failed"
        order["status"] = "payment_failed"
        flash("Payment failed or was cancelled.", "error")
        append_activity("paystack_payment_failed", f"order:{order.get('order_ref', order.get('id'))}", {"reference": reference})
    save_orders(orders)

    transactions = load_transactions()
    for tx in transactions:
        if int(tx.get("order_id", 0) or 0) == int(order.get("id", 0) or 0):
            tx["status"] = "released" if paid else "failed"
            tx["gateway_reference"] = reference
            tx["updated_at"] = utc_now()
            break
    save_transactions(transactions)
    return redirect(url_for("order_detail", order_id=int(order.get("id", 0))))


@app.post("/listing/<slug>/chat")
@login_required
def send_listing_chat(slug: str) -> Any:
    listings = load_listings()
    listing = find_listing_by_slug(listings, slug)
    if listing is None:
        abort(404)
    users = load_users()
    seller_username = resolve_seller_username(listing, users)
    sender = str(session.get("username", "")).strip()
    message_text = request.form.get("message", "").strip()
    if len(message_text) < 2:
        flash("Please enter a valid message.", "error")
        return redirect(url_for("listing_detail", slug=slug))
    if sender.lower() == seller_username.lower():
        flash("Use your seller dashboard to manage conversations for this listing.", "error")
        return redirect(url_for("listing_detail", slug=slug))

    messages = load_messages()
    messages.append(
        {
            "id": next_id(messages),
            "listing_slug": slug,
            "sender": sender,
            "recipient": seller_username,
            "message": message_text,
            "created_at": utc_now(),
        }
    )
    save_messages(messages)
    append_activity("chat_message_sent", f"listing:{slug}", {"sender": sender, "recipient": seller_username})
    flash("Message sent to seller.", "success")
    return redirect(url_for("listing_detail", slug=slug))


@app.post("/seller/<username>/review")
@login_required
def add_seller_review(username: str) -> Any:
    reviewer = str(session.get("username", "")).strip()
    if reviewer.lower() == username.lower():
        flash("You cannot review yourself.", "error")
        return redirect(url_for("seller_profile", username=username))

    listing_slug = request.form.get("listing_slug", "").strip()
    rating = int(request.form.get("rating", "0") or 0)
    comment = request.form.get("comment", "").strip()
    if rating < 1 or rating > 5:
        flash("Rating must be between 1 and 5.", "error")
        return redirect(url_for("seller_profile", username=username))
    if len(comment) < 4:
        flash("Please add a short review comment.", "error")
        return redirect(url_for("seller_profile", username=username))

    reviews = load_reviews()
    existing = next(
        (
            r
            for r in reviews
            if str(r.get("seller", "")).lower() == username.lower()
            and str(r.get("reviewer", "")).lower() == reviewer.lower()
            and str(r.get("listing_slug", "")) == listing_slug
        ),
        None,
    )
    if existing is None:
        reviews.append(
            {
                "id": next_id(reviews),
                "seller": username,
                "reviewer": reviewer,
                "listing_slug": listing_slug,
                "rating": rating,
                "comment": comment,
                "created_at": utc_now(),
            }
        )
    else:
        existing["rating"] = rating
        existing["comment"] = comment
        existing["created_at"] = utc_now()
    save_reviews(reviews)
    append_activity("seller_review_submitted", f"seller:{username}", {"reviewer": reviewer, "rating": rating})
    flash("Review submitted successfully.", "success")
    return redirect(url_for("seller_profile", username=username))


@app.route("/seller/<username>", methods=["GET", "POST"])
def seller_profile(username: str) -> str:
    users = load_users()
    seller = next((u for u in users if str(u.get("username", "")).lower() == username.lower()), None)
    if seller is None:
        abort(404)

    profiles = load_seller_profiles()
    key = str(seller.get("username", "")).lower()
    profile_data = profiles.get(key, {})
    listings = [item for item in load_listings() if item.get("status", "approved") == "approved"]
    seller_listings = [item for item in listings if resolve_seller_username(item, users).lower() == key]
    reviews = load_reviews()
    summary = seller_reviews_summary(str(seller.get("username", "")), reviews)

    if request.method == "POST":
        if not session.get("username") or (
            str(session.get("username", "")).lower() != key and not is_admin_user()
        ):
            flash("Only the seller or admin can update this profile.", "error")
            return redirect(url_for("seller_profile", username=username))
        profile_data["display_name"] = request.form.get("display_name", "").strip() or str(seller.get("username", ""))
        profile_data["about"] = request.form.get("about", "").strip()
        profile_data["location"] = request.form.get("location", "").strip()
        profile_data["phone"] = request.form.get("phone", "").strip()
        profile_data["joined_at"] = profile_data.get("joined_at") or (seller.get("created_at") or utc_now())
        profiles[key] = profile_data
        save_seller_profiles(profiles)
        append_activity("seller_profile_updated", f"seller:{username}")
        flash("Seller profile updated.", "success")
        return redirect(url_for("seller_profile", username=username))

    profile = {
        "display_name": profile_data.get("display_name") or str(seller.get("username", "")),
        "about": profile_data.get("about") or "Trusted seller on Silk Road marketplace.",
        "location": profile_data.get("location") or "Nigeria",
        "phone": profile_data.get("phone") or "",
        "joined_at": profile_data.get("joined_at") or (seller.get("created_at") or ""),
    }
    return render_template(
        "seller_profile.html",
        active_page="seller-profile",
        seller=seller,
        profile=profile,
        seller_listings=seller_listings[:12],
        seller_reviews=summary["items"][:20],
        seller_rating=summary["avg"],
        seller_reviews_count=summary["count"],
    )


@app.get("/store/<username>")
def store_page(username: str) -> Any:
    return redirect(url_for("seller_profile", username=username))


@app.errorhandler(404)
def not_found(_: Any) -> tuple[str, int]:
    return render_template("404.html", active_page=""), 404


@app.get("/auth/google")
def google_auth_start() -> Any:
    if not google_oauth_enabled():
        flash("Google sign-in is not configured yet.", "error")
        return redirect(url_for("login"))

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    session["google_oauth_state"] = state
    session["google_oauth_nonce"] = nonce

    params = {
        "client_id": os.environ.get("GOOGLE_CLIENT_ID", ""),
        "redirect_uri": google_redirect_uri(),
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "online",
        "prompt": "select_account",
        "state": state,
        "nonce": nonce,
    }
    return redirect(f"{GOOGLE_AUTH_URL}?{urlencode(params)}")


@app.get("/auth/google/callback")
def google_auth_callback() -> Any:
    error = request.args.get("error", "").strip()
    if error:
        flash("Google sign-in was cancelled or failed.", "error")
        return redirect(url_for("login"))

    code = request.args.get("code", "").strip()
    returned_state = request.args.get("state", "").strip()
    expected_state = session.pop("google_oauth_state", "")
    session.pop("google_oauth_nonce", None)
    if not code or not returned_state or returned_state != expected_state:
        flash("Google sign-in validation failed. Please try again.", "error")
        return redirect(url_for("login"))

    token_payload = urlencode(
        {
            "code": code,
            "client_id": os.environ.get("GOOGLE_CLIENT_ID", ""),
            "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET", ""),
            "redirect_uri": google_redirect_uri(),
            "grant_type": "authorization_code",
        }
    ).encode("utf-8")

    try:
        token_req = Request(
            GOOGLE_TOKEN_URL,
            data=token_payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urlopen(token_req, timeout=15) as resp:
            token_data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        flash("Could not complete Google sign-in at the moment.", "error")
        return redirect(url_for("login"))

    access_token = str(token_data.get("access_token", "")).strip()
    if not access_token:
        flash("Google sign-in token was not received.", "error")
        return redirect(url_for("login"))

    try:
        userinfo_req = Request(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            method="GET",
        )
        with urlopen(userinfo_req, timeout=15) as resp:
            profile = json.loads(resp.read().decode("utf-8"))
    except Exception:
        flash("Failed to fetch Google profile.", "error")
        return redirect(url_for("login"))

    email = str(profile.get("email", "")).strip().lower()
    email_verified = bool(profile.get("email_verified", False))
    full_name = str(profile.get("name", "")).strip()
    if not email or not email_verified:
        flash("Google account email is not verified.", "error")
        return redirect(url_for("login"))

    user = create_or_get_google_user(email, full_name)
    if user.get("status") in {"banned", "suspended"}:
        flash("Your account is suspended. Contact admin.", "error")
        return redirect(url_for("login"))

    users = load_users()
    for row in users:
        if int(row.get("id", 0)) == int(user.get("id", 0)):
            row["last_login"] = utc_now()
            row["last_ip"] = request.remote_addr or "unknown"
            break
    save_users(users)

    session["username"] = user["username"]
    session["session_version"] = user.get("session_version", 1)
    session.permanent = True
    append_activity("google_login_success", f"user:{user['username']}")
    flash(f"Signed in with Google as {user['username']}.", "success")
    if user.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("home"))


@app.route("/login", methods=["GET", "POST"])
def login() -> str:
    if request.method == "GET":
        return render_template("login.html", active_page="login")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not username or not password:
        flash("Please enter both username and password.", "error")
        return render_template("login.html", active_page="login"), 400

    users = load_users()
    user = next((item for item in users if item.get("username", "").lower() == username.lower()), None)
    if user is None or not check_password_hash(user.get("password_hash", ""), password):
        append_activity("login_failed", f"user:{username}")
        flash("Invalid username or password.", "error")
        return render_template("login.html", active_page="login"), 401
    if user.get("status") in {"banned", "suspended"}:
        flash("Your account is suspended. Contact admin.", "error")
        append_activity("blocked_login", f"user:{username}", {"status": user.get("status")})
        return render_template("login.html", active_page="login"), 403

    user["last_login"] = utc_now()
    user["last_ip"] = request.remote_addr or "unknown"
    save_users(users)

    session["username"] = user["username"]
    session["session_version"] = user.get("session_version", 1)
    session.permanent = True
    append_activity("login_success", f"user:{user['username']}")
    flash(f"Welcome back, {user['username']}!", "success")
    if user.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("home"))


@app.route("/register", methods=["GET", "POST"])
def register() -> str:
    if request.method == "GET":
        return render_template("register.html", active_page="register")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    if len(username) < 3:
        flash("Username must be at least 3 characters.", "error")
        return render_template("register.html", active_page="register"), 400
    if len(password) < 6:
        flash("Password must be at least 6 characters.", "error")
        return render_template("register.html", active_page="register"), 400
    if password != confirm_password:
        flash("Password confirmation does not match.", "error")
        return render_template("register.html", active_page="register"), 400

    users = load_users()
    if any(item.get("username", "").lower() == username.lower() for item in users):
        flash("Username already exists. Try a different one.", "error")
        return render_template("register.html", active_page="register"), 409

    users.append(
        {
            "id": next_id(users),
            "username": username,
            "password_hash": generate_password_hash(password),
            "role": "seller",
            "status": "active",
            "seller_verified": False,
            "session_version": 1,
            "created_at": utc_now(),
        }
    )
    save_users(users)
    append_activity("user_registered", f"user:{username}")
    flash("Registration successful. Please log in with your new account.", "success")
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password() -> str:
    if request.method == "GET":
        return render_template("forgot_password.html", active_page="forgot-password")

    username = request.form.get("username", "").strip()
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    if not username:
        flash("Please enter your username.", "error")
        return render_template("forgot_password.html", active_page="forgot-password"), 400
    if len(new_password) < 6:
        flash("New password must be at least 6 characters.", "error")
        return render_template("forgot_password.html", active_page="forgot-password"), 400
    if new_password != confirm_password:
        flash("Password confirmation does not match.", "error")
        return render_template("forgot_password.html", active_page="forgot-password"), 400

    users = load_users()
    user = next((item for item in users if item.get("username", "").lower() == username.lower()), None)
    if user is None:
        flash("Username not found.", "error")
        return render_template("forgot_password.html", active_page="forgot-password"), 404
    user["password_hash"] = generate_password_hash(new_password)
    user["session_version"] = int(user.get("session_version", 1)) + 1
    save_users(users)
    append_activity("password_reset", f"user:{username}")
    flash("Password updated successfully. You can now log in.", "success")
    return redirect(url_for("login"))


@app.route("/post-ad", methods=["GET", "POST"])
@login_required
def post_ad() -> str:
    categories = load_categories()
    if request.method == "GET":
        return render_template("post_ad.html", active_page="post-ad", categories=categories)

    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()
    price = request.form.get("price", "").strip()
    location = request.form.get("location", "").strip()
    description = request.form.get("description", "").strip()
    image_file = request.files.get("image_file")
    featured = request.form.get("featured") == "on"

    if len(title) < 4:
        flash("Title must be at least 4 characters.", "error")
        return render_template("post_ad.html", active_page="post-ad", categories=categories), 400
    if category not in categories:
        flash("Please select a valid category.", "error")
        return render_template("post_ad.html", active_page="post-ad", categories=categories), 400
    if len(description) < 10:
        flash("Description must be at least 10 characters.", "error")
        return render_template("post_ad.html", active_page="post-ad", categories=categories), 400
    if not location:
        flash("Please enter a location.", "error")
        return render_template("post_ad.html", active_page="post-ad", categories=categories), 400
    if image_file is None or image_file.filename is None or not image_file.filename.strip():
        flash("Please upload a listing image.", "error")
        return render_template("post_ad.html", active_page="post-ad", categories=categories), 400

    listings = load_listings()
    slug = unique_slug(listings, slugify(title))
    listing_id = next_id(listings)
    ensure_upload_structure()
    listing_folder = listing_folder_for(category, slug)
    listing_folder.mkdir(parents=True, exist_ok=True)

    raw_name = secure_filename(image_file.filename)
    ext = Path(raw_name).suffix.lower()
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        flash("Unsupported image type. Use .jpg, .jpeg, .png, or .webp.", "error")
        return render_template("post_ad.html", active_page="post-ad", categories=categories), 400

    stored_file = listing_folder / f"image{ext}"
    image_file.save(stored_file)
    safe_image = file_to_public_path(stored_file)

    settings = load_settings()
    blacklist = [word.lower() for word in settings.get("blacklist_keywords", [])]
    combined_text = f"{title} {description}".lower()
    flagged = any(word in combined_text for word in blacklist if word.strip())
    status = "pending" if not is_admin_user() else "approved"
    if flagged:
        status = "pending"

    new_item = {
        "id": listing_id,
        "slug": slug,
        "title": title,
        "category": category,
        "price": price or "N/A",
        "location": location,
        "image": safe_image,
        "description": description,
        "featured": featured and is_admin_user(),
        "status": status,
        "flagged": flagged,
        "created_by": session.get("username", "system"),
        "created_at": utc_now(),
    }
    listings.append(new_item)
    save_listings(listings)
    append_activity("listing_created", f"listing:{slug}", {"status": status, "flagged": flagged})

    if flagged:
        reports = load_reports()
        reports.append(
            {
                "id": next_id(reports),
                "type": "listing",
                "target": slug,
                "status": "open",
                "reason": "Automated keyword flagging",
                "created_at": utc_now(),
            }
        )
        save_reports(reports)
        flash("Ad submitted and flagged for admin review.", "success")
    elif status == "pending":
        flash("Ad submitted for admin approval.", "success")
    else:
        flash("Ad posted successfully.", "success")
    return redirect(url_for("listing_detail", slug=slug) if status == "approved" else url_for("listings_page"))


@app.post("/logout")
def logout() -> Any:
    append_activity("logout", f"user:{session.get('username', 'unknown')}")
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.get("/admin")
@admin_required
def admin_dashboard() -> str:
    section = request.args.get("section", "overview")
    listings = load_listings()
    users = load_users()
    transactions = load_transactions()
    reports = load_reports()
    categories = load_categories()
    settings = load_settings()
    announcements = load_announcements()
    promotions = load_promotions()
    activity = list(reversed(load_activity_log()))[:80]

    active_users = len([u for u in users if u.get("status") == "active"])
    approved = [l for l in listings if l.get("status") == "approved"]
    pending = [l for l in listings if l.get("status") == "pending"]
    gross_revenue = sum(float(t.get("amount", 0) or 0) for t in transactions if t.get("status") == "released")
    commission_revenue = sum(float(t.get("commission", 0) or 0) for t in transactions if t.get("status") == "released")
    open_reports = len([r for r in reports if r.get("status") == "open"])
    suspicious_transactions = len([t for t in transactions if float(t.get("risk_score", 0) or 0) >= 0.7])

    category_counts: dict[str, int] = {}
    for listing in approved:
        category_counts[listing["category"]] = category_counts.get(listing["category"], 0) + 1
    top_categories = sorted(category_counts.items(), key=lambda pair: pair[1], reverse=True)[:6]

    total_visits = sum(int(v) for v in settings.get("traffic_sources", {}).values()) or 1
    conversion_rate = round((len(transactions) / total_visits) * 100, 2)

    return render_template(
        "admin.html",
        active_page="admin",
        section=section,
        users=users,
        listings=listings,
        transactions=transactions,
        reports=reports,
        categories=categories,
        settings=settings,
        announcements=announcements,
        promotions=promotions,
        activity=activity,
        analytics={
            "total_users": len(users),
            "active_users": active_users,
            "total_listings": len(listings),
            "approved_listings": len(approved),
            "pending_listings": len(pending),
            "sales_volume": round(gross_revenue, 2),
            "platform_revenue": round(commission_revenue, 2),
            "conversion_rate": conversion_rate,
            "open_reports": open_reports,
            "suspicious_transactions": suspicious_transactions,
            "top_categories": top_categories,
            "traffic_sources": settings.get("traffic_sources", {}),
        },
    )


@app.post("/admin/action")
@admin_required
def admin_action() -> Any:
    scope = request.form.get("scope", "").strip()
    action = request.form.get("action", "").strip()

    if scope == "user":
        users = load_users()
        user_id = int(request.form.get("user_id", "0") or 0)
        user = next((u for u in users if int(u.get("id", 0)) == user_id), None)
        if not user:
            flash("User not found.", "error")
            return redirect(url_for("admin_dashboard", section="users"))

        if action == "ban":
            user["status"] = "banned"
            user["session_version"] = int(user.get("session_version", 1)) + 1
        elif action == "suspend":
            user["status"] = "suspended"
            user["session_version"] = int(user.get("session_version", 1)) + 1
        elif action == "activate":
            user["status"] = "active"
        elif action == "verify_seller":
            user["seller_verified"] = True
        elif action == "unverify_seller":
            user["seller_verified"] = False
        elif action == "force_logout":
            user["session_version"] = int(user.get("session_version", 1)) + 1
        elif action == "reset_password":
            user["password_hash"] = generate_password_hash("Temp12345!")
            user["session_version"] = int(user.get("session_version", 1)) + 1
            flash(f"Temporary password for {user['username']} is Temp12345!", "success")
        elif action == "set_role":
            role = normalize_role(request.form.get("role", "seller"))
            if role in VALID_USER_ROLES:
                user["role"] = role
        elif action == "delete":
            if user.get("username") == session.get("username"):
                flash("You cannot delete your own account while logged in.", "error")
                return redirect(url_for("admin_dashboard", section="users"))
            users = [u for u in users if int(u.get("id", 0)) != user_id]
            save_users(users)
            append_activity("admin_user_delete", f"user:{user_id}")
            flash("User deleted.", "success")
            return redirect(url_for("admin_dashboard", section="users"))

        save_users(users)
        append_activity("admin_user_action", f"user:{user_id}", {"action": action})
        flash("User action applied.", "success")
        return redirect(url_for("admin_dashboard", section="users"))

    if scope == "listing":
        listings = load_listings()
        slug = request.form.get("slug", "").strip()
        listing = next((l for l in listings if l.get("slug") == slug), None)
        if not listing:
            flash("Listing not found.", "error")
            return redirect(url_for("admin_dashboard", section="listings"))

        if action == "approve":
            listing["status"] = "approved"
        elif action == "reject":
            listing["status"] = "rejected"
        elif action == "flag":
            listing["flagged"] = True
            listing["status"] = "pending"
        elif action == "remove_flag":
            listing["flagged"] = False
        elif action == "delete":
            listings = [l for l in listings if l.get("slug") != slug]
            save_listings(listings)
            append_activity("admin_listing_delete", f"listing:{slug}")
            flash("Listing deleted.", "success")
            return redirect(url_for("admin_dashboard", section="listings"))
        elif action == "feature":
            listing["featured"] = True
        elif action == "unfeature":
            listing["featured"] = False
        elif action == "edit":
            new_title = request.form.get("title", listing.get("title", "")).strip()
            new_category = request.form.get("category", listing.get("category", "")).strip()
            new_price = request.form.get("price", listing.get("price", "")).strip()
            new_location = request.form.get("location", listing.get("location", "")).strip()
            new_description = request.form.get("description", listing.get("description", "")).strip()
            if new_title:
                listing["title"] = new_title
            if new_category:
                listing["category"] = new_category
            listing["price"] = new_price or "N/A"
            listing["location"] = new_location
            listing["description"] = new_description

        save_listings(listings)
        append_activity("admin_listing_action", f"listing:{slug}", {"action": action})
        flash("Listing action applied.", "success")
        return redirect(url_for("admin_dashboard", section="listings"))

    if scope == "listings_bulk":
        listings = load_listings()
        selected = request.form.getlist("selected_slugs")
        if not selected:
            selected_text = request.form.get("selected_slugs_text", "").strip()
            if selected_text:
                selected = [item.strip() for item in selected_text.split(",") if item.strip()]
        for listing in listings:
            if listing.get("slug") not in selected:
                continue
            if action == "approve":
                listing["status"] = "approved"
            elif action == "reject":
                listing["status"] = "rejected"
            elif action == "feature":
                listing["featured"] = True
            elif action == "unfeature":
                listing["featured"] = False
        if action == "delete":
            listings = [l for l in listings if l.get("slug") not in selected]
        save_listings(listings)
        append_activity("admin_bulk_listing_action", "listings", {"action": action, "count": len(selected)})
        flash("Bulk listing action applied.", "success")
        return redirect(url_for("admin_dashboard", section="listings"))

    if scope == "category":
        categories = load_categories()
        if action == "create":
            name = request.form.get("name", "").strip()
            if name and name not in categories:
                categories.append(name)
                categories.sort()
                save_categories(categories)
        elif action == "rename":
            old_name = request.form.get("old_name", "").strip()
            new_name = request.form.get("new_name", "").strip()
            if old_name in categories and new_name:
                categories = [new_name if c == old_name else c for c in categories]
                categories = sorted(set(categories))
                listings = load_listings()
                for listing in listings:
                    if listing.get("category") == old_name:
                        listing["category"] = new_name
                save_listings(listings)
                save_categories(categories)
        elif action == "delete":
            name = request.form.get("name", "").strip()
            categories = [c for c in categories if c != name]
            save_categories(categories)
        append_activity("admin_category_action", "categories", {"action": action})
        flash("Category action applied.", "success")
        return redirect(url_for("admin_dashboard", section="listings"))

    if scope == "transaction":
        transactions = load_transactions()
        tx_id = int(request.form.get("tx_id", "0") or 0)
        tx = next((t for t in transactions if int(t.get("id", 0)) == tx_id), None)
        if not tx:
            flash("Transaction not found.", "error")
            return redirect(url_for("admin_dashboard", section="payments"))
        if action in {"hold", "release", "refund", "approve"}:
            tx["status"] = {"hold": "held", "release": "released", "refund": "refunded", "approve": "approved"}[action]
        if action == "mark_suspicious":
            tx["risk_score"] = 0.95
        save_transactions(transactions)
        append_activity("admin_transaction_action", f"tx:{tx_id}", {"action": action})
        flash("Transaction action applied.", "success")
        return redirect(url_for("admin_dashboard", section="payments"))

    if scope == "report":
        reports = load_reports()
        report_id = int(request.form.get("report_id", "0") or 0)
        report = next((r for r in reports if int(r.get("id", 0)) == report_id), None)
        if not report:
            flash("Report not found.", "error")
            return redirect(url_for("admin_dashboard", section="moderation"))
        if action in {"resolve", "dismiss", "escalate"}:
            report["status"] = {"resolve": "resolved", "dismiss": "dismissed", "escalate": "escalated"}[action]
        save_reports(reports)
        append_activity("admin_report_action", f"report:{report_id}", {"action": action})
        flash("Report action applied.", "success")
        return redirect(url_for("admin_dashboard", section="moderation"))

    if scope == "settings":
        settings = load_settings()
        settings["site_name"] = request.form.get("site_name", settings["site_name"]).strip() or settings["site_name"]
        settings["commission_percent"] = float(request.form.get("commission_percent", settings["commission_percent"]) or settings["commission_percent"])
        settings["payment_gateway"] = request.form.get("payment_gateway", settings["payment_gateway"]).strip()
        settings["email_provider"] = request.form.get("email_provider", settings["email_provider"]).strip()
        settings["sms_provider"] = request.form.get("sms_provider", settings["sms_provider"]).strip()
        settings["require_admin_2fa"] = request.form.get("require_admin_2fa") == "on"
        settings["escrow_enabled"] = request.form.get("escrow_enabled") == "on"
        settings["multi_vendor_payout_automation"] = request.form.get("multi_vendor_payout_automation") == "on"
        settings["ai_fraud_detection"] = request.form.get("ai_fraud_detection") == "on"
        settings["newsletter_enabled"] = request.form.get("newsletter_enabled") == "on"
        settings["announcement_enabled"] = request.form.get("announcement_enabled") == "on"
        settings["rate_limit_per_minute"] = int(request.form.get("rate_limit_per_minute", settings["rate_limit_per_minute"]) or settings["rate_limit_per_minute"])

        geo_text = request.form.get("geo_restrictions", "").strip()
        blacklist_text = request.form.get("blacklist_keywords", "").strip()
        settings["geo_restrictions"] = [p.strip() for p in geo_text.split(",") if p.strip()]
        settings["blacklist_keywords"] = [p.strip() for p in blacklist_text.split(",") if p.strip()]
        save_settings(settings)
        append_activity("admin_settings_update", "settings")
        flash("Settings updated.", "success")
        return redirect(url_for("admin_dashboard", section="settings"))

    if scope == "announcement":
        announcements = load_announcements()
        if action == "create":
            title = request.form.get("title", "").strip()
            message = request.form.get("message", "").strip()
            if title and message:
                announcements.append(
                    {
                        "id": next_id(announcements),
                        "title": title,
                        "message": message,
                        "created_at": utc_now(),
                        "created_by": session.get("username", "admin"),
                        "active": True,
                    }
                )
                save_announcements(announcements)
        elif action == "delete":
            item_id = int(request.form.get("announcement_id", "0") or 0)
            announcements = [item for item in announcements if int(item.get("id", 0)) != item_id]
            save_announcements(announcements)
        append_activity("admin_announcement_action", "announcements", {"action": action})
        flash("Announcement action applied.", "success")
        return redirect(url_for("admin_dashboard", section="communication"))

    if scope == "promotion":
        promotions = load_promotions()
        if action == "create":
            code = request.form.get("code", "").strip().upper()
            discount = request.form.get("discount", "").strip()
            banner_text = request.form.get("banner_text", "").strip()
            if code:
                promotions.append(
                    {
                        "id": next_id(promotions),
                        "code": code,
                        "discount": discount or "0",
                        "banner_text": banner_text,
                        "active": True,
                        "created_at": utc_now(),
                    }
                )
                save_promotions(promotions)
        elif action == "delete":
            item_id = int(request.form.get("promotion_id", "0") or 0)
            promotions = [item for item in promotions if int(item.get("id", 0)) != item_id]
            save_promotions(promotions)
        elif action == "toggle":
            item_id = int(request.form.get("promotion_id", "0") or 0)
            for promo in promotions:
                if int(promo.get("id", 0)) == item_id:
                    promo["active"] = not promo.get("active", True)
            save_promotions(promotions)
        append_activity("admin_promotion_action", "promotions", {"action": action})
        flash("Promotion action applied.", "success")
        return redirect(url_for("admin_dashboard", section="marketing"))

    if scope == "backup":
        if action == "create":
            backup_path = create_backup_snapshot()
            append_activity("admin_backup_create", str(backup_path))
            flash(f"Backup created at {backup_path.name}.", "success")
        elif action == "restore_latest":
            restored = restore_latest_backup()
            if restored:
                append_activity("admin_backup_restore", "latest")
                flash("Latest backup restored.", "success")
            else:
                flash("No backups found to restore.", "error")
        return redirect(url_for("admin_dashboard", section="security"))

    flash("Unsupported admin action.", "error")
    return redirect(url_for("admin_dashboard"))


if __name__ == "__main__":
    ensure_data_files()
    initialize_database()
    migrate_existing_listing_images_to_folders()
    app.run(debug=True, host="127.0.0.1", port=5500)
