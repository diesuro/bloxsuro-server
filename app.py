from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for, make_response
import os
import re
import time
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

try:
    import psycopg2
    import psycopg2.extras
except Exception:
    psycopg2 = None


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("ADMIN_SECRET") or secrets.token_hex(32)

# Stronger cookie defaults for admin sessions.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "1").strip() != "0",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")

# Optional comma separated allowed origins, for example:
# ALLOWED_ORIGINS=https://your-render-app.onrender.com,https://yourdomain.com
ALLOWED_ORIGINS = [o.strip().rstrip("/") for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]

# Admin credentials are loaded from Render Environment Variables.
# Add these in Render:
# ADMIN_USER_1 / ADMIN_PASS_1
# ADMIN_USER_2 / ADMIN_PASS_2
ADMIN_USERS = {
    os.environ.get("ADMIN_USER_1", ""): os.environ.get("ADMIN_PASS_1", ""),
    os.environ.get("ADMIN_USER_2", ""): os.environ.get("ADMIN_PASS_2", ""),
}
ADMIN_USERS = {u: p for u, p in ADMIN_USERS.items() if u and p}

DB_DIR = os.environ.get("DB_DIR", ".")
os.makedirs(DB_DIR, exist_ok=True)
SQLITE_DB = os.path.join(DB_DIR, "licenses.db")
DB_INITIALIZED = False
DB_MODE = None

# Lightweight in-memory rate limiter. Works well on a single Render instance.
# For multiple instances, move this to Redis later.
RATE_BUCKETS = {}
LAST_USED_UPDATE_COOLDOWN_MINUTES = int(os.environ.get("LAST_USED_UPDATE_COOLDOWN_MINUTES", "60") or "60")


def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limit(bucket: str, limit: int, seconds: int):
    now = time.time()
    key = f"{bucket}:{client_ip()}"
    attempts = [t for t in RATE_BUCKETS.get(key, []) if now - t < seconds]
    if len(attempts) >= limit:
        RATE_BUCKETS[key] = attempts
        return False
    attempts.append(now)
    RATE_BUCKETS[key] = attempts
    return True


@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none';"
    )
    return response


@app.before_request
def basic_request_protection():
    # Optional origin check for JSON write endpoints.
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and ALLOWED_ORIGINS:
        origin = (request.headers.get("Origin") or "").rstrip("/")
        referer = (request.headers.get("Referer") or "").split("/")[:3]
        referer_origin = "/".join(referer).rstrip("/") if referer else ""
        if origin and origin not in ALLOWED_ORIGINS:
            return jsonify({"ok": False, "error": "Origin blocked"}), 403
        if not origin and referer_origin and referer_origin not in ALLOWED_ORIGINS:
            return jsonify({"ok": False, "error": "Origin blocked"}), 403


def using_postgres():
    return bool(
        DATABASE_URL and
        DATABASE_URL.startswith(("postgresql://", "postgres://")) and
        psycopg2 is not None
    )


def now_utc():
    return datetime.utcnow()


def get_conn():
    if using_postgres():
        try:
            return psycopg2.connect(
                DATABASE_URL,
                cursor_factory=psycopg2.extras.RealDictCursor,
                sslmode="require",
                connect_timeout=6,
            )
        except Exception as e:
            print("Postgres failed, fallback SQLite:", e, flush=True)

    con = sqlite3.connect(SQLITE_DB, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    global DB_INITIALIZED, DB_MODE

    current_mode = "postgres" if using_postgres() else "sqlite"
    if DB_INITIALIZED and DB_MODE == current_mode:
        return

    con = get_conn()
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        license_key TEXT PRIMARY KEY,
        expires TEXT NOT NULL,
        hwid TEXT,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT,
        updated_at TEXT
    )
    """)

    if using_postgres():
        cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS owner TEXT DEFAULT ''")
        cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS last_verified_at TEXT DEFAULT ''")
        cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS verify_count INTEGER NOT NULL DEFAULT 0")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_licenses_hwid ON licenses(hwid)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_licenses_owner ON licenses(owner)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_licenses_active ON licenses(active)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_licenses_expires ON licenses(expires)")
    else:
        try:
            cur.execute("PRAGMA table_info(licenses)")
            cols = [row[1] for row in cur.fetchall()]
            if "owner" not in cols:
                cur.execute("ALTER TABLE licenses ADD COLUMN owner TEXT")
            if "last_verified_at" not in cols:
                cur.execute("ALTER TABLE licenses ADD COLUMN last_verified_at TEXT")
            if "verify_count" not in cols:
                cur.execute("ALTER TABLE licenses ADD COLUMN verify_count INTEGER NOT NULL DEFAULT 0")
        except Exception:
            pass

    con.commit()
    con.close()

    DB_INITIALIZED = True
    DB_MODE = current_mode


def sql_params(query):
    return query.replace("?", "%s") if using_postgres() else query


def db_query(query, args=(), fetchone=False, fetchall=False):
    init_db()
    con = get_conn()
    cur = con.cursor()

    try:
        cur.execute(sql_params(query), args)

        result = None
        if fetchone:
            result = cur.fetchone()
        elif fetchall:
            result = cur.fetchall()

        con.commit()

        if result is None:
            return None
        if fetchone:
            return dict(result)
        return [dict(r) for r in result]
    finally:
        con.close()


def parse_duration(duration: str):
    duration = str(duration).strip().lower().replace(" ", "")
    match = re.fullmatch(r"(\d+)(m|h|d)", duration)
    if not match:
        return None

    value = int(match.group(1))
    unit = match.group(2)

    if value <= 0:
        return None
    if unit == "m" and value <= 10080:
        return timedelta(minutes=value)
    if unit == "h" and value <= 8760:
        return timedelta(hours=value)
    if unit == "d" and value <= 3650:
        return timedelta(days=value)
    return None


def remaining_text(expires):
    try:
        expire_date = datetime.fromisoformat(str(expires))
        seconds = int((expire_date - now_utc()).total_seconds())
        if seconds <= 0:
            return "Expired"

        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60

        if days > 0:
            return f"{days}d {hours}h"
        if hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"
    except Exception:
        return "Unknown"


def key_status(expires, active):
    if not active:
        return "Disabled"
    if remaining_text(expires) == "Expired":
        return "Expired"
    return "Active"


def request_data():
    """Accept JSON, form-data and query-string payloads so older Discord bot builds keep working."""
    merged = {}

    data = request.get_json(silent=True)
    if isinstance(data, dict):
        merged.update(data)

    if request.form:
        merged.update(dict(request.form))

    if request.args:
        merged.update(dict(request.args))

    return merged


def clean_license_key(value):
    """Normalize keys sent by Discord bots or copied from chat messages."""
    raw = str(value or "").strip()
    raw = raw.replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")
    return raw.upper()[:80]


def check_secret_from_request(data):
    # Backward-compatible admin secret support for Discord bots and automation calls.
    # Accept body, query-string and common header/token variants.
    if not ADMIN_SECRET:
        return False

    auth_header = request.headers.get("Authorization", "").strip()
    if auth_header.lower().startswith("bearer "):
        auth_header = auth_header[7:].strip()

    candidates = [
        request.headers.get("X-Admin-Secret", ""),
        request.headers.get("X-Admin-Key", ""),
        request.headers.get("X-API-Key", ""),
        auth_header,
        str(data.get("secret", "")),
        str(data.get("ADMIN_SECRET", "")),
        str(data.get("admin_secret", "")),
        str(data.get("adminSecret", "")),
        str(data.get("token", "")),
        str(data.get("api_key", "")),
        str(data.get("apikey", "")),
    ]

    return any(candidate and secrets.compare_digest(str(candidate), ADMIN_SECRET) for candidate in candidates)


def admin_authenticated():
    return bool(session.get("admin_user"))


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def csrf_valid(data):
    sent = request.headers.get("X-CSRF-Token", "") or str(data.get("csrf", ""))
    saved = session.get("csrf_token", "")
    return bool(sent and saved and secrets.compare_digest(sent, saved))


def admin_required_json(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        data = request_data()

        # Backward compatibility for Discord bot / automation calls:
        # if ADMIN_SECRET is provided, bypass CSRF even if a browser session cookie exists.
        if check_secret_from_request(data):
            return fn(*args, **kwargs)

        if admin_authenticated():
            if not csrf_valid(data):
                return jsonify({"ok": False, "error": "Security token expired. Refresh the panel and try again."}), 403
            return fn(*args, **kwargs)

        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    return wrapper


def make_key():
    return "BLOX-" + secrets.token_hex(8).upper()


def safe_owner(value):
    """Normalize owner values coming from the panel or Discord bot.

    Accepts a raw Discord ID, a Discord mention like <@123>, or a nested object
    such as {"id": "123"}. Returns a compact string safe for storage/display.
    """
    if isinstance(value, dict):
        for key in ("id", "user_id", "discord_id", "discordId", "owner"):
            if value.get(key) is not None:
                value = value.get(key)
                break

    owner = str(value or "").strip()

    # Discord mention format: <@123> or <@!123>. Store only the numeric ID.
    mention = re.fullmatch(r"<@!?(\d{5,32})>", owner)
    if mention:
        owner = mention.group(1)

    return owner[:80]


def find_owner_value(data):
    """Find the Discord owner field without accidentally using unrelated generic IDs."""
    preferred = [
        "owner", "user", "discord", "discord_id", "discordId",
        "discord_user", "discordUser", "discord_user_id", "discordUserId",
        "discordIdInput", "discord_id_input", "customer", "customer_id",
        "member", "member_id", "user_id", "userId", "roblox_user",
    ]

    for name in preferred:
        value = data.get(name)
        if value is not None and str(value).strip() != "":
            return safe_owner(value)

    # Some bots send nested data: {"user": {"id": "..."}} or {"discord": {"id": "..."}}.
    for name in ("user", "discord", "member", "owner"):
        value = data.get(name)
        if isinstance(value, dict):
            found = safe_owner(value)
            if found:
                return found

    # Last-resort compatibility only. Avoid using generic `id` if the payload also
    # contains likely interaction/message IDs.
    if data.get("id") and not any(data.get(k) for k in ("interaction_id", "message_id", "guild_id", "channel_id")):
        return safe_owner(data.get("id"))

    return ""


@app.route("/", methods=["GET"])
def home():
    return redirect(url_for("admin_panel"))


@app.route("/health", methods=["GET"])
def health():
    init_db()
    return jsonify({"ok": True, "online": True, "service": "BLOXSURO License Server", "db_mode": DB_MODE or ("postgres" if using_postgres() else "sqlite")})


@app.route("/verify", methods=["POST"])
def verify():
    init_db()
    if not rate_limit("verify", 90, 60):
        return jsonify({"valid": False, "reason": "Too many requests"}), 429

    data = request_data()
    key = clean_license_key(data.get("key", ""))
    hwid = str(data.get("hwid", "")).strip()

    # Last Used is tracked only by the server.
    # It updates on the first successful verification and then at most once per cooldown window.

    if not key or not hwid:
        return jsonify({"valid": False, "reason": "Missing key or HWID"}), 400
    if len(key) > 80 or len(hwid) > 256:
        return jsonify({"valid": False, "reason": "Invalid request"}), 400

    row = db_query(
        "SELECT license_key, expires, hwid, active, last_verified_at FROM licenses WHERE license_key=?",
        (key,),
        fetchone=True,
    )

    if not row:
        return jsonify({"valid": False, "reason": "Invalid key"})

    expires = row["expires"]
    saved_hwid = row.get("hwid")
    active = int(row.get("active") or 0)

    if active != 1:
        return jsonify({"valid": False, "reason": "Disabled key"})

    try:
        expire_date = datetime.fromisoformat(str(expires))
    except Exception:
        return jsonify({"valid": False, "reason": "Invalid expiration"})

    if now_utc() > expire_date:
        return jsonify({"valid": False, "reason": "Expired key"})

    if saved_hwid and saved_hwid != hwid:
        return jsonify({"valid": False, "reason": "Different computer"})

    now_dt = now_utc()
    now_iso = now_dt.isoformat()

    # Server-only Last Used tracking with cooldown.
    # This keeps the existing app build compatible and prevents repeated watchdog checks from overloading the DB.
    should_track_usage = False
    last_verified_raw = str(row.get("last_verified_at") or "").strip()
    if not last_verified_raw:
        should_track_usage = True
    else:
        try:
            last_verified_dt = datetime.fromisoformat(last_verified_raw)
            elapsed_minutes = (now_dt - last_verified_dt).total_seconds() / 60
            should_track_usage = elapsed_minutes >= LAST_USED_UPDATE_COOLDOWN_MINUTES
        except Exception:
            should_track_usage = True

    if not saved_hwid:
        if should_track_usage:
            db_query(
                "UPDATE licenses SET hwid=?, updated_at=?, last_verified_at=?, verify_count=COALESCE(verify_count,0)+1 WHERE license_key=?",
                (hwid, now_iso, now_iso, key),
            )
        else:
            db_query(
                "UPDATE licenses SET hwid=?, updated_at=? WHERE license_key=?",
                (hwid, now_iso, key),
            )
    elif should_track_usage:
        db_query(
            "UPDATE licenses SET last_verified_at=?, verify_count=COALESCE(verify_count,0)+1 WHERE license_key=?",
            (now_iso, key),
        )

    remaining = expire_date - now_utc()
    return jsonify({
        "valid": True,
        "plan": "Premium",
        "expires": expires,
        "remaining_seconds": int(remaining.total_seconds()),
    })


@app.route("/login", methods=["POST"])
def login():
    if not rate_limit("login", 8, 300):
        return jsonify({"ok": False, "error": "Too many login attempts. Try again later."}), 429

    data = request_data()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not ADMIN_USERS:
        return jsonify({"ok": False, "error": "Admin credentials are not configured on Render."}), 500

    stored_password = ADMIN_USERS.get(username)
    if stored_password and secrets.compare_digest(stored_password, password):
        session.clear()
        session.permanent = True
        session["admin_user"] = username
        session["csrf_token"] = secrets.token_urlsafe(32)
        return jsonify({"ok": True, "user": username, "csrf": session["csrf_token"]})

    return jsonify({"ok": False, "error": "Invalid login"}), 401


@app.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    if request.method == "GET":
        return redirect(url_for("admin_panel"))
    return jsonify({"ok": True})


@app.route("/admin/create", methods=["POST"])
@admin_required_json
def admin_create():
    init_db()
    if not rate_limit("admin_create", 45, 60):
        return jsonify({"ok": False, "error": "Too many create requests"}), 429

    data = request_data()
    duration = str(data.get("duration", "30d")).strip().lower()
    delta = parse_duration(duration)

    if not delta:
        return jsonify({"ok": False, "error": "Invalid duration. Use: 15m, 1h, 7d, 30d"}), 400

    license_key = make_key()
    now = now_utc()
    expires = (now + delta).isoformat()
    created = now.isoformat()

    db_query(
        "INSERT INTO licenses (license_key, expires, hwid, active, created_at, updated_at, owner, last_verified_at, verify_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (license_key, expires, None, 1, created, created, "", "", 0),
    )

    return jsonify({"ok": True, "key": license_key, "expires": expires, "duration": duration})


@app.route("/admin/action", methods=["POST"])
@admin_required_json
def admin_action():
    init_db()
    data = request_data()
    action = str(data.get("action", "")).strip().lower()
    keys = data.get("keys", [])
    duration = str(data.get("duration", "")).strip().lower()

    if isinstance(keys, str):
        keys = [keys]
    keys = [str(k).strip() for k in keys if str(k).strip()]
    keys = list(dict.fromkeys(keys))[:250]

    if not keys:
        return jsonify({"ok": False, "error": "No keys selected"}), 400

    # Backward-compatible aliases used by older bot builds.
    if action in {"renew", "enable_with_time", "reenable_with_time", "re_enable_with_time"}:
        action = "enable_duration"

    allowed = {"disable", "enable", "enable_duration", "reset_hwid", "delete"}
    if action not in allowed:
        return jsonify({"ok": False, "error": "Invalid action"}), 400

    delta = None
    if action == "enable_duration":
        delta = parse_duration(duration)
        if not delta:
            return jsonify({"ok": False, "error": "Choose a valid re-enable time, for example 1h, 7d or 30d"}), 400

    changed = 0
    updated_dt = now_utc()
    updated = updated_dt.isoformat()

    for key in keys:
        if action == "disable":
            db_query("UPDATE licenses SET active=0, updated_at=? WHERE license_key=?", (updated, key))
        elif action == "enable":
            db_query("UPDATE licenses SET active=1, updated_at=? WHERE license_key=?", (updated, key))
        elif action == "enable_duration":
            expires = (updated_dt + delta).isoformat()
            db_query("UPDATE licenses SET active=1, expires=?, updated_at=? WHERE license_key=?", (expires, updated, key))
        elif action == "reset_hwid":
            db_query("UPDATE licenses SET hwid=NULL, updated_at=? WHERE license_key=?", (updated, key))
        elif action == "delete":
            db_query("DELETE FROM licenses WHERE license_key=?", (key,))
        changed += 1

    return jsonify({"ok": True, "action": action, "changed": changed})


@app.route("/admin/list", methods=["POST"])
@admin_required_json
def admin_list():
    init_db()
    rows = db_query(
        "SELECT license_key, expires, hwid, active, owner, created_at, updated_at, last_verified_at, verify_count FROM licenses ORDER BY COALESCE(created_at, updated_at, expires) DESC",
        fetchall=True,
    ) or []

    keys = []
    for row in rows:
        license_key = row["license_key"]
        expires = row["expires"]
        hwid = row.get("hwid")
        active = row.get("active")
        status = key_status(expires, bool(active))
        keys.append({
            "key": license_key,
            "expires": expires,
            "remaining": remaining_text(expires),
            "hwid": hwid or "",
            "owner": row.get("owner") or "",
            "active": bool(active),
            "status": status,
            "created_at": row.get("created_at") or "",
            "updated_at": row.get("updated_at") or "",
            "last_verified_at": row.get("last_verified_at") or "",
            "verify_count": int(row.get("verify_count") or 0),
        })

    return jsonify({"ok": True, "count": len(keys), "keys": keys})


def pick_first(data, names):
    for name in names:
        value = data.get(name)
        if value is not None and str(value).strip() != "":
            return str(value).strip()
    return ""


@app.route("/admin/link-owner", methods=["GET", "POST", "PUT", "PATCH"])
@app.route("/admin/link-owner/", methods=["GET", "POST", "PUT", "PATCH"])
@app.route("/admin/link_owner", methods=["GET", "POST", "PUT", "PATCH"])
@app.route("/admin/link_owner/", methods=["GET", "POST", "PUT", "PATCH"])
@app.route("/admin/linkowner", methods=["GET", "POST", "PUT", "PATCH"])
@app.route("/admin/bind-owner", methods=["GET", "POST", "PUT", "PATCH"])
@app.route("/admin/bind_owner", methods=["GET", "POST", "PUT", "PATCH"])
@app.route("/admin/bind-user", methods=["GET", "POST", "PUT", "PATCH"])
@app.route("/admin/bind_user", methods=["GET", "POST", "PUT", "PATCH"])
@app.route("/admin/link-user", methods=["GET", "POST", "PUT", "PATCH"])
@app.route("/admin/link_user", methods=["GET", "POST", "PUT", "PATCH"])
@admin_required_json
def admin_link_owner():
    init_db()
    data = request_data()

    # Fully backward-compatible Discord owner binding.
    # Accepts JSON, form-data or query params.
    key = clean_license_key(pick_first(data, [
        "key", "license_key", "license", "licenseKey", "licenseKeyInput",
        "license_key_input", "licenseKeyValue", "licenseCode", "code"
    ]))

    owner = find_owner_value(data)

    if not key:
        return jsonify({"ok": False, "error": "Missing key", "received_fields": sorted(list(data.keys()))}), 400
    if len(key) > 80:
        return jsonify({"ok": False, "error": "Invalid key"}), 400

    # Important: do not silently clear owner on bot calls when the owner field is missing.
    # Manual unlink from the panel can still send clear_owner=true.
    clear_owner = str(data.get("clear_owner", "")).strip().lower() in {"1", "true", "yes", "clear"}
    if not owner and not clear_owner:
        return jsonify({
            "ok": False,
            "error": "Missing owner",
            "hint": "Send owner, user, discord_id, discordId or user_id with the Discord ID.",
            "received_fields": sorted(list(data.keys()))
        }), 400

    row = db_query("SELECT license_key, owner FROM licenses WHERE license_key=?", (key,), fetchone=True)
    if not row:
        return jsonify({"ok": False, "error": "Key not found", "key": key, "license_key": key}), 404

    updated_at = now_utc().isoformat()
    db_query("UPDATE licenses SET owner=?, updated_at=? WHERE license_key=?", (owner, updated_at, key))

    updated_row = db_query("SELECT license_key, owner, updated_at FROM licenses WHERE license_key=?", (key,), fetchone=True) or {}
    saved_owner = updated_row.get("owner") or ""

    return jsonify({
        "ok": True,
        "linked": bool(saved_owner),
        "key": updated_row.get("license_key") or key,
        "license_key": updated_row.get("license_key") or key,
        "owner": saved_owner,
        "user": saved_owner,
        "discord_id": saved_owner,
        "updated_at": updated_row.get("updated_at") or updated_at,
    })


@app.route("/admin/key-info", methods=["POST"])
@admin_required_json
def admin_key_info():
    init_db()
    data = request_data()
    key = clean_license_key(data.get("key", ""))

    if not key:
        return jsonify({"ok": False, "error": "Missing key"}), 400

    row = db_query(
        "SELECT license_key, expires, hwid, active, owner, created_at, updated_at, last_verified_at, verify_count FROM licenses WHERE license_key=?",
        (key,),
        fetchone=True,
    )

    if not row:
        return jsonify({"ok": False, "error": "Key not found"}), 404

    return jsonify({
        "ok": True,
        "key": row["license_key"],
        "expires": row["expires"],
        "remaining": remaining_text(row["expires"]),
        "hwid": row.get("hwid") or "",
        "owner": row.get("owner") or "",
        "active": bool(row.get("active")),
        "status": key_status(row["expires"], bool(row.get("active"))),
        "created_at": row.get("created_at") or "",
        "updated_at": row.get("updated_at") or "",
        "last_verified_at": row.get("last_verified_at") or "",
        "verify_count": int(row.get("verify_count") or 0),
    })


@app.route("/admin/search-owner", methods=["POST"])
@admin_required_json
def admin_search_owner():
    init_db()
    data = request_data()
    owner = safe_owner(pick_first(data, ["owner", "user", "discord_id", "discordId", "discord_user_id", "user_id", "id"]))

    if not owner:
        return jsonify({"ok": False, "error": "Missing owner"}), 400

    if using_postgres():
        rows = db_query(
            "SELECT license_key, expires, hwid, active, owner, created_at, updated_at, last_verified_at, verify_count FROM licenses WHERE owner ILIKE ? ORDER BY COALESCE(created_at, updated_at, expires) DESC",
            (f"%{owner}%",),
            fetchall=True,
        ) or []
    else:
        rows = db_query(
            "SELECT license_key, expires, hwid, active, owner, created_at, updated_at, last_verified_at, verify_count FROM licenses WHERE lower(owner) LIKE lower(?) ORDER BY COALESCE(created_at, updated_at, expires) DESC",
            (f"%{owner}%",),
            fetchall=True,
        ) or []

    keys = []
    for row in rows:
        keys.append({
            "key": row["license_key"],
            "expires": row["expires"],
            "remaining": remaining_text(row["expires"]),
            "hwid": row.get("hwid") or "",
            "owner": row.get("owner") or "",
            "active": bool(row.get("active")),
            "status": key_status(row["expires"], bool(row.get("active"))),
            "created_at": row.get("created_at") or "",
            "updated_at": row.get("updated_at") or "",
            "last_verified_at": row.get("last_verified_at") or "",
            "last_used": row.get("last_verified_at") or "",
            "verify_count": int(row.get("verify_count") or 0),
        })

    return jsonify({"ok": True, "count": len(keys), "keys": keys})


STYLE = """
<style>
:root{
  --bg:#020202;
  --bg2:#090909;
  --panel:#0d0d0d;
  --panel2:#151515;
  --panel3:#1d1d1d;
  --line:rgba(255,255,255,.145);
  --line2:rgba(255,255,255,.30);
  --text:#f4f4f4;
  --muted:#a3a3a3;
  --muted2:#737373;
  --accent:#ff3848;
  --accent-soft:rgba(255,56,72,.15);
  --green:#bfffd0;
  --amber:#ffdca8;
  --red:#ff8b95;
  --shadow:0 32px 90px rgba(0,0,0,.60);
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{
  margin:0;
  min-height:100vh;
  color:var(--text);
  font-family:Inter,Segoe UI,Arial,sans-serif;
  background:
    radial-gradient(circle at var(--mx,18%) var(--my,10%), rgba(255,255,255,.105), transparent 26%),
    radial-gradient(circle at 82% 12%, rgba(255,56,72,.10), transparent 20%),
    linear-gradient(135deg,#000 0%,#0b0b0b 44%,#020202 100%);
  background-attachment:fixed;
  overflow-x:hidden;
}
body::before{
  content:"";
  position:fixed;
  inset:-35%;
  background:
    linear-gradient(115deg,transparent 0%,rgba(255,255,255,.052) 48%,transparent 54%),
    radial-gradient(circle at 70% 26%,rgba(255,56,72,.08),transparent 28%);
  transform:translate3d(calc(var(--px,0)*1px),calc(var(--py,0)*1px),0);
  pointer-events:none;
  z-index:-1;
  opacity:.76;
}
*::-webkit-scrollbar{width:10px;height:10px}
*::-webkit-scrollbar-track{background:rgba(255,255,255,.04)}
*::-webkit-scrollbar-thumb{background:rgba(255,255,255,.38);border:2px solid rgba(0,0,0,.38)}
button,input,select{font-family:inherit;border-radius:0}
input,select{
  height:46px;
  border:1px solid var(--line);
  background:rgba(4,4,4,.88);
  color:var(--text);
  padding:0 14px;
  outline:none;
  font-weight:720;
  font-size:14px;
  transition:.16s ease;
}
input::placeholder{color:#737373}
input:focus,select:focus{
  border-color:rgba(255,255,255,.58);
  box-shadow:0 0 0 3px rgba(255,56,72,.10),0 0 30px rgba(255,56,72,.06);
  transform:translateY(-1px);
}
button{
  height:46px;
  border:1px solid rgba(255,255,255,.25);
  background:rgba(255,255,255,.035);
  color:#f5f5f5;
  padding:0 15px;
  font-weight:840;
  font-size:13px;
  cursor:pointer;
  position:relative;
  overflow:hidden;
  letter-spacing:.08px;
  transition:transform .16s cubic-bezier(.2,.8,.2,1),background .16s ease,box-shadow .16s ease,border-color .16s ease,opacity .16s ease,color .16s ease;
}
button::before{
  content:"";
  position:absolute;
  inset:0;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.16),transparent);
  transform:translateX(-130%);
  transition:transform .55s ease;
}
button:hover{background:rgba(255,255,255,.075);border-color:rgba(255,255,255,.56);transform:translateY(-2px);box-shadow:0 18px 45px rgba(0,0,0,.38),0 0 28px rgba(255,56,72,.06)}
button:hover::before{transform:translateX(130%)}
button:disabled{opacity:.46;cursor:wait;transform:none}
.primary{background:#f1f1f1;border-color:#f1f1f1;color:#070707;box-shadow:0 22px 55px rgba(255,255,255,.08)}
.primary:hover{background:#fff;color:#000;border-color:#fff;box-shadow:0 24px 60px rgba(255,255,255,.13),0 0 40px rgba(255,56,72,.08)}
.secondary{border-color:rgba(255,255,255,.18);background:rgba(255,255,255,.035);color:var(--text)}
.danger{border-color:rgba(255,56,72,.32);background:rgba(255,56,72,.04);color:#f5f5f5}
.danger:hover{border-color:rgba(255,56,72,.70);color:#fff;box-shadow:0 18px 45px rgba(0,0,0,.38),0 0 36px rgba(255,56,72,.13)}
.brand{display:flex;align-items:center;gap:16px}
.brand-mark{
  width:64px;height:64px;display:grid;place-items:center;border-radius:0;
  background:linear-gradient(145deg,rgba(255,255,255,.14),rgba(255,255,255,.025));
  border:1px solid rgba(255,255,255,.22);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.10),0 24px 55px rgba(0,0,0,.42),0 0 34px rgba(255,56,72,.08);
  animation:brandFloat 3.6s ease-in-out infinite alternate;
}
@keyframes brandFloat{from{transform:translateY(0)}to{transform:translateY(-5px)}}
.brand-mark img{width:46px;height:46px;object-fit:contain;filter:drop-shadow(0 14px 18px rgba(0,0,0,.42)) grayscale(1) brightness(1.45)}
h1{margin:0;font-size:clamp(34px,3vw,46px);letter-spacing:-.9px;line-height:1;animation:titleFade .45s ease both;text-shadow:0 0 28px rgba(255,255,255,.08)}
@keyframes titleFade{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.muted{color:var(--muted);font-size:14px;margin-top:8px;font-weight:650}
.card{
  background:linear-gradient(180deg,rgba(18,18,18,.94),rgba(7,7,7,.965));
  border:1px solid var(--line);
  border-radius:0;
  padding:22px;
  box-shadow:var(--shadow),inset 0 1px 0 rgba(255,255,255,.045);
  backdrop-filter:blur(18px);
  transition:transform .2s cubic-bezier(.2,.8,.2,1),border-color .2s ease,box-shadow .2s ease;
  position:relative;
  overflow:hidden;
}
.card::after{content:"";position:absolute;inset:0;background:radial-gradient(circle at var(--cardx,50%) var(--cardy,0%),rgba(255,255,255,.08),transparent 34%),radial-gradient(circle at 12% 0%,rgba(255,56,72,.055),transparent 28%);opacity:0;pointer-events:none;transition:opacity .2s ease}
.card:hover{transform:translateY(-2px);border-color:rgba(255,255,255,.34);box-shadow:0 36px 105px rgba(0,0,0,.62),0 0 64px rgba(255,56,72,.055)}
.card:hover::after{opacity:1}
.toast{position:fixed;right:24px;bottom:24px;background:#0f0f0f;border:1px solid rgba(255,255,255,.28);border-radius:0;padding:14px 16px;color:var(--text);font-weight:820;opacity:0;transform:translateY(10px);transition:.18s ease;pointer-events:none;z-index:40;box-shadow:0 22px 60px rgba(0,0,0,.55),0 0 34px rgba(255,56,72,.08)}
.toast.show{opacity:1;transform:translateY(0)}
.tooltip{position:fixed;max-width:540px;background:#101010;color:var(--text);border:1px solid rgba(255,255,255,.26);border-radius:0;padding:10px 12px;font-size:12px;font-weight:760;box-shadow:0 20px 60px rgba(0,0,0,.45);opacity:0;pointer-events:none;transform:translateY(6px);transition:opacity .14s ease,transform .14s ease;z-index:50;word-break:break-all}
.tooltip.show{opacity:1;transform:translateY(0)}
</style>
"""


LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>BLOXSURO Login</title>
<link rel="icon" href="/static/Logo%20Bloxsuro.png">
<meta name="viewport" content="width=device-width, initial-scale=1">
""" + STYLE + """
<style>
.login-wrap{min-height:100vh;display:grid;place-items:center;padding:28px}
.login{width:min(500px,calc(100vw - 34px));animation:loginPop .38s cubic-bezier(.2,.8,.2,1) both;padding:32px}
@keyframes loginPop{from{opacity:0;transform:translateY(18px) scale(.985)}to{opacity:1;transform:translateY(0) scale(1)}}
.login .brand{justify-content:center;align-items:center;margin-bottom:12px;gap:14px}
.login .brand-mark{width:64px;height:64px;flex:0 0 auto}
.login .brand-mark img{width:44px;height:44px}
.login h1{font-size:38px;line-height:1;white-space:nowrap;display:flex;align-items:center;height:64px}
.login .sub{text-align:center;margin:2px 0 28px;color:#b7b7b7}
.login input{width:100%}
label{display:block;margin:15px 0 8px;color:#dfdfdf;font-size:12px;font-weight:820;text-transform:uppercase;letter-spacing:.55px}
.passbox{position:relative;width:100%}.passbox input{padding-right:108px}.textbtn{position:absolute;right:7px;top:7px;height:32px;padding:0 12px;border-color:rgba(255,255,255,.14);background:rgba(255,255,255,.035);font-size:12px;color:#fff}.textbtn:hover{transform:none;background:rgba(255,255,255,.08)}
.btn{width:100%;margin-top:23px}.err{display:none;margin-top:14px;padding:13px;background:rgba(255,56,72,.08);border:1px solid rgba(255,56,72,.28);color:#fff;font-weight:780;font-size:13px}.secure-note{margin-top:18px;padding-top:16px;border-top:1px solid rgba(255,255,255,.08);color:#8f8f8f;font-size:12px;line-height:1.55;font-weight:650;text-align:center}
@media(max-width:520px){.login .brand{gap:12px}.login h1{font-size:32px}.login .brand-mark{width:54px;height:54px}.login .brand-mark img{width:38px;height:38px}}
</style>
</head>
<body>
<div class="login-wrap">
  <div class="card login">
    <div class="brand login-brand">
      <div class="brand-mark"><img src="/static/Logo%20Bloxsuro.png" alt="BLOXSURO Logo"></div>
      <h1>BLOXSURO</h1>
    </div>
    <div class="sub muted">Secure admin panel</div>

    <label>Username</label>
    <input id="username" autocomplete="username" placeholder="Admin username" maxlength="80">

    <label>Password</label>
    <div class="passbox">
      <input id="password" type="password" autocomplete="current-password" placeholder="Admin password">
      <button class="textbtn" onclick="togglePass()" type="button">Show</button>
    </div>

    <button class="btn primary" onclick="login()">Login</button>
    <div id="err" class="err">Invalid login.</div>
    <div class="secure-note">Protected with session cookies, request limits, CSRF validation and security headers.</div>
  </div>
</div>
<script>
function togglePass(){const input=document.getElementById("password");const btn=document.querySelector(".textbtn");const show=input.type==="password";input.type=show?"text":"password";btn.textContent=show?"Hide":"Show"}
async function login(){const err=document.getElementById("err");err.style.display="none";const username=document.getElementById("username").value.trim();const password=document.getElementById("password").value;const res=await fetch("/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username,password})});const data=await res.json();if(data.ok){location.href="/admin";return}err.textContent=data.error||"Invalid login.";err.style.display="block"}
document.addEventListener("keydown",e=>{if(e.key==="Enter")login()});
document.addEventListener("pointermove",event=>{const x=event.clientX/window.innerWidth;const y=event.clientY/window.innerHeight;document.body.style.setProperty("--mx",`${x*100}%`);document.body.style.setProperty("--my",`${y*100}%`);document.body.style.setProperty("--px",`${(x-.5)*18}`);document.body.style.setProperty("--py",`${(y-.5)*18}`)});
</script>
</body>
</html>
"""


ADMIN_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>BLOXSURO Admin</title>
<link rel="icon" href="/static/Logo%20Bloxsuro.png">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="{{ csrf }}">
""" + STYLE + """
<style>
.wrap{width:min(1440px,calc(100vw - 56px));margin:0 auto;padding:38px 0 72px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:28px;margin-bottom:26px;animation:fadeDown .34s ease both}@keyframes fadeDown{from{opacity:0;transform:translateY(-12px)}to{opacity:1;transform:translateY(0)}}.top-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.badge{border:1px solid rgba(255,255,255,.18);background:rgba(16,16,16,.78);color:#fff;padding:13px 18px;font-weight:820;font-size:13px;box-shadow:inset 0 0 30px rgba(255,255,255,.025),0 16px 42px rgba(0,0,0,.18);backdrop-filter:blur(14px)}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-bottom:24px}.stat{padding:20px 22px;min-height:96px;display:flex;flex-direction:column;justify-content:center}.stat .num{font-size:30px;font-weight:920;letter-spacing:-.5px}.stat .label{color:var(--muted);font-size:12px;font-weight:780;margin-top:6px;text-transform:uppercase;letter-spacing:.55px}.stat.active .label{color:var(--green)}.stat.disabled .label{color:var(--red)}.stat.expired .label{color:var(--amber)}.grid{display:grid;grid-template-columns:340px minmax(0,1fr);gap:24px;align-items:start;animation:fadeUp .4s ease both}@keyframes fadeUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}h3{margin:0 0 20px;font-size:20px;letter-spacing:-.2px}.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}.field{display:flex;flex-direction:column;gap:9px;margin-bottom:18px}.field label{font-size:12px;color:#d7d7d7;font-weight:820;text-transform:uppercase;letter-spacing:.55px}.field input,.field select{width:100%}.stack{display:flex;flex-direction:column;gap:20px}.toolbar{display:grid;grid-template-columns:minmax(320px,1fr) 150px 180px 112px 96px 104px;gap:12px;align-items:center;margin-bottom:18px}.toolbar input,.toolbar select,.toolbar button{width:100%}.tablewrap{overflow:auto;max-height:650px;border:1px solid rgba(255,255,255,.12);background:rgba(7,7,7,.84);box-shadow:inset 0 0 42px rgba(0,0,0,.22)}table{width:100%;border-collapse:collapse;min-width:1180px;table-layout:fixed}th,td{text-align:left;padding:13px 14px;border-bottom:1px solid rgba(255,255,255,.075);font-size:13px;vertical-align:middle;overflow:hidden;text-overflow:ellipsis}th{color:var(--muted);background:rgba(13,13,13,.98);position:sticky;top:0;z-index:2;backdrop-filter:blur(10px);font-size:11px;text-transform:uppercase;letter-spacing:.6px}tr{transition:background .16s ease,transform .16s ease}tbody tr:hover td{background:rgba(255,255,255,.045)}code{color:#f2f2f2;font-weight:880;letter-spacing:.2px}.col-check{width:48px}.col-key{width:350px}.col-status{width:118px}.col-remain{width:108px}.col-owner{width:145px}.col-hwid{width:160px}.col-used{width:150px}.col-expires{width:145px}.hwid{white-space:nowrap;color:#c7c7c7}.owner{color:#f5f5f5;font-weight:780;font-family:Consolas,monospace;white-space:nowrap;cursor:pointer}.owner:hover{color:#fff;text-decoration:underline;text-decoration-color:var(--accent)}.check{width:17px;height:17px;accent-color:#f2f2f2;min-width:0;display:block;margin:0 auto}.pill{display:inline-block;padding:6px 10px;font-size:12px;font-weight:880;background:#171717;border:1px solid rgba(255,255,255,.13);min-width:76px;text-align:center}.ok{color:var(--green);border-color:rgba(191,255,208,.22);background:rgba(191,255,208,.035)}.warn{color:var(--amber);border-color:rgba(255,220,168,.22);background:rgba(255,220,168,.035)}.bad{color:var(--red);border-color:rgba(255,139,149,.24);background:rgba(255,56,72,.045)}.keycell{display:flex;align-items:center;gap:14px;min-width:0;width:100%}.key-code-wrap{min-width:0;flex:1;display:flex;flex-direction:column;justify-content:center}.keycell code{display:block;white-space:nowrap;line-height:1.2;word-break:normal;overflow:hidden;text-overflow:ellipsis;max-width:100%;font-size:13px}.copybtn{height:34px;min-width:58px;width:58px;padding:0 10px;font-size:11px;color:var(--text);border-color:rgba(255,255,255,.14);background:#111;flex:0 0 58px}.copybtn:hover{border-color:rgba(255,255,255,.56);color:#fff}.small{height:46px;font-size:12px}.logout{color:var(--text);border-color:rgba(255,255,255,.14)}.action-grid{display:grid;grid-template-columns:1fr;gap:12px}.action-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.help{font-size:12px;line-height:1.55;color:#929292;font-weight:650;margin-top:14px}.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.68);backdrop-filter:blur(8px);display:none;align-items:center;justify-content:center;z-index:60;padding:22px}.modal-backdrop.show{display:flex}.modal{width:min(520px,100%);animation:modalPop .2s ease both}@keyframes modalPop{from{opacity:0;transform:translateY(14px) scale(.985)}to{opacity:1;transform:translateY(0) scale(1)}}.modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:18px}.modal .field{margin-top:16px;margin-bottom:0}.modal input{width:100%}.progress{height:3px;background:rgba(255,255,255,.08);overflow:hidden;margin-top:14px}.progress span{display:block;height:100%;width:0;background:linear-gradient(90deg,#fff,var(--accent));transition:width .24s ease}.datecell{color:#b8b8b8;font-size:12px;line-height:1.3}.used-note{color:#777;font-size:11px;margin-top:2px}.empty{padding:28px;text-align:center;color:var(--muted);font-weight:760}.created-note{font-size:11px;color:#777;margin-top:5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.accentline{height:1px;background:linear-gradient(90deg,transparent,rgba(255,56,72,.45),transparent);margin:18px 0}@media(max-width:1200px){.grid{grid-template-columns:1fr}.wrap{width:min(100% - 32px,1080px);padding:28px 0 44px}.toolbar{grid-template-columns:1fr 150px 180px}.toolbar .small{min-width:0}.stats{grid-template-columns:repeat(2,1fr)}}@media(max-width:640px){.stats{grid-template-columns:1fr}.topbar{align-items:flex-start;flex-direction:column}.top-actions{width:100%}.top-actions>*{flex:1}.brand-mark{width:56px;height:56px}.brand-mark img{width:38px;height:38px}.toolbar{grid-template-columns:1fr}.action-row{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <div>
      <div class="brand">
        <div class="brand-mark"><img src="/static/Logo%20Bloxsuro.png" alt="BLOXSURO Logo"></div>
        <h1>BLOXSURO Admin</h1>
      </div>
      <div class="muted">License management, device binding and controlled access</div>
    </div>
    <div class="top-actions">
      <div class="badge" id="counter">Loading</div>
      <button class="logout" onclick="logout()">Logout</button>
    </div>
  </div>

  <div class="stats">
    <div class="card stat"><div class="num" id="statTotal">0</div><div class="label">Total Keys</div></div>
    <div class="card stat active"><div class="num" id="statActive">0</div><div class="label">Active</div></div>
    <div class="card stat disabled"><div class="num" id="statDisabled">0</div><div class="label">Disabled</div></div>
    <div class="card stat expired"><div class="num" id="statExpired">0</div><div class="label">Expired</div></div>
  </div>

  <div class="grid">
    <div class="stack">
      <div class="card">
        <h3>Create License</h3>
        <div class="field"><label>Duration</label><input id="duration" value="30d" placeholder="15m, 1h, 7d, 30d"></div>
        <button class="primary" id="createBtn" onclick="createKey()">Create License</button>
        <div class="help">Creates an unlinked license. Discord ownership is assigned by the bot after the customer links their ID.</div>
        <div class="help">Accepted units: minutes, hours and days. Examples: 15m, 1h, 7d, 30d.</div>
      </div>

      <div class="card">
        <h3>Selected License Operations</h3>
        <div class="field"><label>Renewal Duration</label><input id="reenableDuration" value="30d" placeholder="1h, 7d, 30d"></div>
        <div class="action-grid">
          <button class="primary" onclick="bulkAction('enable_duration')">Renew Access</button>
          <div class="action-row">
            <button class="secondary" onclick="bulkAction('reset_hwid')">Reset HWID</button>
            <button class="secondary" onclick="bulkAction('disable')">Disable Access</button>
          </div>
          <button class="danger" onclick="bulkAction('delete')">Delete Selected</button>
        </div>
        <div class="accentline"></div>
        <div class="help">Renew Access activates selected licenses and sets expiration to now plus the duration above.</div><div class="help">Last Used is tracked by the server with a 60 minute cooldown.</div>
      </div>
    </div>

    <div>
      <div class="card">
        <h3>Licenses</h3>
        <div class="toolbar">
          <input id="search" placeholder="Search key, owner or HWID" oninput="debouncedRender()">
          <select id="filter" onchange="renderKeys()">
            <option value="all">All Status</option>
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
            <option value="expired">Expired</option>
            <option value="bound">Bound HWID</option>
            <option value="unbound">Unbound</option>
          </select>
          <select id="sort" onchange="renderKeys()">
            <option value="created_desc">Newest Created</option>
            <option value="created_asc">Oldest Created</option>
            <option value="expires_desc">Latest Expiration</option>
            <option value="expires_asc">Soonest Expiration</option>
            <option value="status">Status</option>
          </select>
          <button class="secondary small" id="revealBtn" onclick="toggleRevealKeys()">Show Keys</button>
          <button class="secondary small" onclick="clearFilters()">Clear</button>
          <button class="secondary small" id="refreshBtn" onclick="loadKeys()">Refresh</button>
        </div>
        <div class="tablewrap">
          <table>
            <colgroup>
              <col class="col-check">
              <col class="col-key">
              <col class="col-status">
              <col class="col-remain">
              <col class="col-owner">
              <col class="col-hwid">
              <col class="col-used">
              <col class="col-expires">
            </colgroup>
            <thead>
              <tr>
                <th class="col-check"><input class="check" type="checkbox" id="selectAll" onchange="toggleAll()"></th>
                <th class="col-key">Key</th>
                <th class="col-status">Status</th>
                <th class="col-remain">Remaining</th>
                <th class="col-owner">Owner</th>
                <th class="col-hwid">HWID</th>
                <th class="col-used">Last Used</th>
                <th class="col-expires">Expires</th>
              </tr>
            </thead>
            <tbody id="keys"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</div>

<div id="confirmModal" class="modal-backdrop">
  <div class="card modal">
    <h3 id="modalTitle">Confirm Action</h3>
    <div class="muted" id="modalText">Review the action before continuing.</div>
    <div class="progress"><span id="modalProgress"></span></div>
    <div class="modal-actions">
      <button class="secondary" onclick="closeModal()">Cancel</button>
      <button class="primary" id="modalConfirm">Confirm</button>
    </div>
  </div>
</div>

<div id="ownerModal" class="modal-backdrop">
  <div class="card modal">
    <h3>Update Owner</h3>
    <div class="muted">Manual correction only. Normal owner linking should be handled by the Discord bot.</div>
    <div class="field">
      <label>Discord Owner ID</label>
      <input id="ownerEditInput" placeholder="Discord ID or leave empty to unlink">
    </div>
    <div class="modal-actions">
      <button class="secondary" onclick="closeOwnerModal()">Cancel</button>
      <button class="primary" onclick="saveOwnerEdit()">Save Owner</button>
    </div>
  </div>
</div>

<div id="toast" class="toast">Ready.</div>
<div id="tooltip" class="tooltip"></div>

<script>
let allKeys=[];let loading=false;let renderTimer=null;let revealKeys=false;let pendingAction=null;let pendingOwnerKey=null;
const csrf=document.querySelector('meta[name="csrf-token"]').content;
document.addEventListener("pointermove",event=>{const x=event.clientX/window.innerWidth;const y=event.clientY/window.innerHeight;document.body.style.setProperty("--mx",`${x*100}%`);document.body.style.setProperty("--my",`${y*100}%`);document.body.style.setProperty("--px",`${(x-.5)*18}`);document.body.style.setProperty("--py",`${(y-.5)*18}`);const card=event.target.closest?.(".card");if(card){const rect=card.getBoundingClientRect();card.style.setProperty("--cardx",`${((event.clientX-rect.left)/rect.width)*100}%`);card.style.setProperty("--cardy",`${((event.clientY-rect.top)/rect.height)*100}%`)}});
function toast(message){const el=document.getElementById("toast");el.textContent=message;el.classList.add("show");clearTimeout(window.__toastTimer);window.__toastTimer=setTimeout(()=>el.classList.remove("show"),2400)}
function tooltip(event,text){const el=document.getElementById("tooltip");el.textContent=text||"";el.style.left=Math.min(event.clientX+14,window.innerWidth-540)+"px";el.style.top=(event.clientY+16)+"px";el.classList.add("show")}
function hideTooltip(){document.getElementById("tooltip").classList.remove("show")}
async function postJSON(url,payload){const res=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(payload||{})});if(res.status===401){location.href="/admin";return{ok:false,error:"Unauthorized"}}let data={};try{data=await res.json()}catch(e){data={ok:false,error:"Invalid server response"}}if(!data.ok&&data.error)toast(data.error);return data}
async function createKey(){if(loading)return;const btn=document.getElementById("createBtn");const duration=document.getElementById("duration").value.trim();loading=true;btn.disabled=true;setProgress(35);const data=await postJSON("/admin/create",{duration});setProgress(75);if(data.ok){toast("License created");await loadKeys(false);if(data.key)copyText(data.key,"Created key copied")}setProgress(100);setTimeout(()=>setProgress(0),420);btn.disabled=false;loading=false}
function selectedKeys(){return Array.from(document.querySelectorAll(".keyCheck:checked")).map(x=>x.value)}
function actionLabel(action){return {enable_duration:"Renew Access",disable:"Disable Access",reset_hwid:"Reset HWID",delete:"Delete Selected"}[action]||action}
function bulkAction(action){const keys=selectedKeys();if(keys.length===0){toast("No licenses selected");return}const duration=document.getElementById("reenableDuration").value.trim();let text=`${actionLabel(action)} will affect ${keys.length} selected license(s).`;if(action==="enable_duration")text+=` New duration: ${duration}.`;if(action==="delete")text+=" This cannot be undone.";pendingAction={action,keys,duration};document.getElementById("modalTitle").textContent=actionLabel(action);document.getElementById("modalText").textContent=text;document.getElementById("modalConfirm").onclick=confirmPendingAction;document.getElementById("confirmModal").classList.add("show")}
function closeModal(){document.getElementById("confirmModal").classList.remove("show");pendingAction=null;setProgress(0)}
function setProgress(v){const el=document.getElementById("modalProgress");if(el)el.style.width=v+"%"}
async function confirmPendingAction(){if(!pendingAction||loading)return;loading=true;setProgress(30);const data=await postJSON("/admin/action",pendingAction);setProgress(78);if(data.ok){toast(`${data.changed} license(s) updated`);await loadKeys(false)}setProgress(100);setTimeout(closeModal,280);loading=false}
function toggleAll(){const checked=document.getElementById("selectAll").checked;document.querySelectorAll(".keyCheck").forEach(cb=>cb.checked=checked)}
function statusClass(status){if(status==="Active")return"ok";if(status==="Expired")return"warn";return"bad"}
function baseFiltered(){const q=document.getElementById("search").value.toLowerCase().trim();const f=document.getElementById("filter").value;return allKeys.filter(item=>{const hay=`${item.key} ${item.hwid||""} ${item.owner||""} ${item.status}`.toLowerCase();if(q&&!hay.includes(q))return false;if(f==="active"&&item.status!=="Active")return false;if(f==="disabled"&&item.status!=="Disabled")return false;if(f==="expired"&&item.status!=="Expired")return false;if(f==="bound"&&!item.hwid)return false;if(f==="unbound"&&item.hwid)return false;return true})}
function timeValue(v){const t=Date.parse(v||"");return Number.isFinite(t)?t:0}
function filteredKeys(){const sort=document.getElementById("sort").value;const arr=baseFiltered().slice();arr.sort((a,b)=>{if(sort==="created_asc")return timeValue(a.created_at||a.updated_at||a.expires)-timeValue(b.created_at||b.updated_at||b.expires);if(sort==="expires_desc")return timeValue(b.expires)-timeValue(a.expires);if(sort==="expires_asc")return timeValue(a.expires)-timeValue(b.expires);if(sort==="status")return String(a.status).localeCompare(String(b.status));return timeValue(b.created_at||b.updated_at||b.expires)-timeValue(a.created_at||a.updated_at||a.expires)});return arr}
function debouncedRender(){clearTimeout(renderTimer);renderTimer=setTimeout(renderKeys,80)}
function escapeHtml(value){return String(value??"").replace(/[&<>"']/g,s=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[s]))}
function maskKey(key){const raw=String(key||"");if(raw.length<=10)return "****";const prefix=raw.startsWith("BLOX-")?"BLOX":raw.slice(0,4);return prefix+"-********-"+raw.slice(-4)}
function toggleRevealKeys(){revealKeys=!revealKeys;document.getElementById("revealBtn").textContent=revealKeys?"Hide Keys":"Show Keys";renderKeys()}
function clearFilters(){document.getElementById("search").value="";document.getElementById("filter").value="all";document.getElementById("sort").value="created_desc";renderKeys()}
function updateStats(keys){const total=keys.length;const active=keys.filter(k=>k.status==="Active").length;const disabled=keys.filter(k=>k.status==="Disabled").length;const expired=keys.filter(k=>k.status==="Expired").length;document.getElementById("statTotal").textContent=total;document.getElementById("statActive").textContent=active;document.getElementById("statDisabled").textContent=disabled;document.getElementById("statExpired").textContent=expired}
function compactDate(value){if(!value)return"Never";const d=new Date(value);if(Number.isNaN(d.getTime()))return value;const yy=String(d.getFullYear()).slice(2);const mm=String(d.getMonth()+1).padStart(2,"0");const dd=String(d.getDate()).padStart(2,"0");const hh=String(d.getHours()).padStart(2,"0");const mi=String(d.getMinutes()).padStart(2,"0");return `${dd}/${mm}/${yy} ${hh}:${mi}`}
function renderKeys(){const tbody=document.getElementById("keys");const keys=filteredKeys();const frag=document.createDocumentFragment();tbody.innerHTML="";document.getElementById("selectAll").checked=false;document.getElementById("counter").textContent=`${allKeys.length} total, ${keys.length} shown`;updateStats(allKeys);if(keys.length===0){tbody.innerHTML='<tr><td colspan="8"><div class="empty">No licenses found</div></td></tr>';return}for(const item of keys){const tr=document.createElement("tr");const fullHwid=item.hwid||"Not bound";const rawKey=String(item.key||"");const safeKey=escapeHtml(rawKey);const displayKey=escapeHtml(revealKeys?rawKey:maskKey(rawKey));const safeHwid=escapeHtml(fullHwid);const safeOwner=escapeHtml(item.owner&&item.owner.trim()?item.owner:"Not linked");const created=compactDate(item.created_at||item.updated_at||"");const verifyCount=Number(item.verify_count||0);const lastUsed=compactDate(item.last_verified_at);const lastUsedText=lastUsed==="Never"?"Never":lastUsed;const usedSub=verifyCount>0?`${verifyCount} check${verifyCount===1?"":"s"}`:"No usage yet";tr.innerHTML=`<td><input class="check keyCheck" type="checkbox" value="${safeKey}"></td><td><div class="keycell" onmousemove="tooltip(event, revealKeys ? '${safeKey}' : 'Key hidden')" onmouseleave="hideTooltip()"><div class="key-code-wrap"><code>${displayKey}</code><div class="created-note">Created ${escapeHtml(created)}</div></div><button class="copybtn" onclick="copyKey(event,'${safeKey}')">Copy</button></div></td><td><span class="pill ${statusClass(item.status)}">${escapeHtml(item.status)}</span></td><td>${escapeHtml(item.remaining)}</td><td class="owner" onclick="openOwnerModal(event,'${safeKey}','${escapeHtml(item.owner||"")}')" onmousemove="tooltip(event,'Owner linked by Discord bot. Click only for manual correction')" onmouseleave="hideTooltip()">${safeOwner}</td><td class="hwid" onmousemove="tooltip(event,'${safeHwid}')" onmouseleave="hideTooltip()">${safeHwid}</td><td class="datecell" onmousemove="tooltip(event,'Total successful tracked uses: ${verifyCount}. Updates once every 60 minutes per license.')" onmouseleave="hideTooltip()">${escapeHtml(lastUsedText)}<div class="used-note">${escapeHtml(usedSub)}</div></td><td class="datecell">${escapeHtml(compactDate(item.expires))}</td>`;frag.appendChild(tr)}tbody.appendChild(frag)}
function openOwnerModal(event,key,currentOwner){event.stopPropagation();pendingOwnerKey=key;const input=document.getElementById("ownerEditInput");input.value=currentOwner||"";document.getElementById("ownerModal").classList.add("show");setTimeout(()=>input.focus(),40)}
function closeOwnerModal(){document.getElementById("ownerModal").classList.remove("show");pendingOwnerKey=null}
async function saveOwnerEdit(){if(!pendingOwnerKey)return;const owner=document.getElementById("ownerEditInput").value.trim();const payload={key:pendingOwnerKey,owner};if(!owner)payload.clear_owner=true;const data=await postJSON("/admin/link-owner",payload);if(data.ok){toast("Owner updated");closeOwnerModal();await loadKeys(false)}}
async function copyText(text,message){try{await navigator.clipboard.writeText(text);toast(message||"Copied")}catch(e){const temp=document.createElement("textarea");temp.value=text;document.body.appendChild(temp);temp.select();document.execCommand("copy");document.body.removeChild(temp);toast(message||"Copied")}}
async function copyKey(event,key){event.stopPropagation();await copyText(key,"Key copied")}
async function loadKeys(showToast=true){if(loading&&showToast)return;const btn=document.getElementById("refreshBtn");if(btn)btn.disabled=true;const data=await postJSON("/admin/list",{});if(data.ok){allKeys=data.keys||[];renderKeys();if(showToast)toast("Licenses refreshed")}if(btn)btn.disabled=false}
async function logout(){await fetch("/logout",{method:"POST",headers:{"X-CSRF-Token":csrf}});location.href="/admin"}
loadKeys();
</script>
</body>
</html>
"""


@app.route("/admin", methods=["GET"])
def admin_panel():
    init_db()
    if not admin_authenticated():
        return render_template_string(LOGIN_HTML)
    return render_template_string(ADMIN_HTML, csrf=csrf_token())


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
