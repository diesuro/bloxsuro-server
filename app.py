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


def check_secret_from_request(data):
    # Backward-compatible admin secret support, now accepted through header first.
    header_secret = request.headers.get("X-Admin-Secret", "")
    body_secret = str(data.get("secret", ""))
    return ADMIN_SECRET and (secrets.compare_digest(header_secret, ADMIN_SECRET) or secrets.compare_digest(body_secret, ADMIN_SECRET))


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
        data = request.get_json(silent=True) or {}
        if admin_authenticated():
            if not csrf_valid(data):
                return jsonify({"ok": False, "error": "Security token expired. Refresh the panel and try again."}), 403
            return fn(*args, **kwargs)
        if check_secret_from_request(data):
            return fn(*args, **kwargs)
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    return wrapper


def make_key():
    return "BLOX-" + secrets.token_hex(8).upper()


def safe_owner(value):
    owner = str(value or "").strip()
    return owner[:80]


@app.route("/", methods=["GET"])
def home():
    return redirect(url_for("admin_panel"))


@app.route("/verify", methods=["POST"])
def verify():
    init_db()
    if not rate_limit("verify", 90, 60):
        return jsonify({"valid": False, "reason": "Too many requests"}), 429

    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip()
    hwid = str(data.get("hwid", "")).strip()

    if not key or not hwid:
        return jsonify({"valid": False, "reason": "Missing key or HWID"}), 400
    if len(key) > 80 or len(hwid) > 256:
        return jsonify({"valid": False, "reason": "Invalid request"}), 400

    row = db_query(
        "SELECT license_key, expires, hwid, active FROM licenses WHERE license_key=?",
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

    if not saved_hwid:
        db_query(
            "UPDATE licenses SET hwid=?, updated_at=?, last_verified_at=?, verify_count=COALESCE(verify_count,0)+1 WHERE license_key=?",
            (hwid, now_utc().isoformat(), now_utc().isoformat(), key),
        )
    else:
        db_query(
            "UPDATE licenses SET last_verified_at=?, verify_count=COALESCE(verify_count,0)+1 WHERE license_key=?",
            (now_utc().isoformat(), key),
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

    data = request.get_json(silent=True) or {}
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

    data = request.get_json(silent=True) or {}
    duration = str(data.get("duration", "30d")).strip().lower()
    owner = safe_owner(data.get("owner", "") or data.get("user", ""))
    delta = parse_duration(duration)

    if not delta:
        return jsonify({"ok": False, "error": "Invalid duration. Use: 15m, 1h, 7d, 30d"}), 400

    license_key = make_key()
    now = now_utc()
    expires = (now + delta).isoformat()
    created = now.isoformat()

    db_query(
        "INSERT INTO licenses (license_key, expires, hwid, active, created_at, updated_at, owner, last_verified_at, verify_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (license_key, expires, None, 1, created, created, owner, "", 0),
    )

    return jsonify({"ok": True, "key": license_key, "expires": expires, "duration": duration, "owner": owner})


@app.route("/admin/action", methods=["POST"])
@admin_required_json
def admin_action():
    init_db()
    data = request.get_json(silent=True) or {}
    action = str(data.get("action", "")).strip().lower()
    keys = data.get("keys", [])
    duration = str(data.get("duration", "")).strip().lower()

    if isinstance(keys, str):
        keys = [keys]
    keys = [str(k).strip() for k in keys if str(k).strip()]
    keys = list(dict.fromkeys(keys))[:250]

    if not keys:
        return jsonify({"ok": False, "error": "No keys selected"}), 400

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
        "SELECT license_key, expires, hwid, active, owner, created_at, updated_at, last_verified_at, verify_count FROM licenses ORDER BY expires DESC",
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


@app.route("/admin/link-owner", methods=["POST"])
@admin_required_json
def admin_link_owner():
    init_db()
    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip()
    owner = safe_owner(data.get("owner", "") or data.get("user", ""))

    if not key:
        return jsonify({"ok": False, "error": "Missing key"}), 400

    row = db_query("SELECT license_key FROM licenses WHERE license_key=?", (key,), fetchone=True)
    if not row:
        return jsonify({"ok": False, "error": "Key not found"}), 404

    db_query("UPDATE licenses SET owner=?, updated_at=? WHERE license_key=?", (owner, now_utc().isoformat(), key))
    return jsonify({"ok": True, "key": key, "owner": owner})


@app.route("/admin/key-info", methods=["POST"])
@admin_required_json
def admin_key_info():
    init_db()
    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip()

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
    data = request.get_json(silent=True) or {}
    owner = safe_owner(data.get("owner", "") or data.get("user", ""))

    if not owner:
        return jsonify({"ok": False, "error": "Missing owner"}), 400

    if using_postgres():
        rows = db_query(
            "SELECT license_key, expires, hwid, active, owner FROM licenses WHERE owner ILIKE ? ORDER BY expires DESC",
            (f"%{owner}%",),
            fetchall=True,
        ) or []
    else:
        rows = db_query(
            "SELECT license_key, expires, hwid, active, owner FROM licenses WHERE lower(owner) LIKE lower(?) ORDER BY expires DESC",
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
        })

    return jsonify({"ok": True, "count": len(keys), "keys": keys})


STYLE = """
<style>
:root{
  --accent:#ff2338;
  --accent2:#d71328;
  --bg:#050506;
  --panel:#0c0c10;
  --panel2:#111116;
  --line:rgba(255,255,255,.105);
  --line2:rgba(255,35,56,.34);
  --text:#f6f6f8;
  --muted:#a5a6af;
  --good:#8effad;
  --warn:#ffd479;
  --bad:#ff8c98;
  --shadow:0 28px 90px rgba(0,0,0,.48);
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{
  margin:0;
  min-height:100vh;
  color:var(--text);
  font-family:Inter,Segoe UI,Arial,sans-serif;
  background:
    radial-gradient(circle at var(--mx,16%) var(--my,11%), rgba(255,35,56,.20), transparent 30%),
    radial-gradient(circle at 88% 8%, rgba(255,255,255,.07), transparent 26%),
    linear-gradient(145deg,#030304 0%,#111116 44%,#050506 100%);
  background-attachment:fixed;
  overflow-x:hidden;
}
body::before{
  content:"";
  position:fixed;
  inset:-35%;
  background:
    linear-gradient(115deg,transparent 0%,rgba(255,255,255,.05) 50%,transparent 56%),
    radial-gradient(circle at 58% 44%,rgba(255,35,56,.075),transparent 36%);
  transform:translate3d(calc(var(--px,0)*1px),calc(var(--py,0)*1px),0);
  pointer-events:none;
  z-index:-1;
  opacity:.8;
}
*::-webkit-scrollbar{width:10px;height:10px}
*::-webkit-scrollbar-track{background:rgba(255,255,255,.035)}
*::-webkit-scrollbar-thumb{background:rgba(255,35,56,.44);border-radius:999px;border:2px solid rgba(0,0,0,.28)}
button,input,select{font-family:inherit}
input,select{
  height:48px;
  border-radius:10px;
  border:1px solid rgba(255,255,255,.13);
  background:rgba(4,4,6,.78);
  color:var(--text);
  padding:0 14px;
  outline:none;
  font-weight:760;
  font-size:14px;
  transition:.18s ease;
}
input::placeholder{color:#747680}
input:focus,select:focus{
  border-color:rgba(255,35,56,.78);
  box-shadow:0 0 0 4px rgba(255,35,56,.13);
  transform:translateY(-1px);
}
button{
  height:48px;
  border-radius:10px;
  border:1px solid rgba(255,35,56,.70);
  background:rgba(255,35,56,.06);
  color:#fff;
  padding:0 16px;
  font-weight:840;
  font-size:13px;
  cursor:pointer;
  position:relative;
  overflow:hidden;
  transition:transform .18s cubic-bezier(.2,.8,.2,1),background .18s ease,box-shadow .18s ease,border-color .18s ease,opacity .18s ease;
}
button::before{
  content:"";
  position:absolute;
  inset:0;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.13),transparent);
  transform:translateX(-130%);
  transition:transform .55s ease;
}
button:hover{background:rgba(255,35,56,.13);transform:translateY(-2px);box-shadow:0 18px 45px rgba(255,35,56,.13)}
button:hover::before{transform:translateX(130%)}
button:disabled{opacity:.46;cursor:wait;transform:none}
.primary{background:linear-gradient(135deg,var(--accent),var(--accent2));border-color:rgba(255,68,84,.85);box-shadow:0 18px 54px rgba(255,35,56,.19)}
.secondary{border-color:rgba(255,255,255,.13);background:rgba(255,255,255,.035);color:var(--text)}
.danger{border-color:rgba(255,80,96,.58);background:rgba(255,35,56,.08);color:#ffd9de}
.brand{display:flex;align-items:center;gap:16px}
.brand-mark{
  width:64px;height:64px;display:grid;place-items:center;border-radius:18px;
  background:linear-gradient(145deg,rgba(255,35,56,.24),rgba(255,255,255,.035));
  border:1px solid rgba(255,255,255,.12);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.08),0 22px 50px rgba(0,0,0,.34);
}
.brand-mark img{width:46px;height:46px;object-fit:contain;filter:drop-shadow(0 12px 16px rgba(0,0,0,.36))}
h1{margin:0;font-size:clamp(34px,3vw,46px);letter-spacing:-.8px;line-height:1}
.muted{color:var(--muted);font-size:14px;margin-top:8px;font-weight:650}
.card{
  background:linear-gradient(180deg,rgba(18,18,23,.88),rgba(8,8,11,.92));
  border:1px solid var(--line);
  border-radius:20px;
  padding:22px;
  box-shadow:var(--shadow),inset 0 1px 0 rgba(255,255,255,.045);
  backdrop-filter:blur(18px);
  transition:transform .22s cubic-bezier(.2,.8,.2,1),border-color .22s ease,box-shadow .22s ease;
  position:relative;
  overflow:hidden;
}
.card::after{content:"";position:absolute;inset:0;background:radial-gradient(circle at var(--cardx,50%) var(--cardy,0%),rgba(255,35,56,.14),transparent 34%);opacity:0;pointer-events:none;transition:opacity .2s ease}
.card:hover{transform:translateY(-3px);border-color:rgba(255,35,56,.36);box-shadow:0 34px 105px rgba(0,0,0,.54),0 0 60px rgba(255,35,56,.08)}
.card:hover::after{opacity:1}
.toast{position:fixed;right:24px;bottom:24px;background:#101014;border:1px solid rgba(255,35,56,.38);border-radius:12px;padding:14px 16px;color:var(--text);font-weight:820;opacity:0;transform:translateY(10px);transition:.18s ease;pointer-events:none;z-index:40;box-shadow:0 22px 60px rgba(0,0,0,.50),0 0 42px rgba(255,35,56,.10)}
.toast.show{opacity:1;transform:translateY(0)}
.tooltip{position:fixed;max-width:540px;background:#111116;color:var(--text);border:1px solid rgba(255,35,56,.32);border-radius:10px;padding:10px 12px;font-size:12px;font-weight:760;box-shadow:0 20px 60px rgba(0,0,0,.45);opacity:0;pointer-events:none;transform:translateY(6px);transition:opacity .14s ease,transform .14s ease;z-index:50;word-break:break-all}
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
.login{width:min(480px,calc(100vw - 34px));animation:loginPop .42s cubic-bezier(.2,.8,.2,1) both}
@keyframes loginPop{from{opacity:0;transform:translateY(18px) scale(.985)}to{opacity:1;transform:translateY(0) scale(1)}}
.login .sub{margin-left:80px;margin-bottom:26px}
.login input{width:100%}
label{display:block;margin:15px 0 8px;color:#e3e3e7;font-size:13px;font-weight:820}
.passbox{position:relative;width:100%}.passbox input{padding-right:108px}.textbtn{position:absolute;right:7px;top:7px;height:34px;padding:0 12px;border-radius:8px;border-color:rgba(255,255,255,.12);background:rgba(255,255,255,.035);font-size:12px;color:#fff}.textbtn:hover{transform:none;background:rgba(255,255,255,.08)}
.btn{width:100%;margin-top:23px}.err{display:none;margin-top:14px;padding:13px;border-radius:10px;background:rgba(255,35,56,.08);border:1px solid rgba(255,35,56,.32);color:#ffd8dc;font-weight:780;font-size:13px}.secure-note{margin-top:18px;padding-top:16px;border-top:1px solid rgba(255,255,255,.08);color:#8f9099;font-size:12px;line-height:1.55;font-weight:650}
</style>
</head>
<body>
<div class="login-wrap">
  <div class="card login">
    <div class="brand">
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
.wrap{width:min(1360px,calc(100vw - 56px));margin:0 auto;padding:46px 0 68px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-bottom:24px;animation:fadeDown .36s ease both}@keyframes fadeDown{from{opacity:0;transform:translateY(-12px)}to{opacity:1;transform:translateY(0)}}.top-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.badge{border:1px solid rgba(255,35,56,.30);background:rgba(16,16,20,.76);color:#fff;border-radius:12px;padding:12px 16px;font-weight:820;font-size:13px;box-shadow:inset 0 0 30px rgba(255,35,56,.035),0 16px 42px rgba(0,0,0,.18);backdrop-filter:blur(14px)}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:22px}.stat{padding:18px}.stat .num{font-size:28px;font-weight:900;letter-spacing:-.5px}.stat .label{color:var(--muted);font-size:12px;font-weight:760;margin-top:4px}.grid{display:grid;grid-template-columns:340px minmax(0,1fr);gap:22px;align-items:start;animation:fadeUp .42s ease both}@keyframes fadeUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}h3{margin:0 0 14px;font-size:20px;letter-spacing:-.2px}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.field{display:flex;flex-direction:column;gap:8px;margin-bottom:12px}.field label{font-size:12px;color:#d7d7de;font-weight:820}.field input,.field select{width:100%}.stack{display:flex;flex-direction:column;gap:14px}.toolbar{display:flex;gap:12px;flex-wrap:wrap;align-items:center;justify-content:space-between;margin-bottom:14px}.tablewrap{overflow-x:auto;max-height:660px;overflow-y:auto;border:1px solid rgba(255,255,255,.10);border-radius:16px;background:rgba(7,7,9,.82);box-shadow:inset 0 0 42px rgba(0,0,0,.22)}table{width:100%;border-collapse:collapse;min-width:1320px;table-layout:auto}th,td{text-align:left;padding:15px 14px;border-bottom:1px solid rgba(255,255,255,.075);font-size:14px;vertical-align:middle;overflow:hidden;text-overflow:ellipsis}th{color:var(--muted);background:rgba(13,13,17,.97);position:sticky;top:0;z-index:2;backdrop-filter:blur(10px);font-size:12px;text-transform:uppercase;letter-spacing:.6px}tr{transition:background .16s ease}tr:hover td{background:rgba(255,35,56,.045)}code{color:#ff5262;font-weight:880;letter-spacing:.2px}.hwid{max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#c7c7cf}.owner{min-width:190px;width:190px;color:#f5f5f7;font-weight:780;font-family:Consolas,monospace;white-space:nowrap;cursor:pointer}.owner:hover{color:#ff5262}.check{width:18px;height:18px;accent-color:var(--accent);min-width:0}.pill{display:inline-block;border-radius:999px;padding:6px 11px;font-size:12px;font-weight:850;background:#17171b;border:1px solid rgba(255,255,255,.12)}.ok{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}.keycell{display:flex;align-items:center;gap:8px}.copybtn{height:30px;padding:0 10px;border-radius:8px;font-size:11px;color:var(--text);border-color:rgba(255,255,255,.13);background:#111116}.copybtn:hover{border-color:rgba(255,35,56,.7);color:#fff}.small{height:40px;font-size:12px}.logout{color:var(--text);border-color:rgba(255,255,255,.14)}.split{display:grid;grid-template-columns:1fr 1fr;gap:10px}.help{font-size:12px;line-height:1.5;color:#8d8e98;font-weight:650;margin-top:4px}.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.62);backdrop-filter:blur(8px);display:none;align-items:center;justify-content:center;z-index:60;padding:22px}.modal-backdrop.show{display:flex}.modal{width:min(520px,100%);animation:modalPop .22s ease both}@keyframes modalPop{from{opacity:0;transform:translateY(14px) scale(.985)}to{opacity:1;transform:translateY(0) scale(1)}}.modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:16px}.progress{height:3px;background:rgba(255,255,255,.08);overflow:hidden;border-radius:999px;margin-top:14px}.progress span{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--accent),#fff);transition:width .24s ease}.status-dot{width:7px;height:7px;border-radius:50%;display:inline-block;background:currentColor;margin-right:7px}.datecell{color:#b8b9c2;font-size:12px}.empty{padding:28px;text-align:center;color:var(--muted);font-weight:760}@media(max-width:1050px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}.wrap{width:min(100% - 32px,840px);padding:28px 0 44px}.topbar{align-items:flex-start;flex-direction:column}input,select{width:100%}.row{width:100%}.split{grid-template-columns:1fr}}@media(max-width:560px){.stats{grid-template-columns:1fr}.top-actions{width:100%}.top-actions>*{flex:1}.brand-mark{width:56px;height:56px}.brand-mark img{width:38px;height:38px}}
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
      <button class="secondary" onclick="loadKeys()">Refresh</button>
      <button class="logout secondary" onclick="logout()">Logout</button>
    </div>
  </div>

  <div class="stats">
    <div class="card stat"><div class="num" id="statTotal">0</div><div class="label">Total keys</div></div>
    <div class="card stat"><div class="num" id="statActive">0</div><div class="label">Active</div></div>
    <div class="card stat"><div class="num" id="statDisabled">0</div><div class="label">Disabled</div></div>
    <div class="card stat"><div class="num" id="statExpired">0</div><div class="label">Expired</div></div>
  </div>

  <div class="grid">
    <div class="stack">
      <div class="card">
        <h3>Create Key</h3>
        <div class="field"><label>Owner</label><input id="owner" placeholder="Customer or Discord username" maxlength="80"></div>
        <div class="field"><label>Duration</label><input id="duration" value="30d" placeholder="15m, 1h, 7d, 30d"></div>
        <button id="createBtn" class="primary" onclick="createKey()">Create Key</button>
        <div class="help">Accepted units: minutes, hours and days. Examples: 15m, 1h, 7d, 30d.</div>
      </div>

      <div class="card">
        <h3>Bulk Actions</h3>
        <div class="field"><label>Re-enable duration</label><input id="reenableDuration" value="30d" placeholder="1h, 7d, 30d"></div>
        <div class="split">
          <button onclick="bulkAction('enable_duration')">Re-enable with Time</button>
          <button onclick="bulkAction('enable')">Re-enable Only</button>
          <button onclick="bulkAction('reset_hwid')">Reset HWID</button>
          <button onclick="bulkAction('disable')">Disable</button>
        </div>
        <button class="danger" style="width:100%;margin-top:10px" onclick="bulkAction('delete')">Delete Selected</button>
        <div class="help">Re-enable with time activates selected keys and replaces their expiration with the duration chosen above.</div>
      </div>

      <div class="card">
        <h3>Security Status</h3>
        <div class="help">Enabled: CSRF token, secure cookies, request limits, security headers, optional origin allowlist, masked keys by default and safer input limits.</div>
      </div>
    </div>

    <div>
      <div class="card">
        <h3>Keys</h3>
        <div class="toolbar">
          <div class="row">
            <input id="search" placeholder="Search key, owner or HWID" oninput="debouncedRender()">
            <select id="filter" onchange="renderKeys()">
              <option value="all">All</option>
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
              <option value="expired">Expired</option>
              <option value="bound">Bound HWID</option>
              <option value="unbound">Unbound</option>
            </select>
          </div>
          <div class="row">
            <button class="secondary small" id="revealBtn" onclick="toggleRevealKeys()">Show Keys</button>
            <button class="secondary small" onclick="clearFilters()">Clear Filters</button>
          </div>
        </div>
        <div class="tablewrap">
          <table>
            <thead>
              <tr>
                <th><input class="check" type="checkbox" id="selectAll" onchange="toggleAll()"></th>
                <th>Key</th><th>Status</th><th>Remaining</th><th>Owner</th><th>HWID</th><th>Verifications</th><th>Last Verify</th><th>Expires</th><th>Updated</th>
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

<div id="toast" class="toast">Ready.</div>
<div id="tooltip" class="tooltip"></div>

<script>
let allKeys=[];let loading=false;let renderTimer=null;let revealKeys=false;let pendingAction=null;
const csrf=document.querySelector('meta[name="csrf-token"]').content;
document.addEventListener("pointermove",event=>{const x=event.clientX/window.innerWidth;const y=event.clientY/window.innerHeight;document.body.style.setProperty("--mx",`${x*100}%`);document.body.style.setProperty("--my",`${y*100}%`);document.body.style.setProperty("--px",`${(x-.5)*18}`);document.body.style.setProperty("--py",`${(y-.5)*18}`);const card=event.target.closest?.(".card");if(card){const rect=card.getBoundingClientRect();card.style.setProperty("--cardx",`${((event.clientX-rect.left)/rect.width)*100}%`);card.style.setProperty("--cardy",`${((event.clientY-rect.top)/rect.height)*100}%`)}});
function toast(message){const el=document.getElementById("toast");el.textContent=message;el.classList.add("show");clearTimeout(window.__toastTimer);window.__toastTimer=setTimeout(()=>el.classList.remove("show"),2400)}
function tooltip(event,text){const el=document.getElementById("tooltip");el.textContent=text||"";el.style.left=Math.min(event.clientX+14,window.innerWidth-540)+"px";el.style.top=(event.clientY+16)+"px";el.classList.add("show")}
function hideTooltip(){document.getElementById("tooltip").classList.remove("show")}
async function postJSON(url,payload){const res=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(payload||{})});if(res.status===401){location.href="/admin";return{ok:false,error:"Unauthorized"}}let data={};try{data=await res.json()}catch(e){data={ok:false,error:"Invalid server response"}}if(!data.ok&&data.error)toast(data.error);return data}
async function createKey(){if(loading)return;const btn=document.getElementById("createBtn");const duration=document.getElementById("duration").value.trim();const owner=document.getElementById("owner").value.trim();loading=true;btn.disabled=true;setProgress(35);const data=await postJSON("/admin/create",{duration,owner});setProgress(75);if(data.ok){toast("Key created");await loadKeys(false);if(data.key)copyText(data.key,"Created key copied")}setProgress(100);setTimeout(()=>setProgress(0),420);btn.disabled=false;loading=false}
function selectedKeys(){return Array.from(document.querySelectorAll(".keyCheck:checked")).map(x=>x.value)}
function actionLabel(action){return {enable_duration:"Re-enable with time",enable:"Re-enable only",disable:"Disable",reset_hwid:"Reset HWID",delete:"Delete"}[action]||action}
function bulkAction(action){const keys=selectedKeys();if(keys.length===0){toast("No keys selected");return}const duration=document.getElementById("reenableDuration").value.trim();let text=`${actionLabel(action)} will affect ${keys.length} selected key(s).`;if(action==="enable_duration")text+=` New duration: ${duration}.`;if(action==="delete")text+=" This cannot be undone.";pendingAction={action,keys,duration};document.getElementById("modalTitle").textContent=actionLabel(action);document.getElementById("modalText").textContent=text;document.getElementById("modalConfirm").onclick=confirmPendingAction;document.getElementById("confirmModal").classList.add("show")}
function closeModal(){document.getElementById("confirmModal").classList.remove("show");pendingAction=null;setProgress(0)}
function setProgress(v){const el=document.getElementById("modalProgress");if(el)el.style.width=v+"%"}
async function confirmPendingAction(){if(!pendingAction||loading)return;loading=true;setProgress(30);const data=await postJSON("/admin/action",pendingAction);setProgress(78);if(data.ok){toast(`${data.changed} key(s) updated`);await loadKeys(false)}setProgress(100);setTimeout(closeModal,280);loading=false}
function toggleAll(){const checked=document.getElementById("selectAll").checked;document.querySelectorAll(".keyCheck").forEach(cb=>cb.checked=checked)}
function statusClass(status){if(status==="Active")return"ok";if(status==="Expired")return"warn";return"bad"}
function filteredKeys(){const q=document.getElementById("search").value.toLowerCase().trim();const f=document.getElementById("filter").value;return allKeys.filter(item=>{const hay=`${item.key} ${item.hwid||""} ${item.owner||""} ${item.status}`.toLowerCase();if(q&&!hay.includes(q))return false;if(f==="active"&&item.status!=="Active")return false;if(f==="disabled"&&item.status!=="Disabled")return false;if(f==="expired"&&item.status!=="Expired")return false;if(f==="bound"&&!item.hwid)return false;if(f==="unbound"&&item.hwid)return false;return true})}
function debouncedRender(){clearTimeout(renderTimer);renderTimer=setTimeout(renderKeys,80)}
function escapeHtml(value){return String(value??"").replace(/[&<>"']/g,s=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[s]))}
function maskKey(key){const raw=String(key||"");if(raw.length<=10)return "Hidden";return raw.slice(0,5)+"••••••••"+raw.slice(-4)}
function toggleRevealKeys(){revealKeys=!revealKeys;document.getElementById("revealBtn").textContent=revealKeys?"Hide Keys":"Show Keys";renderKeys()}
function clearFilters(){document.getElementById("search").value="";document.getElementById("filter").value="all";renderKeys()}
function updateStats(keys){const total=keys.length;const active=keys.filter(k=>k.status==="Active").length;const disabled=keys.filter(k=>k.status==="Disabled").length;const expired=keys.filter(k=>k.status==="Expired").length;document.getElementById("statTotal").textContent=total;document.getElementById("statActive").textContent=active;document.getElementById("statDisabled").textContent=disabled;document.getElementById("statExpired").textContent=expired}
function renderKeys(){const tbody=document.getElementById("keys");const keys=filteredKeys();const frag=document.createDocumentFragment();tbody.innerHTML="";document.getElementById("selectAll").checked=false;document.getElementById("counter").textContent=`${allKeys.length} total / ${keys.length} shown`;updateStats(allKeys);if(keys.length===0){tbody.innerHTML='<tr><td colspan="10"><div class="empty">No keys found</div></td></tr>';return}for(const item of keys){const tr=document.createElement("tr");const fullHwid=item.hwid||"Not bound";const rawKey=String(item.key||"");const safeKey=escapeHtml(rawKey);const displayKey=escapeHtml(revealKeys?rawKey:maskKey(rawKey));const safeHwid=escapeHtml(fullHwid);const safeOwner=escapeHtml(item.owner&&item.owner.trim()?item.owner:"Not linked");tr.innerHTML=`<td><input class="check keyCheck" type="checkbox" value="${safeKey}"></td><td><div class="keycell" onmousemove="tooltip(event, revealKeys ? '${safeKey}' : 'Key hidden')" onmouseleave="hideTooltip()"><code>${displayKey}</code><button class="copybtn" onclick="copyKey(event,'${safeKey}')">Copy</button></div></td><td><span class="pill ${statusClass(item.status)}"><span class="status-dot"></span>${escapeHtml(item.status)}</span></td><td>${escapeHtml(item.remaining)}</td><td class="owner" onclick="editOwner(event,'${safeKey}','${escapeHtml(item.owner||"")}')" onmousemove="tooltip(event,'Click to edit owner')" onmouseleave="hideTooltip()">${safeOwner}</td><td class="hwid" onmousemove="tooltip(event,'${safeHwid}')" onmouseleave="hideTooltip()">${safeHwid}</td><td>${escapeHtml(item.verify_count||0)}</td><td class="datecell">${escapeHtml(item.last_verified_at||"Never")}</td><td class="datecell">${escapeHtml(item.expires)}</td><td class="datecell">${escapeHtml(item.updated_at||"")}</td>`;frag.appendChild(tr)}tbody.appendChild(frag)}
async function editOwner(event,key,currentOwner){event.stopPropagation();const owner=prompt("Owner",currentOwner||"");if(owner===null)return;const data=await postJSON("/admin/link-owner",{key,owner});if(data.ok){toast("Owner updated");await loadKeys(false)}}
async function copyText(text,message){try{await navigator.clipboard.writeText(text);toast(message||"Copied")}catch(e){const temp=document.createElement("textarea");temp.value=text;document.body.appendChild(temp);temp.select();document.execCommand("copy");document.body.removeChild(temp);toast(message||"Copied")}}
async function copyKey(event,key){event.stopPropagation();await copyText(key,"Key copied")}
async function loadKeys(showToast=true){if(loading&&showToast)return;const data=await postJSON("/admin/list",{});if(data.ok){allKeys=data.keys||[];renderKeys();if(showToast)toast("Keys refreshed")}}
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
