from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
import os
import re
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

# Keep this secret in Render Environment Variables when possible.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("ADMIN_SECRET") or secrets.token_hex(32)

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")

# Two admin accounts requested.
# You can override them later using ADMIN_USERS_JSON if wanted.
ADMIN_USERS = {
    "diesuro": "danid7nii",
    "AtrokZ": "cauaaarao",
}

# SQLite fallback only for local testing.
DB_DIR = os.environ.get("DB_DIR", ".")
os.makedirs(DB_DIR, exist_ok=True)
SQLITE_DB = os.path.join(DB_DIR, "licenses.db")


def using_postgres():
    return bool(DATABASE_URL and DATABASE_URL.startswith(("postgresql://", "postgres://")) and psycopg2 is not None)


def now_utc():
    return datetime.utcnow()


def get_conn():
    if using_postgres():
        return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)

    con = sqlite3.connect(SQLITE_DB)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = get_conn()
    cur = con.cursor()

    if using_postgres():
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
        cur.execute("CREATE INDEX IF NOT EXISTS idx_licenses_hwid ON licenses(hwid)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_licenses_active ON licenses(active)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_licenses_expires ON licenses(expires)")
    else:
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

    con.commit()
    con.close()


def sql_params(query):
    if using_postgres():
        return query.replace("?", "%s")
    return query


def db_query(query, args=(), fetchone=False, fetchall=False):
    init_db()
    con = get_conn()
    cur = con.cursor()

    cur.execute(sql_params(query), args)

    result = None
    if fetchone:
        result = cur.fetchone()
    elif fetchall:
        result = cur.fetchall()

    con.commit()
    con.close()

    if result is None:
        return None

    if fetchone:
        return dict(result)

    return [dict(r) for r in result]


def parse_duration(duration: str):
    duration = str(duration).strip().lower()
    match = re.fullmatch(r"(\d+)([mhd])", duration)
    if not match:
        return None

    value = int(match.group(1))
    unit = match.group(2)

    if value <= 0:
        return None

    if unit == "m":
        return timedelta(minutes=value)
    if unit == "h":
        return timedelta(hours=value)
    if unit == "d":
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


def check_secret_from_json(data):
    return ADMIN_SECRET and str(data.get("secret", "")) == ADMIN_SECRET


def admin_authenticated():
    return bool(session.get("admin_user"))


def admin_required_json(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        data = request.get_json(silent=True) or {}

        # Keeps old API support if your old tools still send ADMIN_SECRET.
        if admin_authenticated() or check_secret_from_json(data):
            return fn(*args, **kwargs)

        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    return wrapper


def make_key():
    return "BLOX-" + secrets.token_hex(6).upper()


@app.route("/", methods=["GET"])
def home():
    # Do not leak database path, connection URL, or admin details here.
    return jsonify({
        "online": True,
        "service": "BLOXSURO License Server"
    })


@app.route("/verify", methods=["POST"])
def verify():
    init_db()

    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip()
    hwid = str(data.get("hwid", "")).strip()

    if not key or not hwid:
        return jsonify({"valid": False, "reason": "Missing key or HWID"}), 400

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
            "UPDATE licenses SET hwid=?, updated_at=? WHERE license_key=?",
            (hwid, now_utc().isoformat(), key)
        )

    remaining = expire_date - now_utc()

    return jsonify({
        "valid": True,
        "plan": "Premium",
        "expires": expires,
        "remaining_seconds": int(remaining.total_seconds())
    })


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if username in ADMIN_USERS and secrets.compare_digest(ADMIN_USERS[username], password):
        session["admin_user"] = username
        return jsonify({"ok": True, "user": username})

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

    data = request.get_json(silent=True) or {}
    duration = str(data.get("duration", "30d")).strip().lower()
    delta = parse_duration(duration)

    if not delta:
        return jsonify({"ok": False, "error": "Invalid duration format. Use examples: 1m, 1h, 1d"}), 400

    license_key = make_key()
    expires = (now_utc() + delta).isoformat()
    created = now_utc().isoformat()

    db_query(
        "INSERT INTO licenses (license_key, expires, hwid, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (license_key, expires, None, 1, created, created)
    )

    return jsonify({"ok": True, "key": license_key, "expires": expires, "duration": duration})


@app.route("/admin/action", methods=["POST"])
@admin_required_json
def admin_action():
    init_db()

    data = request.get_json(silent=True) or {}
    action = str(data.get("action", "")).strip().lower()
    keys = data.get("keys", [])

    if isinstance(keys, str):
        keys = [keys]

    keys = [str(k).strip() for k in keys if str(k).strip()]

    if not keys:
        return jsonify({"ok": False, "error": "No keys selected"}), 400

    allowed = {"disable", "enable", "reset_hwid", "delete"}
    if action not in allowed:
        return jsonify({"ok": False, "error": "Invalid action"}), 400

    changed = 0
    updated = now_utc().isoformat()

    for key in keys:
        if action == "disable":
            db_query("UPDATE licenses SET active=0, updated_at=? WHERE license_key=?", (updated, key))
        elif action == "enable":
            db_query("UPDATE licenses SET active=1, updated_at=? WHERE license_key=?", (updated, key))
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
        "SELECT license_key, expires, hwid, active FROM licenses ORDER BY expires DESC",
        fetchall=True
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
            "hwid": hwid,
            "active": bool(active),
            "status": status
        })

    return jsonify({"ok": True, "count": len(keys), "keys": keys})


LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>BLOXSURO Login</title>
    <link rel="icon" href="/static/Logo%20Bloxsuro.png">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        :root {
            --accent: #ffffff;
            --bg: #030304;
            --surface: rgba(11,11,14,.86);
            --card: rgba(18,18,22,.88);
            --card2: rgba(9,9,12,.94);
            --border: rgba(255,255,255,.12);
            --text: #f5f5f7;
            --muted: #aaaab4;
        }

        * { box-sizing: border-box; }

        html { scroll-behavior: smooth; }

        body {
            min-height: 100vh;
            margin: 0;
            color: var(--text);
            font-family: Segoe UI, Arial, sans-serif;
            background:
                radial-gradient(circle at var(--mx, 20%) var(--my, 10%), rgba(255,255,255,.105), transparent 28%),
                radial-gradient(circle at 88% 5%, rgba(255,255,255,.055), transparent 24%),
                linear-gradient(135deg, #060607 0%, #111116 45%, #020203 100%);
            background-attachment: fixed;
            overflow-x: hidden;
        }

        body::before {
            content: "";
            position: fixed;
            inset: -30%;
            background:
                linear-gradient(115deg, transparent 0%, rgba(255,255,255,.045) 48%, transparent 54%),
                radial-gradient(circle at 55% 42%, rgba(255,255,255,.035), transparent 34%);
            transform: translate3d(calc(var(--px, 0) * 1px), calc(var(--py, 0) * 1px), 0);
            pointer-events: none;
            opacity: .85;
            z-index: -1;
        }

        *::-webkit-scrollbar { width: 10px; height: 10px; }
        *::-webkit-scrollbar-track { background: rgba(255,255,255,.035); border-radius: 999px; }
        *::-webkit-scrollbar-thumb {
            background: rgba(255,255,255,.28);
            border-radius: 999px;
            border: 2px solid rgba(0,0,0,.25);
        }

        .wrap {
            width: min(1280px, calc(100vw - 56px));
            margin: 0 auto;
            padding: 54px 0 72px;
        }

        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 18px;
            margin-bottom: 26px;
            animation: fadeDown .36s ease both;
        }

        @keyframes fadeDown {
            from { opacity: 0; transform: translateY(-12px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .brand img {
            width: 62px;
            height: 62px;
            object-fit: contain;
            filter: drop-shadow(0 18px 24px rgba(0,0,0,.40));
            animation: logoFloat 3.4s ease-in-out infinite alternate;
        }

        @keyframes logoFloat {
            from { transform: translateY(0) rotate(-1deg); }
            to { transform: translateY(-5px) rotate(1deg); }
        }

        h1 {
            color: var(--text);
            margin: 0;
            letter-spacing: .4px;
            font-size: clamp(36px, 3vw, 46px);
            line-height: 1;
            text-shadow: 0 0 28px rgba(255,255,255,.08);
        }

        .muted {
            color: var(--muted);
            font-size: 15px;
            margin-top: 8px;
            font-weight: 650;
        }

        .top-actions {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .badge {
            border: 1px solid rgba(255,255,255,.14);
            background: rgba(16,16,20,.78);
            color: var(--text);
            border-radius: 14px;
            padding: 12px 17px;
            font-weight: 950;
            font-size: 14px;
            box-shadow: inset 0 0 30px rgba(255,255,255,.025), 0 16px 42px rgba(0,0,0,.18);
            backdrop-filter: blur(14px);
        }

        .grid {
            display: grid;
            grid-template-columns: 320px minmax(0, 1fr);
            gap: 22px;
            align-items: start;
            animation: fadeUp .42s ease both;
        }

        @keyframes fadeUp {
            from { opacity: 0; transform: translateY(14px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .card {
            background: linear-gradient(180deg, rgba(22,22,27,.90), rgba(10,10,13,.92));
            border: 1px solid var(--border);
            border-radius: 26px;
            padding: 22px;
            margin-bottom: 20px;
            box-shadow: 0 24px 80px rgba(0,0,0,.42), inset 0 1px 0 rgba(255,255,255,.04);
            transition: transform .22s cubic-bezier(.2,.8,.2,1), border-color .22s ease, box-shadow .22s ease;
            backdrop-filter: blur(18px);
            position: relative;
            overflow: hidden;
        }

        .card::after {
            content: "";
            position: absolute;
            inset: 0;
            background: radial-gradient(circle at var(--cardx, 50%) var(--cardy, 0%), rgba(255,255,255,.09), transparent 34%);
            opacity: 0;
            transition: opacity .22s ease;
            pointer-events: none;
        }

        .card:hover {
            border-color: rgba(255,255,255,.26);
            box-shadow: 0 34px 96px rgba(0,0,0,.52), 0 0 54px rgba(255,255,255,.055);
            transform: translateY(-3px);
        }

        .card:hover::after { opacity: 1; }

        h3 {
            margin: 0 0 14px 0;
            font-size: 21px;
            letter-spacing: -.2px;
        }

        input, select {
            background: #060607;
            color: var(--text);
            border: 1px solid rgba(255,255,255,.13);
            border-radius: 15px;
            padding: 0 14px;
            outline: none;
            min-width: 230px;
            height: 48px;
            font-weight: 850;
            font-size: 15px;
            transition: border-color .18s ease, box-shadow .18s ease, transform .18s ease;
        }

        input:focus, select:focus {
            border-color: rgba(255,255,255,.40);
            box-shadow: 0 0 0 4px rgba(255,255,255,.075);
            transform: translateY(-1px);
        }

        button {
            background: transparent;
            color: var(--text);
            border: 1px solid rgba(255,255,255,.20);
            border-radius: 15px;
            padding: 0 17px;
            font-weight: 950;
            cursor: pointer;
            height: 48px;
            font-size: 14px;
            transition: transform .18s cubic-bezier(.2,.8,.2,1), box-shadow .18s ease, background .18s ease, border-color .18s ease;
            position: relative;
            overflow: hidden;
        }

        button::before {
            content: "";
            position: absolute;
            inset: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,.12), transparent);
            transform: translateX(-110%);
            transition: transform .45s ease;
        }

        button:hover {
            background: rgba(255,255,255,.07);
            border-color: rgba(255,255,255,.36);
            transform: translateY(-2px);
            box-shadow: 0 18px 48px rgba(0,0,0,.30);
        }

        button:hover::before { transform: translateX(110%); }

        button:disabled {
            opacity: .45;
            cursor: wait;
            transform: none;
        }

        .danger { color: #ffffff; border-color: rgba(255,255,255,.22); }
        .ok { color: #9effb7; }
        .warn { color: #ffe08a; }
        .bad { color: #ff9b9b; }

        .row {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            align-items: center;
        }

        .toolbar {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 14px;
        }

        .tablewrap {
            overflow-x: auto;
            max-height: 620px;
            overflow-y: auto;
            border: 1px solid rgba(255,255,255,.12);
            border-radius: 22px;
            background: rgba(7,7,8,.82);
            box-shadow: inset 0 0 42px rgba(0,0,0,.22);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 940px;
        }

        th, td {
            text-align: left;
            padding: 15px 14px;
            border-bottom: 1px solid rgba(255,255,255,.08);
            font-size: 15px;
            vertical-align: middle;
        }

        th {
            color: var(--muted);
            background: rgba(13,13,16,.94);
            position: sticky;
            top: 0;
            z-index: 2;
            backdrop-filter: blur(10px);
        }

        tr { transition: background .16s ease; }
        tr:hover td { background: rgba(255,255,255,.045); }

        code {
            color: #ffffff;
            font-weight: 950;
            letter-spacing: .2px;
        }

        .hwid {
            max-width: 260px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            color: #c7c7cf;
        }

        .check {
            width: 19px;
            height: 19px;
            accent-color: #ffffff;
            min-width: 0;
        }

        .pill {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 12px;
            font-size: 12px;
            font-weight: 950;
            background: #17171b;
            border: 1px solid rgba(255,255,255,.12);
            box-shadow: inset 0 0 28px rgba(255,255,255,.025);
        }

        .keycell {
            display: flex;
            align-items: center;
            gap: 9px;
        }

        .copybtn {
            height: 31px;
            padding: 0 10px;
            border-radius: 10px;
            font-size: 11px;
            color: var(--text);
            border-color: rgba(255,255,255,.14);
            background: #111114;
        }

        .copybtn:hover {
            border-color: rgba(255,255,255,.34);
            color: #fff;
        }

        .toast {
            position: fixed;
            right: 24px;
            bottom: 24px;
            background: #111114;
            border: 1px solid rgba(255,255,255,.22);
            border-radius: 16px;
            padding: 13px 16px;
            color: var(--text);
            font-weight: 950;
            opacity: 0;
            transform: translateY(10px);
            transition: .18s ease;
            pointer-events: none;
            box-shadow: 0 16px 50px rgba(0,0,0,.42), 0 0 36px rgba(255,255,255,.06);
            z-index: 30;
        }

        .toast.show {
            opacity: 1;
            transform: translateY(0);
        }

        .tooltip {
            position: fixed;
            max-width: 540px;
            background: #111114;
            color: var(--text);
            border: 1px solid rgba(255,255,255,.22);
            border-radius: 13px;
            padding: 10px 12px;
            font-size: 12px;
            font-weight: 850;
            box-shadow: 0 20px 60px rgba(0,0,0,.45);
            opacity: 0;
            pointer-events: none;
            transform: translateY(6px);
            transition: opacity .14s ease, transform .14s ease;
            z-index: 40;
            word-break: break-all;
        }

        .tooltip.show {
            opacity: 1;
            transform: translateY(0);
        }

        .logout {
            color: var(--text);
            border-color: rgba(255,255,255,.14);
        }

        @media (max-width: 950px) {
            .grid { grid-template-columns: 1fr; }
            body { padding: 0; }
            .wrap {
                width: min(100% - 32px, 760px);
                padding: 28px 0 44px;
            }
            .topbar { align-items: flex-start; flex-direction: column; }
            input, select { width: 100%; }
            .row { width: 100%; }
        }
    </style>
</head>
<body>
<div class="orb"></div>
<div class="login">
    <div class="brand login-brand">
        <img src="/static/Logo%20Bloxsuro.png" alt="BLOXSURO Logo">
        <h1>BLOXSURO</h1>
    </div>
    <div class="sub">Admin panel login</div>

    <label>Username</label>
    <input id="username" autocomplete="username" placeholder="Admin username">

    <label>Password</label>
    <div class="passbox">
        <input id="password" type="password" autocomplete="current-password" placeholder="Admin password">
        <button class="eye" onclick="togglePass()" type="button">👁</button>
    </div>

    <button class="btn" onclick="login()">Login</button>
    <div id="err" class="err">Invalid login.</div>
</div>

<script>
function togglePass() {
    const input = document.getElementById("password");
    input.type = input.type === "password" ? "text" : "password";
}

async function login() {
    const err = document.getElementById("err");
    err.style.display = "none";

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;

    const res = await fetch("/login", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({username, password})
    });

    const data = await res.json();

    if (data.ok) {
        location.href = "/admin";
        return;
    }

    err.textContent = data.error || "Invalid login.";
    err.style.display = "block";
}

document.addEventListener("keydown", e => {
    if (e.key === "Enter") login();
});
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
    <style>
        :root {
            --red: #ff1f2d;
            --red2: #ff4050;
            --bg: #020203;
            --surface: rgba(8,8,11,.78);
            --card: rgba(18,18,22,.82);
            --card2: rgba(11,11,14,.94);
            --border: rgba(255,255,255,.12);
            --text: #f5f5f7;
            --muted: #a8a8b4;
            --glow: rgba(255,31,45,.16);
        }

        * { box-sizing: border-box; }

        html {
            scroll-behavior: smooth;
        }

        body {
            min-height: 100vh;
            margin: 0;
            color: var(--text);
            font-family: Segoe UI, Arial, sans-serif;
            background:
                radial-gradient(circle at var(--mx, 18%) var(--my, 0%), rgba(255,31,45,.24), transparent 28%),
                radial-gradient(circle at calc(100% - var(--mx, 18%)) 12%, rgba(255,31,45,.10), transparent 24%),
                linear-gradient(180deg, #0b0508 0%, #030304 48%, #080204 100%);
            background-attachment: fixed;
            overflow-x: hidden;
        }

        body::before {
            content: "";
            position: fixed;
            inset: -20%;
            background:
                linear-gradient(115deg, transparent 0%, rgba(255,255,255,.035) 48%, transparent 52%),
                radial-gradient(circle at 20% 25%, rgba(255,31,45,.08), transparent 32%);
            transform: translate3d(calc(var(--px, 0) * 1px), calc(var(--py, 0) * 1px), 0);
            pointer-events: none;
            opacity: .85;
            z-index: -1;
        }

        *::-webkit-scrollbar {
            width: 10px;
            height: 10px;
        }

        *::-webkit-scrollbar-track {
            background: rgba(255,255,255,.035);
            border-radius: 999px;
        }

        *::-webkit-scrollbar-thumb {
            background: rgba(255,31,45,.42);
            border-radius: 999px;
            border: 2px solid rgba(0,0,0,.25);
        }

        .wrap {
            width: min(1280px, calc(100vw - 56px));
            margin: 0 auto;
            padding: 56px 0 72px;
        }

        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 18px;
            margin-bottom: 26px;
            animation: fadeDown .36s ease both;
        }

        @keyframes fadeDown {
            from { opacity: 0; transform: translateY(-12px); }
            to { opacity: 1; transform: translateY(0); }
        }

        h1 {
            color: var(--red);
            margin: 0;
            letter-spacing: 1px;
            font-size: clamp(36px, 3vw, 46px);
            line-height: 1;
            text-shadow: 0 0 34px rgba(255,31,45,.26);
        }

        .muted {
            color: var(--muted);
            font-size: 15px;
            margin-top: 8px;
            font-weight: 600;
        }

        .top-actions {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .badge {
            border: 1px solid rgba(255,31,45,.30);
            background: rgba(16,16,20,.74);
            color: var(--red);
            border-radius: 999px;
            padding: 12px 17px;
            font-weight: 900;
            font-size: 14px;
            box-shadow: inset 0 0 30px rgba(255,31,45,.035), 0 16px 42px rgba(0,0,0,.18);
            backdrop-filter: blur(14px);
        }

        .grid {
            display: grid;
            grid-template-columns: 320px minmax(0, 1fr);
            gap: 22px;
            align-items: start;
            animation: fadeUp .42s ease both;
        }

        @keyframes fadeUp {
            from { opacity: 0; transform: translateY(14px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .card {
            background: linear-gradient(180deg, rgba(20,20,24,.86), rgba(10,10,13,.90));
            border: 1px solid var(--border);
            border-radius: 28px;
            padding: 22px;
            margin-bottom: 20px;
            box-shadow: 0 22px 70px rgba(0,0,0,.36), 0 0 58px rgba(255,31,45,.045);
            transition:
                transform .22s cubic-bezier(.2,.8,.2,1),
                border-color .22s ease,
                box-shadow .22s ease,
                background .22s ease;
            backdrop-filter: blur(18px);
            position: relative;
            overflow: hidden;
        }

        .card::after {
            content: "";
            position: absolute;
            inset: 0;
            background: radial-gradient(circle at var(--cardx, 50%) var(--cardy, 0%), rgba(255,31,45,.10), transparent 34%);
            opacity: 0;
            transition: opacity .22s ease;
            pointer-events: none;
        }

        .card:hover {
            border-color: rgba(255,31,45,.42);
            box-shadow: 0 30px 90px rgba(0,0,0,.46), 0 0 86px rgba(255,31,45,.10);
            transform: translateY(-3px);
        }

        .card:hover::after {
            opacity: 1;
        }

        h3 {
            margin: 0 0 14px 0;
            font-size: 21px;
            letter-spacing: -.2px;
        }

        input, select {
            background: rgba(5,5,6,.92);
            color: var(--text);
            border: 1px solid #34343c;
            border-radius: 15px;
            padding: 0 14px;
            outline: none;
            min-width: 230px;
            height: 48px;
            font-weight: 850;
            font-size: 15px;
            transition: border-color .18s ease, box-shadow .18s ease, transform .18s ease;
        }

        input:focus, select:focus {
            border-color: var(--red);
            box-shadow: 0 0 0 4px rgba(255,31,45,.12), 0 0 30px rgba(255,31,45,.08);
            transform: translateY(-1px);
        }

        button {
            background: transparent;
            color: var(--red);
            border: 1px solid var(--red);
            border-radius: 15px;
            padding: 0 17px;
            font-weight: 900;
            cursor: pointer;
            height: 48px;
            font-size: 14px;
            transition:
                transform .18s cubic-bezier(.2,.8,.2,1),
                box-shadow .18s ease,
                background .18s ease,
                border-color .18s ease;
            position: relative;
            overflow: hidden;
        }

        button::before {
            content: "";
            position: absolute;
            inset: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,.10), transparent);
            transform: translateX(-110%);
            transition: transform .45s ease;
        }

        button:hover {
            background: rgba(255,31,45,.10);
            transform: translateY(-2px);
            box-shadow: 0 16px 40px rgba(255,31,45,.13);
        }

        button:hover::before {
            transform: translateX(110%);
        }

        button:disabled {
            opacity: .45;
            cursor: wait;
            transform: none;
        }

        .danger {
            color: #ef4444;
            border-color: #ef4444;
        }

        .ok { color: #22c55e; }
        .warn { color: #f59e0b; }
        .bad { color: #ef4444; }

        .row {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            align-items: center;
        }

        .toolbar {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 14px;
        }

        .tablewrap {
            overflow-x: auto;
            max-height: 620px;
            overflow-y: auto;
            border: 1px solid #26262d;
            border-radius: 22px;
            background: rgba(7,7,8,.82);
            box-shadow: inset 0 0 42px rgba(0,0,0,.22);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 940px;
        }

        th, td {
            text-align: left;
            padding: 15px 14px;
            border-bottom: 1px solid #202027;
            font-size: 15px;
            vertical-align: middle;
        }

        th {
            color: var(--muted);
            background: rgba(13,13,16,.94);
            position: sticky;
            top: 0;
            z-index: 2;
            backdrop-filter: blur(10px);
        }

        tr {
            transition: background .16s ease, transform .16s ease;
        }

        tr:hover td {
            background: rgba(255,31,45,.045);
        }

        code {
            color: var(--red);
            font-weight: 900;
            letter-spacing: .2px;
        }

        .hwid {
            max-width: 260px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            color: #b5b5c0;
        }

        .check {
            width: 19px;
            height: 19px;
            accent-color: var(--red);
            min-width: 0;
        }

        .pill {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 12px;
            font-size: 12px;
            font-weight: 900;
            background: #17171b;
            border: 1px solid #303038;
            box-shadow: inset 0 0 28px rgba(255,255,255,.025);
        }

        .keycell {
            display: flex;
            align-items: center;
            gap: 9px;
        }

        .copybtn {
            height: 31px;
            padding: 0 10px;
            border-radius: 10px;
            font-size: 11px;
            color: var(--text);
            border-color: #34343c;
            background: #111114;
        }

        .copybtn:hover {
            border-color: var(--red);
            color: var(--red);
        }

        .toast {
            position: fixed;
            right: 24px;
            bottom: 24px;
            background: #111114;
            border: 1px solid var(--red);
            border-radius: 16px;
            padding: 13px 16px;
            color: var(--text);
            font-weight: 900;
            opacity: 0;
            transform: translateY(10px);
            transition: .18s ease;
            pointer-events: none;
            box-shadow: 0 16px 50px rgba(0,0,0,.42), 0 0 36px rgba(255,31,45,.12);
            z-index: 30;
        }

        .toast.show {
            opacity: 1;
            transform: translateY(0);
        }

        .tooltip {
            position: fixed;
            max-width: 540px;
            background: #111114;
            color: var(--text);
            border: 1px solid rgba(255,31,45,.33);
            border-radius: 13px;
            padding: 10px 12px;
            font-size: 12px;
            font-weight: 800;
            box-shadow: 0 20px 60px rgba(0,0,0,.45);
            opacity: 0;
            pointer-events: none;
            transform: translateY(6px);
            transition: opacity .14s ease, transform .14s ease;
            z-index: 40;
            word-break: break-all;
        }

        .tooltip.show {
            opacity: 1;
            transform: translateY(0);
        }

        .logout {
            color: var(--text);
            border-color: #34343c;
        }

        @media (max-width: 950px) {
            .grid { grid-template-columns: 1fr; }
            body { padding: 0; }
            .wrap {
                width: min(100% - 32px, 760px);
                padding: 28px 0 44px;
            }
            .topbar { align-items: flex-start; flex-direction: column; }
            input, select { width: 100%; }
            .row { width: 100%; }
        }
    </style>
</head>
<body>
<div class="wrap">
    <div class="topbar">
        <div>
            <div class="brand admin-brand">
                <img src="/static/Logo%20Bloxsuro.png" alt="BLOXSURO Logo">
                <h1>BLOXSURO Admin</h1>
            </div>
            <div class="muted">License panel • online database • secure admin login</div>
        </div>
        <div class="top-actions">
            <div class="badge" id="counter">Loading...</div>
            <button class="logout" onclick="logout()">Logout</button>
        </div>
    </div>

    <div class="grid">
        <div>
            <div class="card">
                <h3>Create Key</h3>
                <div class="row">
                    <input id="duration" value="30d" placeholder="1m, 1h, 1d, 30d">
                    <button id="createBtn" onclick="createKey()">Create Key</button>
                </div>
                <div class="muted" style="margin-top:10px;">Examples: 15m, 1h, 7d, 30d</div>
            </div>

            <div class="card">
                <h3>Bulk Actions</h3>
                <div class="row">
                    <button onclick="bulkAction('reset_hwid')">Reset HWID</button>
                    <button onclick="bulkAction('disable')" class="danger">Disable</button>
                    <button onclick="bulkAction('enable')">Re-enable</button>
                    <button onclick="bulkAction('delete')" class="danger">Delete</button>
                </div>
                <div class="muted" style="margin-top:10px;">Select keys in the table, then choose an action.</div>
            </div>
        </div>

        <div>
            <div class="card">
                <h3>Keys</h3>
                <div class="toolbar">
                    <div class="row">
                        <input id="search" placeholder="Search key or HWID..." oninput="debouncedRender()">
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
                        <button id="refreshBtn" onclick="loadKeys()">Refresh</button>
                    </div>
                </div>

                <div class="tablewrap">
                    <table>
                        <thead>
                            <tr>
                                <th><input class="check" type="checkbox" id="selectAll" onchange="toggleAll()"></th>
                                <th>Key</th>
                                <th>Status</th>
                                <th>Remaining</th>
                                <th>HWID</th>
                                <th>Expires</th>
                            </tr>
                        </thead>
                        <tbody id="keys"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<div id="toast" class="toast">Ready.</div>
<div id="tooltip" class="tooltip"></div>

<script>
let allKeys = [];
let loading = false;
let renderTimer = null;

document.addEventListener("pointermove", (event) => {
    const x = event.clientX / window.innerWidth;
    const y = event.clientY / window.innerHeight;
    document.body.style.setProperty("--mx", `${x * 100}%`);
    document.body.style.setProperty("--my", `${y * 100}%`);
    document.body.style.setProperty("--px", `${(x - .5) * 18}`);
    document.body.style.setProperty("--py", `${(y - .5) * 18}`);

    const card = event.target.closest?.(".card");
    if (card) {
        const rect = card.getBoundingClientRect();
        card.style.setProperty("--cardx", `${((event.clientX - rect.left) / rect.width) * 100}%`);
        card.style.setProperty("--cardy", `${((event.clientY - rect.top) / rect.height) * 100}%`);
    }
});

function toast(message) {
    const el = document.getElementById("toast");
    el.textContent = message;
    el.classList.add("show");
    clearTimeout(window.__toastTimer);
    window.__toastTimer = setTimeout(() => el.classList.remove("show"), 2400);
}

function tooltip(event, text) {
    const el = document.getElementById("tooltip");
    el.textContent = text || "";
    el.style.left = Math.min(event.clientX + 14, window.innerWidth - 540) + "px";
    el.style.top = (event.clientY + 16) + "px";
    el.classList.add("show");
}

function hideTooltip() {
    document.getElementById("tooltip").classList.remove("show");
}

async function postJSON(url, payload) {
    const res = await fetch(url, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload || {})
    });

    if (res.status === 401) {
        location.href = "/admin";
        return {ok:false, error:"Unauthorized"};
    }

    const data = await res.json();

    if (!data.ok && data.error) {
        toast(data.error);
    }

    return data;
}

async function createKey() {
    if (loading) return;
    const btn = document.getElementById("createBtn");
    const duration = document.getElementById("duration").value.trim();

    loading = true;
    btn.disabled = true;

    const data = await postJSON("/admin/create", {duration});

    if (data.ok) {
        toast("Created: " + data.key);
        await loadKeys(false);
    }

    btn.disabled = false;
    loading = false;
}

function selectedKeys() {
    return Array.from(document.querySelectorAll(".keyCheck:checked")).map(x => x.value);
}

async function bulkAction(action) {
    if (loading) return;

    const keys = selectedKeys();

    if (keys.length === 0) {
        toast("No keys selected.");
        return;
    }

    if (action === "delete" && !confirm("Delete selected keys?")) {
        return;
    }

    loading = true;
    const data = await postJSON("/admin/action", {action, keys});

    if (data.ok) {
        toast(`${data.changed} key(s) updated.`);
        await loadKeys(false);
    }

    loading = false;
}

function toggleAll() {
    const checked = document.getElementById("selectAll").checked;
    document.querySelectorAll(".keyCheck").forEach(cb => cb.checked = checked);
}

function statusClass(status) {
    if (status === "Active") return "ok";
    if (status === "Expired") return "warn";
    return "bad";
}

function filteredKeys() {
    const q = document.getElementById("search").value.toLowerCase().trim();
    const f = document.getElementById("filter").value;

    return allKeys.filter(item => {
        const hay = `${item.key} ${item.hwid || ""} ${item.status}`.toLowerCase();

        if (q && !hay.includes(q)) return false;
        if (f === "active" && item.status !== "Active") return false;
        if (f === "disabled" && item.status !== "Disabled") return false;
        if (f === "expired" && item.status !== "Expired") return false;
        if (f === "bound" && !item.hwid) return false;
        if (f === "unbound" && item.hwid) return false;

        return true;
    });
}

function debouncedRender() {
    clearTimeout(renderTimer);
    renderTimer = setTimeout(renderKeys, 90);
}

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, s => ({
        "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
    }[s]));
}

function renderKeys() {
    const tbody = document.getElementById("keys");
    const keys = filteredKeys();
    const frag = document.createDocumentFragment();

    tbody.innerHTML = "";
    document.getElementById("selectAll").checked = false;
    document.getElementById("counter").textContent = `${allKeys.length} total • ${keys.length} shown`;

    for (const item of keys) {
        const tr = document.createElement("tr");
        const fullHwid = item.hwid || "Not bound";
        const safeKey = escapeHtml(item.key);
        const safeHwid = escapeHtml(fullHwid);

        tr.innerHTML = `
            <td><input class="check keyCheck" type="checkbox" value="${safeKey}"></td>
            <td>
                <div class="keycell" onmousemove="tooltip(event, '${safeKey}')" onmouseleave="hideTooltip()">
                    <code>${safeKey}</code>
                    <button class="copybtn" onclick="copyKey(event, '${safeKey}')">Copy</button>
                </div>
            </td>
            <td><span class="pill ${statusClass(item.status)}">${escapeHtml(item.status)}</span></td>
            <td>${escapeHtml(item.remaining)}</td>
            <td class="hwid" onmousemove="tooltip(event, '${safeHwid}')" onmouseleave="hideTooltip()">${safeHwid}</td>
            <td>${escapeHtml(item.expires)}</td>
        `;

        frag.appendChild(tr);
    }

    tbody.appendChild(frag);
}

async function copyKey(event, key) {
    event.stopPropagation();

    try {
        await navigator.clipboard.writeText(key);
        toast("Key copied.");
    } catch (e) {
        const temp = document.createElement("textarea");
        temp.value = key;
        document.body.appendChild(temp);
        temp.select();
        document.execCommand("copy");
        document.body.removeChild(temp);
        toast("Key copied.");
    }
}

async function loadKeys(showToast = true) {
    if (loading && showToast) return;

    const btn = document.getElementById("refreshBtn");
    btn.disabled = true;

    const data = await postJSON("/admin/list", {});

    if (data.ok) {
        allKeys = data.keys || [];
        renderKeys();
        if (showToast) toast("Keys refreshed.");
    }

    btn.disabled = false;
}

async function logout() {
    await fetch("/logout", {method:"POST"});
    location.href = "/admin";
}

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

    return render_template_string(ADMIN_HTML)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
