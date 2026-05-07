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
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("ADMIN_SECRET") or secrets.token_hex(32)

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")

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
                connect_timeout=6
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
        if admin_authenticated() or check_secret_from_json(data):
            return fn(*args, **kwargs)
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    return wrapper


def make_key():
    return "BLOX-" + secrets.token_hex(6).upper()


@app.route("/", methods=["GET"])
def home():
    return redirect(url_for("admin_panel"))


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
        db_query("UPDATE licenses SET hwid=?, updated_at=? WHERE license_key=?", (hwid, now_utc().isoformat(), key))

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

    if not ADMIN_USERS:
        return jsonify({"ok": False, "error": "Admin credentials are not configured on Render."}), 500

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
    owner = str(data.get("owner", "") or data.get("user", "")).strip()
    delta = parse_duration(duration)

    if not delta:
        return jsonify({"ok": False, "error": "Invalid duration format. Use examples: 1m, 1h, 1d"}), 400

    license_key = make_key()
    expires = (now_utc() + delta).isoformat()
    created = now_utc().isoformat()

    db_query(
        "INSERT INTO licenses (license_key, expires, hwid, active, created_at, updated_at, owner) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (license_key, expires, None, 1, created, created, owner)
    )

    return jsonify({"ok": True, "key": license_key, "expires": expires, "duration": duration, "owner": owner})


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
        "SELECT license_key, expires, hwid, active, owner FROM licenses ORDER BY expires DESC",
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
            "owner": row.get("owner") or "",
            "active": bool(active),
            "status": status
        })

    return jsonify({"ok": True, "count": len(keys), "keys": keys})


STYLE = """
<style>
:root{
  --red:#ff2434;
  --red2:#ff4150;
  --bg:#030304;
  --bg2:#0b0b0f;
  --card:rgba(18,18,22,.78);
  --card2:rgba(10,10,13,.92);
  --border:rgba(255,255,255,.13);
  --text:#f5f5f7;
  --muted:#aaaab4;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{
  margin:0;
  min-height:100vh;
  color:var(--text);
  font-family:Segoe UI,Arial,sans-serif;
  background:
    radial-gradient(circle at var(--mx,18%) var(--my,12%), rgba(255,36,52,.22), transparent 28%),
    radial-gradient(circle at 85% 10%, rgba(255,255,255,.06), transparent 24%),
    linear-gradient(135deg,#050506 0%,#111116 46%,#020203 100%);
  background-attachment:fixed;
  overflow-x:hidden;
}
body::before{
  content:"";
  position:fixed;
  inset:-35%;
  background:
    linear-gradient(110deg,transparent 0%,rgba(255,255,255,.045) 48%,transparent 54%),
    radial-gradient(circle at 52% 46%,rgba(255,36,52,.065),transparent 34%);
  transform:translate3d(calc(var(--px,0)*1px),calc(var(--py,0)*1px),0);
  pointer-events:none;
  z-index:-1;
  opacity:.9;
}
*::-webkit-scrollbar{width:10px;height:10px}
*::-webkit-scrollbar-track{background:rgba(255,255,255,.035);border-radius:999px}
*::-webkit-scrollbar-thumb{background:rgba(255,36,52,.45);border-radius:6px;border:2px solid rgba(0,0,0,.35)}
.brand{display:flex;align-items:center;gap:16px}
.brand img{
  width:66px;
  height:66px;
  object-fit:contain;
  filter:drop-shadow(0 20px 24px rgba(0,0,0,.44));
  animation:logoFloat 3.2s ease-in-out infinite alternate;
}
@keyframes logoFloat{
  from{transform:translateY(0) rotate(-1deg)}
  to{transform:translateY(-6px) rotate(1deg)}
}
h1{
  margin:0;
  color:var(--text);
  font-size:clamp(38px,3.2vw,48px);
  letter-spacing:.3px;
  line-height:1;
  text-shadow:0 0 30px rgba(255,255,255,.08);
}
.muted{color:var(--muted);font-size:15px;margin-top:9px;font-weight:650}
button,input,select{font-family:inherit}
input,select{
  height:50px;
  border-radius:6px;
  border:1px solid rgba(255,255,255,.14);
  background:#050506;
  color:var(--text);
  padding:0 15px;
  outline:none;
  font-weight:850;
  font-size:15px;
  transition:.18s ease;
}
input:focus,select:focus{
  border-color:rgba(255,36,52,.70);
  box-shadow:0 0 0 4px rgba(255,36,52,.13);
  transform:translateY(-1px);
}
button{
  height:50px;
  border-radius:6px;
  border:1px solid rgba(255,36,52,.78);
  background:transparent;
  color:var(--red);
  padding:0 18px;
  font-weight:950;
  font-size:14px;
  cursor:pointer;
  position:relative;
  overflow:hidden;
  transition:transform .18s cubic-bezier(.2,.8,.2,1),background .18s ease,box-shadow .18s ease,border-color .18s ease;
}
button::before{
  content:"";
  position:absolute;
  inset:0;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.14),transparent);
  transform:translateX(-120%);
  transition:transform .48s ease;
}
button:hover{
  background:rgba(255,36,52,.10);
  transform:translateY(-2px);
  box-shadow:0 18px 48px rgba(255,36,52,.13);
}
button:hover::before{transform:translateX(120%)}
button:disabled{opacity:.45;cursor:wait;transform:none}
.card{
  background:linear-gradient(180deg,rgba(23,23,28,.88),rgba(9,9,12,.92));
  border:1px solid var(--border);
  border-radius:12px;
  padding:24px;
  box-shadow:0 26px 80px rgba(0,0,0,.42),inset 0 1px 0 rgba(255,255,255,.04);
  backdrop-filter:blur(18px);
  transition:transform .22s cubic-bezier(.2,.8,.2,1),border-color .22s ease,box-shadow .22s ease;
  position:relative;
  overflow:hidden;
}
.card::after{
  content:"";
  position:absolute;
  inset:0;
  background:radial-gradient(circle at var(--cardx,50%) var(--cardy,0%),rgba(255,36,52,.12),transparent 34%);
  opacity:0;
  pointer-events:none;
  transition:opacity .22s ease;
}
.card:hover{
  transform:translateY(-3px);
  border-color:rgba(255,36,52,.42);
  box-shadow:0 34px 100px rgba(0,0,0,.52),0 0 56px rgba(255,36,52,.08);
}
.card:hover::after{opacity:1}
.toast{
  position:fixed;right:24px;bottom:24px;
  background:#111114;
  border:1px solid rgba(255,36,52,.42);
  border-radius:8px;
  padding:14px 17px;
  color:var(--text);
  font-weight:950;
  opacity:0;
  transform:translateY(10px);
  transition:.18s ease;
  pointer-events:none;
  z-index:40;
  box-shadow:0 18px 54px rgba(0,0,0,.48),0 0 40px rgba(255,36,52,.12);
}
.toast.show{opacity:1;transform:translateY(0)}
.tooltip{
  position:fixed;
  max-width:540px;
  background:#111114;
  color:var(--text);
  border:1px solid rgba(255,36,52,.33);
  border-radius:6px;
  padding:10px 12px;
  font-size:12px;
  font-weight:850;
  box-shadow:0 20px 60px rgba(0,0,0,.45);
  opacity:0;
  pointer-events:none;
  transform:translateY(6px);
  transition:opacity .14s ease,transform .14s ease;
  z-index:50;
  word-break:break-all;
}
.tooltip.show{opacity:1;transform:translateY(0)}

button,input,select{
  border-radius:6px !important;
}
.card{
  border-radius:12px !important;
}
.tablewrap{
  border-radius:10px !important;
}
.pill,.badge,.copybtn,.toast{
  border-radius:6px !important;
}

</style>
"""


@app.route("/admin/link-owner", methods=["POST"])
@admin_required_json
def admin_link_owner():
    init_db()
    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip()
    owner = str(data.get("owner", "") or data.get("user", "")).strip()

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
        "SELECT license_key, expires, hwid, active, owner FROM licenses WHERE license_key=?",
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
    })


@app.route("/admin/search-owner", methods=["POST"])
@admin_required_json
def admin_search_owner():
    init_db()
    data = request.get_json(silent=True) or {}
    owner = str(data.get("owner", "") or data.get("user", "")).strip()

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


LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>BLOXSURO Login</title>
<link rel="icon" href="/static/Logo%20Bloxsuro.png">
<meta name="viewport" content="width=device-width, initial-scale=1">
""" + STYLE + """
<style>
.login-wrap{
  min-height:100vh;
  display:grid;
  place-items:center;
  padding:28px;
}
.login{
  width:min(470px,calc(100vw - 34px));
  animation:loginPop .42s cubic-bezier(.2,.8,.2,1) both;
}
@keyframes loginPop{
  from{opacity:0;transform:translateY(18px) scale(.985)}
  to{opacity:1;transform:translateY(0) scale(1)}
}
.login .sub{margin-left:82px;margin-bottom:26px}
.login input{width:100%}
.login .passbox{width:100%}
label{
  display:block;
  margin:15px 0 8px;
  color:#dedee4;
  font-size:13px;
  font-weight:850;
}
.passbox{position:relative;width:100%}
.passbox input{padding-right:58px;width:100%}
.eye{
  position:absolute;
  right:8px;
  top:50%;
  transform:translateY(-50%);
  width:38px;
  height:34px;
  min-width:38px;
  padding:0;
  display:grid;
  place-items:center;
  border-color:rgba(255,255,255,.12);
  color:#fff;
  background:rgba(255,255,255,.035);
  line-height:1;
}
.eye:hover{
  background:rgba(255,255,255,.08);
  transform:translateY(-50%) scale(1.04);
}
.btn{
  width:100%;
  margin-top:23px;
  background:var(--red);
  color:white;
  box-shadow:0 18px 54px rgba(255,36,52,.20);
}
.btn:hover{background:var(--red2)}
.err{
  display:none;
  margin-top:14px;
  padding:13px;
  border-radius:6px;
  background:rgba(255,36,52,.08);
  border:1px solid rgba(255,36,52,.32);
  color:#ffd8dc;
  font-weight:850;
  font-size:13px;
}
</style>
</head>
<body>
<div class="login-wrap">
  <div class="card login">
    <div class="brand">
      <img src="/static/Logo%20Bloxsuro.png" alt="BLOXSURO Logo">
      <h1>BLOXSURO</h1>
    </div>
    <div class="sub muted">Admin panel login</div>

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
</div>

<script>
function togglePass(){
  const input=document.getElementById("password");
  input.type=input.type==="password"?"text":"password";
}
async function login(){
  const err=document.getElementById("err");
  err.style.display="none";
  const username=document.getElementById("username").value.trim();
  const password=document.getElementById("password").value;
  const res=await fetch("/login",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({username,password})
  });
  const data=await res.json();
  if(data.ok){location.href="/admin";return}
  err.textContent=data.error||"Invalid login.";
  err.style.display="block";
}
document.addEventListener("keydown",e=>{if(e.key==="Enter")login()});
document.addEventListener("pointermove",(event)=>{
  const x=event.clientX/window.innerWidth;
  const y=event.clientY/window.innerHeight;
  document.body.style.setProperty("--mx",`${x*100}%`);
  document.body.style.setProperty("--my",`${y*100}%`);
  document.body.style.setProperty("--px",`${(x-.5)*18}`);
  document.body.style.setProperty("--py",`${(y-.5)*18}`);
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
""" + STYLE + """
<style>
.wrap{
  width:min(1280px,calc(100vw - 56px));
  margin:0 auto;
  padding:54px 0 72px;
}
.topbar{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:18px;
  margin-bottom:28px;
  animation:fadeDown .36s ease both;
}
@keyframes fadeDown{
  from{opacity:0;transform:translateY(-12px)}
  to{opacity:1;transform:translateY(0)}
}
.top-actions{display:flex;align-items:center;gap:12px}
.badge{
  border:1px solid rgba(255,36,52,.30);
  background:rgba(16,16,20,.76);
  color:var(--red);
  border-radius:6px;
  padding:12px 17px;
  font-weight:950;
  font-size:14px;
  box-shadow:inset 0 0 30px rgba(255,36,52,.035),0 16px 42px rgba(0,0,0,.18);
  backdrop-filter:blur(14px);
}
.grid{
  display:grid;
  grid-template-columns:320px minmax(0,1fr);
  gap:22px;
  align-items:start;
  animation:fadeUp .42s ease both;
}
@keyframes fadeUp{
  from{opacity:0;transform:translateY(14px)}
  to{opacity:1;transform:translateY(0)}
}
h3{margin:0 0 14px;font-size:21px}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
.toolbar{display:flex;gap:12px;flex-wrap:wrap;align-items:center;justify-content:space-between;margin-bottom:14px}
.tablewrap{
  overflow-x:auto;
  max-height:620px;
  overflow-y:auto;
  border:1px solid rgba(255,255,255,.12);
  border-radius:10px;
  background:rgba(7,7,8,.82);
  box-shadow:inset 0 0 42px rgba(0,0,0,.22);
}
table{width:100%;border-collapse:collapse;min-width:1180px;table-layout:auto}
th,td{
  text-align:left;
  padding:15px 14px;
  border-bottom:1px solid rgba(255,255,255,.08);
  font-size:15px;
  vertical-align:middle;
  overflow:hidden;
  text-overflow:ellipsis;
}
th{
  color:var(--muted);
  background:rgba(13,13,16,.94);
  position:sticky;
  top:0;
  z-index:2;
  backdrop-filter:blur(10px);
}
tr{transition:background .16s ease}
tr:hover td{background:rgba(255,36,52,.045)}
code{color:var(--red);font-weight:950;letter-spacing:.2px}
.hwid{max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#c7c7cf}
.owner{
  min-width:230px;
  width:230px;
  color:#f5f5f7;
  font-weight:850;
  font-family:Consolas,monospace;
  white-space:nowrap;
  overflow:visible;
  text-overflow:clip;
  cursor:pointer;
  transition:.18s ease;
}
.owner:hover{
  color:#ff2434;
  text-shadow:0 0 18px rgba(255,36,52,.35);
}
.check{width:19px;height:19px;accent-color:var(--red);min-width:0}
.pill{display:inline-block;border-radius:6px;padding:6px 12px;font-size:12px;font-weight:950;background:#17171b;border:1px solid rgba(255,255,255,.12)}
.ok{color:#9effb7}.warn{color:#ffe08a}.bad{color:#ff9b9b}
.keycell{display:flex;align-items:center;gap:9px}
.copybtn{height:31px;padding:0 10px;border-radius:10px;font-size:11px;color:var(--text);border-color:rgba(255,255,255,.14);background:#111114}
.copybtn:hover{border-color:rgba(255,36,52,.7);color:var(--red)}
#revealBtn{min-width:128px}
.keycell code{min-width:150px;display:inline-block}
.logout{color:var(--text);border-color:rgba(255,255,255,.14)}
@media(max-width:950px){
  .grid{grid-template-columns:1fr}
  .wrap{width:min(100% - 32px,760px);padding:28px 0 44px}
  .topbar{align-items:flex-start;flex-direction:column}
  input,select{width:100%}
  .row{width:100%}
}
</style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <div>
      <div class="brand">
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
        <div class="muted">Examples: 15m, 1h, 7d, 30d</div>
      </div>

      <div class="card">
        <h3>Bulk Actions</h3>
        <div class="row">
          <button onclick="bulkAction('reset_hwid')">Reset HWID</button>
          <button onclick="bulkAction('disable')">Disable</button>
          <button onclick="bulkAction('enable')">Re-enable</button>
          <button onclick="bulkAction('delete')">Delete</button>
        </div>
        <div class="muted">Select keys in the table, then choose an action.</div>
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
          <button id="revealBtn" onclick="toggleRevealKeys()" title="Show / hide license keys">👁 Show Keys</button>
          <button id="refreshBtn" onclick="loadKeys()">Refresh</button>
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
                <th>Owner</th>
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
let allKeys=[];
let loading=false;
let renderTimer=null;
let revealKeys=false;

document.addEventListener("pointermove",(event)=>{
  const x=event.clientX/window.innerWidth;
  const y=event.clientY/window.innerHeight;
  document.body.style.setProperty("--mx",`${x*100}%`);
  document.body.style.setProperty("--my",`${y*100}%`);
  document.body.style.setProperty("--px",`${(x-.5)*18}`);
  document.body.style.setProperty("--py",`${(y-.5)*18}`);

  const card=event.target.closest?.(".card");
  if(card){
    const rect=card.getBoundingClientRect();
    card.style.setProperty("--cardx",`${((event.clientX-rect.left)/rect.width)*100}%`);
    card.style.setProperty("--cardy",`${((event.clientY-rect.top)/rect.height)*100}%`);
  }
});

function toast(message){
  const el=document.getElementById("toast");
  el.textContent=message;
  el.classList.add("show");
  clearTimeout(window.__toastTimer);
  window.__toastTimer=setTimeout(()=>el.classList.remove("show"),2400);
}
function tooltip(event,text){
  const el=document.getElementById("tooltip");
  el.textContent=text||"";
  el.style.left=Math.min(event.clientX+14,window.innerWidth-540)+"px";
  el.style.top=(event.clientY+16)+"px";
  el.classList.add("show");
}
function hideTooltip(){document.getElementById("tooltip").classList.remove("show")}
async function postJSON(url,payload){
  const res=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload||{})});
  if(res.status===401){location.href="/admin";return{ok:false,error:"Unauthorized"}}
  const data=await res.json();
  if(!data.ok&&data.error)toast(data.error);
  return data;
}
async function createKey(){
  if(loading)return;
  const btn=document.getElementById("createBtn");
  const duration=document.getElementById("duration").value.trim();
  loading=true;btn.disabled=true;
  const data=await postJSON("/admin/create",{duration});
  if(data.ok){toast("Created: "+data.key);await loadKeys(false)}
  btn.disabled=false;loading=false;
}
function selectedKeys(){return Array.from(document.querySelectorAll(".keyCheck:checked")).map(x=>x.value)}
async function bulkAction(action){
  if(loading)return;
  const keys=selectedKeys();
  if(keys.length===0){toast("No keys selected.");return}
  if(action==="delete"&&!confirm("Delete selected keys?"))return;
  loading=true;
  const data=await postJSON("/admin/action",{action,keys});
  if(data.ok){toast(`${data.changed} key(s) updated.`);await loadKeys(false)}
  loading=false;
}
function toggleAll(){
  const checked=document.getElementById("selectAll").checked;
  document.querySelectorAll(".keyCheck").forEach(cb=>cb.checked=checked);
}
function statusClass(status){
  if(status==="Active")return"ok";
  if(status==="Expired")return"warn";
  return"bad";
}
function filteredKeys(){
  const q=document.getElementById("search").value.toLowerCase().trim();
  const f=document.getElementById("filter").value;
  return allKeys.filter(item=>{
    const hay=`${item.key} ${item.hwid||""} ${item.owner||""} ${item.status}`.toLowerCase();
    if(q&&!hay.includes(q))return false;
    if(f==="active"&&item.status!=="Active")return false;
    if(f==="disabled"&&item.status!=="Disabled")return false;
    if(f==="expired"&&item.status!=="Expired")return false;
    if(f==="bound"&&!item.hwid)return false;
    if(f==="unbound"&&item.hwid)return false;
    return true;
  });
}
function debouncedRender(){
  clearTimeout(renderTimer);
  renderTimer=setTimeout(renderKeys,90);
}
function escapeHtml(value){
  return String(value??"").replace(/[&<>"']/g,s=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[s]));
}
function maskKey(key){
  const raw = String(key || "");
  if (raw.length <= 9) return "••••••";
  return raw.slice(0, 5) + "••••••••" + raw.slice(-4);
}

function toggleRevealKeys(){
  revealKeys = !revealKeys;
  const btn = document.getElementById("revealBtn");
  if (btn) btn.textContent = revealKeys ? "🙈 Hide Keys" : "👁 Show Keys";
  renderKeys();
}

function renderKeys(){
  const tbody=document.getElementById("keys");
  const keys=filteredKeys();
  const frag=document.createDocumentFragment();
  tbody.innerHTML="";
  document.getElementById("selectAll").checked=false;
  document.getElementById("counter").textContent=`${allKeys.length} total • ${keys.length} shown`;

  for(const item of keys){
    const tr=document.createElement("tr");
    const fullHwid=item.hwid||"Not bound";
    const rawKey=String(item.key || "");
    const safeKey=escapeHtml(rawKey);
    const displayKey=escapeHtml(revealKeys ? rawKey : maskKey(rawKey));
    const safeHwid=escapeHtml(fullHwid);
    tr.innerHTML=`
      <td><input class="check keyCheck" type="checkbox" value="${safeKey}"></td>
      <td><div class="keycell" onmousemove="tooltip(event, revealKeys ? '${safeKey}' : 'Key hidden')" onmouseleave="hideTooltip()">
        <code>${displayKey}</code>
        <button class="copybtn" onclick="copyKey(event,'${safeKey}')">Copy</button>
      </div></td>
      <td><span class="pill ${statusClass(item.status)}">${escapeHtml(item.status)}</span></td>
      <td>${escapeHtml(item.remaining)}</td>
      <td class="hwid" onmousemove="tooltip(event,'${safeHwid}')" onmouseleave="hideTooltip()">${safeHwid}</td>
      <td
 class="owner"
 onclick="copyOwner(event, item.owner || '')"
 onmousemove="tooltip(event, item.owner ? 'Click to copy owner: ' + item.owner : 'No owner linked')"
 onmouseleave="hideTooltip()">
${escapeHtml((item.owner && item.owner.trim() !== "" ? item.owner : "Not linked"))}
</td>
      <td>${escapeHtml(item.expires)}</td>`;
    frag.appendChild(tr);
  }
  tbody.appendChild(frag);
}
async function copyOwner(event, owner){
  event.stopPropagation();

  if(!owner || !owner.trim()){
    toast("No owner linked.");
    return;
  }

  try{
    await navigator.clipboard.writeText(owner);
    toast("Owner copied.");
  }catch(e){
    const temp=document.createElement("textarea");
    temp.value=owner;
    document.body.appendChild(temp);
    temp.select();
    document.execCommand("copy");
    document.body.removeChild(temp);
    toast("Owner copied.");
  }
}

async function copyKey(event,key){
  event.stopPropagation();
  try{await navigator.clipboard.writeText(key);toast("Key copied.")}
  catch(e){
    const temp=document.createElement("textarea");
    temp.value=key;document.body.appendChild(temp);temp.select();document.execCommand("copy");document.body.removeChild(temp);
    toast("Key copied.");
  }
}
async function loadKeys(showToast=true){
  if(loading&&showToast)return;
  const btn=document.getElementById("refreshBtn");
  btn.disabled=true;
  const data=await postJSON("/admin/list",{});
  if(data.ok){allKeys=data.keys||[];renderKeys();if(showToast)toast("Keys refreshed.")}
  btn.disabled=false;
}
async function logout(){
  await fetch("/logout",{method:"POST"});
  location.href="/admin";
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
