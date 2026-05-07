from flask import Flask, request, jsonify, render_template_string
import sqlite3
import secrets
import os
import re
from datetime import datetime, timedelta

app = Flask(__name__)

DB = "licenses.db"
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")


def init_db():
    con = sqlite3.connect(DB)
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        license_key TEXT PRIMARY KEY,
        expires TEXT,
        hwid TEXT,
        active INTEGER
    )
    """)

    con.commit()
    con.close()


def db_query(query, args=(), fetchone=False, fetchall=False):
    init_db()
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute(query, args)

    result = None
    if fetchone:
        result = cur.fetchone()
    elif fetchall:
        result = cur.fetchall()

    con.commit()
    con.close()
    return result


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


def check_secret_from_json(data):
    return ADMIN_SECRET and str(data.get("secret", "")) == ADMIN_SECRET


def check_secret_from_url():
    return ADMIN_SECRET and request.args.get("secret", "") == ADMIN_SECRET


def mask_key(key):
    if not key or len(key) < 10:
        return key
    return key[:9] + "..." + key[-4:]


def remaining_text(expires):
    try:
        expire_date = datetime.fromisoformat(expires)
        seconds = int((expire_date - datetime.utcnow()).total_seconds())

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


@app.route("/", methods=["GET"])
def home():
    init_db()
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
        return jsonify({
            "valid": False,
            "reason": "Missing key or HWID"
        }), 400

    row = db_query(
        "SELECT license_key, expires, hwid, active FROM licenses WHERE license_key=?",
        (key,),
        fetchone=True,
    )

    if not row:
        return jsonify({
            "valid": False,
            "reason": "Invalid key"
        })

    _, expires, saved_hwid, active = row

    if active != 1:
        return jsonify({
            "valid": False,
            "reason": "Disabled key"
        })

    try:
        expire_date = datetime.fromisoformat(expires)
    except Exception:
        return jsonify({
            "valid": False,
            "reason": "Invalid expiration"
        })

    if datetime.utcnow() > expire_date:
        return jsonify({
            "valid": False,
            "reason": "Expired key"
        })

    if saved_hwid and saved_hwid != hwid:
        return jsonify({
            "valid": False,
            "reason": "Different computer"
        })

    if not saved_hwid:
        db_query(
            "UPDATE licenses SET hwid=? WHERE license_key=?",
            (hwid, key)
        )

    remaining = expire_date - datetime.utcnow()

    return jsonify({
        "valid": True,
        "plan": "Premium",
        "expires": expires,
        "remaining_seconds": int(remaining.total_seconds())
    })


@app.route("/admin/create", methods=["POST"])
def admin_create():
    init_db()

    if not ADMIN_SECRET:
        return jsonify({
            "ok": False,
            "error": "ADMIN_SECRET is not configured"
        }), 500

    data = request.get_json(silent=True) or {}

    if not check_secret_from_json(data):
        return jsonify({
            "ok": False,
            "error": "Unauthorized"
        }), 401

    duration = str(data.get("duration", "30d")).strip().lower()
    delta = parse_duration(duration)

    if not delta:
        return jsonify({
            "ok": False,
            "error": "Invalid duration format. Use examples: 1m, 1h, 1d"
        }), 400

    license_key = "BLOX-" + secrets.token_hex(6).upper()
    expires = (datetime.utcnow() + delta).isoformat()

    db_query(
        "INSERT INTO licenses (license_key, expires, hwid, active) VALUES (?, ?, ?, ?)",
        (license_key, expires, None, 1)
    )

    return jsonify({
        "ok": True,
        "key": license_key,
        "expires": expires,
        "duration": duration
    })


@app.route("/admin/disable", methods=["POST"])
def admin_disable():
    init_db()

    if not ADMIN_SECRET:
        return jsonify({
            "ok": False,
            "error": "ADMIN_SECRET is not configured"
        }), 500

    data = request.get_json(silent=True) or {}

    if not check_secret_from_json(data):
        return jsonify({
            "ok": False,
            "error": "Unauthorized"
        }), 401

    key = str(data.get("key", "")).strip()

    if not key:
        return jsonify({
            "ok": False,
            "error": "Missing key"
        }), 400

    db_query(
        "UPDATE licenses SET active=0 WHERE license_key=?",
        (key,)
    )

    return jsonify({
        "ok": True,
        "disabled": key
    })


@app.route("/admin/enable", methods=["POST"])
def admin_enable():
    init_db()

    if not ADMIN_SECRET:
        return jsonify({
            "ok": False,
            "error": "ADMIN_SECRET is not configured"
        }), 500

    data = request.get_json(silent=True) or {}

    if not check_secret_from_json(data):
        return jsonify({
            "ok": False,
            "error": "Unauthorized"
        }), 401

    key = str(data.get("key", "")).strip()

    if not key:
        return jsonify({
            "ok": False,
            "error": "Missing key"
        }), 400

    db_query(
        "UPDATE licenses SET active=1 WHERE license_key=?",
        (key,)
    )

    return jsonify({
        "ok": True,
        "enabled": key
    })


@app.route("/admin/reset-hwid", methods=["POST"])
def admin_reset_hwid():
    init_db()

    if not ADMIN_SECRET:
        return jsonify({
            "ok": False,
            "error": "ADMIN_SECRET is not configured"
        }), 500

    data = request.get_json(silent=True) or {}

    if not check_secret_from_json(data):
        return jsonify({
            "ok": False,
            "error": "Unauthorized"
        }), 401

    key = str(data.get("key", "")).strip()

    if not key:
        return jsonify({
            "ok": False,
            "error": "Missing key"
        }), 400

    row = db_query(
        "SELECT license_key FROM licenses WHERE license_key=?",
        (key,),
        fetchone=True
    )

    if not row:
        return jsonify({
            "ok": False,
            "error": "Key not found"
        }), 404

    db_query(
        "UPDATE licenses SET hwid=NULL WHERE license_key=?",
        (key,)
    )

    return jsonify({
        "ok": True,
        "reset_hwid": key
    })


@app.route("/admin/delete", methods=["POST"])
def admin_delete():
    init_db()

    if not ADMIN_SECRET:
        return jsonify({
            "ok": False,
            "error": "ADMIN_SECRET is not configured"
        }), 500

    data = request.get_json(silent=True) or {}

    if not check_secret_from_json(data):
        return jsonify({
            "ok": False,
            "error": "Unauthorized"
        }), 401

    key = str(data.get("key", "")).strip()

    if not key:
        return jsonify({
            "ok": False,
            "error": "Missing key"
        }), 400

    db_query(
        "DELETE FROM licenses WHERE license_key=?",
        (key,)
    )

    return jsonify({
        "ok": True,
        "deleted": key
    })


@app.route("/admin/list", methods=["POST"])
def admin_list():
    init_db()

    if not ADMIN_SECRET:
        return jsonify({
            "ok": False,
            "error": "ADMIN_SECRET is not configured"
        }), 500

    data = request.get_json(silent=True) or {}

    if not check_secret_from_json(data):
        return jsonify({
            "ok": False,
            "error": "Unauthorized"
        }), 401

    rows = db_query(
        "SELECT license_key, expires, hwid, active FROM licenses ORDER BY expires DESC",
        fetchall=True
    ) or []

    keys = []
    for license_key, expires, hwid, active in rows:
        keys.append({
            "key": license_key,
            "expires": expires,
            "remaining": remaining_text(expires),
            "hwid": hwid,
            "active": bool(active)
        })

    return jsonify({
        "ok": True,
        "count": len(keys),
        "keys": keys
    })


ADMIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>BLOXSURO Admin</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            background: #050506;
            color: #f5f5f7;
            font-family: Segoe UI, Arial, sans-serif;
            margin: 0;
            padding: 28px;
        }
        .wrap {
            max-width: 1100px;
            margin: auto;
        }
        h1 {
            color: #ff1f2d;
            margin-bottom: 4px;
            letter-spacing: 1px;
        }
        .muted {
            color: #a1a1aa;
            margin-bottom: 24px;
        }
        .card {
            background: #111114;
            border: 1px solid #26262d;
            border-radius: 18px;
            padding: 18px;
            margin-bottom: 18px;
        }
        input, select {
            background: #050506;
            color: #f5f5f7;
            border: 1px solid #34343c;
            border-radius: 12px;
            padding: 12px;
            outline: none;
            min-width: 220px;
        }
        button {
            background: transparent;
            color: #ff1f2d;
            border: 1px solid #ff1f2d;
            border-radius: 12px;
            padding: 11px 14px;
            font-weight: 700;
            cursor: pointer;
            margin: 4px;
        }
        button:hover {
            background: #1d1d23;
        }
        .danger {
            color: #ef4444;
            border-color: #ef4444;
        }
        .ok {
            color: #22c55e;
        }
        .warn {
            color: #f59e0b;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            overflow: hidden;
            border-radius: 14px;
        }
        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #26262d;
            font-size: 14px;
        }
        th {
            color: #a1a1aa;
        }
        code {
            color: #ff1f2d;
        }
        .row {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
        }
        #result {
            white-space: pre-wrap;
            background: #050506;
            border: 1px solid #26262d;
            border-radius: 14px;
            padding: 12px;
            min-height: 42px;
            color: #f5f5f7;
        }
    </style>
</head>
<body>
<div class="wrap">
    <h1>BLOXSURO Admin</h1>
    <div class="muted">License panel</div>

    <div class="card">
        <h3>Create Key</h3>
        <div class="row">
            <input id="duration" value="30d" placeholder="1m, 1h, 1d, 30d">
            <button onclick="createKey()">Create</button>
        </div>
    </div>

    <div class="card">
        <h3>Manage Key</h3>
        <div class="row">
            <input id="key" placeholder="BLOX-XXXXXXXXXXXX">
            <button onclick="resetHwid()">Reset HWID</button>
            <button onclick="disableKey()" class="danger">Disable</button>
            <button onclick="enableKey()">Enable</button>
            <button onclick="deleteKey()" class="danger">Delete</button>
        </div>
    </div>

    <div class="card">
        <h3>Result</h3>
        <div id="result">Ready.</div>
    </div>

    <div class="card">
        <h3>Keys</h3>
        <button onclick="loadKeys()">Refresh List</button>
        <div style="overflow-x:auto;">
            <table>
                <thead>
                    <tr>
                        <th>Key</th>
                        <th>Remaining</th>
                        <th>Active</th>
                        <th>HWID</th>
                        <th>Expires</th>
                    </tr>
                </thead>
                <tbody id="keys"></tbody>
            </table>
        </div>
    </div>
</div>

<script>
const secret = new URLSearchParams(window.location.search).get("secret") || "";

async function postJSON(url, payload) {
    const res = await fetch(url, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({...payload, secret})
    });
    const data = await res.json();
    document.getElementById("result").innerText = JSON.stringify(data, null, 2);
    return data;
}

async function createKey() {
    const duration = document.getElementById("duration").value;
    await postJSON("/admin/create", {duration});
    await loadKeys();
}

async function resetHwid() {
    const key = document.getElementById("key").value.trim();
    await postJSON("/admin/reset-hwid", {key});
    await loadKeys();
}

async function disableKey() {
    const key = document.getElementById("key").value.trim();
    await postJSON("/admin/disable", {key});
    await loadKeys();
}

async function enableKey() {
    const key = document.getElementById("key").value.trim();
    await postJSON("/admin/enable", {key});
    await loadKeys();
}

async function deleteKey() {
    const key = document.getElementById("key").value.trim();
    if (!confirm("Delete this key?")) return;
    await postJSON("/admin/delete", {key});
    await loadKeys();
}

async function loadKeys() {
    const data = await postJSON("/admin/list", {});
    const tbody = document.getElementById("keys");
    tbody.innerHTML = "";

    if (!data.ok) return;

    for (const item of data.keys) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><code>${item.key}</code></td>
            <td>${item.remaining}</td>
            <td>${item.active ? '<span class="ok">YES</span>' : '<span class="warn">NO</span>'}</td>
            <td>${item.hwid || "Not bound"}</td>
            <td>${item.expires}</td>
        `;
        tbody.appendChild(tr);
    }
}

loadKeys();
</script>
</body>
</html>
"""


@app.route("/admin", methods=["GET"])
def admin_panel():
    init_db()

    if not check_secret_from_url():
        return "Unauthorized", 401

    return render_template_string(ADMIN_HTML)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
