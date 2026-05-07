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


def key_status(expires, active):
    if not active:
        return "Disabled"
    if remaining_text(expires) == "Expired":
        return "Expired"
    return "Active"


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
        return jsonify({"valid": False, "reason": "Missing key or HWID"}), 400

    row = db_query(
        "SELECT license_key, expires, hwid, active FROM licenses WHERE license_key=?",
        (key,),
        fetchone=True,
    )

    if not row:
        return jsonify({"valid": False, "reason": "Invalid key"})

    _, expires, saved_hwid, active = row

    if active != 1:
        return jsonify({"valid": False, "reason": "Disabled key"})

    try:
        expire_date = datetime.fromisoformat(expires)
    except Exception:
        return jsonify({"valid": False, "reason": "Invalid expiration"})

    if datetime.utcnow() > expire_date:
        return jsonify({"valid": False, "reason": "Expired key"})

    if saved_hwid and saved_hwid != hwid:
        return jsonify({"valid": False, "reason": "Different computer"})

    if not saved_hwid:
        db_query("UPDATE licenses SET hwid=? WHERE license_key=?", (hwid, key))

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
        return jsonify({"ok": False, "error": "ADMIN_SECRET is not configured"}), 500

    data = request.get_json(silent=True) or {}

    if not check_secret_from_json(data):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    duration = str(data.get("duration", "30d")).strip().lower()
    delta = parse_duration(duration)

    if not delta:
        return jsonify({"ok": False, "error": "Invalid duration format. Use examples: 1m, 1h, 1d"}), 400

    license_key = "BLOX-" + secrets.token_hex(6).upper()
    expires = (datetime.utcnow() + delta).isoformat()

    db_query(
        "INSERT INTO licenses (license_key, expires, hwid, active) VALUES (?, ?, ?, ?)",
        (license_key, expires, None, 1)
    )

    return jsonify({"ok": True, "key": license_key, "expires": expires, "duration": duration})


@app.route("/admin/action", methods=["POST"])
def admin_action():
    init_db()

    if not ADMIN_SECRET:
        return jsonify({"ok": False, "error": "ADMIN_SECRET is not configured"}), 500

    data = request.get_json(silent=True) or {}

    if not check_secret_from_json(data):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

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

    for key in keys:
        if action == "disable":
            db_query("UPDATE licenses SET active=0 WHERE license_key=?", (key,))
        elif action == "enable":
            db_query("UPDATE licenses SET active=1 WHERE license_key=?", (key,))
        elif action == "reset_hwid":
            db_query("UPDATE licenses SET hwid=NULL WHERE license_key=?", (key,))
        elif action == "delete":
            db_query("DELETE FROM licenses WHERE license_key=?", (key,))
        changed += 1

    return jsonify({"ok": True, "action": action, "changed": changed})


@app.route("/admin/disable", methods=["POST"])
def admin_disable():
    data = request.get_json(silent=True) or {}
    data["action"] = "disable"
    return admin_action_from_data(data)


@app.route("/admin/enable", methods=["POST"])
def admin_enable():
    data = request.get_json(silent=True) or {}
    data["action"] = "enable"
    return admin_action_from_data(data)


@app.route("/admin/reset-hwid", methods=["POST"])
def admin_reset_hwid():
    data = request.get_json(silent=True) or {}
    data["action"] = "reset_hwid"
    return admin_action_from_data(data)


@app.route("/admin/delete", methods=["POST"])
def admin_delete():
    data = request.get_json(silent=True) or {}
    data["action"] = "delete"
    return admin_action_from_data(data)


def admin_action_from_data(data):
    if not ADMIN_SECRET:
        return jsonify({"ok": False, "error": "ADMIN_SECRET is not configured"}), 500

    if not check_secret_from_json(data):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    key = str(data.get("key", "")).strip()
    if not key:
        return jsonify({"ok": False, "error": "Missing key"}), 400

    action = data.get("action")
    if action == "disable":
        db_query("UPDATE licenses SET active=0 WHERE license_key=?", (key,))
        return jsonify({"ok": True, "disabled": key})
    if action == "enable":
        db_query("UPDATE licenses SET active=1 WHERE license_key=?", (key,))
        return jsonify({"ok": True, "enabled": key})
    if action == "reset_hwid":
        db_query("UPDATE licenses SET hwid=NULL WHERE license_key=?", (key,))
        return jsonify({"ok": True, "reset_hwid": key})
    if action == "delete":
        db_query("DELETE FROM licenses WHERE license_key=?", (key,))
        return jsonify({"ok": True, "deleted": key})

    return jsonify({"ok": False, "error": "Invalid action"}), 400


@app.route("/admin/list", methods=["POST"])
def admin_list():
    init_db()

    if not ADMIN_SECRET:
        return jsonify({"ok": False, "error": "ADMIN_SECRET is not configured"}), 500

    data = request.get_json(silent=True) or {}

    if not check_secret_from_json(data):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    rows = db_query(
        "SELECT license_key, expires, hwid, active FROM licenses ORDER BY expires DESC",
        fetchall=True
    ) or []

    keys = []
    for license_key, expires, hwid, active in rows:
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


ADMIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>BLOXSURO Admin</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; }
        body {
            background: radial-gradient(circle at top, #111116 0%, #050506 42%, #020203 100%);
            color: #f5f5f7;
            font-family: Segoe UI, Arial, sans-serif;
            margin: 0;
            padding: 28px;
        }
        .wrap {
            max-width: 1180px;
            margin: auto;
        }
        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 14px;
            margin-bottom: 22px;
        }
        h1 {
            color: #ff1f2d;
            margin: 0;
            letter-spacing: 1px;
            font-size: 32px;
        }
        .muted {
            color: #a1a1aa;
            font-size: 14px;
            margin-top: 4px;
        }
        .badge {
            border: 1px solid #33232a;
            background: #101014;
            color: #ff1f2d;
            border-radius: 999px;
            padding: 9px 14px;
            font-weight: 800;
            font-size: 13px;
        }
        .grid {
            display: grid;
            grid-template-columns: 280px 1fr;
            gap: 18px;
            align-items: start;
        }
        .card {
            background: linear-gradient(180deg, rgba(18, 18, 22, 0.98), rgba(12, 12, 15, 0.98));
            border: 1px solid #282832;
            border-radius: 22px;
            padding: 18px;
            margin-bottom: 18px;
            box-shadow: 0 18px 60px rgba(0, 0, 0, 0.28), 0 0 40px rgba(255, 31, 45, 0.035);
        }
        .card:hover {
            border-color: #3a1f28;
        }
        h3 {
            margin: 0 0 12px 0;
            font-size: 18px;
        }
        input, select {
            background: #050506;
            color: #f5f5f7;
            border: 1px solid #34343c;
            border-radius: 12px;
            padding: 12px;
            outline: none;
            min-width: 220px;
            height: 42px;
            font-weight: 700;
        }
        input:focus {
            border-color: #ff1f2d;
        }
        button {
            background: transparent;
            color: #ff1f2d;
            border: 1px solid #ff1f2d;
            border-radius: 12px;
            padding: 11px 14px;
            font-weight: 800;
            cursor: pointer;
            height: 42px;
            transition: 0.12s ease;
        }
        button:hover {
            background: #1d1d23;
            transform: translateY(-1px);
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
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
        }
        .toolbar {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 12px;
        }
        .tablewrap {
            overflow-x: auto;
            max-height: 560px;
            overflow-y: auto;
            border: 1px solid #26262d;
            border-radius: 18px;
            background: #070708;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 880px;
        }
        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #202027;
            font-size: 14px;
            vertical-align: middle;
        }
        th {
            color: #a1a1aa;
            background: #0d0d10;
            position: sticky;
            top: 0;
            z-index: 2;
        }
        tr:hover td {
            background: #101014;
        }
        code {
            color: #ff1f2d;
            font-weight: 800;
        }
        .hwid {
            max-width: 220px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            color: #b5b5c0;
        }
        .check {
            width: 18px;
            height: 18px;
            accent-color: #ff1f2d;
            min-width: 0;
        }
        .pill {
            display: inline-block;
            border-radius: 999px;
            padding: 5px 10px;
            font-size: 12px;
            font-weight: 800;
            background: #17171b;
            border: 1px solid #303038;
        }
        .keycell {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .copybtn {
            height: 28px;
            padding: 4px 9px;
            border-radius: 9px;
            font-size: 11px;
            color: #f5f5f7;
            border-color: #34343c;
            background: #111114;
        }
        .copybtn:hover {
            border-color: #ff1f2d;
            color: #ff1f2d;
        }
        .toast {
            position: fixed;
            right: 24px;
            bottom: 24px;
            background: #111114;
            border: 1px solid #ff1f2d;
            border-radius: 14px;
            padding: 12px 16px;
            color: #f5f5f7;
            font-weight: 800;
            opacity: 0;
            transform: translateY(10px);
            transition: 0.18s ease;
            pointer-events: none;
        }
        .toast.show {
            opacity: 1;
            transform: translateY(0);
        }
        @media (max-width: 850px) {
            .grid { grid-template-columns: 1fr; }
            body { padding: 16px; }
        }
    </style>
</head>
<body>
<div class="wrap">
    <div class="topbar">
        <div>
            <h1>BLOXSURO Admin</h1>
            <div class="muted">License panel • create, select and manage keys</div>
        </div>
        <div class="badge" id="counter">Loading...</div>
    </div>

    <div class="grid">
        <div>
            <div class="card">
                <h3>Create Key</h3>
                <div class="row">
                    <input id="duration" value="30d" placeholder="1m, 1h, 1d, 30d">
                    <button onclick="createKey()">Create Key</button>
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
                        <input id="search" placeholder="Search key or HWID..." oninput="renderKeys()">
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
                        <button onclick="loadKeys()">Refresh</button>
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

<script>
const secret = new URLSearchParams(window.location.search).get("secret") || "";
let allKeys = [];

function toast(message) {
    const el = document.getElementById("toast");
    el.textContent = message;
    el.classList.add("show");
    clearTimeout(window.__toastTimer);
    window.__toastTimer = setTimeout(() => el.classList.remove("show"), 2200);
}

async function postJSON(url, payload) {
    const res = await fetch(url, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({...payload, secret})
    });

    const data = await res.json();

    if (!data.ok && data.error) {
        toast(data.error);
    }

    return data;
}

async function createKey() {
    const duration = document.getElementById("duration").value.trim();
    const data = await postJSON("/admin/create", {duration});

    if (data.ok) {
        toast("Created: " + data.key);
        await loadKeys();
    }
}

function selectedKeys() {
    return Array.from(document.querySelectorAll(".keyCheck:checked")).map(x => x.value);
}

async function bulkAction(action) {
    const keys = selectedKeys();

    if (keys.length === 0) {
        toast("No keys selected.");
        return;
    }

    if (action === "delete" && !confirm("Delete selected keys?")) {
        return;
    }

    const data = await postJSON("/admin/action", {action, keys});

    if (data.ok) {
        toast(`${data.changed} key(s) updated.`);
        await loadKeys();
    }
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

function renderKeys() {
    const tbody = document.getElementById("keys");
    const keys = filteredKeys();
    tbody.innerHTML = "";
    document.getElementById("selectAll").checked = false;

    document.getElementById("counter").textContent = `${allKeys.length} total • ${keys.length} shown`;

    for (const item of keys) {
        const tr = document.createElement("tr");

        tr.innerHTML = `
            <td><input class="check keyCheck" type="checkbox" value="${item.key}"></td>
            <td>
                <div class="keycell">
                    <code>${item.key}</code>
                    <button class="copybtn" onclick="copyKey(event, '${item.key}')">Copy</button>
                </div>
            </td>
            <td><span class="pill ${statusClass(item.status)}">${item.status}</span></td>
            <td>${item.remaining}</td>
            <td class="hwid" title="${item.hwid || "Not bound"}">${item.hwid || "Not bound"}</td>
            <td>${item.expires}</td>
        `;

        tbody.appendChild(tr);
    }
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

async function loadKeys() {
    const data = await postJSON("/admin/list", {});

    if (!data.ok) return;

    allKeys = data.keys || [];
    renderKeys();
    toast("Keys refreshed.");
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
