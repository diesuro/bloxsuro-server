from flask import Flask, request, jsonify
import sqlite3
import secrets
import os
import re

from datetime import datetime, timedelta

app = Flask(**name**)

DB = "licenses.db"

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")

def init_db():

```
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
```

def db_query(query, args=(), fetchone=False):

```
init_db()

con = sqlite3.connect(DB)

cur = con.cursor()

cur.execute(query, args)

row = cur.fetchone() if fetchone else None

con.commit()
con.close()

return row
```

def parse_duration(duration: str):

```
duration = str(duration).strip().lower()

match = re.fullmatch(r"(\d+)([mhd])", duration)

if not match:
    return None

value = int(match.group(1))
unit = match.group(2)

if unit == "m":
    return timedelta(minutes=value)

if unit == "h":
    return timedelta(hours=value)

if unit == "d":
    return timedelta(days=value)

return None
```

@app.route("/", methods=["GET"])
def home():

```
init_db()

return jsonify({
    "online": True,
    "service": "BLOXSURO License Server"
})
```

@app.route("/verify", methods=["POST"])
def verify():

```
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

if saved_hwid:

    if saved_hwid != hwid:

        return jsonify({
            "valid": False,
            "reason": "Different computer"
        })

else:

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
```

@app.route("/admin/create", methods=["POST"])
def admin_create():

```
init_db()

if not ADMIN_SECRET:

    return jsonify({
        "ok": False,
        "error": "ADMIN_SECRET is not configured"
    }), 500

data = request.get_json(silent=True) or {}

secret = str(data.get("secret", ""))

if secret != ADMIN_SECRET:

    return jsonify({
        "ok": False,
        "error": "Unauthorized"
    }), 401

duration = str(data.get("duration", "30d"))

delta = parse_duration(duration)

if not delta:

    return jsonify({
        "ok": False,
        "error": "Invalid duration format. Use 1m, 1h or 1d"
    }), 400

license_key = "BLOX-" + secrets.token_hex(6).upper()

expires = (
    datetime.utcnow() + delta
).isoformat()

db_query(
    "INSERT INTO licenses (license_key, expires, hwid, active) VALUES (?, ?, ?, ?)",
    (
        license_key,
        expires,
        None,
        1
    )
)

return jsonify({
    "ok": True,
    "key": license_key,
    "expires": expires,
    "duration": duration
})
```

@app.route("/admin/disable", methods=["POST"])
def admin_disable():

```
init_db()

if not ADMIN_SECRET:

    return jsonify({
        "ok": False,
        "error": "ADMIN_SECRET is not configured"
    }), 500

data = request.get_json(silent=True) or {}

if str(data.get("secret", "")) != ADMIN_SECRET:

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
```

if **name** == "**main**":

```
init_db()

app.run(
    host="0.0.0.0",
    port=5000
)
```
