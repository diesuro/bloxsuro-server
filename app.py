from flask import Flask, request, jsonify
import sqlite3
from datetime import datetime

app = Flask(**name**)

DB = "licenses.db"

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

@app.route("/verify", methods=["POST"])
def verify():

```
data = request.json

key = data.get("key")
hwid = data.get("hwid")

con = sqlite3.connect(DB)
cur = con.cursor()

cur.execute(
    "SELECT license_key, expires, hwid, active FROM licenses WHERE license_key=?",
    (key,)
)

row = cur.fetchone()

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

expire_date = datetime.fromisoformat(expires)

if datetime.now() > expire_date:
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

    cur.execute(
        "UPDATE licenses SET hwid=? WHERE license_key=?",
        (hwid, key)
    )

    con.commit()

con.close()

return jsonify({
    "valid": True,
    "plan": "Premium",
    "expires": expires
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
