"""GridPay — smart meter billing with remote disconnect.

Flask + SQLite + MQTT (HiveMQ).
  * Device publishes "M1 kWh:12.34" / "M2 kWh:8.90" (cumulative) to topic "tx"
  * App publishes R1ON / R1OFF / R2ON / R2OFF to topic "rx"
      R?ON  -> relay energised  -> supply CUT
      R?OFF -> relay released   -> supply RESTORED
  * A bill left unpaid for `disconnect_delay` seconds (default 30) cuts supply;
    paying it restores supply automatically.
"""
import logging
import math
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, flash, jsonify, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from mailer import Mailer
from mqtt_bridge import MqttBridge

# ---------------------------------------------------------------- config
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_env_file(path):
    """Read KEY=VALUE lines from .env into the environment (real env vars win)."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))


load_env_file(os.path.join(BASE_DIR, ".env"))

DB_PATH = os.environ.get("GRIDPAY_DB", os.path.join(BASE_DIR, "gridpay.db"))
MQTT_HOST = os.environ.get("MQTT_HOST", "broker.hivemq.com")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
TOPIC_TX = os.environ.get("MQTT_TOPIC_TX", "tx")   # device -> app (readings)
TOPIC_RX = os.environ.get("MQTT_TOPIC_RX", "rx")   # app -> device (relay commands)

EMAIL_SENDER = os.environ.get("EMAIL_SENDER", "")
EMAIL_PASSWORD = os.environ.get("APP_PASS_EMAIL_PASSWORD", "")
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
EMAIL_FROM_NAME = os.environ.get("EMAIL_FROM_NAME", "GridPay Billing")
ORG_NAME = os.environ.get("ORG_NAME", "Smart Meter Billing")
APP_URL = os.environ.get("APP_URL", "http://127.0.0.1:5000").rstrip("/")

TS_FMT = "%Y-%m-%d %H:%M:%S"
METERS = (1, 2)
READING_RE = re.compile(r"M\s*([12])\s*kWh\s*:\s*(-?\d+(?:\.\d+)?)", re.IGNORECASE)
DEFAULT_SETTINGS = {"rate": "8.00", "fixed_charge": "0.00", "disconnect_delay": "30"}

DB_LOCK = threading.RLock()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("gridpay")


def now():
    return datetime.now()


def ts(dt=None):
    return (dt or now()).strftime(TS_FMT)


def parse_ts(value):
    return datetime.strptime(value, TS_FMT)


# ---------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL UNIQUE,
    password    TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    meter       INTEGER UNIQUE,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS readings (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    meter  INTEGER NOT NULL,
    kwh    REAL NOT NULL,      -- cumulative value sent by the meter
    delta  REAL NOT NULL,      -- consumption since the previous reading
    ts     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_readings_meter ON readings (meter, id);
CREATE INDEX IF NOT EXISTS idx_readings_ts ON readings (meter, ts);
CREATE TABLE IF NOT EXISTS bills (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users (id),
    meter           INTEGER NOT NULL,
    from_reading_id INTEGER NOT NULL,
    to_reading_id   INTEGER NOT NULL,
    opening_kwh     REAL NOT NULL,
    closing_kwh     REAL NOT NULL,
    units           REAL NOT NULL,
    rate            REAL NOT NULL,
    fixed_charge    REAL NOT NULL,
    amount          REAL NOT NULL,
    status          TEXT NOT NULL DEFAULT 'unpaid' CHECK (status IN ('unpaid', 'paid')),
    created_at      TEXT NOT NULL,
    disconnect_at   TEXT NOT NULL,
    disconnected    INTEGER NOT NULL DEFAULT 0,
    paid_at         TEXT,
    pay_method      TEXT,
    txn_ref         TEXT
);
CREATE TABLE IF NOT EXISTS relays (
    meter       INTEGER PRIMARY KEY,
    state       TEXT NOT NULL CHECK (state IN ('connected', 'disconnected')),
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS email_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    to_addr  TEXT NOT NULL,
    subject  TEXT NOT NULL,
    kind     TEXT NOT NULL,
    ok       INTEGER NOT NULL,
    error    TEXT
);
CREATE TABLE IF NOT EXISTS mqtt_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    direction  TEXT NOT NULL,   -- in / out / info
    topic      TEXT NOT NULL,
    payload    TEXT NOT NULL
);
"""


@contextmanager
def db_conn():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with DB_LOCK, db_conn() as conn:
        conn.executescript(SCHEMA)
        conn.execute("PRAGMA journal_mode = WAL")
        for key, value in DEFAULT_SETTINGS.items():
            conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value))
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('secret_key', ?)",
                     (secrets.token_hex(32),))
        for m in METERS:
            conn.execute("INSERT OR IGNORE INTO relays (meter, state, updated_at) VALUES (?, 'connected', ?)",
                         (m, ts()))


def get_settings(conn):
    return {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM settings")}


def log_mqtt(conn, direction, topic, payload):
    conn.execute("INSERT INTO mqtt_log (ts, direction, topic, payload) VALUES (?, ?, ?, ?)",
                 (ts(), direction, topic, payload[:300]))
    conn.execute("DELETE FROM mqtt_log WHERE id <= (SELECT MAX(id) - 500 FROM mqtt_log)")


# ---------------------------------------------------------------- MQTT handling
def record_reading(meter, kwh):
    """Store a cumulative reading and the consumption since the previous one."""
    with DB_LOCK, db_conn() as conn:
        last = conn.execute("SELECT kwh FROM readings WHERE meter = ? ORDER BY id DESC LIMIT 1",
                            (meter,)).fetchone()
        if last is None:
            delta = 0.0                      # first reading is the baseline
        else:
            diff = kwh - last["kwh"]
            delta = diff if diff >= 0 else kwh   # counter went backwards: meter was reset
        conn.execute("INSERT INTO readings (meter, kwh, delta, ts) VALUES (?, ?, ?, ?)",
                     (meter, kwh, round(delta, 6), ts()))


def handle_mqtt_message(topic, text):
    matches = READING_RE.findall(text)
    with DB_LOCK, db_conn() as conn:
        log_mqtt(conn, "in", topic, text if matches else f"{text}  (ignored: not M1/M2 kWh format)")
    for meter, value in matches:
        record_reading(int(meter), float(value))


def handle_mqtt_event(text):
    with DB_LOCK, db_conn() as conn:
        log_mqtt(conn, "info", "broker", text)


bridge = MqttBridge(MQTT_HOST, MQTT_PORT, TOPIC_TX, TOPIC_RX,
                    on_message=handle_mqtt_message, on_event=handle_mqtt_event)


def set_relay(meter, cut, source):
    """cut=True sends R?ON (supply off); cut=False sends R?OFF (supply on)."""
    command = f"R{meter}{'ON' if cut else 'OFF'}"
    sent = bridge.publish(command)
    with DB_LOCK, db_conn() as conn:
        conn.execute("UPDATE relays SET state = ?, updated_at = ? WHERE meter = ?",
                     ("disconnected" if cut else "connected", ts(), meter))
        note = f"{command}  ({source})" + ("" if sent else "  NOT SENT: broker offline")
        log_mqtt(conn, "out", TOPIC_RX, note)
    log.info("Relay %s -> %s (%s) sent=%s", meter, command, source, sent)
    return sent


# ---------------------------------------------------------------- email
def record_email_result(to, subject, kind, ok, err):
    with DB_LOCK, db_conn() as conn:
        conn.execute("INSERT INTO email_log (ts, to_addr, subject, kind, ok, error) VALUES (?, ?, ?, ?, ?, ?)",
                     (ts(), to, subject, kind, 1 if ok else 0, err))
        conn.execute("DELETE FROM email_log WHERE id <= (SELECT MAX(id) - 300 FROM email_log)")


mailer = Mailer(EMAIL_SENDER, EMAIL_PASSWORD, host=SMTP_HOST, port=SMTP_PORT,
                from_name=EMAIL_FROM_NAME, on_result=record_email_result, brevo_key=BREVO_API_KEY)


def nice_time(value):
    dt = parse_ts(value) if isinstance(value, str) else value
    return dt.strftime("%d %b %Y, %I:%M:%S %p").lstrip("0")


def render_email(template, **ctx):
    """Render the HTML body. Works from request handlers and background threads."""
    ctx.setdefault("org_name", ORG_NAME)
    with app.app_context():
        return render_template(f"email/{template}.html", **ctx)


BANNERS = {
    "bill": {"bg": "#FFF4DE", "fg": "#7A4304", "icon": "&#128196;", "text": "New electricity bill"},
    "disconnected": {"bg": "#FBE0DD", "fg": "#8A1C12", "icon": "&#9888;", "text": "Power supply disconnected"},
    "receipt": {"bg": "#DDF3E4", "fg": "#14532D", "icon": "&#10004;", "text": "Payment received"},
}


def notify_bill_event(bill_id, kind, restored=False):
    """Queue the email for a bill event: kind is 'bill', 'disconnected' or 'receipt'."""
    with db_conn() as conn:
        b = conn.execute("""SELECT b.*, u.name, u.email FROM bills b JOIN users u ON u.id = b.user_id
                            WHERE b.id = ?""", (bill_id,)).fetchone()
    if not b:
        return
    amount = inr(b["amount"])
    units = f"{b['units']:.3f}"
    first = b["name"].split()[0]
    ctx = {"name": first, "meter": b["meter"], "bill_id": b["id"], "amount": amount, "units": units,
           "pay_url": f"{APP_URL}/me", "account_url": f"{APP_URL}/me", "banner": BANNERS[kind]}

    if kind == "bill":
        rows = [("Bill number", f"#{b['id']}"), ("Meter", f"Meter {b['meter']}"),
                ("Meter reading", f"{b['opening_kwh']:.2f} to {b['closing_kwh']:.2f} kWh"),
                ("Units used", f"{units} kWh"), ("Rate", f"{inr(b['rate'])} per kWh")]
        if b["fixed_charge"] > 0:
            rows.append(("Fixed charge", inr(b["fixed_charge"])))
        rows += [("Total", amount), ("Generated on", nice_time(b["created_at"]))]
        pay_by = nice_time(b["disconnect_at"])
        subject = f"Electricity bill #{b['id']}: {amount} due for Meter {b['meter']}"
        preheader = f"{units} kWh used. Pay before {pay_by} to avoid disconnection."
        ctx.update(rows=rows, pay_by=pay_by)
        text = (f"Hello {first},\n\nYour electricity bill for Meter {b['meter']} is ready.\n\n"
                + "\n".join(f"{k}: {v}" for k, v in rows)
                + f"\n\nPlease pay before {pay_by}. If the bill is still unpaid then, power supply to "
                  f"Meter {b['meter']} will be disconnected automatically.\n\nPay now: {APP_URL}/me\n")
    elif kind == "disconnected":
        cut_at = nice_time(now())
        subject = f"Power supply disconnected on Meter {b['meter']}: bill #{b['id']} unpaid"
        preheader = f"Pay {amount} to restore supply automatically."
        ctx.update(cut_at=cut_at)
        text = (f"Hello {first},\n\nPower supply to Meter {b['meter']} was disconnected at {cut_at} because "
                f"bill #{b['id']} ({amount}) was not paid by the due time.\n\nSupply is restored automatically "
                f"within a few seconds of payment.\n\nPay now: {APP_URL}/me\n")
    else:  # receipt
        rows = [("Bill number", f"#{b['id']}"), ("Meter", f"Meter {b['meter']}"), ("Units billed", f"{units} kWh"),
                ("Amount paid", amount), ("Payment method", b["pay_method"] or "UPI"),
                ("Transaction reference", b["txn_ref"]), ("Paid on", nice_time(b["paid_at"]))]
        subject = f"Payment received: {amount} for bill #{b['id']}"
        preheader = ("Supply restored. " if restored else "") + f"Reference {b['txn_ref']}."
        ctx.update(rows=rows, txn_ref=b["txn_ref"], restored=restored)
        status = (f"Power supply to Meter {b['meter']} has been restored." if restored
                  else "Paid on time. Your supply was not interrupted.")
        text = (f"Hello {first},\n\nWe have received your payment for bill #{b['id']}.\n\n"
                + "\n".join(f"{k}: {v}" for k, v in rows) + f"\n\n{status}\n")

    ctx.update(subject=subject, preheader=preheader)
    mailer.send_async(b["email"], subject, text, render_email(kind, **ctx), kind=kind)


# ---------------------------------------------------------------- billing
class BillingError(Exception):
    pass


def generate_bill(user_id):
    with DB_LOCK, db_conn() as conn:
        user = conn.execute("SELECT id, name, meter FROM users WHERE id = ? AND role = 'user'",
                            (user_id,)).fetchone()
        if not user:
            raise BillingError("Pick a registered user to bill.")
        meter = user["meter"]
        s = get_settings(conn)
        rate, fixed, delay = float(s["rate"]), float(s["fixed_charge"]), int(s["disconnect_delay"])

        latest = conn.execute("SELECT id, kwh FROM readings WHERE meter = ? ORDER BY id DESC LIMIT 1",
                              (meter,)).fetchone()
        if not latest:
            raise BillingError(f"No readings from Meter {meter} yet. Check the device is publishing to '{TOPIC_TX}'.")

        prev = conn.execute("SELECT to_reading_id, closing_kwh FROM bills WHERE meter = ? ORDER BY id DESC LIMIT 1",
                            (meter,)).fetchone()
        if prev:
            from_id, opening = prev["to_reading_id"], prev["closing_kwh"]
        else:
            first = conn.execute("SELECT kwh FROM readings WHERE meter = ? ORDER BY id LIMIT 1", (meter,)).fetchone()
            from_id, opening = 0, first["kwh"]

        units = conn.execute(
            "SELECT COALESCE(SUM(delta), 0) FROM readings WHERE meter = ? AND id > ? AND id <= ?",
            (meter, from_id, latest["id"])).fetchone()[0]
        units = round(units, 3)
        amount = round(units * rate + fixed, 2)
        if amount <= 0:
            raise BillingError(f"Nothing to bill: Meter {meter} has no consumption since the last bill. "
                               "Set a fixed charge in tariff settings to bill anyway.")

        created = now()
        cur = conn.execute(
            """INSERT INTO bills (user_id, meter, from_reading_id, to_reading_id, opening_kwh, closing_kwh,
                                  units, rate, fixed_charge, amount, created_at, disconnect_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user["id"], meter, from_id, latest["id"], opening, latest["kwh"], units, rate, fixed,
             amount, ts(created), ts(created + timedelta(seconds=delay))))
        return {"id": cur.lastrowid, "name": user["name"], "meter": meter,
                "units": units, "amount": amount, "delay": delay}


def pay_bill(bill_id, user_id, method):
    with DB_LOCK, db_conn() as conn:
        bill = conn.execute("SELECT * FROM bills WHERE id = ? AND user_id = ?", (bill_id, user_id)).fetchone()
        if not bill:
            raise BillingError("Bill not found.")
        if bill["status"] == "paid":
            raise BillingError("This bill is already paid.")
        txn = f"SIM{now():%y%m%d%H%M%S}{secrets.token_hex(2).upper()}"
        conn.execute("UPDATE bills SET status = 'paid', paid_at = ?, pay_method = ?, txn_ref = ? WHERE id = ?",
                     (ts(), method, txn, bill_id))
        still_overdue = conn.execute(
            "SELECT COUNT(*) FROM bills WHERE meter = ? AND status = 'unpaid' AND disconnected = 1",
            (bill["meter"],)).fetchone()[0]
        relay = conn.execute("SELECT state FROM relays WHERE meter = ?", (bill["meter"],)).fetchone()["state"]

    restored = False
    if still_overdue == 0 and relay == "disconnected":
        set_relay(bill["meter"], cut=False, source=f"bill #{bill_id} paid")
        restored = True
    notify_bill_event(bill_id, "receipt", restored=restored)
    return {"txn_ref": txn, "restored": restored, "meter": bill["meter"]}


def enforce_due_disconnects():
    with DB_LOCK, db_conn() as conn:
        due = conn.execute(
            "SELECT id, meter FROM bills WHERE status = 'unpaid' AND disconnected = 0 AND disconnect_at <= ?",
            (ts(),)).fetchall()
        for b in due:
            conn.execute("UPDATE bills SET disconnected = 1 WHERE id = ?", (b["id"],))
    for meter in sorted({b["meter"] for b in due}):
        ids = ", ".join(f"#{b['id']}" for b in due if b["meter"] == meter)
        set_relay(meter, cut=True, source=f"bill {ids} unpaid")
    for b in due:
        notify_bill_event(b["id"], "disconnected")


def enforcement_loop():
    while True:
        try:
            enforce_due_disconnects()
        except Exception:
            log.exception("Enforcement check failed")
        time.sleep(1)


# ---------------------------------------------------------------- snapshots for the UI
def meter_snapshot(conn, meter):
    latest = conn.execute("SELECT kwh, ts FROM readings WHERE meter = ? ORDER BY id DESC LIMIT 1",
                          (meter,)).fetchone()
    month_start = now().strftime("%Y-%m-01 00:00:00")
    month_units = conn.execute("SELECT COALESCE(SUM(delta), 0) FROM readings WHERE meter = ? AND ts >= ?",
                               (meter, month_start)).fetchone()[0]
    relay = conn.execute("SELECT state, updated_at FROM relays WHERE meter = ?", (meter,)).fetchone()
    owner = conn.execute("SELECT name FROM users WHERE meter = ?", (meter,)).fetchone()
    pending = conn.execute(
        """SELECT id, amount, disconnect_at, disconnected FROM bills
           WHERE meter = ? AND status = 'unpaid' ORDER BY disconnected DESC, disconnect_at ASC LIMIT 1""",
        (meter,)).fetchone()

    pend = None
    if pending:
        left = 0
        if not pending["disconnected"]:
            left = max(0, math.ceil((parse_ts(pending["disconnect_at"]) - now()).total_seconds()))
        pend = {"id": pending["id"], "amount": pending["amount"],
                "seconds_left": left, "disconnected": bool(pending["disconnected"])}

    return {
        "meter": meter,
        "owner": owner["name"] if owner else None,
        "kwh": latest["kwh"] if latest else None,
        "last_seen": latest["ts"] if latest else None,
        "seconds_since": (now() - parse_ts(latest["ts"])).total_seconds() if latest else None,
        "month_units": round(month_units, 3),
        "relay": relay["state"],
        "relay_updated": relay["updated_at"],
        "pending": pend,
    }


def bills_version(conn, user_id=None):
    sql = ("SELECT COUNT(*) AS c, COALESCE(SUM(status = 'paid'), 0) AS p, "
           "COALESCE(SUM(disconnected), 0) AS d FROM bills")
    row = conn.execute(sql + " WHERE user_id = ?", (user_id,)).fetchone() if user_id else conn.execute(sql).fetchone()
    return f"{row['c']}-{row['p']}-{row['d']}"


# ---------------------------------------------------------------- Flask app
init_db()
app = Flask(__name__)
with db_conn() as _c:
    app.secret_key = get_settings(_c)["secret_key"]


@app.template_filter("inr")
def inr(value):
    return f"₹{float(value or 0):,.2f}"


@app.template_filter("units")
def units_fmt(value):
    return f"{float(value or 0):,.3f}"


def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            is_api = request.path.startswith("/api/") or request.is_json
            if "user_id" not in session:
                if is_api:
                    return jsonify(ok=False, error="Log in first."), 401
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                if is_api:
                    return jsonify(ok=False, error="Not allowed for this account."), 403
                flash(f"That page is for the {role} account.", "error")
                return redirect(url_for("index"))
            return fn(*args, **kwargs)
        return inner
    return decorator


@app.route("/")
def index():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    if session.get("role") == "user":
        return redirect(url_for("user_dashboard"))
    return redirect(url_for("login"))


# ---- auth
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with db_conn() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session.clear()
            session.update(user_id=user["id"], name=user["name"], role=user["role"], meter=user["meter"])
            return redirect(url_for("index"))
        flash("Email or password is wrong.", "error")
    with db_conn() as conn:
        admin_exists = conn.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone() is not None
        user_count = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'user'").fetchone()[0]
    return render_template("login.html", admin_exists=admin_exists, user_slots=len(METERS) - user_count)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "ok")
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    return handle_register("user")


@app.route("/admin/register", methods=["GET", "POST"])
def admin_register():
    return handle_register("admin")


def handle_register(role):
    def availability(conn):
        admin_exists = conn.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone() is not None
        taken = {r["meter"] for r in conn.execute("SELECT meter FROM users WHERE role = 'user'")}
        return admin_exists, [m for m in METERS if m not in taken]

    with db_conn() as conn:
        admin_exists, free = availability(conn)
    closed = (role == "admin" and admin_exists) or (role == "user" and not free)

    form = {"name": "", "email": ""}
    if request.method == "POST" and not closed:
        form["name"] = request.form.get("name", "").strip()
        form["email"] = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        error = None
        if len(form["name"]) < 2:
            error = "Enter your full name."
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", form["email"]):
            error = "Enter a valid email address."
        elif len(password) < 6:
            error = "Password needs at least 6 characters."
        elif password != confirm:
            error = "Passwords don't match."

        if error:
            flash(error, "error")
        else:
            try:
                with DB_LOCK, db_conn() as conn:
                    admin_exists, free = availability(conn)
                    if role == "admin" and admin_exists:
                        raise ValueError("An admin account already exists.")
                    if role == "user" and not free:
                        raise ValueError("Both meters already have a user.")
                    meter = free[0] if role == "user" else None
                    conn.execute(
                        "INSERT INTO users (name, email, password, role, meter, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (form["name"], form["email"], generate_password_hash(password), role, meter, ts()))
            except sqlite3.IntegrityError:
                flash("That email is already registered.", "error")
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                msg = "Admin account created." if role == "admin" else f"Account created and linked to Meter {meter}."
                flash(msg + " Log in to continue.", "ok")
                return redirect(url_for("login"))

    return render_template("register.html", role=role, closed=closed,
                           next_meter=free[0] if free else None, form=form)


# ---- admin
@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    with db_conn() as conn:
        settings = get_settings(conn)
        users = conn.execute(
            "SELECT id, name, email, meter, created_at FROM users WHERE role = 'user' ORDER BY meter").fetchall()
        bills = conn.execute(
            """SELECT b.*, u.name FROM bills b JOIN users u ON u.id = b.user_id
               ORDER BY b.id DESC LIMIT 50""").fetchall()
        mqtt_log = conn.execute("SELECT * FROM mqtt_log ORDER BY id DESC LIMIT 40").fetchall()
        version = bills_version(conn)
        unpaid_total = conn.execute("SELECT COALESCE(SUM(amount), 0) FROM bills WHERE status = 'unpaid'").fetchone()[0]
        email_log = conn.execute("SELECT * FROM email_log ORDER BY id DESC LIMIT 15").fetchall()
    owners = {u["meter"]: u["name"] for u in users}
    return render_template("admin.html", settings=settings, users=users, owners=owners, bills=bills,
                           mqtt_log=mqtt_log, mqtt=bridge.status(), bills_version=version,
                           unpaid_total=unpaid_total, meters=METERS,
                           email_log=email_log, email_status=email_status())


@app.post("/admin/bills")
@login_required("admin")
def admin_generate_bill():
    try:
        bill = generate_bill(int(request.form.get("user_id", 0)))
    except (BillingError, ValueError) as exc:
        flash(str(exc) if isinstance(exc, BillingError) else "Pick a user to bill.", "error")
    else:
        notify_bill_event(bill["id"], "bill")
        flash(f"Bill #{bill['id']} for {bill['name']}: {inr(bill['amount'])} for {bill['units']:.3f} kWh. "
              f"Meter {bill['meter']} supply will be cut in {bill['delay']} seconds unless it's paid.", "ok")
    return redirect(url_for("admin_dashboard"))


@app.post("/admin/settings")
@login_required("admin")
def admin_settings():
    try:
        rate = float(request.form["rate"])
        fixed = float(request.form["fixed_charge"])
        delay = int(request.form["disconnect_delay"])
        if rate < 0 or fixed < 0 or not 5 <= delay <= 86400:
            raise ValueError
    except (KeyError, ValueError):
        flash("Rate and fixed charge must be zero or more; grace period between 5 and 86400 seconds.", "error")
        return redirect(url_for("admin_dashboard"))
    with DB_LOCK, db_conn() as conn:
        for key, value in (("rate", f"{rate:.2f}"), ("fixed_charge", f"{fixed:.2f}"), ("disconnect_delay", str(delay))):
            conn.execute("UPDATE settings SET value = ? WHERE key = ?", (value, key))
    flash("Tariff saved. New bills will use it.", "ok")
    return redirect(url_for("admin_dashboard"))


@app.post("/admin/relay")
@login_required("admin")
def admin_relay():
    try:
        meter = int(request.form.get("meter", 0))
    except ValueError:
        meter = 0
    action = request.form.get("action")
    if meter not in METERS or action not in ("connect", "disconnect"):
        flash("Unknown relay command.", "error")
        return redirect(url_for("admin_dashboard"))
    cut = action == "disconnect"
    sent = set_relay(meter, cut=cut, source="admin manual")
    command = f"R{meter}{'ON' if cut else 'OFF'}"
    if sent:
        flash(f"Sent {command}: Meter {meter} supply {'cut' if cut else 'restored'}.", "ok")
    else:
        flash(f"{command} saved but not sent. The broker is offline; check the connection.", "error")
    return redirect(url_for("admin_dashboard"))


def email_status():
    return {"configured": mailer.configured, "sender": EMAIL_SENDER, "transport": mailer.transport,
            "host": "api.brevo.com" if BREVO_API_KEY else SMTP_HOST,
            "port": SMTP_PORT, "app_url": APP_URL}


@app.post("/admin/email/test")
@login_required("admin")
def admin_test_email():
    with db_conn() as conn:
        admin = conn.execute("SELECT name, email FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    to = request.form.get("to", "").strip() or admin["email"]
    subject = "GridPay test email"
    sent_at = nice_time(now())
    html = render_email("test", subject=subject, preheader="Email sending works.", banner=None,
                        name=admin["name"].split()[0], sender=EMAIL_SENDER, host=SMTP_HOST, sent_at=sent_at)
    text = f"Hello,\n\nThis is a test email from GridPay sent at {sent_at}. Email sending is set up correctly.\n"
    ok, err = mailer.send_now(to, subject, text, html)
    flash(f"Test email sent to {to}. Check the inbox (and spam folder)." if ok else f"Test email failed: {err}",
          "ok" if ok else "error")
    return redirect(url_for("admin_dashboard"))


# ---- user
@app.route("/me")
@login_required("user")
def user_dashboard():
    meter, uid = session["meter"], session["user_id"]
    with db_conn() as conn:
        settings = get_settings(conn)
        rows = conn.execute(
            """SELECT substr(ts, 1, 7) AS month, SUM(delta) AS units, MIN(kwh) AS low, MAX(kwh) AS high,
                      COUNT(*) AS readings
               FROM readings WHERE meter = ? GROUP BY month ORDER BY month DESC LIMIT 12""",
            (meter,)).fetchall()
        bills = conn.execute("SELECT * FROM bills WHERE user_id = ? ORDER BY id DESC", (uid,)).fetchall()
        version = bills_version(conn, uid)

    rate = float(settings["rate"])
    months = [{
        "label": datetime.strptime(r["month"], "%Y-%m").strftime("%B %Y"),
        "units": round(r["units"] or 0, 3),
        "estimate": round((r["units"] or 0) * rate, 2),
        "readings": r["readings"],
        "high": r["high"],
    } for r in rows]
    peak = max([m["units"] for m in months] + [0.001])
    due = sum(b["amount"] for b in bills if b["status"] == "unpaid")
    return render_template("user.html", months=months, peak=peak, bills=bills, due=due,
                           rate=rate, meter=meter, bills_version=version, mqtt=bridge.status())


@app.post("/me/bills/<int:bill_id>/pay")
@login_required("user")
def user_pay(bill_id):
    method = request.form.get("method", "UPI")[:20]
    try:
        result = pay_bill(bill_id, session["user_id"], method)
    except BillingError as exc:
        return jsonify(ok=False, error=str(exc)), 400
    return jsonify(ok=True, **result)


# ---- JSON for live updates
@app.get("/api/status")
@login_required()
def api_status():
    with db_conn() as conn:
        if session["role"] == "admin":
            meters, version = [meter_snapshot(conn, m) for m in METERS], bills_version(conn)
        else:
            meters = [meter_snapshot(conn, session["meter"])]
            version = bills_version(conn, session["user_id"])
    return jsonify(meters=meters, mqtt=bridge.status(), bills_version=version)


@app.get("/api/log")
@login_required("admin")
def api_log():
    with db_conn() as conn:
        rows = conn.execute("SELECT ts, direction, topic, payload FROM mqtt_log ORDER BY id DESC LIMIT 40").fetchall()
    return jsonify(items=[dict(r) for r in rows])


# ---------------------------------------------------------------- run
def start_background():
    mailer.start()
    bridge.start()
    threading.Thread(target=enforcement_loop, name="enforcer", daemon=True).start()


if __name__ == "__main__":
    start_background()
    port = int(os.environ.get("PORT", "5000"))
    log.info("GridPay running on http://127.0.0.1:%s", port)
    # use_reloader=False so the MQTT client and enforcer start only once
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False, threaded=True)
