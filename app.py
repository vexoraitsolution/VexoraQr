"""
License Server — Vexora QR Generator
Secured: environment-based secrets, admin auth, rate limiting,
HMAC-SHA256 token signing, soft device binding, lifetime support.
"""

from flask import Flask, request, jsonify, g, redirect,render_template
from flask_cors import CORS
import psycopg2, psycopg2.pool
import hashlib, hmac, json, os, uuid, logging
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta

from zoneinfo import ZoneInfo
from functools import wraps
import base64

# Load .env BEFORE reading os.environ
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
except ImportError:
    pass
# ─────────────────────────────────────────
# CONFIG  (override via environment vars)
# ─────────────────────────────────────────
DB_HOST     = os.environ.get("DB_HOST")
DB_NAME     = os.environ.get("DB_NAME")
DB_USER     = os.environ.get("DB_USER")
DB_PASS     = os.environ.get("DB_PASS")          # never hardcode!
ADMIN_KEY   = os.environ.get("ADMIN_KEY")          # must be set in production
SECRET      = os.environ.get("LICENSE_SECRET")       # must be set in production
GRACE_DAYS = int(os.environ.get("GRACE_DAYS", 30))
# Warn loudly if critical secrets are missing
if not SECRET:
    logging.warning("WARNING: LICENSE_SECRET env var not set. Use a strong secret in production!")
    SECRET = "CHANGE_ME_IN_PRODUCTION"
if not ADMIN_KEY:
    logging.warning("WARNING: ADMIN_KEY env var not set. Admin endpoints are open!")

# ─────────────────────────────────────────
# FLASK + CORS
# ─────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": os.environ.get("ALLOWED_ORIGINS", "*")}})

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/qr-admin')
def qr_admin():
    return render_template('qr_admin.html')

# ─────────────────────────────────────────
# CONNECTION POOL  (replaces single conn)
# ─────────────────────────────────────────
_pool = None

def get_pool():
    global _pool
    if _pool is None:
        _pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=1, maxconn=10,
            host=DB_HOST, database=DB_NAME,
            user=DB_USER, password=DB_PASS
        )
    return _pool

def get_db():
    if "db" not in g:
        g.db = get_pool().getconn()
    return g.db

@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        get_pool().putconn(db)

# ─────────────────────────────────────────
# SIMPLE IN-MEMORY RATE LIMITER
# ─────────────────────────────────────────
_rate_limit = {}   # {ip: [timestamps]}
RATE_LIMIT_MAX   = int(os.environ.get("RATE_LIMIT_MAX", "100"))    # requests
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60")) # seconds

def rate_limited(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr or "unknown"
        now = datetime.now()
        window_start = now - timedelta(seconds=RATE_LIMIT_WINDOW)

        hits = _rate_limit.get(ip, [])
        hits = [t for t in hits if t > window_start]  # prune old hits
        if len(hits) >= RATE_LIMIT_MAX:
            logger.warning("Rate limit hit for IP %s", ip)
            return jsonify({"valid": False, "message": "Too many requests. Try again later."}), 429
        hits.append(now)
        _rate_limit[ip] = hits
        return f(*args, **kwargs)
    return wrapper

# ─────────────────────────────────────────
# ADMIN AUTH DECORATOR
# ─────────────────────────────────────────
def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        provided = request.headers.get("X-Admin-Key", "")
        if not ADMIN_KEY or not hmac.compare_digest(
            hmac.new(b"admin", provided.encode(), hashlib.sha256).hexdigest(),
            hmac.new(b"admin", ADMIN_KEY.encode(), hashlib.sha256).hexdigest()
        ):
            logger.warning("Unauthorized admin access attempt from %s", request.remote_addr)
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper

# ─────────────────────────────────────────
# TOKEN HELPERS
# ─────────────────────────────────────────
def _sign(data_str: str) -> str:
    return hmac.new(SECRET.encode(), data_str.encode(), hashlib.sha256).hexdigest()

def create_offline_token(license_key: str, device_id: str, expiry: str, max_devices: int, features: dict = None) -> str:
    # Ensure features is a dict
    features = features or {}
    # Make sure we sort keys for consistent signing if we ever used JSON string,
    # but here we'll just include a hash of the features in the raw or sign the whole json output.
    # To avoid changing the format too much, we will sign the standard items plus the features hash.
    feat_json = json.dumps(features, sort_keys=True)
    feat_hash = hashlib.sha256(feat_json.encode()).hexdigest()
    raw = f"{license_key}|{device_id}|{expiry}|{max_devices}|{feat_hash}"
    
    payload = {
        "license": license_key,
        "device":  device_id,
        "max_devices": max_devices,
        "features": features,
        "expiry":  expiry,
        "sig":     _sign(raw)
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()

def verify_offline_token(token: str, device_id: str) -> tuple[bool, str]:
    try:
        payload = json.loads(base64.b64decode(token.encode()))
        
        # Calculate raw based on features if present
        if "features" in payload:
            feat_json = json.dumps(payload["features"], sort_keys=True)
            feat_hash = hashlib.sha256(feat_json.encode()).hexdigest()
            raw = f"{payload['license']}|{payload['device']}|{payload['expiry']}|{payload.get('max_devices', 1)}|{feat_hash}"
        elif "max_devices" in payload:
            raw = f"{payload['license']}|{payload['device']}|{payload['expiry']}|{payload['max_devices']}"
        else:
            raw = f"{payload['license']}|{payload['device']}|{payload['expiry']}"

        if not hmac.compare_digest(_sign(raw), payload["sig"]):
            return False, "Invalid token signature"

        if payload["device"] != device_id:
            return False, "Device fingerprint mismatch"

        if payload["expiry"] != "lifetime":
            expiry_dt = datetime.fromisoformat(payload["expiry"])
            if datetime.now() > expiry_dt + timedelta(days=GRACE_DAYS):
                return False, "License expired"

        return True, "Valid"
    except Exception as exc:
        logger.exception("Token verification error")
        return False, "Malformed token"


DYNAMIC_QR_COLUMNS = [
    "short_code",
    "content_type",
    "content_data",
    "title",
    "created_at",
    "updated_at",
    "expiry_date",
    "scan_count",
    "last_scanned_at",
    "time_based_content",
    "created_by_user",
    "server_settings",
]


def _clone_default(default):
    if isinstance(default, dict):
        return dict(default)
    if isinstance(default, list):
        return list(default)
    return default


def _load_json(value, default):
    if value in (None, ""):
        return _clone_default(default)
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return _clone_default(default)


def _coerce_positive_int(value):
    if value in (None, ""):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _normalize_datetime(value):
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        dt_value = value
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            dt_value = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt_value.tzinfo is not None:
        dt_value = dt_value.astimezone().replace(tzinfo=None)
    return dt_value


def _isoformat(value):
    dt_value = _normalize_datetime(value)
    return dt_value.isoformat() if dt_value else None


def _normalize_clock_time(value, fallback):
    text = str(value or fallback).strip()
    try:
        parsed = datetime.strptime(text, "%H:%M")
        return parsed.strftime("%H:%M")
    except ValueError:
        return fallback


def _normalize_days(days):
    if isinstance(days, str):
        days = [part.strip() for part in days.split(",")]
    if not isinstance(days, list):
        return []
    valid = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
    normalized = []
    for day in days:
        token = str(day).strip().lower()[:3]
        if token in valid and token not in normalized:
            normalized.append(token)
    return normalized


def _normalize_time_based_content(raw):
    schedules = _load_json(raw, [])
    if not isinstance(schedules, list):
        return []

    cleaned = []
    for item in schedules:
        if not isinstance(item, dict):
            continue
        content_data = str(item.get("content_data") or item.get("content") or "").strip()
        mapping_key = str(item.get("mapping_key") or "").strip()
        if not content_data and not mapping_key:
            continue
        cleaned.append({
            "days": _normalize_days(item.get("days", [])),
            "start": _normalize_clock_time(item.get("start"), "00:00"),
            "end": _normalize_clock_time(item.get("end"), "23:59"),
            "content_type": str(item.get("content_type") or "url").strip() or "url",
            "content_data": content_data,
            "title": str(item.get("title") or "").strip(),
            "mapping_key": mapping_key,
        })
    return cleaned


def _normalize_content_mapping(raw):
    mapping = _load_json(raw, {})
    if not isinstance(mapping, dict):
        return {}

    cleaned = {}
    for key, value in mapping.items():
        map_key = str(key).strip()
        if not map_key or not isinstance(value, dict):
            continue
        content_data = str(value.get("content_data") or value.get("content") or "").strip()
        if not content_data:
            continue
        cleaned[map_key] = {
            "content_type": str(value.get("content_type") or "url").strip() or "url",
            "content_data": content_data,
            "title": str(value.get("title") or "").strip(),
        }
    return cleaned


def _hash_password(password: str) -> str:
    return hmac.new(SECRET.encode(), password.encode(), hashlib.sha256).hexdigest()


def _password_matches(expected_hash: str, candidate: str) -> bool:
    if not expected_hash or not candidate:
        return False
    return hmac.compare_digest(expected_hash, _hash_password(candidate))


def _merge_server_settings(existing, incoming):
    settings = dict(existing or {})
    updates = dict(incoming or {})

    if "scan_limit" in updates:
        scan_limit = _coerce_positive_int(updates.get("scan_limit"))
        if scan_limit:
            settings["scan_limit"] = scan_limit
        else:
            settings.pop("scan_limit", None)

    if "content_mapping" in updates:
        mapping = _normalize_content_mapping(updates.get("content_mapping"))
        if mapping:
            settings["content_mapping"] = mapping
            active_key = str(updates.get("active_mapping_key") or settings.get("active_mapping_key") or "").strip()
            if active_key not in mapping:
                active_key = next(iter(mapping))
            settings["active_mapping_key"] = active_key
        else:
            settings.pop("content_mapping", None)
            settings.pop("active_mapping_key", None)
    elif "active_mapping_key" in updates and settings.get("content_mapping"):
        active_key = str(updates.get("active_mapping_key") or "").strip()
        if active_key in settings["content_mapping"]:
            settings["active_mapping_key"] = active_key

    if "password" in updates or updates.get("remove_password"):
        password = str(updates.get("password") or "").strip()
        if password:
            settings["password_hash"] = _hash_password(password)
        else:
            settings.pop("password_hash", None)

    return settings


def _public_server_settings(settings):
    public = {}
    scan_limit = _coerce_positive_int((settings or {}).get("scan_limit"))
    if scan_limit:
        public["scan_limit"] = scan_limit
    if (settings or {}).get("content_mapping"):
        public["content_mapping"] = settings["content_mapping"]
        public["active_mapping_key"] = settings.get("active_mapping_key")
    public["password_enabled"] = bool((settings or {}).get("password_hash"))
    return public


def _dynamic_row_to_record(row):
    if not row:
        return None
    return dict(zip(DYNAMIC_QR_COLUMNS, row))


def _fetch_dynamic_qr(cur, short_code):
    cur.execute(
        """
        SELECT short_code, content_type, content_data, title, created_at, updated_at,
               expiry_date, scan_count, last_scanned_at, time_based_content,
               created_by_user, server_settings
          FROM dynamic_qrs
         WHERE short_code = %s
        """,
        (short_code,),
    )
    return _dynamic_row_to_record(cur.fetchone())


def _get_owner_features(db, owner_identifier):
    if not owner_identifier:
        return {}
    cur = db.cursor()
    cur.execute(
        """
        SELECT l.features, p.features
          FROM licenses l
          LEFT JOIN plans p ON l.plan_id = p.id
         WHERE l.license_key = %s
        """,
        (owner_identifier,),
    )
    row = cur.fetchone()
    if not row:
        return {}
    license_features = row[0] if isinstance(row[0], dict) else _load_json(row[0], {})
    plan_features = row[1] if isinstance(row[1], dict) else _load_json(row[1], {})
    return {**plan_features, **license_features}


def _resolve_scan_limit(db, record, settings):
    scan_limit = _coerce_positive_int((settings or {}).get("scan_limit"))
    if scan_limit:
        return scan_limit
    owner_identifier = record.get("created_by_user")
    features = _get_owner_features(db, owner_identifier)
    return _coerce_positive_int(features.get("max_scans"))


def _apply_mapping_choice(base_content, settings, mapping_key=None):
    mapping = (settings or {}).get("content_mapping") or {}
    if not mapping:
        return dict(base_content)

    active_key = mapping_key or settings.get("active_mapping_key")
    if active_key and active_key in mapping:
        selected = mapping[active_key]
        return {
            "content_type": selected.get("content_type") or base_content["content_type"],
            "content_data": selected.get("content_data") or base_content["content_data"],
            "title": selected.get("title") or base_content["title"],
        }
    return dict(base_content)


def _resolve_dynamic_content(record, access_time=None):
    when = access_time or datetime.now()
    settings = _load_json(record.get("server_settings"), {})
    base_content = {
        "content_type": record.get("content_type") or "url",
        "content_data": record.get("content_data") or "",
        "title": record.get("title") or "",
    }
    resolved = _apply_mapping_choice(base_content, settings)
    schedules = _normalize_time_based_content(record.get("time_based_content"))
    weekday = when.strftime("%a").lower()[:3]
    current_time = when.strftime("%H:%M")

    for schedule in schedules:
        days = schedule.get("days") or []
        if days and weekday not in days:
            continue
        if schedule["start"] <= current_time <= schedule["end"]:
            if schedule.get("mapping_key"):
                resolved = _apply_mapping_choice(resolved, settings, schedule["mapping_key"])
            elif schedule.get("content_data"):
                resolved = {
                    "content_type": schedule.get("content_type") or resolved["content_type"],
                    "content_data": schedule.get("content_data") or resolved["content_data"],
                    "title": schedule.get("title") or resolved["title"],
                }
            break
    return resolved


def _dynamic_qr_status(db, record, access_time=None):
    when = access_time or datetime.now()
    settings = _load_json(record.get("server_settings"), {})
    expiry_date = _normalize_datetime(record.get("expiry_date"))
    scan_count = int(record.get("scan_count") or 0)
    scan_limit = _resolve_scan_limit(db, record, settings)

    expired = bool(expiry_date and when > expiry_date)
    scan_limit_reached = bool(scan_limit and scan_count >= scan_limit)

    if expired:
        status = "expired"
        message = "This QR code has passed its expiry date and is no longer active."
    elif scan_limit_reached:
        status = "scan_limit_reached"
        message = "This QR code has reached its scan limit and is no longer serving content."
    else:
        status = "active"
        message = "This QR code is active."

    return {
        "status": status,
        "status_message": message,
        "expiry_status": "Expired" if expired else "Active",
        "scan_limit": scan_limit,
        "scan_limit_reached": scan_limit_reached,
        "expired": expired,
    }


def _serialize_dynamic_qr(db, record, access_time=None):
    when = access_time or datetime.now()
    resolved = _resolve_dynamic_content(record, when)
    settings = _load_json(record.get("server_settings"), {})
    status = _dynamic_qr_status(db, record, when)
    return {
        "short_code": record.get("short_code"),
        "qr_type": "dynamic",
        "title": resolved.get("title") or record.get("title") or "",
        "content_type": resolved.get("content_type") or record.get("content_type") or "url",
        "content_data": resolved.get("content_data") or record.get("content_data") or "",
        "scan_count": int(record.get("scan_count") or 0),
        "last_scanned_at": _isoformat(record.get("last_scanned_at")),
        "expiry_date": _isoformat(record.get("expiry_date")),
        "created_at": _isoformat(record.get("created_at")),
        "updated_at": _isoformat(record.get("updated_at")),
        "time_based_content": _normalize_time_based_content(record.get("time_based_content")),
        "server_settings": _public_server_settings(settings),
        "status": status["status"],
        "status_message": status["status_message"],
        "expiry_status": status["expiry_status"],
        "scan_limit": status["scan_limit"],
        "scan_limit_reached": status["scan_limit_reached"],
        "password_enabled": bool(settings.get("password_hash")),
    }


def _request_server_settings(data, existing=None):
    incoming = _load_json(data.get("server_settings"), {}) if isinstance(data, dict) else {}
    for key in ("scan_limit", "password", "remove_password", "content_mapping", "active_mapping_key"):
        if isinstance(data, dict) and key in data and key not in incoming:
            incoming[key] = data.get(key)
    return _merge_server_settings(existing or {}, incoming)


def _update_dynamic_qr_record(db, record, data):
    cur = db.cursor()
    existing_settings = _load_json(record.get("server_settings"), {})
    existing_time_based = _normalize_time_based_content(record.get("time_based_content"))

    content_data = str(data.get("content_data") or "").strip() or record.get("content_data") or ""
    content_type = str(data.get("content_type") or record.get("content_type") or "url").strip() or "url"
    title = str(data.get("title") or record.get("title") or "").strip()

    expiry_source = data.get("expiry_date", data.get("expire_at"))
    expiry_date = _normalize_datetime(expiry_source) if expiry_source is not None else _normalize_datetime(record.get("expiry_date"))

    time_source = data.get("time_based_content", data.get("time_schedules"))
    time_based_content = (
        _normalize_time_based_content(time_source)
        if time_source is not None
        else existing_time_based
    )
    server_settings = _request_server_settings(data, existing_settings)

    cur.execute(
        """
        UPDATE dynamic_qrs
           SET content_type = %s,
               content_data = %s,
               title = %s,
               expiry_date = %s,
               time_based_content = %s,
               server_settings = %s,
               updated_at = NOW()
         WHERE short_code = %s
        """,
        (
            content_type,
            content_data,
            title,
            expiry_date,
            json.dumps(time_based_content) if time_based_content else None,
            json.dumps(server_settings),
            record["short_code"],
        ),
    )
    db.commit()
    return _fetch_dynamic_qr(cur, record["short_code"])

# ─────────────────────────────────────────
# ROUTES — PUBLIC
# ─────────────────────────────────────────
@app.route("/activate", methods=["POST"])
@rate_limited
def activate():
    data = request.get_json(silent=True) or {}
    license_key = (data.get("license_key") or "").strip()
    device_id   = (data.get("device_id")   or "").strip()
    max_devices = (data.get("max_devices")   or "").strip()

    if not license_key or not device_id:
        return jsonify({"valid": False, "message": "Missing license_key or device_id"}), 400

    try:
        db  = get_db()
        cur = db.cursor()
        cur.execute(
            """SELECT l.expiry_date, l.is_active, l.max_devices, l.devices, p.features, p.name as plan_name, l.features as custom_features
               FROM licenses l
               LEFT JOIN plans p ON l.plan_id = p.id
               WHERE l.license_key = %s""",
            (license_key,)
        )
        row = cur.fetchone()

        if not row:
            logger.info("Activation attempt with unknown key: %s", license_key[:8] + "****")
            return jsonify({"valid": False, "message": "Invalid license key"}), 403

        expiry, is_active, max_devices, devices_json, features_json, plan_name, custom_features_json = row
        devices = devices_json if isinstance(devices_json, list) else json.loads(devices_json or "[]")
        p_features = features_json if isinstance(features_json, dict) else json.loads(features_json or "{}")
        c_features = custom_features_json if isinstance(custom_features_json, dict) else json.loads(custom_features_json or "{}")
        
        # License features override Plan features
        features = { **p_features, **c_features }
        
        if plan_name:
            features["plan_name"] = plan_name

        if not is_active:
            return jsonify({"valid": False, "message": "License is inactive"}), 403

        # Expiry check (None == lifetime)
        expiry_str = "lifetime"
        if expiry is not None:
            if datetime.now() > expiry:
                return jsonify({"valid": False, "message": "License has expired"}), 403
            expiry_str = expiry.isoformat()

        # Device binding: bind first device, check subsequent
        if device_id not in devices:
            if len(devices) >= max_devices:
                return jsonify({"valid": False, "message": "Max device limit reached"}), 403
            devices.append(device_id)
            cur.execute(
                "UPDATE licenses SET devices = %s WHERE license_key = %s",
                (json.dumps(devices), license_key)
            )
            db.commit()
            logger.info("New device bound to license %s", license_key[:8] + "****")

        token = create_offline_token(license_key, device_id, expiry_str, max_devices, features)
        return jsonify({"valid": True, "offline_token": token, "expiry": expiry_str, "features": features})

    except Exception:
        logger.exception("Activation error")
        return jsonify({"valid": False, "message": "Server error"}), 500

@app.route("/api/update_dynamic_qr", methods=["POST"])
@rate_limited
def update_dynamic_qr_post():
    """Compatibility endpoint for updating an existing dynamic QR."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"ok": False, "message": "Missing Bearer token"}), 401
    token = auth_header.split(" ")[1]
    device_id = request.headers.get("X-Device-Id", "")
    ok, msg = verify_offline_token(token, device_id)
    if not ok:
        return jsonify({"ok": False, "message": msg}), 401
    try:
        payload = json.loads(base64.b64decode(token.encode()))
        owner_identifier = payload.get("license")
        features = payload.get("features", {})
        if not features.get("dynamic_qrs", False):
            return jsonify({"ok": False, "message": "Your plan does not support dynamic QR sync"}), 403

        data = request.get_json(silent=True) or {}
        short_code = (data.get("short_code") or "").strip()
        if not short_code:
            return jsonify({"error": "short_code is required"}), 400

        db = get_db()
        cur = db.cursor()
        record = _fetch_dynamic_qr(cur, short_code)
        if not record:
            return jsonify({"error": "QR not found"}), 404
        if record.get("created_by_user") != owner_identifier:
            return jsonify({"error": "Not authorized"}), 403
        updated_record = _update_dynamic_qr_record(db, record, data)
        return jsonify({"ok": True, "short_code": short_code, "qr": _serialize_dynamic_qr(db, updated_record)})
    except Exception:
        logger.exception("update_dynamic_qr_post error")
        return jsonify({"error": "Server error"}), 500




@app.route("/api/extend_license", methods=["POST"])
@rate_limited
@require_admin  
def extend_license():
    """Extend an existing license"""
    db = None
    cur = None
    
    try:
        form_data = request.get_json(silent=True) or {}
        license_key = form_data.get("license_key")
        duration = form_data.get("duration")
        expiry_date = form_data.get("expiryDate")
        custom = form_data.get("custom", False)

        if not license_key:
            return jsonify({"error": "license_key is required"}), 400
        
        db = get_db()
        cur = db.cursor()
        
        # Fetch license
        cur.execute(
            "SELECT expiry_date, is_active FROM licenses WHERE license_key = %s",
            (license_key,)
        )
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "License not found"}), 404
        
        current_expiry, is_active = row

        # banned check
        if str(is_active).lower() == 'false':
            return jsonify({"error": "Cannot extend a banned license"}), 400

        # timezone
        sri_lanka = ZoneInfo("Asia/Colombo")
        utc = ZoneInfo("UTC")
        now = datetime.now(utc)

        # normalize db datetime
        if current_expiry and current_expiry.tzinfo is None:
            current_expiry = current_expiry.replace(tzinfo=utc)

        # ----------------------------
        # CUSTOM DATE
        # ----------------------------
        if custom and expiry_date:
            new_expiry = datetime.fromtimestamp(int(expiry_date) / 1000, tz=utc)
            renewal_type = "custom"

        # ----------------------------
        # LIFETIME
        # ----------------------------
        elif str(duration).lower() == "lifetime":
            new_expiry = None
            renewal_type = "lifetime"

        # ----------------------------
        # NORMAL EXTENSION
        # ----------------------------
        else:
            duration = int(duration)

            if current_expiry and current_expiry > now:
                new_expiry = current_expiry + relativedelta(days=duration)
                renewal_type = "extension"
            else:
                new_expiry = now + relativedelta(days=duration)
                renewal_type = "reactivation"

        db_duration = None
        
        if new_expiry:
            if current_expiry:
                diff = new_expiry - current_expiry
            else:
                diff = new_expiry - now
        
            db_duration = diff.days
        
        cur.execute(
            "UPDATE licenses SET expiry_date = %s , duration = %s WHERE license_key = %s",
            (new_expiry, db_duration, license_key)
        )
        db.commit()

        # format response
        if new_expiry:
            display_expiry = new_expiry.astimezone(sri_lanka).strftime("%Y-%m-%d %H:%M:%S %Z")
        else:
            display_expiry = "Lifetime"

        return jsonify({
            "success": True,
            "license_key": license_key,
            "expiry_date": display_expiry,
            "renewal_type": renewal_type,
            "message": "License extended successfully"
        })

    except Exception as e:
        logger.exception("extend_license error")
        return jsonify({"error": str(e)}), 500
    finally:
        if cur:
            cur.close()
        if db:
            db.close()

@app.route("/api/renew_license", methods=["POST"])
@rate_limited
@require_admin
def renew_license():
    """Renew an existing license"""
    db = None
    cur = None
    
    try:
        # Get input
        form_data = request.get_json(silent=True) or {}
        license_key = form_data.get("license_key")
        if not license_key:
            return jsonify({"error": "license_key is required"}), 400
        
        db = get_db()
        cur = db.cursor()
        
        # Fetch current license
        cur.execute(
            "SELECT expiry_date, is_active, duration FROM licenses WHERE license_key = %s",
            (license_key,)
        )
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "License not found"}), 404
        
        current_expiry, is_active, duration = row
        duration = int(duration)
        
        # Lifetime check
        if current_expiry is None:
            return jsonify({"error": "Lifetime licenses cannot be renewed"}), 400
        
        # Banned check
        if str(is_active).lower() == 'false':
            return jsonify({"error": "Cannot renew a banned license"}), 400
        
        # --- Timezone setup ---
        sri_lanka = ZoneInfo("Asia/Colombo")
        utc = ZoneInfo("UTC")
        now = datetime.now(utc)
        
        # Normalize DB datetime to UTC
        if current_expiry.tzinfo is None:
            current_expiry = current_expiry.replace(tzinfo=utc)
        
        # --- Calculate new expiry ---
        if current_expiry > now:
            # Active: extend by duration months (same calendar day)
            new_expiry = current_expiry + relativedelta(days=duration)
            renewal_type = "extension"
        else:
            # Expired: start from today
            new_expiry = now + relativedelta(days=duration)
            renewal_type = "reactivation"
        
        # --- Store in DB as UTC naive (timezone safe) ---
        new_expiry_utc = new_expiry.astimezone(utc).replace(tzinfo=None)
        
        cur.execute(
            """UPDATE licenses
               SET expiry_date = %s,
                   updated_at = CURRENT_TIMESTAMP,
                   is_active = 'true'
               WHERE license_key = %s""",
            (new_expiry_utc, license_key)
        )
        db.commit()
        
        # Fetch updated license
        cur.execute("""
            SELECT id, license_key, expiry_date, max_devices, devices,
                   plan_id, features, created_at, updated_at, is_active
            FROM licenses
            WHERE license_key = %s
        """, (license_key,))
        
        renewed_license = cur.fetchone()
        
        if renewed_license and hasattr(cur, 'description'):
            columns = [desc[0] for desc in cur.description]
            license_dict = dict(zip(columns, renewed_license))
        else:
            license_dict = renewed_license
        
        # --- Convert expiry to Sri Lanka for response ---
        display_expiry = new_expiry.astimezone(sri_lanka)
        
        logger.info(f"License renewed: {license_key} - {renewal_type} until {display_expiry}")
        
        return jsonify({
            "success": True,
            "license": license_dict,
            "renewal_type": renewal_type,
            "new_expiry_date": display_expiry.isoformat(),
            "message": "License renewed successfully"
        })
        
    except Exception as e:
        if db:
            db.rollback()
        logger.exception("renew_license error")
        return jsonify({"error": "Server error"}), 500
        
    finally:
        if cur:
            cur.close()
        if db:
            db.close()

@app.route("/api/dynamic_qr", methods=["POST"])
@rate_limited
def create_dynamic_qr():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"valid": False, "message": "Missing Bearer token"}), 401
    token = auth_header.split(" ")[1]
    
    
    device_id = request.headers.get("X-Device-Id", "")
    ok, msg = verify_offline_token(token, device_id)
    if not ok:
        return jsonify({"valid": False, "message": msg}), 401
        
    try:
        payload = json.loads(base64.b64decode(token.encode()))
        owner_identifier = payload.get("license")
        features = payload.get("features", {})

        if not features.get("customize", False):
            return jsonify({"valid": False, "message": "Your plan does not support dynamic embedded QR sync"}), 403


        if not features.get("dynamic_qrs", False):
            return jsonify({"valid": False, "message": "Your plan does not support dynamic embedded QR sync"}), 403

        data = request.get_json(silent=True) or {}
        content_type = str(data.get("content_type") or "url").strip() or "url"
        content_data = str(data.get("content_data") or "").strip()
        title = str(data.get("title") or "").strip()
        
        if not content_data:
            return jsonify({"error": "Missing content_data"}), 400

        short_code = uuid.uuid4().hex[:8]
        expiry_date = _normalize_datetime(data.get("expiry_date", data.get("expire_at")))
        time_based_content = _normalize_time_based_content(data.get("time_based_content", data.get("time_schedules")))
        server_settings = _request_server_settings(data, {})

        db = get_db()
        cur = db.cursor()
        cur.execute(
            """
            INSERT INTO dynamic_qrs
                (short_code, content_type, content_data, title, expiry_date,
                 time_based_content, created_by_user, server_settings)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                short_code,
                content_type,
                content_data,
                title,
                expiry_date,
                json.dumps(time_based_content) if time_based_content else None,
                owner_identifier,
                json.dumps(server_settings),
            ),
        )
        db.commit()
        record = _fetch_dynamic_qr(cur, short_code)
        return jsonify({
            "success": True,
            "short_code": short_code,
            "dynamic_url": f"{request.host_url.rstrip('/')}/q/{short_code}",
            "qr": _serialize_dynamic_qr(db, record),
        })
    except Exception:
        logger.exception("Error creating dynamic qr")
        return jsonify({"error": "Failed to create dynamic QR"}), 500


@app.route("/api/dynamic_qrs", methods=["GET"])
@rate_limited
def list_dynamic_qrs():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Bearer token"}), 401
    token = auth_header.split(" ")[1]
    device_id = request.headers.get("X-Device-Id", "")
    ok, msg = verify_offline_token(token, device_id)
    if not ok:
        return jsonify({"error": msg}), 401

    try:
        payload = json.loads(base64.b64decode(token.encode()))
        owner_identifier = payload.get("license")
        db = get_db()
        cur = db.cursor()
        cur.execute(
            """
            SELECT short_code, content_type, content_data, title, created_at, updated_at,
                   expiry_date, scan_count, last_scanned_at, time_based_content,
                   created_by_user, server_settings
              FROM dynamic_qrs
             WHERE created_by_user = %s
             ORDER BY created_at DESC
            """,
            (owner_identifier,),
        )
        records = [_dynamic_row_to_record(row) for row in cur.fetchall()]
        return jsonify([_serialize_dynamic_qr(db, record) for record in records])
    except Exception:
        logger.exception("list_dynamic_qrs error")
        return jsonify({"error": "Server error"}), 500


@app.route("/q/<short_code>", methods=["GET", "POST"])
def visit_dynamic_qr(short_code):
    
    try:
        db = get_db()
        cur = db.cursor()
        record = _fetch_dynamic_qr(cur, short_code)

        if not record:
            return _error_page("QR Code Not Found", "This QR code does not exist or has been removed."), 404
        expire_at = record.get("expiry_date")
        if expire_at:
            try:
                exp_dt = datetime.fromisoformat(str(expire_at))
                if datetime.now() > exp_dt:
                    db.commit()
                    return _error_page("Link Expired",
                                       "This QR code has passed its expiry date and is no longer active."), 410
            except Exception:
                pass  # malformed date — keep serving
        # Password protection check
        settings = _load_json(record.get("server_settings"), {})
        password_hash = settings.get("password_hash")
        provided_password = (request.values.get("password") or "").strip()
        
        if password_hash and not _password_matches(password_hash, provided_password):
            message = "Enter the password to view this QR content."
            if provided_password:
                message = "That password is incorrect. Please try again."
            status_code = 401 if provided_password else 200
            return _password_page(record.get("title") or "Protected QR", short_code, message, bool(provided_password)), status_code

        # Update scan count
        now = datetime.now()
        cur.execute(
            """UPDATE dynamic_qrs SET scan_count = scan_count + 1, last_scanned_at = NOW()
               WHERE short_code = %s""",
            (short_code,),
        )
        
        new_count = int(record.get("scan_count") or 0) + 1
        record["scan_count"] = new_count
        record["last_scanned_at"] = now
        
        # Check status (expiry, scan limits)
        status = _dynamic_qr_status(db, record, now)
        db.commit()

        if status["expired"]:
            return _error_page("Expired QR", status["status_message"]), 410
        if status["scan_limit"] and new_count > status["scan_limit"]:
            return _error_page("Scan Limit Reached", status["status_message"]), 403

        # Resolve content
        resolved = _resolve_dynamic_content(record, now)
        content_data = (resolved.get("content_data") or "").strip()
        
        if not content_data:
            return _error_page("Content Unavailable", "This QR code does not currently have active content configured."), 503
        
        # Redirect for URLs
        if resolved.get("content_type") == "url":
            return redirect(content_data, code=302)

        # Display content page for other types
        plural = "s" if new_count != 1 else ""
        display_title = resolved.get("title") or record.get("title") or "QR Content"
        return _content_page(display_title, content_data, new_count, plural)
        
    except Exception:
        logger.exception("Error fetching dynamic QR")
        return _error_page("Server Error", "Something went wrong. Please try again later."), 500


def _error_page(heading, message):
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vexora QR — {heading}</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:-apple-system,'Segoe UI',sans-serif;background:#f8fafc;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}}.card{{background:#fff;border:1px solid #e2e8f0;border-radius:16px;box-shadow:0 20px 60px rgba(79,70,229,.1);max-width:480px;width:100%;overflow:hidden}}.stripe{{height:4px;background:linear-gradient(90deg,#4f46e5,#818cf8,#a5b4fc)}}.body{{padding:32px}}.brand{{display:flex;align-items:center;gap:10px;margin-bottom:24px;font-size:.85rem;color:#64748b;font-weight:600}}.brand-icon{{width:30px;height:30px;background:linear-gradient(135deg,#4f46e5,#818cf8);border-radius:8px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:.9rem}}h2{{font-size:1.1rem;color:#dc2626;margin-bottom:12px;font-weight:700}}p{{color:#64748b;font-size:.9rem;line-height:1.6}}</style></head>
<body><div class="card"><div class="stripe"></div><div class="body">
<div class="brand"><div class="brand-icon">&#9889;</div>Vexora QR</div>
<h2>&#9888; {heading}</h2><p>{message}</p>
</div></div></body></html>"""


def _password_page(title, short_code, message, invalid=False):
    import html as _html

    safe_title = _html.escape(title)
    safe_message = _html.escape(message)
    safe_action = _html.escape(f"/q/{short_code}")
    border = "#fecaca" if invalid else "#c7d2fe"
    background = "#fef2f2" if invalid else "#eef2ff"
    accent = "#dc2626" if invalid else "#4f46e5"
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vexora QR â€” Protected</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:-apple-system,'Segoe UI',sans-serif;background:#f8fafc;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}}.card{{background:#fff;border:1px solid #e2e8f0;border-radius:16px;box-shadow:0 20px 60px rgba(79,70,229,.1);max-width:480px;width:100%;overflow:hidden}}.stripe{{height:4px;background:linear-gradient(90deg,#4f46e5,#818cf8,#a5b4fc)}}.body{{padding:32px}}.brand{{display:flex;align-items:center;gap:10px;margin-bottom:24px;font-size:.85rem;color:#64748b;font-weight:600}}.brand-icon{{width:30px;height:30px;background:linear-gradient(135deg,#4f46e5,#818cf8);border-radius:8px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:.9rem}}h2{{font-size:1.1rem;color:#0f172a;margin-bottom:10px;font-weight:700}}p{{color:#64748b;font-size:.92rem;line-height:1.6;margin-bottom:18px}}.notice{{background:{background};border:1px solid {border};color:{accent};padding:12px 14px;border-radius:10px;margin-bottom:18px;font-size:.85rem}}form{{display:flex;flex-direction:column;gap:12px}}input{{width:100%;padding:12px 14px;border:1px solid #cbd5e1;border-radius:10px;font-size:.95rem}}button{{background:{accent};border:none;color:#fff;padding:12px 14px;border-radius:10px;font-weight:600;cursor:pointer}}</style></head>
<body><div class="card"><div class="stripe"></div><div class="body">
<div class="brand"><div class="brand-icon">&#9889;</div>Vexora QR</div>
<div class="notice">{safe_message}</div>
<p>This QR code is protected. Enter the server password to continue.</p>
<form method="POST" action="{safe_action}">
<input type="password" name="password" placeholder="Enter password" autocomplete="current-password" required>
<button type="submit">Unlock QR Content</button>
</form>
</div></div></body></html>"""


def _content_page(title, content, scan_count, plural):
    import html as _html
    safe_title = _html.escape(title)
    safe_content = _html.escape(content)
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vexora QR — {safe_title}</title>
<style>*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:-apple-system,'Segoe UI',sans-serif;background:#f8fafc;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}}.card{{background:#fff;border:1px solid #e2e8f0;border-radius:16px;box-shadow:0 20px 60px rgba(79,70,229,.1);max-width:520px;width:100%;overflow:hidden}}.stripe{{height:4px;background:linear-gradient(90deg,#4f46e5,#818cf8,#a5b4fc)}}.body{{padding:32px}}.brand{{display:flex;align-items:center;gap:10px;margin-bottom:24px;font-size:.85rem;color:#64748b;font-weight:600}}.brand-icon{{width:30px;height:30px;background:linear-gradient(135deg,#4f46e5,#818cf8);border-radius:8px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:.9rem}}h2{{font-size:1.1rem;color:#0f172a;margin-bottom:14px;font-weight:700}}.content{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:18px;font-size:.95rem;color:#334155;line-height:1.7;word-break:break-word;white-space:pre-wrap}}.meta{{margin-top:20px;padding-top:14px;border-top:1px solid #f1f5f9;display:flex;justify-content:space-between;font-size:.78rem;color:#94a3b8}}.badge{{background:#f0fdf4;color:#16a34a;border:1px solid #bbf7d0;padding:3px 10px;border-radius:999px;font-size:.75rem;font-weight:600}}</style></head>
<body><div class="card"><div class="stripe"></div><div class="body">
<div class="brand"><div class="brand-icon">&#9889;</div>Vexora QR</div>
<h2>{safe_title}</h2>
<div class="content">{safe_content}</div>
<div class="meta"><span class="badge">&#128065; Scanned {scan_count} time{plural}</span><span>Powered by Vexora IT Solution</span></div>
</div></div></body></html>"""


# ─────────────────────────────────────────
# ROUTE — RECORD QR SCAN (called by client after each QR generation)
# ─────────────────────────────────────────
@app.route("/api/record-scan", methods=["POST"])
@rate_limited
def record_scan():
    """Increment qr_scan_count for the license that belongs to this device."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"ok": False, "message": "Missing Bearer token"}), 401
    token = auth_header.split(" ")[1]

    device_id = request.headers.get("X-Device-Id", "")
    ok, msg = verify_offline_token(token, device_id)
    if not ok:
        return jsonify({"ok": False, "message": msg}), 401

    try:
        payload = json.loads(base64.b64decode(token.encode()))
        license_key = payload.get("license")
        if not license_key:
            return jsonify({"ok": False, "message": "No license in token"}), 400

        db = get_db()
        cur = db.cursor()
        cur.execute(
            "UPDATE licenses SET qr_scan_count = qr_scan_count + 1 WHERE license_key = %s",
            (license_key,)
        )
        db.commit()
        # Return new total
        cur.execute("SELECT qr_scan_count FROM licenses WHERE license_key = %s", (license_key,))
        row = cur.fetchone()
        return jsonify({"ok": True, "qr_scan_count": row[0] if row else 0})
    except Exception:
        logger.exception("record_scan error")
        return jsonify({"ok": False, "message": "Server error"}), 500


@app.route("/verify", methods=["POST"])
@rate_limited
def verify():
    """Verify an offline token without touching the DB (fully offline)."""
    data = request.get_json(silent=True) or {}
    token     = (data.get("token")     or "").strip()
    device_id = (data.get("device_id") or "").strip()

    if not token or not device_id:
        return jsonify({"valid": False, "message": "Missing token or device_id"}), 400

    ok, msg = verify_offline_token(token, device_id)
    return jsonify({"valid": ok, "message": msg})


# ─────────────────────────────────────────
# GET /api/scan-counts — Per-QR scan counts for this license
# ─────────────────────────────────────────
@app.route("/api/scan-counts", methods=["GET"])
@rate_limited
def get_scan_counts():
    """Return {short_code: scan_count} for all dynamic QRs owned by this license."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing Bearer token"}), 401
    token = auth_header.split(" ")[1]
    device_id = request.headers.get("X-Device-Id", "")
    ok, msg = verify_offline_token(token, device_id)
    if not ok:
        return jsonify({"error": msg}), 401
    try:
        payload = json.loads(base64.b64decode(token.encode()))
        owner_identifier = payload.get("license")
        db = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT short_code, scan_count FROM dynamic_qrs WHERE created_by_user = %s",
            (owner_identifier,)
        )
        rows = cur.fetchall()
        return jsonify({r[0]: r[1] for r in rows})
    except Exception:
        logger.exception("get_scan_counts error")
        return jsonify({}), 500


# ─────────────────────────────────────────
# PUT /api/dynamic_qr/<short_code> — Update dynamic QR content
# ─────────────────────────────────────────
@app.route("/api/dynamic_qr/<short_code>", methods=["PUT"])
@rate_limited
def update_dynamic_qr(short_code):
    """Update the latest server-side content and settings for a dynamic QR."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"ok": False, "message": "Missing Bearer token"}), 401
    token = auth_header.split(" ")[1]
    device_id = request.headers.get("X-Device-Id", "")
    ok, msg = verify_offline_token(token, device_id)
    if not ok:
        return jsonify({"ok": False, "message": msg}), 401
    try:
        payload = json.loads(base64.b64decode(token.encode()))
        owner_identifier = payload.get("license")
        data = request.get_json(silent=True) or {}
        db = get_db()
        cur = db.cursor()
        record = _fetch_dynamic_qr(cur, short_code)
        if not record:
            return jsonify({"error": "QR not found"}), 404
        if record.get("created_by_user") != owner_identifier:
            return jsonify({"error": "Not authorized"}), 403
        updated_record = _update_dynamic_qr_record(db, record, data)
        return jsonify({"ok": True, "short_code": short_code, "qr": _serialize_dynamic_qr(db, updated_record)})
    except Exception:
        logger.exception("update_dynamic_qr error")
        return jsonify({"error": "Server error"}), 500



# ─────────────────────────────────────────
# ROUTES — ADMIN  (protected by X-Admin-Key header)
# ─────────────────────────────────────────
@app.route("/admin/create", methods=["POST"])
@rate_limited
@require_admin
def create_license():
    data = request.get_json(silent=True) or {}
    duration    = data.get("duration", "30")
    max_devices = max(1, int(data.get("max_devices", 1)))
    note        = data.get("note", "")[:200]   # optional label
    features    = data.get("features", {})     # custom license features

    key = str(uuid.uuid4()).upper()

    if duration == "lifetime":
        expiry = None
    else:
        try:
            days = int(duration)
            if days <= 0:
                raise ValueError
        except ValueError:
            return jsonify({"error": "Invalid duration"}), 400
        expiry = datetime.now() + timedelta(days=days)

    try:
        db  = get_db()
        cur = db.cursor()
        cur.execute(
            """INSERT INTO licenses
               (license_key, expiry_date, max_devices, devices, is_active, note, plan_id, features, duration)
               VALUES (%s,%s,%s,%s,true,%s,%s,%s,%s)""",
            (key, expiry, max_devices, json.dumps([]), note, data.get("plan_id"), json.dumps(features), duration)
        )
        db.commit()
        logger.info("License created: %s expires=%s max_devices=%s", key[:8] + "****", expiry, max_devices)
    except Exception:
        logger.exception("Create license error")
        return jsonify({"error": "DB error"}), 500

    return jsonify({
        "license":     key,
        "expiry":      expiry.isoformat() if expiry else "lifetime",
        "max_devices": max_devices,
        "note":        note
    }), 201


@app.route("/admin/list", methods=["GET"])
@rate_limited
@require_admin
def list_licenses():
    try:
        db  = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT l.license_key, l.expiry_date, l.max_devices, l.is_active, l.note, l.devices, p.name, l.features, l.qr_scan_count, l.duration "
            "FROM licenses l LEFT JOIN plans p ON l.plan_id = p.id "
            "ORDER BY l.is_active DESC, l.expiry_date DESC NULLS LAST"
        )
        rows = cur.fetchall()
    except Exception:
        logger.exception("List licenses error")
        return jsonify({"error": "DB error"}), 500

    results = []
    for r in rows:
        devices = r[5] if isinstance(r[5], list) else json.loads(r[5] or "[]")
        c_features = r[7] if isinstance(r[7], dict) else json.loads(r[7] or "{}")
        results.append({
            "license":         r[0],
            "expiry":          r[1].isoformat() if r[1] else "lifetime",
            "max_devices":     r[2],
            "active_devices":  len(devices),
            "is_active":       r[3],
            "note":            r[4] or "",
            "plan_name":       r[6] or "Legacy",
            "features":        c_features,
            "qr_scan_count":   r[8] or 0,
            "duration":        r[9] or "30"
        })

    return jsonify(results)


@app.route("/admin/revoke", methods=["POST"])
@rate_limited
@require_admin
def revoke_license():
    data = request.get_json(silent=True) or {}
    license_key = (data.get("license_key") or "").strip()
    if not license_key:
        return jsonify({"error": "Missing license_key"}), 400

    try:
        db  = get_db()
        cur = db.cursor()
        cur.execute(
            "UPDATE licenses SET is_active=false WHERE license_key=%s",
            (license_key,)
        )
        if cur.rowcount == 0:
            return jsonify({"error": "License not found"}), 404
        db.commit()
        logger.info("License revoked: %s", license_key[:8] + "****")
    except Exception:
        logger.exception("Revoke error")
        return jsonify({"error": "DB error"}), 500

    return jsonify({"success": True})


@app.route("/admin/reset-device", methods=["POST"])
@rate_limited
@require_admin
def reset_device():
    """Remove a specific device (or all devices) from a license."""
    data = request.get_json(silent=True) or {}
    license_key = (data.get("license_key") or "").strip()
    device_id   = (data.get("device_id")   or "").strip()   # empty = reset all

    if not license_key:
        return jsonify({"error": "Missing license_key"}), 400

    try:
        db  = get_db()
        cur = db.cursor()
        if device_id:
            cur.execute("SELECT devices FROM licenses WHERE license_key=%s", (license_key,))
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "License not found"}), 404
            devices = row[0] if isinstance(row[0], list) else json.loads(row[0] or "[]")
            devices = [d for d in devices if d != device_id]
        else:
            devices = []

        cur.execute(
            "UPDATE licenses SET devices=%s WHERE license_key=%s",
            (json.dumps(devices), license_key)
        )
        db.commit()
    except Exception:
        logger.exception("Reset device error")
        return jsonify({"error": "DB error"}), 500

    return jsonify({"success": True, "remaining_devices": len(devices)})

# ─────────────────────────────────────────
# ROUTES — ADMIN PLANS
# ─────────────────────────────────────────
@app.route("/admin/plans", methods=["GET"])
def list_plans():
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, name, features FROM plans ORDER BY id ASC")
        rows = cur.fetchall()
        return jsonify([{"id": r[0], "name": r[1], "features": r[2]} for r in rows])
    except Exception:
        logger.exception("List plans error")
        return jsonify({"error": "DB error"}), 500

@app.route("/admin/plans", methods=["POST"])
@require_admin
def create_plan():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    features = data.get("features", {})
    if not name:
        return jsonify({"error": "Plan name needed"}), 400
        
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO plans (name, features) VALUES (%s, %s) RETURNING id", (name, json.dumps(features)))
        plan_id = cur.fetchone()[0]
        db.commit()
        return jsonify({"success": True, "id": plan_id})
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "Plan name already exists"}), 400
    except Exception:
        logger.exception("Create plan error")
        return jsonify({"error": "Server error"}), 500

@app.route("/admin/plans/<int:plan_id>", methods=["DELETE"])
@require_admin
def delete_plan(plan_id):
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("DELETE FROM plans WHERE id = %s", (plan_id,))
        db.commit()
        return jsonify({"success": True})
    except Exception:
        db.rollback()
        return jsonify({"error": "DB error"}), 500


# ─────────────────────────────────────────
# HEALTH CHECK (no auth)
# ─────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})


# ─────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────
if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    port  = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=debug)
