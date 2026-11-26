import os
import re
import sys
import math
import hmac
import uuid
import json
import base64
import hashlib
import secrets
import sqlite3
import subprocess
import time
import threading
import urllib.parse
from contextlib import contextmanager
from datetime import datetime, timedelta
from functools import lru_cache
from flask import Flask, render_template, request, jsonify, Response, redirect, url_for, session, abort
from flask.sessions import SecureCookieSessionInterface
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import telebot
except ImportError:
    telebot = None

# مسیر ذخیره‌سازی داده‌ها (دیتابیس، رمز ادمین، کلید سشن).
# روی Railway/Docker باید به یک Volume پایدار اشاره کند، وگرنه با هر Deploy پاک می‌شود.
DATA_DIR = os.environ.get("DATA_DIR", ".")
os.makedirs(DATA_DIR, exist_ok=True)

def data_path(name):
    return os.path.join(DATA_DIR, name)

LEGACY_INSECURE_SECRET = "pablo-rail-secret-key-change-me"

def write_private_file(path, content):
    """نوشتن اتمیک فایل با دسترسی فقط-مالک (۰۶۰۰)"""
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)

def load_secret_key():
    """کلید سشن: از ENV، وگرنه یک کلید تصادفی که یک‌بار ساخته و ذخیره می‌شود"""
    env_key = os.environ.get("SECRET_KEY", "").strip()
    if env_key and env_key != LEGACY_INSECURE_SECRET:
        return env_key

    key_file = data_path(".secret_key")
    try:
        with open(key_file, "r", encoding="utf-8") as f:
            key = f.read().strip()
        if key:
            return key
    except OSError:
        pass

    key = secrets.token_hex(32)
    try:
        write_private_file(key_file, key)
    except OSError as e:
        print("[SECURITY] Could not persist secret key (sessions reset on restart):", e)
    return key

class AutoSecureSessionInterface(SecureCookieSessionInterface):
    """کوکی فقط روی HTTPS با فلگ Secure ست شود (روی HTTP محلی هم کار کند)"""
    def get_cookie_secure(self, app):
        return request.is_secure

app = Flask(__name__)
app.secret_key = load_secret_key()
app.session_interface = AutoSecureSessionInterface()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    MAX_CONTENT_LENGTH=1024 * 1024,
)

# تعداد پراکسی‌های مورد اعتماد جلوی Flask (Railway edge). صفر یعنی هدرهای X-Forwarded نادیده گرفته شوند.
PROXY_HOPS = int(os.environ.get("TRUSTED_PROXY_HOPS", "1"))
if PROXY_HOPS > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=PROXY_HOPS, x_proto=PROXY_HOPS)

XRAY_PORT = 10000
XRAY_API_PORT = 10085
FLASK_PORT = 5000

DB_PATH = data_path("users.db")
XRAY_CONFIG_PATH = "xray_config.json"
NGINX_CONFIG_PATH = "nginx.conf"
CREDS_FILE = data_path("panel_settings.json")

ONLINE_USERS = {}
ONLINE_THRESHOLD = 90

USERNAME_RE = re.compile(r"^[\w .\-@]{1,64}$")
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$")
MAX_QUOTA_GB = 100000
MAX_DAYS = 36500
MIN_PASSWORD_LEN = 8

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn

@contextmanager
def db():
    """کانکشن دیتابیس با commit/rollback و بستن تضمینی (جلوگیری از نشت کانکشن)"""
    conn = get_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    conn = get_db()
    c = conn.cursor()

    # WAL: خواندن/نوشتن همزمان بین Collector و درخواست‌های وب بدون قفل شدن دیتابیس
    c.execute("PRAGMA journal_mode=WAL")

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            uuid TEXT UNIQUE NOT NULL,
            quota_gb REAL DEFAULT 0,
            used_bytes INTEGER DEFAULT 0,
            expire_days INTEGER DEFAULT 30,
            created_at TEXT,
            enabled INTEGER DEFAULT 1
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    conn.commit()
    conn.close()

def get_setting(key, default=""):
    try:
        with db() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else default
    except Exception:
        return default

def set_setting(key, value):
    try:
        with db() as conn:
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
        return True
    except Exception as e:
        print("Error saving setting:", e)
        return False

# ---------------------------------------------------------------------------
# احراز هویت ادمین
# اولویت: فایل رمز (بعد از تغییر رمز از داخل پنل) > ENV (ADMIN_USER / ADMIN_PASS) > رمز تصادفی اولین اجرا
# رمزها فقط به‌صورت هش ذخیره می‌شوند.
# ---------------------------------------------------------------------------

def read_creds_file():
    try:
        with open(CREDS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None

@lru_cache(maxsize=1)
def hash_env_password(password):
    return generate_password_hash(password)

def get_admin_credentials():
    """(username, password_hash) یا (None, None) اگر هنوز چیزی تنظیم نشده"""
    data = read_creds_file()
    if data and data.get("username") and data.get("password_hash"):
        return data["username"], data["password_hash"]

    env_user = os.environ.get("ADMIN_USER", "").strip()
    env_pass = os.environ.get("ADMIN_PASS", "")
    if env_user and env_pass:
        return env_user, hash_env_password(env_pass)

    return None, None

def save_admin_credentials(username, password):
    data = {
        "username": username,
        "password_hash": generate_password_hash(password),
    }
    write_private_file(CREDS_FILE, json.dumps(data, ensure_ascii=False, indent=2))

def init_admin_credentials():
    """اجرا در استارت: مهاجرت رمز متنی قدیمی، یا ساخت رمز تصادفی اگر هیچ رمزی تنظیم نشده"""
    data = read_creds_file()

    # مهاجرت فایل قدیمی که رمز را به‌صورت متن ساده نگه می‌داشت
    if data and data.get("password") and not data.get("password_hash"):
        save_admin_credentials(data.get("username") or "admin", data["password"])
        print("[SECURITY] Legacy plaintext admin password was migrated to a hash.")
        return

    username, _ = get_admin_credentials()
    if username:
        if os.environ.get("ADMIN_PASS") == "admin" and not (data and data.get("password_hash")):
            print("[SECURITY] WARNING: ADMIN_PASS is set to the default 'admin'. Change it immediately.")
        return

    password = secrets.token_urlsafe(12)
    save_admin_credentials("admin", password)
    print("=" * 60)
    print("[SECURITY] No admin credentials configured. Generated first-run login:")
    print(f"           username: admin")
    print(f"           password: {password}")
    print("           Change it in Settings, or set ADMIN_USER / ADMIN_PASS.")
    print("=" * 60)

def creds_fingerprint():
    """با تغییر رمز، همه سشن‌های قبلی خودکار باطل می‌شوند"""
    _, pw_hash = get_admin_credentials()
    return hashlib.sha256((pw_hash or "").encode()).hexdigest()[:20]

def is_admin():
    if not session.get("admin"):
        return False
    return hmac.compare_digest(str(session.get("fp", "")), creds_fingerprint())

# محدودسازی تلاش‌های ناموفق ورود (در برابر brute-force)
LOGIN_MAX_FAILS = 5
LOGIN_WINDOW = 300
LOGIN_FAILS = {}
LOGIN_LOCK = threading.Lock()

def _recent_fails(ip, now):
    fails = [t for t in LOGIN_FAILS.get(ip, []) if now - t < LOGIN_WINDOW]
    if fails:
        LOGIN_FAILS[ip] = fails
    else:
        LOGIN_FAILS.pop(ip, None)
    return fails

def login_blocked(ip):
    with LOGIN_LOCK:
        return len(_recent_fails(ip, time.time())) >= LOGIN_MAX_FAILS

def record_failed_login(ip):
    with LOGIN_LOCK:
        now = time.time()
        if len(LOGIN_FAILS) > 10000:
            for key in list(LOGIN_FAILS):
                _recent_fails(key, now)
        LOGIN_FAILS.setdefault(ip, []).append(now)

def clear_failed_logins(ip):
    with LOGIN_LOCK:
        LOGIN_FAILS.pop(ip, None)

def get_all_users():
    with db() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()]
    return rows

def calc_days_left(user):
    """روزهای باقی‌مانده اشتراک؛ در صورت خراب بودن تاریخ، کل مدت را برمی‌گرداند"""
    try:
        created_dt = datetime.fromisoformat(user["created_at"])
        elapsed_days = (datetime.now() - created_dt).days
        return max(0, user["expire_days"] - elapsed_days)
    except Exception:
        return user["expire_days"]

def get_public_host():
    """هاست عمومی برای ساخت کانفیگ‌ها. هدر Host کاربر مستقیم داخل کانفیگ/صفحه نمی‌رود مگر معتبر باشد."""
    configured = os.environ.get("PUBLIC_HOST", "").strip()
    if configured:
        return configured
    host = request.host.split(":")[0]
    if not HOST_RE.match(host):
        abort(400)
    return host

def is_user_active(user):
    """بررسی فعال بودن کاربر بر اساس ترافیک، زمان و وضعیت کلی"""
    if user["enabled"] == 0:
        return False, "disabled"

    try:
        created_dt = datetime.fromisoformat(user["created_at"])
        elapsed_days = (datetime.now() - created_dt).days
        if elapsed_days >= user["expire_days"]:
            return False, "expired"
    except Exception:
        pass

    used_gb = user["used_bytes"] / (1024 ** 3)
    if user["quota_gb"] > 0 and used_gb >= user["quota_gb"]:
        return False, "limit_exceeded"

    return True, "active"

def enrich_user(u):
    days_left = calc_days_left(u)

    used_gb = round(u["used_bytes"] / (1024 ** 3), 2)
    quota_gb = round(float(u["quota_gb"]), 2)

    if quota_gb > 0:
        percent = min(100, round((used_gb / quota_gb) * 100, 1))
    else:
        percent = 0

    active_state, reason = is_user_active(u)

    u["used_gb"] = used_gb
    u["days_left"] = days_left
    u["percent"] = percent
    u["is_expired"] = days_left <= 0 or reason == "expired"
    u["is_limit_exceeded"] = reason == "limit_exceeded"
    u["is_active"] = active_state
    u["created_date"] = u["created_at"][:10] if u.get("created_at") else ""
    u["is_online"] = is_user_online(u["name"])

    return u

def is_user_online(name):
    last_seen = ONLINE_USERS.get(name, 0)
    return (time.time() - last_seen) < ONLINE_THRESHOLD

def build_xray_config():
    """کانفیگ Xray را می‌سازد و مجموعه نام کاربران فعال داخل آن را برمی‌گرداند"""
    users = get_all_users()
    clients = []
    active_names = set()

    for u in users:
        # فقط کاربرانی که واقعاً فعال هستند داخل کانفیگ Xray ریخته می‌شوند
        active, _ = is_user_active(u)
        if active:
            active_names.add(u["name"])
            clients.append({
                "id": u["uuid"],
                "email": u["name"],
                "level": 0
            })

    if not clients:
        clients.append({
            "id": str(uuid.uuid4()),
            "email": "default_user",
            "level": 0
        })

    config = {
        "log": {
            "loglevel": "warning"
        },
        "stats": {},
        "api": {
            "tag": "api",
            "services": ["StatsService"]
        },
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True
            }
        },
        "inbounds": [
            {
                "tag": "api",
                "port": XRAY_API_PORT,
                "listen": "127.0.0.1",
                "protocol": "dokodemo-door",
                "settings": {
                    "address": "127.0.0.1"
                }
            },
            {
                "tag": "vless-in",
                "port": XRAY_PORT,
                "listen": "127.0.0.1",
                "protocol": "vless",
                "settings": {
                    "clients": clients,
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {
                        "path": "/ws"
                    }
                }
            }
        ],
        "outbounds": [
            {
                "protocol": "freedom",
                "tag": "direct"
            }
        ],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["api"],
                    "outboundTag": "api"
                }
            ]
        }
    }

    # کانفیگ شامل UUID کاربران است؛ فقط برای مالک قابل خواندن باشد
    write_private_file(XRAY_CONFIG_PATH, json.dumps(config, indent=2, ensure_ascii=False))
    return active_names

def find_xray_bin():
    xray_bin = "/usr/local/bin/xray/xray"
    return xray_bin if os.path.exists(xray_bin) else "xray"

XRAY_PROCESS = None
XRAY_LOCK = threading.RLock()
CURRENT_ACTIVE = set()

def stop_xray():
    """فقط پروسس Xray خودِ پنل متوقف می‌شود (نه pkill -9 روی هر چیزی که 'xray' در نامش دارد)"""
    global XRAY_PROCESS

    if XRAY_PROCESS is None:
        # اولین اجرا: پروسس یتیم از اجرای قبلی (در صورت وجود) پاک شود
        try:
            subprocess.run(["pkill", "-f", "xray run -c"], check=False)
            time.sleep(0.5)
        except Exception:
            pass
        return

    if XRAY_PROCESS.poll() is None:
        XRAY_PROCESS.terminate()
        try:
            XRAY_PROCESS.wait(timeout=5)
        except subprocess.TimeoutExpired:
            XRAY_PROCESS.kill()
            XRAY_PROCESS.wait()
    XRAY_PROCESS = None

def restart_xray():
    global XRAY_PROCESS, CURRENT_ACTIVE

    with XRAY_LOCK:
        # مصرفی که هنوز ثبت نشده قبل از ریستارت ذخیره شود (وگرنه با ریست شمارنده‌ها از بین می‌رفت)
        if XRAY_PROCESS is not None:
            record_usage()

        CURRENT_ACTIVE = build_xray_config()
        stop_xray()

        try:
            XRAY_PROCESS = subprocess.Popen(
                [find_xray_bin(), "run", "-c", XRAY_CONFIG_PATH],
                stdout=sys.stdout,
                stderr=sys.stderr
            )
        except Exception as e:
            XRAY_PROCESS = None
            print("Xray start error:", e)

def xray_needs_restart():
    """اگر مجموعه کاربران فعال تغییر کرده (مثلاً انقضای زمانی) یا Xray کرش کرده باشد"""
    wanted = {u["name"] for u in get_all_users() if is_user_active(u)[0]}
    if wanted != CURRENT_ACTIVE:
        return True
    return XRAY_PROCESS is not None and XRAY_PROCESS.poll() is not None

def xray_query_stats():
    stats = {}
    xray_bin = find_xray_bin()

    try:
        result = subprocess.run(
            [
                xray_bin,
                "api",
                "statsquery",
                f"--server=127.0.0.1:{XRAY_API_PORT}",
                "-pattern=user>>>",
                "-reset=true"
            ],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return stats

        data = json.loads(result.stdout)
        stat_list = data.get("stat", [])

        for item in stat_list:
            name = item.get("name", "")
            value = int(item.get("value", 0))

            parts = name.split(">>>")
            if len(parts) >= 4 and parts[0] == "user":
                user_email = parts[1]

                if user_email not in stats:
                    stats[user_email] = 0

                stats[user_email] += value

    except Exception:
        pass

    return stats

def xray_reset_user_stats(user_email):
    xray_bin = find_xray_bin()

    try:
        for direction in ["uplink", "downlink"]:
            subprocess.run(
                [
                    xray_bin,
                    "api",
                    "statsquery",
                    f"--server=127.0.0.1:{XRAY_API_PORT}",
                    "-reset=true",
                    f"-pattern=user>>>{user_email}>>>traffic>>>{direction}"
                ],
                capture_output=True,
                timeout=3
            )
    except Exception:
        pass

PENDING_USAGE = {}
USAGE_LOCK = threading.Lock()

def record_usage():
    """مصرف را از Xray می‌خواند و به دیتابیس اضافه می‌کند.
    اگر نوشتن در دیتابیس شکست بخورد، مقدار در PENDING_USAGE می‌ماند و بار بعد دوباره تلاش می‌شود
    (چون شمارنده‌های Xray با -reset=true صفر می‌شوند)."""
    stats = xray_query_stats()

    with USAGE_LOCK:
        for name, value in stats.items():
            if value > 0:
                PENDING_USAGE[name] = PENDING_USAGE.get(name, 0) + value

        if not PENDING_USAGE:
            return

        try:
            with db() as conn:
                for name, value in PENDING_USAGE.items():
                    conn.execute(
                        "UPDATE users SET used_bytes = used_bytes + ? WHERE name = ?",
                        (value, name)
                    )
        except Exception as e:
            print("Usage write error (will retry):", e)
            return

        now = time.time()
        for name in PENDING_USAGE:
            ONLINE_USERS[name] = now
        PENDING_USAGE.clear()

def stats_collector():
    while True:
        try:
            time.sleep(15)

            with XRAY_LOCK:
                record_usage()

                # محدودیت حجم/زمان برای همه کاربران بررسی می‌شود (نه فقط کسانی که ترافیک داشته‌اند)
                if xray_needs_restart():
                    print("[QUOTA/TIME] Active user set changed or Xray exited. Rebuilding Xray config.")
                    restart_xray()

        except Exception as e:
            print("Stats collector error:", e)

def start_stats_collector():
    t = threading.Thread(target=stats_collector, daemon=True)
    t.start()

def start_nginx():
    port = os.environ.get("PORT", "8080")

    nginx_conf = f"""
pid /run/nginx.pid;
error_log /dev/stderr warn;
events {{
    worker_connections 1024;
}}
http {{
    access_log /dev/stdout;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;
    server_tokens off;
    client_max_body_size 1m;
    map $http_upgrade $connection_upgrade {{
        default upgrade;
        '' close;
    }}
    # پروتکل/IP اصلی کلاینت که پراکسی بالادستی (Railway) ست کرده حفظ شود
    map $http_x_forwarded_proto $fwd_proto {{
        default $http_x_forwarded_proto;
        '' $scheme;
    }}
    map $http_x_forwarded_for $fwd_for {{
        default $http_x_forwarded_for;
        '' $remote_addr;
    }}
    server {{
        listen {port};
        server_name _;
        location ~ ^/ws {{
            proxy_redirect off;
            rewrite ^/ws.*$ /ws break;
            proxy_pass http://127.0.0.1:{XRAY_PORT};
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_read_timeout 86400s;
            proxy_send_timeout 86400s;
        }}
        location / {{
            proxy_pass http://127.0.0.1:{FLASK_PORT};
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $fwd_for;
            proxy_set_header X-Forwarded-Proto $fwd_proto;
        }}
    }}
}}
"""

    with open(NGINX_CONFIG_PATH, "w", encoding="utf-8") as f:
        f.write(nginx_conf)

    try:
        subprocess.run(["pkill", "-9", "-f", "nginx"], check=False)
        time.sleep(0.3)
    except Exception:
        pass

    subprocess.Popen([
        "nginx",
        "-c",
        os.path.abspath(NGINX_CONFIG_PATH),
        "-g",
        "daemon off;"
    ])

def make_all_vless_configs(user, host):
    u_uuid = user["uuid"]
    name = user["name"]

    def config_remark(number):
        remark_text = (
            f"کانفیـگ پرسرعـت | "
            f"𝗣𝗔𝗕𝗟𝗢 𝗣𝗔𝗡𝗘𝗟 | "
            f"{number} | "
            f"{name}"
        )
        return urllib.parse.quote(remark_text)

    configs = []

    c1 = (
        f"vless://{u_uuid}@{host}:443"
        f"?path=%2Fws%2F{u_uuid}"
        f"&security=tls"
        f"&alpn=http%2F1.1"
        f"&encryption=none"
        f"&insecure=0"
        f"&host={host}"
        f"&fp=chrome"
        f"&type=ws"
        f"&allowInsecure=0"
        f"&sni={host}"
        f"#{config_remark(1)}"
    )
    configs.append({
        "title": "کانفیـگ پرسرعـت | 𝗣𝗔𝗕𝗟𝗢 𝗣𝗔𝗡𝗘𝗟 | 1",
        "desc": "اتصال فوق‌العاده پایدار و بدون قطعی (پیشنهادی)",
        "tag": "HighSpeed 1",
        "config": c1
    })

    c2 = (
        f"vless://{u_uuid}@{host}:443"
        f"?path=%2Fws%2F{u_uuid}%3Fed%3D2560"
        f"&security=tls"
        f"&alpn=http%2F1.1"
        f"&encryption=none"
        f"&insecure=0"
        f"&host={host}"
        f"&fp=chrome"
        f"&type=ws"
        f"&allowInsecure=0"
        f"&sni={host}"
        f"#{config_remark(2)}"
    )
    configs.append({
        "title": "کانفیـگ پرسرعـت | 𝗣𝗔𝗕𝗟𝗢 𝗣𝗔𝗡𝗘𝗟 | 2",
        "desc": "بهینه‌شده با پینگ بسیار پایین مخصوص بازی و وب‌گردی",
        "tag": "HighSpeed 2",
        "config": c2
    })

    c3 = (
        f"vless://{u_uuid}@{host}:443"
        f"?path=%2Fws%2F{u_uuid}"
        f"&security=tls"
        f"&alpn=h2%2Chttp%2F1.1"
        f"&encryption=none"
        f"&insecure=0"
        f"&host={host}"
        f"&fp=firefox"
        f"&type=ws"
        f"&allowInsecure=0"
        f"&sni={host}"
        f"#{config_remark(3)}"
    )
    configs.append({
        "title": "کانفیـگ پرسرعـت | 𝗣𝗔𝗕𝗟𝗢 𝗣𝗔𝗡𝗘𝗟 | 3",
        "desc": "فرکانس چندگانه و ضد فیلتر مناسب دانلود‌های سنگین",
        "tag": "HighSpeed 3",
        "config": c3
    })

    c4 = (
        f"vless://{u_uuid}@{host}:443"
        f"?path=%2Fws%2F{u_uuid}"
        f"&security=tls"
        f"&alpn=http%2F1.1"
        f"&encryption=none"
        f"&insecure=0"
        f"&host={host}"
        f"&fp=chrome"
        f"&type=ws"
        f"&allowInsecure=0"
        f"&sni={host}"
        f"#{config_remark(4)}"
    )
    configs.append({
        "title": "کانفیـگ پرسرعـت | 𝗣𝗔𝗕𝗟𝗢 𝗣𝗔𝗡𝗘𝗟 | 4",
        "desc": "متد بهینه‌سازی شده‌ی نمونه مخصوص دور زدن فیلترینگ شدید همراه اول",
        "tag": "HighSpeed 4",
        "config": c4
    })

    c5 = (
        f"vless://{u_uuid}@{host}:443"
        f"?path=%2Fws%2F{u_uuid}%3Fed%3D2048"
        f"&security=tls"
        f"&alpn=h2"
        f"&encryption=none"
        f"&insecure=0"
        f"&host={host}"
        f"&fp=edge"
        f"&type=ws"
        f"&allowInsecure=0"
        f"&sni={host}"
        f"#{config_remark(5)}"
    )
    configs.append({
        "title": "کانفیـگ پرسرعـت | 𝗣𝗔𝗕𝗟𝗢 𝗣𝗔𝗡𝗘𝗟 | 5",
        "desc": "مخصوص ایرانسل با فینگرپرینت متمایز Edge جهت پایداری بالا",
        "tag": "HighSpeed 5",
        "config": c5
    })

    c6 = (
        f"vless://{u_uuid}@{host}:443"
        f"?path=%2Fws%2F{u_uuid}"
        f"&security=tls"
        f"&encryption=none"
        f"&insecure=0"
        f"&host={host}"
        f"&fp=opera"
        f"&type=ws"
        f"&allowInsecure=0"
        f"&sni={host}"
        f"#{config_remark(6)}"
    )
    configs.append({
        "title": "کانفیـگ پرسرعـت | 𝗣𝗔𝗕𝗟𝗢 𝗣𝗔𝗡𝗘𝗟 | 6",
        "desc": "مخصوص مخابرات، شاتل، آسیاتک و پارس‌آنلاین با فینگرپرینت Opera",
        "tag": "HighSpeed 6",
        "config": c6
    })

    c7 = (
        f"vless://{u_uuid}@{host}:443"
        f"?path=%2Fws%2F{u_uuid}%3Fed%3D2560"
        f"&security=tls"
        f"&alpn=http%2F1.1"
        f"&encryption=none"
        f"&insecure=0"
        f"&host={host}"
        f"&fp=android"
        f"&type=ws"
        f"&allowInsecure=0"
        f"&sni={host}"
        f"#{config_remark(7)}"
    )
    configs.append({
        "title": "کانفیـگ پرسرعـت | 𝗣𝗔𝗕𝗟𝗢 𝗣𝗔𝗡𝗘𝗟 | 7",
        "desc": "شبیه‌سازی بر بستر آندروید سازگار با رایتل و شاتل‌موبایل",
        "tag": "HighSpeed 7",
        "config": c7
    })

    c8 = (
        f"vless://{u_uuid}@{host}:80"
        f"?path=%2Fws%2F{u_uuid}"
        f"&security=none"
        f"&encryption=none"
        f"&host={host}"
        f"&type=ws"
        f"#{config_remark(8)}"
    )
    configs.append({
        "title": "کانفیـگ پرسرعـت | 𝗣𝗔𝗕𝗟𝗢 𝗣𝗔𝗡𝗘𝗟 | 8",
        "desc": "پورت اضطراری ۸۰ بدون رمزنگاری TLS (برای زمان اختلالات شدید گیت‌وی)",
        "tag": "HighSpeed 8",
        "config": c8
    })

    c9 = (
        f"vless://{u_uuid}@{host}:443"
        f"?path=%2Fws%2F{u_uuid}"
        f"&security=tls"
        f"&alpn=http%2F1.1"
        f"&encryption=none"
        f"&insecure=0"
        f"&host={host}"
        f"&fp=random"
        f"&type=ws"
        f"&allowInsecure=0"
        f"&sni={host}"
        f"#{config_remark(9)}"
    )
    configs.append({
        "title": "کانفیـگ پرسرعـت | 𝗣𝗔𝗕𝗟𝗢 𝗣𝗔𝗡𝗘𝗟 | 9",
        "desc": "دارای فینگرپرینت کاملاً رندوم برای دور زدن فیلترینگ‌های هوشمند",
        "tag": "HighSpeed 9",
        "config": c9
    })

    c10 = (
        f"vless://{u_uuid}@{host}:443"
        f"?path=%2Fws%2F{u_uuid}%3Fhost%3D{host}"
        f"&security=tls"
        f"&alpn=http%2F1.1"
        f"&encryption=none"
        f"&insecure=0"
        f"&host={host}"
        f"&fp=chrome"
        f"&type=ws"
        f"&allowInsecure=0"
        f"&sni={host}"
        f"#{config_remark(10)}"
    )
    configs.append({
        "title": "کانفیـگ پرسرعـت | 𝗣𝗔𝗕𝗟𝗢 𝗣𝗔𝗡𝗘𝗟 | 10",
        "desc": "مخصوص دور زدن پکت‌لاسی زیرساخت شبکه با روت بهینه‌سازی شده CDN",
        "tag": "HighSpeed 10",
        "config": c10
    })

    return configs

def make_fake_config(reason, user, host):
    """تولید کانکشن غیرفعال (نمایشی) جهت اطلاع‌رسانی به کاربر نهایی در نرم‌افزارش"""
    u_uuid = str(uuid.uuid4())
    name = user["name"]
    
    if reason == "limit_exceeded":
        remark = f"⛔️ Traffic Limit Exceeded | {name}"
        desc = "حجم ترافیک مجاز شما به اتمام رسیده است. جهت تمدید اقدام کنید."
    elif reason == "expired":
        remark = f"⛔️ Subscription Expired | {name}"
        desc = "زمان اشتراک شما به پایان رسیده است. جهت تمدید اقدام کنید."
    else:
        remark = f"⛔️ Service Disabled | {name}"
        desc = "سرویس شما توسط ادمین غیرفعال شده است."
        
    remark_encoded = urllib.parse.quote(remark)
    
    config_str = (
        f"vless://{u_uuid}@{host}:443"
        f"?path=%2Fws%2Fdummy"
        f"&security=tls"
        f"&encryption=none"
        f"&host={host}"
        f"&fp=chrome"
        f"&type=ws"
        f"&sni={host}"
        f"#{remark_encoded}"
    )
    return [{
        "title": remark,
        "desc": desc,
        "tag": "Alert",
        "config": config_str
    }]

def get_subscription_header(user):
    """تولید هدر استاندارد مانیتورینگ حجم برای نمایش بالای نرم‌افزار کاربر"""
    used = int(user["used_bytes"])
    total = int(float(user["quota_gb"]) * (1024 ** 3))
    try:
        created_dt = datetime.fromisoformat(user["created_at"])
        expire_dt = created_dt + timedelta(days=int(user["expire_days"]))
        expire_ts = int(expire_dt.timestamp())
    except Exception:
        expire_ts = 0
    return f"upload=0; download={used}; total={total}; expire={expire_ts}"

@app.before_request
def block_cross_origin_writes():
    """محافظت CSRF: درخواست‌های تغییردهنده فقط از همین Origin پذیرفته می‌شوند"""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        source = request.headers.get("Origin") or request.headers.get("Referer")
        if source:
            try:
                source_host = urllib.parse.urlparse(source).netloc
            except ValueError:
                source_host = ""
            if source_host != request.host:
                return jsonify({"status": "error", "message": "درخواست نامعتبر"}), 403

@app.after_request
def add_security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    if request.is_secure:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    if not request.path.startswith("/static/"):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp

@app.route("/healthz")
def healthz():
    return "ok", 200, {"Content-Type": "text/plain"}

@app.route("/")
def home():
    if not is_admin():
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "unknown"

        if login_blocked(ip):
            return render_template(
                "login.html",
                error="تلاش‌های ناموفق زیاد بود. چند دقیقه دیگر دوباره تلاش کنید."
            ), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        current_username, current_hash = get_admin_credentials()

        # هر دو بررسی همیشه انجام می‌شوند تا زمان پاسخ اطلاعاتی لو ندهد
        user_ok = hmac.compare_digest(username.encode(), (current_username or "").encode())
        pass_ok = check_password_hash(current_hash, password) if current_hash else False

        if user_ok and pass_ok:
            clear_failed_logins(ip)
            session.clear()
            session["admin"] = True
            session["fp"] = creds_fingerprint()
            session.permanent = True
            return redirect(url_for("dashboard"))

        record_failed_login(ip)
        return render_template("login.html", error="نام کاربری یا رمز عبور اشتباه است!")

    return render_template("login.html", error=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if not is_admin():
        return redirect(url_for("login"))

    users = get_all_users()

    total_gb = sum(u["quota_gb"] for u in users)
    total_used = sum(u["used_bytes"] for u in users) / (1024 ** 3)
    active_count = sum(1 for u in users if is_user_active(u)[0])

    return render_template(
        "dashboard.html",
        users=users,
        total_users=len(users),
        active_users=active_count,
        total_gb=round(total_gb, 2),
        total_used=round(total_used, 2)
    )

@app.route("/users")
def users_page():
    if not is_admin():
        return redirect(url_for("login"))

    raw_users = get_all_users()
    users = [enrich_user(u) for u in raw_users]

    total_gb = sum(u["quota_gb"] for u in raw_users)
    total_used = sum(u["used_bytes"] for u in raw_users) / (1024 ** 3)
    active_count = sum(1 for u in users if u["is_active"])
    disabled_count = sum(1 for u in users if u["enabled"] == 0)
    expired_count = sum(1 for u in users if u["is_expired"] or u["is_limit_exceeded"])
    online_count = sum(1 for u in users if u["is_online"])

    return render_template(
        "users.html",
        users=users,
        total_users=len(users),
        active_users=active_count,
        disabled_users=disabled_count,
        expired_users=expired_count,
        online_users=online_count,
        total_gb=round(total_gb, 2),
        total_used=round(total_used, 2)
    )

@app.route("/api/online_users")
def api_online_users():
    if not is_admin():
        return jsonify({"status": "error"}), 401

    raw_users = get_all_users()
    online = []

    for u in raw_users:
        if is_user_online(u["name"]):
            last_seen = ONLINE_USERS.get(u["name"], 0)
            seconds_ago = int(time.time() - last_seen)

            online.append({
                "id": u["id"],
                "name": u["name"],
                "used_gb": round(u["used_bytes"] / (1024 ** 3), 2),
                "quota_gb": u["quota_gb"],
                "seconds_ago": seconds_ago
            })

    return jsonify({
        "status": "success",
        "count": len(online),
        "users": online
    })

@app.route("/settings")
def settings():
    if not is_admin():
        return redirect(url_for("login"))

    username, _ = get_admin_credentials()
    tg_token = get_setting("telegram_token", "")
    tg_admin_id = get_setting("telegram_admin_id", "")

    return render_template(
        "settings.html",
        current_username=username,
        telegram_token=tg_token,
        telegram_admin_id=tg_admin_id
    )

@app.route("/api/settings", methods=["POST"])
def update_settings():
    if not is_admin():
        return jsonify({"status": "error", "message": "دسترسی غیرمجاز"}), 401

    data = request.get_json(silent=True) or {}
    action = data.get("action", "")

    if action == "telegram":
        tg_token = data.get("telegram_token", "").strip()
        tg_admin_id = data.get("telegram_admin_id", "").strip()

        try:
            set_setting("telegram_token", tg_token)
            set_setting("telegram_admin_id", tg_admin_id)
            # ربات فعلی متوقف می‌شود تا با توکن/ادمین جدید دوباره بالا بیاید
            restart_telegram_bot()
            return jsonify({"status": "success", "message": "تنظیمات ربات تلگرام با موفقیت ثبت شد"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    elif action == "security":
        new_username = data.get("username", "").strip()
        new_password = data.get("password", "")
        current_password = data.get("current_password", "")

        if not new_username:
            return jsonify({"status": "error", "message": "نام کاربری جدید الزامی است"}), 400

        if not new_password:
            return jsonify({"status": "error", "message": "رمز عبور جدید الزامی است"}), 400

        _, current_hash = get_admin_credentials()
        ip = request.remote_addr or "unknown"

        # تأیید رمز فعلی هم باید در برابر حدس‌زدن محدود شود
        if login_blocked(ip):
            return jsonify({"status": "error", "message": "تلاش‌های ناموفق زیاد بود. چند دقیقه دیگر تلاش کنید"}), 429

        if not current_hash or not check_password_hash(current_hash, current_password):
            record_failed_login(ip)
            return jsonify({"status": "error", "message": "رمز عبور فعلی اشتباه است"}), 400

        if len(new_username) < 3:
            return jsonify({"status": "error", "message": "نام کاربری حداقل باید ۳ کاراکتر باشد"}), 400

        if len(new_password) < MIN_PASSWORD_LEN:
            return jsonify({"status": "error", "message": f"رمز عبور حداقل باید {MIN_PASSWORD_LEN} کاراکتر باشد"}), 400

        try:
            save_admin_credentials(new_username, new_password)
            # با تغییر رمز، اثرانگشت رمز عوض می‌شود و همه سشن‌های قبلی باطل می‌شوند
            session.clear()
            return jsonify({"status": "success", "message": "اطلاعات ورود تغییر کرد"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({"status": "error", "message": "درخواست نامعتبر"}), 400

def parse_quota_days(data, quota_key, days_key):
    """حجم و روز را اعتبارسنجی می‌کند (NaN/Infinity/مقادیر غیرمنطقی رد می‌شوند)"""
    try:
        quota = float(data.get(quota_key))
        days = int(data.get(days_key))
    except (TypeError, ValueError):
        return None, None, "حجم یا تعداد روز نامعتبر است"

    if not math.isfinite(quota) or quota <= 0:
        return None, None, "حجم باید عددی بیشتر از صفر باشد"
    if days <= 0:
        return None, None, "تعداد روز باید بیشتر از صفر باشد"
    if quota > MAX_QUOTA_GB or days > MAX_DAYS:
        return None, None, "مقدار حجم یا روز بیش از حد مجاز است"

    return quota, days, None

@app.route("/api/add_user", methods=["POST"])
def add_user():
    if not is_admin():
        return jsonify({"status": "error", "message": "دسترسی غیرمجاز"}), 401

    data = request.get_json(silent=True) or {}

    name = str(data.get("name", "")).strip()

    if not name:
        return jsonify({"status": "error", "message": "نام کاربر الزامی است"}), 400

    if not USERNAME_RE.match(name):
        return jsonify({
            "status": "error",
            "message": "نام کاربر فقط می‌تواند شامل حروف، عدد، فاصله و . _ - @ باشد (حداکثر ۶۴ کاراکتر)"
        }), 400

    quota, days, error = parse_quota_days(
        {"quota": data.get("quota", 30), "days": data.get("days", 30)}, "quota", "days"
    )
    if error:
        return jsonify({"status": "error", "message": error}), 400

    user_uuid = str(uuid.uuid4())

    try:
        with db() as conn:
            conn.execute(
                """
                INSERT INTO users
                (name, uuid, quota_gb, expire_days, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (name, user_uuid, quota, days, datetime.now().isoformat())
            )

        restart_xray()

        return jsonify({"status": "success", "message": "کاربر با موفقیت ساخته شد"})

    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "این نام کاربری قبلاً وجود دارد"}), 400
    except Exception as e:
        print("add_user error:", e)
        return jsonify({"status": "error", "message": "خطای داخلی سرور"}), 500

@app.route("/api/edit_user/<int:user_id>", methods=["POST"])
def edit_user(user_id):
    if not is_admin():
        return jsonify({"status": "error"}), 401

    data = request.get_json(silent=True) or {}

    new_quota, new_days, error = parse_quota_days(data, "quota_gb", "expire_days")
    if error:
        return jsonify({"status": "error", "message": error}), 400

    try:
        with db() as conn:
            cur = conn.execute(
                "UPDATE users SET quota_gb=?, expire_days=? WHERE id=?",
                (new_quota, new_days, user_id)
            )
            found = cur.rowcount > 0

        if not found:
            return jsonify({"status": "error", "message": "کاربر یافت نشد"}), 404

        # بازسازی هسته چون امکان دارد کاربر ویرایش‌شده تمدید حجم شده باشد و باید دوباره فعال شود
        restart_xray()

        return jsonify({"status": "success", "message": "کاربر با موفقیت ویرایش شد"})

    except Exception as e:
        print("edit_user error:", e)
        return jsonify({"status": "error", "message": "خطای داخلی سرور"}), 500

@app.route("/api/reset_user/<int:user_id>", methods=["POST"])
def reset_user(user_id):
    if not is_admin():
        return jsonify({"status": "error"}), 401

    try:
        with db() as conn:
            row = conn.execute("SELECT name FROM users WHERE id=?", (user_id,)).fetchone()

            if not row:
                return jsonify({"status": "error", "message": "کاربر یافت نشد"}), 404

            xray_reset_user_stats(row["name"])

            conn.execute(
                "UPDATE users SET used_bytes=0, created_at=? WHERE id=?",
                (datetime.now().isoformat(), user_id)
            )

        # بازسازی فایل کانفیگ برای فعال شدن مجدد کاربر قطع شده در Xray
        restart_xray()

        return jsonify({"status": "success", "message": "ترافیک کاربر صفر شد"})

    except Exception as e:
        print("reset_user error:", e)
        return jsonify({"status": "error", "message": "خطای داخلی سرور"}), 500

@app.route("/api/delete_user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if not is_admin():
        return jsonify({"status": "error"}), 401

    try:
        with db() as conn:
            cur = conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            found = cur.rowcount > 0

        if not found:
            return jsonify({"status": "error", "message": "کاربر یافت نشد"}), 404

        restart_xray()

        return jsonify({"status": "success", "message": "کاربر با موفقیت حذف شد"})

    except Exception as e:
        print("delete_user error:", e)
        return jsonify({"status": "error", "message": "خطای داخلی سرور"}), 500

@app.route("/api/toggle_user/<int:user_id>", methods=["POST"])
def toggle_user(user_id):
    if not is_admin():
        return jsonify({"status": "error"}), 401

    try:
        with db() as conn:
            row = conn.execute("SELECT enabled FROM users WHERE id=?", (user_id,)).fetchone()

            if not row:
                return jsonify({"status": "error", "message": "کاربر یافت نشد"}), 404

            new_val = 0 if row[0] == 1 else 1
            conn.execute("UPDATE users SET enabled=? WHERE id=?", (new_val, user_id))

        restart_xray()

        return jsonify({"status": "success", "new_state": new_val})

    except Exception as e:
        print("toggle_user error:", e)
        return jsonify({"status": "error", "message": "خطای داخلی سرور"}), 500

@app.route("/api/user_config/<int:user_id>")
def user_config(user_id):
    if not is_admin():
        return jsonify({"status": "error"}), 401

    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    if not user:
        return jsonify({"status": "error", "message": "کاربر یافت نشد"}), 404

    host = get_public_host()

    configs = make_all_vless_configs(dict(user), host)

    sub_link = f"{request.host_url}sub/{user['uuid']}"

    return jsonify({
        "status": "success",
        "configs": configs,
        "sub": sub_link,
        "user": dict(user)
    })

@app.route("/sub/<user_uuid>")
def subscription(user_uuid):
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE uuid=?", (user_uuid,)).fetchone()

    # اگر کاربر اصلاً در دیتابیس نبود ارور می‌دهد
    if not user:
        return ("User not found", 404)

    user_dict = dict(user)
    ua = request.headers.get("User-Agent", "").lower()

    client_keywords = [
        "v2ray", "clash", "sing-box", "hiddify",
        "nekobox", "streisand", "foxray", "shadowrocket", "v2box"
    ]

    is_client = any(k in ua for k in client_keywords)
    host = get_public_host()

    # بررسی وضعیت واقعی ترافیک و اعتبار کاربر
    active, reason = is_user_active(user_dict)

    if active:
        all_configs = make_all_vless_configs(user_dict, host)
    else:
        # اگر حجم کاربر تمام شده باشد، به جای کانفیگ های واقعی، کانفیگ اطلاع رسانی ارسال می شود
        all_configs = make_fake_config(reason, user_dict, host)

    # قالب متناسب با کلاینت های فیلترشکن (ارسال هدر مانیتورینگ حجم و سابسکریپشن)
    if is_client:
        raw_text = "\n".join(item["config"] for item in all_configs)
        encoded = base64.b64encode(raw_text.encode()).decode()
        
        resp = Response(encoded, mimetype="text/plain")
        resp.headers["Subscription-Userinfo"] = get_subscription_header(user_dict)
        return resp

    # قالب مشاهده در مرورگر (وب سایت سابسکریپشن)
    days_left = calc_days_left(user_dict)

    used_gb = round(user_dict["used_bytes"] / (1024 ** 3), 2)
    remaining_gb = max(0.0, round(user_dict["quota_gb"] - used_gb, 2))

    percent = (
        used_gb / user_dict["quota_gb"] * 100
        if user_dict["quota_gb"] > 0 else 0
    )

    raw_text = "\n".join(item["config"] for item in all_configs)
    encoded_sub = base64.b64encode(raw_text.encode()).decode()

    resp = Response(render_template(
        "subscription.html",
        user_name=user_dict["name"],
        used_gb=used_gb,
        quota_gb=user_dict["quota_gb"],
        remaining_gb=remaining_gb,
        days_left=days_left,
        percent=round(percent, 1),
        configs=all_configs,
        sub_raw=encoded_sub,
        sub_url=request.url
    ))
    resp.headers["Subscription-Userinfo"] = get_subscription_header(user_dict)
    return resp

CURRENT_BOT = None

def restart_telegram_bot():
    """polling فعلی را متوقف می‌کند؛ حلقه‌ی اصلی ربات را با تنظیمات جدید دوباره بالا می‌آورد"""
    bot = CURRENT_BOT
    if bot is not None:
        try:
            bot.stop_polling()
        except Exception as e:
            print("[Telegram Bot] stop_polling error:", e)

def run_telegram_bot_thread():
    global CURRENT_BOT

    if not telebot:
        print("[Telegram Bot] telebot module not found. Skipping bot launch.")
        return

    while True:
        try:
            tg_token = get_setting("telegram_token", "").strip()
            tg_admin_id = get_setting("telegram_admin_id", "").strip()

            if not tg_token:
                time.sleep(10)
                continue

            bot = telebot.TeleBot(tg_token)
            CURRENT_BOT = bot

            @bot.message_handler(commands=['start'])
            def cmd_start(message):
                chat_id = str(message.chat.id)
                if chat_id == tg_admin_id:
                    markup = telebot.types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
                    btn_status = telebot.types.KeyboardButton('📊 وضعیت پنل')
                    btn_users = telebot.types.KeyboardButton('👥 لیست کاربران')
                    markup.add(btn_status, btn_users)
                    
                    bot.send_message(
                        message.chat.id,
                        "⚡ **سلام ادمین گرامی!**\nبه پنل مدیریت تلگرامی Pablo خوش آمدید.\nیکی از دکمه‌های زیر را انتخاب کنید:",
                        reply_markup=markup,
                        parse_mode="Markdown"
                    )
                else:
                    bot.send_message(
                        message.chat.id,
                        "👋 **سلام کاربر عزیز!**\nبرای استعلام مشخصات کانکشن خود، لطفاً **نام کاربری** یا **UUID** خود را ارسال کنید:"
                    )

            @bot.message_handler(func=lambda m: True)
            def handle_messages(message):
                text = (message.text or "").strip()
                chat_id = str(message.chat.id)

                if chat_id == tg_admin_id:
                    if text == '📊 وضعیت پنل':
                        users = get_all_users()
                        total = len(users)
                        active = sum(1 for u in users if is_user_active(u)[0])
                        total_bytes = sum(u["used_bytes"] for u in users)
                        total_gb = round(total_bytes / (1024 ** 3), 2)

                        msg = (
                            f"🌐 **وضعیت سرور Pablo Panel**\n"
                            f"━━━━━━━━━━━━━━━━━━\n"
                            f"👥 کل کاربران: {total} کاربر\n"
                            f"🟢 کاربران فعال: {active} کاربر\n"
                            f"📊 مصرف کل دیتابیس: {total_gb} GB\n"
                            f"━━━━━━━━━━━━━━━━━━"
                        )
                        bot.send_message(chat_id, msg, parse_mode="Markdown")

                    elif text == '👥 لیست کاربران':
                        users = get_all_users()
                        if not users:
                            bot.send_message(chat_id, "هیچ کاربری یافت نشد.")
                            return

                        msg = "👥 **لیست کاربران پنل (نمایش ۱۵ کاربر آخر):**\n\n"
                        for u in users[:15]:
                            active, _ = is_user_active(u)
                            status = "🟢" if active else "🔴"
                            used = round(u["used_bytes"] / (1024 ** 3), 2)
                            msg += f"{status} `{u['name']}` | {used}/{u['quota_gb']} GB\n"

                        if len(users) > 15:
                            msg += f"\nو {len(users) - 15} کاربر دیگر..."

                        bot.send_message(chat_id, msg, parse_mode="Markdown")

                else:
                    with db() as conn:
                        user = conn.execute(
                            "SELECT * FROM users WHERE name = ? OR uuid = ?", (text, text)
                        ).fetchone()

                    if user:
                        u = dict(user)
                        used_gb = round(u["used_bytes"] / (1024 ** 3), 2)
                        
                        active, reason = is_user_active(u)
                        if active:
                            status = "فعال 🟢"
                        else:
                            if reason == "limit_exceeded":
                                status = "اتمام حجم 🔴"
                            elif reason == "expired":
                                status = "پایان اعتبار زمانی 🔴"
                            else:
                                status = "غیرفعال 🔴"
                        
                        days_left = calc_days_left(u)

                        msg = (
                            f"👤 **مشخصات اشتراک شما**\n"
                            f"━━━━━━━━━━━━━\n"
                            f"🆔 نام کاربری: `{u['name']}`\n"
                            f"⚡ وضعیت اکانت: {status}\n"
                            f"📊 ترافیک مصرفی: {used_gb} GB\n"
                            f"💾 سقف حجم کل: {u['quota_gb']} GB\n"
                            f"📅 اعتبار باقی‌مانده: {days_left} روز\n"
                            f"━━━━━━━━━━━━━"
                        )
                        bot.send_message(chat_id, msg, parse_mode="Markdown")
                    else:
                        bot.send_message(chat_id, "❌ کاربری با این نام یا UUID یافت نشد.")

            print("[Telegram Bot] Bot polling started successfully.")
            bot.infinity_polling(timeout=10, long_polling_timeout=5)
            time.sleep(1)

        except Exception as e:
            print("[Telegram Bot] Polling crash/error, restarting in 10s:", e)
            time.sleep(10)

def start_telegram_bot():
    t = threading.Thread(target=run_telegram_bot_thread, daemon=True)
    t.start()

if __name__ == "__main__":
    init_db()
    init_admin_credentials()
    restart_xray()
    start_nginx()
    start_stats_collector()
    start_telegram_bot()
    app.run(host="127.0.0.1", port=FLASK_PORT)
