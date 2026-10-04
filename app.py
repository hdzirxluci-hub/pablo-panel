import os
import sys
import uuid
import json
import base64
import sqlite3
import subprocess
import time
import threading
import socket
import struct
import urllib.parse
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response, redirect, url_for, session

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "pablo-rail-secret-key-change-me")

# =========================================================
# تنظیمات اصلی
# =========================================================

ADMIN_USERNAME = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASS", "admin")

XRAY_PORT = 10000
XRAY_API_PORT = 10085
FLASK_PORT = 5000

DB_PATH = "users.db"
XRAY_CONFIG_PATH = "xray_config.json"
NGINX_CONFIG_PATH = "nginx.conf"

ONLINE_USERS = {}
ONLINE_THRESHOLD = 90

# =========================================================
# دیتابیس
# =========================================================

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

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

    conn.commit()
    conn.close()


# =========================================================
# مدیریت تنظیمات ورود پنل
# =========================================================

def get_admin_credentials():
    env_user = os.environ.get("ADMIN_USER")
    env_pass = os.environ.get("ADMIN_PASS")

    if env_user is not None and env_pass is not None:
        return env_user, env_pass

    settings_file = "panel_settings.json"

    if os.path.exists(settings_file):
        try:
            with open(settings_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            username = data.get("username", "admin")
            password = data.get("password", "admin")

            return username, password

        except Exception:
            pass

    return "admin", "admin"


def save_admin_credentials(username, password):
    settings_file = "panel_settings.json"

    data = {
        "username": username,
        "password": password
    }

    with open(settings_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# =========================================================
# کاربران
# =========================================================

def get_all_users():
    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM users ORDER BY id DESC")

    rows = [dict(r) for r in c.fetchall()]

    conn.close()

    return rows


def enrich_user(u):
    try:
        created_dt = datetime.fromisoformat(u["created_at"])
        elapsed_days = (datetime.now() - created_dt).days
        days_left = max(0, u["expire_days"] - elapsed_days)
    except Exception:
        days_left = u["expire_days"]

    used_gb = round(u["used_bytes"] / (1024 ** 3), 2)
    quota_gb = round(float(u["quota_gb"]), 2)

    if quota_gb > 0:
        percent = min(100, round((used_gb / quota_gb) * 100, 1))
    else:
        percent = 0

    u["used_gb"] = used_gb
    u["days_left"] = days_left
    u["percent"] = percent
    u["is_expired"] = days_left <= 0
    u["created_date"] = u["created_at"][:10] if u.get("created_at") else ""
    u["is_online"] = is_user_online(u["name"])

    return u


def is_user_online(name):
    last_seen = ONLINE_USERS.get(name, 0)
    return (time.time() - last_seen) < ONLINE_THRESHOLD


# =========================================================
# ساخت کانفیگ Xray
# =========================================================

def build_xray_config():

    users = get_all_users()

    clients = []

    for u in users:

        if u["enabled"] == 1:

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

    with open(XRAY_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


# =========================================================
# ری‌استارت Xray
# =========================================================

def restart_xray():

    build_xray_config()

    try:
        subprocess.run(["pkill", "-9", "-f", "xray"], check=False)
        time.sleep(0.5)
    except Exception:
        pass

    try:
        xray_bin = "/usr/local/bin/xray/xray"
        if not os.path.exists(xray_bin):
            xray_bin = "xray"

        subprocess.Popen(
            [xray_bin, "run", "-c", XRAY_CONFIG_PATH],
            stdout=sys.stdout,
            stderr=sys.stderr
        )
    except Exception as e:
        print("Xray start error:", e)


# =========================================================
# Xray Stats API
# =========================================================

def xray_query_stats():
    stats = {}

    xray_bin = "/usr/local/bin/xray/xray"
    if not os.path.exists(xray_bin):
        xray_bin = "xray"

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
    xray_bin = "/usr/local/bin/xray/xray"
    if not os.path.exists(xray_bin):
        xray_bin = "xray"

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


# =========================================================
# تایمر پس‌زمینه (جمع‌آوری آمار + چک حجم)
# =========================================================

PREVIOUS_STATS = {}


def stats_collector():
    global PREVIOUS_STATS

    while True:
        try:
            time.sleep(15)

            stats = xray_query_stats()

            if not stats:
                continue

            conn = get_db()
            c = conn.cursor()

            need_restart = False

            for user_email, total_bytes in stats.items():
                if total_bytes <= 0:
                    continue

                c.execute(
                    "UPDATE users SET used_bytes = used_bytes + ? WHERE name = ?",
                    (total_bytes, user_email)
                )

                ONLINE_USERS[user_email] = time.time()

                c.execute(
                    "SELECT id, quota_gb, used_bytes, enabled FROM users WHERE name = ?",
                    (user_email,)
                )

                row = c.fetchone()

                if row and row["enabled"] == 1:
                    used_gb = row["used_bytes"] / (1024 ** 3)
                    if row["quota_gb"] > 0 and used_gb >= row["quota_gb"]:
                        c.execute(
                            "UPDATE users SET enabled = 0 WHERE id = ?",
                            (row["id"],)
                        )
                        need_restart = True
                        print(f"[QUOTA] User '{user_email}' exceeded quota. Disabled.")

            conn.commit()
            conn.close()

            if need_restart:
                restart_xray()

        except Exception as e:
            print("Stats collector error:", e)


def start_stats_collector():
    t = threading.Thread(target=stats_collector, daemon=True)
    t.start()


# =========================================================
# NGINX
# =========================================================

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

    map $http_upgrade $connection_upgrade {{
        default upgrade;
        '' close;
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

            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

            proxy_set_header X-Forwarded-Proto $scheme;
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


# =========================================================
# ساخت کانفیگ‌های ۱۰ گانه
# =========================================================

def make_all_vless_configs(user, host):

    created_dt = datetime.fromisoformat(user["created_at"])
    elapsed_days = (datetime.now() - created_dt).days
    days_left = max(0, user["expire_days"] - elapsed_days)

    used_gb = round(user["used_bytes"] / (1024 ** 3), 2)
    quota_gb = round(float(user["quota_gb"]), 2)
    remaining_gb = max(0.0, round(quota_gb - used_gb, 2))

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

    # 1
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

    # 2
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

    # 3
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

    # 4
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

    # 5
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

    # 6
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

    # 7
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

    # 8
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

    # 9
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

    # 10
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


# =========================================================
# روت‌ها
# =========================================================

@app.route("/")
def home():
    if "admin" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        current_username, current_password = get_admin_credentials()

        if username == current_username and password == current_password:
            session["admin"] = True
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="نام کاربری یا رمز عبور اشتباه است!")

    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.pop("admin", None)
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "admin" not in session:
        return redirect(url_for("login"))

    users = get_all_users()

    total_gb = sum(u["quota_gb"] for u in users)
    total_used = sum(u["used_bytes"] for u in users) / (1024 ** 3)
    active_count = sum(1 for u in users if u["enabled"] == 1)

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
    if "admin" not in session:
        return redirect(url_for("login"))

    raw_users = get_all_users()
    users = [enrich_user(u) for u in raw_users]

    total_gb = sum(u["quota_gb"] for u in raw_users)
    total_used = sum(u["used_bytes"] for u in raw_users) / (1024 ** 3)
    active_count = sum(1 for u in users if u["enabled"] == 1 and not u["is_expired"])
    disabled_count = sum(1 for u in users if u["enabled"] == 0)
    expired_count = sum(1 for u in users if u["is_expired"])
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
    if "admin" not in session:
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
    if "admin" not in session:
        return redirect(url_for("login"))

    username, _ = get_admin_credentials()

    return render_template("settings.html", current_username=username)


@app.route("/api/settings", methods=["POST"])
def update_settings():
    if "admin" not in session:
        return jsonify({"status": "error", "message": "دسترسی غیرمجاز"}), 401

    data = request.get_json(silent=True) or {}

    new_username = data.get("username", "").strip()
    new_password = data.get("password", "")
    current_password = data.get("current_password", "")

    if not new_username:
        return jsonify({"status": "error", "message": "نام کاربری جدید الزامی است"}), 400

    if not new_password:
        return jsonify({"status": "error", "message": "رمز عبور جدید الزامی است"}), 400

    username, password = get_admin_credentials()

    if current_password != password:
        return jsonify({"status": "error", "message": "رمز عبور فعلی اشتباه است"}), 400

    if len(new_username) < 3:
        return jsonify({"status": "error", "message": "نام کاربری حداقل باید ۳ کاراکتر باشد"}), 400

    if len(new_password) < 4:
        return jsonify({"status": "error", "message": "رمز عبور حداقل باید ۴ کاراکتر باشد"}), 400

    try:
        save_admin_credentials(new_username, new_password)
        session.pop("admin", None)
        return jsonify({"status": "success", "message": "اطلاعات ورود با موفقیت تغییر کرد"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/add_user", methods=["POST"])
def add_user():
    if "admin" not in session:
        return jsonify({"status": "error", "message": "دسترسی غیرمجاز"}), 401

    data = request.json or {}

    name = data.get("name", "").strip()

    try:
        quota = float(data.get("quota", 30))
        days = int(data.get("days", 30))
    except Exception:
        return jsonify({"status": "error", "message": "حجم یا تعداد روز نامعتبر است"}), 400

    if not name:
        return jsonify({"status": "error", "message": "نام کاربر الزامی است"}), 400

    if quota <= 0:
        return jsonify({"status": "error", "message": "حجم باید بیشتر از صفر باشد"}), 400

    if days <= 0:
        return jsonify({"status": "error", "message": "تعداد روز باید بیشتر از صفر باشد"}), 400

    user_uuid = str(uuid.uuid4())

    try:
        conn = get_db()
        c = conn.cursor()

        c.execute(
            """
            INSERT INTO users
            (name, uuid, quota_gb, expire_days, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (name, user_uuid, quota, days, datetime.now().isoformat())
        )

        conn.commit()
        conn.close()

        restart_xray()

        return jsonify({"status": "success", "message": "کاربر با موفقیت ساخته شد"})

    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "این نام کاربری قبلاً وجود دارد"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/edit_user/<int:user_id>", methods=["POST"])
def edit_user(user_id):
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    data = request.get_json(silent=True) or {}

    try:
        new_quota = float(data.get("quota_gb", 0))
        new_days = int(data.get("expire_days", 0))
    except Exception:
        return jsonify({"status": "error", "message": "مقادیر نامعتبر"}), 400

    if new_quota <= 0 or new_days <= 0:
        return jsonify({"status": "error", "message": "حجم و روز باید بیشتر از صفر باشند"}), 400

    try:
        conn = get_db()
        c = conn.cursor()

        c.execute(
            "UPDATE users SET quota_gb=?, expire_days=? WHERE id=?",
            (new_quota, new_days, user_id)
        )

        conn.commit()
        conn.close()

        return jsonify({"status": "success", "message": "کاربر با موفقیت ویرایش شد"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/reset_user/<int:user_id>", methods=["POST"])
def reset_user(user_id):
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    try:
        conn = get_db()
        c = conn.cursor()

        c.execute("SELECT name FROM users WHERE id=?", (user_id,))
        row = c.fetchone()

        if row:
            xray_reset_user_stats(row["name"])

        c.execute(
            "UPDATE users SET used_bytes=0, created_at=? WHERE id=?",
            (datetime.now().isoformat(), user_id)
        )

        conn.commit()
        conn.close()

        return jsonify({"status": "success", "message": "ترافیک کاربر صفر شد"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/delete_user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    conn = get_db()
    c = conn.cursor()

    c.execute("DELETE FROM users WHERE id=?", (user_id,))

    conn.commit()
    conn.close()

    restart_xray()

    return jsonify({"status": "success", "message": "کاربر با موفقیت حذف شد"})


@app.route("/api/toggle_user/<int:user_id>", methods=["POST"])
def toggle_user(user_id):
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT enabled FROM users WHERE id=?", (user_id,))

    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "کاربر یافت نشد"}), 404

    new_val = 0 if row[0] == 1 else 1

    c.execute("UPDATE users SET enabled=? WHERE id=?", (new_val, user_id))

    conn.commit()
    conn.close()

    restart_xray()

    return jsonify({"status": "success", "new_state": new_val})


@app.route("/api/user_config/<int:user_id>")
def user_config(user_id):
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()

    conn.close()

    if not user:
        return jsonify({"status": "error", "message": "کاربر یافت نشد"}), 404

    host = request.host.split(":")[0]

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
    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE uuid=?", (user_uuid,))
    user = c.fetchone()

    conn.close()

    if not user or user["enabled"] == 0:
        return ("User not found or disabled", 404)

    ua = request.headers.get("User-Agent", "").lower()

    client_keywords = [
        "v2ray", "clash", "sing-box", "hiddify",
        "nekobox", "streisand", "foxray", "shadowrocket", "v2box"
    ]

    is_client = any(k in ua for k in client_keywords)

    host = request.host.split(":")[0]

    user_dict = dict(user)

    all_configs = make_all_vless_configs(user_dict, host)

    if is_client:
        raw_text = "\n".join(item["config"] for item in all_configs)
        encoded = base64.b64encode(raw_text.encode()).decode()
        return Response(encoded, mimetype="text/plain")

    created_dt = datetime.fromisoformat(user_dict["created_at"])
    elapsed_days = (datetime.now() - created_dt).days
    days_left = max(0, user_dict["expire_days"] - elapsed_days)

    used_gb = round(user_dict["used_bytes"] / (1024 ** 3), 2)
    remaining_gb = max(0.0, round(user_dict["quota_gb"] - used_gb, 2))

    percent = (
        used_gb / user_dict["quota_gb"] * 100
        if user_dict["quota_gb"] > 0 else 0
    )

    raw_text = "\n".join(item["config"] for item in all_configs)
    encoded_sub = base64.b64encode(raw_text.encode()).decode()

    return render_template(
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
    )


# =========================================================
# شروع برنامه
# =========================================================

if __name__ == "__main__":
    init_db()
    restart_xray()
    start_nginx()
    start_stats_collector()
    app.run(host="127.0.0.1", port=FLASK_PORT)
