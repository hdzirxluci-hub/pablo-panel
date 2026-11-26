# ✦ P A B L O · P A N E L ✦

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:05001A,45:101B4D,75:312E81,100:00BFFF&height=190&section=header&text=%E2%9C%A6%20P%20A%20B%20L%20O%20%C2%B7%20P%20A%20N%20E%20L%20%E2%9C%A6&fontColor=FFFFFF&fontSize=38&fontAlignY=42&animation=twinkling" width="100%"/>
</p>

<p align="center">
  <strong>پنل مدیریت کاربران و اشتراک‌ها برای Xray (VLESS + WebSocket)</strong>
</p>

---

## ✦ درباره پروژه

**Pablo Panel** یک پنل وب سبک و موبایل‌محور است که روی هسته [Xray](https://github.com/XTLS/Xray-core) کار می‌کند. با آن می‌توانید کاربر بسازید، حجم و مدت اعتبار تعیین کنید، مصرف را زنده ببینید و لینک اشتراک (Subscription) را به کاربران بدهید.

همه چیز داخل یک کانتینر اجرا می‌شود: **Nginx** (ورودی و پراکسی) ← **Flask** (پنل و API) + **Xray** (هسته).

---

## ⚡ امکانات

• ساخت، ویرایش، حذف، فعال/غیرفعال و ریست ترافیک کاربران  
• سقف حجم (GB) و مدت اعتبار (روز) برای هر کاربر  
• قطع خودکار کاربر هنگام اتمام حجم یا پایان اعتبار  
• نمایش مصرف و وضعیت آنلاین بودن کاربران  
• ۱۰ کانفیگ آماده برای هر کاربر (فینگرپرینت‌ها و حالت‌های مختلف)  
• لینک اشتراک سازگار با v2rayNG، Hiddify، Clash، sing-box، Streisand، Shadowrocket و …  
• صفحه وب اشتراک با QR و دکمه Copy برای هر کانفیگ  
• ربات تلگرام: وضعیت پنل و لیست کاربران برای ادمین، استعلام اشتراک برای کاربران  
• رابط تاریک، دو زبانه (فارسی / English) و بهینه برای موبایل  

---

## 🚀 راه‌اندازی

### Railway

1. Repository را به Railway وصل کنید (Deploy از Dockerfile).
2. یک **Volume** بسازید و روی مسیر `/data` mount کنید. بدون آن، دیتابیس و رمز ادمین با هر Deploy پاک می‌شود.
3. در Variables مقدار `ADMIN_USER` و `ADMIN_PASS` را تنظیم کنید (اختیاری، پایین را ببینید).
4. Deploy کنید و آدرس عمومی را باز کنید.

### Docker

<pre>
docker build -t pablo-panel .
docker run -d -p 8080:8080 -v pablo-data:/data \
  -e ADMIN_USER=admin -e ADMIN_PASS='یک-رمز-قوی' \
  pablo-panel
</pre>

پنل روی `http://localhost:8080` در دسترس است.

### اولین ورود

اگر `ADMIN_USER` / `ADMIN_PASS` را تنظیم نکنید، در اولین اجرا یک رمز تصادفی برای کاربر `admin` ساخته و **در لاگ‌های کانتینر** چاپ می‌شود. بعد از ورود، آن را از بخش «تنظیمات» عوض کنید.

---

## 🔐 متغیرهای محیطی

| متغیر | پیش‌فرض | توضیح |
|---|---|---|
| `ADMIN_USER` / `ADMIN_PASS` | — | نام کاربری و رمز اولیه ادمین. اگر تنظیم نشوند رمز تصادفی ساخته می‌شود. |
| `SECRET_KEY` | تصادفی | کلید امضای سشن. اگر تنظیم نشود، یک کلید تصادفی ساخته و در `DATA_DIR` ذخیره می‌شود. |
| `DATA_DIR` | `/data` (Docker) | مسیر ذخیره دیتابیس، رمز ادمین و کلید سشن. باید روی Volume پایدار باشد. |
| `PUBLIC_HOST` | هدر Host | دامنه‌ای که داخل کانفیگ‌ها و لینک اشتراک قرار می‌گیرد. |
| `TRUSTED_PROXY_HOPS` | `1` | تعداد پراکسی‌های مورد اعتماد جلوی پنل. `0` یعنی هدرهای `X-Forwarded-*` نادیده گرفته شوند. |
| `PORT` | `8080` | پورتی که Nginx روی آن گوش می‌دهد. |

---

## 🤖 ربات تلگرام

1. از [@BotFather](https://t.me/BotFather) یک ربات بسازید و توکن را بگیرید.
2. در پنل به **تنظیمات ← ربات تلگرام** بروید و توکن و شناسه عددی (Chat ID) ادمین را وارد کنید.
3. تغییرات بدون ریستارت اعمال می‌شود.

ادمین: دکمه‌های «وضعیت پنل» و «لیست کاربران». سایر کاربران: ارسال نام کاربری یا UUID برای دیدن حجم و اعتبار.

---

## 🛡️ نکات امنیتی

• رمز ادمین فقط به‌صورت هش ذخیره می‌شود.  
• ورود ناموفق بیش از ۵ بار در ۵ دقیقه موقتاً مسدود می‌شود.  
• با تغییر رمز، همه سشن‌های قبلی باطل می‌شوند.  
• رمز ذخیره‌شده از داخل پنل بر `ADMIN_PASS` اولویت دارد.  
• درخواست‌های تغییردهنده فقط از همان Origin پذیرفته می‌شوند (محافظت CSRF).  
• پنل را پشت HTTPS اجرا کنید (Railway به‌صورت پیش‌فرض این کار را می‌کند).  
• فایل‌های `*.db`، `panel_settings.json` و `.secret_key` را هرگز commit نکنید (در `.gitignore` هستند).  

---

## 🗂️ ساختار پروژه

<pre>
app.py            بک‌اند Flask، مدیریت Xray و Nginx، ربات تلگرام
templates/        صفحات: login، dashboard، users، settings، subscription
static/           فایل‌های استاتیک
Dockerfile        Python + Nginx + Xray
requirements.txt  وابستگی‌های پایتون
</pre>

مسیرهای مهم: `/login`، `/dashboard`، `/users`، `/settings`، `/sub/<uuid>` و `/healthz` (بدون احراز هویت، برای Health Check).

---

# 💙 حرف آخر

ساخته شده با ♥️ توسط [@poll_o0](https://t.me/poll_o0)

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:00BFFF,45:312E81,75:101B4D,100:05001A&height=120&section=footer&animation=twinkling" width="100%"/>
</p>
