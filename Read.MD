# Watchtower + Recon Ecosystem — راهنمای راه‌اندازی

این پروژه بعد از بازطراحی معماری، به این شکل تقسیم می‌شه:

| بخش | محل اجرا | نوع اجرا |
|---|---|---|
| Frontend (`watchtower-frontend`) | **فقط سیستم شخصی (لوکال)** | systemd service، همیشه روشن |
| Backend API (`watchtower/app.py`) | **سیستم شخصی (لوکال)** | systemd service، `python3 app.py` |
| Backend API (`watchtower/app.py`) | **VPS ساعتی** | Docker Compose، `python3 app.py` مستقیم، بدون Gunicorn |
| Recon + xsscanner | **فقط VPS ساعتی** | Docker Compose، اجرای یک‌باره (`profile: manual`) |
| MongoDB | **فقط Atlas (کلاود)** | هیچ Mongo لوکالی نداریم، نه روی لوکال نه روی سرور |

نکته‌ی کلیدی: چون VPS ساعتی گرفته می‌شه و بعد از هر اسکن پاک می‌شه، فرانت‌اند و
مانیتورینگ دائمی **هیچ‌وقت روی سرور نیستن** — فقط MongoDB Atlas بین لوکال و
VPS مشترکه و پل واقعی اطلاعاته. هیچ nginx، هیچ reverse proxy، و هیچ auth
token‌ای هم لازم نیست چون API سرور فقط از شبکه‌ی خودت و به‌صورت موقت صدا زده می‌شه.

---

## بخش ۱ — راه‌اندازی لوکال (سیستم شخصی، همیشه روشن)

### پیش‌نیازها
- Python 3.11+
- Node.js + pnpm
- یک کلاستر MongoDB Atlas (رایگان هم کافیه)

### مرحله ۱ — کلون و تنظیم بک‌اند
```bash
git clone <repo-url> ~/Recon_ecosystem
cd ~/Recon_ecosystem

cp watchtower/.env.example watchtower/.env
nano watchtower/.env
# فقط همین رو پر کن:
#   MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/watchtower?retryWrites=true&w=majority
# بقیه (Telegram, Censys, Shodan, Chaos) اختیاریه

cd watchtower
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
cd ..
```

### مرحله ۲ — تنظیم فرانت‌اند
```bash
cp watchtower-frontend/.env.example watchtower-frontend/.env
nano watchtower-frontend/.env
# اینجا چون بک‌اند هم روی همین سیستمه:
#   VITE_API_URL=http://127.0.0.1:3131/api

cd watchtower-frontend
pnpm install
cd ..
```

### مرحله ۳ — تست دستی قبل از سرویس کردن
```bash
# ترمینال ۱
cd watchtower && source venv/bin/activate && python3 app.py

# ترمینال ۲
cd watchtower-frontend && pnpm run dev
```
بعد از باز شدن `http://localhost:3000` و اتصال موفق به API، برو سراغ systemd.

### مرحله ۴ — راه‌اندازی به‌صورت سرویس دائمی

فایل‌های آماده توی `deploy/systemd/` هستن:
- `watchtower-api.service`
- `watchtower-frontend.service`

```bash
# داخل هر دو فایل، مسیر /home/arian/... و User=arian رو با یوزر و مسیر خودت جایگزین کن
sudo cp deploy/systemd/watchtower-api.service /etc/systemd/system/
sudo cp deploy/systemd/watchtower-frontend.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now watchtower-api
sudo systemctl enable --now watchtower-frontend

# چک کردن وضعیت و لاگ
systemctl status watchtower-api
journalctl -u watchtower-api -f
```

برای فرانت‌اند لازمه قبلش `pnpm run build` بزنی چون سرویس از `dist/index.js`
استفاده می‌کنه:
```bash
cd watchtower-frontend
pnpm run build
```

---

## بخش ۲ — راه‌اندازی روی VPS ساعتی (فقط اسکن)

روی سرور **فقط** دو چیز داریم: `watchtower-api` (برای ثبت نتایج در Mongo) و
`recon-tools` (خود اسکنر). فرانت‌اند اصلاً روی سرور کلون/بیلد نمی‌شه.

### مرحله ۱ — بالا آوردن سرور و کلون ریپو
```bash
ssh root@<VPS_IP>
apt-get update && apt-get install -y docker.io docker-compose-plugin git
git clone <repo-url> /opt/Recon_ecosystem
cd /opt/Recon_ecosystem
```

### مرحله ۲ — تنظیم `.env` مشترک
```bash
cp .env.example .env
nano .env
```
فقط `MONGO_URI` رو به همون کلاستر Atlas که توی لوکال هم استفاده می‌کنی وصل کن.
بقیه (Telegram, Censys, Shodan, Chaos) اختیاریه. **هیچ توکن API اینجا لازم نیست.**

### مرحله ۳ — بیلد و بالا آوردن API
```bash
docker compose up -d --build watchtower-api
docker compose logs -f watchtower-api
```
این سرویس روی پورت `3131` بالا میاد، دقیقاً با `python3 app.py` (نه Gunicorn)،
همون‌طور که لوکال هم اجرا می‌کنی — لاگ‌هاش رو مستقیم با `docker compose logs`
می‌بینی.

### مرحله ۴ — اجرای اسکن (یک‌باره، نه سرویس دائمی)
```bash
docker compose run --rm recon-tools bash -c \
  "/app/watchtower/watch.sh && /app/xsscanner/xsscanner -phase 4"
```
یا اگه `docker-compose.override.yml` رو از روی نمونه‌ش فعال کردی:
```bash
cp docker-compose.override.yml.example docker-compose.override.yml
docker compose run --rm recon-tools
```

### مرحله ۵ — پایان کار، پاک کردن سرور
نتایج مستقیم توی MongoDB Atlas ذخیره شدن، پس نیازی به بک‌آپ گرفتن از سرور نیست.
```bash
docker compose down -v
```
بعدش سرور رو از پنل هاست ترمینیت/پاک کن.

---

## نکات مهم معماری

- **بدون nginx**: چون فرانت‌اند اصلاً روی سرور نیست، هیچ reverse proxy‌ای هم لازم
  نداریم. API مستقیم روی پورت 3131 گوش می‌ده.
- **بدون auth token**: چون سرور فقط موقع اسکن بالاست و فقط از IP خودت بهش وصل
  می‌شی، auth اضافه نکردیم. اگه در آینده IP سرور public در معرض ترافیک ناخواسته
  قرار گرفت، باید یه لایه‌ی basic auth یا firewall rule اضافه کنی.
- **بدون Mongo لوکال روی سرور**: `docker-compose.yml` سرور دیگه هیچ سرویس
  `mongo:` نداره. تنها دیتابیس، Atlas مشترک بین لوکال و سرور است.
- **مسیر پایتون در `xsscanner`**: `main.go` حالا اول مسیر داکر
  (`/app/watchtower/venv/bin/python3`) رو چک می‌کنه و اگه نبود می‌ره سراغ
  fallbackهای دیگه — پس چه لوکال چه روی سرور کار می‌کنه بدون نیاز به مسیر
  هاردکد `/opt/Recon_ecosystem`.
- **هر بار IP سرور عوض شد**: فقط کافیه `watchtower-frontend/.env` رو لوکال
  آپدیت کنی (یا با اسکریپت آماده):
  ```bash
  cd watchtower-frontend
  ./scripts/set-api-url.sh http://<NEW_VPS_IP>:3131/api
  ```

---

## ساختار نهایی فایل‌ها (بعد از تغییرات)

```
Recon_ecosystem/
├── docker-compose.yml          ← فقط watchtower-api + recon-tools (سرور)
├── .env.example                ← فقط MONGO_URI + کلیدهای اختیاری
├── watchtower/
│   ├── app.py
│   ├── database/
│   │   ├── Dockerfile          ← python3 app.py مستقیم، بدون gunicorn
│   │   └── (بدون docker-compose.yml محلی / بدون سرویس mongo)
│   └── ...
├── xsscanner/
│   ├── Dockerfile
│   ├── main.go                 ← مسیر پایتون داکر-آگاه
│   └── ...
├── watchtower-frontend/        ← فقط لوکال، هیچ‌وقت روی سرور کلون نمی‌شه
└── deploy/
    └── systemd/
        ├── watchtower-api.service
        └── watchtower-frontend.service
```