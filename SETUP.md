# راه‌اندازی Recon Ecosystem

این پروژه دو محیط اجرا دارد:

| بخش | محل اجرا | نوع اجرا |
|---|---|---|
| Frontend (watchtower-frontend) | **فقط سیستم شخصی (لوکال)** | systemd service، همیشه روشن |
| Backend API (watchtower/app.py) | **سیستم شخصی (لوکال)** | systemd service، همیشه روشن |
| Backend API (watchtower/app.py) | **VPS ساعتی** | Docker Compose، dev mode، موقت |
| Recon + xsscanner | **فقط VPS ساعتی** | Docker Compose، اجرای یک‌باره |

نکته کلیدی: چون VPS ساعتی گرفته و بعد از اسکن پاک می‌شود، **فرانت‌اند و
مانیتورینگ دائمی هرگز روی VPS نیستند** — فقط دیتابیس (MongoDB Atlas)
مشترک بین لوکال و VPS است و پل ارتباطی واقعی محسوب می‌شود.

---

## 1) راه‌اندازی لوکال (همیشه روشن)

### پیش‌نیاز
- Python 3.11+, Node.js, pnpm
- یک MongoDB Atlas cluster (یا Mongo لوکال)

### مراحل
```bash
git clone <repo> ~/Recon_ecosystem
cd ~/Recon_ecosystem

# بک‌اند
cp watchtower/.env.example watchtower/.env
# MONGO_URI را پر کن
cd watchtower
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
deactivate
cd ..

# فرانت‌اند
cp watchtower-frontend/.env.example watchtower-frontend/.env
# VITE_API_URL را فعلاً [http://127.0.0.1:3131/api](http://127.0.0.1:3131/api) بگذار (بعداً وقتی VPS
# بالا اومد عوضش می‌کنیم - بخش 3)
cd watchtower-frontend
pnpm install
cd ..