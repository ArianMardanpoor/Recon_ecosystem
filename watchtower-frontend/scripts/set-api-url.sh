#!/bin/bash

ENV_FILE=".env"
NEW_URL=$1

if [ -z "$NEW_URL" ]; then
  echo "❌ خطا: آدرس IP یا URL وارد نشده است."
  echo "💡 راهنمای استفاده: ./scripts/set-api-url.sh http://<VPS_IP>:3131/api"
  exit 1
fi

# بررسی وجود فایل .env
if [ ! -f "$ENV_FILE" ]; then
  echo "⚠️ فایل .env پیدا نشد. در حال ایجاد فایل جدید..."
  touch "$ENV_FILE"
fi

# آپدیت یا اضافه کردن متغیر با کمک sed
if grep -q "^VITE_API_URL=" "$ENV_FILE"; then
  sed -i "s|^VITE_API_URL=.*|VITE_API_URL=$NEW_URL|" "$ENV_FILE"
else
  echo "VITE_API_URL=$NEW_URL" >> "$ENV_FILE"
fi

echo "✅ مقدار VITE_API_URL در فایل $ENV_FILE به $NEW_URL تغییر یافت."