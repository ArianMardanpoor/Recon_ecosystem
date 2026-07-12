FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 3131

# تنظیم متغیر محیطی برای تعداد workerها با مقدار پیش‌فرض 4
ENV GUNICORN_WORKERS=4

# استفاده از Gunicorn برای Production. بایند باید 0.0.0.0 باشد تا در داکر در دسترس قرار گیرد.
CMD ["sh", "-c", "gunicorn -w $GUNICORN_WORKERS -b 0.0.0.0:3131 --timeout 120 app:app"]