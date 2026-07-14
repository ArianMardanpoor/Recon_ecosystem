# watchtower/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# psycopg2 نیاز به libpq-dev برای build داره
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 3131

# Dev mode ساده طبق خواسته کاربر - نه gunicorn
CMD ["python3", "app.py"]