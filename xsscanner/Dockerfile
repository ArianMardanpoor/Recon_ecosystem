# xsscanner/Dockerfile

FROM golang:latest AS builder

WORKDIR /build

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/ImAyrix/fallparams@latest

COPY xsscanner/go.mod xsscanner/go.sum ./

RUN go mod download

COPY xsscanner/ .

RUN go build -o nice_passive nice_passive.go && \
    go build -o nice_katana nice_katana.go && \
    go build -o nice_params nice_params.go && \
    go build -o x9 x9.go && \
    go build -o xssniper xssniper.go && \
    go build -o xsscanner main.go && \
    go build -o dom_sink_checker dom_sink_checker.go

# ---------------- Runtime ----------------

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl unzip python3 python3-venv python3-pip git \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxkbcommon0 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 \
    libpango-1.0-0 libasound2 \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSL "https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip" \
    -o /tmp/amass.zip \
    && unzip -o -j /tmp/amass.zip "amass_Linux_amd64/amass" -d /usr/local/bin \
    && chmod +x /usr/local/bin/amass \
    && rm /tmp/amass.zip

RUN curl -sSL --proto '=https' --tlsv1.2 https://sh.rustup.rs -o /tmp/rustup.sh \
    && sh /tmp/rustup.sh -y --profile minimal \
    && . "$HOME/.cargo/env" \
    && git clone --depth 1 https://github.com/sh1yo/x8 /tmp/x8-build \
    && cd /tmp/x8-build \
    && cargo build --release \
    && cp ./target/release/x8 /usr/local/bin/ \
    && rm -rf /tmp/x8-build "$HOME/.cargo" "$HOME/.rustup" /tmp/rustup.sh

RUN pip3 install uro --break-system-packages

COPY --from=builder /go/bin/* /usr/local/bin/

# حذف /app و انتقال مستقیم به روت
COPY --from=builder \
    /build/nice_passive \
    /build/nice_katana \
    /build/nice_params \
    /build/x9 \
    /build/xssniper \
    /build/xsscanner \
    /build/dom_sink_checker \
    /xsscanner/

# کپی مستقیم پوشه watchtower به روت
COPY watchtower /watchtower

# ساخت محیط مجازی و نصب پیش‌نیازها در مسیر جدید
RUN python3 -m venv /watchtower/venv && \
    /watchtower/venv/bin/pip install --no-cache-dir \
    -r /watchtower/requirements.txt

# تغییر مسیر پیش‌فرض کانتینر
WORKDIR /xsscanner

# آپدیت متغیرهای محیطی
ENV WATCHTOWER_PYTHON=/watchtower/venv/bin/python3
ENV WATCHTOWER_API_URL=http://watchtower-api:3131/api

CMD ["./xsscanner"]
