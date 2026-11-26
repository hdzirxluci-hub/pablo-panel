FROM python:3.12-slim

WORKDIR /app

ENV XRAY_LOCATION_ASSET=/usr/local/bin/xray
ENV PATH="/usr/local/bin/xray:${PATH}"
ENV PYTHONUNBUFFERED=1

# نصب Nginx و هسته رسمی Xray
RUN apt-get update && apt-get install -y --no-install-recommends nginx wget unzip procps curl ca-certificates && \
    rm -rf /etc/nginx/sites-enabled/* /etc/nginx/conf.d/* && \
    mkdir -p /usr/local/bin/xray /run /var/log/nginx && \
    wget -q https://github.com/XTLS/Xray-core/releases/download/v1.8.11/Xray-linux-64.zip && \
    unzip -q Xray-linux-64.zip -d /usr/local/bin/xray && \
    chmod +x /usr/local/bin/xray/xray && \
    rm Xray-linux-64.zip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# محل ذخیره دیتابیس و رمز ادمین. روی Railway یک Volume به /data وصل کنید تا با Deploy پاک نشود.
ENV DATA_DIR=/data
RUN mkdir -p /data

ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/healthz" || exit 1

CMD ["python", "app.py"]
