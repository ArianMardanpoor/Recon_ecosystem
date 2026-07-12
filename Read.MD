# Deploying to a VPS (non-Codespaces)

This folder replaces the Codespaces-only setup (`.devcontainer/`, `run_all.sh`
with its infinite `nohup` loop) with a standard Linux/systemd deployment.

## 1. Get the code on the server

```bash
sudo mkdir -p /opt/recon-ecosystem
sudo chown $USER:$USER /opt/recon-ecosystem
git clone <your-repo-url> /opt/recon-ecosystem
cd /opt/recon-ecosystem
```

If you use a different path than `/opt/recon-ecosystem`, update it in:
- `deploy/systemd/*.service` (`WorkingDirectory=`, `ExecStart=`)
- `deploy/systemd/watch-loop.sh` (`REPO_ROOT=`)

## 2. Create a dedicated user (recommended, avoid running as root)

```bash
sudo useradd -r -m -s /bin/bash watchtower
sudo chown -R watchtower:watchtower /opt/recon-ecosystem
sudo mkdir -p /var/log/watchtower
sudo chown watchtower:watchtower /var/log/watchtower
```

## 3. Run the install script

```bash
sudo -u watchtower bash /opt/recon-ecosystem/deploy/install_tools_vps.sh
```

This installs Go, the recon tools (subfinder, katana, nuclei, httpx, dnsx,
amass, x8, fallparams, gau, waybackurls), sets up the Python venv, and
compiles the `xsscanner` binaries.

## 4. Configure environment files

```bash
cp watchtower/.env.example watchtower/.env
cp watchtower-frontend/.env.example watchtower-frontend/.env
cp xsscanner/.env.example xsscanner/.env
```

Fill in `MONGO_URI`, `WATCHTOWER_API_TOKEN` (must match on backend and
frontend), Telegram tokens, etc. See the comments in each `.env.example`.

For the frontend, since it's no longer proxied through Vite dev server in
production, set:
```
VITE_API_URL=https://yourdomain.com/api
```
(or wherever your reverse proxy exposes the backend — see nginx note below).

## 5. Build the frontend

```bash
cd watchtower-frontend
pnpm install
pnpm build
```

This produces `dist/public` (static assets) and `dist/index.js` (the small
Express server referenced by `watchtower-frontend.service`).

## 6. MongoDB

Either:
- Point `MONGO_URI` in `watchtower/.env` at MongoDB Atlas (simplest), or
- Run the bundled local Mongo:
  ```bash
  cd watchtower/database
  docker compose --profile local-db up -d
  ```
  and use `MONGO_URI=mongodb://localhost:27017/watchtower`.

## 7. Install and enable the systemd services

```bash
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo chmod +x deploy/systemd/watch-loop.sh
sudo systemctl daemon-reload

sudo systemctl enable --now watchtower-api.service
sudo systemctl enable --now watchtower-frontend.service
sudo systemctl enable --now watch-loop.service
```

Check status/logs:
```bash
systemctl status watchtower-api
journalctl -u watchtower-api -f
tail -f /var/log/watchtower/api.log
```

## 8. Reverse proxy (nginx) — recommended for TLS + a single public port

Example `/etc/nginx/sites-available/watchtower`:
```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location /api/ {
        proxy_pass http://127.0.0.1:3131/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```
Then run `sudo certbot --nginx -d yourdomain.com` for HTTPS.

## What changed vs. the Codespaces setup

| Codespaces version | VPS version |
|---|---|
| `.devcontainer/devcontainer.json` | Deleted — not needed outside VS Code/Codespaces |
| `install_tools.sh` (`REPO_ROOT=$(dirname "$(pwd)")`) | `install_tools_vps.sh` resolves root from the script's own path |
| `run_all.sh` infinite `nohup ... &` loop | `watch-loop.service` + `watch-loop.sh`, supervised by systemd |
| Codespaces auto-generated `*.app.github.dev` URLs | nginx + your own domain/TLS |
| `xsscanner/main.go` hardcoded `/workspaces/Recon_ecosystem/...` python path | Made relative to `repoRoot` / overridable via `WATCHTOWER_PYTHON` env var (see separate patch) |

## Updating the deployment later

```bash
cd /opt/recon-ecosystem
git pull
cd xsscanner && go build -o xsscanner main.go && go build -o xssniper xssniper.go   # rebuild changed binaries
cd ../watchtower-frontend && pnpm install && pnpm build
sudo systemctl restart watchtower-api watchtower-frontend watch-loop
```