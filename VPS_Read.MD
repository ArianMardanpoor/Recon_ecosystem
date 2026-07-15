# requirements
```
sudo apt update
sudo apt install -y ca-certificates curl gnupg
sudo apt install -y git
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```
# clone repository
```
cd /opt
git clone https://github.com/ArianMardanpoor/Recon_ecosystem.git
```
# config .env
```
cd Recon_ecosystem/
cp .env.example .env
vim .env
```

# build the project and api
```
docker compose up -d --build watchtower-api
docker compose logs -f watchtower-api
```
# full scan command
```
docker compose run --rm recon-tools bash -c \
  "/xsscanner/xsscanner"
```
# fresh scan command
```
docker compose run --rm recon-tools bash -c \
  "/xsscanner/xsscanner -mode fresh"
```

# watch cammand 
```
docker compose run --rm recon-tools bash -c \
  "/watchtower/watch.sh"
```
# finishing ...
```
docker compose down -v
```

