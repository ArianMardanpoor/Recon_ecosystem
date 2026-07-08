# Watchtower
Welcome to my Watchtower - Automated Bug Bounty Recon.

## Setup
1. Install the requirements with `pip3 install -r requirements.txt`
2. Inside the database directory run `docker compose up -d`
3. Modify `config.py` and put your own directory paths.
4. Configure your zshrc file.

## ZSHRC Configurations
Add the following lines to your `~/.zshrc` file:
```bash
# Watchtower Aliases
alias watch_sync_programs="python3 ~/watchtower/programs/watch_sync_program.py"
alias watch_subfinder="python3 ~/watchtower/enum/watch_subfinder.py"
alias watch_crtsh="python3 ~/watchtower/enum/watch_crtsh.py"
alias watch_enum_all="python3 ~/watchtower/enum/watch_enum_all.py"
alias watch_abuseipdb="python3 ~/watchtower/enum/watch_abuseipdb.py"
alias watch_ns="python3 ~/watchtower/ns/watch_ns.py"
alias watch_ns_all="python3 ~/watchtower/ns/watch_ns_all.py"
alias watch_http="python3 ~/watchtower/http/watch_http.py"
alias watch_http_all="python3 ~/watchtower/http/watch_http_all.py"
alias watch_nuclei_all="python3 ~/watchtower/nuclei/watch_nuclei_all.py"
