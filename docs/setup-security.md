# VPS Security Hardening Checklist (2026)

Prioritized, practical hardening steps for a freshly bought Linux VPS (Ubuntu/Debian–style; CentOS/RHEL notes included). Steps are ranked by impact vs. effort and ordered so you can do them safely without locking yourself out.

---

## 0. Before you start: safety net

Do these first so a misconfiguration doesn't strand you.

### 0. Setup ssh

### 1. Generate keypair / copy public key to a VPS

ssh-keygen -a 100 -t ed25519 -f ~/.ssh/id_ed25519_vps_secure -C "dmikhailov@vps"
ssh-copy-id -i ~/.ssh/id_ed25519_vps_secure.pub root@your_vps_ip

### 1. Take a snapshot / backup

- Use your VPS provider's snapshot feature before making SSH/firewall changes.
- Keep console/VNC access enabled in the control panel.

### 2. Patch the system first (before hardening)

```bash
sudo apt update && sudo apt full-upgrade -y && sudo apt autoremove -y
sudo reboot
```

Also update installed snapshot/CVE-critical packages on RHEL-family with `sudo dnf upgrade`.

### 3. Test SSH key login before disabling passwords

From your local machine:

```bash
ssh -i ~/.ssh/id_ed25519_vps_secure vps@your_vps_ip
```

Confirm it works without a password.

### 4. Pre-flight status check

Read-only snapshot of what the server already has, so you can skip anything already done:

```bash
# OS release and kernel
. /etc/os-release && echo "$PRETTY_NAME"

# SSH listening port + effective sshd settings
sudo ss -tlnp | grep ssh
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauth|kbdinteractive|authenticationmethods|pubkeyauthentication|port ' | sort -u

# Firewall
sudo ufw status verbose

# Fail2ban
systemctl is-active fail2ban;  sudo fail2ban-client status 2>/dev/null

# Automatic updates
dpkg -l unattended-upgrades 2>/dev/null | tail -1

# Kernel hardening values
sudo sysctl net.ipv4.tcp_syncookies kernel.randomize_va_space fs.protected_symlinks net.ipv4.conf.all.rp_filter

# Time sync
systemctl is-active chrony systemd-timesyncd
```

---

## Tier 1 – Must‑do (highest impact, low effort)

### 1. Create a non‑root sudo user and disable root SSH login

**Why:** Reduces blast radius and blocks direct root brute‑force.

```bash
# On the VPS (as root initially)
adduser vps_user
usermod -aG sudo vps_user        # Debian/Ubuntu
# For CentOS/RHEL/Fedora:
# usermod -aG wheel vps_user

# Test from another terminal:
ssh -i ~/.ssh/id_ed25519_vps_secure vps_user@your_vps_ip

# Verify/fix SSH file permissions on the VPS:
ssh -i ~/.ssh/id_ed25519_vps_secure vps_user@your_vps_ip \
  'chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys'
```

Then in `/etc/ssh/sshd_config`:

```conf
PermitRootLogin no
```

(Or `prohibit-password` if you still want root key‑only temporarily, but `no` is better once your user works.)

---

### 2. Enforce SSH key‑only authentication (disable password auth)

**Why:** Stops password brute‑force and credential stuffing entirely.

In `/etc/ssh/sshd_config`:

```conf
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
```

Reload:

```bash
sudo systemctl restart sshd
```

Keep one old session open until you confirm new key‑only login works from another terminal.

---

### 3. Harden SSH config (ciphers, KEX, limits)

**Why:** Removes weak algorithms and slows automated attacks.

Add/adjust in `/etc/ssh/sshd_config`:

```conf
# Modern algorithms (Ubuntu 22+/Debian 12+ defaults are usually fine; this is explicit)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# Reduce attack surface
MaxAuthTries 3
MaxStartups 10:30:60
LoginGraceTime 60
AllowAgentForwarding no
AllowTcpForwarding local    # keep -L local tunnels working; `-R` remote forwarding still off
X11Forwarding no
PermitEmptyPasswords no
PermitUserEnvironment no
```

Validate syntax before restart:

```bash
sudo sshd -t
sudo systemctl restart sshd
```

#### Recommended: use a drop-in file instead of editing `sshd_config`

Ubuntu 22.04+/Debian 11+/OpenSSH ≥8.2 include `/etc/ssh/sshd_config.d/*.conf`. A drop-in survives `openssh-server` package updates that rewrite the main file (first value wins, so it overrides defaults):

```bash
sudo tee /etc/ssh/sshd_config.d/99-hardening.conf > /dev/null <<'EOF'
# Consolidated steps 1-3
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PubkeyAuthentication yes
PermitEmptyPasswords no
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding local    # keep -L local tunnels working; `-R` remote forwarding still off
X11Forwarding no
MaxAuthTries 3
MaxStartups 10:30:60
LoginGraceTime 60
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
EOF
sudo sshd -t
```

If `sshd -t` passes, restart and test from a **second terminal** before closing your current one.

---

### 4. Set up a host firewall (default‑deny, allow only needed ports)

**Why:** Limits exposure even if a service is misconfigured.

#### Ubuntu/Debian (UFW)

```bash
sudo apt update
sudo apt install ufw

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (use `limit` to rate-limit brute force; adjust port if you changed it)
sudo ufw limit ssh/tcp       # or `sudo ufw allow 2222/tcp` if you changed port

# Allow web/mail/etc as needed
# sudo ufw allow 80/tcp
# sudo ufw allow 443/tcp

sudo ufw enable
sudo ufw status verbose
```

#### CentOS/RHEL (firewalld)

```bash
sudo dnf install firewalld
sudo systemctl enable --now firewalld

sudo firewall-cmd --set-default-zone=public
sudo firewall-cmd --permanent --remove-service=ssh
sudo firewall-cmd --permanent --add-service=ssh   # or custom port later
# sudo firewall-cmd --permanent --add-service=http
# sudo firewall-cmd --permanent --add-service=https

sudo firewall-cmd --reload
```

---

### 5. Enable automatic security updates

**Why:** Closes known vulnerabilities quickly without manual work.

#### Debian/Ubuntu

```bash
sudo apt update
sudo apt install unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

Ensure only security updates:

```bash
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
```

Make sure you have something like:

```conf
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
//  "${distro_id}:${distro_codename}-updates";   // optional
};
```

Test dry‑run:

```bash
sudo unattended-upgrade --dry-run
```

#### RHEL/CentOS/Fedora

Use `dnf-automatic`:

```bash
sudo dnf install dnf-automatic
sudo systemctl enable --now dnf-automatic-install.timer
```

Configure `/etc/dnf/automatic.conf` to apply security updates.

---

## Tier 2 – Very important (strong security boost)

### 6. Change SSH port (optional but useful)

**Why:** Reduces noise from bots scanning port 22. Not strong security by itself, but helpful combined with other steps.

Pick a high, unused port (e.g. `2222` or something less common).

1. Update firewall first:

```bash
# UFW
sudo ufw allow 2222/tcp

# firewalld
sudo firewall-cmd --permanent --add-port=2222/tcp
sudo firewall-cmd --reload
```

2. Edit `/etc/ssh/sshd_config`:

```conf
Port 22
Port 2222
```

(Keep both temporarily; remove `Port 22` later.)

3. Restart SSH and test from a **new** terminal:

```bash
ssh -p 2222 -i ~/.ssh/your_key vps_user@your_vps_ip
```

If OK, remove `Port 22` from `sshd_config` and restart again.

If using SELinux (CentOS/RHEL):

```bash
sudo dnf install policycoreutils-python-utils
sudo semanage port -a -t ssh_port_t -p tcp 2222
```

---

### 7. Install and configure Fail2Ban (or CrowdSec)

**Why:** Automatically bans IPs that show brute‑force or abusive behavior.

#### Fail2Ban

```bash
sudo apt install fail2ban    # Debian/Ubuntu
# or
sudo dnf install fail2ban    # RHEL/CentOS
```

Create `/etc/fail2ban/jail.local` (don't edit `jail.conf` directly):

```ini
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
banaction = nftables      # or firewall-cmd for firewalld

[sshd]
enabled = true
port = ssh           # or 2222 if you changed it
logpath = %(sshd_log)s
maxretry = 5
bantime = 3600
```

For web servers, add jails like `nginx-bad-request`, `apache-auth`, etc.

Enable and check:

```bash
sudo systemctl enable --now fail2ban
sudo fail2ban-client status
sudo fail2ban-client status sshd
```

---

### 8. Basic kernel/sysctl hardening

**Why:** Mitigates some network‑level attacks and information leaks.

Create `/etc/sysctl.d/99-hardening.conf`:

```conf
# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Anti-spoofing (reverse path filtering) and SYN flood protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1

# ASLR and reduce kernel info leaks
kernel.randomize_va_space = 2
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1

# Prevent symlink/hardlink attacks
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Disable IPv6 if not used (optional)
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1
```

Apply:

```bash
sudo sysctl --system
```

---

### 9. Disable unused services and close unnecessary ports

**Why:** Less code running = smaller attack surface.

Check listening services:

```bash
sudo ss -tulpn
# or
sudo netstat -tulpn
```

From another host, scan:

```bash
nmap -sV your_vps_ip
```

Stop and disable anything you don't need:

```bash
sudo systemctl stop some-service
sudo systemctl disable some-service
```

Common candidates: unused FTP, telnet, old database listeners, demo apps, etc.

---

## Tier 3 – Strong additional hardening

### 10. Enable AppArmor or SELinux in enforcing mode

**Why:** Adds mandatory access control, limiting what compromised services can do.

#### Ubuntu (AppArmor)

```bash
sudo apt install apparmor apparmor-utils
sudo aa-status
```

Ensure important profiles are in `enforce` mode.

#### RHEL/CentOS/Fedora (SELinux)

```bash
getenforce
# Should be Enforcing; if not:
sudo setenforce 1
# Make permanent in /etc/selinux/config: SELINUX=enforcing
```

Audit and tune with `audit2allow` if needed.

---

### 11. File integrity monitoring (AIDE, osquery, etc.)

**Why:** Detects unexpected changes to critical files (possible compromise).

Example with AIDE:

```bash
sudo apt install aide
sudo aide --init
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
```

Later, check:

```bash
sudo aide --check
```

Integrate with cron and alerting as needed.

---

### 12. Secure time sync and logging

**Why:** Accurate timestamps are crucial for forensics and correlation.

Enable `systemd-timesyncd` or `chrony`:

```bash
sudo apt install chrony
sudo systemctl enable --now chrony
```

If you use chrony, disable `systemd-timesyncd` first to avoid conflict:

```bash
sudo systemctl disable --now systemd-timesyncd
```

Verify sync:

```bash
chronyc tracking | head -4
```

Ensure logs are retained and rotated:

```bash
sudo nano /etc/logrotate.conf
```

Consider remote log shipping (e.g., to a separate server or S3‑compatible storage) for critical systems.

---

### 13. Restrict sudo and use strong policies

**Why:** Limits privilege escalation paths.

Edit `/etc/sudoers` with `visudo`:

```conf
vps_user ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/systemctl reload nginx
```

Avoid blanket `NOPASSWD: ALL` unless absolutely necessary. Use per‑command rules where possible.

---

## Tier 4 – Advanced / optional (good for high‑value servers)

### 14. Honeypots / deception (e.g., cowrie, endlessh)

**Why:** Wastes attackers' time, gives early warning, and provides logs. Not a replacement for hardening, but useful extra layer.

Example: simple SSH honeypot (cowrie) in a container or separate VM, not on your main production IP if possible. Basic idea:

```bash
# Example: run cowrie in Docker (on a separate host/IP ideally)
docker run -d --name cowrie \
  -p 2222:2222 \
  cowrie/cowrie
```

Configure it to listen on a different port/IP and monitor logs. Treat any connection to that port as suspicious activity.

For "endlessh" (SSH tarpit):

```bash
git clone https://github.com/skeeto/endlessh
cd endlessh
make
sudo ./endlessh -p 2222 &
```

Then advertise that port via DNS or let bots find it; they'll get stuck.

---

### 15. Intrusion detection / host monitoring

**Why:** Helps detect compromise early.

Options:

- **OSSEC / Wazuh** (HIDS)  
- **Lynis** for periodic auditing:

```bash
sudo apt install lynis
sudo lynis audit system
```

Review output and fix high‑priority findings.

---

### 16. Network‑level protections (provider / external)

Depending on your VPS provider:

- Enable **DDoS protection** if available.  
- Use **private networking** for DB/cache/app tiers; bind services to private IPs or `127.0.0.1`.  
- Put public services behind a reverse proxy (nginx/Cloudflare/etc.) and restrict direct access to app ports via firewall.

For databases:

```conf
# Example: bind MySQL to localhost only
bind-address = 127.0.0.1
```

Then access via local socket or private network.

---

### 17. Backups and disaster recovery

**Why:** If you're compromised, clean restore is often safer than "cleaning" a hacked box.

- Regular **off‑site, encrypted backups** of critical data and configs.  
- Periodically test **restore** procedures.  
- Keep at least one **immutable** backup copy if your provider supports it.

Use tools like `restic`, `borg`, or provider snapshots plus external storage.

---

### 18. Additional SSH hardening (advanced)

If you control clients too:

- Use **short‑lived certificates** (OpenSSH CA).  
- Restrict users via `Match User` blocks in `sshd_config`.  
- Use `ForceCommand` or restricted shells for specific accounts.  
- Enable two‑factor (e.g., `google-authenticator` PAM) if password auth must stay for some users (less ideal than key‑only).

---

### 19. Malware scanning (ClamAV)

**Why:** Proxy/VPN servers relay untrusted traffic and can silently host malicious uploads; a background scanner catches known malware before it spreads.

Install and start the daemon + signature updater:

```bash
sudo apt install -y clamav clamav-daemon
sudo systemctl enable --now clamav-freshclam clamav-daemon
sudo freshclam                      # pull signatures immediately (first run takes a few minutes)
```

Enable useful logging in `/etc/clamav/clamd.conf`:

```conf
LogTime true
LogRotate true
```

Then `sudo systemctl restart clamav-daemon`. Monitor:

```bash
sudo journalctl -u clamav-daemon -f        # follow daemon logs (systemd)
sudo journalctl -u clamav-freshclam -f     # signature updates
sudo tail -f /var/log/clamav/clamav.log    # file log if configured
sudo clamdscan /etc/hosts                   # sanity check that scanning works
```

Scheduled full-disk scan (weekly, daemon already running):

```bash
sudo tee /etc/cron.daily/clamscan > /dev/null <<'EOF'
#!/bin/sh
clamdscan --quiet --exclude-dir=/proc --exclude-dir=/sys --exclude-dir=/dev --exclude-dir=/run --exclude-dir=/boot /
EOF
sudo chmod +x /etc/cron.daily/clamscan
```

Notes:

- 3x-ui/Xray and scanned uploads live under `/var/lib/xray` or your config dirs — add an explicit `clamdscan` on them if you want tighter coverage.
- ClamAV costs ~300–500 MB RAM and noticeable CPU on scans; on a small VPS prefer `clamdscan` (daemon) over one-shot `clamscan` and schedule scans off-peak.
- On-access scanning (`OnAccessPrevention`) requires fanotify kernel support and can interfere with active transfer workloads — leave it off for a proxy box.

---

### 20. Swap / memory headroom

**Why:** On small VPSes (1 GB RAM is common), swap prevents OOM-kills when ClamAV scans or Xray bursts. Size guidance for a 1-core / 1 GB RAM / 10 GB disk box: **1–2 GB** (2 GB recommended; below 1 GB isn't worth it, and don't eat more than ~20% of your disk).

Check current state:

```bash
free -h
swapon --show
```

Set up a swapfile if none exists:

```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# keep swap for emergencies rather than active use:
echo 'vm.swappiness = 10' | sudo tee /etc/sysctl.d/99-swap.conf
sudo sysctl --system
```

> If `fallocate` isn't supported on the filesystem (e.g. errors), use `sudo dd if=/dev/zero of=/swapfile bs=1M count=2048` instead.

Resize an existing swapfile (swap can't be resized in place — recreate it; `/etc/fstab` needs no edits since the path is unchanged):

```bash
sudo swapoff -a
sudo rm -f /swapfile
sudo fallocate -l 2G /swapfile                 # new size
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
swapon --show
```

> If `swapoff -a` fails because RAM is too full to hold the swap contents, run it during a quiet window (stop ClamAV scan first) or temporarily increase size from a snapshot.

---

### 21. VLESS VPN via 3x-ui (Xray)

**Why:** 3x-ui is a web panel that manages a VLESS/Xray proxy. It is a high-value public target with a history of CVEs — the panel itself is the weak point, not Xray. This section is the "tuning" companion to the rest of the checklist for a proxy box.

#### 21.1 Install 3x-ui and verify

```bash
bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
sudo systemctl status x-ui --no-pager
```

> `curl | bash` of a third-party script is inherently trusting — run it on a fresh box, right after your snapshot. State lives in `/usr/local/x-ui` (binaries) and `/etc/x-ui/x-ui.db` (config, users, inbounds), path varies by 3x-ui version; some builds use `/etc/3x-ui/`).

#### 21.2 Harden the panel immediately (do this before adding users)

3x-ui listens on **0.0.0.0** — the firewall is what protects it:

```bash
# fix default admin/admin password via CLI:
sudo x-ui              # → Panel settings → change username/password
```

Then in **Panel Settings** (web UI):

- Set a **strong random panel password** (not `admin`).
- Set a **non-default web base path** (URI path) — e.g. `/xui-x-#7k2` — so the login page isn't at the well-known `/`.
- Set the panel port to a high random value (e.g. `55123`) and keep the UFW rule in sync.
- Pick your inbounds: prefer a **single VLESS inbound on 443 with TLS** (Reality or WebSocket+TLS) to minimize the listening surface; avoid opening many proxy ports.

#### 21.3 UFW rules for the proxy

**Configure UFW *before* running the installer.** With default-deny already active, whatever 3x-ui binds (panel port, xray ports) is unreachable until a rule exists — this closes the window between install finishing and you changing the default `admin` credentials. If you plan SSH-tunnel-only panel access, add no panel rule at all.

```bash
# VLESS+TLS + optional HTTP fallback:
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp               # only if you use a redirect/fallback site

# Everything else stays default-deny:
sudo ufw status verbose
```

Prefer the **SSH-tunnel only** approach for the panel and delete the panel rule entirely — then 0.0.0.0:55123 is unreachable from the Internet:

```bash
ssh -N -L :55123:localhost:55123 vps_user@your_vps_ip
# open http://127.0.0.1:55123 locally
```

#### 21.4 TLS certificate: generate + install (Let's Encrypt via acme.sh)

A real, trusted cert is required for VLESS+WS+TLS to terminate TLS properly (Reality/self-signed won't do). Prereqs: the domain's A record points to the VPS and port 80 is open for the HTTP-01 challenge.

```bash
# 1. Issue an ECDSA cert (standalone temporarily binds :80)
/root/.acme.sh/acme.sh --issue -d your-domain.com \
  --standalone --keylength ec-256 --server letsencrypt

# 2. Install into a stable, x-ui-readable path + auto-restart x-ui on renewal
sudo mkdir -p /usr/local/x-ui/bin/cert
/root/.acme.sh/acme.sh --install-cert -d your-domain.com --ecc \
  --key-file       /usr/local/x-ui/bin/cert/your-domain.com.key \
  --fullchain-file /usr/local/x-ui/bin/cert/your-domain.com.fullchain \
  --reloadcmd "systemctl restart x-ui"
```

Verify files + that the server serves them:

```bash
sudo ls -la /usr/local/x-ui/bin/cert/
echo | openssl s_client -connect your_vps_ip:443 -servername your-domain.com 2>&1 \
  | grep -E "subject=|issuer=|Verify return"
# expect: CN=your-domain.com, issuer Let's Encrypt, "Verify return code: 0 (ok)"
```

#### 21.5 Point 3x-ui at the cert + gotchas that actually made it work

In 3x-ui, edit the **port-443 VLESS inbound → Transport tab**:

- **Network**: `ws` (WebSocket) · **Path**: `/asdfv` · **Host**: your-domain.com
- **Security**: `TLS` (NOT Reality) · **Server name (SNI)**: your-domain.com · ALPN: `h2, http/1.1`
- **Certificates → Public Key File**: `/usr/local/x-ui/bin/cert/your-domain.com.fullchain`
- **Certificates → Private Key File**:  `/usr/local/x-ui/bin/cert/your-domain.com.key`

Gotchas that caused the long "timeouts / unrecognized name" hunt:

1. **The 3x-ui cert field must be a real cert chain (`.fullchain`/`.cer`/`.pem`), never a `.csr`.** A `.csr` (signing request) breaks TLS silently → timeouts.
2. **`config.json` is regenerated from 3x-ui's SQLite DB** (`/usr/local/x-ui/bin/config.json`). Don't hand-edit it; Xray hot-applies changes from the DB on panel Save, so an on-disk `config.json` can look stale even when the live config is fine.
3. **Keep client/server in sync**: matching UUID, port 443, and correct client `server` address (a `localhost` typo = pure timeouts). **Disable ECH in the Hiddify client** — Xray has no ECH, so an ECH-enabled client breaks the handshake.
4. **Verify listeners + TLS after each change**:
   ```bash
   sudo ss -tlnp | grep 443          # proxy actually listening?
   curl -sk -o /dev/null -w "%{http_code}\n" "https://your-domain.com/asdfv" \
     -H "Connection: Upgrade" -H "Upgrade: websocket" \
     -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
   # HTTP 400 = Xray WS endpoint alive (rejects the non-VLESS handshake — expected)
   ```
5. **Reality vs WS+TLS under DPI**: a byte-identical Reality config failed here (timeouts / "reality verification failed") — classic ISP/ТСПУ probing. **VLESS+WS+TLS direct to the VPS worked** where Reality didn't. Hiding the VPS IP from DPI would need the domain behind Cloudflare CDN, which requires delegating nameservers (mooo.com / free VDSina domains usually can't).

## Post-hardening verification

Run this sweep to confirm everything stuck:

```bash
echo "== sshd =="
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauth|kbdinteractive|authenticationmethods|pubkeyauthentication'
echo "== firewall =="
sudo ufw status verbose
echo "== fail2ban =="
sudo fail2ban-client status sshd
echo "== kernel =="
sudo sysctl net.ipv4.tcp_syncookies kernel.randomize_va_space fs.protected_symlinks net.ipv4.conf.all.rp_filter
```

Expected: `PermitRootLogin no`, `passwordauthentication no`, `authenticationmethods publickey`; UFW `Status: active`; fail2ban `Number of currently failed: 0`; sysctl values `1 / 2 / 1 / 1`.

---

## Suggested order of operations (safe sequence)

1. Snapshot VPS.  
2. Create non‑root user, set up SSH keys, test login.  
3. Harden `sshd_config` (algorithms, limits), keep password auth temporarily.  
4. Install and configure firewall; allow SSH + required ports.  
5. Enable auto security updates.  
6. Test everything, then:  
   - Disable root login.  
   - Disable password authentication.  
   - Optionally change SSH port (with firewall + SELinux updates).  
7. Install Fail2Ban/CrowdSec.  
8. Apply sysctl hardening, disable unused services.  
9. Enable AppArmor/SELinux enforcing, set up logging/monitoring.  
10. Add backups, integrity checks, malware scanning (ClamAV), and optional honeypots/IDS.

If you tell me your distro (Ubuntu/Debian/CentOS/etc.) and main services (web, DB, etc.), I can give you a tailored, copy‑pasteable hardening script.

Everything above is also automated in [`scripts/security_setup_base.sh`](../scripts/security_setup_base.sh) — same order, idempotent, backs up configs before touching them, and won't restart SSH unless you pass `--apply-ssh`.
