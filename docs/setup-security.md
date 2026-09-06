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
AllowTcpForwarding no
X11Forwarding no
PermitEmptyPasswords no
```

Validate syntax before restart:

```bash
sudo sshd -t
sudo systemctl restart sshd
```

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

# Allow SSH (adjust port if you change it later)
sudo ufw allow 22/tcp          # or 2222/tcp if you changed port

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
10. Add backups, integrity checks, and optional honeypots/IDS.

If you tell me your distro (Ubuntu/Debian/CentOS/etc.) and main services (web, DB, etc.), I can give you a tailored, copy‑pasteable hardening script.
