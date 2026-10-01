# Write-up : "Yer a Wizard, Harry!"

**Target:** 10.10.0.5

**Difficulty:** Easy

**Date:** 14/09/2026

**Objective:** Get user.txt

**Techniques used:** Network reconnaissance, anonymous FTP exploitation, credential reuse, nested Base64 decoding

**Tools used:** nmap, ftp, ssh, base64

---

## 1.1 Connectivity check (ping)

**Command:**

```bash
ping -c 4 10.10.0.5
```

**Why:** before launching a full port scan (which can take a while, especially with -p-), we check that the target machine is reachable on the network. This lets us:

- Confirm that the VPN/lab connection is properly established and that the route to the target works.

- Get a first estimate of latency (useful if heavier scans are planned).

- Quickly detect a network configuration issue on the attacker's side rather than wasting time debugging an nmap that returns nothing.

**Result:** the machine responds to ICMP requests (consistent TTL, response time) -> the target is indeed active and reachable.

## 1.2 Network reconnaissance (Nmap)

**Command:**

```bash
nmap -sC -sV -p- -T4 10.10.0.5
```

**Why:** the first systematic step of any pentest/CTF -> identify the services exposed on the target machine to know where to get in.

**Result:** 2 open ports

- `21/tcp`: FTP (vsftpd 3.0.5)
- `22/tcp`: SSH (OpenSSH 10.0p2)

---

## 2. Anonymous FTP exploitation

**Vulnerability exploited:** Unrestricted anonymous FTP access (CWE-284: Improper Access Control) -> service misconfiguration allowing anonymous authentication on a service that should be protected.

```bash
ftp 10.10.0.5
```

Then in the ftp session:

```
Name: anonymous
Password: [empty, just Enter]
ls -la
get .hidden (doesn't work)
quit
```

In the exegol container:

```
wget -r ftp://anonymous:anonymous@10.10.0.5/
```

```
Name: anonymous
Password: [empty, just Enter]
cd ...
ls -la
get .reallyHidden
quit
```

- `ls -la` = Lists the current directory's content on the FTP server, with the options:

-l: detailed format (permissions, owner, size, date)
-a: also shows hidden files/folders (those starting with a dot .)

- `get .hidden` = Downloads the .hidden file from the FTP server to the local directory.

- `wget -r ftp://anonymous:anonymous@10.10.0.5/` = To download everything at once.

- `cd ...` = Hide a directory discreetly. A folder name "camouflaged" to look like a navigation shortcut.

- `ls -la` = Same as the first time, but applied to the content of the `...` folder we just entered -> to spot other hidden files inside it.

- `get .reallyHidden` = Downloads a second hidden file, .reallyHidden, found in this `...` subdirectory.

- `quit` = Closes the FTP connection and exits the FTP client, returning to the local shell.

**Why it worked:** the FTP server accepted connections with the `anonymous` login without requiring a valid password -> poor configuration practice.

**Files found:**

- `.hidden` -> first password (didn't work)
- Hidden folder `...` -> contained `.reallyHidden` with the correct password

---

## 3. Reading the retrieved files

```bash
cat .hidden
# → "Il0veTheMalefoys" (password that didn't work)

cat .reallyHidden
# → "IAlreadySaidTooMuch" (correct password)
```

---

## 4. SSH authentication with a weak password

**Vulnerability exploited:** Weak / exposed credentials (CWE-521 (Weak Password) / CWE-522 (Insufficiently Protected Credentials)
-> credential leak via a poorly secured service, then reuse on another service.

```bash
ssh hagrid@10.10.0.5
```

Prompt responses:

```
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
hagrid@10.10.0.5's password: IAlreadySaidTooMuch
```

**Why it worked:** the password found via FTP (`IAlreadySaidTooMuch`) matched the SSH account `hagrid` - a classic exploitation chain where a weakness on one service (FTP) allows pivoting to another (SSH), via reuse of discovered information rather than a technical exploit.

---

## 5. Post-connection exploration

```bash
ls -la
find / -name "user.txt" 2>/dev/null
cat user.txt
```

**Items spotted in `hagrid`'s home:**

- `user.txt` -> the flag we're looking for (base64 encoded)
- `riddle.txt` with permissions `----------` (unreadable, potential hint for privilege escalation)
- `.ssh` folder with the `headmaster` group (suspicious, likely a lead for later)
- `hut` folder

---

## 6. Decoding the flag (nested Base64 obfuscation)

**Layer 1:**

```bash
echo "VWxaQ1NtVjZRblZOTVRseVdWVTFabUpxVGpKTk1VcG1ZVWRHVjAweE9IcGlha0pXVDFWb1prNVVRa1JUZWtvNVEyYzlQUT09" | base64 -d
# → UlZCSmV6QnVNMTlyWVU1ZmJqTjJNMUpmYUdGV00xOHpiakJWT1VoZk5UQkRTeko5Q2c9PQ==
```

**Layer 2:**

```bash
echo "UlZCSmV6QnVNMTlyWVU1ZmJqTjJNMUpmYUdGV00xOHpiakJWT1VoZk5UQkRTeko5Q2c9PQ==" | base64 -d
# → RVBJezBuM19rYU5fbjN2M1JfaGFWM18zbjBVOUhfNTBDSzJ9Cg==
```

**Layer 3 (final):**

```bash
echo "RVBJezBuM19rYU5fbjN2M1JfaGFWM18zbjBVOUhfNTBDSzJ9Cg==" | base64 -d
```

**FLAG obtained:**

```
EPI{0n3_kaN_n3v3R_haV3_3n0U9H_50CK2}
```

---

## Summary of exploited vulnerabilities

| #   | Vulnerability                                        | Type / Category                                      |
| --- | ----------------------------------------------------- | ------------------------------------------------------ |
| 1   | Anonymous FTP enabled                                 | Misconfiguration / access control (CWE-284)             |
| 2   | Plaintext passwords in accessible files               | Credential exposure                                     |
| 3   | Weak password reused for SSH                          | Weak credentials / reuse (CWE-798)                      |

---

## Conclusion

- **Initial access:** exploitation of anonymous FTP → retrieval of two hidden files containing passwords.
- **Pivot:** reuse of the FTP password for SSH authentication as `hagrid`.
- **User flag:** `EPI{0n3_kaN_n3v3R_haV3_3n0U9H_50CK2}` obtained after decoding three successive Base64 layers in `user.txt`.

---

## Evidences

### Nmap / Network reconnaissance

![Nmap / Network reconnaissance](Evidences/Nmap%20Yer%20a%20wizard.png)

### Hidden file

![Hidden file](Evidences/Hidden%20file.png)

### ReallyHidden file

![ReallyHidden file](Evidences/ReallyHidden%20file.png)

### Flag

![Flag file](Evidences/Flag%20Yer%20a%20wizard.png)
