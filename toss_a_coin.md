# Write-up : "Toss a Coin"

**Cible :** 10.10.0.15

**Objectif :** Récupérer user.txt

**Difficulté :** Easy

**Date :** 18/09/2026

**Techniques utilisées :** Reconnaissance réseau, stéganographie (piste écartée), fuzzing récursif de répertoires, analyse du code source HTML

**Outils utilisés :** nmap, curl, exiftool, strings, binwalk, steghide, stegseek, gobuster, ssh

---

## 1. Reconnaissance initiale

### 1.1 Scan de ports

```bash
nmap -sC -sV -oN scan_initial.txt 10.10.0.15
```

**Résultat :**

| Port   | Service | Version                    |
| ------ | ------- | -------------------------- |
| 22/tcp | SSH     | OpenSSH 10.0p2 (Debian 13) |
| 80/tcp | HTTP    | Apache 2.4.68 (Debian)     |

Le titre de la page web (`http-title`) est "Toss a coin to your witcher", référence directe à la chanson du même nom de la série Netflix _The Witcher_, interprétée par le personnage de Jaskier. Le nom du challenge et cet indice donnent tout de suite la piste thématique à suivre.

### 1.2 Page d'accueil

```bash
curl -s http://10.10.0.15/
```

Pour voir les headers de réponse (souvent des indices y sont cachés).

La page contient :

- Un lien vers `/main.css`
- Une image `/img/jaskier.jpg`
- Un texte d'indice : _"Don't fight it, you know you want to sing it, it might even help you out."_

→ Message clair : il faut littéralement "chanter" / connaître les paroles de la chanson pour progresser.

---

## 2. Fausses pistes explorées

Avant de trouver la bonne voie, plusieurs hypothèses classiques de CTF ont été testées et écartées.

### 2.1 Stéganographie sur l'image

```bash
exiftool jaskier.jpg
strings jaskier.jpg | tail -50
binwalk jaskier.jpg
steghide info jaskier.jpg
```

`steghide` a détecté un format JPEG compatible avec une capacité de dissimulation (~5 KB), suggérant une possible donnée cachée protégée par passphrase.

**Outils utilisés pour le bruteforce :**

- Installation de `stegseek` (via `.deb` GitHub, car les dépôts Debian avaient un conflit de dépendances libc6/libstdc++6) :

```bash
wget https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb
dpkg -i stegseek_0.6-1.deb
```

- Bruteforce avec rockyou.txt :

```bash
stegseek jaskier.jpg /usr/share/wordlists/rockyou.txt
```

- Wordlist personnalisée basée sur les thèmes de la chanson (mots-clés, pas de paroles complètes reproduites).

**Résultat :** aucune passphrase valide trouvée. Cette piste a été abandonnée -> l'image ne contenait pas de données stéganographiques exploitables (ou pas avec cette méthode).

**Leçon :** ne pas s'acharner sur une piste si les outils dédiés (stegseek avec rockyou) ne donnent rien rapidement ; il faut explorer les autres surfaces d'attaque en parallèle.

---

## 3. La véritable faille : fuzzing récursif "épelé"

### 3.1 Découverte du dossier /t/

```bash
gobuster dir -u http://10.10.0.15/ -w /opt/lists/seclists/Discovery/Web-Content/common.txt -x php,txt,html,zip,bak -t 50
```

**Résultat notable :**

```
img (Status: 301) --> /img/
t   (Status: 301) --> /t/
```

Le dossier `/img/` était déjà connu. Le dossier `/t/` est la vraie piste.

### 3.2 Contenu de /t/

```bash
curl -s http://10.10.0.15/t/
```

**Message affiché :** _"Do you know the lyrics? this one is pretty famous!"_

-> Confirmation : le chemin serveur encode la chanson lettre par lettre.

### 3.3 Principe de la vulnérabilité

Le serveur expose une arborescence de répertoires où chaque caractère de la phrase-clé (le refrain de la chanson) devient un sous-dossier d'une seule lettre, et les espaces entre les mots sont encodés par des underscores (`_`) servant de séparateurs. Il fallait fuzzer niveau par niveau pour reconstituer le chemin complet, caractère par caractère.

### 3.4 Méthodologie de découverte

Pour chaque niveau de répertoire découvert, la même boucle a été répétée :

```bash
# 1. Voir le contenu du dossier courant
curl -s http://10.10.0.15/<chemin_actuel>/

# 2. Fuzzer pour trouver le caractère/segment suivant
gobuster dir -u http://10.10.0.15/<chemin_actuel>/ \
  -w /opt/lists/seclists/Discovery/Web-Content/common.txt \
  -x php,txt,html,zip,bak -t 50
```

`-t 50` = c'est juste le nombre de threads (requêtes en parallèle) que gobuster va utiliser. Si l'on met rien, gubuster utilise 10 par défaut.

Chaque exécution de gobuster révélait un nouveau sous-dossier (statut 301) correspondant à la lettre suivante, jusqu'à révéler progressivement le chemin :

```
/t/o/s/s/_/a/_/c/o/i/n/_/t/o/_/y/o/u/r/_/w/i/t/c/h/e/r/_/o/h/_/v/a/l/l/e/y/_/o/f/_/p/l/e/n/t/y/
```

Ce chemin épelle, lettre par lettre et mot par mot (séparés par `_`), la phrase-clé du refrain de la chanson (sans caractère apostrophe, remplacé ici par "oh").

### 3.5 La page finale

```bash
curl -s "http://10.10.0.15/t/o/s/s/_/a/_/c/o/i/n/_/t/o/_/y/o/u/r/_/w/i/t/c/h/e/r/_/o/h/_/v/a/l/l/e/y/_/o/f/_/p/l/e/n/t/y/"
```

Cette page (taille `index.html` : 371 octets, contre 226 sur toutes les pages "génériques" précédentes) contenait :

- Un message de validation : _"So you DO know the lyrics. Well, good for you!"_
- Une seconde image : `/img/jaskier2.jpg`
- Des identifiants cachés dans un élément HTML masqué (`style="display: none;"`) :

```
jaskier:YouHaveTheMostIncredibleNeckItsLikeASexyGoose
```

**Faille exploitée ici :** divulgation d'informations sensibles (credentials) dans le code source HTML, cachées visuellement via CSS (`display: none`) mais totalement visibles dans le code source brut / réponse HTTP.

---

## 4. Accès SSH

Avec les identifiants trouvés :

```bash
ssh jaskier@10.10.0.15
# Password: YouHaveTheMostIncredibleNeckItsLikeASexyGoose
```

Connexion réussie sur `the_continent` (Linux, kernel 6.8.0-136-generic Ubuntu).

### Récupération du flag

```bash
cat ~/user.txt
```

**Résultat obtenu :**

```
EPI{R3Sp3C7_D03sNT_M4k3_h1S70rY}
```

---

## 5. Résumé de la chaîne d'attaque

| Étape | Action                             | Résultat                                     |
| ----- | ---------------------------------- | -------------------------------------------- |
| 1     | Scan Nmap                          | Ports 22 (SSH) et 80 (HTTP) ouverts          |
| 2     | Analyse page web                   | Indice thématique "chanson à chanter"        |
| 3     | Stéganographie (fausse piste)      | Aucune donnée cachée trouvée dans l'image    |
| 4     | Gobuster sur /                     | Découverte du dossier `/t/`                  |
| 5     | Fuzzing récursif lettre par lettre | Reconstruction du chemin épelant le refrain  |
| 6     | Page finale                        | Credentials cachés en HTML (`display: none`) |
| 7     | SSH avec les credentials           | Accès shell obtenu                           |
| 8     | `cat user.txt`                     | Flag récupéré                                |

---

## Résumé de la faille exploitée

| #   | Faille                                                                         | Type / Catégorie                            | Explication courte                                                                                                                      |
| --- | ------------------------------------------------------------------------------ | ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Credentials exposés dans le HTML, masqués uniquement via CSS (`display: none`) | Exposure of Sensitive Information (CWE-200) | Une "sécurité" purement visuelle côté client n'a aucun effet côté serveur : les identifiants restent lisibles dans le code source brut. |

---

## Conclusion

- **Accès initial :** énumération OSINT/narrative (indices de la page) -> fuzzing récursif de répertoires épelant les paroles d'une chanson -> découverte de credentials cachés en HTML.
- **Flag user :** obtenu dans `~/user.txt` après connexion SSH avec l'utilisateur `jaskier`.

---

## Evidences

### File / Toss A Coin

![File / Toss A Coin](Evidences/File%20Toss%20a%20coin.png)

### Fichier hidden

![Fichier hidden](Evidences/Flag%20Toss%20a%20coin.png)
