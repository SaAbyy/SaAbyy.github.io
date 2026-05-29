---
title: "Think Outside The Box 1, 2 & 3"
date: 2025-10-27
platform: DEADFACE CTF 2025
category: steg
difficulty: easy
tags: [JPEG, GIF, Aperisolve]
description: "Série de 3 challenges de stéganographie du DEADFACE CTF 2025 — manipulation de headers JPEG, stégo GIF et analyse de couches couleur."
---

## Think Outside The Box 1 — JPEG Height Manipulation

### Contexte

L'indice : "think outside the box LITERALLY" — quelque chose est caché **hors des limites visibles** de l'image, dans ses dimensions déclarées.

### Analyse

Les fichiers JPEG contiennent des marqueurs structurés. Le marqueur **SOF (Start Of Frame)** déclare la hauteur et la largeur de l'image. On localise le marqueur `FFC2` (SOF progressif) dans un éditeur hex :

```
ff c2 00 11 08 01 79 01 f4
```

| Bytes | Signification |
|-------|--------------|
| `ff c2` | Marqueur SOF2 |
| `00 11` | Longueur du segment (17) |
| `08` | Précision (8 bits) |
| `01 79` | **Hauteur** = 0x0179 = **377 px** |
| `01 f4` | **Largeur** = 0x01F4 = **500 px** |

### Exploitation

Le fichier contient plus de données de scan que ce que la hauteur déclarée n'affiche. En augmentant la hauteur déclarée, le viewer rend les scanlines supplémentaires comme pixels visibles.

On modifie les bytes de hauteur de `01 79` → `03 79` :

```
ff c2 00 11 08 03 79 01 f4
                ↑
           0x0379 = 889 px
```

On peut faire ça manuellement dans HxD/xxd, ou directement via [CyberChef](https://cyberchef.io/).

### Steps

1. Copier le fichier JPG original
2. Ouvrir dans un éditeur hex (HxD, Bless, xxd)
3. Chercher le marqueur `ff c2` (ou `ff c0`)
4. Localiser les 2 bytes de hauteur après le byte de précision
5. Les modifier vers une valeur plus grande (`01 79` → `03 79`)
6. Sauvegarder et rouvrir l'image

La zone cachée sous l'image originale devient visible et révèle le flag.

```
deadface{jp3g_alt3red_he1ght!}
```

---

## Think Outside The Box 2 — GIF Steganography

### Contexte

Un fichier GIF en apparence normal — stéganographie suspectée dans les frames.

### Outil

`gift` — outil CLI pour la stéganographie GIF : [https://dtm.uk/gif-steganography/](https://dtm.uk/gif-steganography/)

### Analyse

```bash
gift analyze challenge.gif
```

L'outil dumpe les frames individuelles. Les frames **172 à 185** contiennent du texte visible quand on les inspecte séquentiellement.

```
deadface{cuT_th3_f33D!!}
```

---

## Think Outside The Box 3 — Channel Decomposition

### Contexte

Même série, même indice — cette fois l'information est cachée dans les **couches couleur** de l'image.

### Outil

[Aperisolve](https://www.aperisolve.com/) — analyse automatique de stéganographie visuelle.

### Steps

1. Charger l'image sur Aperisolve
2. Inspecter la vue **Decomposer** (analyse par couches/canaux)
3. Examiner chaque frame décomposée

```
deadface{Th3_b0X_d0esnT_eX1st}
```
