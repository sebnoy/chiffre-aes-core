# Spécification du format `.enc`

Ce document décrit le format de fichier `.enc` produit par `chiffre_aes_core`,
suffisamment précisément pour qu'un tiers puisse le reconstruire ou
l'auditer sans lire l'intégralité du code source.

Primitives : **AES-256-GCM** (confidentialité + authentification),
**Argon2id** (dérivation de clé à partir du mot de passe), **SHA-256**
(liaison cryptographique du header aux chunks — voir §3).

---

## 1. Vue d'ensemble

```
┌──────────────┬──────────────┬───────────┬───────────┬─────┬───────────┐
│ Header (clair)│ Tag header  │ Chunk 0   │ Chunk 1   │ ... │ Chunk N-1 │
│  HEADER_FIXED │  16 octets  │ ciphertext│ ciphertext│     │ ciphertext│
│    _LEN       │  (GCM tag)  │ + tag     │ + tag     │     │ + tag     │
└──────────────┴──────────────┴───────────┴───────────┴─────┴───────────┘
```

Le header est stocké **en clair** (il contient les paramètres Argon2
nécessaires pour dériver la clé — on ne peut pas le chiffrer avant
d'avoir la clé). Son intégrité est garantie séparément par le tag qui le
suit immédiatement.

## 2. Header — `HEADER_FIXED_LEN` octets

Disposition binaire exacte, gros-boutiste (big-endian) pour tous les
entiers :

| Champ | Taille | Description |
|---|---|---|
| `magic` | 4 octets | constante `b"ENC1"` |
| `version` | 1 octet | `1` (version de format actuelle) |
| `salt` | 16 octets | sel Argon2, aléatoire par fichier |
| `argon2_memory_kib` | 4 octets (u32) | paramètre mémoire Argon2id |
| `argon2_iterations` | 4 octets (u32) | paramètre itérations Argon2id |
| `argon2_parallelism` | 1 octet (u8) | paramètre parallélisme Argon2id |
| `base_nonce` | 12 octets | nonce de base, aléatoire par fichier |
| `chunk_size` | 4 octets (u32) | taille de chunk en clair (défaut 1 Mio) |
| `total_chunks` | 8 octets (u64) | nombre de chunks de données |
| `total_plaintext_size` | 8 octets (u64) | taille totale du contenu en clair |

Longueur totale : `4+1+16+4+4+1+12+4+8+8` = `HEADER_FIXED_LEN` octets.

## 3. Authentification du header

Le tag du header est calculé avec **AES-256-GCM utilisé comme MAC** :
texte clair vide, header entier passé en **AAD** (Additional Authenticated
Data), sous un nonce dérivé dédié (§4). Le "ciphertext" produit par cette
opération ne contient donc que le tag GCM de 16 octets — c'est exactement
lui qui est stocké après le header.

```
header_tag = AES-256-GCM.encrypt(
    key    = derive_key(password, salt, argon2_params),
    nonce  = derive_nonce(base_nonce, HEADER_NONCE_COUNTER),
    plaintext = [] (vide),
    aad    = header_bytes (les HEADER_FIXED_LEN octets ci-dessus)
)   // -> 16 octets (le tag GCM ; pas de ciphertext puisque plaintext est vide)
```

À la vérification, `AES-256-GCM.decrypt` est appelé avec `ciphertext =
header_tag` et `aad = header_bytes` : la clé étant dérivée du mot de
passe fourni par l'utilisateur, l'échec de cette étape est interprété
comme un mot de passe incorrect plutôt qu'un fichier corrompu, car
c'est de loin la cause la plus probable à ce stade.

`header_hash = SHA-256(header_bytes || header_tag)` est ensuite calculé
et réutilisé dans l'AAD de chaque chunk (§5) — c'est ce qui lie
cryptographiquement chaque chunk à l'en-tête exact du fichier.

## 4. Construction des nonces

Un unique `base_nonce` de 12 octets (aléatoire, généré à la création du
fichier) sert de base à tous les nonces du fichier, dérivés
déterministiquement par XOR d'un compteur 64 bits sur les 8 derniers
octets :

```
derive_nonce(base_nonce, counter) = base_nonce XOR (0..0 || counter_be_bytes)
                                                      └─ 4 octets ─┘└─ 8 octets ─┘
```

- Header : `counter = HEADER_NONCE_COUNTER = u64::MAX`.
- Chunk `i` (0-indexé) : `counter = i`.

`u64::MAX` est réservé exclusivement au header et n'est, en pratique,
jamais atteignable comme index de chunk (il faudrait `2^64` chunks).
Unicité garantie : `base_nonce` est aléatoire par fichier, et pour un
même fichier chaque compteur (`0..total_chunks-1`, plus `u64::MAX` pour
le header) est utilisé au plus une fois — donc chaque nonce dérivé est
utilisé au plus une fois sous une même clé.

## 5. AAD et authentification de chaque chunk

Chaque chunk est chiffré/authentifié indépendamment avec :

```
aad(index, is_last) = header_hash (32 octets, §3)
                    || index.to_be_bytes()   (8 octets, u64)
                    || (is_last ? 1u8 : 0u8) (1 octet)

nonce = derive_nonce(base_nonce, index)

ciphertext_i = AES-256-GCM.encrypt(key, nonce, plaintext_chunk_i, aad(index, is_last))
```

`ciphertext_i` (taille chunk + 16 octets de tag) est écrit tel quel à la
suite du header et de son tag, dans l'ordre des index.

### Conséquence directe sur les attaques de réordonnancement/substitution

Un ciphertext valide pour l'index `i` **échoue systématiquement**
l'authentification s'il est présenté à la position `j ≠ i` : son AAD
d'origine contenait `i`, pas `j`. De même, un chunk provenant d'une
**autre archive** échoue car `header_hash` diffère. Ces cas remontent
tous comme `FormatError::Corrupted` (échec de tag GCM à l'index
attendu), pas comme une erreur silencieuse.

## 6. Déchiffrement : ordre de lecture et détections

Le déchiffreur lit et vérifie les chunks **strictement dans l'ordre**,
`index = 0, 1, 2, ...` :

1. lit `chunk_size + 16` octets (dernier chunk : taille résiduelle
   calculée à partir de `total_plaintext_size`) ;
2. reconstruit `aad(index, is_last)` avec l'`index` **attendu** (jamais
   lu depuis le fichier) et `is_last = (index + 1 == total_chunks)` ;
3. déchiffre — un échec de tag GCM ici signifie que le chunk a été
   modifié, déplacé, dupliqué, substitué, ou que `is_last` ne
   correspond pas à ce qui a été authentifié à l'écriture.

Après le dernier chunk attendu, le déchiffreur lit un octet
supplémentaire : s'il en reste, le fichier contient des données en trop
(`FormatError::Corrupted`). Enfin, la somme des tailles de chunks
déchiffrés est comparée à `total_plaintext_size` du header
(`FormatError::Truncated` en cas d'écart) — cette dernière vérification
détecte une troncature qui se serait arrêtée exactement sur une
frontière de chunk (et qui, sans elle, aurait pu passer inaperçue).

| Manipulation | Détection | Erreur retournée |
|---|---|---|
| Header modifié (tout champ) | tag GCM du header invalide | `WrongPassword`* |
| Chunk modifié (ciphertext/tag) | tag GCM du chunk invalide | `Corrupted` |
| Chunks échangés / réordonnés | `index` dans l'AAD ne correspond plus à la position | `Corrupted` |
| Chunk dupliqué | le doublon est lu à un index où il n'a jamais été authentifié | `Corrupted` |
| Chunk supprimé | décalage cascade sur tous les chunks suivants, ou fichier trop court | `Corrupted` ou `Truncated` |
| Chunk inséré | idem, décalage cascade | `Corrupted` |
| Chunk d'une autre archive | `header_hash` dans l'AAD ne correspond pas | `Corrupted` |
| Fichier tronqué en cours de chunk | pas assez d'octets lus pour le chunk courant | `Truncated` |
| Données ajoutées après le dernier chunk | octet résiduel détecté après la boucle | `Corrupted` |
| Mot de passe incorrect | tag GCM du header invalide | `WrongPassword` |

\* Un header modifié et un mot de passe incorrect produisent la même
erreur (`WrongPassword`) car les deux se traduisent identiquement par
un échec de tag GCM sur le header — il n'y a, par construction, aucun
moyen de les distinguer sans le mot de passe correct, et ce n'est pas
souhaitable de vouloir le faire (cela reviendrait à donner à un
attaquant un oracle sur la validité du mot de passe indépendamment de
l'intégrité du fichier).

## 7. Ce qui n'est explicitement PAS garanti

- Aucune protection si le mot de passe correct est déjà connu de
  l'attaquant, ou si le poste est compromis pendant l'opération.
- Le nombre de chunks et la taille totale du fichier `.enc` sont
  visibles en clair (pas de padding de longueur) : la taille
  approximative du contenu original n'est pas cachée.
- Aucune protection contre un attaquant qui remplace le fichier `.enc`
  entier par un autre fichier `.enc` valide chiffré avec le même mot de
  passe (aucun lien n'est fait avec un nom de fichier ou un contexte
  externe) — l'intégrité porte sur le contenu du fichier lui-même, pas
  sur son identité/emplacement.

## 8. Statut

Ce document décrit une spécification interne au projet, rédigée par les
mainteneurs. **Ce n'est pas un audit cryptographique externe.** Voir
[`SECURITY.md`](./SECURITY.md) pour signaler un problème.
