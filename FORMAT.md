# Spécification du format `.enc`

Ce document décrit le format de fichier `.enc` produit par `chiffre_aes_core`,
avec une précision suffisante pour qu'une implémentation indépendante
produise un fichier binaire compatible. Ce n'est plus seulement une
intention déclarée : voir [`tests/vectors/`](./core/tests/vectors/) pour
une démonstration concrète, exécutable à chaque `cargo test`.

**Génération indépendante.** [`generate_vector.py`](./core/generate_vector.py)
calcule des fichiers `.enc` complets à partir de la seule lecture de ce
document — dérivation Argon2id, assemblage du header, tag GCM du header,
AAD et chiffrement de chaque chunk. Le script n'importe aucun code de ce
dépôt et repose uniquement sur `argon2-cffi` et `cryptography`, deux
bibliothèques indépendantes de l'implémentation Rust (`argon2`,
`aes-gcm` de RustCrypto). Trois vecteurs sont actuellement générés :

| Vecteur | Ce qu'il couvre |
|---|---|
| `vector_001` | Cas nominal, un seul chunk. |
| `vector_002` | 6 chunks, dont un dernier chunk partiel (14 octets) — exerce la dérivation du nonce par compteur sur plusieurs valeurs et la position réelle du drapeau `is_last`. |
| `vector_003` | Fichier vide — 1 chunk vide explicitement marqué dernier (cas limite de `total_chunks`/`total_plaintext_size`). |

**Vérification côté Rust, à deux niveaux.** [`tests/vectors.rs`](./core/tests/vectors.rs)
consomme les trois vecteurs ci-dessus et vérifie, pour chacun :

1. *Boîte noire* (`all_vectors_decrypt_via_public_api`) — le fichier
   `.enc` produit en Python est déchiffré via `decrypt_file`, la seule
   API publique qu'un utilisateur final emploierait, et le texte en
   clair obtenu est comparé à l'original. C'est le test le plus
   représentatif : il exerce tout le chemin réel (lecture du header,
   vérification Argon2, déchiffrement de chaque chunk, écriture) sans
   accès privilégié au code interne.
2. *Boîte grise* (`all_vectors_derived_key_matches_independent_reference`,
   `all_vectors_every_chunk_ciphertext_matches_independent_reference`) —
   la clé dérivée par Argon2id, puis **chaque chunk pris individuellement**
   (pas seulement le premier), sont comparés octet par octet aux valeurs
   calculées en Python. Sur `vector_002`, cela signifie que les 6 chunks
   sont vérifiés un par un : si une divergence apparaissait un jour entre
   les deux implémentations, ce niveau de test indique précisément *à
   quel chunk et sur quelle valeur* (clé, nonce, AAD ou ciphertext) elle
   se produit, plutôt que de simplement constater l'échec du fichier final.

Cette double vérification (bout-en-bout + intermédiaire, sur un cas à un
seul chunk et un cas à plusieurs) est ce qui permet d'affirmer que le
format est non seulement *spécifié* de façon suffisamment précise, mais
aussi *implémenté* conformément à cette spécification — deux propriétés
distinctes, dont seule la seconde était auparavant une affirmation non
vérifiée.

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

Longueur totale : `4+1+16+4+4+1+12+4+8+8` = `HEADER_FIXED_LEN` = **62 octets**.

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

Cette propriété est testée explicitement (pas seulement affirmée par le
raisonnement mathématique ci-dessus) dans `core/src/format.rs` :
injectivité de `derive_nonce` sur un large échantillon de compteurs,
absence de collision entre le nonce de l'en-tête et ceux des chunks, et
déterminisme de la dérivation (nécessaire pour que le déchiffreur
reconstruise le même nonce que celui utilisé au chiffrement).

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
- **Fuite d'information par la taille, amplifiée par la compression
  (archivage multi-fichiers/dossiers).** Le pipeline compresse le
  contenu (`compress.rs`, deflate) avant de le chiffrer. Un chiffrement
  authentifié comme AES-GCM ne masque jamais la longueur du texte clair
  qu'il traite : la taille finale du fichier `.enc` reflète directement
  la taille **compressée**, qui elle-même reflète la redondance interne
  du contenu d'origine. Deux conséquences concrètes, de nature
  différente :
  - *Comparaison de contenus proches* — un observateur qui voit
    plusieurs fichiers `.enc` successifs (sans jamais casser le
    chiffrement, par exemple un même document mis à jour et re-chiffré
    périodiquement) peut comparer leurs tailles. Un ratio de
    compression différent entre deux variantes du contenu peut trahir
    *ce qui a changé* entre elles, par analogie avec les attaques
    connues type CRIME/BREACH sur d'autres protocoles compressant avant
    de chiffrer. Le risque réel dépend fortement du scénario d'usage :
    il est maximal quand du contenu partiellement prévisible/contrôlé
    par l'observateur et un secret sont compressés *ensemble* dans le
    même flux, ce qui n'est pas le cas d'usage principal visé par ce
    projet (fichiers personnels indépendants), mais reste possible de
    façon plus grossière pour des versions successives d'un même
    document.
  - *Identification d'un fichier volumineux connu* — pour un contenu
    volumineux et distinctif (film, image disque, logiciel précis),
    un attaquant peut se procurer ce contenu par ailleurs, le
    compresser lui-même avec le même algorithme, et comparer la taille
    obtenue (plus l'overhead connu et calculable : `HEADER_FIXED_LEN`
    + 16 octets de tag pour l'en-tête, + 16 octets de tag par chunk) à
    la taille réelle du fichier `.enc`. Une correspondance constitue
    une confirmation à forte confiance de *quel contenu précis* a été
    chiffré, sans casser le mot de passe ni l'authentification. Ce
    risque est négligeable pour du contenu de petite taille ou non
    distinctif (sa taille compressée n'identifie rien de spécifique),
    et croît avec la taille et le caractère unique du contenu.

  Ces deux points ne remettent pas en cause l'authentification ou la
  confidentialité du *contenu* (personne sans le mot de passe ne peut
  lire les données) — ils concernent uniquement ce qu'une taille de
  fichier peut, dans certains scénarios d'usage, laisser deviner sur
  la nature du contenu chiffré. Voir §9 pour une réflexion sur des
  atténuations possibles dans une version future.

## 8. Bornes de politique et limites de ressources

Indépendantes du contenu du fichier `.enc` (jamais lues depuis le
fichier lui-même), pour empêcher un en-tête ou une archive hostile de
provoquer une consommation de ressources disproportionnée avant même
que le mot de passe soit vérifié :

| Paramètre | Min | Max | Vérifié |
|---|---|---|---|
| Mémoire Argon2id | 8 Mio | 1 Gio | avant toute dérivation (`derive_key`) |
| Itérations Argon2id | 1 | 50 | avant toute dérivation |
| Parallélisme Argon2id | 1 | 16 | avant toute dérivation |
| `chunk_size` | 1 Kio | 64 Mio | à la lecture de l'en-tête |
| Nombre d'entrées d'archive | — | 1 000 000 | avant extraction |
| Taille compressée par entrée | — | 8 Gio | avant allocation |
| Taille totale extraite | — | 100 Gio | en continu pendant l'extraction (protège aussi contre une bombe de décompression) |
| Longueur de chemin (archive) | — | 65 535 octets UTF-8 | à l'écriture de l'archive |

Un en-tête dont les paramètres Argon2 sont hors politique est rejeté
avec une erreur dédiée (`Argon2ParamsOutOfPolicy`), **distincte** de
`WrongPassword` — ce rejet a nécessairement lieu avant l'authentification
du mot de passe (dériver la clé est le préalable à cette vérification),
et ne doit donc jamais être interprété comme une information sur la
validité du mot de passe lui-même : il porte uniquement sur les
paramètres, indépendamment de qui les a produits.

L'écriture du fichier final (`.enc` en chiffrement, fichier restauré en
déchiffrement) passe systématiquement par un fichier temporaire créé de
façon sécurisée dans le même répertoire que la destination (nom non
prévisible, création atomique), puis renommé — jamais d'écriture directe
partielle visible à la destination finale.

Ce même principe s'applique à l'étape de désarchivage (dossiers/archives
multi-fichiers), qui désarchive vers un dossier temporaire avant de
basculer vers le dossier de destination final. Voir la section
« Atomicité de l'extraction » du `README.md` pour le détail et la limite
résiduelle documentée dans le cas d'un dossier de destination déjà
existant.

## 9. Réflexion pour une version future : masquage de la taille (non implémenté)

Cette section documente une réflexion de conception issue de commentaires
avisés externes, pas une fonctionnalité existante. Elle est conservée
ici pour que la décision — et ses limites assumées — reste traçable si
elle est implémentée plus tard, ou si elle est délibérément écartée.

### Le problème (rappel du §7)

Deux fuites distinctes liées à la taille du fichier `.enc` :
1. comparaison de tailles entre chiffrements successifs de contenus
   proches (fuite via le ratio de compression) ;
2. identification d'un contenu volumineux et distinctif par
   correspondance de taille (fuite via la taille brute).

Aucune des deux ne compromet le contenu lui-même ; toutes deux
concernent ce qu'une taille de fichier peut laisser deviner.

### Options envisagées

**A. Compression optionnelle (bascule au choix de l'utilisateur)**
Neutralise le problème 1 : sans compression, la taille du ciphertext ne
dépend que de la longueur du texte clair, plus de sa redondance interne
— deux variantes de même longueur produisent alors des tailles
identiques.
*Limite* : n'aide pas le problème 2, et peut légèrement l'aggraver — la
taille du fichier `.enc` révèle alors la taille **exacte** du contenu
d'origine (à l'overhead connu près), un oracle plus précis qu'une
estimation basée sur un ratio de compression variable.

**B. Padding déterministe (arrondi à des paliers)**
Arrondir la taille finale à des paliers fixes (puissances de 2, ou un
schéma type *Padmé*) réduit la précision de l'identification par la
taille (problème 2), et peut absorber de petites variations de ratio de
compression si elles tombent dans le même palier (aide partiellement le
problème 1).
*Limites* : (a) le projet étant open source, l'algorithme d'arrondi est
public — un attaquant retrouve le palier avec certitude plutôt que la
taille exacte, ce qui reste discriminant si peu de contenus candidats
tombent dans le même palier (un film volumineux reste identifiable à
l'échelle du palier) ; (b) compromis direct espace disque / précision
du masquage — paliers plus larges = moins de fuite mais plus de
remplissage inutile.

**C. Bruit aléatoire additionnel (option avancée, en complément de B)**
Ajouter une quantité aléatoire et imprévisible d'octets en plus du
padding déterministe : contrairement à B, l'attaquant ne peut plus
reproduire exactement le résultat même en connaissant parfaitement
l'algorithme (protège spécifiquement contre "je recalcule et je compare
bit à bit").
*Limites* : ne fait que réduire la précision de l'estimation, pas la
supprimer — si la plage de bruit reste petite par rapport à la taille du
fichier (nécessaire pour ne pas gaspiller excessivement l'espace disque
en pratique), l'attaquant retrouve toujours un intervalle étroit, plus
flou qu'un palier fixe mais non nul. Pour un contenu dont l'ordre de
grandeur brut est déjà en lui-même une empreinte (ex. "environ 1,4 Go"
suffit à deviner "probablement ce film-là" si peu de films font cette
taille), aucune des trois options ne fait disparaître complètement le
problème 2 — elles en réduisent seulement la précision.

### Évaluation de l'utilité réelle

Le modèle de menace de ce projet (voir la section « Modèle de sécurité »
du `README.md`) suppose un attaquant sans le mot de passe qui observe le
fichier `.enc`. Pour que la fuite par la taille soit réellement
exploitable, il faut *en plus* que cet attaquant :
- ait un accès passif régulier aux fichiers `.enc` concernés
  (stockage partagé, interception réseau...) ;
- dispose d'une liste de contenus candidats plausibles à comparer ;
- ait un intérêt suffisant pour mener cette analyse.

C'est un scénario réel mais minoritaire parmi l'ensemble des usages
visés par ce projet (chiffrement de documents/fichiers personnels). Pour
la majorité des utilisateurs, cette classe d'attaque n'a pas
d'attaquant motivé en face, et le coût (espace disque, complexité
d'interface, surface de tests supplémentaire) ne serait pas justifié
si ces options étaient activées par défaut.

### Orientation retenue si implémenté

- Option opt-in explicite, jamais activée par défaut.
- Un seul réglage utilisateur à plusieurs niveaux (ex. *aucun / arrondi
  / arrondi + bruit*) plutôt que plusieurs cases indépendantes
  combinables, pour rester lisible et limiter la matrice de tests.
- Avertissement explicite au moment de l'activation dans l'interface
  elle-même (pas seulement dans ce document) sur ce que l'option réduit
  réellement et ce qu'elle ne supprime pas — notamment le cas d'un
  contenu dont la taille brute est en elle-même une empreinte.

## 10. Métadonnées d'archive et durcissement de l'API bas niveau

Cette section documente deux propriétés issues de commentaires de revue
externes, distinctes du format `.enc` chiffré lui-même mais nécessaires
pour évaluer correctement la sécurité de bout en bout du moteur.

### 10.1 Types d'objets et permissions dans l'archive interne

L'AEAD (AES-256-GCM) garantit que le contenu de l'archive n'a pas été
modifié par quelqu'un qui ne connaît pas le mot de passe — il ne
garantit **pas** que les métadonnées qu'elle transporte sont sûres à
restaurer telles quelles sur le système de fichiers. Si le mot de passe
est partagé avec un tiers, ce tiers peut produire une archive
authentique dont le contenu est néanmoins hostile.

Deux garanties s'appliquent en conséquence, indépendamment du contenu de
l'archive :

- **Types d'objets supportés** : seuls deux types d'entrée existent dans
  le format d'archive interne — fichier régulier et dossier. Aucun lien
  symbolique, lien physique, périphérique, FIFO ou socket n'est
  représentable dans le format lui-même ; les liens symboliques
  rencontrés à l'archivage sont ignorés (jamais suivis ni stockés), avec
  un avertissement (`ArchiveWarning`) reporté à l'appelant.
- **Permissions filtrées à l'extraction** : le mode Unix stocké dans une
  entrée est filtré avant application sur le disque — `setuid`,
  `setgid`, `sticky` et l'écriture "autres" (`other-write`) sont
  **toujours** retirés, quel que soit le contenu de l'archive, y compris
  lorsque le bit exécutable est préservé. Le bit exécutable, lui, est
  restauré par défaut (`ExtractionLimits::preserve_executable_bit` à
  `true`) — comportement historique nécessaire pour qu'un script
  personnel chiffré reste exécutable après déchiffrement — et peut être
  désactivé explicitement si l'archive peut provenir d'un tiers auquel le
  mot de passe a été partagé sans confiance totale.

### 10.2 API bas niveau : nonce comme type possédé

Voir la section « API cryptographique bas niveau » du `README.md` pour
le contexte d'usage. Au niveau du type :

```rust
pub struct Nonce([u8; NONCE_LEN]); // non-Clone, non-Copy

pub fn encrypt_buffer(key: &DerivedKey, nonce: Nonce, plaintext: &[u8], aad: &[u8])
    -> Result<Vec<u8>, CryptoError>;
```

`Nonce` est consommé par valeur : une fois passé à `encrypt_buffer`, il
ne peut plus être réutilisé par erreur dans le même scope (l'erreur de
réutilisation la plus fréquente en pratique — une variable de nonce
capturée deux fois dans une boucle — ne compile simplement plus). Ceci
ne remplace pas une preuve globale d'unicité — `Nonce::from_raw_unchecked`
reste disponible pour qui doit reconstruire un nonce déjà utilisé (cas
légitime en déchiffrement) — mais élimine la classe d'erreur la plus
courante par construction du système de types plutôt que par simple
documentation. `NonceSequence` fournit un générateur à compteur
garantissant l'unicité pour un usage répété sous une même clé.

## 11. Statut

Ce document décrit une spécification interne au projet, rédigée par les
mainteneurs. **Ce n'est pas un audit cryptographique externe.** Voir
[`SECURITY.md`](./SECURITY.md) pour signaler un problème.
