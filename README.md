# chiffre_aes_core / chiffre_aes_cli

Moteur de chiffrement de fichiers et de dossiers développé en Rust.

Le projet fournit un moteur cryptographique indépendant de toute interface graphique, basé sur **AES-256-GCM** pour le chiffrement authentifié et **Argon2id** pour la dérivation de clé à partir d'un mot de passe.

Le moteur utilise un format de conteneur `.enc` propriétaire, versionné, conçu pour traiter les données par chunks et détecter les modifications, la troncature et le réordonnancement des données chiffrées.

> **Important : ce projet n'a pas fait l'objet d'un audit cryptographique indépendant.**
>
> L'utilisation de primitives cryptographiques reconnues ne constitue pas, à elle seule, une preuve de sécurité de l'assemblage réalisé dans ce projet.

## Auteur et statut du projet

`chiffre-aes-core` est un projet personnel développé et maintenu par **Sébastien Noyal**.

Je suis l'auteur du code présent dans ce dépôt. Le projet est développé dans une démarche d'apprentissage, d'expérimentation et de mise à disposition d'un moteur de chiffrement open source.

Il ne prétend pas remplacer une bibliothèque cryptographique auditée ni fournir une garantie de sécurité formelle.

---

# Architecture

Le dépôt est volontairement séparé en plusieurs composants.

```text
                         chiffre-aes-core
                                │
             ┌──────────────────┴──────────────────┐
             │                                     │
            core                                   cli
             │                                     │
   moteur cryptographique                    interface CLI
   + format .enc                             + automatisation
             │
             ├── crypto
             ├── format
             ├── archive
             ├── compress
             └── pipeline
```

### `core/`

`chiffre_aes_core` contient la logique de chiffrement et le format de fichier.

C'est la partie qui doit faire l'objet d'une éventuelle revue cryptographique indépendante.

Elle ne contient ni interface graphique, ni communication réseau.

### `cli/`

`chiffre_aes_cli` fournit une interface en ligne de commande utilisant le moteur `core`.

Une interface graphique desktop et une application Android sont développées et distribuées séparément.

---

# Construction du traitement

Pour un ensemble de fichiers ou de dossiers, le traitement général est le suivant :

```text
Fichiers / dossiers
        │
        ▼
Archivage / compression
        │
        ▼
Flux binaire
        │
        ▼
Découpage en chunks
        │
        ▼
Dérivation de la clé avec Argon2id
        │
        ▼
AES-256-GCM
        │
        ▼
Conteneur .enc
```

L'archivage/compression est effectué avant le chiffrement.

Le chiffrement lui-même est réalisé sur le flux binaire résultant, par blocs de taille configurable dans le format.

---

# Primitives cryptographiques

## AES-256-GCM

Les données sont chiffrées avec **AES-256-GCM**, un mode AEAD (*Authenticated Encryption with Associated Data*).

La clé AES est de 256 bits.

Chaque opération produit également un tag d'authentification de **128 bits**.

AES-GCM fournit simultanément :

- confidentialité des données ;
- détection des modifications du texte chiffré ;
- authentification des données associées.

Le projet utilise la bibliothèque `aes-gcm` de RustCrypto plutôt qu'une implémentation personnelle d'AES.

## Argon2id

La clé AES est dérivée du mot de passe utilisateur avec **Argon2id**.

Paramètres par défaut :

```text
Algorithme    : Argon2id
Mémoire       : 64 MiB
Itérations    : 3
Parallélisme  : 4
Sortie        : 32 octets
Salt          : 16 octets
```

Le salt est généré aléatoirement pour chaque archive et est stocké dans l'en-tête du fichier.

Le mot de passe n'est pas enregistré dans le fichier chiffré.

Les paramètres Argon2 utilisés pour une archive sont également stockés dans son en-tête afin que le déchiffrement puisse reproduire la dérivation de clé.

---

# Format du conteneur `.enc`

Le format est actuellement en **version 1**.

Chaque fichier commence par un en-tête fixe de 66 octets.

```text
Offset       Taille       Champ
------------------------------------------------
0            4            Magic = "ENC1"
4            1            Version du format
5            16           Salt Argon2id
21           4            Mémoire Argon2id (KiB)
25           4            Itérations Argon2id
29           1            Parallélisme Argon2id
30           12           Nonce de base
42           4            Taille d'un chunk
46           8            Nombre total de chunks
54           8            Taille totale en clair
------------------------------------------------
Total        66 octets
```

L'en-tête est suivi d'un tag d'authentification de 16 octets.

Puis viennent les chunks chiffrés :

```text
┌───────────────────────────────┐
│ En-tête                       │ 66 octets
├───────────────────────────────┤
│ Tag GCM de l'en-tête          │ 16 octets
├───────────────────────────────┤
│ Chunk 0 + tag GCM             │
├───────────────────────────────┤
│ Chunk 1 + tag GCM             │
├───────────────────────────────┤
│ ...                           │
├───────────────────────────────┤
│ Chunk N + tag GCM             │
└───────────────────────────────┘
```

Un chunk contient donc son texte chiffré ainsi que son propre tag d'authentification GCM.

---

# Nonces AES-GCM

AES-GCM utilise des nonces de 12 octets.

Le fichier contient un **nonce de base aléatoire**.

Un nonce distinct est ensuite dérivé pour chaque chunk à partir de ce nonce de base et de l'index du chunk.

Le nonce réservé à l'authentification de l'en-tête utilise un compteur distinct.

L'objectif est d'empêcher la réutilisation d'un même nonce avec la même clé entre les différentes opérations AES-GCM du conteneur.

---

# Authentification de l'en-tête

L'en-tête n'est pas seulement stocké en clair : il est également authentifié.

Un nonce réservé est dérivé à partir du nonce de base et l'en-tête est authentifié avec AES-256-GCM.

Le tag obtenu est stocké immédiatement après l'en-tête.

Ainsi, une modification de paramètres tels que :

- le salt ;
- les paramètres Argon2id ;
- le nonce de base ;
- la taille des chunks ;
- le nombre de chunks ;
- la taille totale en clair ;

doit être détectée lors du déchiffrement.

---

# Authenticated Associated Data des chunks

Chaque chunk utilise des données associées (AAD) qui ne sont pas chiffrées mais qui sont authentifiées par AES-GCM.

L'AAD est construite à partir de :

```text
SHA-256(en-tête || tag de l'en-tête)
        ||
index du chunk
        ||
indicateur du dernier chunk
```

Cela lie cryptographiquement chaque chunk :

1. à l'en-tête de son propre conteneur ;
2. à sa position dans le flux ;
3. à son statut de dernier chunk.

Cette construction permet notamment de détecter le réordonnancement ou la duplication de chunks.

---

# Protection contre la troncature

Le nombre de chunks et la taille totale des données en clair sont enregistrés dans l'en-tête.

Lors du déchiffrement, le moteur connaît donc la quantité de données attendue pour chaque chunk.

Si le fichier chiffré est tronqué ou si un chunk est incomplet, l'opération échoue.

Le moteur ne considère pas un fichier partiellement présent comme un fichier correctement déchiffré.

Cette propriété est également couverte par des tests automatisés.

---

# Propriétés de sécurité recherchées

Le système cherche à fournir les propriétés suivantes, sous réserve de l'utilisation correcte d'un mot de passe suffisamment robuste et de l'absence de compromission de la machine exécutant le logiciel :

### Confidentialité

Une personne ne possédant pas le mot de passe ne doit pas pouvoir récupérer le contenu en clair du conteneur sans casser les primitives cryptographiques utilisées ou retrouver le mot de passe.

### Intégrité

Une modification des données chiffrées doit être détectée par l'authentification AES-GCM.

### Authentification des données

Les chunks sont authentifiés individuellement et liés au conteneur auquel ils appartiennent.

### Détection du réordonnancement

Un déplacement d'un chunk à une autre position doit provoquer un échec d'authentification.

### Détection de la troncature

La suppression d'une partie du conteneur doit être détectée.

### Résistance aux attaques hors ligne sur le mot de passe

Argon2id est utilisé afin de rendre les essais successifs de mots de passe plus coûteux qu'une simple fonction de hachage rapide.

Cette propriété dépend cependant directement de la qualité du mot de passe choisi par l'utilisateur.

---

# Ce que le système ne garantit pas

Le projet ne prétend pas :

- cacher la taille du fichier ou du conteneur ;
- fournir l'anonymat ;
- protéger un mot de passe faible contre une attaque par dictionnaire ;
- protéger les données si la machine utilisée pour les chiffrer ou les déchiffrer est compromise ;
- protéger un mot de passe pendant sa saisie contre un logiciel espion présent sur le système ;
- fournir une sécurité formellement démontrée ;
- avoir été validé par un audit cryptographique indépendant.

En particulier, **AES-256-GCM et Argon2id étant des primitives reconnues, cela ne signifie pas que l'assemblage réalisé dans ce projet est automatiquement sécurisé**.

Le format de fichier, la gestion des nonces, la dérivation de clé, l'AAD et la logique de traitement des chunks constituent eux-mêmes des éléments devant être examinés.

---

# Vérifications et tests

Le dépôt contient des tests couvrant notamment :

- le chiffrement/déchiffrement ;
- les fichiers multi-chunks ;
- les fichiers vides ;
- la détection d'une troncature ;
- la détection du réordonnancement de chunks ;
- la progression du traitement ;
- les erreurs d'authentification.

Ces tests permettent de vérifier les propriétés fonctionnelles implémentées mais **ne constituent pas un audit cryptographique**.

Un test logiciel démontrant qu'une attaque particulière échoue ne constitue pas une preuve générale de sécurité.

---

# Audit de sécurité

À la date actuelle, ce projet **n'a pas fait l'objet d'un audit de sécurité cryptographique indépendant**.

Le projet utilise des bibliothèques cryptographiques reconnues, notamment les implémentations RustCrypto de `aes-gcm` et `argon2`.

Cependant, l'assemblage réalisé dans `chiffre_aes_core` — notamment :

- le format du conteneur ;
- la gestion des nonces ;
- la dérivation de clé ;
- l'authentification de l'en-tête ;
- la construction de l'AAD ;
- la gestion des chunks ;
- le pipeline d'archivage et de chiffrement ;

reste spécifique à ce projet et n'a pas encore été examiné par un tiers indépendant.

**Le projet doit donc être considéré comme expérimental du point de vue de l'assurance de sécurité, malgré l'utilisation de primitives cryptographiques reconnues.**

---

# Compilation

```bash
cargo build --workspace
cargo test --workspace
```

Exemple :

```bash
cargo run -p chiffre_aes_cli -- encrypt \
    --input mon_dossier \
    --output archive.enc

cargo run -p chiffre_aes_cli -- decrypt \
    --input archive.enc \
    --output mon_dossier
```

Les options exactes sont définies dans `cli/src/main.rs`.

---

# Utiliser `chiffre_aes_core`

Le moteur peut être intégré dans un autre projet Rust :

```toml
[dependencies]
chiffre_aes_core = "0.1"
```

API principale :

```rust
use chiffre_aes_core::{
    encrypt_file,
    decrypt_file,
    Password,
};
```

La documentation Rust du crate fournit la description complète de l'API.

---

# Transparence

La séparation du moteur cryptographique et des interfaces utilisateur a pour objectif de permettre une inspection indépendante du code.

Le moteur peut être lu, audité, forké et réutilisé sous les termes de sa licence.

Une revue cryptographique indépendante est souhaitée avant toute utilisation dans un contexte nécessitant une forte assurance de sécurité.

---

# Licence

Double licence, au choix :

- MIT
- Apache License 2.0

Voir `NOTICE.md` pour les licences des dépendances tierces.