# chiffre_aes_core / chiffre_aes_cli

Moteur de chiffrement de fichiers et de dossiers développé en Rust.

Le projet fournit un moteur cryptographique indépendant de toute interface graphique, ainsi qu'une interface en ligne de commande permettant de l'utiliser directement.

Le chiffrement repose sur **AES-256-GCM** pour le chiffrement authentifié et **Argon2id** pour la dérivation de clé à partir d'un mot de passe.

Le moteur utilise un format de conteneur `.enc` propriétaire et versionné, conçu pour traiter les données par chunks et détecter notamment les modifications, la corruption, la troncature et le réordonnancement des données chiffrées.

> **Important : ce projet n'a pas fait l'objet d'un audit cryptographique ou d'un audit de sécurité indépendant.**
>
> L'utilisation de primitives cryptographiques reconnues ne constitue pas, à elle seule, une preuve de sécurité de l'assemblage réalisé dans ce projet.
>
> Les propriétés décrites dans ce document correspondent aux propriétés recherchées par la conception et à l'implémentation actuelle. Elles ne constituent pas une preuve formelle de sécurité.

---

# Auteur et statut du projet

`chiffre-aes-core` est un projet personnel développé et maintenu par **Sébastien Noyal**.

Le projet est développé dans une démarche d'apprentissage, d'expérimentation et de mise à disposition d'un moteur de chiffrement open source.

Il ne prétend pas remplacer une bibliothèque cryptographique auditée ni fournir une garantie de sécurité formelle.

Le code source du moteur cryptographique est volontairement public afin de permettre son inspection, son utilisation, son fork et, à terme, son audit indépendant.

---

## Documentation technique

- [`FORMAT.md`](./FORMAT.md) — spécification complète du format `.enc` :
  disposition binaire du header, construction des nonces, calcul de
  l'AAD par chunk, et tableau exhaustif attaque → détection → erreur.
  Suffisant pour reconstruire le format sans lire le code.
- [`USAGE.md`](./USAGE.md) — usage détaillé du CLI, codes de sortie et
  signification de chaque message d'erreur.

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

## `core/`

`chiffre_aes_core` contient la logique de chiffrement et le format de fichier.

Il prend notamment en charge :

- la dérivation de clé ;
- le chiffrement authentifié ;
- le format du conteneur `.enc` ;
- le traitement par chunks ;
- l'authentification de l'en-tête ;
- l'authentification des chunks ;
- les contrôles d'intégrité ;
- le pipeline de chiffrement et de déchiffrement.

C'est la partie qui doit faire l'objet d'une éventuelle revue cryptographique indépendante.

Elle ne contient ni interface graphique, ni communication réseau.

## `cli/`

`chiffre_aes_cli` fournit une interface en ligne de commande utilisant le moteur `core`.

Elle permet notamment d'utiliser le moteur dans des scripts et des opérations automatisées.

Une interface graphique desktop et une application Android sont développées et distribuées séparément.

Cette séparation permet de limiter le périmètre du code cryptographique et de faciliter son inspection, ses tests et son éventuel audit.

Le moteur `core` ne dépend ni d'une interface graphique ni d'un service réseau.

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

L'archivage et la compression sont effectués avant le chiffrement.

Le chiffrement lui-même est réalisé sur le flux binaire résultant, par blocs.

La taille des chunks est enregistrée dans le format du conteneur afin que le déchiffrement puisse reproduire correctement le découpage utilisé lors du chiffrement.

La conception par chunks permet de traiter des fichiers de grande taille sans charger l'ensemble des données en mémoire.

---

# Construction cryptographique

Le système utilise les primitives suivantes :

| Fonction | Primitive |
|---|---|
| Chiffrement authentifié | AES-256-GCM |
| Dérivation de clé depuis un mot de passe | Argon2id |
| Hash utilisé pour lier les chunks à l'en-tête | SHA-256 |
| Nonces AES-GCM | nonce de base + compteur/index de chunk |
| Taille de la clé AES | 256 bits |
| Taille d'un nonce GCM | 96 bits |
| Taille d'un tag d'authentification | 128 bits |

Le projet ne réimplémente pas AES-GCM ou Argon2id.

Il utilise les implémentations fournies par l'écosystème **RustCrypto**, notamment les bibliothèques `aes-gcm` et `argon2`.

La sécurité du projet dépend donc à la fois de ces primitives et de la manière dont elles sont assemblées dans le format et le pipeline propres à ce projet.

---

# AES-256-GCM

Les données sont chiffrées avec **AES-256-GCM**, un mode AEAD (*Authenticated Encryption with Associated Data*).

La clé AES est de 256 bits.

Chaque opération produit également un tag d'authentification de **128 bits**.

AES-GCM fournit simultanément :

- la confidentialité des données ;
- la détection des modifications du texte chiffré ;
- l'authentification des données associées.

Le projet utilise une implémentation existante de RustCrypto plutôt qu'une implémentation personnelle d'AES.

---

# Argon2id

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

Argon2id est utilisé afin de rendre les essais successifs de mots de passe plus coûteux qu'une fonction de hachage rapide classique.

Cette propriété dépend cependant directement de la qualité du mot de passe choisi par l'utilisateur.

---

# Format du conteneur `.enc`

Le format `.enc` est un format binaire propriétaire et versionné.

La version actuelle du format est **1**.

Chaque fichier commence par un en-tête fixe de **66 octets**.

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

L'en-tête est suivi d'un tag d'authentification de **16 octets**.

Puis viennent les chunks chiffrés :

```text
┌────────────────────────────────┐
│ En-tête                        │ 66 octets
├────────────────────────────────┤
│ Tag GCM de l'en-tête           │ 16 octets
├────────────────────────────────┤
│ Chunk 0 + tag GCM              │
├────────────────────────────────┤
│ Chunk 1 + tag GCM              │
├────────────────────────────────┤
│ ...                            │
├────────────────────────────────┤
│ Chunk N + tag GCM              │
└────────────────────────────────┘
```

Un chunk contient donc son texte chiffré ainsi que son propre tag d'authentification GCM.

La taille standard de traitement est de **1 MiB**.

Le format prévoit que la taille des chunks soit enregistrée dans l'en-tête.

---

# Informations présentes dans l'en-tête

L'en-tête contient notamment :

- l'identifiant de format (`ENC1`) ;
- la version du format ;
- le salt aléatoire utilisé par Argon2id ;
- les paramètres Argon2id ;
- le nonce de base ;
- la taille des chunks ;
- le nombre total de chunks ;
- la taille totale des données en clair.

Une partie de ces informations est nécessaire au déchiffrement et n'est donc pas considérée comme secrète.

En particulier, la taille totale du plaintext est enregistrée dans l'en-tête.

Le format ne cherche donc pas à dissimuler la taille des données.

---

# Nonces AES-GCM

AES-GCM utilise des nonces de **12 octets**.

Le fichier contient un **nonce de base aléatoire**.

Un nonce distinct est ensuite dérivé pour chaque opération de chiffrement d'un chunk à partir de ce nonce de base et de l'index du chunk.

Le nonce réservé à l'authentification de l'en-tête utilise un compteur distinct.

L'objectif est d'éviter la réutilisation d'un même nonce avec la même clé entre les différentes opérations AES-GCM du conteneur.

La gestion des nonces constitue donc une partie importante de la sécurité du format.

---

# Authentification de l'en-tête

L'en-tête n'est pas utilisé comme une simple zone de métadonnées non authentifiée.

Il est lui-même authentifié avec AES-256-GCM.

Un nonce réservé à cette opération est dérivé à partir du nonce de base.

Le tag obtenu est stocké immédiatement après l'en-tête.

Ainsi, une modification de paramètres tels que :

- le salt ;
- les paramètres Argon2id ;
- le nonce de base ;
- la taille des chunks ;
- le nombre de chunks ;
- la taille totale en clair ;

doit être détectée lors du déchiffrement.

Après lecture du fichier, le déchiffrement commence par la vérification de l'authenticité de l'en-tête.

Un échec à cette étape est traité comme une erreur d'authentification, notamment compatible avec un mot de passe incorrect.

---

# Authenticated Associated Data des chunks

Chaque chunk utilise des **données associées (AAD)**.

Les données associées ne sont pas chiffrées, mais elles sont authentifiées par AES-GCM.

L'AAD est construite à partir de :

```text
SHA-256(en-tête || tag de l'en-tête)
        ||
index du chunk
        ||
indicateur du dernier chunk
```

Cette construction lie cryptographiquement chaque chunk :

1. à l'en-tête de son propre conteneur ;
2. à sa position dans le flux ;
3. à son statut de dernier chunk.

Cette liaison permet notamment de détecter :

- la modification d'un chunk ;
- le réordonnancement des chunks ;
- la duplication d'un chunk ;
- l'utilisation d'un chunk provenant d'un autre conteneur ;
- certaines manipulations combinant suppression et ajout de données.

Le dernier chunk est explicitement identifié par son indicateur d'authentification.

---

# Protection contre la troncature

Le nombre de chunks et la taille totale des données en clair sont enregistrés dans l'en-tête.

Lors du déchiffrement, le moteur connaît donc la quantité de données attendue.

La cohérence est vérifiée notamment entre :

- le nombre attendu de chunks ;
- la taille des chunks ;
- le nombre d'octets réellement déchiffrés ;
- la taille totale annoncée dans l'en-tête.

Le déchiffrement vérifie également qu'aucune donnée supplémentaire ne reste après le dernier chunk attendu.

Si le fichier chiffré est tronqué ou si un chunk est incomplet, l'opération échoue.

Le moteur ne considère pas un fichier partiellement présent comme un fichier correctement déchiffré.

Cette propriété est également couverte par des tests automatisés.

---

# Écriture atomique

Le moteur cherche également à éviter de laisser un fichier de sortie partiellement produit à la suite d'une erreur ou d'une interruption.

Lors du chiffrement :

1. les données sont écrites dans un fichier temporaire ;
2. le conteneur nouvellement créé est entièrement relu ;
3. l'authentification de l'ensemble des données est vérifiée ;
4. le fichier temporaire est renommé vers la destination finale uniquement si la vérification réussit.

Lors du déchiffrement, le même principe est utilisé :

1. les données sont écrites dans un fichier temporaire ;
2. le traitement complet est effectué ;
3. les contrôles d'authentification et de cohérence sont effectués ;
4. la destination finale n'est créée ou remplacée qu'après réussite complète du traitement.

Cette conception vise à éviter qu'une erreur ou une annulation laisse derrière elle un fichier présenté comme valide alors qu'il est incomplet.

---

# Modèle de sécurité

Le modèle de menace principal est celui d'un attaquant qui peut obtenir une copie du fichier `.enc` et éventuellement la modifier, mais qui ne connaît pas le mot de passe utilisé pour le chiffrement.

Dans ce modèle, le système cherche à fournir plusieurs propriétés.

## Confidentialité

Une personne ne possédant pas le mot de passe ne doit pas pouvoir récupérer le contenu en clair du conteneur sans casser les primitives cryptographiques utilisées ou retrouver le mot de passe.

Cette propriété repose notamment sur AES-256-GCM, Argon2id, la gestion correcte des clés et des nonces, ainsi que sur la qualité du mot de passe choisi.

## Intégrité

Une modification des données chiffrées doit être détectée par l'authentification AES-GCM.

## Authentification des données

Les chunks sont authentifiés individuellement et liés au conteneur auquel ils appartiennent.

## Intégrité du format

Les modifications de l'en-tête, des paramètres du conteneur ou du contexte cryptographique des chunks doivent être détectées.

## Détection du réordonnancement

Un déplacement d'un chunk vers une autre position doit provoquer un échec d'authentification puisque son index fait partie des données associées.

## Détection de la duplication

La duplication d'un chunk à une position différente doit être détectée par l'authentification de son index.

## Détection de la troncature

La suppression d'une partie du conteneur doit être détectée plutôt que d'être acceptée comme un déchiffrement valide d'un fichier partiel.

## Résistance aux attaques hors ligne sur le mot de passe

Argon2id est utilisé afin de rendre les essais successifs de mots de passe plus coûteux.

Cette propriété n'empêche toutefois pas une attaque par dictionnaire ou par force brute lorsque le mot de passe choisi est faible.

---

# Ce que le système ne garantit pas

Le projet ne prétend pas :

- cacher la taille du fichier ou du conteneur ;
- fournir l'anonymat ;
- protéger un mot de passe faible contre une attaque par dictionnaire ;
- protéger les données si la machine utilisée pour les chiffrer ou les déchiffrer est compromise ;
- protéger un mot de passe pendant sa saisie contre un logiciel espion présent sur le système ;
- protéger les données présentes en mémoire contre une compromission du système ;
- protéger les copies ou sauvegardes non chiffrées du fichier original ;
- fournir une sécurité formellement démontrée ;
- avoir été validé par un audit cryptographique indépendant ;
- fournir un mécanisme de récupération du mot de passe ;
- fournir un mécanisme de partage de secrets ou de clés.

Un attaquant possédant le mot de passe doit être considéré comme pouvant accéder aux données qu'il permet de déchiffrer.

La sécurité globale d'une utilisation réelle dépend donc également de la gestion du mot de passe et de la sécurité du système d'exploitation sur lequel le logiciel est exécuté.

---

# Hypothèses cryptographiques

La sécurité recherchée repose notamment sur les hypothèses suivantes :

- AES-256 est considéré comme résistant aux attaques cryptographiques connues dans son domaine d'utilisation ;
- AES-GCM est utilisé avec des nonces uniques par clé ;
- Argon2id fournit une dérivation de clé conçue pour rendre les attaques par essais de mots de passe plus coûteuses ;
- SHA-256 est utilisé comme fonction de hachage pour lier cryptographiquement les chunks à l'en-tête et à leur contexte ;
- les bibliothèques cryptographiques utilisées implémentent correctement les primitives correspondantes.

La sécurité du projet ne dépend toutefois pas uniquement de ces primitives.

Elle dépend également de leur assemblage dans le format `.enc`, de la gestion des nonces, de la dérivation de clé, de la construction de l'AAD, de la gestion des erreurs et de l'implémentation du pipeline de chiffrement et de déchiffrement.

---

# Limites liées aux métadonnées

Le conteneur ne cherche pas à masquer toutes les métadonnées.

Certaines informations sont volontairement stockées dans l'en-tête afin de permettre le déchiffrement et les contrôles de cohérence.

En particulier, la taille totale des données en clair est enregistrée.

Le format ne doit donc pas être considéré comme un mécanisme permettant de masquer l'existence d'un fichier chiffré ou toutes les informations relatives à sa taille.

---

# Archivage et compression

Lorsque plusieurs fichiers ou un dossier sont traités, l'archivage et la compression sont réalisés avant le chiffrement.

Le moteur de chiffrement reçoit alors un flux binaire unique qui est découpé en chunks.

Cette organisation permet de séparer conceptuellement :

```text
Gestion des fichiers
        ↓
Archivage / compression
        ↓
Flux binaire
        ↓
Cryptographie
        ↓
Conteneur .enc
```

La compression n'est pas présentée comme une fonction de sécurité cryptographique.

---

# Tests et vérifications

Le dépôt contient des tests couvrant notamment :

- le chiffrement puis le déchiffrement ;
- les fichiers vides ;
- les fichiers dépassant la taille d'un chunk ;
- les fichiers comportant plusieurs chunks ;
- le dernier chunk partiel ;
- la détection d'une troncature ;
- la détection du réordonnancement des chunks ;
- la vérification de l'intégrité des données ;
- les erreurs d'authentification ;
- le comportement avec un mauvais mot de passe ;
- la progression du traitement.

Les tests permettent de vérifier certaines propriétés fonctionnelles et certains comportements de sécurité attendus.

Ils ne constituent toutefois **pas un audit cryptographique**.

Un test démontrant qu'une attaque particulière échoue ne constitue pas une preuve générale de sécurité du système.

Les tests peuvent montrer qu'une propriété particulière est correctement implémentée dans les cas testés ; ils ne démontrent pas l'absence de vulnérabilités non testées.

Pour exécuter les tests :

```bash
cargo test --workspace
```

---

# Audit de sécurité et niveau de confiance

À la date actuelle, ce projet **n'a pas fait l'objet d'un audit de sécurité cryptographique indépendant**.

Le projet utilise des bibliothèques cryptographiques reconnues, notamment les implémentations RustCrypto de `aes-gcm` et `argon2`.

Cependant, l'assemblage réalisé dans `chiffre_aes_core` — notamment :

- le format du conteneur ;
- la gestion des nonces ;
- la dérivation de clé ;
- l'authentification de l'en-tête ;
- la construction de l'AAD ;
- la gestion des chunks ;
- les contrôles de cohérence ;
- le pipeline d'archivage, de compression et de chiffrement ;
- la gestion des erreurs ;

reste spécifique à ce projet et n'a pas encore été examiné par un tiers indépendant.

**Le projet doit donc être considéré comme expérimental du point de vue de l'assurance de sécurité, malgré l'utilisation de primitives cryptographiques reconnues.**

Une revue cryptographique indépendante serait nécessaire avant de présenter ce projet comme une solution cryptographique ayant fait ses preuves.

---

# Compilation

Pour compiler l'ensemble du workspace :

```bash
cargo build --workspace
```

Pour exécuter les tests :

```bash
cargo test --workspace
```

---

# Utilisation de la CLI

Exemple de chiffrement :

```bash
cargo run -p chiffre_aes_cli -- encrypt \
    --input mon_dossier \
    --output archive.enc
```

Exemple de déchiffrement :

```bash
cargo run -p chiffre_aes_cli -- decrypt \
    --input archive.enc \
    --output mon_dossier
```

Les options exactes sont définies par l'implémentation actuelle de la CLI et peuvent évoluer avec le projet.

---

# Utiliser `chiffre_aes_core`

Le moteur peut être intégré dans un autre projet Rust.

Exemple de dépendance :

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

La documentation complète de l'API Rust peut être générée avec :

```bash
cargo doc --open -p chiffre_aes_core
```

---

# Transparence et réutilisation

La séparation du moteur cryptographique et des interfaces utilisateur a notamment pour objectif de permettre une inspection indépendante du code.

Le moteur peut être :

- inspecté ;
- testé ;
- audité ;
- forké ;
- intégré dans d'autres applications ;
- réutilisé conformément aux termes de sa licence.

Une revue cryptographique indépendante est souhaitée avant toute utilisation dans un contexte nécessitant une forte assurance de sécurité.

---

# Licence

Le projet est distribué sous double licence, au choix :

- MIT
- Apache License 2.0

Voir `NOTICE.md` pour les licences des dépendances tierces.
