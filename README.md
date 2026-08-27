# chiffre-aes-core

Bibliothèque Rust de chiffrement de fichiers et d'archives avec **AES-256-GCM** et dérivation de clé par **Argon2id**.

Le projet sépare le moteur cryptographique du CLI et des interfaces qui pourront l'utiliser ultérieurement.

> **Statut de sécurité :** le code a fait l'objet d'une revue de conception et d'une analyse adversariale du format. Il n'a pas fait l'objet d'un audit cryptographique externe ni d'une preuve formelle de sécurité.

## Objectif

Le projet vise à fournir un conteneur chiffré capable de protéger des fichiers ou des archives contre :

- la lecture sans le mot de passe ;
- la modification ;
- la troncature ;
- l'insertion ou la suppression de données ;
- le réordonnancement des blocs ;
- certaines manipulations du format.

Le format utilise AES-256-GCM pour fournir confidentialité et authentification, et Argon2id pour transformer un mot de passe en clé de chiffrement.

---

# Construction cryptographique

La construction générale est :

```text
mot de passe
     │
     ▼
   Argon2id
     │
     ▼
 clé AES-256
     │
     ▼
 AES-256-GCM
     │
     ├── Header authentifié
     │
     └── Chunks authentifiés
```

## Argon2id

La clé AES est dérivée du mot de passe avec Argon2id.

Le fichier contient les paramètres nécessaires à la dérivation ainsi qu'un sel aléatoire.

Les paramètres sont soumis à une politique de bornes afin d'éviter qu'un fichier hostile puisse imposer un coût de calcul arbitraire.

Le mot de passe n'est jamais stocké dans le fichier chiffré.

## AES-256-GCM

AES-256-GCM est utilisé comme chiffrement authentifié AEAD.

Il fournit simultanément :

- confidentialité ;
- intégrité ;
- authentification.

Une modification du ciphertext ou des données authentifiées entraîne l'échec du déchiffrement.

---

# Format du conteneur `.enc`

Le conteneur est organisé conceptuellement comme suit :

```text
+-----------------------------+
| Header                      |
+-----------------------------+
| Chunk 0                     |
+-----------------------------+
| Chunk 1                     |
+-----------------------------+
| ...                         |
+-----------------------------+
| Chunk N-1                   |
+-----------------------------+
```

Le header contient notamment :

- une signature/magic ;
- une version ;
- les paramètres Argon2id ;
- le sel ;
- un nonce de base ;
- la taille des chunks ;
- la taille totale en clair ;
- le nombre total de chunks ;
- l'authentification du header.

Les tailles et représentations binaires sont définies par l'implémentation du format. Toute évolution incompatible doit utiliser une nouvelle version.

## Invariants

Pour une taille totale `S`, une taille de chunk `C` et `N` chunks :

```text
N = ceil(S / C)
```

pour un contenu non vide.

Le cas d'un contenu vide est traité explicitement par le parser.

Le déchiffreur vérifie également :

- l'ordre des chunks ;
- l'index de chaque chunk ;
- le nombre de chunks ;
- le marqueur `is_last` ;
- la taille totale ;
- l'absence de données après le dernier chunk.

---

# Authentification du header et des chunks

Le header n'est pas considéré comme une simple métadonnée de confiance.

Il est authentifié cryptographiquement.

Chaque chunk utilise une AAD (Additional Authenticated Data) qui lie le ciphertext à la structure du conteneur.

Cette AAD comprend notamment :

```text
header canonique
+
index du chunk
+
indication is_last
```

Ainsi, un ciphertext authentique pour le chunk `i` ne peut pas simplement être déplacé vers la position `j`.

## Réordonnancement

Supposons :

```text
Chunk 0
Chunk 1
Chunk 2
```

Un attaquant qui produit :

```text
Chunk 1
Chunk 0
Chunk 2
```

ne dispose pas d'une authentification valide pour les nouvelles positions.

Le déchiffrement échoue.

Cette propriété est obtenue par l'authentification de l'index du chunk, et non simplement par l'utilisation d'AES-GCM.

## Suppression et insertion

Le déchiffreur attend les chunks dans l'ordre.

Une suppression ou une insertion modifie la séquence attendue et entraîne une incohérence détectée par les contrôles de structure et d'authentification.

## Troncature

La fin du conteneur est vérifiée.

Le dernier chunk doit être identifié correctement et la quantité de données produite doit correspondre à la taille totale annoncée.

Une troncature entraîne donc un échec.

## Données supplémentaires

Une fois le dernier chunk rencontré, aucune donnée supplémentaire n'est acceptée.

Cela évite qu'un attaquant puisse simplement ajouter des octets arbitraires à la fin d'un conteneur valide.

---

# Nonces

Chaque opération AES-GCM nécessite un nonce unique sous une même clé.

Le format utilise un nonce de base aléatoire auquel est associé l'index du chunk.

Le nonce utilisé pour l'authentification du header est distinct de ceux réservés aux chunks.

L'index d'un chunk est unique dans une archive et les limites du format empêchent un dépassement de l'espace d'indexation autorisé.

La construction doit conserver ces invariants lors de toute évolution du format.

---

# Modèle de menace

Le modèle de menace considère un attaquant capable de :

- lire le fichier ;
- copier le fichier ;
- modifier arbitrairement les octets ;
- tronquer le fichier ;
- ajouter des données ;
- supprimer des chunks ;
- réordonner les chunks ;
- dupliquer des chunks ;
- modifier le header ;
- fournir des paramètres Argon2 malveillants.

L'attaquant ne possède pas le mot de passe correct.

Le projet ne prétend pas protéger contre :

- un système d'exploitation compromis ;
- un processus déjà compromis ;
- un attaquant ayant accès aux secrets en mémoire ;
- des attaques avancées par canaux auxiliaires ;
- une compromission des primitives cryptographiques elles-mêmes.

---

# Archive et compression

Lorsque plusieurs fichiers sont regroupés, ils sont archivés et compressés avant chiffrement.

Conceptuellement :

```text
fichiers
   │
   ▼
archive
   │
   ▼
compression
   │
   ▼
AES-256-GCM
   │
   ▼
.enc
```

La compression intervient avant le chiffrement afin de ne pas compresser directement des données chiffrées.

## Sécurité des chemins

L'extraction rejette notamment les chemins susceptibles de sortir du répertoire de destination, tels que les chemins absolus ou contenant des composants `..`.

Les longueurs de chemins sont également soumises aux limites du format.

## Limites de ressources

Une archive authentique peut néanmoins contenir beaucoup de données.

L'authentification cryptographique ne constitue pas une protection contre une consommation excessive de CPU, de mémoire ou d'espace disque.

Les limites de ressources de l'extraction doivent donc être considérées comme une protection applicative distincte.

---

# Streaming

Le chiffrement et le déchiffrement sont effectués par chunks afin de ne pas nécessiter le chargement de l'ensemble du contenu chiffré en mémoire.

La phase d'archivage/compression peut toutefois nécessiter davantage de mémoire selon le chemin d'exécution utilisé.

Le projet ne prétend donc pas que l'intégralité du pipeline est actuellement un pipeline streaming de bout en bout.

---

# Sécurité du mot de passe

La sécurité contre une attaque par force brute dépend fortement de la qualité du mot de passe.

Argon2id augmente le coût d'une tentative de dérivation, mais ne peut pas rendre un mot de passe faible suffisamment sûr.

La politique de mot de passe de l'application est une mesure complémentaire et ne constitue pas une propriété cryptographique du format.

---

# Propriétés de sécurité recherchées

Sous les hypothèses habituelles d'AES-GCM et d'Argon2id, le format cherche notamment à fournir :

### Confidentialité

Sans le mot de passe, le contenu chiffré ne doit pas permettre de récupérer le contenu en clair, sous réserve de la sécurité des primitives et de la bonne gestion des clés et nonces.

### Intégrité

Toute modification d'un ciphertext, du header ou des données authentifiées doit être détectée.

### Liaison à la position

Un chunk authentique pour une position ne doit pas pouvoir être déplacé vers une autre position.

### Intégrité structurelle

La suppression, l'insertion, la duplication, le réordonnancement et la troncature doivent être détectés lorsque ces opérations violent les invariants du format.

---

# Ce que le projet ne revendique pas

Le projet ne revendique pas :

- une preuve mathématique formelle de sécurité du protocole complet ;
- un audit cryptographique indépendant ;
- une résistance à toutes les formes de déni de service ;
- une protection contre une machine compromise ;
- une sécurité absolue.

Le fait d'utiliser des primitives cryptographiques reconnues ne suffit pas à démontrer la sécurité de leur assemblage. C'est pourquoi le format, ses invariants et son modèle de menace sont documentés explicitement.

---

# Tests de sécurité

Le projet doit notamment tester les scénarios suivants :

- modification du header ;
- modification de la taille totale ;
- modification de la taille de chunk ;
- modification des paramètres Argon2 ;
- modification du salt ;
- modification du nonce ;
- modification d'un ciphertext ;
- modification d'un tag ;
- échange de deux chunks ;
- duplication d'un chunk ;
- suppression d'un chunk ;
- insertion d'un chunk ;
- modification de `is_last` ;
- troncature ;
- données supplémentaires après le dernier chunk ;
- chunk provenant d'une autre archive ;
- mot de passe incorrect.

Ces tests ont pour but de vérifier les propriétés revendiquées par le format, et non de constituer à eux seuls une preuve de sécurité.

---

# État du projet

Le projet est en cours de développement.

Avant une utilisation dans un contexte où une compromission aurait des conséquences importantes, une revue indépendante du protocole et de son implémentation est recommandée.

Les primitives cryptographiques utilisées sont :

- AES-256-GCM ;
- Argon2id.

Le projet utilise les implémentations fournies par les bibliothèques Rust correspondantes plutôt que de réimplémenter lui-même AES ou Argon2.

---

# Licence

Double licence :

- MIT
- Apache-2.0

Voir les fichiers `LICENSE-MIT` et `LICENSE-APACHE`.

---

# Philosophie de conception

Le projet cherche à respecter une règle simple :

> **La sécurité doit être démontrable par la construction et les invariants du format, et pas uniquement par le nom des primitives cryptographiques utilisées.**

Le format doit donc rester suffisamment simple, déterministe et documenté pour pouvoir être analysé indépendamment de l'interface utilisateur.


# Synthèse

Moteur de chiffrement de fichiers/dossiers en Rust, 100 % logique métier,
sans aucune dépendance à une interface graphique. Chiffrement authentifié
**AES-256-GCM**, dérivation de clé **Argon2id**, format de fichier `.enc`
en streaming par chunks avec protection contre la troncature et le
réordonnancement.

Ce dépôt contient :
- **`core/`** (`chiffre_aes_core`) — la bibliothèque cryptographique et le format
  de fichier. C'est la seule brique qui a une valeur de sécurité à faire
  auditer : elle ne fait ni UI, ni I/O superflu, ni réseau.
- **`cli/`** (`chiffre_aes_cli`) — une interface en ligne de commande construite
  sur `chiffre_aes_core`, utilisable telle quelle en script/automatisation, et
  qui sert aussi de référence d'intégration pour quiconque veut consommer
  `chiffre_aes_core` dans son propre projet.

Une interface graphique desktop (Slint) et une application Android
existent également, packagées et distribuées séparément (voir plus bas).

## Pourquoi séparer le moteur du reste ?

Le chiffrement, c'est un sujet de confiance. Le code qui manipule vos
mots de passe et vos données ne devrait jamais être une boîte noire :
`chiffre_aes_core` est donc publié en licence permissive et peut être lu, audité,
forké et réutilisé librement — y compris dans des logiciels propriétaires.
L'interface graphique et l'application mobile, elles, sont un produit
packagé, maintenu et distribué séparément.

## Compilation

```bash
cargo build --workspace
cargo test --workspace
```

```bash
cargo run -p chiffre_aes_cli -- encrypt --input mon_dossier --output archive.enc
cargo run -p chiffre_aes_cli -- decrypt --input archive.enc --output mon_dossier
```

(Adapter les options exactes à l'implémentation actuelle de `cli/src/main.rs`.)

## Utiliser `chiffre_aes_core` dans votre propre projet

```toml
[dependencies]
chiffre_aes_core = "0.1"
```

```rust
use chiffre_aes_core::{encrypt_file, decrypt_file, Password};
```

Voir la documentation du crate (`cargo doc --open -p chiffre_aes_core`) pour l'API
complète : `crypto`, `format`, `compress`, `archive`, `pipeline`,
`password_policy`.

## Sécurité

Merci de lire [`SECURITY.md`](./SECURITY.md) avant de signaler une
vulnérabilité — ne pas ouvrir d'issue publique pour un problème de
sécurité non encore corrigé.

Ce projet n'a, à ce jour, **pas fait l'objet d'un audit de sécurité
externe indépendant**. Il s'appuie sur des primitives éprouvées
(RustCrypto : `aes-gcm`, `argon2`) mais l'assemblage (format de fichier,
gestion des chunks, dérivation) n'a pas été revu par un tiers. À utiliser
en connaissance de cause tant qu'un audit n'a pas été mené.

## Licence

Double licence, au choix : [MIT](./LICENSE-MIT) ou
[Apache License 2.0](./LICENSE-APACHE). Voir [`NOTICE.md`](./NOTICE.md)
pour les licences des dépendances tierces.
