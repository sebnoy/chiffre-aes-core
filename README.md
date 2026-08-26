# chiffre_aes_core / chiffre_aes_cli

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


