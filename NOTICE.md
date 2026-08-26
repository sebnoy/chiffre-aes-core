# Notices tierces

⚠️ Ce fichier est un point de départ manuel. À régénérer automatiquement
à chaque changement de dépendances, par exemple avec :

```bash
cargo install cargo-about
cargo about generate about.hbs > NOTICE.md
```

ou plus simplement pour un premier inventaire :

```bash
cargo install cargo-license
cargo license
```

## Dépendances directes de `chiffre_aes_core`

| Crate | Licence |
|---|---|
| aes-gcm | MIT OR Apache-2.0 |
| argon2 | MIT OR Apache-2.0 |
| zeroize | MIT OR Apache-2.0 |
| rand | MIT OR Apache-2.0 |
| thiserror | MIT OR Apache-2.0 |
| sha2 | MIT OR Apache-2.0 |
| flate2 (backend rust_backend / miniz_oxide) | MIT OR Apache-2.0 OR Zlib |
| zxcvbn | MIT |

## Dépendances directes de `chiffre_aes_cli`

| Crate | Licence |
|---|---|
| chiffre_aes_core | MIT OR Apache-2.0 (ce projet) |
| zeroize | MIT OR Apache-2.0 |

Aucune dépendance transitive en (L)GPL identifiée à ce jour — à
reconfirmer avec `cargo about` / `cargo license` avant chaque release,
transitive comprise (`cargo tree` pour explorer l'arbre complet).
