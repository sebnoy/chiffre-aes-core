# Fuzzing de `chiffre_aes_core`

Sept cibles, chacune exerçant une fonction publique autonome sur des
octets arbitraires (ou, pour `roundtrip_bytes`, une propriété sur des clairs
arbitraires). Propriété recherchée dans tous les cas : aucun panic,
quelle que soit l'entrée (le crate ne contient aucun `unsafe`, donc il
n'y a pas de corruption mémoire à chercher — la valeur du fuzzing ici est
de détecter des paniques de logique et une consommation de ressources
disproportionnée).

| Cible | Fonction visée | Ce qu'elle exerce |
|---|---|---|
| `decrypt_file` | `chiffre_aes_core::decrypt_file` | Parsing du header **v1** (62 octets, mot de passe), vérification du tag GCM du header, lecture/déchiffrement de chaque chunk. |
| `decrypt_file_with_raw_key` | `chiffre_aes_core::decrypt_file_with_raw_key` | Parsing du header **v2** (`HeaderV2::from_reader`, longueur variable, liste de destinataires) — surface distincte de `decrypt_file`, qui rejette tout header non-v1 avant même d'atteindre ce code. |
| `extract_archive` | `chiffre_aes_core::archive::extract_archive_with_limits` | Parsing du format d'archive interne : entrées, chemins, permissions, taille compressée, décompression. |
| `decompress_bytes` | `chiffre_aes_core::compress::decompress_bytes_capped` | Le décodeur Deflate isolément, avec vérification explicite que le plafond de sortie n'est jamais dépassé. |
| `decrypt_bytes` | `chiffre_aes_core::decrypt_bytes` | Même surface que `decrypt_file` (header v1, tag du header, chunks, troncature) **sans fichier** : beaucoup plus rapide. Son corpus est **authentifié avec le mot de passe du harnais**, donc le fuzzer atteint réellement la couche « chunks ». Vérifie aussi que le clair et sa capacité ne dépassent jamais la taille du conteneur. |
| `roundtrip_bytes` | `encrypt_bytes` + `decrypt_bytes` | Propriété : `decrypt_bytes(encrypt_bytes(x)) == x`, et l'altération d'un seul bit du conteneur est toujours rejetée. Lente (3 dérivations Argon2id minimales par exécution). |
| `assess_password_with_context` | `password_policy::assess_password_with_context` | Saisies Unicode arbitraires : aucun panic, cohérence des champs retournés (score, drapeaux, codes). Format d'entrée : mot de passe, puis jusqu'à quatre termes de contexte séparés par l'octet NUL. |

## Installation (une fois)

`cargo-fuzz` nécessite le toolchain **nightly** (pour l'instrumentation
libFuzzer/sanitizers) même si le reste du projet compile en stable :

```bash
rustup install nightly
cargo install cargo-fuzz
```

## Lancer une campagne

Depuis `core/` (là où se trouve ce dossier `fuzz/`) :

```bash
cargo +nightly fuzz run decrypt_file
cargo +nightly fuzz run decrypt_file_with_raw_key
cargo +nightly fuzz run extract_archive
cargo +nightly fuzz run decompress_bytes
cargo +nightly fuzz run decrypt_bytes
cargo +nightly fuzz run roundtrip_bytes
cargo +nightly fuzz run assess_password_with_context
```

test sur 30 minutes
```bash
cargo +nightly fuzz run decrypt_file -- -max_total_time=1800
cargo +nightly fuzz run decrypt_file_with_raw_key -- -max_total_time=1800
cargo +nightly fuzz run extract_archive -- -max_total_time=1800
cargo +nightly fuzz run decompress_bytes -- -max_total_time=1800
cargo +nightly fuzz run decrypt_bytes -- -max_total_time=1800
cargo +nightly fuzz run roundtrip_bytes -- -max_total_time=1800
cargo +nightly fuzz run assess_password_with_context -- -max_total_time=1800
```

Particularités des cibles ajoutées en v2.1.0 :

- **`roundtrip_bytes`** — le `chunk_size` par défaut est de 1 Mio : avec la longueur d'entrée par défaut de libFuzzer (4 096 octets), la frontière entre deux chunks n'est jamais franchie. Pour l'exercer, lancer aussi une campagne avec
  `cargo +nightly fuzz run roundtrip_bytes -- -max_len=3145728 -max_total_time=1800` (plus lente).
- **`decrypt_bytes` et `decrypt_file`** — l'en-tête déclare ses propres paramètres Argon2id (bornés par la politique du crate) : une entrée qui les met à des valeurs coûteuses tout en restant valide peut prendre plusieurs secondes. Ajouter `-timeout=120` si libFuzzer signale un « timeout » sur une entrée qui n'est en réalité que coûteuse ; un vrai blocage se reconnaît à l'absence de tout progrès au-delà.
- **`assess_password_with_context`** — pas de dépendance à Argon2id : cible très rapide.

Chaque commande tourne indéfiniment (Ctrl+C pour arrêter) et affiche un
compteur d'exécutions par seconde ainsi que la couverture de code
explorée. Pour une première campagne, quelques heures par cible sur une
machine de développement classique donnent déjà un signal significatif ;
au-delà, les gains sont décroissants sauf changement de code source.

Pour limiter dans le temps plutôt qu'à la main :

```bash
cargo +nightly fuzz run decrypt_file -- -max_total_time=3600   # 1h
```

## Corpus de départ

Chaque cible a un corpus initial dans `fuzz/corpus/<cible>/` :
- `decrypt_file/` : les 3 vecteurs v1 (`vector_00{1,2,3}.enc`) — un
  fichier `.enc` structurellement valide, même si le mot de passe du
  harnais ne correspond pas (sans importance : seule la structure du
  header/chunks compte pour amorcer le fuzzer, pas la réussite du
  déchiffrement).
- `decrypt_file_with_raw_key/` : les 3 vecteurs v2
  (`seed_vector_v2_00{1,2,3}.enc`, produits par
  `generate_vector_v2_external()` dans `generate_vector.py`) — couvrent
  un seul destinataire, plusieurs destinataires/chunks, et le fichier
  vide.
- `extract_archive/` : une archive minimale à une entrée, valide.
- `decompress_bytes/` : un flux Deflate brut valide.
- `decrypt_bytes/` : trois conteneurs **authentifiés avec le mot de passe du harnais** (`seed_auth_*.enc` : JSON court, contenu vide, 3 Ko) — c'est ce qui permet de muter la couche « chunks » sans casser le tag de l'en-tête — plus les 3 vecteurs v1 (`vector_00{1,2,3}.enc`, structure d'en-tête valide, authentification en échec). Ils ont été produits par `encrypt_bytes` avec les paramètres Argon2id minimaux.
- `roundtrip_bytes/` : trois clairs (JSON court, 2 Ko pseudo-aléatoires, texte UTF-8).
- `assess_password_with_context/` : mots de passe courants, avec et sans contexte, chaîne vide, Unicode (accents, kanji, cyrillique, émojis), longue répétition.
Le fuzzer enrichit ces dossiers automatiquement au fil de l'exécution
avec les entrées qui augmentent la couverture — **committer le contenu
de `fuzz/corpus/` après une campagne significative** est une bonne
pratique : ça accélère les campagnes futures (CI ou relance locale) en
repartant d'un corpus déjà riche plutôt que des seeds initiales seules.

## Si un crash est trouvé

`cargo-fuzz` écrit l'entrée fautive dans
`fuzz/artifacts/<cible>/crash-<hash>` et affiche la panique déclenchée
(message + backtrace). Étapes à suivre, dans l'ordre :

1. **Minimiser** l'entrée pour isoler la cause :
   ```bash
   cargo +nightly fuzz tmin decrypt_file fuzz/artifacts/decrypt_file/crash-<hash>
   ```
   Produit une version réduite du fichier qui déclenche toujours le même
   panic — beaucoup plus facile à lire que l'entrée brute.

2. **Rejouer** hors du fuzzer pour confirmer et déboguer normalement :
   ```bash
   cargo +nightly fuzz run decrypt_file fuzz/artifacts/decrypt_file/crash-<hash>
   ```

3. **Corriger** le code source (jamais le harnais — le harnais ne fait
   que révéler un problème réel dans le crate).

4. **Transformer le crash en test de non-régression permanent** : copier
   l'entrée minimisée dans `core/tests/fuzz_regressions/` et ajouter un
   test dans `core/tests/vectors.rs` (ou un nouveau fichier
   `tests/fuzz_regressions.rs`) qui rejoue exactement cette entrée et
   vérifie l'absence de panic — pour que ce cas précis reste couvert par
   `cargo test --workspace` en continu, sans redépendre de retrouver le
   même crash par du fuzzing aléatoire.

## Intégration continue (optionnel, à envisager plus tard)

Une campagne de fuzzing complète n'a pas sa place dans une CI qui doit
rester rapide (chaque exécution dure des minutes à des heures). Deux
approches courantes, à ne considérer qu'une fois ce dossier en place et
éprouvé localement :
- un job **hebdomadaire/nocturne séparé**, non bloquant, qui lance
  chaque cible quelques minutes et alerte en cas de nouveau crash ;
- `cargo +nightly fuzz run <cible> -- -runs=100000` (nombre d'exécutions
  fixe plutôt qu'une durée) comme vérification rapide et bornée à chaque
  pull request, en complément — pas en remplacement — d'une vraie
  campagne longue lancée manuellement de temps en temps.
