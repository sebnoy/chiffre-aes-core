# Changelog

## v1.0.0

Première version considérée stable. Deux axes de travail depuis la
v0.2.2 : passer d'une conformité au format *affirmée* à une conformité
*démontrée* (vecteurs de test indépendants), et passer d'une robustesse
*supposée* à une robustesse *vérifiée par fuzzing* — dont un vrai bug
trouvé et corrigé.

- **Vecteurs de test indépendants** — [`core/generate_vector.py`](./core/generate_vector.py)
  calcule des fichiers `.enc` complets (dérivation Argon2id, header, tag
  GCM, AAD et chiffrement de chaque chunk) à partir de la seule lecture
  de `FORMAT.md`, sans importer aucun code de ce dépôt (`argon2-cffi` +
  `cryptography`, indépendantes de `argon2`/`aes-gcm` côté Rust). Trois
  vecteurs versionnés dans `core/tests/vectors/` : cas nominal à un
  chunk, cas à 6 chunks avec dernier chunk partiel, fichier vide.
  Consommés côté Rust par [`core/tests/vectors.rs`](./core/tests/vectors.rs)
  à deux niveaux — boîte noire (`decrypt_file`, le chemin réel complet)
  et boîte grise (clé dérivée et **chaque chunk** comparés octet par
  octet à la référence indépendante). Voir FORMAT.md, introduction et
  §10, pour le détail. Aucun changement de comportement : ce travail
  démontre une propriété déjà vraie, il ne la modifie pas.

- **Infrastructure de fuzzing** (`cargo-fuzz`) — trois cibles dans
  [`core/fuzz/`](./core/fuzz/), chacune sur une fonction publique
  autonome : `decrypt_file` (parsing du header + déchiffrement des
  chunks), `archive::extract_archive_with_limits` (parsing du format
  d'archive interne), `compress::decompress_bytes_capped` (décodeur
  Deflate, avec vérification explicite du plafond anti-bombe). Corpus de
  départ construits à partir d'entrées structurellement valides plutôt
  que d'octets aléatoires, versionnés dans `core/fuzz/corpus/`. Voir
  [`core/fuzz/README.md`](./core/fuzz/README.md) pour la procédure
  complète et FORMAT.md §11 pour les résultats.

- **Correctif de sécurité — déni de service par allocation mémoire dans
  `extract_archive`** (trouvé par la campagne de fuzzing ci-dessus,
  en quelques minutes). Une entrée d'archive déclarant une taille
  compressée (`content_len`) sous la limite de politique
  (`max_entry_compressed_size`, 8 Gio par défaut) mais très supérieure
  aux octets réellement présents dans le flux déclenchait une tentative
  d'allocation à cette taille déclarée **avant même d'avoir lu un octet
  du flux réel** — une archive de quelques dizaines d'octets suffisait à
  provoquer une tentative d'allocation de plusieurs gigaoctets. Corrigé
  en remplaçant l'allocation d'un seul bloc par une lecture incrémentale
  par blocs de 64 Kio (`archive::read_len_incrementally`) : la mémoire
  réellement consommée suit désormais les octets *effectivement
  disponibles* dans le flux, jamais la valeur déclarée. Couvert par un
  test de non-régression dédié
  (`extract_does_not_allocate_declared_size_before_reading_actual_bytes`).
  Une campagne de 2h sur la version corrigée n'a fait remonter aucun
  nouveau crash sur cette cible.

- **Durcissement des permissions à l'extraction d'archive** —
  `setuid`, `setgid`, `sticky` et l'écriture « autres » (`other-write`)
  stockés dans une entrée d'archive sont désormais **toujours** retirés
  avant application sur le disque, quel que soit le contenu de
  l'archive (`archive::sanitize_mode`) : l'authentification AEAD garantit
  l'origine de l'archive (quelqu'un connaissant le mot de passe), pas
  l'innocuité de ses métadonnées de permissions si ce tiers est
  malveillant. Le bit exécutable, lui, reste restauré par défaut
  (comportement historique nécessaire à un usage normal de
  sauvegarde/restauration de ses propres fichiers) — désactivable via le
  nouveau champ `ExtractionLimits::preserve_executable_bit` si l'archive
  peut provenir d'un tiers auquel le mot de passe a été partagé sans
  confiance totale. **Changement potentiellement cassant** pour tout code
  externe construisant `ExtractionLimits` par littéral de structure
  exhaustif plutôt que via `..ExtractionLimits::default()`.

- **Durcissement de l'API cryptographique bas niveau** —
  `crypto::encrypt_buffer`/`crypto::decrypt_buffer` prennent désormais un
  nonce en paramètre sous la forme du nouveau type `crypto::Nonce`
  (possédé, non-`Clone`/non-`Copy`) plutôt qu'une référence vers un
  tableau d'octets librement réutilisable : une fois consommé par ces
  fonctions, un `Nonce` ne peut plus être réutilisé par erreur dans le
  même scope — la réutilisation accidentelle d'une même variable de
  nonce dans une boucle, l'erreur la plus fréquente en pratique, ne
  compile simplement plus. Nouveau type `crypto::NonceSequence` pour un
  usage répété sûr sous une même clé (compteur garanti sans répétition,
  nouvelle erreur `CryptoError::NonceSequenceExhausted` en cas
  d'épuisement). L'API recommandée (`encrypt_file`/`decrypt_file`,
  `pipeline::*`) est inchangée. **Changement cassant** pour tout code
  externe utilisant directement `crypto::encrypt_buffer`/
  `crypto::decrypt_buffer` (déjà non réexportées à la racine depuis la
  v0.2.2) — remplacer un nonce `&[u8; NONCE_LEN]` par
  `Nonce::from_raw_unchecked(...)`.

- **Corrections de documentation** — la taille de l'en-tête était
  affichée à tort comme 66 octets dans README.md/FORMAT.md (la somme
  réelle des champs, confirmée par les vecteurs de test indépendants,
  donne 62 octets) ; l'affirmation « suffisant pour reconstruire le
  format sans lire le code » a été reformulée pour pointer vers la
  démonstration concrète d'interopérabilité plutôt que rester une
  promesse non vérifiée ; le coût réel du pire cas Argon2id dans la
  politique actuelle est désormais documenté avec un chiffre mesuré
  (64 secondes) plutôt qu'affirmé seulement borné en théorie (FORMAT.md
  §8) — décision assumée de ne pas resserrer la politique, celle-ci
  s'appliquant symétriquement au chiffrement et au déchiffrement ; les
  types d'objets supportés par l'archive (fichier/dossier uniquement,
  aucun lien symbolique/physique/périphérique) sont désormais
  explicitement documentés plutôt qu'implicitement garantis par le code
  seul.

## v0.2.2

- **P1.3 / P1.5** (documentation uniquement, suite à ranalyse) —
  ajout de deux sections au `README.md` : « Gestion mémoire et effacement
  des secrets (zeroization) », qui précise exactement quelles données sont
  effacées activement (mot de passe, clé dérivée, plaintext de chunk) et
  lesquelles ne le sont pas (buffers d'archivage/compression, fichiers
  temporaires intermédiaires) ; et « Ce qui est réellement streaming, et
  ce qui ne l'est pas », qui distingue le chiffrement/déchiffrement
  (streaming réel par chunks de 1 Mio) de l'archivage/la compression
  (chaque fichier chargé intégralement en mémoire). Aucun changement de
  code ni de comportement — clarification de propriétés déjà vraies dans
  l'implémentation actuelle.
- **P1.4** (durcissement, suite à analyse) — l'extraction d'une
  archive désarchive désormais vers un dossier temporaire
  (`pipeline::decrypt_to_dir`/`decrypt_to_dir_with_progress`) avant de
  basculer vers le dossier de destination une fois le désarchivage
  entièrement réussi (renommage atomique si la destination n'existe pas
  encore, fusion élément par élément sinon — voir README.md « Atomicité de
  l'extraction » pour la limite résiduelle documentée de ce second cas).
  Auparavant, une erreur en cours de désarchivage (limite de ressources,
  entrée malformée, erreur disque) pouvait laisser des fichiers déjà
  extraits dans le dossier de destination sans nettoyage. Aucun changement
  de format ni de signature d'API publique.
- **P0.1** (durcissement, suite à analyse) — ajout de tests
  explicites sur l'unicité et le déterminisme de `derive_nonce`
  (`core/src/format.rs`) : injectivité sur un large échantillon de
  compteurs, absence de collision entre nonce d'en-tête et nonces de
  chunks, déterminisme de la dérivation. L'invariant lui-même
  (`base_nonce` fixe + XOR d'un compteur unique par opération) était déjà
  respecté par l'implémentation ; ce changement le rend vérifiable
  automatiquement plutôt que garanti uniquement par un raisonnement
  mathématique en commentaire. Aucun changement de comportement ni de
  format.
- **P0.2** (durcissement, suite à analyse) — `crypto::encrypt_buffer`
  et `crypto::decrypt_buffer` ne sont plus réexportées à la racine du
  crate. Elles restent accessibles via `chiffre_aes_core::crypto::...`
  pour qui en a explicitement besoin, avec une documentation renforcée sur
  le risque de réutilisation de nonce. L'API recommandée
  (`encrypt_file`/`decrypt_file`, `pipeline::encrypt_paths`/
  `decrypt_to_dir`) est inchangée et continue de gérer les nonces pour
  l'appelant. **Changement potentiellement cassant** pour tout code
  externe qui importait `encrypt_buffer`/`decrypt_buffer` depuis la racine
  du crate (`use chiffre_aes_core::encrypt_buffer` devient
  `use chiffre_aes_core::crypto::encrypt_buffer`).

## v0.2.1

- Ajout de `chiffre_aes_core::VERSION` (constante publique, dérivée de
  `CARGO_PKG_VERSION`) — permet aux applications intégrant ce crate
  d'afficher la version du moteur cryptographique réellement lié au
  binaire, sans avoir à la dupliquer/maintenir manuellement à un second
  endroit. Ajout purement additif, aucun changement de comportement.

## v0.2.0

Durcissement du format `.enc` suite à analyse (spécification
interne, voir historique des commits) :

- **M1** — bornes de politique sur les paramètres Argon2id (mémoire,
  itérations, parallélisme), vérifiées avant toute dérivation coûteuse.
  Empêche un en-tête `.enc` hostile de provoquer un déni de service.
- **M2** — invariants structurels complets sur l'en-tête : bornes de
  `chunk_size`, cohérence `total_chunks == ceil(total_plaintext_size /
  chunk_size)`, arithmétique protégée contre les dépassements.
- **A1** — la longueur de chemin dans l'archive interne utilise désormais
  une conversion vérifiée plutôt qu'un cast silencieux pouvant tronquer un
  chemin trop long.
- **A3** — limites de ressources à l'extraction (nombre d'entrées, taille
  compressée par entrée, taille totale extraite) — protège aussi contre
  les bombes de décompression.
- **A4** — les fichiers temporaires (chiffrement, déchiffrement, archive
  intermédiaire) sont désormais créés avec la crate `tempfile` (nom non
  prévisible, création atomique, nettoyage automatique y compris en cas
  de panic), plutôt qu'avec un nom de fichier prévisible.
- **M6** — ajout d'une trentaine de tests adversariaux couvrant les points
  ci-dessus (chunk dupliqué, chunk d'une autre archive, données en trop,
  en-tête altéré champ par champ, dépassement des limites de ressources).
- Nouveaux documents [`FORMAT.md`](./FORMAT.md) (spécification complète du
  format `.enc`) et [`USAGE.md`](./USAGE.md) (usage détaillé du CLI).

Aucun changement de signature dans l'API publique existante. Compatible
avec les fichiers `.enc` produits par la v0.1.0 (le format sur le fil n'a
pas changé, seule la validation à la lecture est plus stricte).

## v0.1.0

Version initiale : chiffrement/déchiffrement AES-256-GCM, dérivation
Argon2id, format `.enc` en streaming par chunks, CLI.
