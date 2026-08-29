# Changelog

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
