# Changelog

## v0.2.0

Durcissement du format `.enc` suite à une revue de sécurité (spécification
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
