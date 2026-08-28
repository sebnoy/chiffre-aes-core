# Usage de `chiffre_aes_cli`

```
chiffre_aes_cli encrypt <sortie.enc> <source1> [source2 ...]
chiffre_aes_cli decrypt <source.enc> <dossier_sortie>
chiffre_aes_cli check-password
```

Le mot de passe est toujours demandé de façon interactive (saisie sur
stdin après un prompt), jamais passé en argument de ligne de commande —
volontairement, pour ne jamais l'exposer dans l'historique du shell ni
dans la liste des processus (`ps`).

## `encrypt`

```
chiffre_aes_cli encrypt archive.enc dossier_a_chiffrer/
chiffre_aes_cli encrypt archive.enc fichier1.txt fichier2.pdf dossier/
```

Accepte un mélange de fichiers et de dossiers en sources. Utilise les
paramètres Argon2 par défaut du projet (voir `Argon2Params::default()`
dans `core/src/crypto.rs` pour les valeurs exactes et leur justification).
Émet un avertissement sur stderr par élément source ignoré (ex. lien
symbolique non suivi), sans faire échouer l'ensemble de l'opération —
le code de sortie reste `0` (succès) tant qu'au moins l'opération
globale a abouti.

## `decrypt`

```
chiffre_aes_cli decrypt archive.enc dossier_sortie/
```

`dossier_sortie` est créé s'il n'existe pas. Les chemins internes à
l'archive sont validés avant extraction (rejet des chemins absolus, des
composants `..`, etc. — voir [`FORMAT.md`](./FORMAT.md) et le module
`core/src/archive.rs`).

## `check-password`

```
chiffre_aes_cli check-password
```

Évalue un mot de passe (score `zxcvbn` sur 4, longueur minimale,
correspondance de confirmation) sans effectuer de chiffrement — utile
pour tester la politique de mot de passe du projet de façon isolée, ou
en script/CI.

## Codes de sortie

`0` en cas de succès, `1` dans tous les cas d'échec. Le message
d'erreur sur stderr distingue explicitement (voir aussi
[`FORMAT.md §6`](./FORMAT.md#6-déchiffrement--ordre-de-lecture-et-détections)) :

| Message | Cause |
|---|---|
| `mot de passe incorrect` | échec d'authentification du header (mot de passe erroné **ou** header altéré — indissociables, voir FORMAT.md §6) |
| `fichier corrompu ou altéré` | échec d'authentification d'un chunk : modification, réordonnancement, substitution |
| `fichier tronqué (données manquantes)` | fin de fichier prématurée, ou taille totale incohérente |
| `ce fichier n'est pas une archive .enc valide` | magic ou version de format non reconnus |
| `opération annulée` | interruption demandée en cours de traitement |
| `erreur système : ...` | erreur d'E/S sous-jacente (disque, permissions, etc.) |
| `erreur d'archivage : ...` | problème lors de l'archivage/désarchivage (voir `core/src/archive.rs`) |
