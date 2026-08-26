# Contribuer

Merci de l'intérêt porté à ce projet !

## Avant de proposer une PR

- Pour un changement touchant la cryptographie ou le format de fichier
  (`core/src/crypto.rs`, `core/src/format.rs`) : ouvrez d'abord une
  discussion/issue pour valider l'approche avant d'investir du temps
  dans le code — ce sont les parties les plus sensibles du projet.
- `cargo test --workspace` et `cargo clippy --workspace -- -D warnings`
  doivent passer.
- Toute nouvelle dépendance doit être en licence permissive compatible
  (MIT, Apache-2.0, BSD, Zlib...) — pas de (L)GPL, pour ne pas
  contaminer la licence du crate.

## Licence des contributions

En soumettant une contribution, vous acceptez qu'elle soit publiée sous
la même double licence MIT OR Apache-2.0 que le reste du projet.

> Si vous envisagez un jour de proposer une licence commerciale séparée
> de `chiffre_aes_core` à des tiers, il est recommandé de faire signer un CLA
> (Contributor License Agreement) simple à chaque contributeur externe,
> pour conserver le droit de re-licencier l'ensemble du code. Sans CLA,
> chaque contribution reste la propriété de son auteur sous MIT/Apache-2.0
> uniquement.
