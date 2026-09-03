//! Fuzz `decrypt_file_with_raw_key` sur un fichier `.enc` v2 arbitraire.
//!
//! Cible spécifiquement `HeaderV2::from_reader` — le parsing à longueur
//! variable introduit pour le header v2 (liste de destinataires, chacun
//! avec un `recipient_id`/`wrapped_key` de longueur déclarée) — qui n'est
//! **pas** exercé par la cible `decrypt_file` existante : celle-ci
//! rejette tout header dont le champ version n'est pas 1, avant même
//! d'atteindre le code de parsing v2. C'est précisément le genre de
//! surface (longueurs déclarées, contrôlées par l'entrée) qui a produit
//! le bug OOM trouvé sur `extract_archive` — les bornes de politique
//! (`MAX_RECIPIENTS`, `MAX_RECIPIENT_ID_LEN`, `MAX_WRAPPED_KEY_LEN`) ont
//! été conçues dès le départ en tenant compte de cette leçon (voir
//! `crypto.rs`), mais seul le fuzzing démontre que l'implémentation
//! respecte réellement cette conception.
//!
//! Propriété recherchée : comme pour `decrypt_file`, jamais de panic ni
//! de consommation de ressources disproportionnée, quelle que soit
//! l'entrée. La clé fournie est fixe et arbitraire — elle ne
//! correspondra à aucun header généré aléatoirement (l'authentification
//! échouera presque toujours), ce qui est sans importance : c'est le
//! *parsing* du header, qui a lieu avant toute vérification
//! cryptographique, qui est visé ici.

#![no_main]

use chiffre_aes_core::RawKey;
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let Ok(tmp) = tempfile::tempdir() else {
        return;
    };
    let enc_path = tmp.path().join("fuzz_input_v2.enc");
    let out_path = tmp.path().join("fuzz_output_v2.dat");

    let Ok(mut f) = std::fs::File::create(&enc_path) else {
        return;
    };
    if f.write_all(data).is_err() {
        return;
    }
    drop(f);

    // Clé fixe et arbitraire : seul le parsing du header nous intéresse
    // ici, pas la réussite de l'authentification (voir doc de module).
    let key = RawKey::from_bytes([0x42u8; 32]);

    let _ = chiffre_aes_core::decrypt_file_with_raw_key(&enc_path, &out_path, key);
});
