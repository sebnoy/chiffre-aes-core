//! Fuzz `decrypt_file` sur un fichier `.enc` arbitraire.
//!
//! Ceci exerce tout le chemin de lecture attaquable : parsing du header à
//! taille fixe (magic, version, salt, paramètres Argon2, nonce de base,
//! chunk_size, total_chunks, taille totale), vérification du tag GCM du
//! header, puis lecture et déchiffrement de chaque chunk. C'est la
//! surface la plus riche et la plus directement exposée à un fichier
//! hostile, puisque `decrypt_file` est le point d'entrée public que tout
//! utilisateur (CLI, GUI) appelle sur un fichier qu'il n'a pas
//! nécessairement produit lui-même.
//!
//! Propriété recherchée : quelle que soit l'entrée, `decrypt_file` doit
//! toujours retourner un `Result` — jamais paniquer, jamais consommer une
//! mémoire ou un temps disproportionnés par rapport à la taille de
//! l'entrée. Le mot de passe est fixe et non pertinent ici : on ne fuzz
//! pas Argon2id lui-même (déterministe, déjà éprouvé par ses propres
//! auteurs), seulement l'interprétation du header et des chunks.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Write;
use zeroize::Zeroizing;

fuzz_target!(|data: &[u8]| {
    // Répertoire temporaire dédié à CETTE exécution du harnais ; libFuzzer
    // peut invoquer la fonction des milliers de fois par seconde, d'où le
    // nom de fichier fixe (pas besoin d'un nom unique, le contenu suffit
    // à distinguer chaque cas et le répertoire est recréé à chaque appel).
    let Ok(tmp) = tempfile::tempdir() else {
        return;
    };
    let enc_path = tmp.path().join("fuzz_input.enc");
    let out_path = tmp.path().join("fuzz_output.dat");

    let Ok(mut f) = std::fs::File::create(&enc_path) else {
        return;
    };
    if f.write_all(data).is_err() {
        return;
    }
    drop(f);

    let password: Zeroizing<String> = Zeroizing::new("mot-de-passe-de-fuzzing".to_string());

    // On ignore volontairement le Result : seul un panic constitue un
    // signal pour libFuzzer. Une erreur (WrongPassword, Corrupted,
    // InvalidFormat, ...) est un comportement normal et attendu face à
    // une entrée arbitraire.
    let _ = chiffre_aes_core::decrypt_file(&enc_path, &out_path, &password);
});
