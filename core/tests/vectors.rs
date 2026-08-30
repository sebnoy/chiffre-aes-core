//! Tests d'intégration à partir de vecteurs indépendants (générés en
//! Python, sans dépendance au code de ce crate — voir
//! `generate_vector.py` et `tests/vectors/*.json`).
//!
//! Deux niveaux, appliqués génériquement à CHAQUE vecteur listé dans
//! `VECTOR_FILES` :
//! - boîte noire : `decrypt_file` sur le `.enc` complet — le test le plus
//!   représentatif, exerce tout le chemin réel.
//! - boîte grise : vérifie séparément la clé dérivée et le ciphertext de
//!   chaque chunk, pour localiser précisément une éventuelle divergence.
//!
//! Pour ajouter un nouveau vecteur : générer `vector_NNN.json` +
//! `vector_NNN.enc` (voir `generate_vector.py`), les déposer dans
//! `tests/vectors/`, puis ajouter une entrée à `VECTOR_FILES` ci-dessous.
//! Aucun autre changement n'est nécessaire — les deux niveaux de test
//! s'appliquent automatiquement au nouveau vecteur.

use chiffre_aes_core::crypto::{decrypt_buffer, derive_key, Argon2Params, Nonce};
use chiffre_aes_core::decrypt_file;
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct Vector {
    inputs: Inputs,
    expected: Expected,
}

#[derive(Deserialize)]
struct Inputs {
    password_utf8: String,
    salt_hex: String,
    #[allow(dead_code)]
    base_nonce_hex: String,
    argon2_memory_kib: u32,
    argon2_iterations: u32,
    argon2_parallelism: u8,
    #[allow(dead_code)]
    chunk_size: u32,
    plaintext_utf8: String,
}

#[derive(Deserialize)]
struct Expected {
    derived_key_hex: String,
    #[allow(dead_code)]
    header_hex: String,
    #[allow(dead_code)]
    header_tag_hex: String,
    #[allow(dead_code)]
    header_hash_hex: String,
    #[allow(dead_code)]
    total_chunks: u64,
    chunks: Vec<ChunkVector>,
    #[allow(dead_code)]
    full_enc_file_hex: String,
}

#[derive(Deserialize)]
struct ChunkVector {
    index: u64,
    is_last: bool,
    plaintext_len: usize,
    aad_hex: String,
    nonce_hex: String,
    ciphertext_with_tag_hex: String,
}

/// Décodeur hexadécimal minimal, pour éviter d'ajouter une dépendance
/// `hex` juste pour les tests.
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex invalide dans le vecteur"))
        .collect()
}

/// Un vecteur = son nom (pour les messages d'erreur), son JSON, et son
/// `.enc` complet — chargés à la compilation via `include_str!`/
/// `include_bytes!` (le chemin est relatif à CE fichier).
struct VectorFile {
    name: &'static str,
    json: &'static str,
    enc: &'static [u8],
}

/// Liste explicite des vecteurs à tester. Ajouter une ligne ici suffit à
/// faire tourner les deux niveaux de test sur un nouveau vecteur —
/// `include_str!`/`include_bytes!` exigeant un chemin littéral connu à la
/// compilation, cette liste ne peut pas être générée dynamiquement en
/// scannant le dossier, mais rester à jour ici est le seul geste manuel
/// requis.
const VECTOR_FILES: &[VectorFile] = &[
    VectorFile {
        name: "vector_001",
        json: include_str!("vectors/vector_001.json"),
        enc: include_bytes!("vectors/vector_001.enc"),
    },
    VectorFile {
        name: "vector_002",
        json: include_str!("vectors/vector_002.json"),
        enc: include_bytes!("vectors/vector_002.enc"),
    },
    VectorFile {
        name: "vector_003",
        json: include_str!("vectors/vector_003.json"),
        enc: include_bytes!("vectors/vector_003.enc"),
    },
];

fn load(vf: &VectorFile) -> Vector {
    serde_json::from_str(vf.json)
        .unwrap_or_else(|e| panic!("{} : JSON invalide ({e})", vf.name))
}

// --- Niveau 1 : boîte noire, API publique complète ----------------------
//
// Un seul test, qui boucle sur tous les vecteurs listés — plutôt qu'une
// fonction #[test] par vecteur — pour que la liste ci-dessus reste le
// seul endroit à modifier lors de l'ajout d'un vecteur.

#[test]
fn all_vectors_decrypt_via_public_api() {
    for vf in VECTOR_FILES {
        let v = load(vf);
        let password: Zeroizing<String> = Zeroizing::new(v.inputs.password_utf8.clone());

        let tmp = tempfile::tempdir().unwrap();
        let enc_path = tmp.path().join(format!("{}.enc", vf.name));
        std::fs::write(&enc_path, vf.enc).unwrap();
        let out_path = tmp.path().join(format!("{}.out", vf.name));

        decrypt_file(&enc_path, &out_path, &password)
            .unwrap_or_else(|e| panic!("{} : decrypt_file a échoué : {e:?}", vf.name));

        let decrypted = std::fs::read_to_string(&out_path)
            .unwrap_or_else(|e| panic!("{} : lecture du fichier déchiffré : {e}", vf.name));

        assert_eq!(
            decrypted, v.inputs.plaintext_utf8,
            "{} : le plaintext déchiffré ne correspond pas à celui attendu",
            vf.name
        );
    }
}

// --- Niveau 2 : boîte grise, valeurs intermédiaires ----------------------

#[test]
fn all_vectors_derived_key_matches_independent_reference() {
    for vf in VECTOR_FILES {
        let v = load(vf);
        let password: Zeroizing<String> = Zeroizing::new(v.inputs.password_utf8.clone());
        let salt: [u8; 16] = hex_decode(&v.inputs.salt_hex)
            .try_into()
            .unwrap_or_else(|_| panic!("{} : salt_hex doit faire 16 octets", vf.name));
        let params = Argon2Params {
            memory_kib: v.inputs.argon2_memory_kib,
            iterations: v.inputs.argon2_iterations,
            parallelism: v.inputs.argon2_parallelism,
        };

        let key = derive_key(&password, &salt, params)
            .unwrap_or_else(|e| panic!("{} : dérivation de clé a échoué : {e:?}", vf.name));

        assert_eq!(
            key.as_bytes().as_slice(),
            hex_decode(&v.expected.derived_key_hex).as_slice(),
            "{} : la clé dérivée par Argon2id ne correspond pas au vecteur indépendant",
            vf.name
        );
    }
}

#[test]
fn all_vectors_every_chunk_ciphertext_matches_independent_reference() {
    for vf in VECTOR_FILES {
        let v = load(vf);
        let password: Zeroizing<String> = Zeroizing::new(v.inputs.password_utf8.clone());
        let salt: [u8; 16] = hex_decode(&v.inputs.salt_hex).try_into().unwrap();
        let params = Argon2Params {
            memory_kib: v.inputs.argon2_memory_kib,
            iterations: v.inputs.argon2_iterations,
            parallelism: v.inputs.argon2_parallelism,
        };
        let key = derive_key(&password, &salt, params).unwrap();
        let full_plaintext = v.inputs.plaintext_utf8.as_bytes();

        let mut offset = 0usize;
        for chunk in &v.expected.chunks {
            let nonce_bytes: [u8; 12] = hex_decode(&chunk.nonce_hex)
                .try_into()
                .unwrap_or_else(|_| {
                    panic!("{} chunk {} : nonce_hex doit faire 12 octets", vf.name, chunk.index)
                });
            let aad = hex_decode(&chunk.aad_hex);
            let ciphertext = hex_decode(&chunk.ciphertext_with_tag_hex);

            let plaintext = decrypt_buffer(&key, Nonce::from_raw_unchecked(nonce_bytes), &ciphertext, &aad)
                .unwrap_or_else(|e| {
                    panic!(
                        "{} chunk {} (is_last={}) : déchiffrement a échoué : {e:?}",
                        vf.name, chunk.index, chunk.is_last
                    )
                });

            assert_eq!(
                plaintext.len(),
                chunk.plaintext_len,
                "{} chunk {} : longueur de plaintext inattendue",
                vf.name,
                chunk.index
            );

            let expected_slice = &full_plaintext[offset..offset + chunk.plaintext_len];
            assert_eq!(
                plaintext.as_slice(),
                expected_slice,
                "{} chunk {} : contenu déchiffré ne correspond pas au segment attendu",
                vf.name,
                chunk.index
            );

            offset += chunk.plaintext_len;
        }

        assert_eq!(
            offset,
            full_plaintext.len(),
            "{} : la somme des chunks ne couvre pas tout le plaintext",
            vf.name
        );
    }
}
